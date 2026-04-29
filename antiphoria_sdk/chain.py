"""SealEngine: append-only seal chain over a workspace directory."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

from filelock import FileLock, Timeout

from antiphoria_sdk._version import __version__ as _SDK_VERSION
from antiphoria_sdk.canonical import canonical_json_bytes
from antiphoria_sdk.signing import Signer, Verifier
from antiphoria_sdk.types import (
    ChainRecord,
    GenesisReceipt,
    SealReceipt,
    StepType,
    StepVerification,
    VerificationReport,
    is_safe_relative_path,
)

_LOGGER = logging.getLogger(__name__)

_CHAIN_DIR_NAME = "chain"
_CHAIN_LOCK_NAME = ".chain.lock"
_RECORD_FILENAME_RE = re.compile(r"^(\d{6})_([A-Z][A-Z0-9_]{0,63})\.json$")
_DEFAULT_FILE_LOCK_TIMEOUT_S = 30.0
_VERIFY_ONLY_FINGERPRINT = "0" * 32


class ChainError(RuntimeError):
    """Raised when a seal operation cannot be completed."""


class ChainSequenceError(ChainError):
    """Raised when attempted writes would violate monotonicity or linkage."""


class SealEngine:
    """Owns one (workspace, run_id).

    Cross-process safety: each engine acquires a ``filelock.FileLock`` on
    ``chain/.chain.lock`` while writing a record. Two engines pointed at
    the same workspace will not corrupt the chain on disk, but in-memory
    ``latest_step``/``latest_hash`` may go stale; rebuild via ``resume``.

    Intra-process: not safe to share a single engine across asyncio
    tasks; use one engine per run.
    """

    def __init__(
        self,
        *,
        workspace: Path,
        run_id: str,
        signer: Signer,
        verifier: Verifier,
        file_lock_timeout_s: float = _DEFAULT_FILE_LOCK_TIMEOUT_S,
    ) -> None:
        self._workspace = Path(workspace).resolve()
        self._run_id = run_id
        self._signer = signer
        self._verifier = verifier
        self._lock = asyncio.Lock()
        self._chain_dir = self._workspace / _CHAIN_DIR_NAME
        self._latest_step: int = -1
        self._latest_hash: str | None = None
        self._file_lock_timeout_s = file_lock_timeout_s
        self._file_lock = FileLock(
            str(self._chain_dir / _CHAIN_LOCK_NAME),
            timeout=file_lock_timeout_s,
        )

    @classmethod
    def create(
        cls,
        workspace: Path,
        run_id: str,
        *,
        signer: Signer,
        verifier: Verifier,
        file_lock_timeout_s: float = _DEFAULT_FILE_LOCK_TIMEOUT_S,
    ) -> SealEngine:
        """Create a fresh engine and ensure workspace/chain/ exists."""
        ws = Path(workspace).resolve()
        ws.mkdir(parents=True, exist_ok=True)
        (ws / _CHAIN_DIR_NAME).mkdir(exist_ok=True)
        return cls(
            workspace=ws,
            run_id=run_id,
            signer=signer,
            verifier=verifier,
            file_lock_timeout_s=file_lock_timeout_s,
        )

    @classmethod
    def resume(
        cls,
        workspace: Path,
        run_id: str,
        *,
        signer: Signer,
        verifier: Verifier,
        file_lock_timeout_s: float = _DEFAULT_FILE_LOCK_TIMEOUT_S,
    ) -> SealEngine:
        """Reopen an existing workspace. Verifies the full chain before restoring state."""
        engine = cls.create(
            workspace,
            run_id,
            signer=signer,
            verifier=verifier,
            file_lock_timeout_s=file_lock_timeout_s,
        )
        report = engine._verify_chain_sync()
        if not report.chain_intact:
            raise ChainError(
                f"Cannot resume: chain at {workspace} is invalid. "
                f"First error at step {report.first_error_index}.",
            )
        if report.total_steps == 0:
            return engine
        last = report.steps[-1]
        record_bytes = last.record_path.read_bytes()
        engine._latest_step = last.step_index
        engine._latest_hash = _compute_entry_hash(record_bytes)
        return engine

    @property
    def workspace(self) -> Path:
        return self._workspace

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def chain_dir(self) -> Path:
        return self._chain_dir

    @property
    def latest_hash(self) -> str | None:
        return self._latest_hash

    @property
    def latest_step(self) -> int:
        return self._latest_step

    async def hash_file(self, path: str | Path) -> str:
        """Return 'sha256:<hex>' of a content file's raw bytes."""
        abs_path, _rel = self._resolve_content_path_and_rel(path)
        return await asyncio.to_thread(_sha256_file, abs_path)

    async def begin_chain(
        self,
        *,
        research_brief: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> GenesisReceipt:
        """Write the GENESIS record. Must be called exactly once before any other seal.

        ``research_brief`` is stored under the reserved ``research_brief`` key
        in metadata. Passing ``research_brief`` *and* ``metadata={"research_brief": ...}``
        is rejected to prevent silent overwrites.
        """
        async with self._lock:
            if self._latest_hash is not None:
                raise ChainError("begin_chain called but chain already has state.")
            if any(self._chain_dir.iterdir()):
                raise ChainError(f"begin_chain refused: {self._chain_dir} is not empty.")
            genesis_meta: dict[str, Any] = dict(metadata) if metadata else {}
            if research_brief is not None:
                if "research_brief" in genesis_meta:
                    raise ValueError(
                        "research_brief is reserved at GENESIS; do not include "
                        "it in metadata when also passing research_brief.",
                    )
                genesis_meta["research_brief"] = research_brief

            record, entry_hash, record_path = await asyncio.to_thread(
                self._build_sign_and_write,
                step_index=0,
                step_type=StepType.GENESIS,
                content_file_hashes={},
                metadata=genesis_meta,
                previous_hash=None,
            )
            self._latest_step = 0
            self._latest_hash = entry_hash
            return GenesisReceipt(
                step_index=0,
                step_type=StepType.GENESIS,
                entry_hash=entry_hash,
                previous_hash=None,
                record_path=record_path,
                timestamp=record.timestamp,
            )

    async def seal(
        self,
        *,
        step_type: str,
        content_file_paths: list[str | Path],
        metadata: dict[str, Any],
    ) -> SealReceipt:
        """Seal a step: hash content files, build + sign record, write atomically."""
        if step_type == StepType.GENESIS:
            raise ValueError("Use begin_chain() for GENESIS records.")
        async with self._lock:
            if self._latest_hash is None:
                raise ChainError("No genesis record found. Call begin_chain() first.")

            content_hashes: dict[str, str] = {}
            for raw_path in content_file_paths:
                abs_path, rel = self._resolve_content_path_and_rel(raw_path)
                if rel.startswith(f"{_CHAIN_DIR_NAME}/"):
                    raise ChainError(
                        f"Content files may not live under {_CHAIN_DIR_NAME}/: {rel}",
                    )
                digest = await asyncio.to_thread(_sha256_file, abs_path)
                content_hashes[rel] = digest

            next_step = self._latest_step + 1
            record, entry_hash, record_path = await asyncio.to_thread(
                self._build_sign_and_write,
                step_index=next_step,
                step_type=step_type,
                content_file_hashes=content_hashes,
                metadata=metadata,
                previous_hash=self._latest_hash,
            )
            self._latest_step = next_step
            self._latest_hash = entry_hash
            return SealReceipt(
                step_index=next_step,
                step_type=step_type,
                entry_hash=entry_hash,
                previous_hash=record.previous_hash,
                record_path=record_path,
                timestamp=record.timestamp,
            )

    async def verify_chain(self) -> VerificationReport:
        """Re-verify the chain from disk, ignoring in-memory state."""
        return await asyncio.to_thread(self._verify_chain_sync)

    def _resolve_content_path_and_rel(self, path: str | Path) -> tuple[Path, str]:
        """Return ``(abs_path_to_read, relative_path_to_record)``.

        Caller-supplied **relative** paths are recorded verbatim after
        being validated as safe POSIX paths under the workspace; symlinks
        are followed only when reading content. Caller-supplied
        **absolute** paths are resolved (following symlinks) and stored
        relative to the workspace.
        """
        p = Path(path)
        if p.is_absolute():
            try:
                rel_path = p.resolve().relative_to(self._workspace)
            except ValueError as exc:
                raise ChainError(
                    f"Content file {p} is outside workspace {self._workspace}",
                ) from exc
            rel = rel_path.as_posix()
            abs_path = p
        else:
            rel = p.as_posix()
            if not is_safe_relative_path(rel):
                raise ChainError(
                    f"Content path is not a safe relative path: {path!r}",
                )
            abs_path = self._workspace / p
        if not abs_path.is_file():
            raise FileNotFoundError(f"Content file not found: {abs_path}")
        return abs_path, rel

    def _build_sign_and_write(
        self,
        *,
        step_index: int,
        step_type: str,
        content_file_hashes: dict[str, str],
        metadata: dict[str, Any],
        previous_hash: str | None,
    ) -> tuple[ChainRecord, str, Path]:
        timestamp = datetime.now(UTC).isoformat()
        signing_target = {
            "sdk_version": _SDK_VERSION,
            "run_id": self._run_id,
            "step_index": step_index,
            "step_type": step_type,
            "content_file_hashes": content_file_hashes,
            "metadata": metadata,
            "previous_hash": previous_hash,
            "timestamp": timestamp,
        }
        target_bytes = canonical_json_bytes(signing_target)
        signature = self._signer.sign(target_bytes)
        signer_fp = getattr(self._signer, "public_key_fingerprint", None)
        if signer_fp is not None and signature.public_key_fingerprint != signer_fp:
            raise ChainError(
                f"Signer fingerprint mismatch: signer advertises {signer_fp!r}, "
                f"signature embeds {signature.public_key_fingerprint!r}",
            )
        record = ChainRecord(
            sdk_version=_SDK_VERSION,
            run_id=self._run_id,
            step_index=step_index,
            step_type=step_type,
            content_file_hashes=content_file_hashes,
            metadata=metadata,
            previous_hash=previous_hash,
            timestamp=timestamp,
            signature=signature,
        )
        record_dict = record.model_dump(mode="json")
        record_canonical = canonical_json_bytes(record_dict)
        entry_hash = _compute_entry_hash(record_canonical)

        filename = f"{step_index:06d}_{step_type}.json"
        path = self._chain_dir / filename
        try:
            with self._file_lock:
                if path.exists():
                    raise ChainSequenceError(
                        f"Refusing to overwrite chain record: {path}",
                    )
                self._atomic_write_bytes(path, record_canonical)
        except Timeout as exc:
            raise ChainError(
                f"Could not acquire chain file lock within "
                f"{self._file_lock_timeout_s}s: {self._file_lock.lock_file}",
            ) from exc
        return record, entry_hash, path

    def _atomic_write_bytes(self, path: Path, data: bytes) -> None:
        """Write ``data`` to ``path`` atomically via a uniquely-named tmp file.

        Uses ``tempfile.mkstemp`` to avoid colliding with stale ``.tmp``
        files from prior crashed writes. Cleans up the tmp file on
        failure.
        """
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._chain_dir),
            prefix=f"{path.stem}.",
            suffix=".json.tmp",
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                with contextlib.suppress(OSError):
                    os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            if tmp.exists():
                with contextlib.suppress(OSError):
                    tmp.unlink()
            raise

    def _verify_chain_sync(self) -> VerificationReport:
        verifications: list[StepVerification] = []
        chain_intact = True
        first_error: int | None = None
        expected_prev: str | None = None
        run_id_seen: str | None = None

        for idx, (path, record_bytes) in enumerate(self._iter_chain_records()):
            errors: list[str] = []
            signature_valid = False
            content_hashes_valid = False
            previous_hash_matches = False
            canonical_form_valid = False
            parsed_step_type = ""
            parsed_step_index = idx

            record: ChainRecord | None = None
            try:
                record_dict = json.loads(record_bytes.decode("utf-8"))
                record = ChainRecord.model_validate(record_dict)
                parsed_step_type = record.step_type
                parsed_step_index = record.step_index
            except Exception as exc:
                errors.append(f"Parse/validate error: {exc}")

            if record is not None:
                canon = canonical_json_bytes(record.model_dump(mode="json"))
                canonical_form_valid = canon == record_bytes
                if not canonical_form_valid:
                    errors.append(
                        "Record on disk is not in canonical form "
                        "(tampering or non-canonical writer).",
                    )

                signing_target = {
                    "sdk_version": record.sdk_version,
                    "run_id": record.run_id,
                    "step_index": record.step_index,
                    "step_type": record.step_type,
                    "content_file_hashes": record.content_file_hashes,
                    "metadata": record.metadata,
                    "previous_hash": record.previous_hash,
                    "timestamp": record.timestamp,
                }
                try:
                    target_bytes = canonical_json_bytes(signing_target)
                    signature_valid = self._verifier.verify(target_bytes, record.signature)
                    if not signature_valid:
                        errors.append("Signature verification failed.")
                except Exception as exc:
                    errors.append(f"Signature verify raised: {exc}")

                if record.run_id != self._run_id:
                    errors.append(
                        f"run_id mismatch: engine expects {self._run_id!r}, "
                        f"record has {record.run_id!r}",
                    )

                content_hashes_valid = True
                for rel, expected in record.content_file_hashes.items():
                    if not is_safe_relative_path(rel):
                        errors.append(f"Unsafe content path in record: {rel!r}")
                        content_hashes_valid = False
                        continue
                    abs_path = self._workspace / rel
                    if not abs_path.is_file():
                        errors.append(f"Content file missing: {rel}")
                        content_hashes_valid = False
                        continue
                    actual = _sha256_file(abs_path)
                    if actual != expected:
                        errors.append(
                            f"Content hash mismatch for {rel}: expected {expected}, got {actual}",
                        )
                        content_hashes_valid = False

                if idx == 0:
                    if record.step_type != StepType.GENESIS:
                        errors.append(
                            f"First record must be {StepType.GENESIS!r}, got {record.step_type!r}",
                        )
                    previous_hash_matches = record.previous_hash is None
                    if not previous_hash_matches:
                        errors.append("Genesis record must have previous_hash=null.")
                else:
                    if record.step_type == StepType.GENESIS:
                        errors.append(
                            f"{StepType.GENESIS!r} only allowed at step 0, saw at step {idx}",
                        )
                    previous_hash_matches = record.previous_hash == expected_prev
                    if not previous_hash_matches:
                        errors.append(
                            f"previous_hash mismatch: record={record.previous_hash!r} "
                            f"expected={expected_prev!r}",
                        )

                if record.step_index != idx:
                    errors.append(
                        f"step_index mismatch: file position {idx}, record {record.step_index}",
                    )

                if run_id_seen is None:
                    run_id_seen = record.run_id
                elif record.run_id != run_id_seen:
                    errors.append(
                        f"run_id mismatch inside chain: saw {run_id_seen!r} then {record.run_id!r}",
                    )

                # Always derive the next link from the canonical bytes.
                # Non-canonical on-disk records fail at this step's
                # canonical_form check; the next record's previous_hash
                # was written against the canonical form, so we want to
                # compare against that too rather than cascading errors.
                expected_prev = _compute_entry_hash(canon)
            else:
                expected_prev = None

            step_ok = (
                record is not None
                and signature_valid
                and content_hashes_valid
                and previous_hash_matches
                and canonical_form_valid
                and not errors
            )
            if not step_ok:
                chain_intact = False
                if first_error is None:
                    first_error = idx

            verifications.append(
                StepVerification(
                    step_index=parsed_step_index,
                    step_type=parsed_step_type,
                    record_path=path,
                    signature_valid=signature_valid,
                    content_hashes_valid=content_hashes_valid,
                    previous_hash_matches=previous_hash_matches,
                    canonical_form_valid=canonical_form_valid,
                    errors=errors,
                ),
            )

        return VerificationReport(
            run_id=run_id_seen or self._run_id,
            chain_intact=chain_intact,
            total_steps=len(verifications),
            steps=verifications,
            first_error_index=first_error,
        )

    def _iter_chain_records(self) -> Iterator[tuple[Path, bytes]]:
        records: list[tuple[int, Path]] = []
        for p in self._chain_dir.iterdir():
            if not p.is_file() or not p.name.endswith(".json"):
                continue
            m = _RECORD_FILENAME_RE.match(p.name)
            if not m:
                _LOGGER.warning("Unrecognized file in chain dir, ignoring: %s", p.name)
                continue
            records.append((int(m.group(1)), p))
        records.sort(key=lambda t: t[0])
        for _idx, p in records:
            yield p, p.read_bytes()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def _compute_entry_hash(record_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(record_bytes).hexdigest()


class _VerifyOnlySigner:
    """Placeholder Signer for stateless verification.

    Sentinel fingerprint of all-zeros has negligible collision probability
    with any real key. ``sign`` raises to prevent accidental use.
    """

    public_key_fingerprint = _VERIFY_ONLY_FINGERPRINT

    def sign(self, data: bytes) -> NoReturn:
        raise RuntimeError("Verification-only engine cannot sign.")


async def verify_chain(
    workspace: Path,
    run_id: str,
    *,
    verifier: Verifier,
) -> VerificationReport:
    """Stateless chain verification. Does not require a functional Signer."""
    engine = SealEngine(
        workspace=Path(workspace).resolve(),
        run_id=run_id,
        signer=_VerifyOnlySigner(),
        verifier=verifier,
    )
    return await engine.verify_chain()
