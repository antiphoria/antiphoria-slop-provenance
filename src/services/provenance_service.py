"""Core provenance service for anchoring and trusted timestamping."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pygit2
from filelock import FileLock

from src.env_config import read_env_bool, read_env_optional
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.ots_adapter import OTSAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter, TimestampVerification
from src.adapters.transparency_log import TransparencyLogAdapter, TransparencyLogEntry
from src.models import Artifact, sha256_hex
from src.events import StoryOtsPending
from src.parsing import parse_artifact_markdown, parse_artifact_markdown_text
from src.repository import SQLiteRepository

_logger = logging.getLogger(__name__)
_BRANCH_LOG_PATH = ".provenance/transparency-log.jsonl"


def _sanitize_for_log(raw: str, max_len: int = 200) -> str:
    """Truncate and redact secret-like substrings before logging."""
    if not raw:
        return raw
    out = re.sub(
        r"(Bearer|apikey|Authorization)[=:\s]+[^\s]+",
        r"\1=***",
        raw,
        flags=re.IGNORECASE,
    )
    return out[:max_len] + "..." if len(out) > max_len else out
_DEFAULT_LEDGER_AUTHOR_NAME = "Slop Orchestrator"
_DEFAULT_LEDGER_AUTHOR_EMAIL = "bot@antiphoria.local"


@dataclass(frozen=True)
class AnchorOutcome:
    """Transparency anchoring outcome payload."""

    entry_id: str
    entry_hash: str
    artifact_hash: str
    artifact_id: str
    anchored_at: str
    log_path: str


@dataclass(frozen=True)
class TimestampOutcome:
    """Timestamping outcome payload."""

    created_at: str
    tsa_url: str
    digest_algorithm: str
    verification: TimestampVerification
    token_base64: str | None = None
    story_ots_pending: StoryOtsPending | None = None


class ProvenanceService:
    """Coordinates provenance anchoring, timestamping, and key registration."""

    def __init__(
        self,
        repository: SQLiteRepository,
        transparency_log_adapter: TransparencyLogAdapter,
        tsa_adapter: RFC3161TSAAdapter | None,
        key_registry: KeyRegistryAdapter,
        ots_adapter: OTSAdapter | None = None,
        env_path: Path | None = None,
    ) -> None:
        self._repository = repository
        self._transparency_log_adapter = transparency_log_adapter
        self._tsa_adapter = tsa_adapter
        self._key_registry = key_registry
        self._ots_adapter = ots_adapter
        self._env_path = env_path

    def register_signing_key(
        self,
        signer_fingerprint: str,
        key_version: str | None,
    ) -> None:
        """Register signing key metadata in the local key registry."""

        metadata = json.dumps({"managedBy": "slop-orchestrator"})
        self._key_registry.register_key(
            fingerprint=signer_fingerprint,
            key_version=key_version,
            status="active",
            metadata_json=metadata,
        )

    def anchor_artifact(
        self,
        artifact_path: Path,
        request_id: UUID | None,
        repository_path: Path | None = None,
    ) -> AnchorOutcome:
        """Anchor one artifact hash and commit to branch when request_id + repo given."""

        if request_id is not None and repository_path is not None:
            return self._anchor_artifact_and_commit(
                artifact_path=artifact_path,
                request_id=request_id,
                repository_path=repository_path,
            )
        envelope, payload = parse_artifact_markdown(artifact_path)
        source_file = self._repo_relative_path(artifact_path, repository_path)
        entry = self._anchor_parsed_artifact(
            envelope=envelope,
            payload=payload,
            source_file=source_file or str(artifact_path),
            request_id=request_id,
        )
        self._repository.create_transparency_log_record(
            entry_id=entry.entry_id,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            request_id=entry.request_id,
            source_file=entry.source_file,
            log_path=str(self._transparency_log_adapter.log_path),
            previous_entry_hash=entry.previous_entry_hash,
            entry_hash=entry.entry_hash,
            published_at=entry.anchored_at,
            remote_receipt=entry.remote_receipt,
        )
        return AnchorOutcome(
            entry_id=entry.entry_id,
            entry_hash=entry.entry_hash,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            anchored_at=entry.anchored_at,
            log_path=str(self._transparency_log_adapter.log_path),
        )

    def _anchor_artifact_and_commit(
        self,
        artifact_path: Path,
        request_id: UUID,
        repository_path: Path,
    ) -> AnchorOutcome:
        """Anchor artifact from file and commit to artifact branch (idempotent)."""

        envelope, payload = parse_artifact_markdown(artifact_path)
        artifact_hash = sha256_hex(payload.encode("utf-8"))
        self._assert_artifact_hash_matches_signature(
            artifact_hash=artifact_hash,
            signature_artifact_hash=(
                None if envelope.signature is None else envelope.signature.artifact_hash
            ),
        )
        ledger_path = f"{request_id}.md"
        branch_ref = f"refs/heads/artifact/{request_id}"
        existing_log = self._read_branch_file(
            repository_path=repository_path,
            ref_name=branch_ref,
            relative_path=_BRANCH_LOG_PATH,
        )
        entries = self._transparency_log_adapter.parse_entries_from_jsonl(
            existing_log
        )
        matches = [e for e in entries if e.artifact_hash == artifact_hash]
        if matches:
            last = matches[-1]
            return AnchorOutcome(
                entry_id=last.entry_id,
                entry_hash=last.entry_hash,
                artifact_hash=last.artifact_hash,
                artifact_id=last.artifact_id,
                anchored_at=last.anchored_at,
                log_path=_BRANCH_LOG_PATH,
            )
        previous_entry_hash = self._resolve_previous_entry_hash(
            repository_path, existing_log
        )
        entry, serializable = self._transparency_log_adapter.build_entry_record(
            artifact_hash=artifact_hash,
            artifact_id=str(envelope.id),
            source_file=ledger_path,
            previous_entry_hash=previous_entry_hash,
            request_id=str(request_id),
            metadata={"source": envelope.provenance.source},
            skip_remote=True,
        )
        next_log_content = f"{existing_log}{json.dumps(serializable, sort_keys=True)}\n"
        self._commit_branch_file(
            repository_path=repository_path,
            ref_name=branch_ref,
            relative_path=_BRANCH_LOG_PATH,
            payload_text=next_log_content,
            commit_message=f"provenance: append transparency anchor ({request_id})",
        )
        remote_receipt = self._transparency_log_adapter.publish_entry(serializable)
        self._repository.create_transparency_log_record(
            entry_id=entry.entry_id,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            request_id=entry.request_id,
            source_file=entry.source_file,
            log_path=_BRANCH_LOG_PATH,
            previous_entry_hash=entry.previous_entry_hash,
            entry_hash=entry.entry_hash,
            published_at=entry.anchored_at,
            remote_receipt=remote_receipt,
        )
        return AnchorOutcome(
            entry_id=entry.entry_id,
            entry_hash=entry.entry_hash,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            anchored_at=entry.anchored_at,
            log_path=_BRANCH_LOG_PATH,
        )

    @staticmethod
    def _repo_relative_path(artifact_path: Path, repository_path: Path | None) -> str | None:
        """Return artifact path relative to repository root, or None if not under repo."""
        if repository_path is None:
            return None
        try:
            return str(artifact_path.resolve().relative_to(repository_path.resolve()))
        except ValueError:
            return None

    def anchor_committed_artifact(
        self,
        repository_path: Path,
        commit_oid: str,
        ledger_path: str,
        request_id: UUID,
    ) -> AnchorOutcome:
        """Anchor one artifact from a branch commit without touching worktree."""

        markdown_text = self._read_markdown_from_commit(
            repository_path=repository_path,
            commit_oid=commit_oid,
            ledger_path=ledger_path,
        )
        envelope, payload = parse_artifact_markdown_text(markdown_text)
        artifact_hash = sha256_hex(payload.encode("utf-8"))
        self._assert_artifact_hash_matches_signature(
            artifact_hash=artifact_hash,
            signature_artifact_hash=(
                None
                if envelope.signature is None
                else envelope.signature.artifact_hash
            ),
        )

        branch_ref = f"refs/heads/artifact/{request_id}"
        existing_log = self._read_branch_file(
            repository_path=repository_path,
            ref_name=branch_ref,
            relative_path=_BRANCH_LOG_PATH,
        )
        entries = self._transparency_log_adapter.parse_entries_from_jsonl(
            existing_log
        )
        matches = [e for e in entries if e.artifact_hash == artifact_hash]
        if matches:
            last = matches[-1]
            return AnchorOutcome(
                entry_id=last.entry_id,
                entry_hash=last.entry_hash,
                artifact_hash=last.artifact_hash,
                artifact_id=last.artifact_id,
                anchored_at=last.anchored_at,
                log_path=_BRANCH_LOG_PATH,
            )
        previous_entry_hash = self._resolve_previous_entry_hash(
            repository_path, existing_log
        )
        entry, serializable = self._transparency_log_adapter.build_entry_record(
            artifact_hash=artifact_hash,
            artifact_id=str(envelope.id),
            source_file=ledger_path,
            previous_entry_hash=previous_entry_hash,
            request_id=str(request_id),
            metadata={"source": envelope.provenance.source},
            skip_remote=True,
        )
        next_log_content = f"{existing_log}{json.dumps(serializable, sort_keys=True)}\n"
        self._commit_branch_file(
            repository_path=repository_path,
            ref_name=branch_ref,
            relative_path=_BRANCH_LOG_PATH,
            payload_text=next_log_content,
            commit_message=f"provenance: append transparency anchor ({request_id})",
        )
        remote_receipt = self._transparency_log_adapter.publish_entry(serializable)
        self._repository.create_transparency_log_record(
            entry_id=entry.entry_id,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            request_id=entry.request_id,
            source_file=entry.source_file,
            log_path=_BRANCH_LOG_PATH,
            previous_entry_hash=entry.previous_entry_hash,
            entry_hash=entry.entry_hash,
            published_at=entry.anchored_at,
            remote_receipt=remote_receipt,
        )
        return AnchorOutcome(
            entry_id=entry.entry_id,
            entry_hash=entry.entry_hash,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            anchored_at=entry.anchored_at,
            log_path=_BRANCH_LOG_PATH,
        )

    def timestamp_artifact(
        self,
        artifact_path: Path,
        request_id: UUID | None,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> TimestampOutcome:
        """Acquire and verify RFC3161 token for one artifact hash."""

        envelope, payload = parse_artifact_markdown(artifact_path)
        return self._timestamp_parsed_artifact(
            envelope_id=str(envelope.id),
            payload=payload,
            request_id=request_id,
            tsa_ca_cert_path=tsa_ca_cert_path,
            digest_algorithm=digest_algorithm,
        )

    def timestamp_committed_artifact(
        self,
        repository_path: Path,
        commit_oid: str,
        ledger_path: str,
        request_id: UUID | None,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> TimestampOutcome:
        """Timestamp one artifact from a branch commit without worktree writes.

        Writes the .tsr token to the Git ledger at .provenance/timestamp-<request_id>.tsr
        so verification does not depend solely on SQLite.
        """

        markdown_text = self._read_markdown_from_commit(
            repository_path=repository_path,
            commit_oid=commit_oid,
            ledger_path=ledger_path,
        )
        envelope, payload = parse_artifact_markdown_text(markdown_text)
        outcome = self._timestamp_parsed_artifact(
            envelope_id=str(envelope.id),
            payload=payload,
            request_id=request_id,
            tsa_ca_cert_path=tsa_ca_cert_path,
            digest_algorithm=digest_algorithm,
        )
        if (
            outcome.token_base64 is not None
            and request_id is not None
        ):
            ref_name = f"refs/heads/artifact/{request_id}"

            # 1. Commit the TSR sidecar (legacy compat)
            ts_path = f".provenance/timestamp-{request_id}.tsr"
            self._commit_branch_file(
                repository_path=repository_path,
                ref_name=ref_name,
                relative_path=ts_path,
                payload_text=outcome.token_base64,
                commit_message=f"provenance: add RFC3161 timestamp sidecar ({request_id})",
            )

            # 2. Fast-follow: inject into the monolithic .md file
            current_md = self._read_markdown_from_commit(
                repository_path=repository_path,
                commit_oid=commit_oid,
                ledger_path=ledger_path,
            )

            # Hardened idempotency: search only in tail after signature (defeat payload injection)
            signature_end_marker = "-----END ANTIPHORIA ARTIFACT SIGNATURE-----"
            if signature_end_marker in current_md:
                tail = current_md.split(signature_end_marker)[-1]
                if "-----BEGIN RFC3161 TIMESTAMP TOKEN-----" not in tail:
                    wrapped_token = "\n".join(
                        textwrap.wrap(outcome.token_base64, width=76)
                    )
                    monolithic_md = (
                        f"{current_md}\n"
                        "-----BEGIN RFC3161 TIMESTAMP TOKEN-----\n"
                        f"{wrapped_token}\n"
                        "-----END RFC3161 TIMESTAMP TOKEN-----\n"
                    )
                    self._commit_branch_file(
                        repository_path=repository_path,
                        ref_name=ref_name,
                        relative_path=ledger_path,
                        payload_text=monolithic_md,
                        commit_message=f"provenance: bake RFC3161 token into artifact ({request_id})",
                    )

            # OTS stamp (gated by ENABLE_OTS_FORGE)
            story_ots_pending: StoryOtsPending | None = None
            if (
                request_id is not None
                and self._ots_adapter is not None
                and read_env_bool("ENABLE_OTS_FORGE", default=False, env_path=self._env_path)
            ):
                try:
                    payload_bytes = payload.encode("utf-8")
                    artifact_hash = sha256_hex(payload_bytes)
                    ots_bytes = self._ots_adapter.request_ots_stamp(payload_bytes)
                    pending_b64 = base64.b64encode(ots_bytes).decode("ascii")
                    self._repository.create_ots_forge_record(
                        request_id=request_id,
                        artifact_hash=artifact_hash,
                        pending_ots_b64=pending_b64,
                    )
                    ots_path = f".provenance/ots-{request_id}.ots"
                    self._commit_branch_file_bytes(
                        repository_path=repository_path,
                        ref_name=ref_name,
                        relative_path=ots_path,
                        payload_bytes=ots_bytes,
                        commit_message=f"provenance: add OTS pending proof ({request_id})",
                    )
                    story_ots_pending = StoryOtsPending(
                        request_id=request_id,
                        artifact_hash=artifact_hash,
                        pending_ots_b64=pending_b64,
                    )
                except Exception as exc:
                    _logger.warning(
                        "OTS stamp skipped for request_id=%s (e.g. OpenSSL/bitcoinlib on Windows): %s",
                        request_id,
                        _sanitize_for_log(str(exc)),
                    )

            if story_ots_pending is not None:
                return TimestampOutcome(
                    created_at=outcome.created_at,
                    tsa_url=outcome.tsa_url,
                    digest_algorithm=outcome.digest_algorithm,
                    verification=outcome.verification,
                    token_base64=outcome.token_base64,
                    story_ots_pending=story_ots_pending,
                )
        return outcome

    def _timestamp_parsed_artifact(
        self,
        envelope_id: str,
        payload: str,
        request_id: UUID | None,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> TimestampOutcome:
        """Acquire and verify RFC3161 token for an already parsed payload."""

        if self._tsa_adapter is None:
            raise RuntimeError("TSA adapter is not configured.")
        artifact_hash = sha256_hex(payload.encode("utf-8"))
        token_bytes = self._tsa_adapter.request_timestamp_token(
            digest_hex=artifact_hash,
            digest_algorithm=digest_algorithm,
        )
        verification = self._tsa_adapter.verify_timestamp_token(
            digest_hex=artifact_hash,
            token_bytes=token_bytes,
            tsa_ca_cert_path=tsa_ca_cert_path,
            digest_algorithm=digest_algorithm,
        )
        encoded_token = base64.b64encode(token_bytes).decode("ascii")
        created_at = self._repository.create_timestamp_record(
            artifact_hash=artifact_hash,
            artifact_id=envelope_id,
            request_id=None if request_id is None else str(request_id),
            tsa_url=self._tsa_adapter.tsa_url or "",
            token_base64=encoded_token,
            digest_algorithm=digest_algorithm,
            verification_status="verified" if verification.ok else "failed",
            verification_message=verification.message,
        )
        return TimestampOutcome(
            created_at=created_at,
            tsa_url=self._tsa_adapter.tsa_url or "",
            digest_algorithm=digest_algorithm,
            verification=verification,
            token_base64=encoded_token,
        )

    def _anchor_parsed_artifact(
        self,
        envelope: Artifact,
        payload: str,
        source_file: str,
        request_id: UUID | None,
    ) -> TransparencyLogEntry:
        artifact_hash = sha256_hex(payload.encode("utf-8"))
        signature_artifact_hash: str | None = None
        if envelope.signature is not None:
            signature_artifact_hash = envelope.signature.artifact_hash
        self._assert_artifact_hash_matches_signature(
            artifact_hash=artifact_hash,
            signature_artifact_hash=signature_artifact_hash,
        )
        matches = self._transparency_log_adapter.find_entries_by_artifact_hash(
            artifact_hash
        )
        if matches:
            return matches[-1]
        return self._transparency_log_adapter.append_entry(
            artifact_hash=artifact_hash,
            artifact_id=str(envelope.id),
            source_file=source_file,
            request_id=None if request_id is None else str(request_id),
            metadata={"source": envelope.provenance.source},
        )

    @staticmethod
    def _assert_artifact_hash_matches_signature(
        artifact_hash: str,
        signature_artifact_hash: str | None,
    ) -> None:
        if signature_artifact_hash is None:
            raise RuntimeError("Artifact envelope is missing signature block.")
        if artifact_hash != signature_artifact_hash:
            raise RuntimeError(
                "Artifact hash mismatch for transparency anchor request."
            )

    def get_artifact_payload_bytes_from_branch(
        self,
        repository_path: Path,
        request_id: UUID,
        ledger_path: str,
    ) -> bytes | None:
        """Read artifact payload bytes from branch head for OTS verification.

        Returns None if branch or artifact not found.
        """
        ref_name = f"refs/heads/artifact/{request_id}"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
        except (KeyError, pygit2.GitError):
            return None
        if not isinstance(commit_obj, pygit2.Commit):
            return None
        try:
            tree_entry = commit_obj.tree[ledger_path]
        except KeyError:
            return None
        blob_obj = repo[tree_entry.id]
        if not isinstance(blob_obj, pygit2.Blob):
            return None
        markdown_text = bytes(blob_obj.data).decode("utf-8")
        _, payload = parse_artifact_markdown_text(markdown_text)
        return payload.encode("utf-8")

    @staticmethod
    def _read_markdown_from_commit(
        repository_path: Path,
        commit_oid: str,
        ledger_path: str,
    ) -> str:
        try:
            repo = pygit2.Repository(str(repository_path))
            commit_obj = repo.revparse_single(commit_oid)
        except (KeyError, pygit2.GitError) as exc:
            raise RuntimeError(
                f"Unable to load commit '{commit_oid}' in '{repository_path}'."
            ) from exc
        if not isinstance(commit_obj, pygit2.Commit):
            raise RuntimeError(f"Object '{commit_oid}' is not a commit.")
        try:
            tree_entry = commit_obj.tree[ledger_path]
        except KeyError as exc:
            raise RuntimeError(
                f"Committed artifact path '{ledger_path}' not found in commit."
            ) from exc
        blob_obj = repo[tree_entry.id]
        if not isinstance(blob_obj, pygit2.Blob):
            raise RuntimeError(
                f"Committed artifact path '{ledger_path}' does not resolve to a blob."
            )
        return bytes(blob_obj.data).decode("utf-8")

    @staticmethod
    def _read_branch_file(
        repository_path: Path,
        ref_name: str,
        relative_path: str,
    ) -> str:
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
        except (KeyError, pygit2.GitError) as exc:
            raise RuntimeError(
                f"Unable to open branch ref '{ref_name}' in '{repository_path}'."
            ) from exc
        commit_obj = repo[reference.target]
        if not isinstance(commit_obj, pygit2.Commit):
            raise RuntimeError(f"Branch ref '{ref_name}' does not point to a commit.")
        try:
            tree_entry = commit_obj.tree[relative_path]
        except KeyError:
            return ""
        blob_obj = repo[tree_entry.id]
        if not isinstance(blob_obj, pygit2.Blob):
            raise RuntimeError(
                f"Branch path '{relative_path}' does not resolve to a blob."
            )
        return bytes(blob_obj.data).decode("utf-8")

    @staticmethod
    def _read_latest_entry_hash(log_content: str) -> str | None:
        for raw in reversed(log_content.splitlines()):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                loaded = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            entry_hash = loaded.get("entryHash")
            if entry_hash is None:
                return None
            return str(entry_hash)
        return None

    def _resolve_previous_entry_hash(
        self,
        repository_path: Path,
        branch_log_content: str,
    ) -> str | None:
        """Resolve previous entry hash from global ref, then branch-local fallback."""
        global_ref = read_env_optional(
            "TRANSPARENCY_LOG_GLOBAL_REF",
            env_path=self._env_path,
        ) or "refs/heads/main"
        global_log = ""
        try:
            global_log = self._read_branch_file(
                repository_path=repository_path,
                ref_name=global_ref,
                relative_path=_BRANCH_LOG_PATH,
            )
        except RuntimeError:
            pass
        return (
            self._read_latest_entry_hash(global_log)
            or self._read_latest_entry_hash(branch_log_content)
        )

    def _commit_branch_file(
        self,
        repository_path: Path,
        ref_name: str,
        relative_path: str,
        payload_text: str,
        commit_message: str,
    ) -> None:
        repo_hash = hashlib.sha256(
            str(repository_path.resolve()).encode()
        ).hexdigest()[:16]
        lock_dir = Path(tempfile.gettempdir()) / "slop-orchestrator" / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = lock_dir / f"{repo_hash}_{ref_name.replace('/', '_')}.lock"
        with FileLock(lock_path):
            self._commit_branch_file_impl(
                repository_path=repository_path,
                ref_name=ref_name,
                relative_path=relative_path,
                payload_text=payload_text,
                commit_message=commit_message,
            )

    def _commit_branch_file_bytes(
        self,
        repository_path: Path,
        ref_name: str,
        relative_path: str,
        payload_bytes: bytes,
        commit_message: str,
    ) -> None:
        """Commit binary blob to branch (e.g. .ots files)."""

        repo_hash = hashlib.sha256(
            str(repository_path.resolve()).encode()
        ).hexdigest()[:16]
        lock_dir = Path(tempfile.gettempdir()) / "slop-orchestrator" / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = lock_dir / f"{repo_hash}_{ref_name.replace('/', '_')}.lock"
        with FileLock(lock_path):
            self._commit_branch_file_bytes_impl(
                repository_path=repository_path,
                ref_name=ref_name,
                relative_path=relative_path,
                payload_bytes=payload_bytes,
                commit_message=commit_message,
            )

    def _commit_branch_file_impl(
        self,
        repository_path: Path,
        ref_name: str,
        relative_path: str,
        payload_text: str,
        commit_message: str,
    ) -> None:
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
        except (KeyError, pygit2.GitError) as exc:
            raise RuntimeError(
                f"Unable to open branch ref '{ref_name}' in '{repository_path}'."
            ) from exc

        parent_commit = repo[reference.target]
        if not isinstance(parent_commit, pygit2.Commit):
            raise RuntimeError(f"Branch ref '{ref_name}' does not point to a commit.")

        path_obj = Path(relative_path)
        path_parts = path_obj.parts
        if not path_parts:
            raise RuntimeError("Invalid empty branch path.")

        blob_oid = repo.create_blob(payload_text.encode("utf-8"))

        current_tree: pygit2.Tree | None = parent_commit.tree
        tree_stack: list[pygit2.Tree | None] = [current_tree]

        # Traverse down, guarding against NoneType when walking missing nested dirs
        for part in path_parts[:-1]:
            if current_tree is not None and part in current_tree:
                entry = current_tree[part]
                current_tree = repo[entry.id]
                if not isinstance(current_tree, pygit2.Tree):
                    raise RuntimeError(
                        f"Path part '{part}' exists but is not a directory."
                    )
            else:
                current_tree = None
            tree_stack.append(current_tree)

        current_oid = blob_oid
        current_mode = pygit2.GIT_FILEMODE_BLOB

        # Build back up
        for i, part in reversed(list(enumerate(path_parts))):
            tb = (
                repo.TreeBuilder(tree_stack[i])
                if tree_stack[i] is not None
                else repo.TreeBuilder()
            )
            tb.insert(part, current_oid, current_mode)
            current_oid = tb.write()
            current_mode = pygit2.GIT_FILEMODE_TREE

        if parent_commit and current_oid == parent_commit.tree_id:
            return

        signature = self._resolve_commit_signature(repo, self._env_path)
        repo.create_commit(
            ref_name,
            signature,
            signature,
            commit_message,
            current_oid,
            [parent_commit.id],
        )

    def _commit_branch_file_bytes_impl(
        self,
        repository_path: Path,
        ref_name: str,
        relative_path: str,
        payload_bytes: bytes,
        commit_message: str,
    ) -> None:
        """Inner commit logic for binary blobs (caller holds FileLock)."""

        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
        except (KeyError, pygit2.GitError) as exc:
            raise RuntimeError(
                f"Unable to open branch ref '{ref_name}' in '{repository_path}'."
            ) from exc

        parent_commit = repo[reference.target]
        if not isinstance(parent_commit, pygit2.Commit):
            raise RuntimeError(f"Branch ref '{ref_name}' does not point to a commit.")

        path_obj = Path(relative_path)
        path_parts = path_obj.parts
        if not path_parts:
            raise RuntimeError("Invalid empty branch path.")

        blob_oid = repo.create_blob(payload_bytes)

        current_tree: pygit2.Tree | None = parent_commit.tree
        tree_stack: list[pygit2.Tree | None] = [current_tree]

        # Traverse down, guarding against NoneType when walking missing nested dirs
        for part in path_parts[:-1]:
            if current_tree is not None and part in current_tree:
                entry = current_tree[part]
                current_tree = repo[entry.id]
                if not isinstance(current_tree, pygit2.Tree):
                    raise RuntimeError(
                        f"Path part '{part}' exists but is not a directory."
                    )
            else:
                current_tree = None
            tree_stack.append(current_tree)

        current_oid = blob_oid
        current_mode = pygit2.GIT_FILEMODE_BLOB

        # Build back up
        for i, part in reversed(list(enumerate(path_parts))):
            tb = (
                repo.TreeBuilder(tree_stack[i])
                if tree_stack[i] is not None
                else repo.TreeBuilder()
            )
            tb.insert(part, current_oid, current_mode)
            current_oid = tb.write()
            current_mode = pygit2.GIT_FILEMODE_TREE

        if parent_commit and current_oid == parent_commit.tree_id:
            return

        signature = self._resolve_commit_signature(repo, self._env_path)
        repo.create_commit(
            ref_name,
            signature,
            signature,
            commit_message,
            current_oid,
            [parent_commit.id],
        )

    @staticmethod
    def _resolve_commit_signature(
        repo: pygit2.Repository, env_path: Path | None = None
    ) -> pygit2.Signature:
        name = read_env_optional("LEDGER_AUTHOR_NAME", env_path=env_path)
        email = read_env_optional("LEDGER_AUTHOR_EMAIL", env_path=env_path)
        try:
            name = name or repo.config["user.name"]
            email = email or repo.config["user.email"]
        except KeyError:
            name = name or _DEFAULT_LEDGER_AUTHOR_NAME
            email = email or _DEFAULT_LEDGER_AUTHOR_EMAIL
        return pygit2.Signature(name, email)
