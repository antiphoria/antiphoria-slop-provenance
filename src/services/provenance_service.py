"""Core provenance service for anchoring and trusted timestamping."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pygit2
from filelock import FileLock

from src.env_config import read_env_optional
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter, TimestampVerification
from src.adapters.transparency_log import TransparencyLogAdapter, TransparencyLogEntry
from src.models import Artifact, sha256_hex
from src.parsing import parse_artifact_markdown, parse_artifact_markdown_text
from src.repository import SQLiteRepository

_BRANCH_LOG_PATH = ".provenance/transparency-log.jsonl"
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


class ProvenanceService:
    """Coordinates provenance anchoring, timestamping, and key registration."""

    def __init__(
        self,
        repository: SQLiteRepository,
        transparency_log_adapter: TransparencyLogAdapter,
        tsa_adapter: RFC3161TSAAdapter | None,
        key_registry: KeyRegistryAdapter,
        env_path: Path | None = None,
    ) -> None:
        self._repository = repository
        self._transparency_log_adapter = transparency_log_adapter
        self._tsa_adapter = tsa_adapter
        self._key_registry = key_registry
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
        previous_entry_hash = self._read_latest_entry_hash(existing_log)
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
        previous_entry_hash = self._read_latest_entry_hash(existing_log)
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
            ts_path = f".provenance/timestamp-{request_id}.tsr"
            self._commit_branch_file(
                repository_path=repository_path,
                ref_name=ref_name,
                relative_path=ts_path,
                payload_text=outcome.token_base64,
                commit_message=f"provenance: add RFC3161 timestamp ({request_id})",
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
        # Constraint: relative_path must be exactly two levels (e.g. ".provenance/transparency-log.jsonl").
        # Nested paths like ".provenance/subdir/transparency-log.jsonl" are not supported.
        if len(path_parts) != 2:
            raise RuntimeError(
                f"Invalid branch log path '{relative_path}'. "
                "Expected two levels (e.g. .provenance/transparency-log.jsonl)."
            )
        directory_name, filename = path_parts

        root_tb = repo.TreeBuilder(parent_commit.tree)
        subtree_obj: pygit2.Tree | None = None
        try:
            subtree_entry = parent_commit.tree[directory_name]
            subtree_candidate = repo[subtree_entry.id]
            if not isinstance(subtree_candidate, pygit2.Tree):
                raise RuntimeError(
                    f"Path '{directory_name}' exists but is not a directory tree."
                )
            subtree_obj = subtree_candidate
        except KeyError:
            subtree_obj = None

        if subtree_obj is None:
            subtree_tb = repo.TreeBuilder()
        else:
            subtree_tb = repo.TreeBuilder(subtree_obj)
        payload_blob = repo.create_blob(payload_text.encode("utf-8"))
        subtree_tb.insert(filename, payload_blob, pygit2.GIT_FILEMODE_BLOB)
        subtree_oid = subtree_tb.write()
        root_tb.insert(directory_name, subtree_oid, pygit2.GIT_FILEMODE_TREE)
        tree_oid = root_tb.write()
        if tree_oid == parent_commit.tree_id:
            return

        signature = self._resolve_commit_signature(repo, self._env_path)
        repo.create_commit(
            ref_name,
            signature,
            signature,
            commit_message,
            tree_oid,
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
