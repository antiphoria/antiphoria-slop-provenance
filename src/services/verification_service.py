"""Verification service for full-chain provenance audit reports."""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

import pygit2

from src.adapters.c2pa_manifest import (
    build_c2pa_validation_payload,
    validate_c2pa_sidecar,
)
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.ots_adapter import OTSAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    TransparencyLogEntry,
)
from src.canonicalization import compute_payload_hash
from src.models import Artifact, sha256_hex
from src.parsing import (
    parse_artifact_markdown,
    parse_artifact_markdown_text,
)
from src.repository import SQLiteRepository
from src.services.curation_service import extract_request_id_from_artifact_path

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditReport:
    """Machine-readable audit report schema."""

    artifact_id: str
    request_id: str | None
    source_file: str
    envelope_valid: bool
    signature_valid: bool
    payload_hash_match: bool
    transparency_anchor_found: bool
    transparency_log_integrity: bool
    timestamp_found: bool
    timestamp_valid: bool
    key_status_at_signing_time: str
    remote_anchor_verified: bool | None = None
    c2pa_present: bool = False
    c2pa_valid: bool = False
    c2pa_validation_state: str | None = None
    c2pa_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    branch: str | None = None
    commit_oid: str | None = None
    ledger_path: str | None = None
    ots_forged: bool = False
    bitcoin_block_height: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert report dataclass to serializable dictionary."""

        return asdict(self)


class ArtifactVerifierPort(Protocol):
    """Port for artifact signature verification."""

    def verify_artifact_payload(
        self,
        envelope: Artifact,
        payload: str,
        manifest_hash: str | None,
    ) -> bool:
        """Verify one parsed envelope+payload pair."""


class VerificationService:
    """Orchestrates envelope, signature, anchor, timestamp, and key checks."""

    def __init__(
        self,
        repository: SQLiteRepository,
        transparency_log_adapter: TransparencyLogAdapter,
        tsa_adapter: RFC3161TSAAdapter | None,
        key_registry: KeyRegistryAdapter,
        artifact_verifier: ArtifactVerifierPort,
        ots_adapter: OTSAdapter | None = None,
        env_path: Path | None = None,
    ) -> None:
        self._repository = repository
        self._transparency_log_adapter = transparency_log_adapter
        self._tsa_adapter = tsa_adapter
        self._key_registry = key_registry
        self._artifact_verifier = artifact_verifier
        self._ots_adapter = ots_adapter
        self._env_path = env_path or Path(".env")

    def audit_artifact(
        self,
        artifact_path: Path,
        tsa_ca_cert_path: Path | None,
        repository_path: Path | None = None,
    ) -> AuditReport:
        """Run full-chain audit and persist report."""

        request_id: str | None = None
        try:
            request_id = str(
                extract_request_id_from_artifact_path(artifact_path)
            )
        except RuntimeError:
            request_id = None

        branch: str | None = None
        commit_oid: str | None = None
        ledger_path: str | None = None
        if request_id and repository_path is not None:
            branch, commit_oid, ledger_path = self._resolve_branch_context(
                repository_path, request_id
            )

        try:
            envelope, payload = parse_artifact_markdown(artifact_path)
            digest_hex = compute_payload_hash(payload)
            if branch and commit_oid and ledger_path and repository_path is not None:
                log_text = self._read_optional_blob_from_branch(
                    repository_path, f"artifact/{request_id}", ".provenance/transparency-log.jsonl"
                )
                entries = self._transparency_log_adapter.parse_entries_from_jsonl(
                    log_text
                )
                transparency_anchor_found = any(
                    e.artifact_hash == digest_hex for e in entries
                )
                transparency_log_integrity = (
                    self._transparency_log_adapter.verify_integrity_entries(entries)
                )
                remote_anchor_verified: bool | None = None
                remote_error_message: str | None = None
                try:
                    remote_anchor_verified = self._verify_remote_anchor(
                        digest_hex=digest_hex,
                        entries=entries,
                    )
                except RuntimeError as remote_exc:
                    remote_anchor_verified = False
                    remote_error_message = str(remote_exc)
            else:
                if repository_path is not None:
                    log_text = self._read_optional_blob_from_head(
                        repository_path,
                        ".provenance/transparency-log.jsonl",
                    )
                    entries = self._transparency_log_adapter.parse_entries_from_jsonl(
                        log_text
                    )
                else:
                    entries = self._transparency_log_adapter.find_entries_by_artifact_hash(
                        digest_hex
                    )
                transparency_anchor_found = any(
                    e.artifact_hash == digest_hex for e in entries
                )
                transparency_log_integrity = (
                    self._transparency_log_adapter.verify_integrity_entries(entries)
                    if entries
                    else True
                )
                remote_anchor_verified = None
                remote_error_message = None
                try:
                    remote_anchor_verified = self._verify_remote_anchor(
                        digest_hex=digest_hex,
                        entries=entries,
                    )
                except RuntimeError as remote_exc:
                    remote_anchor_verified = False
                    remote_error_message = str(remote_exc)
            manifest_hash, manifest_bytes = self._read_manifest_for_file(artifact_path)
            ots_forged, bitcoin_block_height = self._verify_ots_from_git(
                repository_path=repository_path,
                request_id=request_id,
                branch=branch,
                payload=payload,
            )
            report = self._build_audit_report(
                envelope=envelope,
                payload=payload,
                request_id=request_id,
                source_file=str(artifact_path),
                manifest_hash=manifest_hash,
                manifest_bytes=manifest_bytes,
                transparency_anchor_found=transparency_anchor_found,
                transparency_log_integrity=transparency_log_integrity,
                remote_anchor_verified=remote_anchor_verified,
                remote_error_message=remote_error_message,
                tsa_ca_cert_path=tsa_ca_cert_path,
                branch=branch,
                commit_oid=commit_oid,
                ledger_path=ledger_path,
                ots_forged=ots_forged,
                bitcoin_block_height=bitcoin_block_height,
            )
        except (RuntimeError, KeyError, ValueError, FileNotFoundError, OSError) as exc:
            report = self._build_error_report(
                source_file=str(artifact_path),
                request_id=request_id,
                error_message=str(exc),
                branch=branch,
                ledger_path=ledger_path,
            )
        except Exception:
            _logger.exception("Unexpected error during audit_artifact")
            raise
        self._persist_report(report)
        return report

    @staticmethod
    def _resolve_branch_context(
        repository_path: Path,
        request_id: str,
    ) -> tuple[str | None, str | None, str | None]:
        """Resolve branch, commit_oid, ledger_path for artifact when branch exists."""
        branch = f"artifact/{request_id}"
        ref_name = f"refs/heads/{branch}"
        ledger_path = f"{request_id}.md"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if isinstance(commit_obj, pygit2.Commit):
                return branch, str(commit_obj.id), ledger_path
        except (KeyError, pygit2.GitError):
            pass
        return None, None, None

    @staticmethod
    def _read_optional_blob_from_branch(
        repository_path: Path,
        branch_name: str,
        relative_path: str,
    ) -> str:
        """Read blob from branch or return empty string if branch/path missing."""
        ref_name = f"refs/heads/{branch_name}"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if not isinstance(commit_obj, pygit2.Commit):
                return ""
            tree_entry = commit_obj.tree[relative_path]
            blob_obj = repo[tree_entry.id]
        except (KeyError, pygit2.GitError):
            return ""
        if not isinstance(blob_obj, pygit2.Blob):
            return ""
        return bytes(blob_obj.data).decode("utf-8")

    @staticmethod
    def _read_blob_bytes_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        relative_path: str,
    ) -> bytes | None:
        """Read raw blob bytes from commit; return None if path missing."""
        try:
            tree_entry = commit_obj.tree[relative_path]
            blob_obj = repo[tree_entry.id]
        except (KeyError, pygit2.GitError):
            return None
        if not isinstance(blob_obj, pygit2.Blob):
            return None
        return bytes(blob_obj.data)

    @staticmethod
    def _read_optional_blob_bytes_from_branch(
        repository_path: Path,
        branch_name: str,
        relative_path: str,
    ) -> bytes | None:
        """Read raw blob bytes from branch; return None if branch/path missing."""
        ref_name = f"refs/heads/{branch_name}"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if not isinstance(commit_obj, pygit2.Commit):
                return None
            return VerificationService._read_blob_bytes_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=relative_path,
            )
        except (KeyError, pygit2.GitError):
            return None

    @staticmethod
    def _read_optional_blob_from_head(
        repository_path: Path,
        relative_path: str,
    ) -> str:
        """Read blob from HEAD commit; return empty string if path missing."""
        try:
            repo = pygit2.Repository(str(repository_path))
            commit_obj = repo.revparse_single("HEAD")
            if not isinstance(commit_obj, pygit2.Commit):
                return ""
            tree_entry = commit_obj.tree[relative_path]
            blob_obj = repo[tree_entry.id]
        except (KeyError, pygit2.GitError, AttributeError, ValueError):
            return ""
        if not isinstance(blob_obj, pygit2.Blob):
            return ""
        return bytes(blob_obj.data).decode("utf-8")

    def _verify_remote_anchor(
        self,
        digest_hex: str,
        entries: list[TransparencyLogEntry],
    ) -> bool | None:
        """Verify remote Supabase has matching entry. None=skip, True=ok, False=fail."""
        matching_entry = next(
            (e for e in entries if e.artifact_hash == digest_hex), None
        )
        if matching_entry is None:
            return None
        remote_rows = self._transparency_log_adapter.fetch_remote_entries_by_artifact_hash(
            digest_hex
        )
        if remote_rows is None:
            return None
        if not remote_rows:
            return False
        for row in remote_rows:
            payload = row.get("payload") or row.get("Payload")
            if not isinstance(payload, dict):
                _logger.warning(
                    "Remote transparency log row has unexpected shape: "
                    "payload column missing or not a dict. Keys: %s",
                    list(row.keys()) if isinstance(row, dict) else "not a dict",
                )
                continue

            # Deep check: recompute entryHash from remote payload; detect tampering
            expected_hash = TransparencyLogAdapter.compute_expected_entry_hash_from_payload(
                payload
            )
            if expected_hash != payload.get("entryHash"):
                _logger.warning(
                    "Remote transparency log payload tampered: recomputed entryHash "
                    "does not match stored value."
                )
                continue

            if payload.get("entryHash") != matching_entry.entry_hash:
                continue
            if payload.get("artifactHash") != matching_entry.artifact_hash:
                _logger.warning(
                    "Remote row entryHash matches but artifactHash differs: "
                    "expected %s, got %s",
                    matching_entry.artifact_hash,
                    payload.get("artifactHash"),
                )
                continue
            return True
        return False

    def audit_committed_artifact(
        self,
        repository_path: Path,
        request_id: UUID,
        tsa_ca_cert_path: Path | None,
    ) -> AuditReport:
        """Audit one artifact branch directly from git objects."""

        branch = f"artifact/{request_id}"
        ref_name = f"refs/heads/{branch}"
        ledger_path = f"{request_id}.md"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if not isinstance(commit_obj, pygit2.Commit):
                raise RuntimeError(
                    f"Branch ref '{ref_name}' does not point to a commit."
                )
            ledger_path = self._resolve_ledger_path_from_commit(
                commit_obj=commit_obj,
                request_id=str(request_id),
            )
            markdown_text = self._read_blob_text_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=ledger_path,
            )
            envelope, payload = parse_artifact_markdown_text(markdown_text)
            digest_hex = compute_payload_hash(payload)
            log_text = self._read_optional_blob_text_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=".provenance/transparency-log.jsonl",
            )
            entries = self._transparency_log_adapter.parse_entries_from_jsonl(
                log_text
            )
            transparency_anchor_found = any(
                entry.artifact_hash == digest_hex for entry in entries
            )
            transparency_log_integrity = (
                self._transparency_log_adapter.verify_integrity_entries(entries)
            )
            remote_anchor_verified: bool | None = None
            remote_error_message: str | None = None
            try:
                remote_anchor_verified = self._verify_remote_anchor(
                    digest_hex=digest_hex,
                    entries=entries,
                )
            except RuntimeError as remote_exc:
                remote_anchor_verified = False
                remote_error_message = str(remote_exc)
            manifest_hash, manifest_bytes = self._read_manifest_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                ledger_path=ledger_path,
            )
            ots_forged, bitcoin_block_height = self._verify_ots_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                request_id=str(request_id),
                payload=payload,
            )
            report = self._build_audit_report(
                envelope=envelope,
                payload=payload,
                request_id=str(request_id),
                source_file=ledger_path,
                manifest_hash=manifest_hash,
                manifest_bytes=manifest_bytes,
                transparency_anchor_found=transparency_anchor_found,
                transparency_log_integrity=transparency_log_integrity,
                remote_anchor_verified=remote_anchor_verified,
                remote_error_message=remote_error_message,
                tsa_ca_cert_path=tsa_ca_cert_path,
                branch=branch,
                commit_oid=str(commit_obj.id),
                ledger_path=ledger_path,
                ots_forged=ots_forged,
                bitcoin_block_height=bitcoin_block_height,
            )
        except (RuntimeError, KeyError, ValueError, FileNotFoundError, OSError) as exc:
            report = self._build_error_report(
                source_file=ledger_path,
                request_id=str(request_id),
                error_message=str(exc),
                branch=branch,
                ledger_path=ledger_path,
            )
        except Exception:
            _logger.exception("Unexpected error during audit_committed_artifact")
            raise
        self._persist_report(report)
        return report

    def _verify_ots_from_git(
        self,
        repository_path: Path | None,
        request_id: str | None,
        branch: str | None,
        payload: str,
    ) -> tuple[bool, int | None]:
        """Verify OTS proof from Git; return (ots_forged, bitcoin_block_height)."""
        if not request_id or not repository_path or not self._ots_adapter:
            return False, None
        branch_name = branch or f"artifact/{request_id}"
        ots_path = f".provenance/ots-{request_id}.ots"
        ots_bytes = self._read_optional_blob_bytes_from_branch(
            repository_path, branch_name, ots_path
        )
        if not ots_bytes:
            return False, None
        return self._ots_adapter.verify_ots_proof(
            payload_bytes=payload.encode("utf-8"),
            ots_bytes=ots_bytes,
        )

    def _verify_ots_from_commit(
        self,
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        request_id: str,
        payload: str,
    ) -> tuple[bool, int | None]:
        """Verify OTS proof from commit; return (ots_forged, bitcoin_block_height)."""
        if not self._ots_adapter:
            return False, None
        ots_path = f".provenance/ots-{request_id}.ots"
        ots_bytes = self._read_blob_bytes_from_commit(
            repo=repo, commit_obj=commit_obj, relative_path=ots_path
        )
        if not ots_bytes:
            return False, None
        return self._ots_adapter.verify_ots_proof(
            payload_bytes=payload.encode("utf-8"),
            ots_bytes=ots_bytes,
        )

    def _build_audit_report(
        self,
        envelope: Artifact,
        payload: str,
        request_id: str | None,
        source_file: str,
        manifest_hash: str | None,
        manifest_bytes: bytes | None,
        transparency_anchor_found: bool,
        transparency_log_integrity: bool,
        remote_anchor_verified: bool | None = None,
        remote_error_message: str | None = None,
        tsa_ca_cert_path: Path | None = None,
        branch: str | None = None,
        commit_oid: str | None = None,
        ledger_path: str | None = None,
        ots_forged: bool = False,
        bitcoin_block_height: int | None = None,
    ) -> AuditReport:
        errors: list[str] = []
        signature_valid = False
        payload_hash_match = False
        timestamp_found = False
        timestamp_valid = False
        key_status = "unknown"
        c2pa_present = manifest_hash is not None and manifest_bytes is not None
        c2pa_valid = False
        c2pa_validation_state: str | None = None
        c2pa_errors: list[str] = []

        digest_hex = compute_payload_hash(payload)
        if envelope.signature is None:
            errors.append("Artifact envelope is missing signature block.")
        else:
            payload_hash_match = digest_hex == envelope.signature.artifact_hash
            if not payload_hash_match:
                errors.append(
                    "Payload hash mismatch against signature artifactHash."
                )
            key_status_lookup = self._key_registry.get_status(
                envelope.signature.verification_anchor.signer_fingerprint
            )
            key_status = key_status_lookup or "unregistered"

        signature_valid = self._artifact_verifier.verify_artifact_payload(
            envelope=envelope,
            payload=payload,
            manifest_hash=manifest_hash,
        )
        if c2pa_present and manifest_bytes is not None:
            validation_payload, validation_format = build_c2pa_validation_payload(
                envelope=envelope,
                body=payload,
                env_path=self._env_path,
            )
            c2pa_validation = validate_c2pa_sidecar(
                payload_bytes=validation_payload,
                manifest_bytes=manifest_bytes,
                content_type=envelope.content_type,
                payload_format=validation_format,
                env_path=self._env_path,
                body_for_mvp=payload,
            )
            c2pa_valid = c2pa_validation.valid
            c2pa_validation_state = c2pa_validation.validation_state
            c2pa_errors = c2pa_validation.errors
            if not c2pa_valid:
                errors.append("C2PA sidecar semantic validation failed.")
        if not transparency_anchor_found:
            errors.append("No transparency anchor found for artifact hash.")
        if not transparency_log_integrity:
            errors.append("Transparency log hash chain integrity check failed.")
        if remote_anchor_verified is False:
            if remote_error_message:
                errors.append(f"Remote transparency log: {remote_error_message}")
            else:
                errors.append("Remote transparency log: no matching entry.")
        if key_status == "revoked":
            errors.append("Signing key has been revoked.")

        token_base64_to_verify = (
            envelope.signature.rfc3161_token
            if (
                envelope.signature is not None
                and envelope.signature.rfc3161_token is not None
            )
            else None
        )

        if token_base64_to_verify is not None and self._tsa_adapter is not None:
            timestamp_found = True
            try:
                token_bytes = base64.b64decode(
                    token_base64_to_verify.encode("ascii"), validate=True
                )
                verification = self._tsa_adapter.verify_timestamp_token(
                    digest_hex=digest_hex,
                    token_bytes=token_bytes,
                    tsa_ca_cert_path=tsa_ca_cert_path,
                    digest_algorithm="sha256",
                )
                timestamp_valid = verification.ok
                if not verification.ok:
                    errors.append(verification.message)
            except Exception as exc:
                timestamp_valid = False
                errors.append(f"Git timestamp verification failed: {exc}")
        else:
            if token_base64_to_verify is None:
                errors.append("No RFC3161 timestamp token.")

        return AuditReport(
            artifact_id=str(envelope.id),
            request_id=request_id,
            source_file=source_file,
            envelope_valid=True,
            signature_valid=signature_valid,
            payload_hash_match=payload_hash_match,
            transparency_anchor_found=transparency_anchor_found,
            transparency_log_integrity=transparency_log_integrity,
            remote_anchor_verified=remote_anchor_verified,
            timestamp_found=timestamp_found,
            timestamp_valid=timestamp_valid,
            key_status_at_signing_time=key_status,
            c2pa_present=c2pa_present,
            c2pa_valid=c2pa_valid,
            c2pa_validation_state=c2pa_validation_state,
            c2pa_errors=c2pa_errors,
            errors=errors,
            branch=branch,
            commit_oid=commit_oid,
            ledger_path=ledger_path,
            ots_forged=ots_forged,
            bitcoin_block_height=bitcoin_block_height,
        )

    def _build_error_report(
        self,
        source_file: str,
        request_id: str | None,
        error_message: str,
        branch: str | None = None,
        ledger_path: str | None = None,
    ) -> AuditReport:
        return AuditReport(
            artifact_id="",
            request_id=request_id,
            source_file=source_file,
            envelope_valid=False,
            signature_valid=False,
            payload_hash_match=False,
            transparency_anchor_found=False,
            transparency_log_integrity=False,
            remote_anchor_verified=None,
            timestamp_found=False,
            timestamp_valid=False,
            key_status_at_signing_time="unknown",
            c2pa_present=False,
            c2pa_valid=False,
            c2pa_validation_state=None,
            c2pa_errors=[],
            errors=[error_message],
            branch=branch,
            commit_oid=None,
            ledger_path=ledger_path,
            ots_forged=False,
            bitcoin_block_height=None,
        )

    def _persist_report(self, report: AuditReport) -> None:
        self._repository.create_audit_report(
            artifact_id=report.artifact_id or "<unknown>",
            request_id=report.request_id,
            report_json=json.dumps(report.to_dict(), sort_keys=True),
        )

    @staticmethod
    def _resolve_ledger_path_from_commit(
        commit_obj: pygit2.Commit,
        request_id: str,
    ) -> str:
        """Resolve ledger path by trying common layouts (flat, artifacts_directory)."""
        candidates = [f"{request_id}.md", f"artifact/{request_id}.md"]
        for candidate in candidates:
            try:
                _ = commit_obj.tree[candidate]
                return candidate
            except KeyError:
                continue
        return f"{request_id}.md"

    @staticmethod
    def _read_manifest_for_file(artifact_path: Path) -> tuple[str | None, bytes | None]:
        sidecar_path = artifact_path.with_suffix(".c2pa")
        if not sidecar_path.exists():
            return (None, None)
        manifest_bytes = sidecar_path.read_bytes()
        return (sha256_hex(manifest_bytes), manifest_bytes)

    @staticmethod
    def _read_blob_text_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        relative_path: str,
    ) -> str:
        try:
            tree_entry = commit_obj.tree[relative_path]
        except KeyError as exc:
            raise RuntimeError(
                f"Branch artifact path '{relative_path}' not found in commit."
            ) from exc
        blob_obj = repo[tree_entry.id]
        if not isinstance(blob_obj, pygit2.Blob):
            raise RuntimeError(
                f"Branch artifact path '{relative_path}' "
                "does not resolve to a blob."
            )
        return bytes(blob_obj.data).decode("utf-8")

    @staticmethod
    def _read_optional_blob_text_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        relative_path: str,
    ) -> str:
        try:
            return VerificationService._read_blob_text_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=relative_path,
            )
        except RuntimeError:
            return ""

    @staticmethod
    def _read_manifest_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        ledger_path: str,
    ) -> tuple[str | None, bytes | None]:
        sidecar_path = str(Path(ledger_path).with_suffix(".c2pa"))
        try:
            tree_entry = commit_obj.tree[sidecar_path]
        except KeyError:
            return (None, None)
        blob_obj = repo[tree_entry.id]
        if not isinstance(blob_obj, pygit2.Blob):
            return (None, None)
        manifest_bytes = bytes(blob_obj.data)
        return (sha256_hex(manifest_bytes), manifest_bytes)
