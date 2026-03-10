"""Verification service for full-chain provenance audit reports."""

from __future__ import annotations

import json
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
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
from src.models import Artifact, sha256_hex
from src.parsing import (
    parse_artifact_markdown,
    parse_artifact_markdown_text,
)
from src.repository import SQLiteRepository
from src.services.curation_service import extract_request_id_from_artifact_path


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
    c2pa_present: bool = False
    c2pa_valid: bool = False
    c2pa_validation_state: str | None = None
    c2pa_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    branch: str | None = None
    commit_oid: str | None = None
    ledger_path: str | None = None

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
    ) -> None:
        self._repository = repository
        self._transparency_log_adapter = transparency_log_adapter
        self._tsa_adapter = tsa_adapter
        self._key_registry = key_registry
        self._artifact_verifier = artifact_verifier

    def audit_artifact(
        self,
        artifact_path: Path,
        tsa_ca_cert_path: Path | None,
    ) -> AuditReport:
        """Run full-chain audit and persist report."""

        request_id: str | None = None
        try:
            request_id = str(
                extract_request_id_from_artifact_path(artifact_path)
            )
        except RuntimeError:
            request_id = None

        try:
            envelope, payload = parse_artifact_markdown(artifact_path)
            digest_hex = sha256_hex(payload.encode("utf-8"))
            anchor_matches = self._transparency_log_adapter.find_entries_by_artifact_hash(
                digest_hex
            )
            manifest_hash, manifest_bytes = self._read_manifest_for_file(artifact_path)
            report = self._build_audit_report(
                envelope=envelope,
                payload=payload,
                request_id=request_id,
                source_file=str(artifact_path),
                manifest_hash=manifest_hash,
                manifest_bytes=manifest_bytes,
                transparency_anchor_found=len(anchor_matches) > 0,
                transparency_log_integrity=(
                    self._transparency_log_adapter.verify_integrity()
                ),
                tsa_ca_cert_path=tsa_ca_cert_path,
            )
        except Exception as exc:  # noqa: BLE001
            report = self._build_error_report(
                source_file=str(artifact_path),
                request_id=request_id,
                error_message=str(exc),
            )
        self._persist_report(report)
        return report

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
            markdown_text = self._read_blob_text_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=ledger_path,
            )
            envelope, payload = parse_artifact_markdown_text(markdown_text)
            digest_hex = sha256_hex(payload.encode("utf-8"))
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
            manifest_hash, manifest_bytes = self._read_manifest_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                ledger_path=ledger_path,
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
                tsa_ca_cert_path=tsa_ca_cert_path,
                branch=branch,
                commit_oid=str(commit_obj.id),
                ledger_path=ledger_path,
            )
        except Exception as exc:  # noqa: BLE001
            report = self._build_error_report(
                source_file=ledger_path,
                request_id=str(request_id),
                error_message=str(exc),
                branch=branch,
                ledger_path=ledger_path,
            )
        self._persist_report(report)
        return report

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
        tsa_ca_cert_path: Path | None,
        branch: str | None = None,
        commit_oid: str | None = None,
        ledger_path: str | None = None,
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

        digest_hex = sha256_hex(payload.encode("utf-8"))
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
            )
            c2pa_validation = validate_c2pa_sidecar(
                payload_bytes=validation_payload,
                manifest_bytes=manifest_bytes,
                content_type=envelope.content_type,
                payload_format=validation_format,
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

        latest_timestamp = self._repository.get_latest_timestamp_record(digest_hex)
        if latest_timestamp is not None:
            timestamp_found = True
            if self._tsa_adapter is None:
                timestamp_valid = False
                errors.append(
                    "TSA adapter unavailable for RFC3161 verification."
                )
            else:
                verification = self._repository.verify_latest_timestamp_record(
                    artifact_hash=digest_hex,
                    tsa_adapter=self._tsa_adapter,
                    tsa_ca_cert_path=tsa_ca_cert_path,
                )
                timestamp_valid = verification.ok
                if not verification.ok:
                    errors.append(verification.message)
        else:
            errors.append("No RFC3161 timestamp token found for artifact hash.")

        return AuditReport(
            artifact_id=str(envelope.id),
            request_id=request_id,
            source_file=source_file,
            envelope_valid=True,
            signature_valid=signature_valid,
            payload_hash_match=payload_hash_match,
            transparency_anchor_found=transparency_anchor_found,
            transparency_log_integrity=transparency_log_integrity,
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
        )

    def _persist_report(self, report: AuditReport) -> None:
        self._repository.create_audit_report(
            artifact_id=report.artifact_id or "<unknown>",
            request_id=report.request_id,
            report_json=json.dumps(report.to_dict(), sort_keys=True),
        )

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
        sidecar_path = f"{Path(ledger_path).stem}.c2pa"
        try:
            tree_entry = commit_obj.tree[sidecar_path]
        except KeyError:
            return (None, None)
        blob_obj = repo[tree_entry.id]
        if not isinstance(blob_obj, pygit2.Blob):
            return (None, None)
        manifest_bytes = bytes(blob_obj.data)
        return (sha256_hex(manifest_bytes), manifest_bytes)
