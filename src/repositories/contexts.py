"""Bounded-context repository facades over ``SQLiteRepository``.

These facades are migration-safe wrappers that group related methods by
domain context while the legacy ``SQLiteRepository`` API remains available.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from src.adapters.rfc3161_tsa import RFC3161TSAAdapter, TimestampVerification
from src.models import Artifact

if TYPE_CHECKING:
    from src.repository import ArtifactRecord, SQLiteRepository

ArtifactLifecycleStatus = str


class ArtifactLifecycleRepository:
    """Artifact lifecycle persistence context."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self._repository = repository

    def create_record(
        self,
        request_id: UUID,
        status: ArtifactLifecycleStatus,
        artifact: Artifact,
        prompt: str,
        body: str,
        model_id: str,
    ) -> None:
        self._repository.create_artifact_record(
            request_id=request_id,
            status=status,
            artifact=artifact,
            prompt=prompt,
            body=body,
            model_id=model_id,
        )

    def update_status(
        self,
        request_id: UUID,
        status: ArtifactLifecycleStatus,
        ledger_path: str | None = None,
        commit_oid: str | None = None,
    ) -> None:
        self._repository.update_artifact_status(
            request_id=request_id,
            status=status,
            ledger_path=ledger_path,
            commit_oid=commit_oid,
        )

    def update_curation(
        self,
        request_id: UUID,
        curated_body: str,
        artifact_hash: str,
        cryptographic_signature: str,
    ) -> None:
        self._repository.update_artifact_curation(
            request_id=request_id,
            curated_body=curated_body,
            artifact_hash=artifact_hash,
            cryptographic_signature=cryptographic_signature,
        )

    def get_record(self, request_id: UUID) -> ArtifactRecord | None:
        return self._repository.get_artifact_record(request_id=request_id)

    def list_records(
        self,
        status: ArtifactLifecycleStatus | None = None,
        limit: int = 100,
    ) -> list[ArtifactRecord]:
        return self._repository.list_artifact_records(status=status, limit=limit)

    def delete_record(self, request_id: UUID) -> None:
        self._repository.delete_artifact_record(request_id=request_id)


class TransparencyLogRepository:
    """Transparency-log persistence context."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self._repository = repository

    def has_record(self, artifact_hash: str) -> bool:
        return self._repository.has_transparency_log_record(artifact_hash=artifact_hash)

    def create_record(
        self,
        entry_id: str,
        artifact_hash: str,
        artifact_id: str,
        request_id: str | None,
        source_file: str,
        log_path: str,
        previous_entry_hash: str | None,
        entry_hash: str,
        published_at: str,
        remote_receipt: str | None,
    ) -> None:
        self._repository.create_transparency_log_record(
            entry_id=entry_id,
            artifact_hash=artifact_hash,
            artifact_id=artifact_id,
            request_id=request_id,
            source_file=source_file,
            log_path=log_path,
            previous_entry_hash=previous_entry_hash,
            entry_hash=entry_hash,
            published_at=published_at,
            remote_receipt=remote_receipt,
        )


class TimestampRepository:
    """RFC3161 timestamp persistence context."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self._repository = repository

    def create_record(
        self,
        artifact_hash: str,
        artifact_id: str,
        request_id: str | None,
        tsa_url: str,
        token_base64: str,
        digest_algorithm: str,
        verification_status: str,
        verification_message: str,
    ) -> str:
        return self._repository.create_timestamp_record(
            artifact_hash=artifact_hash,
            artifact_id=artifact_id,
            request_id=request_id,
            tsa_url=tsa_url,
            token_base64=token_base64,
            digest_algorithm=digest_algorithm,
            verification_status=verification_status,
            verification_message=verification_message,
        )

    def verify_latest_record(
        self,
        artifact_hash: str,
        tsa_adapter: RFC3161TSAAdapter,
        tsa_ca_cert_path: Path | None,
    ) -> TimestampVerification:
        return self._repository.verify_latest_timestamp_record(
            artifact_hash=artifact_hash,
            tsa_adapter=tsa_adapter,
            tsa_ca_cert_path=tsa_ca_cert_path,
        )


class KeyRegistryRepository:
    """Signing-key lifecycle persistence context."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self._repository = repository

    def upsert_entry(
        self,
        fingerprint: str,
        key_version: str | None,
        status: str,
        metadata_json: str | None,
    ) -> None:
        self._repository.upsert_key_registry_entry(
            fingerprint=fingerprint,
            key_version=key_version,
            status=status,
            metadata_json=metadata_json,
        )

    def update_status(self, fingerprint: str, status: str) -> int:
        return self._repository.update_key_registry_status(
            fingerprint=fingerprint,
            status=status,
        )

    def get_entry(self, fingerprint: str) -> dict[str, str] | None:
        return self._repository.get_key_registry_entry(fingerprint=fingerprint)


class AuditRepository:
    """Audit-report persistence context."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self._repository = repository

    def create_report(
        self,
        artifact_id: str,
        request_id: str | None,
        report_json: str,
    ) -> str:
        return self._repository.create_audit_report(
            artifact_id=artifact_id,
            request_id=request_id,
            report_json=report_json,
        )


class ProvenanceEventRepository:
    """Provenance telemetry/event-log persistence context."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self._repository = repository

    def create_event(
        self,
        event_type: str,
        request_id: str | None,
        artifact_id: str | None,
        payload_json: str,
    ) -> None:
        self._repository.create_provenance_event_log(
            event_type=event_type,
            request_id=request_id,
            artifact_id=artifact_id,
            payload_json=payload_json,
        )

    def list_events(
        self,
        limit: int = 50,
        event_type: str | None = None,
    ) -> list[dict[str, str | int | None]]:
        return self._repository.list_provenance_event_logs(
            limit=limit,
            event_type=event_type,
        )
