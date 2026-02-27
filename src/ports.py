"""Core ports for hexagonal architecture boundaries."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol
from uuid import UUID

from src.adapters.rfc3161_tsa import TimestampVerification
from src.models import Artifact
from src.services.provenance_service import AnchorOutcome, TimestampOutcome
from src.services.verification_service import AuditReport


class RepositoryPort(Protocol):
    """Port for persistence operations used by orchestration services."""

    def create_artifact_record(
        self,
        request_id: UUID,
        status: str,
        artifact: Artifact,
        prompt: str,
        body: str,
        model_id: str,
    ) -> None:
        """Create a new artifact lifecycle record."""

    def update_artifact_status(
        self,
        request_id: UUID,
        status: str,
        ledger_path: str | None = None,
        commit_oid: str | None = None,
    ) -> None:
        """Update artifact lifecycle status."""

    def update_artifact_curation(
        self,
        request_id: UUID,
        curated_body: str,
        artifact_hash: str,
        cryptographic_signature: str,
    ) -> None:
        """Update artifact curation fields."""

    def create_provenance_event_log(
        self,
        event_type: str,
        request_id: str | None,
        artifact_id: str | None,
        payload_json: str,
    ) -> None:
        """Persist one provenance event log payload."""

    def get_latest_timestamp_record(self, artifact_hash: str) -> object | None:
        """Return latest timestamp row for one artifact hash."""

    def verify_latest_timestamp_record(
        self,
        artifact_hash: str,
        tsa_adapter: object,
        tsa_ca_cert_path: Path | None,
    ) -> TimestampVerification:
        """Verify latest timestamp record for one artifact hash."""


class ProvenanceServicePort(Protocol):
    """Port for anchoring/timestamping/key registration workflows."""

    def register_signing_key(
        self,
        signer_fingerprint: str,
        key_version: str | None,
    ) -> None:
        """Register signing key metadata."""

    def anchor_artifact(
        self,
        artifact_path: Path,
        request_id: UUID | None,
    ) -> AnchorOutcome:
        """Anchor one artifact in transparency log."""

    def timestamp_artifact(
        self,
        artifact_path: Path,
        request_id: UUID | None,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> TimestampOutcome:
        """Request and verify RFC3161 timestamp for one artifact."""


class VerificationServicePort(Protocol):
    """Port for full-chain artifact audit workflows."""

    def audit_artifact(
        self,
        artifact_path: Path,
        tsa_ca_cert_path: Path | None,
    ) -> AuditReport:
        """Generate one full-chain audit report."""
