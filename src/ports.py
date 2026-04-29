"""Core ports for hexagonal architecture boundaries."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol
from uuid import UUID


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
    ) -> object:
        """Anchor one artifact in transparency log."""

    def anchor_committed_artifact(
        self,
        repository_path: Path,
        commit_oid: str,
        ledger_path: str,
        request_id: UUID,
    ) -> object:
        """Anchor one committed artifact directly from git objects."""

    def timestamp_artifact(
        self,
        artifact_path: Path,
        request_id: UUID | None,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> object:
        """Request and verify RFC3161 timestamp for one artifact."""

    def timestamp_committed_artifact(
        self,
        repository_path: Path,
        commit_oid: str,
        ledger_path: str,
        request_id: UUID | None,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> object:
        """Request/verify timestamp for one committed artifact."""
