"""Signing key registry adapter for lifecycle and revocation metadata."""

from __future__ import annotations

from src.repository import SQLiteRepository


class KeyRegistryAdapter:
    """Persist and query signing key registry metadata."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self._repository = repository

    def register_key(
        self,
        fingerprint: str,
        key_version: str | None,
        status: str = "active",
        metadata_json: str | None = None,
    ) -> None:
        """Create or update a signing key entry."""

        self._repository.upsert_key_registry_entry(
            fingerprint=fingerprint,
            key_version=key_version,
            status=status,
            metadata_json=metadata_json,
        )

    def set_status(
        self,
        fingerprint: str,
        status: str,
    ) -> None:
        """Update status for a known key fingerprint."""

        self._repository.update_key_registry_status(
            fingerprint=fingerprint, status=status
        )

    def get_status(self, fingerprint: str) -> str | None:
        """Return status for one fingerprint when present."""

        record = self._repository.get_key_registry_entry(fingerprint=fingerprint)
        if record is None:
            return None
        return record["status"]
