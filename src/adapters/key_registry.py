"""Signing key registry adapter for lifecycle and revocation metadata."""

from __future__ import annotations

from typing import Final

from src.repository import SQLiteRepository

_ALLOWED_STATUSES: Final[frozenset[str]] = frozenset(("active", "revoked"))


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

        if status not in _ALLOWED_STATUSES:
            raise RuntimeError(
                f"Invalid key status '{status}'. Allowed: {', '.join(sorted(_ALLOWED_STATUSES))}."
            )
        existing = self._repository.get_key_registry_entry(fingerprint=fingerprint)
        if (
            existing is not None
            and existing["status"] == "revoked"
            and status == "active"
        ):
            raise RuntimeError(
                "Refusing to reactivate revoked key via register_key. "
                "Use a controlled key-rotation path."
            )
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

        if status not in _ALLOWED_STATUSES:
            raise RuntimeError(
                f"Invalid key status '{status}'. Allowed: {', '.join(sorted(_ALLOWED_STATUSES))}."
            )
        existing = self._repository.get_key_registry_entry(fingerprint=fingerprint)
        if existing is None:
            raise RuntimeError(f"Key fingerprint not found in registry: {fingerprint}")
        updated_count = self._repository.update_key_registry_status(
            fingerprint=fingerprint,
            status=status,
        )
        if updated_count == 0:
            raise RuntimeError(f"Key fingerprint not found in registry: {fingerprint}")

    def get_status(self, fingerprint: str) -> str | None:
        """Return status for one fingerprint when present."""

        record = self._repository.get_key_registry_entry(fingerprint=fingerprint)
        if record is None:
            return None
        return record["status"]
