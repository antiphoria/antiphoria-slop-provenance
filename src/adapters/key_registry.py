"""Signing key registry adapter for lifecycle and revocation metadata."""

from __future__ import annotations

import json
import re
from typing import Final, Protocol

_ALLOWED_STATUSES: Final[frozenset[str]] = frozenset(("active", "revoked"))
_FINGERPRINT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9:_-]{3,128}$")


def _normalize_fingerprint(fingerprint: str) -> str:
    """Normalize and validate key fingerprint input."""
    value = fingerprint.strip()
    if not value:
        raise RuntimeError("Key fingerprint must not be empty.")
    if _FINGERPRINT_PATTERN.fullmatch(value) is None:
        raise RuntimeError(
            "Invalid key fingerprint format. Allowed chars: letters, digits, "
            "colon, underscore, hyphen."
        )
    return value


def _normalize_metadata_json(metadata_json: str | None) -> str | None:
    """Validate metadata_json payload and return canonical JSON string."""
    if metadata_json is None:
        return None
    raw = metadata_json.strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid metadata_json payload: {exc}") from exc
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"))


class KeyRegistryStorePort(Protocol):
    """Narrow storage contract for key registry lifecycle metadata."""

    def upsert_key_registry_entry(
        self,
        fingerprint: str,
        key_version: str | None,
        status: str,
        metadata_json: str | None,
    ) -> None: ...

    def update_key_registry_status(self, fingerprint: str, status: str) -> int: ...

    def get_key_registry_entry(self, fingerprint: str) -> dict[str, str] | None: ...

    def append_key_status_transition(
        self,
        fingerprint: str,
        previous_status: str | None,
        new_status: str,
        transition_source: str,
    ) -> None: ...


class KeyRegistryAdapter:
    """Persist and query signing key registry metadata."""

    def __init__(self, store: KeyRegistryStorePort) -> None:
        self._store = store

    def register_key(
        self,
        fingerprint: str,
        key_version: str | None,
        status: str = "active",
        metadata_json: str | None = None,
    ) -> None:
        """Create or update a signing key entry."""

        fingerprint = _normalize_fingerprint(fingerprint)
        metadata_json = _normalize_metadata_json(metadata_json)
        if status not in _ALLOWED_STATUSES:
            raise RuntimeError(
                f"Invalid key status '{status}'. Allowed: {', '.join(sorted(_ALLOWED_STATUSES))}."
            )
        existing = self._store.get_key_registry_entry(fingerprint=fingerprint)
        if (
            existing is not None
            and existing["status"] == "revoked"
            and status == "active"
        ):
            raise RuntimeError(
                "Refusing to reactivate revoked key via register_key. "
                "Use a controlled key-rotation path."
            )
        self._store.upsert_key_registry_entry(
            fingerprint=fingerprint,
            key_version=key_version,
            status=status,
            metadata_json=metadata_json,
        )
        previous_status = None if existing is None else existing["status"]
        if previous_status != status:
            self._store.append_key_status_transition(
                fingerprint=fingerprint,
                previous_status=previous_status,
                new_status=status,
                transition_source="register_key",
            )

    def set_status(
        self,
        fingerprint: str,
        status: str,
    ) -> None:
        """Update status for a known key fingerprint."""

        fingerprint = _normalize_fingerprint(fingerprint)
        if status not in _ALLOWED_STATUSES:
            raise RuntimeError(
                f"Invalid key status '{status}'. Allowed: {', '.join(sorted(_ALLOWED_STATUSES))}."
            )
        existing = self._store.get_key_registry_entry(fingerprint=fingerprint)
        if existing is None:
            raise RuntimeError(f"Key fingerprint not found in registry: {fingerprint}")
        updated_count = self._store.update_key_registry_status(
            fingerprint=fingerprint,
            status=status,
        )
        if updated_count == 0:
            raise RuntimeError(f"Key fingerprint not found in registry: {fingerprint}")
        previous_status = existing["status"]
        if previous_status != status:
            self._store.append_key_status_transition(
                fingerprint=fingerprint,
                previous_status=previous_status,
                new_status=status,
                transition_source="set_status",
            )

    def get_status(self, fingerprint: str) -> str | None:
        """Return status for one fingerprint when present."""

        fingerprint = _normalize_fingerprint(fingerprint)
        record = self._store.get_key_registry_entry(fingerprint=fingerprint)
        if record is None:
            return None
        return record["status"]
