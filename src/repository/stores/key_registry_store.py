"""Signing key registry SQL store."""

from __future__ import annotations

from src.repository.db import SQLiteConnectionFactory
from src.repository.types import utc_now_iso


class KeyRegistryStore:
    """Store for signing key lifecycle rows."""

    def __init__(self, connections: SQLiteConnectionFactory) -> None:
        self._connections = connections

    def upsert_key_registry_entry(
        self,
        fingerprint: str,
        key_version: str | None,
        status: str,
        metadata_json: str | None,
    ) -> None:
        """Create or update key registry entry."""

        now = utc_now_iso()
        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT INTO key_registry (
                    fingerprint, key_version, status, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    key_version = excluded.key_version,
                    status = excluded.status,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at;
                """,
                (fingerprint, key_version, status, metadata_json, now, now),
            )

    def update_key_registry_status(self, fingerprint: str, status: str) -> int:
        """Update lifecycle status for one key fingerprint."""

        now = utc_now_iso()
        with self._connections.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE key_registry
                SET status = ?, updated_at = ?
                WHERE fingerprint = ?;
                """,
                (status, now, fingerprint),
            )
            return int(cursor.rowcount)

    def append_key_status_transition(
        self,
        fingerprint: str,
        previous_status: str | None,
        new_status: str,
        transition_source: str,
    ) -> None:
        """Append one key status transition audit row."""

        changed_at = utc_now_iso()
        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT INTO key_status_audit_log (
                    fingerprint,
                    previous_status,
                    new_status,
                    transition_source,
                    changed_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (
                    fingerprint,
                    previous_status,
                    new_status,
                    transition_source,
                    changed_at,
                ),
            )

    def get_key_registry_entry(self, fingerprint: str) -> dict[str, str] | None:
        """Get key registry entry by signer fingerprint."""

        with self._connections.connect() as connection:
            row = connection.execute(
                """
                SELECT fingerprint, key_version, status, metadata_json, created_at, updated_at
                FROM key_registry
                WHERE fingerprint = ?;
                """,
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        return {
            "fingerprint": str(row["fingerprint"]),
            "key_version": "" if row["key_version"] is None else str(row["key_version"]),
            "status": str(row["status"]),
            "metadata_json": ("" if row["metadata_json"] is None else str(row["metadata_json"])),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }
