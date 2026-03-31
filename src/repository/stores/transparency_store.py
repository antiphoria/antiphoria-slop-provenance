"""Transparency log SQL store."""

from __future__ import annotations

from src.repository.db import SQLiteConnectionFactory


class TransparencyStore:
    """Store for transparency log publication records."""

    def __init__(self, connections: SQLiteConnectionFactory) -> None:
        self._connections = connections

    def has_transparency_log_record(self, artifact_hash: str) -> bool:
        """Return True if a transparency row exists for artifact hash."""

        with self._connections.connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM transparency_log_records
                WHERE artifact_hash = ?
                LIMIT 1;
                """,
                (artifact_hash,),
            ).fetchone()
        return row is not None

    def create_transparency_log_record(
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
        """Persist one transparency log publication record."""

        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO transparency_log_records (
                    entry_id, artifact_hash, artifact_id, request_id,
                    source_file, log_path, previous_entry_hash,
                    entry_hash, published_at, remote_receipt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    entry_id,
                    artifact_hash,
                    artifact_id,
                    request_id,
                    source_file,
                    log_path,
                    previous_entry_hash,
                    entry_hash,
                    published_at,
                    remote_receipt,
                ),
            )
