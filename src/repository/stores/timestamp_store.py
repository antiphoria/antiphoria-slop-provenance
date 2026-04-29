"""RFC3161 timestamp SQL store."""

from __future__ import annotations

from src.repository.db import SQLiteConnectionFactory
from src.repository.types import utc_now_iso


class TimestampStore:
    """Store for RFC3161 timestamp rows."""

    def __init__(self, connections: SQLiteConnectionFactory) -> None:
        self._connections = connections

    def create_timestamp_record(
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
        """Persist one RFC3161 token row and return creation timestamp."""

        created_at = utc_now_iso()
        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT INTO timestamp_records (
                    artifact_hash, artifact_id, request_id, tsa_url,
                    token_base64, digest_algorithm, verification_status,
                    verification_message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    artifact_hash,
                    artifact_id,
                    request_id,
                    tsa_url,
                    token_base64,
                    digest_algorithm,
                    verification_status,
                    verification_message,
                    created_at,
                ),
            )
        return created_at
