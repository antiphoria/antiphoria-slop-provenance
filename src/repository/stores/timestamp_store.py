"""RFC3161 timestamp SQL store."""

from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

from src.adapters.rfc3161_tsa import RFC3161TSAAdapter, TimestampVerification
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

    def get_latest_timestamp_record(
        self,
        artifact_hash: str,
    ) -> sqlite3.Row | None:
        """Return latest timestamp row for one artifact hash."""

        with self._connections.connect() as connection:
            return connection.execute(
                """
                SELECT *
                FROM timestamp_records
                WHERE artifact_hash = ?
                ORDER BY id DESC
                LIMIT 1;
                """,
                (artifact_hash,),
            ).fetchone()

    def verify_latest_timestamp_record(
        self,
        artifact_hash: str,
        tsa_adapter: RFC3161TSAAdapter,
        tsa_ca_cert_path: Path | None,
    ) -> TimestampVerification:
        """Verify latest timestamp token against current artifact hash."""

        record = self.get_latest_timestamp_record(artifact_hash)
        if record is None:
            return TimestampVerification(
                ok=False,
                message=(
                    "No timestamp token found "
                    f"for artifact_hash={artifact_hash}."
                ),
            )
        token_b64 = str(record["token_base64"])
        token_bytes = base64.b64decode(
            token_b64.encode("ascii"),
            validate=True,
        )
        return tsa_adapter.verify_timestamp_token(
            digest_hex=artifact_hash,
            token_bytes=token_bytes,
            tsa_ca_cert_path=tsa_ca_cert_path,
            digest_algorithm=str(record["digest_algorithm"]),
        )
