"""Artifact lifecycle SQL store."""

from __future__ import annotations

import sqlite3
from uuid import UUID

from src.models import Artifact
from src.repository.db import SQLiteConnectionFactory
from src.repository.types import (
    ArtifactLifecycleStatus,
    ArtifactRecord,
    utc_now_iso,
)


class ArtifactStore:
    """Store for artifact lifecycle records."""

    def __init__(self, connections: SQLiteConnectionFactory) -> None:
        self._connections = connections

    def create_artifact_record(
        self,
        request_id: UUID,
        status: ArtifactLifecycleStatus,
        artifact: Artifact,
        prompt: str,
        body: str,
        model_id: str,
    ) -> None:
        """Create a new artifact lifecycle record."""

        if artifact.signature is None:
            raise RuntimeError("Artifact signature block is missing for persistence.")

        now = utc_now_iso()
        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT INTO artifact_records (
                    request_id, status, title, prompt, body, model_id,
                    artifact_hash,
                    cryptographic_signature, ledger_path, commit_oid,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(request_id),
                    status,
                    artifact.title,
                    prompt,
                    body,
                    model_id,
                    artifact.signature.artifact_hash,
                    artifact.signature.cryptographic_signature,
                    None,
                    None,
                    now,
                    now,
                ),
            )

    def update_artifact_curation(
        self,
        request_id: UUID,
        curated_body: str,
        artifact_hash: str,
        cryptographic_signature: str,
    ) -> None:
        """Update an existing record with curated content and signature."""

        now = utc_now_iso()
        with self._connections.connect() as connection:
            existing = connection.execute(
                """
                SELECT request_id FROM artifact_records
                WHERE request_id = ?;
                """,
                (str(request_id),),
            ).fetchone()
            if existing is None:
                raise RuntimeError(f"Artifact record not found for request_id={request_id}.")
            connection.execute(
                """
                UPDATE artifact_records
                SET status = 'curated',
                    body = ?,
                    artifact_hash = ?,
                    cryptographic_signature = ?,
                    updated_at = ?
                WHERE request_id = ?;
                """,
                (
                    curated_body,
                    artifact_hash,
                    cryptographic_signature,
                    now,
                    str(request_id),
                ),
            )

    def get_artifact_record(self, request_id: UUID) -> ArtifactRecord | None:
        """Fetch one lifecycle record by request id."""

        with self._connections.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifact_records WHERE request_id = ?;",
                (str(request_id),),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def update_artifact_status(
        self,
        request_id: UUID,
        status: ArtifactLifecycleStatus,
        ledger_path: str | None = None,
        commit_oid: str | None = None,
    ) -> None:
        """Update lifecycle status and optional ledger metadata."""

        now = utc_now_iso()
        with self._connections.connect() as connection:
            existing = connection.execute(
                """
                SELECT request_id FROM artifact_records
                WHERE request_id = ?;
                """,
                (str(request_id),),
            ).fetchone()
            if existing is None:
                raise RuntimeError(f"Artifact record not found for request_id={request_id}.")

            connection.execute(
                """
                UPDATE artifact_records
                SET status = ?,
                    ledger_path = COALESCE(?, ledger_path),
                    commit_oid = COALESCE(?, commit_oid),
                    updated_at = ?
                WHERE request_id = ?;
                """,
                (status, ledger_path, commit_oid, now, str(request_id)),
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ArtifactRecord:
        """Convert a SQLite row into an immutable record."""

        return ArtifactRecord(
            request_id=str(row["request_id"]),
            status=row["status"],
            title=row["title"],
            prompt=row["prompt"],
            body=row["body"],
            model_id=row["model_id"],
            artifact_hash=row["artifact_hash"],
            cryptographic_signature=row["cryptographic_signature"],
            ledger_path=row["ledger_path"],
            commit_oid=row["commit_oid"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
