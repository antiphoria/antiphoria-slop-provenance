"""SQLite repository adapter for artifact lifecycle persistence.

This module isolates all SQL operations behind a synchronous repository that
persists generated/signed artifact lifecycle records in `state.db`.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID

from src.models import Artifact

ArtifactLifecycleStatus = Literal["requested", "generated", "signed", "committed", "failed"]


def _utc_now_iso() -> str:
    """Return current UTC timestamp as ISO-8601 string."""

    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ArtifactRecord:
    """Persistent lifecycle state for one artifact pipeline request.

    Attributes:
        request_id: Correlation ID for orchestration events.
        status: Current lifecycle phase.
        title: Artifact frontmatter title.
        body: Raw generated artifact body.
        model_id: Generator model identifier.
        artifact_hash: SHA-256 hash of body content.
        cryptographic_signature: Base64 ML-DSA signature payload.
        ledger_path: Relative path committed to the git ledger.
        commit_oid: Git commit object id that persisted this artifact.
        created_at: UTC creation timestamp.
        updated_at: UTC last-update timestamp.
    """

    request_id: str
    status: ArtifactLifecycleStatus
    title: str
    body: str
    model_id: str
    artifact_hash: str
    cryptographic_signature: str
    ledger_path: str | None
    commit_oid: str | None
    created_at: str
    updated_at: str


class SQLiteRepository:
    """Synchronous SQLite repository for artifact lifecycle CRUD."""

    def __init__(self, db_path: Path | None = None) -> None:
        """Initialize repository and ensure schema exists.

        Args:
            db_path: Optional path to the SQLite database file.
        """

        self._db_path = db_path or Path("state.db")
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        """Create a configured SQLite connection."""

        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_schema(self) -> None:
        """Create required tables and indexes if absent."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS artifact_records (
                    request_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    artifact_hash TEXT NOT NULL,
                    cryptographic_signature TEXT NOT NULL,
                    ledger_path TEXT,
                    commit_oid TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_artifact_records_status
                ON artifact_records(status);
                """
            )

    def create_artifact_record(
        self,
        request_id: UUID,
        status: ArtifactLifecycleStatus,
        artifact: Artifact,
        body: str,
        model_id: str,
    ) -> None:
        """Create a new artifact lifecycle record.

        Args:
            request_id: Event correlation identifier.
            status: Initial artifact lifecycle status.
            artifact: Artifact frontmatter payload.
            body: Raw generated body.
            model_id: Generation model identifier.
        """

        now = _utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO artifact_records (
                    request_id, status, title, body, model_id, artifact_hash,
                    cryptographic_signature, ledger_path, commit_oid,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(request_id),
                    status,
                    artifact.title,
                    body,
                    model_id,
                    artifact.provenance.artifact_hash,
                    artifact.provenance.cryptographic_signature,
                    None,
                    None,
                    now,
                    now,
                ),
            )

    def get_artifact_record(self, request_id: UUID) -> ArtifactRecord | None:
        """Fetch one lifecycle record by request id.

        Args:
            request_id: Event correlation identifier.

        Returns:
            The persistent record or `None` if absent.
        """

        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifact_records WHERE request_id = ?;",
                (str(request_id),),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def list_artifact_records(
        self,
        status: ArtifactLifecycleStatus | None = None,
        limit: int = 100,
    ) -> list[ArtifactRecord]:
        """List lifecycle records, optionally filtered by status.

        Args:
            status: Optional lifecycle status filter.
            limit: Maximum records returned.

        Returns:
            Most-recently updated records first.
        """

        if limit <= 0:
            raise RuntimeError("list limit must be a positive integer.")

        query = "SELECT * FROM artifact_records"
        params: tuple[object, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY updated_at DESC LIMIT ?;"
        params = (*params, limit)

        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def update_artifact_status(
        self,
        request_id: UUID,
        status: ArtifactLifecycleStatus,
        ledger_path: str | None = None,
        commit_oid: str | None = None,
    ) -> None:
        """Update lifecycle status and optional ledger metadata.

        Args:
            request_id: Event correlation identifier.
            status: New lifecycle status.
            ledger_path: Optional repository path for committed markdown.
            commit_oid: Optional commit id where artifact was persisted.
        """

        now = _utc_now_iso()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT request_id FROM artifact_records WHERE request_id = ?;",
                (str(request_id),),
            ).fetchone()
            if existing is None:
                raise RuntimeError(
                    f"Artifact record not found for request_id={request_id}."
                )

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

    def delete_artifact_record(self, request_id: UUID) -> None:
        """Delete one lifecycle record.

        Args:
            request_id: Event correlation identifier.
        """

        with self._connect() as connection:
            connection.execute(
                "DELETE FROM artifact_records WHERE request_id = ?;",
                (str(request_id),),
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ArtifactRecord:
        """Convert a SQLite row into a typed immutable record."""

        return ArtifactRecord(
            request_id=str(row["request_id"]),
            status=row["status"],
            title=row["title"],
            body=row["body"],
            model_id=row["model_id"],
            artifact_hash=row["artifact_hash"],
            cryptographic_signature=row["cryptographic_signature"],
            ledger_path=row["ledger_path"],
            commit_oid=row["commit_oid"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
