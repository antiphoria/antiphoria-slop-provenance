"""SQLite repository adapter for artifact lifecycle persistence.

This module isolates all SQL operations behind a synchronous repository that
persists generated/signed artifact lifecycle records. DedupRepository handles
message-level idempotency (processed_messages) per-service; SQLiteRepository
handles shared artifact lifecycle (artifact_records, key_registry, etc.).
"""

from __future__ import annotations

import base64
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from src.adapters.rfc3161_tsa import RFC3161TSAAdapter, TimestampVerification
from src.models import Artifact


class DedupRepository:
    """Per-service SQLite repository for message deduplication only.

    Each service uses its own STATE_DB_PATH (e.g. /state/ledger.db) to avoid
    lock contention. Implements MessageDedupRepository protocol.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or Path("state.db")
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_messages (
                    message_id TEXT PRIMARY KEY,
                    consumer_name TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                );
                """
            )

    def is_message_processed(self, message_id: str, consumer_name: str) -> bool:
        """Return True when message was already marked processed."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM processed_messages
                WHERE message_id = ? AND consumer_name = ?;
                """,
                (message_id, consumer_name),
            ).fetchone()
            return row is not None

    def mark_message_processed(self, message_id: str, consumer_name: str) -> None:
        """Mark one message id as processed. Idempotent."""
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO processed_messages (
                    message_id, consumer_name, processed_at
                ) VALUES (?, ?, ?);
                """,
                (message_id, consumer_name, _utc_now_iso()),
            )

    def try_mark_message_processed(self, message_id: str, consumer_name: str) -> bool:
        """Try to mark one message id as processed.

        Returns:
            True when inserted for the first time, False if already processed.
        """
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO processed_messages (
                    message_id, consumer_name, processed_at
                ) VALUES (?, ?, ?);
                """,
                (message_id, consumer_name, _utc_now_iso()),
            )
            return cursor.rowcount == 1

    def unmark_message_processed(self, message_id: str, consumer_name: str) -> None:
        """Remove processed mark so message can be retried after handler failure."""
        with self._connect() as connection:
            connection.execute(
                """
                DELETE FROM processed_messages
                WHERE message_id = ? AND consumer_name = ?;
                """,
                (message_id, consumer_name),
            )


ArtifactLifecycleStatus = Literal[
    "requested",
    "generated",
    "signed",
    "curated",
    "committed",
    "failed",
]

OtsForgeStatus = Literal["PENDING", "FORGED", "FAILED"]


@dataclass(frozen=True)
class OtsForgeRecord:
    """OpenTimestamps forge state for one artifact."""

    request_id: str
    artifact_hash: str
    status: str
    pending_ots_b64: str
    final_ots_b64: str | None
    bitcoin_block_height: int | None
    created_at: str
    updated_at: str


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
        prompt: Original user prompt used for generation.
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
    prompt: str
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
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
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
                    prompt TEXT NOT NULL DEFAULT '',
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
            existing_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(artifact_records);")
            }
            if "prompt" not in existing_columns:
                connection.execute(
                    """
                    ALTER TABLE artifact_records
                    ADD COLUMN prompt TEXT NOT NULL DEFAULT '';
                    """
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS transparency_log_records (
                    entry_id TEXT PRIMARY KEY,
                    artifact_hash TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    request_id TEXT,
                    source_file TEXT NOT NULL,
                    log_path TEXT NOT NULL,
                    previous_entry_hash TEXT,
                    entry_hash TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    remote_receipt TEXT
                );
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS timestamp_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_hash TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    request_id TEXT,
                    tsa_url TEXT NOT NULL,
                    token_base64 TEXT NOT NULL,
                    digest_algorithm TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    verification_message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS key_registry (
                    fingerprint TEXT PRIMARY KEY,
                    key_version TEXT,
                    status TEXT NOT NULL,
                    metadata_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_reports (
                    audit_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    request_id TEXT,
                    report_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS provenance_event_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    request_id TEXT,
                    artifact_id TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_artifact_record(
        self,
        request_id: UUID,
        status: ArtifactLifecycleStatus,
        artifact: Artifact,
        prompt: str,
        body: str,
        model_id: str,
    ) -> None:
        """Create a new artifact lifecycle record.

        Args:
            request_id: Event correlation identifier.
            status: Initial artifact lifecycle status.
            artifact: Artifact frontmatter payload.
            prompt: Original user prompt for this artifact.
            body: Raw generated body.
            model_id: Generation model identifier.
        """

        if artifact.signature is None:
            raise RuntimeError("Artifact signature block is missing for persistence.")

        now = _utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO artifact_records (
                    request_id, status, title, prompt, body, model_id, artifact_hash,
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
        """Update an existing record with curated content and signature.

        Args:
            request_id: Event correlation identifier.
            curated_body: Human-curated artifact body.
            artifact_hash: New SHA-256 hash for curated body.
            cryptographic_signature: New ML-DSA signature.
        """

        now = _utc_now_iso()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT request_id FROM artifact_records WHERE request_id = ?;",
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

    def has_transparency_log_record(self, artifact_hash: str) -> bool:
        """Return True if a transparency log record exists for this artifact hash."""
        with self._connect() as connection:
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

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO transparency_log_records (
                    entry_id, artifact_hash, artifact_id, request_id, source_file, log_path,
                    previous_entry_hash, entry_hash, published_at, remote_receipt
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
        """Persist one RFC3161 token record and return creation timestamp."""

        created_at = _utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO timestamp_records (
                    artifact_hash, artifact_id, request_id, tsa_url, token_base64,
                    digest_algorithm, verification_status, verification_message, created_at
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

    def get_latest_timestamp_record(self, artifact_hash: str) -> sqlite3.Row | None:
        """Return latest timestamp record for one artifact hash."""

        with self._connect() as connection:
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
                message=f"No timestamp token found for artifact_hash={artifact_hash}.",
            )
        token_b64 = str(record["token_base64"])
        token_bytes = base64.b64decode(token_b64.encode("ascii"), validate=True)
        return tsa_adapter.verify_timestamp_token(
            digest_hex=artifact_hash,
            token_bytes=token_bytes,
            tsa_ca_cert_path=tsa_ca_cert_path,
            digest_algorithm=str(record["digest_algorithm"]),
        )

    def upsert_key_registry_entry(
        self,
        fingerprint: str,
        key_version: str | None,
        status: str,
        metadata_json: str | None,
    ) -> None:
        """Create or update key registry entry."""

        now = _utc_now_iso()
        with self._connect() as connection:
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

    def update_key_registry_status(self, fingerprint: str, status: str) -> None:
        """Update lifecycle status for one key fingerprint."""

        now = _utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE key_registry
                SET status = ?, updated_at = ?
                WHERE fingerprint = ?;
                """,
                (status, now, fingerprint),
            )

    def get_key_registry_entry(self, fingerprint: str) -> dict[str, str] | None:
        """Get key registry entry by signer fingerprint."""

        with self._connect() as connection:
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

    def create_audit_report(
        self,
        artifact_id: str,
        request_id: str | None,
        report_json: str,
    ) -> str:
        """Persist one machine-readable audit report."""

        audit_id = str(uuid4())
        created_at = _utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_reports (
                    audit_id, artifact_id, request_id, report_json, created_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (audit_id, artifact_id, request_id, report_json, created_at),
            )
        return audit_id

    def create_provenance_event_log(
        self,
        event_type: str,
        request_id: str | None,
        artifact_id: str | None,
        payload_json: str,
    ) -> None:
        """Persist one provenance lifecycle event payload."""

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO provenance_event_log (
                    event_type, request_id, artifact_id, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (event_type, request_id, artifact_id, payload_json, _utc_now_iso()),
            )

    def list_provenance_event_logs(
        self,
        limit: int = 50,
        event_type: str | None = None,
    ) -> list[dict[str, str | int | None]]:
        """List recent provenance lifecycle events with optional type filter."""

        if limit <= 0:
            raise RuntimeError("event log limit must be a positive integer.")
        query = (
            "SELECT id, event_type, request_id, artifact_id, payload_json, created_at "
            "FROM provenance_event_log"
        )
        params: tuple[object, ...] = ()
        if event_type is not None:
            query += " WHERE event_type = ?"
            params = (event_type,)
        query += " ORDER BY id DESC LIMIT ?;"
        params = (*params, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "id": int(row["id"]),
                "event_type": str(row["event_type"]),
                "request_id": (None if row["request_id"] is None else str(row["request_id"])),
                "artifact_id": (None if row["artifact_id"] is None else str(row["artifact_id"])),
                "payload_json": str(row["payload_json"]),
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

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
