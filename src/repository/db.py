"""Shared SQLite connection and schema utilities for repository stores."""

from __future__ import annotations

import sqlite3
from pathlib import Path


class SQLiteConnectionFactory:
    """Create consistently configured SQLite connections."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    @property
    def db_path(self) -> Path:
        """Return configured SQLite file path."""

        return self._db_path

    def connect(self) -> sqlite3.Connection:
        """Open one configured SQLite connection."""

        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection


def initialize_artifact_schema(connections: SQLiteConnectionFactory) -> None:
    """Create artifact lifecycle persistence schema if absent."""

    with connections.connect() as connection:
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
            row["name"]
            for row in connection.execute("PRAGMA table_info(artifact_records);")
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
            CREATE TABLE IF NOT EXISTS key_status_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                previous_status TEXT,
                new_status TEXT NOT NULL,
                transition_source TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_key_status_audit_fingerprint_changed_at
            ON key_status_audit_log(fingerprint, changed_at DESC);
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


def initialize_dedup_schema(connections: SQLiteConnectionFactory) -> None:
    """Create per-service message-deduplication schema if absent."""

    with connections.connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_messages (
                message_id TEXT PRIMARY KEY,
                consumer_name TEXT NOT NULL,
                processed_at TEXT NOT NULL
            );
            """
        )
