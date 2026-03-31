"""Per-service dedup repository for processed message IDs."""

from __future__ import annotations

from pathlib import Path

from src.repository.db import SQLiteConnectionFactory, initialize_dedup_schema
from src.repository.types import utc_now_iso


class DedupRepository:
    """Per-service SQLite repository for message deduplication only."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or Path("state.db")
        self._connections = SQLiteConnectionFactory(self._db_path)
        initialize_dedup_schema(self._connections)

    def _connect(self):
        """Create a configured SQLite connection."""

        return self._connections.connect()

    def _initialize_schema(self) -> None:
        """Create dedup schema if absent."""

        initialize_dedup_schema(self._connections)

    def is_message_processed(
        self,
        message_id: str,
        consumer_name: str,
    ) -> bool:
        """Return True when message was already marked processed."""

        with self._connections.connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM processed_messages
                WHERE message_id = ? AND consumer_name = ?;
                """,
                (message_id, consumer_name),
            ).fetchone()
            return row is not None

    def mark_message_processed(
        self,
        message_id: str,
        consumer_name: str,
    ) -> None:
        """Mark one message id as processed. Idempotent."""

        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO processed_messages (
                    message_id, consumer_name, processed_at
                ) VALUES (?, ?, ?);
                """,
                (message_id, consumer_name, utc_now_iso()),
            )

    def try_mark_message_processed(
        self,
        message_id: str,
        consumer_name: str,
    ) -> bool:
        """Try to mark one message id as processed."""

        with self._connections.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO processed_messages (
                    message_id, consumer_name, processed_at
                ) VALUES (?, ?, ?);
                """,
                (message_id, consumer_name, utc_now_iso()),
            )
            return cursor.rowcount == 1

    def unmark_message_processed(
        self,
        message_id: str,
        consumer_name: str,
    ) -> None:
        """Remove processed mark so message can be retried."""

        with self._connections.connect() as connection:
            connection.execute(
                """
                DELETE FROM processed_messages
                WHERE message_id = ? AND consumer_name = ?;
                """,
                (message_id, consumer_name),
            )
