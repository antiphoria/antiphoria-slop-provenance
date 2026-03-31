"""Provenance event telemetry SQL store."""

from __future__ import annotations

from src.repository.db import SQLiteConnectionFactory
from src.repository.types import utc_now_iso


class TelemetryStore:
    """Store for provenance event log telemetry rows."""

    def __init__(self, connections: SQLiteConnectionFactory) -> None:
        self._connections = connections

    def create_provenance_event_log(
        self,
        event_type: str,
        request_id: str | None,
        artifact_id: str | None,
        payload_json: str,
    ) -> None:
        """Persist one provenance lifecycle event payload."""

        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT INTO provenance_event_log (
                    event_type, request_id, artifact_id, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (event_type, request_id, artifact_id, payload_json, utc_now_iso()),
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
        with self._connections.connect() as connection:
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
