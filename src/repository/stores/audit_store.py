"""Audit report SQL store."""

from __future__ import annotations

from uuid import uuid4

from src.repository.db import SQLiteConnectionFactory
from src.repository.types import utc_now_iso


class AuditStore:
    """Store for machine-readable provenance audit reports."""

    def __init__(self, connections: SQLiteConnectionFactory) -> None:
        self._connections = connections

    def create_audit_report(
        self,
        artifact_id: str,
        request_id: str | None,
        report_json: str,
    ) -> str:
        """Persist one machine-readable audit report."""

        audit_id = str(uuid4())
        created_at = utc_now_iso()
        with self._connections.connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_reports (
                    audit_id, artifact_id, request_id, report_json, created_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (audit_id, artifact_id, request_id, report_json, created_at),
            )
        return audit_id
