"""Strict SQLite repository root exposing scoped stores only."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from src.repository.db import SQLiteConnectionFactory, initialize_artifact_schema
from src.repository.stores import (
    ArtifactStore,
    AuditStore,
    KeyRegistryStore,
    TelemetryStore,
    TimestampStore,
    TransparencyStore,
)


class SQLiteRepository:
    """SQLite-backed repository root composed of bounded stores."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or Path("state.db")
        self._connections = SQLiteConnectionFactory(self._db_path)
        initialize_artifact_schema(self._connections)

        self.artifacts = ArtifactStore(self._connections)
        self.transparency = TransparencyStore(self._connections)
        self.timestamps = TimestampStore(self._connections)
        self.keys = KeyRegistryStore(self._connections)
        self.audit = AuditStore(self._connections)
        self.telemetry = TelemetryStore(self._connections)

    def _connect(self) -> sqlite3.Connection:
        """Return one configured sqlite3 connection."""

        return self._connections.connect()
