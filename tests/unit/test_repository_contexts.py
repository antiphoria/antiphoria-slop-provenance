"""Tests for bounded-context repository facades."""

from __future__ import annotations

from pathlib import Path

from src.repository.sqlite import SQLiteRepository


def test_sqlite_repository_exposes_context_facades(tmp_path: Path) -> None:
    repository = SQLiteRepository(db_path=tmp_path / "state.db")

    repository.keys.upsert_key_registry_entry(
        fingerprint="fp-context-test",
        key_version="v1",
        status="active",
        metadata_json='{"source":"test"}',
    )
    key_entry = repository.keys.get_key_registry_entry("fp-context-test")
    assert key_entry is not None
    assert key_entry["status"] == "active"

    repository.telemetry.create_provenance_event_log(
        event_type="StoryAnchored",
        request_id="req-1",
        artifact_id="art-1",
        payload_json='{"ok":true}',
    )
    events = repository.telemetry.list_provenance_event_logs(limit=5)
    assert len(events) == 1
    assert events[0]["event_type"] == "StoryAnchored"
