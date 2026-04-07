"""Unit tests for async-safe provenance telemetry persistence."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from src.adapters.provenance_telemetry import ProvenanceTelemetryAdapter
from src.domain.events import StoryAnchored, StoryAudited
from src.infrastructure.event_bus import InMemoryEventBus


async def _run_in_fake_thread(
    func: object,
    *args: object,
    **kwargs: object,
) -> object:
    callable_func = func
    if not callable(callable_func):
        raise RuntimeError("Expected callable for asyncio.to_thread test shim.")
    return callable_func(*args, **kwargs)


class ProvenanceTelemetryAdapterTest(unittest.IsolatedAsyncioTestCase):
    """Validate async loop safety and failure isolation."""

    async def test_anchored_event_persists_via_to_thread(self) -> None:
        store = MagicMock()
        adapter = ProvenanceTelemetryAdapter(
            event_bus=InMemoryEventBus(),
            store=store,
        )
        request_id = uuid4()
        artifact_id = uuid4()
        event = StoryAnchored(
            request_id=request_id,
            artifact_id=artifact_id,
            artifact_hash="a" * 64,
            transparency_entry_id="entry-1",
            transparency_entry_hash="b" * 64,
            log_path=".provenance/transparency-log.jsonl",
        )

        with patch(
            "src.adapters.provenance_telemetry.asyncio.to_thread",
            side_effect=_run_in_fake_thread,
        ) as to_thread_mock:
            await adapter._on_story_anchored(event)

        self.assertEqual(to_thread_mock.await_count, 1)
        store.create_provenance_event_log.assert_called_once()
        persisted = store.create_provenance_event_log.call_args.args
        self.assertEqual(persisted[0], "StoryAnchored")
        self.assertEqual(persisted[1], str(request_id))
        self.assertEqual(persisted[2], str(artifact_id))
        self.assertIn('"artifact_id"', persisted[3])

    async def test_audited_event_logs_failure_without_raising(self) -> None:
        store = MagicMock()
        store.create_provenance_event_log.side_effect = RuntimeError("db write failed")
        adapter = ProvenanceTelemetryAdapter(
            event_bus=InMemoryEventBus(),
            store=store,
        )
        event = StoryAudited(
            request_id=uuid4(),
            artifact_id=None,
            audit_passed=False,
            report_path="audit.json",
        )

        with (
            patch(
                "src.adapters.provenance_telemetry.asyncio.to_thread",
                side_effect=_run_in_fake_thread,
            ),
            self.assertLogs(
                "src.adapters.provenance_telemetry",
                level="ERROR",
            ) as logs,
        ):
            await adapter._on_story_audited(event)

        self.assertIn(
            "Failed to persist provenance telemetry",
            "\n".join(logs.output),
        )


if __name__ == "__main__":
    unittest.main()
