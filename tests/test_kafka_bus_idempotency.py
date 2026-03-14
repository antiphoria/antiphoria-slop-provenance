"""Tests for Kafka event bus idempotency helpers."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

import pytest

pytest.importorskip("aiokafka")

from src.kafka.event_bus import KafkaEventBus


@dataclass
class _FakeMessage:
    topic: str
    partition: int
    offset: int
    headers: list[tuple[str, bytes]] | None


class _FakeDedupRepository:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def is_message_processed(self, message_id: str, consumer_name: str) -> bool:
        _ = consumer_name
        return message_id in self._seen

    def mark_message_processed(self, message_id: str, consumer_name: str) -> None:
        _ = consumer_name
        self._seen.add(message_id)

    def try_mark_message_processed(self, message_id: str, consumer_name: str) -> bool:
        _ = consumer_name
        if message_id in self._seen:
            return False
        self._seen.add(message_id)
        return True


class KafkaBusIdempotencyTest(unittest.IsolatedAsyncioTestCase):
    """Validate message id extraction and dedupe behavior."""

    async def test_should_process_message_dedupes_same_message(self) -> None:
        repository = _FakeDedupRepository()
        bus = KafkaEventBus(
            bootstrap_servers="localhost:9092",
            consumer_group="test-group",
            dedup_repository=repository,
        )
        message = _FakeMessage(
            topic="story.requested",
            partition=0,
            offset=10,
            headers=[("x-message-id", b"mid-123")],
        )
        first = await bus._should_process_message(message)
        await bus._mark_message_processed(message)
        second = await bus._should_process_message(message)
        self.assertTrue(first)
        self.assertFalse(second)

    def test_extract_message_id_from_headers(self) -> None:
        message = _FakeMessage(
            topic="story.generated",
            partition=1,
            offset=22,
            headers=[("x-message-id", b"msg-abc")],
        )
        extracted = KafkaEventBus._extract_message_id(message)
        self.assertEqual(extracted, "msg-abc")

    def test_extract_message_id_fallback(self) -> None:
        message = _FakeMessage(
            topic="story.signed",
            partition=2,
            offset=99,
            headers=[],
        )
        extracted = KafkaEventBus._extract_message_id(message)
        self.assertEqual(extracted, "story.signed:2:99")

    async def test_attempt_handoff_reports_retry_failure(self) -> None:
        bus = KafkaEventBus(
            bootstrap_servers="localhost:9092",
            consumer_group="test-group",
        )

        async def _boom_retry(*args: object, **kwargs: object) -> None:
            _ = (args, kwargs)
            raise RuntimeError("retry unavailable")

        bus._publish_retry = _boom_retry  # type: ignore[method-assign]
        message = _FakeMessage(
            topic="story.generated",
            partition=1,
            offset=9,
            headers=[("x-retry-count", b"0")],
        )
        ok, target, error = await bus._attempt_handoff(
            base_topic="story.generated",
            message=message,
            retry_count=0,
            failure_message="handler failed",
        )
        self.assertFalse(ok)
        self.assertEqual(target, "retry")
        self.assertIn("retry unavailable", error or "")

    def test_metrics_snapshot_reflects_increments(self) -> None:
        bus = KafkaEventBus(
            bootstrap_servers="localhost:9092",
            consumer_group="test-group",
        )
        bus._increment_metric("events_processed_total", "story.generated")
        bus._increment_metric("events_processed_total", "story.generated")
        metrics = bus.metrics_snapshot()
        self.assertEqual(metrics["events_processed_total:story.generated"], 2)

    def test_metrics_snapshot_persists_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "generator-service.json"
            bus = KafkaEventBus(
                bootstrap_servers="localhost:9092",
                consumer_group="generator-service",
                metrics_snapshot_path=snapshot_path,
                metrics_flush_every=1,
            )
            bus._increment_metric("events_processed_total", "story.generated")
            self.assertTrue(snapshot_path.exists())
            loaded = snapshot_path.read_text(encoding="utf-8")
            self.assertIn('"consumerGroup": "generator-service"', loaded)
            self.assertIn('"events_processed_total:story.generated": 1', loaded)


if __name__ == "__main__":
    unittest.main()
