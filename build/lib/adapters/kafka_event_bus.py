"""Kafka-backed event bus adapter with retry and DLQ support."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any
from typing import Protocol
from typing import cast
from uuid import UUID, uuid4

from pydantic import BaseModel

from src.events import (
    EventBusPort,
    EventHandler,
    EventHandlerError,
    EventT,
    ErrorHandler,
    StoryAnchored,
    StoryAudited,
    StoryCommitted,
    StoryCurated,
    StoryGenerated,
    StoryRequested,
    StorySigned,
    StoryTimestamped,
)

LOGGER = logging.getLogger(__name__)

_EVENT_TYPES: tuple[type[BaseModel], ...] = (
    StoryRequested,
    StoryGenerated,
    StorySigned,
    StoryCommitted,
    StoryCurated,
    StoryAnchored,
    StoryTimestamped,
    StoryAudited,
)
_EVENT_BY_NAME = {event_type.__name__: event_type for event_type in _EVENT_TYPES}

_TOPIC_BY_EVENT = {
    StoryRequested: "story.requested",
    StoryGenerated: "story.generated",
    StorySigned: "story.signed",
    StoryCommitted: "story.committed",
    StoryCurated: "story.curated",
    StoryAnchored: "story.anchored",
    StoryTimestamped: "story.timestamped",
    StoryAudited: "story.audited",
}


class MessageDedupRepository(Protocol):
    """Persistence interface for message-level idempotency checks."""

    def try_mark_message_processed(self, message_id: str, consumer_name: str) -> bool:
        """Return True when message id is newly marked."""


class KafkaEventBus(EventBusPort):
    """Distributed event bus backed by Kafka topics."""

    def __init__(
        self,
        bootstrap_servers: str,
        consumer_group: str,
        retry_topic_suffix: str = ".retry",
        dlq_topic_suffix: str = ".dlq",
        max_retries: int = 3,
        dedup_repository: MessageDedupRepository | None = None,
        metrics_snapshot_path: Path | None = None,
        metrics_flush_every: int = 100,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._consumer_group = consumer_group
        self._retry_topic_suffix = retry_topic_suffix
        self._dlq_topic_suffix = dlq_topic_suffix
        self._max_retries = max_retries
        self._dedup_repository = dedup_repository
        self._metrics_snapshot_path = metrics_snapshot_path
        self._metrics_flush_every = max(1, metrics_flush_every)
        self._producer = None
        self._subscribers: dict[type[BaseModel], list[EventHandler[BaseModel]]] = {}
        self._error_subscribers: list[ErrorHandler] = []
        self._consumer_tasks: dict[type[BaseModel], asyncio.Task[None]] = {}
        self._consumer_handles: dict[type[BaseModel], object] = {}
        self._metrics: dict[str, int] = {}
        self._metrics_dirty_updates = 0
        self._lock = asyncio.Lock()
        self._stopped = False

    async def start(self) -> None:
        """Initialize Kafka producer lazily."""

        try:
            from aiokafka import AIOKafkaProducer  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "aiokafka is required for Kafka mode. Install 'aiokafka'."
            ) from exc
        self._producer = AIOKafkaProducer(bootstrap_servers=self._bootstrap_servers)
        await self._producer.start()
        self._stopped = False

    async def stop(self) -> None:
        """Shutdown consumers and producer."""

        self._stopped = True
        async with self._lock:
            tasks = tuple(self._consumer_tasks.values())
            self._consumer_tasks.clear()
            consumers = tuple(self._consumer_handles.values())
            self._consumer_handles.clear()
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                continue
        for consumer in consumers:
            try:
                await consumer.stop()
            except Exception:
                continue
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None
        self._persist_metrics_snapshot(force=True)

    async def subscribe(
        self,
        event_type: type[EventT],
        handler: EventHandler[EventT],
    ) -> None:
        """Register handler and spawn topic consumers for event type."""

        async with self._lock:
            self._subscribers.setdefault(event_type, []).append(
                cast(EventHandler[BaseModel], handler)
            )
            if event_type not in self._consumer_tasks:
                task = asyncio.create_task(self._consume_event_type(event_type))
                self._consumer_tasks[event_type] = task

    async def unsubscribe(
        self,
        event_type: type[EventT],
        handler: EventHandler[EventT],
    ) -> None:
        """Remove handler for one event type."""

        async with self._lock:
            handlers = self._subscribers.get(event_type)
            if handlers is None:
                return
            raw_handler = cast(EventHandler[BaseModel], handler)
            if raw_handler in handlers:
                handlers.remove(raw_handler)
            if not handlers:
                del self._subscribers[event_type]

    async def subscribe_errors(self, handler: ErrorHandler) -> None:
        """Register error handler for dispatch failures."""

        async with self._lock:
            self._error_subscribers.append(handler)

    async def unsubscribe_errors(self, handler: ErrorHandler) -> None:
        """Remove registered error handler."""

        async with self._lock:
            if handler in self._error_subscribers:
                self._error_subscribers.remove(handler)

    async def emit(self, event: EventT) -> None:
        """Publish event to corresponding Kafka topic."""

        if self._producer is None:
            raise RuntimeError("Kafka producer is not started.")
        topic = _TOPIC_BY_EVENT.get(type(event))
        if topic is None:
            raise RuntimeError(f"Unsupported Kafka event type: {type(event).__name__}.")
        event_data = {
            "eventType": type(event).__name__,
            "payload": event.model_dump(mode="json"),
        }
        request_id_value = getattr(event, "request_id", None)
        key = self._build_event_key(request_id_value)
        await self._producer.send_and_wait(
            topic=topic,
            key=key,
            value=json.dumps(event_data, sort_keys=True).encode("utf-8"),
            headers=[("x-message-id", str(uuid4()).encode("ascii"))],
        )
        self._increment_metric("events_emitted_total", topic)

    async def _consume_event_type(self, event_type: type[BaseModel]) -> None:
        """Consume primary and retry topics for one event type."""

        try:
            from aiokafka import AIOKafkaConsumer  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "aiokafka is required for Kafka mode. Install 'aiokafka'."
            ) from exc
        topic = _TOPIC_BY_EVENT[event_type]
        retry_topic = f"{topic}{self._retry_topic_suffix}"
        consumer = AIOKafkaConsumer(
            topic,
            retry_topic,
            bootstrap_servers=self._bootstrap_servers,
            group_id=self._consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        async with self._lock:
            self._consumer_handles[event_type] = consumer
        await consumer.start()
        try:
            while not self._stopped:
                message_batch = await consumer.getmany(timeout_ms=1000)
                for _, messages in message_batch.items():
                    for message in messages:
                        await self._handle_message(
                            event_type=event_type,
                            base_topic=topic,
                            consumer=consumer,
                            message=message,
                        )
        finally:
            await consumer.stop()

    async def _handle_message(
        self,
        event_type: type[BaseModel],
        base_topic: str,
        consumer: Any,
        message: Any,
    ) -> None:
        """Decode and dispatch one Kafka message for a typed event."""

        try:
            if not await self._should_process_message(message):
                self._increment_metric("events_deduplicated_total", base_topic)
                await self._commit_message_offset(consumer, message)
                return
            raw = json.loads(message.value.decode("utf-8"))
            event_name = str(raw["eventType"])
            payload = raw["payload"]
            resolved_type = _EVENT_BY_NAME.get(event_name)
            if resolved_type is None or resolved_type is not event_type:
                await self._commit_message_offset(consumer, message)
                return
            event = event_type.model_validate(payload)
            handlers = tuple(self._subscribers.get(event_type, []))
            for handler in handlers:
                await handler(event)
            self._increment_metric("events_processed_total", base_topic)
            await self._commit_message_offset(consumer, message)
        except Exception as exc:  # noqa: BLE001
            retry_count = self._extract_retry_count(message.headers)
            handoff_succeeded, handoff_target, handoff_error = await self._attempt_handoff(
                base_topic=base_topic,
                message=message,
                retry_count=retry_count,
                failure_message=str(exc),
            )
            if handoff_succeeded:
                metric_name = (
                    "events_retried_total" if handoff_target == "retry" else "events_dlq_total"
                )
                self._increment_metric(metric_name, base_topic)
            else:
                self._increment_metric("handoff_failures_total", base_topic)
                LOGGER.error(
                    "Kafka handoff failed",
                    extra={
                        "topic": base_topic,
                        "partition": message.partition,
                        "offset": message.offset,
                        "retry_count": retry_count,
                        "handoff_target": handoff_target,
                        "handoff_error": handoff_error,
                    },
                )
            await self._publish_handler_error(event_type, exc)
            if handoff_succeeded:
                await self._commit_message_offset(consumer, message)

    async def _publish_retry(
        self,
        base_topic: str,
        message: object,
        retry_count: int,
    ) -> None:
        """Republish failed message to retry topic."""

        if self._producer is None:
            return
        headers = list(message.headers or [])
        headers = [h for h in headers if h[0] != "x-retry-count"]
        headers.append(("x-retry-count", str(retry_count).encode("ascii")))
        await self._producer.send_and_wait(
            topic=f"{base_topic}{self._retry_topic_suffix}",
            key=message.key,
            value=message.value,
            headers=headers,
        )

    async def _publish_dlq(
        self,
        base_topic: str,
        message: object,
        error_message: str,
    ) -> None:
        """Publish irrecoverable message to dead-letter queue."""

        if self._producer is None:
            return
        payload = {
            "topic": base_topic,
            "partition": message.partition,
            "offset": message.offset,
            "error": error_message,
            "value": message.value.decode("utf-8", errors="replace"),
        }
        await self._producer.send_and_wait(
            topic=f"{base_topic}{self._dlq_topic_suffix}",
            key=message.key,
            value=json.dumps(payload, sort_keys=True).encode("utf-8"),
        )

    async def _publish_handler_error(
        self,
        event_type: type[BaseModel],
        error: Exception,
    ) -> None:
        """Emit structured handler errors to registered error handlers."""

        payload = EventHandlerError(
            event_type=event_type.__name__,
            handler_name="KafkaEventBus",
            error_type=type(error).__name__,
            error_message=str(error) or "<no message>",
        )
        handlers = tuple(self._error_subscribers)
        for handler in handlers:
            try:
                await handler(payload)
            except Exception:
                continue
        LOGGER.exception("Kafka event dispatch failed for %s", event_type.__name__)

    async def _attempt_handoff(
        self,
        base_topic: str,
        message: Any,
        retry_count: int,
        failure_message: str,
    ) -> tuple[bool, str, str | None]:
        """Attempt retry or DLQ handoff and return status."""

        if retry_count < self._max_retries:
            try:
                await self._publish_retry(base_topic, message, retry_count + 1)
                return (True, "retry", None)
            except Exception as retry_exc:  # noqa: BLE001
                return (False, "retry", str(retry_exc))
        try:
            await self._publish_dlq(base_topic, message, failure_message)
            return (True, "dlq", None)
        except Exception as dlq_exc:  # noqa: BLE001
            return (False, "dlq", str(dlq_exc))

    async def _should_process_message(self, message: Any) -> bool:
        """Return False when message was already processed by this consumer."""

        if self._dedup_repository is None:
            return True
        message_id = self._extract_message_id(message)
        return await asyncio.to_thread(
            self._dedup_repository.try_mark_message_processed,
            message_id,
            self._consumer_group,
        )

    async def _commit_message_offset(self, consumer: Any, message: Any) -> None:
        """Commit one message offset only after successful processing handoff."""

        from aiokafka.structs import OffsetAndMetadata, TopicPartition  # type: ignore

        topic_partition = TopicPartition(message.topic, message.partition)
        offset_metadata = OffsetAndMetadata(message.offset + 1, "")
        await consumer.commit({topic_partition: offset_metadata})

    @staticmethod
    def _build_event_key(request_id_value: object) -> bytes:
        """Build deterministic event key from request id when available."""

        if isinstance(request_id_value, UUID):
            return str(request_id_value).encode("ascii")
        if isinstance(request_id_value, str) and request_id_value:
            return request_id_value.encode("ascii", errors="ignore")
        return str(uuid4()).encode("ascii")

    @staticmethod
    def _extract_retry_count(headers: list[tuple[str, bytes]] | None) -> int:
        """Read retry count from Kafka headers."""

        if headers is None:
            return 0
        for key, value in headers:
            if key != "x-retry-count":
                continue
            try:
                return int(value.decode("ascii"))
            except ValueError:
                return 0
        return 0

    @staticmethod
    def _extract_message_id(message: Any) -> str:
        """Extract stable message id from headers or fallback topic offset key."""

        headers = list(message.headers or [])
        for key, value in headers:
            if key != "x-message-id":
                continue
            decoded = value.decode("ascii", errors="ignore").strip()
            if decoded:
                return decoded
        return f"{message.topic}:{message.partition}:{message.offset}"

    def _increment_metric(self, metric_name: str, topic: str) -> None:
        """Increment one in-memory per-topic metric counter."""

        key = f"{metric_name}:{topic}"
        self._metrics[key] = self._metrics.get(key, 0) + 1
        self._metrics_dirty_updates += 1
        if self._metrics_dirty_updates >= self._metrics_flush_every:
            self._persist_metrics_snapshot(force=False)

    def metrics_snapshot(self) -> dict[str, int]:
        """Return a shallow copy of collected in-memory counters."""

        return dict(self._metrics)

    def _persist_metrics_snapshot(self, force: bool) -> None:
        """Persist metric counters to JSON snapshot when configured."""

        if self._metrics_snapshot_path is None:
            return
        if not force and self._metrics_dirty_updates < self._metrics_flush_every:
            return
        payload = {
            "consumerGroup": self._consumer_group,
            "metrics": self.metrics_snapshot(),
        }
        self._metrics_snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        self._metrics_snapshot_path.write_text(
            json.dumps(payload, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        self._metrics_dirty_updates = 0
