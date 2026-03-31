"""Event subscriber adapter for provenance lifecycle telemetry."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Protocol

from src.domain.events import EventBusPort, StoryAnchored, StoryAudited, StoryTimestamped
from src.logging_config import bind_log_context

_logger = logging.getLogger(__name__)


class TelemetryStorePort(Protocol):
    """Narrow storage contract for provenance event telemetry."""

    def create_provenance_event_log(
        self,
        event_type: str,
        request_id: str | None,
        artifact_id: str | None,
        payload_json: str,
    ) -> None: ...


class ProvenanceTelemetryAdapter:
    """Persist provenance lifecycle events in a structured telemetry log."""

    def __init__(self, event_bus: EventBusPort, store: TelemetryStorePort) -> None:
        self._event_bus = event_bus
        self._store = store

    async def start(self) -> None:
        """Subscribe to provenance lifecycle event channels."""

        await self._event_bus.subscribe(StoryAnchored, self._on_story_anchored)
        await self._event_bus.subscribe(StoryTimestamped, self._on_story_timestamped)
        await self._event_bus.subscribe(StoryAudited, self._on_story_audited)

    async def _on_story_anchored(self, event: StoryAnchored) -> None:
        """Persist one anchoring event telemetry record."""
        await self._persist_event(
            event=event,
            artifact_id=str(event.artifact_id),
        )

    async def _on_story_timestamped(self, event: StoryTimestamped) -> None:
        """Persist one timestamp event telemetry record."""
        await self._persist_event(
            event=event,
            artifact_id=str(event.artifact_id),
        )

    async def _on_story_audited(self, event: StoryAudited) -> None:
        """Persist one audit event telemetry record."""
        await self._persist_event(
            event=event,
            artifact_id=None if event.artifact_id is None else str(event.artifact_id),
        )

    async def _persist_event(
        self,
        event: StoryAnchored | StoryTimestamped | StoryAudited,
        artifact_id: str | None,
    ) -> None:
        """Serialize and persist telemetry without blocking the event loop."""
        bind_log_context(
            request_id=event.request_id,
            artifact_id=artifact_id,
        )
        request_id = None if event.request_id is None else str(event.request_id)
        event_type = type(event).__name__
        try:
            payload_json = json.dumps(event.model_dump(mode="json"), sort_keys=True)
            await asyncio.to_thread(
                self._store.create_provenance_event_log,
                event_type,
                request_id,
                artifact_id,
                payload_json,
            )
        except Exception:
            _logger.exception(
                "Failed to persist provenance telemetry event_type=%s request_id=%s artifact_id=%s",
                event_type,
                request_id or "-",
                artifact_id or "-",
            )
