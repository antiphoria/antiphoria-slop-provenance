"""Event subscriber adapter for provenance lifecycle telemetry."""

from __future__ import annotations

import json

from src.events import EventBusPort, StoryAnchored, StoryAudited, StoryTimestamped
from src.repository import SQLiteRepository


class ProvenanceTelemetryAdapter:
    """Persist provenance lifecycle events in a structured telemetry log."""

    def __init__(self, event_bus: EventBusPort, repository: SQLiteRepository) -> None:
        self._event_bus = event_bus
        self._repository = repository

    async def start(self) -> None:
        """Subscribe to provenance lifecycle event channels."""

        await self._event_bus.subscribe(StoryAnchored, self._on_story_anchored)
        await self._event_bus.subscribe(StoryTimestamped, self._on_story_timestamped)
        await self._event_bus.subscribe(StoryAudited, self._on_story_audited)

    async def _on_story_anchored(self, event: StoryAnchored) -> None:
        """Persist one anchoring event telemetry record."""

        self._repository.create_provenance_event_log(
            event_type=type(event).__name__,
            request_id=None if event.request_id is None else str(event.request_id),
            artifact_id=str(event.artifact_id),
            payload_json=json.dumps(event.model_dump(mode="json"), sort_keys=True),
        )

    async def _on_story_timestamped(self, event: StoryTimestamped) -> None:
        """Persist one timestamp event telemetry record."""

        self._repository.create_provenance_event_log(
            event_type=type(event).__name__,
            request_id=None if event.request_id is None else str(event.request_id),
            artifact_id=str(event.artifact_id),
            payload_json=json.dumps(event.model_dump(mode="json"), sort_keys=True),
        )

    async def _on_story_audited(self, event: StoryAudited) -> None:
        """Persist one audit event telemetry record."""

        self._repository.create_provenance_event_log(
            event_type=type(event).__name__,
            request_id=None if event.request_id is None else str(event.request_id),
            artifact_id=None if event.artifact_id is None else str(event.artifact_id),
            payload_json=json.dumps(event.model_dump(mode="json"), sort_keys=True),
        )
