"""Kafka/event worker that anchors and timestamps committed artifacts."""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

from src.env_config import read_env_optional
from src.events import (
    EventBusPort,
    StoryAnchored,
    StoryCommitted,
    StoryOtsPending,
    StoryTimestamped,
)
from src.services.provenance_service import ProvenanceService


class ProvenanceWorkerAdapter:
    """Subscribe to commit events and execute provenance hardening steps."""

    def __init__(
        self,
        event_bus: EventBusPort,
        provenance_service: ProvenanceService,
        repository_path: Path,
        tsa_ca_cert_path: Path | None,
    ) -> None:
        self._event_bus = event_bus
        self._provenance_service = provenance_service
        self._repository_path = repository_path
        self._tsa_ca_cert_path = tsa_ca_cert_path

    async def start(self) -> None:
        """Subscribe to commit events."""

        await self._event_bus.subscribe(
            StoryCommitted, self._on_story_committed
        )

    async def _on_story_committed(self, event: StoryCommitted) -> None:
        """Anchor and timestamp one committed artifact."""

        anchor_outcome = await asyncio.to_thread(
            self._provenance_service.anchor_committed_artifact,
            self._repository_path,
            event.commit_oid,
            event.ledger_path,
            event.request_id,
        )
        await self._event_bus.emit(
            StoryAnchored(
                request_id=event.request_id,
                artifact_id=UUID(anchor_outcome.artifact_id),
                artifact_hash=anchor_outcome.artifact_hash,
                transparency_entry_id=anchor_outcome.entry_id,
                transparency_entry_hash=anchor_outcome.entry_hash,
                log_path=anchor_outcome.log_path,
            )
        )
        try:
            timestamp_outcome = await asyncio.to_thread(
                self._provenance_service.timestamp_committed_artifact,
                self._repository_path,
                event.commit_oid,
                event.ledger_path,
                event.request_id,
                self._tsa_ca_cert_path,
            )
            verification_status = (
                "verified" if timestamp_outcome.verification.ok else "failed"
            )
            await self._event_bus.emit(
                StoryTimestamped(
                    request_id=event.request_id,
                    artifact_id=UUID(anchor_outcome.artifact_id),
                    artifact_hash=anchor_outcome.artifact_hash,
                    tsa_url=timestamp_outcome.tsa_url,
                    digest_algorithm=timestamp_outcome.digest_algorithm,
                    verification_status=verification_status,
                    verification_message=timestamp_outcome.verification.message,
                )
            )
            if timestamp_outcome.story_ots_pending is not None:
                await self._event_bus.emit(timestamp_outcome.story_ots_pending)
        except RuntimeError as exc:
            await self._event_bus.emit(
                StoryTimestamped(
                    request_id=event.request_id,
                    artifact_id=UUID(anchor_outcome.artifact_id),
                    artifact_hash=anchor_outcome.artifact_hash,
                    tsa_url=read_env_optional("RFC3161_TSA_URL") or "unconfigured",
                    digest_algorithm="sha256",
                    verification_status="failed",
                    verification_message=str(exc),
                )
            )
