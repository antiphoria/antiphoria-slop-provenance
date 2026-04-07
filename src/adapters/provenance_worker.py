"""Event worker that anchors and timestamps committed artifacts."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from uuid import UUID

from src.domain.events import (
    EventBusPort,
    StoryAnchored,
    StoryCommitted,
    StoryTimestamped,
)
from src.env_config import read_env_optional
from src.logging_config import bind_log_context, should_log_route
from src.services.provenance_service import ProvenanceService

_adapter_logger = logging.getLogger("src.adapters.provenance_worker")
_ANCHOR_TIMEOUT_SEC = 120.0
_TIMESTAMP_TIMEOUT_SEC = 120.0


class ProvenanceWorkerAdapter:
    """Subscribe to commit events and execute provenance hardening steps."""

    def __init__(
        self,
        event_bus: EventBusPort,
        provenance_service: ProvenanceService,
        repository_path: Path,
        tsa_ca_cert_path: Path | None,
        env_path: Path | None = None,
    ) -> None:
        self._event_bus = event_bus
        self._provenance_service = provenance_service
        self._repository_path = repository_path
        self._tsa_ca_cert_path = tsa_ca_cert_path
        self._env_path = env_path
        self._tsa_url_fallback = (
            read_env_optional("RFC3161_TSA_URL", env_path=self._env_path) or "unconfigured"
        )

    async def start(self) -> None:
        """Subscribe to commit events."""

        await self._event_bus.subscribe(StoryCommitted, self._on_story_committed)

    async def _on_story_committed(self, event: StoryCommitted) -> None:
        """Anchor and timestamp one committed artifact."""
        bind_log_context(request_id=event.request_id)

        try:
            anchor_outcome = await asyncio.wait_for(
                asyncio.to_thread(
                    self._provenance_service.anchor_committed_artifact,
                    self._repository_path,
                    event.commit_oid,
                    event.ledger_path,
                    event.request_id,
                ),
                timeout=_ANCHOR_TIMEOUT_SEC,
            )
        except Exception as exc:  # noqa: BLE001
            message = "Anchoring timed out." if isinstance(exc, asyncio.TimeoutError) else str(exc)
            _adapter_logger.exception(
                "Anchoring failed request_id=%s commit_oid=%s",
                event.request_id,
                event.commit_oid,
                extra={"request_id": str(event.request_id)},
            )
            _adapter_logger.warning(
                "Skipping timestamping because anchoring failed request_id=%s error=%s",
                event.request_id,
                message,
                extra={"request_id": str(event.request_id)},
            )
            return

        try:
            artifact_id = UUID(anchor_outcome.artifact_id)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "Anchoring returned an invalid artifact_id; expected UUID "
                f"for request_id={event.request_id}: {anchor_outcome.artifact_id!r}"
            ) from exc
        if should_log_route("coarse"):
            _adapter_logger.info(
                "ProvenanceWorkerAdapter emitting StoryAnchored request_id=%s",
                event.request_id,
                extra={"request_id": str(event.request_id)},
            )
        await self._event_bus.emit(
            StoryAnchored(
                request_id=event.request_id,
                artifact_id=artifact_id,
                artifact_hash=anchor_outcome.artifact_hash,
                transparency_entry_id=anchor_outcome.entry_id,
                transparency_entry_hash=anchor_outcome.entry_hash,
                log_path=anchor_outcome.log_path,
            )
        )

        timestamp_outcome = None
        try:
            timestamp_outcome = await asyncio.wait_for(
                asyncio.to_thread(
                    self._provenance_service.timestamp_committed_artifact,
                    self._repository_path,
                    event.commit_oid,
                    event.ledger_path,
                    event.request_id,
                    self._tsa_ca_cert_path,
                ),
                timeout=_TIMESTAMP_TIMEOUT_SEC,
            )
            verification_status = "verified" if timestamp_outcome.verification.ok else "failed"
            if should_log_route("coarse"):
                _adapter_logger.info(
                    "ProvenanceWorkerAdapter emitting StoryTimestamped request_id=%s",
                    event.request_id,
                    extra={"request_id": str(event.request_id)},
                )
            await self._event_bus.emit(
                StoryTimestamped(
                    request_id=event.request_id,
                    artifact_id=artifact_id,
                    artifact_hash=anchor_outcome.artifact_hash,
                    tsa_url=timestamp_outcome.tsa_url,
                    digest_algorithm=timestamp_outcome.digest_algorithm,
                    verification_status=verification_status,
                    verification_message=timestamp_outcome.verification.message,
                )
            )
        except Exception as exc:  # noqa: BLE001
            message = (
                "Timestamping timed out." if isinstance(exc, asyncio.TimeoutError) else str(exc)
            )
            await self._event_bus.emit(
                StoryTimestamped(
                    request_id=event.request_id,
                    artifact_id=artifact_id,
                    artifact_hash=anchor_outcome.artifact_hash,
                    tsa_url=self._tsa_url_fallback,
                    digest_algorithm="sha256",
                    verification_status="failed",
                    verification_message=message,
                )
            )
            _adapter_logger.warning(
                "Timestamping failed request_id=%s error=%s",
                event.request_id,
                message,
                extra={"request_id": str(event.request_id)},
            )
            return

        if timestamp_outcome is None or timestamp_outcome.story_ots_pending is None:
            return
        try:
            if should_log_route("coarse"):
                _adapter_logger.info(
                    "ProvenanceWorkerAdapter emitting StoryOtsPending request_id=%s",
                    event.request_id,
                    extra={"request_id": str(event.request_id)},
                )
            await self._event_bus.emit(timestamp_outcome.story_ots_pending)
        except Exception:  # noqa: BLE001
            _adapter_logger.exception(
                "StoryOtsPending emit failed request_id=%s",
                event.request_id,
                extra={"request_id": str(event.request_id)},
            )
