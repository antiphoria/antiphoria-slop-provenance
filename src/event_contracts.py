"""Strict event payload contracts for provenance orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable, Protocol, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from src.models import (
    Artifact,
    AuthorAttestation,
    Curation,
    EmbeddedWatermark,
    RegistrationCeremony,
    UsageMetrics,
    WebAuthnAttestation,
)

EventT = TypeVar("EventT", bound=BaseModel)
EventHandler = Callable[[EventT], Awaitable[None]]
ErrorHandler = Callable[["EventHandlerError"], Awaitable[None]]


def _utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class StoryRequested(BaseModel):
    """Event emitted when a new generation request is created."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID = Field(default_factory=uuid4)
    event_version: str = Field(default="v1")
    prompt: str = Field(min_length=1)
    requested_at: datetime = Field(default_factory=_utc_now)


class StoryGenerated(BaseModel):
    """Event emitted when the generation adapter returns text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    prompt: str = Field(min_length=1)
    title: str = Field(min_length=1)
    body: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
    system_instruction: str = Field(min_length=1)
    temperature: float = Field(ge=0.0, le=2.0)
    top_p: float = Field(ge=0.0, le=1.0)
    top_k: int = Field(ge=0)
    content_type: str = Field(min_length=1)
    license: str = Field(min_length=1)
    usage_metrics: UsageMetrics | None = None
    embedded_watermark: EmbeddedWatermark | None = None
    generated_at: datetime = Field(default_factory=_utc_now)


class StorySigned(BaseModel):
    """Event emitted after post-quantum signing completes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    artifact: Artifact
    body: str = Field(min_length=1)
    c2pa_manifest_hash: str | None = None
    c2pa_manifest_bytes_b64: str | None = None
    c2pa_manifest_bytes_ref: str | None = None
    signed_at: datetime = Field(default_factory=_utc_now)


class StoryCommitted(BaseModel):
    """Event emitted when a signed artifact is committed to the ledger."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    ledger_path: str = Field(min_length=1)
    commit_oid: str = Field(min_length=1)
    committed_at: datetime = Field(default_factory=_utc_now)


class StoryAnchored(BaseModel):
    """Event emitted when an artifact hash is anchored."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID | None = None
    event_version: str = Field(default="v1")
    artifact_id: UUID
    artifact_hash: str = Field(min_length=64, max_length=64)
    transparency_entry_id: str = Field(min_length=1)
    transparency_entry_hash: str = Field(min_length=64, max_length=64)
    log_path: str = Field(min_length=1)
    anchored_at: datetime = Field(default_factory=_utc_now)


class StoryOtsPending(BaseModel):
    """Event emitted when OTS stamp is requested."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    artifact_hash: str = Field(min_length=64, max_length=64)
    pending_ots_b64: str = Field(min_length=1)
    ots_pending_at: datetime = Field(default_factory=_utc_now)


class StoryForged(BaseModel):
    """Event emitted when OTS proof is Bitcoin-anchored."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    artifact_hash: str = Field(min_length=64, max_length=64)
    bitcoin_block_height: int = Field(ge=0)
    final_ots_b64: str = Field(min_length=1)
    forged_at: datetime = Field(default_factory=_utc_now)


class StoryTimestamped(BaseModel):
    """Event emitted when RFC3161 timestamping is completed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID | None = None
    event_version: str = Field(default="v1")
    artifact_id: UUID
    artifact_hash: str = Field(min_length=64, max_length=64)
    tsa_url: str = Field(min_length=1)
    digest_algorithm: str = Field(min_length=1)
    verification_status: str = Field(min_length=1)
    verification_message: str = Field(min_length=1)
    timestamped_at: datetime = Field(default_factory=_utc_now)


class StoryAudited(BaseModel):
    """Event emitted after generating a machine-readable audit report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID | None = None
    event_version: str = Field(default="v1")
    artifact_id: UUID | None = None
    audit_passed: bool
    report_path: str | None = None
    audited_at: datetime = Field(default_factory=_utc_now)


class StoryCurated(BaseModel):
    """Event emitted when a human-curated artifact is submitted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    curated_body: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    curation_metadata: Curation
    model_id: str = Field(min_length=1)
    title: str | None = None


class StoryHumanRegistered(BaseModel):
    """Event emitted when human-only content is submitted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID = Field(default_factory=uuid4)
    event_version: str = Field(default="v1")
    body: str = Field(min_length=1)
    title: str = Field(min_length=1)
    license: str = Field(min_length=1, default="ARR")
    attestation: AuthorAttestation
    webauthn_attestation: WebAuthnAttestation | None = None
    registration_ceremony: RegistrationCeremony | None = None


class EventHandlerError(BaseModel):
    """Structured payload emitted when an event handler fails."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str = Field(min_length=1)
    event_version: str = Field(default="v1")
    handler_name: str = Field(min_length=1)
    error_type: str = Field(min_length=1)
    error_message: str = Field(min_length=1)
    request_id: str | None = None
    occurred_at: datetime = Field(default_factory=_utc_now)


class EventBusPort(Protocol):
    """Abstract event bus port used by adapters and services."""

    async def subscribe(
        self,
        event_type: type[EventT],
        handler: EventHandler[EventT],
    ) -> None:
        """Register an async handler for an event type."""

    async def unsubscribe(
        self,
        event_type: type[EventT],
        handler: EventHandler[EventT],
    ) -> None:
        """Remove a previously registered event handler."""

    async def subscribe_errors(self, handler: ErrorHandler) -> None:
        """Register an async handler for event-dispatch errors."""

    async def unsubscribe_errors(self, handler: ErrorHandler) -> None:
        """Remove a previously registered event-dispatch error handler."""

    async def emit(self, event: EventT) -> None:
        """Dispatch one typed event instance to subscribers."""
