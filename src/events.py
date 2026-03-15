"""Asynchronous event bus and strict event payload contracts.

This module provides a lightweight asyncio pub/sub implementation and typed
Pydantic events used to coordinate the core domain and adapters.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Awaitable, Callable, Protocol, TypeVar, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from src.logging_config import (
    bind_log_context,
    redact_event_for_trace,
    should_log_route,
)
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
_RawEventHandler = Callable[[BaseModel], Awaitable[None]]
ErrorHandler = Callable[["EventHandlerError"], Awaitable[None]]

_route_logger = logging.getLogger("src.events")


def _utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class StoryRequested(BaseModel):
    """Event emitted when a new generation request is created.

    Attributes:
        request_id: Stable correlation ID for this generation flow.
        prompt: Prompt text provided by the CLI/user.
        requested_at: UTC timestamp for event creation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID = Field(default_factory=uuid4)
    event_version: str = Field(default="v1")
    prompt: str = Field(min_length=1)
    requested_at: datetime = Field(default_factory=_utc_now)


class StoryGenerated(BaseModel):
    """Event emitted when the generation adapter returns text.

    Attributes:
        request_id: Correlation ID from the original request.
        prompt: Original user prompt that initiated generation.
        title: Artifact title inferred/provided by the generator.
        body: Raw generated story text.
        model_id: Source model identifier used by the adapter.
        system_instruction: Active system instruction for generation.
        temperature: Temperature used for generation.
        top_p: Top-p value used for generation.
        top_k: Top-k value used for generation.
        content_type: MIME type for generated payload.
        license: License applied to the generated payload.
        usage_metrics: Model token usage metrics if available.
        embedded_watermark: Declared embedded watermark status if available.
        generated_at: UTC timestamp for event creation.
    """

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
    """Event emitted after post-quantum signing completes.

    Attributes:
        request_id: Correlation ID from the original request.
        artifact: Fully formed frontmatter artifact metadata.
        body: Raw generated body to be published beneath frontmatter.
        signed_at: UTC timestamp for event creation.
    """

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
    """Event emitted when a signed artifact is committed to the ledger.

    Attributes:
        request_id: Correlation ID from the original request.
        ledger_path: Repository-relative markdown path for the artifact.
        commit_oid: Created git commit object id.
        committed_at: UTC timestamp for event creation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    ledger_path: str = Field(min_length=1)
    commit_oid: str = Field(min_length=1)
    committed_at: datetime = Field(default_factory=_utc_now)


class StoryAnchored(BaseModel):
    """Event emitted when an artifact hash is anchored.

    Attributes:
        request_id: Correlation ID from the generation/curation flow if known.
        artifact_id: Artifact UUID from frontmatter envelope.
        artifact_hash: SHA-256 payload digest that was anchored.
        transparency_entry_id: Append-only transparency entry identifier.
        transparency_entry_hash: Hash of the transparency entry payload.
        log_path: Local transparency log file path.
        anchored_at: UTC timestamp for event creation.
    """

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
    """Event emitted when OTS stamp is requested (pending Bitcoin anchor).

    Attributes:
        request_id: Correlation ID from the generation/curation flow.
        artifact_hash: SHA-256 payload digest.
        pending_ots_b64: Base64-encoded pending OTS proof.
        ots_pending_at: UTC timestamp for event creation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    artifact_hash: str = Field(min_length=64, max_length=64)
    pending_ots_b64: str = Field(min_length=1)
    ots_pending_at: datetime = Field(default_factory=_utc_now)


class StoryForged(BaseModel):
    """Event emitted when OTS proof is Bitcoin-anchored.

    Attributes:
        request_id: Correlation ID from the generation/curation flow.
        artifact_hash: SHA-256 payload digest.
        bitcoin_block_height: Bitcoin block number where proof was anchored.
        final_ots_b64: Base64-encoded forged OTS proof.
        forged_at: UTC timestamp for event creation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    artifact_hash: str = Field(min_length=64, max_length=64)
    bitcoin_block_height: int = Field(ge=0)
    final_ots_b64: str = Field(min_length=1)
    forged_at: datetime = Field(default_factory=_utc_now)


class StoryTimestamped(BaseModel):
    """Event emitted when RFC3161 timestamping is completed.

    Attributes:
        request_id: Correlation ID from the generation/curation flow if known.
        artifact_id: Artifact UUID from frontmatter envelope.
        artifact_hash: SHA-256 payload digest used for RFC3161 query.
        tsa_url: RFC3161 TSA endpoint URL.
        digest_algorithm: Digest algorithm used for timestamp query.
        verification_status: Timestamp status
            (`verified`, `failed`, or `skipped`).
        verification_message: Human-readable verification details.
        timestamped_at: UTC timestamp for event creation.
    """

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
    """Event emitted after generating a machine-readable audit report.

    Attributes:
        request_id: Correlation ID from the generation/curation flow if known.
        artifact_id: Artifact UUID from frontmatter envelope when resolved.
        audit_passed: True when full-chain checks pass, otherwise False.
        report_path: Filesystem path for emitted audit report when persisted.
        audited_at: UTC timestamp for event creation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID | None = None
    event_version: str = Field(default="v1")
    artifact_id: UUID | None = None
    audit_passed: bool
    report_path: str | None = None
    audited_at: datetime = Field(default_factory=_utc_now)


class StoryCurated(BaseModel):
    """Event emitted when a human-curated artifact is submitted.

    Attributes:
        request_id: Correlation ID from the original generation request.
        curated_body: Human-edited markdown body without metadata wrappers.
        prompt: Original user prompt that birthed the artifact.
        curation_metadata: Computed curation metadata containing score/diff.
        model_id: Source model identifier for provenance continuity.
        title: Optional original artifact title; when provided (e.g. human-registered),
            used instead of deriving from body.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    event_version: str = Field(default="v1")
    curated_body: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    curation_metadata: Curation
    model_id: str = Field(min_length=1)
    title: str | None = None


class StoryHumanRegistered(BaseModel):
    """Event emitted when human-only content is submitted for certification.

    Attributes:
        request_id: Correlation ID for this registration flow.
        body: Raw human-authored markdown body.
        title: Artifact title for the envelope.
        license: Content license to apply (e.g. ARR, CC-BY-4.0).
        attestation: Artistic declarations from the wizard.
        registration_ceremony: Proof-of-environment metadata (optional).
    """

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
    """Structured error payload emitted when an event handler fails.

    Attributes:
        event_type: Name of the event model being processed.
        handler_name: Qualified handler callable name when available.
        error_type: Exception class name raised by the handler.
        error_message: Exception message string.
        request_id: Correlation ID when available from the event being processed.
        occurred_at: UTC timestamp for error capture.
    """

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


class InMemoryEventBus:
    """Typed asynchronous pub/sub event bus.

    Subscribers register an async handler for a specific event model class.
    Emission is fan-out and concurrent using `asyncio.gather`.
    """

    def __init__(self) -> None:
        """Initialize empty subscriber registry."""

        self._subscribers: dict[type[BaseModel], list[_RawEventHandler]] = {}
        self._error_subscribers: list[ErrorHandler] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self._lock = asyncio.Lock()

    async def subscribe(
        self,
        event_type: type[EventT],
        handler: EventHandler[EventT],
    ) -> None:
        """Register an async handler for an event type.

        Args:
            event_type: Concrete Pydantic event model class to subscribe to.
            handler: Async callable that receives the typed event payload.
        """

        async with self._lock:
            raw_handler = cast(_RawEventHandler, handler)
            self._subscribers.setdefault(event_type, []).append(raw_handler)

    async def unsubscribe(
        self,
        event_type: type[EventT],
        handler: EventHandler[EventT],
    ) -> None:
        """Remove an existing handler for an event type.

        Args:
            event_type: Concrete event model class previously subscribed.
            handler: Handler instance to remove.
        """

        async with self._lock:
            handlers = self._subscribers.get(event_type)
            if handlers is None:
                return

            raw_handler = cast(_RawEventHandler, handler)
            if raw_handler in handlers:
                handlers.remove(raw_handler)

            if not handlers:
                del self._subscribers[event_type]

    async def subscribe_errors(self, handler: ErrorHandler) -> None:
        """Register an async handler for event-dispatch errors.

        Args:
            handler: Async callable for `EventHandlerError` payloads.
        """

        async with self._lock:
            self._error_subscribers.append(handler)

    async def unsubscribe_errors(self, handler: ErrorHandler) -> None:
        """Remove a previously registered event-dispatch error handler."""

        async with self._lock:
            if handler in self._error_subscribers:
                self._error_subscribers.remove(handler)

    async def emit(self, event: EventT) -> None:
        """Dispatch an event to subscribers without awaiting their completion.

        Args:
            event: Concrete Pydantic event payload instance.
        """
        event_type = type(event).__name__
        req_id = str(getattr(event, "request_id", "")) or None

        if should_log_route("coarse"):
            _route_logger.info(
                "emit %s request_id=%s",
                event_type,
                req_id or "-",
                extra={"request_id": req_id or "-"},
            )
        if should_log_route("trace"):
            redacted = redact_event_for_trace(event)
            _route_logger.debug(
                "emit payload %s",
                json.dumps(redacted, default=str),
                extra={"request_id": req_id or "-"},
            )

        async with self._lock:
            handlers = tuple(self._subscribers.get(type(event), []))

        if not handlers:
            return

        for handler in handlers:
            task = asyncio.create_task(self._run_handler(handler, event))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _run_handler(
        self,
        handler: _RawEventHandler,
        event: BaseModel,
    ) -> None:
        """Execute one handler and publish failures to the error channel."""
        event_type = type(event).__name__
        handler_name = getattr(handler, "__qualname__", repr(handler))
        req_id = getattr(event, "request_id", None)
        req_id_str = str(req_id) if req_id is not None else "-"

        if should_log_route("fine"):
            _route_logger.info(
                "handler %s received %s request_id=%s",
                handler_name,
                event_type,
                req_id_str,
                extra={"request_id": req_id_str},
            )
        if req_id is not None:
            bind_log_context(request_id=req_id)

        try:
            await handler(event)
        except Exception as exc:
            await self._publish_handler_error(handler, event, exc)
        finally:
            if should_log_route("fine"):
                _route_logger.info(
                    "handler %s completed %s request_id=%s",
                    handler_name,
                    event_type,
                    req_id_str,
                    extra={"request_id": req_id_str},
                )

    async def _publish_handler_error(
        self,
        handler: _RawEventHandler,
        event: BaseModel,
        error: Exception,
    ) -> None:
        """Emit a structured handler failure to error subscribers."""

        async with self._lock:
            error_handlers = tuple(self._error_subscribers)

        if not error_handlers:
            loop = asyncio.get_running_loop()
            loop.call_exception_handler(
                {
                    "message": "Unhandled event handler failure",
                    "exception": error,
                    "event_type": type(event).__name__,
                }
            )
            return

        req_id = getattr(event, "request_id", None)
        if req_id is not None:
            bind_log_context(request_id=req_id)

        payload = EventHandlerError(
            event_type=type(event).__name__,
            handler_name=getattr(handler, "__qualname__", repr(handler)),
            error_type=type(error).__name__,
            error_message=str(error) or "<no message>",
            request_id=str(req_id) if req_id is not None else None,
        )
        for error_handler in error_handlers:
            try:
                await error_handler(payload)
            except Exception:
                continue

    async def drain(self) -> None:
        """Wait until all currently scheduled handler tasks complete."""

        tasks = tuple(self._tasks)
        if not tasks:
            return
        await asyncio.gather(*tasks, return_exceptions=True)


EventBus = InMemoryEventBus
