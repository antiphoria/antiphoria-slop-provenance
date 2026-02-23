"""Asynchronous event bus and strict event payload contracts.

This module provides a lightweight asyncio pub/sub implementation and typed
Pydantic events used to coordinate the core domain and adapters.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Awaitable, Callable, TypeVar, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from src.models import Artifact, Curation

EventT = TypeVar("EventT", bound=BaseModel)
EventHandler = Callable[[EventT], Awaitable[None]]
_RawEventHandler = Callable[[BaseModel], Awaitable[None]]
ErrorHandler = Callable[["EventHandlerError"], Awaitable[None]]


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
        generated_at: UTC timestamp for event creation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    prompt: str = Field(min_length=1)
    title: str = Field(min_length=1)
    body: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
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
    artifact: Artifact
    body: str = Field(min_length=1)
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
    ledger_path: str = Field(min_length=1)
    commit_oid: str = Field(min_length=1)
    committed_at: datetime = Field(default_factory=_utc_now)


class StoryCurated(BaseModel):
    """Event emitted when a human-curated artifact is submitted.

    Attributes:
        request_id: Correlation ID from the original generation request.
        curated_body: Human-edited markdown body without metadata wrappers.
        prompt: Original user prompt that birthed the artifact.
        curation_metadata: Computed curation metadata containing score/diff.
        model_id: Source model identifier for provenance continuity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    curated_body: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    curation_metadata: Curation
    model_id: str = Field(min_length=1)


class EventHandlerError(BaseModel):
    """Structured error payload emitted when an event handler fails.

    Attributes:
        event_type: Name of the event model being processed.
        handler_name: Qualified handler callable name when available.
        error_type: Exception class name raised by the handler.
        error_message: Exception message string.
        occurred_at: UTC timestamp for error capture.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str = Field(min_length=1)
    handler_name: str = Field(min_length=1)
    error_type: str = Field(min_length=1)
    error_message: str = Field(min_length=1)
    occurred_at: datetime = Field(default_factory=_utc_now)


class EventBus:
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

        try:
            await handler(event)
        except Exception as exc:
            await self._publish_handler_error(handler, event, exc)

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

        payload = EventHandlerError(
            event_type=type(event).__name__,
            handler_name=getattr(handler, "__qualname__", repr(handler)),
            error_type=type(error).__name__,
            error_message=str(error) or "<no message>",
        )
        for error_handler in error_handlers:
            try:
                await error_handler(payload)
            except Exception:
                continue
