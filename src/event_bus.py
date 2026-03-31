"""Async in-memory event bus runtime implementation."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Awaitable, Callable, cast

from pydantic import BaseModel

from src.event_contracts import ErrorHandler, EventHandlerError, EventT
from src.logging_config import (
    bind_log_context,
    redact_event_for_trace,
    should_log_route,
)

_RawEventHandler = Callable[[BaseModel], Awaitable[None]]
_route_logger = logging.getLogger("src.events")


class InMemoryEventBus:
    """Typed asynchronous pub/sub event bus."""

    def __init__(self, max_pending_tasks: int = 10_000) -> None:
        self._subscribers: dict[type[BaseModel], list[_RawEventHandler]] = {}
        self._error_subscribers: list[ErrorHandler] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self._lock = asyncio.Lock()
        self._max_pending_tasks = max_pending_tasks

    async def subscribe(
        self,
        event_type: type[EventT],
        handler: Callable[[EventT], Awaitable[None]],
    ) -> None:
        """Register an async handler for an event type."""

        async with self._lock:
            raw_handler = cast(_RawEventHandler, handler)
            self._subscribers.setdefault(event_type, []).append(raw_handler)

    async def unsubscribe(
        self,
        event_type: type[EventT],
        handler: Callable[[EventT], Awaitable[None]],
    ) -> None:
        """Remove an existing handler for an event type."""

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
        """Register an async handler for event-dispatch errors."""

        async with self._lock:
            self._error_subscribers.append(handler)

    async def unsubscribe_errors(self, handler: ErrorHandler) -> None:
        """Remove a previously registered event-dispatch error handler."""

        async with self._lock:
            if handler in self._error_subscribers:
                self._error_subscribers.remove(handler)

    async def emit(self, event: EventT) -> None:
        """Dispatch an event to subscribers without awaiting completion."""

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

        if len(self._tasks) >= self._max_pending_tasks:
            raise RuntimeError(
                "Event bus queue full "
                f"({self._max_pending_tasks} pending tasks). "
                "Publication blocked to prevent OOM."
            )

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
        """Emit structured handler failure to error subscribers."""

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
