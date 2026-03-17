"""Tests for in-memory event bus task draining behavior."""

from __future__ import annotations

import asyncio
import unittest

from src.events import InMemoryEventBus, StoryRequested


class InMemoryEventBusTest(unittest.IsolatedAsyncioTestCase):
    """Validate event-bus task completion guarantees."""

    async def test_drain_waits_for_handler_completion(self) -> None:
        event_bus = InMemoryEventBus()
        started = asyncio.Event()
        done = asyncio.Event()

        async def _handler(event: StoryRequested) -> None:
            _ = event
            started.set()
            await asyncio.sleep(0.001)
            done.set()

        await event_bus.subscribe(StoryRequested, _handler)
        await event_bus.emit(StoryRequested(prompt="test"))
        await asyncio.wait_for(started.wait(), timeout=1.0)
        await event_bus.drain()
        self.assertTrue(done.is_set())

    async def test_emit_rejects_when_queue_full(self) -> None:
        """Emit raises RuntimeError when max_pending_tasks exceeded."""
        event_bus = InMemoryEventBus(max_pending_tasks=2)
        blocker = asyncio.Event()

        async def _slow_handler(event: StoryRequested) -> None:
            _ = event
            await blocker.wait()

        await event_bus.subscribe(StoryRequested, _slow_handler)
        await event_bus.emit(StoryRequested(prompt="1"))
        await event_bus.emit(StoryRequested(prompt="2"))
        with self.assertRaises(RuntimeError):
            await event_bus.emit(StoryRequested(prompt="3"))
        blocker.set()
        await event_bus.drain()


if __name__ == "__main__":
    unittest.main()
