"""Tests for in-memory event bus task draining behavior."""

from __future__ import annotations

import asyncio
import unittest

from src.events import InMemoryEventBus, StoryRequested


class InMemoryEventBusTest(unittest.IsolatedAsyncioTestCase):
    """Validate event-bus task completion guarantees."""

    async def test_drain_waits_for_handler_completion(self) -> None:
        event_bus = InMemoryEventBus()
        state = {"done": False}

        async def _handler(event: StoryRequested) -> None:
            _ = event
            await asyncio.sleep(0.01)
            state["done"] = True

        await event_bus.subscribe(StoryRequested, _handler)
        await event_bus.emit(StoryRequested(prompt="test"))
        await event_bus.drain()
        self.assertTrue(state["done"])


if __name__ == "__main__":
    unittest.main()
