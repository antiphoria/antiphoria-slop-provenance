"""Compatibility exports for event contracts and event bus runtime.

New code should import from:
- ``src.event_contracts`` for event payload models and protocols.
- ``src.event_bus`` for in-memory bus implementation.
"""

from src.event_bus import EventBus, InMemoryEventBus
from src.event_contracts import (
    ErrorHandler,
    EventBusPort,
    EventHandler,
    EventHandlerError,
    EventT,
    StoryAnchored,
    StoryAudited,
    StoryCommitted,
    StoryCurated,
    StoryForged,
    StoryGenerated,
    StoryHumanRegistered,
    StoryOtsPending,
    StoryRequested,
    StorySigned,
    StoryTimestamped,
)

__all__ = [
    "ErrorHandler",
    "EventBus",
    "EventBusPort",
    "EventHandler",
    "EventHandlerError",
    "EventT",
    "InMemoryEventBus",
    "StoryAnchored",
    "StoryAudited",
    "StoryCommitted",
    "StoryCurated",
    "StoryForged",
    "StoryGenerated",
    "StoryHumanRegistered",
    "StoryOtsPending",
    "StoryRequested",
    "StorySigned",
    "StoryTimestamped",
]
