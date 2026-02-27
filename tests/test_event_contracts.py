"""Contract tests for event payload schemas."""

from __future__ import annotations

import unittest
from uuid import uuid4

from src.events import StoryRequested


class EventContractsTest(unittest.TestCase):
    """Validate event-versioned payload contracts."""

    def test_story_requested_defaults_version(self) -> None:
        event = StoryRequested(request_id=uuid4(), prompt="hello")
        self.assertEqual(event.event_version, "v1")


if __name__ == "__main__":
    unittest.main()
