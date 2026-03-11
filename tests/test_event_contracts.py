"""Contract tests for event payload schemas."""

from __future__ import annotations

import unittest
from uuid import uuid4

from src.events import StoryRequested, StoryHumanRegistered
from src.models import AuthorAttestation


class EventContractsTest(unittest.TestCase):
    """Validate event-versioned payload contracts."""

    def test_story_requested_defaults_version(self) -> None:
        event = StoryRequested(request_id=uuid4(), prompt="hello")
        self.assertEqual(event.event_version, "v1")

    def test_story_human_registered_includes_license_and_attestation(self) -> None:
        attestation = AuthorAttestation(
            classification="fiction",
            is_human=True,
            is_original_creation=True,
            is_independent_and_accurate=True,
            understands_cryptographic_permanence=True,
        )
        event = StoryHumanRegistered(
            body="Human content.",
            title="Test",
            license="CC-BY-4.0",
            attestation=attestation,
        )
        self.assertEqual(event.license, "CC-BY-4.0")
        self.assertEqual(event.attestation.classification, "fiction")
        self.assertIs(event.attestation.is_human, True)

    def test_story_human_registered_defaults_license_to_arr(self) -> None:
        attestation = AuthorAttestation(
            classification="fact",
            is_human=True,
            is_original_creation=True,
            is_independent_and_accurate=True,
            understands_cryptographic_permanence=True,
        )
        event = StoryHumanRegistered(
            body="Content",
            title="Title",
            attestation=attestation,
        )
        self.assertEqual(event.license, "ARR")
