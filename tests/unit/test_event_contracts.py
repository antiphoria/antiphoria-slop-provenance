"""Contract tests for event payload schemas."""

from __future__ import annotations

import unittest
from uuid import uuid4

from src.domain.events import StoryHumanRegistered, StoryRequested
from src.models import AttestationQa, AuthorAttestation


def _sample_attestations() -> list[AttestationQa]:
    return [
        AttestationQa(question="Q1?", answer="y"),
        AttestationQa(question="Q2?", answer="y"),
        AttestationQa(question="Q3?", answer="y"),
        AttestationQa(question="Q4?", answer="y"),
    ]


class EventContractsTest(unittest.TestCase):
    """Validate event-versioned payload contracts."""

    def test_story_requested_defaults_version(self) -> None:
        event = StoryRequested(request_id=uuid4(), prompt="hello")
        self.assertEqual(event.event_version, "v1")

    def test_story_human_registered_includes_license_and_attestation(self) -> None:
        attestation = AuthorAttestation(
            classification="fiction",
            attestations=_sample_attestations(),
        )
        event = StoryHumanRegistered(
            body="Human content.",
            title="Test",
            license="CC-BY-4.0",
            attestation=attestation,
        )
        self.assertEqual(event.license, "CC-BY-4.0")
        self.assertEqual(event.attestation.classification, "fiction")
        self.assertEqual(len(event.attestation.attestations), 4)

    def test_story_human_registered_defaults_license_to_arr(self) -> None:
        attestation = AuthorAttestation(
            classification="fact",
            attestations=_sample_attestations(),
        )
        event = StoryHumanRegistered(
            body="Content",
            title="Title",
            attestation=attestation,
        )
        self.assertEqual(event.license, "ARR")
