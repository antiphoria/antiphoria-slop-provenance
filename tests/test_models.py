"""Tests for Eternity v1 data models."""

from __future__ import annotations

import unittest

from src.models import (
    AttestationQa,
    AuthorAttestation,
    GenerationContext,
    Hyperparameters,
    Provenance,
)


def _sample_attestations() -> list[AttestationQa]:
    """Four canonical Q&A pairs for tests."""
    return [
        AttestationQa(question="Are you human?", answer="y"),
        AttestationQa(question="Is this original?", answer="y"),
        AttestationQa(question="Is it accurate?", answer="y"),
        AttestationQa(question="Do you understand permanence?", answer="y"),
    ]


class AuthorAttestationTest(unittest.TestCase):
    """Validate AuthorAttestation serialization and aliases."""

    def test_serializes_with_attestations(self) -> None:
        att = AuthorAttestation(
            classification="fiction",
            attestations=_sample_attestations(),
        )
        dumped = att.model_dump(by_alias=True)
        self.assertIn("classification", dumped)
        self.assertIn("attestations", dumped)
        self.assertEqual(dumped["classification"], "fiction")
        self.assertEqual(len(dumped["attestations"]), 4)
        self.assertEqual(dumped["attestations"][0]["question"], "Are you human?")
        self.assertEqual(dumped["attestations"][0]["answer"], "y")

    def test_accepts_all_artistic_classifications(self) -> None:
        for classification in ("fact", "opinion", "fiction", "satire"):
            att = AuthorAttestation(
                classification=classification,
                attestations=_sample_attestations(),
            )
            self.assertEqual(att.classification, classification)


class ProvenanceAuthorAttestationTest(unittest.TestCase):
    """Validate Provenance accepts author_attestation."""

    def test_provenance_accepts_author_attestation(self) -> None:
        att = AuthorAttestation(
            classification="opinion",
            attestations=_sample_attestations(),
        )
        prov = Provenance(
            source="human",
            engineVersion="slop-orchestrator-v1.0.0",
            modelId="human",
            generationContext=GenerationContext(
                systemInstruction="Human-authored.",
                prompt="N/A",
                hyperparameters=Hyperparameters(
                    temperature=0.0,
                    topP=1.0,
                    topK=0,
                ),
            ),
            authorAttestation=att,
        )
        self.assertIsNotNone(prov.author_attestation)
        self.assertEqual(prov.author_attestation.classification, "opinion")

    def test_provenance_author_attestation_defaults_to_none(self) -> None:
        prov = Provenance(
            source="synthetic",
            engineVersion="slop-orchestrator-v1.0.0",
            modelId="gemini-2.5-flash",
            generationContext=GenerationContext(
                systemInstruction="system",
                prompt="prompt",
                hyperparameters=Hyperparameters(
                    temperature=0.1,
                    topP=1.0,
                    topK=0,
                ),
            ),
        )
        self.assertIsNone(prov.author_attestation)


if __name__ == "__main__":
    unittest.main()
