"""Tests for Eternity v1 data models."""

from __future__ import annotations

import unittest

from src.models import (
    AuthorAttestation,
    GenerationContext,
    Hyperparameters,
    Provenance,
)


class AuthorAttestationTest(unittest.TestCase):
    """Validate AuthorAttestation serialization and aliases."""

    def test_serializes_with_camelcase_aliases(self) -> None:
        att = AuthorAttestation(
            classification="fiction",
            is_human=True,
            is_original_creation=True,
            is_independent_and_accurate=True,
            understands_cryptographic_permanence=True,
        )
        dumped = att.model_dump(by_alias=True)
        self.assertIn("classification", dumped)
        self.assertIn("isHuman", dumped)
        self.assertIn("isOriginalCreation", dumped)
        self.assertIn("isIndependentAndAccurate", dumped)
        self.assertIn("understandsCryptographicPermanence", dumped)
        self.assertNotIn("is_human", dumped)
        self.assertEqual(dumped["classification"], "fiction")
        self.assertIs(dumped["isHuman"], True)

    def test_accepts_all_artistic_classifications(self) -> None:
        for classification in ("fact", "opinion", "fiction", "satire"):
            att = AuthorAttestation(
                classification=classification,
                is_human=True,
                is_original_creation=True,
                is_independent_and_accurate=True,
                understands_cryptographic_permanence=True,
            )
            self.assertEqual(att.classification, classification)


class ProvenanceAuthorAttestationTest(unittest.TestCase):
    """Validate Provenance accepts author_attestation."""

    def test_provenance_accepts_author_attestation(self) -> None:
        att = AuthorAttestation(
            classification="opinion",
            is_human=True,
            is_original_creation=True,
            is_independent_and_accurate=True,
            understands_cryptographic_permanence=True,
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
