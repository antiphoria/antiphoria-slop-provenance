"""Tests for Eternity v1 data models."""

from __future__ import annotations

import unittest

import pytest
from pydantic import ValidationError

from src.models import (
    AttestationQa,
    AuthorAttestation,
    GenerationContext,
    Hyperparameters,
    Provenance,
    canonical_json_bytes,
)


def _sample_attestations() -> list[AttestationQa]:
    """Four canonical Q&A pairs for tests."""
    return [
        AttestationQa(question="Are you human?", answer="y"),
        AttestationQa(question="Is this original?", answer="y"),
        AttestationQa(question="Is it accurate?", answer="y"),
        AttestationQa(question="Do you understand permanence?", answer="y"),
    ]


def _attestations_dict() -> list[dict[str, str]]:
    """Four Q&A dicts for AuthorAttestation payloads."""
    return [
        {"question": "Q1", "answer": "a"},
        {"question": "Q2", "answer": "a"},
        {"question": "Q3", "answer": "a"},
        {"question": "Q4", "answer": "a"},
    ]


def _valid_provenance_base() -> dict[str, object]:
    """Minimal valid Provenance dict (alias keys)."""
    return {
        "source": "synthetic",
        "engineVersion": "v1",
        "modelId": "id",
        "generationContext": {
            "systemInstruction": "si",
            "prompt": "p",
            "hyperparameters": {
                "temperature": 0.0,
                "topP": 1.0,
                "topK": 0,
            },
        },
    }


@pytest.mark.parametrize(
    "payload,match",
    [
        (
            {
                "classification": "fiction",
                "attestations": _attestations_dict(),
                "extra_field": "x",
            },
            "Extra inputs are not permitted",
        ),
        (
            {
                "classification": "invalid",
                "attestations": _attestations_dict(),
            },
            "fact|opinion|fiction|satire",
        ),
    ],
)
def test_author_attestation_validation_error(payload: dict, match: str) -> None:
    """AuthorAttestation raises ValidationError for invalid payloads."""
    with pytest.raises(ValidationError, match=match):
        AuthorAttestation.model_validate(payload)


def test_author_attestation_rejects_excessive_attestations() -> None:
    """AuthorAttestation raises ValidationError for more than 64 attestations."""
    attestations = [{"question": f"Q{i}", "answer": "a"} for i in range(65)]
    with pytest.raises(ValidationError, match="64"):
        AuthorAttestation.model_validate(
            {"classification": "fiction", "attestations": attestations}
        )


@pytest.mark.parametrize(
    "payload,match",
    [
        (
            {
                **_valid_provenance_base(),
                "generationContext": {
                    "systemInstruction": "si",
                    "prompt": "p",
                    "hyperparameters": {
                        "temperature": -1,
                        "topP": 1.0,
                        "topK": 0,
                    },
                },
            },
            r"greater_than_equal|0\.0",
        ),
        (
            {**_valid_provenance_base(), "extra_field": "x"},
            "Extra inputs are not permitted",
        ),
    ],
)
def test_provenance_validation_error(payload: dict, match: str) -> None:
    """Provenance raises ValidationError for invalid payloads."""
    with pytest.raises(ValidationError, match=match):
        Provenance.model_validate(payload)


@pytest.mark.parametrize("classification", ["fact", "opinion", "fiction", "satire"])
def test_author_attestation_valid(classification: str) -> None:
    """AuthorAttestation accepts all artistic classifications."""
    att = AuthorAttestation(
        classification=classification,
        attestations=_sample_attestations(),
    )
    assert att.classification == classification


@pytest.mark.parametrize(
    "payload,expected_bytes",
    [
        ({"temp": 0.0}, b'{"temp":0}'),
        (
            {"nested": {"b": 1, "a": 2}},
            b'{"nested":{"a":2,"b":1}}',
        ),
        ({"emoji": "🚀"}, '{"emoji":"🚀"}'.encode()),
        ({"a": 1, "b": 2}, b'{"a":1,"b":2}'),
    ],
)
def test_canonical_json_bytes(payload: dict, expected_bytes: bytes) -> None:
    """canonical_json_bytes produces RFC 8785 deterministic output for signing."""
    assert canonical_json_bytes(payload) == expected_bytes


def test_canonical_json_bytes_float_normalization() -> None:
    """RFC 8785: 1e2 and 100 produce same canonical bytes."""
    assert canonical_json_bytes({"x": 1e2}) == canonical_json_bytes({"x": 100})


def test_canonical_json_bytes_unicode_escape() -> None:
    """RFC 8785: Unicode escapes normalized consistently."""
    result = canonical_json_bytes({"c": "\u003c"})
    assert b"<" in result or b"\\u003c" in result
    assert canonical_json_bytes({"c": "<"}) == result


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


class ProvenanceAuthorAttestationTest(unittest.TestCase):
    """Validate Provenance accepts author_attestation."""

    def test_provenance_accepts_author_attestation(self) -> None:
        att = AuthorAttestation(
            classification="opinion",
            attestations=_sample_attestations(),
        )
        prov = Provenance(
            source="human",
            engineVersion="antiphoria-slop-provenance-v1.0.0",
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
            engineVersion="antiphoria-slop-provenance-v1.0.0",
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
