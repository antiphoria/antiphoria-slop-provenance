"""Shared register/seal metadata for v2 wire-format tests."""

from __future__ import annotations

from src.models import (
    AuthorAttestation,
    Provenance,
    RegistrationCeremony,
)

TEST_OPERATOR_PSEUDONYM = "b" * 64


def sample_registration_ceremony(**overrides: object) -> RegistrationCeremony:
    base = {
        "registrationUtcMs": 1_700_000_000_000,
        "orchestratorGitCommit": "deadbeef",
        "operatorPseudonymHash": TEST_OPERATOR_PSEUDONYM,
    }
    base.update(overrides)
    return RegistrationCeremony.model_validate(base)


def sample_human_attestation(**overrides: object) -> AuthorAttestation:
    base = {
        "attestationNature": "self-declaration",
        "attestationMode": "interactive",
        "classification": "fiction",
        "attestations": [
            {"question": "Are you human?", "answer": "y"},
            {"question": "Is this original?", "answer": "y"},
            {"question": "Is it accurate?", "answer": "y"},
            {"question": "Do you understand permanence?", "answer": "y"},
        ],
    }
    base.update(overrides)
    return AuthorAttestation.model_validate(base)


def sample_synthetic_attestation(**overrides: object) -> AuthorAttestation:
    base = {
        "attestationNature": "orchestration-declaration",
        "attestationMode": "interactive",
        "classification": "fiction",
        "attestations": [
            {"question": "Q1?", "answer": "y"},
            {"question": "Q2?", "answer": "y"},
            {"question": "Q3?", "answer": "y"},
            {"question": "Q4?", "answer": "y"},
        ],
    }
    base.update(overrides)
    return AuthorAttestation.model_validate(base)


def enrich_provenance_for_v2_wire(provenance: Provenance) -> Provenance:
    """Ensure register/seal artifacts include required metadata.

    v3 (Gap 2): registration_ceremony / webauthn_attestation / attestation_strength
    moved from Provenance to OperatorSeal. This helper now only ensures
    author_attestation is present (the one piece that still lives on Provenance).
    """

    updates: dict[str, object] = {}
    if provenance.author_attestation is None:
        if provenance.source == "human":
            updates["author_attestation"] = sample_human_attestation()
        elif provenance.source == "synthetic":
            updates["author_attestation"] = sample_synthetic_attestation()
    if not updates:
        return provenance
    return provenance.model_copy(update=updates)
