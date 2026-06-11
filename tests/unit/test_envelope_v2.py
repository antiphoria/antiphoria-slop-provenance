"""Unit tests for eternity.v2 envelope wire codec."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
import yaml

from src.canonicalization import compute_payload_hash
from src.envelope_v2 import (
    PROFILE_REGISTER,
    PROFILE_SEAL,
    EnvelopeSidecars,
    generation_context_for_source,
    parse_artifact_markdown_text_v2,
    render_artifact_markdown_v2,
    render_artifact_markdown_wire,
)
from src.models import (
    Artifact,
    Provenance,
    SignatureBlock,
    VerificationAnchor,
    WebAuthnAttestation,
    build_envelope_signing_target,
    canonical_json_bytes,
    sha256_hex,
)
from src.parsing import parse_artifact_markdown_text
from src.policies.license_text import resolve_license_text
from src.services.verification_service import VerificationService
from tests.support.v2_envelope_fixtures import (
    enrich_provenance_for_v2_wire,
    sample_human_attestation,
    sample_registration_ceremony,
    sample_synthetic_attestation,
)

_REQUEST_ID = UUID("11111111-2222-3333-4444-555555555555")
_LEDGER_ID = str(_REQUEST_ID)


def _signing_hash(artifact: Artifact, body: str) -> str:
    payload_hash = compute_payload_hash(body)
    target = build_envelope_signing_target(
        artifact,
        payload_hash,
        manifest_sha256_hex=None,
        prev_hash=None,
    )
    return sha256_hex(canonical_json_bytes(target))


def _build_register_artifact(**overrides: object) -> Artifact:
    body_hash = compute_payload_hash("Human body for v2.")
    provenance = enrich_provenance_for_v2_wire(
        Provenance(
            source="human",
            engineVersion="antiphoria-slop-provenance-v1.0.0",
            modelId="human",
            generationContext=generation_context_for_source("human"),
            provenanceGrade="declared",
            authorAttestation=sample_human_attestation(),
            registrationCeremony=sample_registration_ceremony(),
        )
    )
    artifact = Artifact(
        id=_REQUEST_ID,
        title="Human Register Fixture",
        timestamp=datetime(2026, 3, 14, 10, 41, 18, tzinfo=UTC),
        contentType="text/markdown",
        license="ARR",
        provenance=provenance,
        signature=SignatureBlock(
            artifactHash=body_hash,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
        ),
    )
    if overrides:
        return artifact.model_copy(update=overrides)
    return artifact


def _build_seal_artifact(**overrides: object) -> Artifact:
    body_hash = compute_payload_hash("Synthetic body for v2.")
    narrative_hash = "c" * 64
    provenance = enrich_provenance_for_v2_wire(
        Provenance(
            source="synthetic",
            engineVersion="antiphoria-slop-provenance-v1.0.0",
            modelId="composite",
            generationContext=generation_context_for_source("synthetic"),
            provenanceGrade="declared",
            modelsUsed=["gemini-3.1-pro"],
            processNarrativeHash=narrative_hash,
            authorAttestation=sample_synthetic_attestation(),
            registrationCeremony=sample_registration_ceremony(),
        )
    )
    artifact = Artifact(
        id=_REQUEST_ID,
        title="Synthetic Seal Fixture",
        timestamp=datetime(2026, 3, 14, 10, 41, 18, tzinfo=UTC),
        contentType="text/markdown",
        license="CC0-1.0",
        provenance=provenance,
        signature=SignatureBlock(
            artifactHash=body_hash,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
        ),
    )
    if overrides:
        return artifact.model_copy(update=overrides)
    return artifact


def test_golden_register_header_shape() -> None:
    body = "Human body for v2."
    markdown = render_artifact_markdown_v2(
        _build_register_artifact(),
        body,
        ledger_request_id=_LEDGER_ID,
    )
    assert markdown.startswith("---\nantiphoria:\n")
    assert 'schemaVersion: "eternity.v2"' in markdown
    assert f'profile: "{PROFILE_REGISTER}"' in markdown
    assert 'source: "human"' in markdown
    assert 'speechAct: "self-declaration"' in markdown
    assert 'policyId: "ARR"' in markdown
    arr = resolve_license_text("ARR")
    assert f'notice: "{arr.notice}"' in markdown
    assert f'statement: "{arr.statement}"' in markdown
    assert 'attestationStrength: "none"' in markdown
    assert "synthesis:" not in markdown
    assert ": null" not in markdown
    assert "generationContext:" not in markdown


def test_golden_seal_header_shape() -> None:
    body = "Synthetic body for v2."
    narrative_hash = "c" * 64
    markdown = render_artifact_markdown_v2(
        _build_seal_artifact(),
        body,
        ledger_request_id=_LEDGER_ID,
        sidecars=EnvelopeSidecars(process_narrative=f"{_LEDGER_ID}.process.json"),
    )
    assert f'profile: "{PROFILE_SEAL}"' in markdown
    assert "synthesis:" in markdown
    assert 'speechAct: "orchestration-declaration"' in markdown
    assert f'contentHash: "{narrative_hash}"' in markdown
    cc0 = resolve_license_text("CC0-1.0")
    assert 'policyId: "CC0-1.0"' in markdown
    assert f'notice: "{cc0.notice}"' in markdown
    assert f'statement: "{cc0.statement}"' in markdown
    assert "integrity:\n" in markdown
    assert "  signatures:" in markdown


def test_round_trip_preserves_signing_hash() -> None:
    for builder, body in (
        (_build_register_artifact, "Human body for v2."),
        (_build_seal_artifact, "Synthetic body for v2."),
    ):
        artifact = builder()
        markdown = render_artifact_markdown_v2(
            artifact,
            body,
            ledger_request_id=_LEDGER_ID,
            sidecars=EnvelopeSidecars(process_narrative=f"{_LEDGER_ID}.process.json"),
        )
        parsed, parsed_body = parse_artifact_markdown_text_v2(markdown)
        assert parsed_body == body.strip()
        assert _signing_hash(artifact, body) == _signing_hash(parsed, body)


def test_unattended_register_omits_classification_on_wire() -> None:
    body = "Human body for v2."
    artifact_hash = compute_payload_hash(body)
    artifact = Artifact(
        id=_REQUEST_ID,
        title="Unattended Register",
        timestamp=datetime(2026, 3, 14, 10, 41, 18, tzinfo=UTC),
        contentType="text/markdown",
        license="ARR",
        provenance=enrich_provenance_for_v2_wire(
            Provenance(
                source="human",
                engineVersion="antiphoria-slop-provenance-v1.0.0",
                modelId="human",
                generationContext=generation_context_for_source("human"),
                provenanceGrade="unattended",
                attestationStrength="unattended",
                authorAttestation=sample_human_attestation(
                    attestationMode="unattended",
                    classification=None,
                    attestations=[],
                ),
                registrationCeremony=sample_registration_ceremony(),
            )
        ),
        signature=SignatureBlock(
            artifactHash=artifact_hash,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
        ),
    )
    markdown = render_artifact_markdown_v2(artifact, body, ledger_request_id=_LEDGER_ID)
    assert "classification:" not in markdown
    parsed, _ = parse_artifact_markdown_text_v2(markdown)
    assert parsed.provenance.author_attestation is not None
    assert parsed.provenance.author_attestation.attestation_mode == "unattended"
    assert parsed.provenance.author_attestation.classification is None


def test_parse_rejects_register_with_synthesis() -> None:
    body = "Human body for v2."
    markdown = render_artifact_markdown_v2(
        _build_register_artifact(), body, ledger_request_id=_LEDGER_ID
    )
    delimiter = markdown.find("\n---\n", 4)
    loaded = yaml.safe_load(markdown[4:delimiter])
    loaded["synthesis"] = {"modelId": "human"}
    tampered = "---\n" + yaml.safe_dump(loaded, sort_keys=False) + "---\n" + body + "\n"
    with pytest.raises(RuntimeError, match="register profile MUST NOT contain synthesis"):
        parse_artifact_markdown_text_v2(tampered)


def test_parse_rejects_unknown_profile() -> None:
    body = "Synthetic body for v2."
    markdown = render_artifact_markdown_v2(
        _build_seal_artifact(),
        body,
        ledger_request_id=_LEDGER_ID,
        sidecars=EnvelopeSidecars(process_narrative=f"{_LEDGER_ID}.process.json"),
    )
    delimiter = markdown.find("\n---\n", 4)
    loaded = yaml.safe_load(markdown[4:delimiter])
    loaded["antiphoria"]["profile"] = "unknown.profile"
    tampered = "---\n" + yaml.safe_dump(loaded, sort_keys=False) + "---\n" + body + "\n"
    with pytest.raises(RuntimeError, match="Unknown or unsupported v2 profile"):
        parse_artifact_markdown_text_v2(tampered)


def test_parse_rejects_seal_without_synthesis() -> None:
    body = "Synthetic body for v2."
    markdown = render_artifact_markdown_v2(
        _build_seal_artifact(),
        body,
        ledger_request_id=_LEDGER_ID,
        sidecars=EnvelopeSidecars(process_narrative=f"{_LEDGER_ID}.process.json"),
    )
    delimiter = markdown.find("\n---\n", 4)
    loaded = yaml.safe_load(markdown[4:delimiter])
    loaded.pop("synthesis", None)
    tampered = "---\n" + yaml.safe_dump(loaded, sort_keys=False) + "---\n" + body + "\n"
    with pytest.raises(RuntimeError, match="seal profile MUST contain synthesis"):
        parse_artifact_markdown_text_v2(tampered)


def test_parse_rejects_unknown_top_level_section() -> None:
    body = "Synthetic body for v2."
    markdown = render_artifact_markdown_v2(
        _build_seal_artifact(),
        body,
        ledger_request_id=_LEDGER_ID,
        sidecars=EnvelopeSidecars(process_narrative=f"{_LEDGER_ID}.process.json"),
    )
    delimiter = markdown.find("\n---\n", 4)
    loaded = yaml.safe_load(markdown[4:delimiter])
    loaded["unexpectedSection"] = 1
    tampered = "---\n" + yaml.safe_dump(loaded, sort_keys=False) + "---\n" + body + "\n"
    with pytest.raises(RuntimeError, match="Unknown top-level v2 section"):
        parse_artifact_markdown_text_v2(tampered)


def test_operator_webauthn_round_trip() -> None:
    body = "Human body for v2."
    webauthn = WebAuthnAttestation(
        credentialId="cred-123",
        clientDataJsonHash="a" * 64,
        authenticatorData="auth-data",
        signature="sig-data",
        fmt="packed",
    )
    provenance = enrich_provenance_for_v2_wire(
        Provenance(
            source="human",
            engineVersion="antiphoria-slop-provenance-v1.0.0",
            modelId="human",
            generationContext=generation_context_for_source("human"),
            provenanceGrade="declared",
            attestationStrength="webauthn",
            authorAttestation=sample_human_attestation(),
            registrationCeremony=sample_registration_ceremony(),
            webauthnAttestation=webauthn,
        )
    )
    artifact = Artifact(
        id=_REQUEST_ID,
        title="WebAuthn Register",
        timestamp=datetime(2026, 3, 14, 10, 41, 18, tzinfo=UTC),
        contentType="text/markdown",
        license="ARR",
        provenance=provenance,
        signature=SignatureBlock(
            artifactHash=compute_payload_hash(body),
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
        ),
    )
    markdown = render_artifact_markdown_v2(
        artifact,
        body,
        ledger_request_id=_LEDGER_ID,
        sidecars=EnvelopeSidecars(ots=f".provenance/ots-{_LEDGER_ID}.ots"),
    )
    assert "  webauthn:" in markdown
    assert 'attestationStrength: "webauthn"' in markdown
    assert f'    ots: ".provenance/ots-{_LEDGER_ID}.ots"' in markdown
    parsed, parsed_body = parse_artifact_markdown_text_v2(markdown)
    assert parsed_body == body.strip()
    assert parsed.provenance.webauthn_attestation is not None
    assert parsed.provenance.webauthn_attestation.credential_id == "cred-123"
    assert parsed.provenance.attestation_strength == "webauthn"


def test_v2_parser_maps_legacy_attestation_strength_to_none() -> None:
    body = "Human body for v2."
    markdown = render_artifact_markdown_v2(
        _build_register_artifact(),
        body,
        ledger_request_id=_LEDGER_ID,
    ).replace('attestationStrength: "none"', 'attestationStrength: "legacy"')
    parsed, _ = parse_artifact_markdown_text_v2(markdown)
    assert parsed.provenance.attestation_strength == "none"


def test_v1_fixture_regression() -> None:
    fixture_path = Path("tests/fixtures/valid_artifact.md")
    text = fixture_path.read_text(encoding="utf-8")
    envelope, payload = parse_artifact_markdown_text(text)
    assert envelope.schema_version == "eternity.v1"
    assert envelope.provenance.source == "synthetic"
    assert "DUMMY INCIDENT" in payload


def test_legacy_generate_uses_v1_wire_when_ceremony_missing() -> None:
    body = "Legacy generated body."
    artifact = Artifact(
        title="Generated",
        timestamp=datetime.now(UTC),
        contentType="text/markdown",
        license="CC0-1.0",
        provenance=Provenance(
            source="synthetic",
            engineVersion="test-engine",
            modelId="test-model",
            generationContext=generation_context_for_source("synthetic"),
        ),
        signature=SignatureBlock(
            artifactHash=compute_payload_hash(body),
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="fp"),
        ),
    )
    markdown = render_artifact_markdown_wire(artifact, body, ledger_request_id=str(uuid4()))
    assert 'schemaVersion: "eternity.v1"' in markdown
    envelope, parsed_body = parse_artifact_markdown_text(markdown)
    assert envelope.schema_version == "eternity.v1"
    assert parsed_body == body


@patch("src.services.verification_service.CatalogAdapter")
def test_catalog_source_mismatch_error(mock_catalog_cls: MagicMock) -> None:
    mock_catalog_cls.return_value.read_entries.return_value = [
        {"requestId": "abc", "source": "synthetic"}
    ]
    service = VerificationService.__new__(VerificationService)
    service._env_path = Path(".env")
    errors = service._catalog_source_errors(
        repository_path=Path("."),
        request_id="abc",
        envelope_source="human",
    )
    assert len(errors) == 1
    assert "Catalog source 'synthetic' != envelope source 'human'" in errors[0]
