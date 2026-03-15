"""Eternity v1 provenance envelope and companion schema utilities."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Any, Literal, TypeAlias
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

CRYPTO_ALGORITHM_ML_DSA_44 = "CRYSTALS-Dilithium (NIST ML-DSA-44)"
"""Canonical algorithm label required in frontmatter."""

CRYPTO_ALGORITHM_ED25519 = "Ed25519"
"""Classical algorithm for hybrid (belt-and-suspenders) signing."""

PolicyLicenseId: TypeAlias = Literal["ARR", "CC-BY-4.0", "CC0-1.0"]
"""Canonical license IDs from CONTENT_LICENSE_POLICY. Use | str for custom escape hatch."""

ArtisticClassification: TypeAlias = Literal["fact", "opinion", "fiction", "satire"]
"""Artistic classification for human-authored content."""


class StrictModel(BaseModel):
    """Strict immutable base model used across Eternity v1."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Hyperparameters(StrictModel):
    """Generation hyperparameters preserved for provenance transparency."""

    temperature: float = Field(ge=0.0, le=2.0)
    top_p: float = Field(alias="topP", ge=0.0, le=1.0)
    top_k: int = Field(alias="topK", ge=0)


class GenerationContext(StrictModel):
    """Prompt and instruction context for this generation event."""

    system_instruction: str = Field(alias="systemInstruction", min_length=1)
    prompt: str = Field(min_length=1)
    hyperparameters: Hyperparameters


class UsageMetrics(StrictModel):
    """Compute usage telemetry for audit and cost analysis."""

    prompt_tokens: int = Field(alias="promptTokens", ge=0)
    completion_tokens: int = Field(alias="completionTokens", ge=0)
    total_tokens: int = Field(alias="totalTokens", ge=0)


class EmbeddedWatermark(StrictModel):
    """Declaration for latent provider watermark availability."""

    provider: str = Field(min_length=1)
    status: Literal["present", "absent", "unknown"]


class Curation(StrictModel):
    """Human curation metadata for hybrid artifacts."""

    difference_score: float = Field(alias="differenceScore", ge=0.0, le=100.0)
    unified_diff: str = Field(alias="unifiedDiff", min_length=1)


class AttestationQa(StrictModel):
    """Single Q&A pair stored verbatim for legal record. Questions and answers
    must be preserved in full, unchanged length."""

    question: str = Field(min_length=1)
    answer: str = Field(min_length=1)


class AuthorAttestation(StrictModel):
    """Explicit artistic declarations made by a human author. Stores the
    actual questions and answers verbatim for legal importance."""

    classification: ArtisticClassification
    attestations: list[AttestationQa] = Field(min_length=4)


class WebAuthnAttestation(StrictModel):
    """FIDO2/WebAuthn assertion for strong non-repudiation of author attestation."""

    credential_id: str = Field(alias="credentialId", min_length=1)
    client_data_json_hash: str = Field(
        alias="clientDataJsonHash",
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
    )
    authenticator_data: str = Field(alias="authenticatorData", min_length=1)
    signature: str = Field(min_length=1)
    fmt: str = Field(min_length=1)


AttestationStrength: TypeAlias = Literal["webauthn", "legacy"]


class VerificationAnchor(StrictModel):
    """Public verification anchor for signature identity lookup."""

    signer_fingerprint: str = Field(alias="signerFingerprint", min_length=1)
    public_key_uri: HttpUrl | None = Field(alias="publicKeyUri", default=None)


class RegistrationCeremony(StrictModel):
    """Proof-of-environment metadata for human registration."""

    registration_utc_ms: int = Field(alias="registrationUtcMs")
    orchestrator_git_commit: str = Field(
        alias="orchestratorGitCommit", min_length=1
    )
    machine_id_hash: str | None = Field(
        alias="machineIdHash", default=None
    )


class Provenance(StrictModel):
    """Provenance metadata independent from transport/render format."""

    source: Literal["synthetic", "hybrid", "human"]
    engine_version: str = Field(alias="engineVersion", min_length=1)
    model_id: str = Field(alias="modelId", min_length=1)
    generation_context: GenerationContext = Field(alias="generationContext")
    usage_metrics: UsageMetrics | None = Field(alias="usageMetrics", default=None)
    embedded_watermark: EmbeddedWatermark | None = Field(
        alias="embeddedWatermark",
        default=None,
    )
    author_attestation: AuthorAttestation | None = Field(
        alias="authorAttestation",
        default=None,
    )
    webauthn_attestation: WebAuthnAttestation | None = Field(
        alias="webauthnAttestation",
        default=None,
    )
    attestation_strength: AttestationStrength | None = Field(
        alias="attestationStrength",
        default=None,
    )
    registration_ceremony: RegistrationCeremony | None = Field(
        alias="registrationCeremony",
        default=None,
    )


class SignatureBlock(StrictModel):
    """Cryptographic seal details for envelope verification."""

    crypto_algorithm: Literal[
        CRYPTO_ALGORITHM_ML_DSA_44, CRYPTO_ALGORITHM_ED25519
    ] = Field(
        alias="cryptoAlgorithm",
        default=CRYPTO_ALGORITHM_ML_DSA_44,
    )
    artifact_hash: str = Field(
        alias="artifactHash",
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
    )
    cryptographic_signature: str = Field(alias="cryptographicSignature", min_length=1)
    verification_anchor: VerificationAnchor = Field(alias="verificationAnchor")
    rfc3161_token: str | None = Field(alias="rfc3161Token", default=None)
    payload_canonicalization: str | None = Field(
        alias="payloadCanonicalization",
        default=None,
    )


class Artifact(StrictModel):
    """Eternity v1 portable artifact envelope."""

    schema_version: Literal["eternity.v1"] = Field(
        alias="schemaVersion",
        default="eternity.v1",
    )
    id: UUID = Field(default_factory=uuid4)
    title: str = Field(min_length=1)
    timestamp: datetime
    content_type: str = Field(alias="contentType", min_length=1)
    license: Annotated[
        PolicyLicenseId | str,
        Field(min_length=1),
    ]
    provenance: Provenance
    curation: Curation | None = None
    signature: SignatureBlock | None = None
    hybrid_signature: SignatureBlock | None = Field(
        alias="hybridSignature", default=None
    )
    record_status: Literal["unverified"] = Field(
        alias="recordStatus", default="unverified"
    )

    def to_frontmatter_dict(self) -> dict[str, object]:
        """Return frontmatter dictionary with alias keys."""

        return self.model_dump(by_alias=True, exclude_none=True)


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Return deterministic canonical JSON bytes for signing.

    Uses sort_keys + compact separators. Python json.dumps formats floats as 0.0
    (not 0); strict RFC 8785 JCS requires 0 for integral floats. Cross-language
    validators (Go, TypeScript) implementing JCS may produce different bytes.
    JCS compliance is deferred; use the `jcs` library if interoperability with
    strict JCS validators is required.
    """

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def build_envelope_signing_target(
    envelope: Artifact,
    payload_sha256_hex: str,
    manifest_sha256_hex: str | None,
    prev_hash: str | None,
    canonicalization_version: str | None = None,
) -> dict[str, Any]:
    """Build canonical signing target from envelope and chain anchors."""

    envelope_data = envelope.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    # Signature metadata is excluded from the signed envelope target to keep
    # sign/verify bytes stable regardless of post-signature attachment details.
    envelope_data.pop("signature", None)
    envelope_data.pop("hybridSignature", None)

    target: dict[str, Any] = {
        "schemaVersion": "eternity.signing-target.v1",
        "artifactId": str(envelope.id),
        "payloadHash": payload_sha256_hex,
        "manifestHash": manifest_sha256_hex,
        "prevHash": prev_hash,
        "envelope": envelope_data,
    }
    if canonicalization_version:
        target["canonicalizationVersion"] = canonicalization_version
    return target


def sha256_hex(data: bytes) -> str:
    """Return lowercase SHA-256 digest for bytes payload."""

    return hashlib.sha256(data).hexdigest()


EternityEnvelopeV1 = Artifact
"""Explicit alias for the embedded Eternity v1 envelope model."""
