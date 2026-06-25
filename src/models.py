"""Eternity v1 provenance envelope and companion schema utilities."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Annotated, Any, Literal, Self, TypeAlias
from uuid import UUID, uuid4

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

CRYPTO_ALGORITHM_ML_DSA_44 = "CRYSTALS-Dilithium (NIST ML-DSA-44)"
"""Canonical algorithm label required in frontmatter."""

CRYPTO_ALGORITHM_ED25519 = "Ed25519"
"""Classical algorithm for hybrid (belt-and-suspenders) signing."""

PolicyLicenseId: TypeAlias = Literal["ARR", "CC-BY-4.0", "CC0-1.0"]
"""Canonical license IDs from CONTENT_LICENSE_POLICY. Use | str for custom escape hatch."""

ArtisticClassification: TypeAlias = Literal["fact", "opinion", "fiction", "satire"]
"""Artistic classification for human-authored content."""

AttestationNature: TypeAlias = Literal["self-declaration", "orchestration-declaration"]
"""What kind of operator statement is recorded (not a legal certification)."""

AttestationMode: TypeAlias = Literal["interactive", "unattended"]
"""How the operator statement was captured."""

ProvenanceGrade: TypeAlias = Literal["recorded", "declared", "unattended"]
"""Epistemic grade: recorded at creation, declared at seal, or unattended automation."""


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
    """Single self-declaration prompt and operator response, stored verbatim."""

    question: str = Field(min_length=1)
    answer: str = Field(min_length=1)


class AuthorAttestation(StrictModel):
    """Operator self-declaration captured at human registration time."""

    attestation_nature: AttestationNature = Field(
        alias="attestationNature",
        default="self-declaration",
    )
    attestation_mode: AttestationMode = Field(
        alias="attestationMode",
        default="interactive",
    )
    classification: ArtisticClassification | None = Field(default=None)
    attestations: list[AttestationQa] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def validate_attestations_for_mode(self) -> Self:
        if self.attestation_mode == "interactive":
            if self.classification is None:
                raise ValueError("interactive attestation requires classification")
            if len(self.attestations) < 4:
                raise ValueError("interactive attestation requires at least 4 Q&A pairs")
        elif self.attestation_mode == "unattended":
            if self.classification is not None:
                raise ValueError("unattended attestation must not include classification")
            if self.attestations:
                raise ValueError("unattended attestation must not include Q&A pairs")
        return self


class WebAuthnAttestation(StrictModel):
    """FIDO2/WebAuthn assertion captured at operator ceremony time.

    v3 (Flaw A, pre-release.md §3): ``client_data_json`` is now stored in full
    (base64-encoded), not just its hash. This closes the verification loop —
    the assertion's signature is over ``authenticatorData || SHA-256(clientDataJSON)``,
    and the ``clientDataJSON.challenge`` field must equal the expected body hash
    for the assertion to mean anything. Without the full clientDataJSON, the
    challenge couldn't be checked.
    """

    credential_id: str = Field(alias="credentialId", min_length=1)
    client_data_json: str = Field(
        alias="clientDataJson",
        min_length=1,
        description="base64-encoded clientDataJSON (full, not just the hash).",
    )
    client_data_json_hash: str = Field(
        alias="clientDataJsonHash",
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
    )
    authenticator_data: str = Field(alias="authenticatorData", min_length=1)
    signature: str = Field(min_length=1)
    fmt: str = Field(min_length=1)


AttestationStrength: TypeAlias = Literal["webauthn", "none", "unattended"]


RevisionReason: TypeAlias = Literal[
    "copyright-flag",
    "error-correction",
    "plagiarism-removal",
    "editorial",
    "legal",
    "other",
]


class Revision(StrictModel):
    """Work-version link. Absent on the first version of a work; present on
    every superseding version.

    Design (Gap 1, pre-release.md §3): the link is a *content commitment*, not a
    verification dependency. ``supersedesHash`` proves the new author had the
    prior version's exact bytes — it does NOT make this artifact's verification
    depend on the prior artifact existing. Every artifact stays independently
    verifiable. The block lives inside the signed envelope target, so it's
    covered by every operator seal automatically.
    """

    chain_root: str = Field(
        alias="chainRoot",
        min_length=1,
        description="Stable identifier for the work across all versions (the v1 requestId).",
    )
    sequence: int = Field(
        ge=2,
        description="1-based version number. v1 has no revision block; v2+ start at 2.",
    )
    supersedes: str = Field(
        alias="supersedes",
        min_length=1,
        description="requestId of the immediately-prior version.",
    )
    supersedes_hash: str = Field(
        alias="supersedesHash",
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
        description="payloadHash of the prior version — content commitment, not a dependency.",
    )
    reason: RevisionReason = Field(
        description="Why this version supersedes the prior (machine-readable category).",
    )
    note: str | None = Field(
        default=None,
        description="Free-text explanation. Optional; included in the signed envelope if present.",
    )


class VerificationAnchor(StrictModel):
    """Public verification anchor for signature identity lookup."""

    signer_fingerprint: str = Field(alias="signerFingerprint", min_length=1)
    public_key_uri: HttpUrl | None = Field(alias="publicKeyUri", default=None)


class RegistrationCeremony(StrictModel):
    """Proof-of-environment metadata for human registration."""

    registration_utc_ms: int = Field(alias="registrationUtcMs")
    orchestrator_git_commit: str = Field(alias="orchestratorGitCommit", min_length=1)
    machine_id_hash: str | None = Field(alias="machineIdHash", default=None)
    operator_pseudonym_hash: str | None = Field(
        alias="operatorPseudonymHash",
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )


class Provenance(StrictModel):
    """Provenance metadata independent from transport/render format.

    v3 (Gap 2): ``webauthn_attestation``, ``attestation_strength``, and
    ``registration_ceremony`` were moved from Provenance to ``OperatorSeal``.
    Each seal is self-contained; Provenance describes the work, not who sealed
    it or how. This keeps the signing target stable regardless of how many
    witnesses append seals.
    """

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
    provenance_grade: ProvenanceGrade | None = Field(
        alias="provenanceGrade",
        default=None,
    )
    models_used: list[str] | None = Field(
        alias="modelsUsed",
        default=None,
        max_length=64,
    )
    process_narrative_hash: str | None = Field(
        alias="processNarrativeHash",
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
    )


class SignatureBlock(StrictModel):
    """Cryptographic seal details for envelope verification."""

    crypto_algorithm: Literal[CRYPTO_ALGORITHM_ML_DSA_44, CRYPTO_ALGORITHM_ED25519] = Field(
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


OperatorSealRole: TypeAlias = Literal["sealer", "witness"]


class OperatorSeal(StrictModel):
    """One operator's independent seal over the canonical envelope target.

    v3 (Gap 2, Option A): every seal has identical anatomy. The ``role`` string
    distinguishes the primary sealer from witnesses (and future roles). Each
    seal is self-contained — it carries its own ceremony, webauthn attestation,
    and primary + hybrid signature pair. Multiple operators each independently
    sign identical canonical bytes; seals are order-independent and verify
    independently.
    """

    operator_pseudonym_hash: str | None = Field(
        alias="operatorPseudonymHash",
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    role: OperatorSealRole = Field(default="sealer")
    sealed_at: str = Field(
        alias="sealedAt",
        min_length=1,
        description="ISO-8601 UTC timestamp when this seal was applied.",
    )
    ceremony: RegistrationCeremony | None = Field(default=None)
    webauthn_attestation: WebAuthnAttestation | None = Field(
        alias="webauthn",
        default=None,
    )
    attestation_strength: AttestationStrength | None = Field(
        alias="attestationStrength",
        default=None,
    )
    primary: SignatureBlock
    hybrid: SignatureBlock | None = None


class Artifact(StrictModel):
    """Eternity v3 portable artifact envelope.

    v3 bumps the wire format from v2 to reflect: operator/author role split,
    witnessing, versioning, and the license-owner correction. See
    `user-stories.md §7.1` and `pre-release.md §3` (Flaw D).
    """

    schema_version: Literal["eternity.v3", "eternity.v1"] = Field(
        alias="schemaVersion",
        default="eternity.v3",
    )
    id: UUID = Field(default_factory=uuid4)
    title: str = Field(min_length=1)
    timestamp: datetime
    content_type: str = Field(alias="contentType", min_length=1)
    license: Annotated[
        PolicyLicenseId | str,
        Field(min_length=1),
    ]
    rights_holder: str | None = Field(
        alias="rightsHolder",
        default=None,
        description=(
            "The rights holder for this work — the author's pen name or legal "
            "name (Flaw F). Antiphoria warrants provenance; the author owns the "
            "work. None on legacy v2 artifacts; required for v3 seals."
        ),
    )
    revision: Revision | None = Field(
        default=None,
        description=(
            "Work-version link (Gap 1). None on the first version of a work; "
            "present on every superseding version. Lives inside the signed "
            "envelope, so it's covered by every operator seal automatically."
        ),
    )
    provenance: Provenance
    curation: Curation | None = None
    operator_seals: list[OperatorSeal] = Field(
        alias="operatorSeals",
        default_factory=list,
        description=(
            "v3 (Gap 2, Option A): independent operator seals over the canonical "
            "envelope target. Each seal is self-contained (pseudonym, role, "
            "ceremony, webauthn, primary + hybrid signatures). Min 1 (the "
            "sealer); additional entries are witnesses. Order-independent."
        ),
    )
    record_status: Literal["unverified"] = Field(alias="recordStatus", default="unverified")

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_signature_fields(cls, data: Any) -> Any:
        """Map legacy singular signature/hybridSignature into operatorSeals[].

        v3 (Gap 2): Artifact no longer has ``signature`` / ``hybridSignature``
        as real fields — they're computed properties over ``operator_seals``.
        But many callers (tests, the v2 parser, legacy code paths) still
        construct Artifact with the old singular fields. This validator
        translates them into a single ``role="sealer"`` OperatorSeal entry
        before validation runs, so the old call sites keep working.

        Ceremony/webauthn/strength come from ``provenance`` if present there
        (the v2 parser still reads them from that location for legacy input).
        """
        if not isinstance(data, dict):
            return data
        sig = data.get("signature") or data.get("signatureBlock")
        hybrid = data.get("hybridSignature") or data.get("hybrid_signature")
        existing_seals = data.get("operatorSeals") or data.get("operator_seals")
        if sig is not None and not existing_seals:
            # v3 (Gap 2): ceremony / webauthn / strength now live on OperatorSeal,
            # not Provenance. Legacy callers that construct Artifact with the old
            # singular signature field won't have these — the seal gets minimal
            # metadata and the renderer synthesizes a placeholder ceremony.
            from datetime import UTC, datetime as _dt

            seal_dict: dict[str, Any] = {
                "role": "sealer",
                "sealedAt": _dt.now(UTC).isoformat(),
                "primary": sig,
            }
            if hybrid is not None:
                seal_dict["hybrid"] = hybrid
            # Use the alias key the field expects.
            data = {k: v for k, v in data.items() if k not in (
                "signature",
                "signatureBlock",
                "hybridSignature",
                "hybrid_signature",
            )}
            data["operatorSeals"] = [seal_dict]
        return data

    # --- Backward-compat computed views onto operator_seals ---
    # These let existing callers (catalog, notary, verification, maintenance,
    # provenance_service, repository) keep reading envelope.signature /
    # envelope.hybrid_signature unchanged. They return the *sealer's* primary
    # and hybrid signature blocks — i.e. the first operatorSeal with
    # role == "sealer" (or the first seal if none is explicitly the sealer).
    # Gap 2's witness command reads operator_seals directly.

    @property
    def signature(self) -> SignatureBlock | None:
        """The sealer's primary signature block (backward compat)."""
        for seal in self.operator_seals:
            if seal.role == "sealer":
                return seal.primary
        return self.operator_seals[0].primary if self.operator_seals else None

    @property
    def hybrid_signature(self) -> SignatureBlock | None:
        """The sealer's hybrid signature block (backward compat)."""
        for seal in self.operator_seals:
            if seal.role == "sealer":
                return seal.hybrid
        return self.operator_seals[0].hybrid if self.operator_seals else None


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Return deterministic canonical JSON bytes for signing.

    Uses RFC 8785 (JSON Canonicalization Scheme) for strict JCS compliance.
    Ensures consistent output across parsers for float normalization,
    Unicode normalization, and escape sequences.
    """
    return rfc8785.dumps(data)


def build_envelope_signing_target(
    envelope: Artifact,
    payload_sha256_hex: str,
    manifest_sha256_hex: str | None,
    canonicalization_version: str | None = None,
) -> dict[str, Any]:
    """Build canonical signing target from envelope.

    v3: `prev_hash` was removed (OD-2, pre-release.md §4). Work-versioning is
    handled by the signed `revision` block (Gap 1) — a content commitment, not a
    verification dependency. Each artifact stays independently verifiable.

    Gap 2 (Option A): the target strips `cryptographicSignature` from every
    `operatorSeals[].primary` and `.hybrid` block, while leaving all other seal
    metadata (pseudonymHash, role, ceremony, webauthn, algorithm,
    signerFingerprint, artifactHash) intact. Every operator independently signs
    identical canonical bytes; seals are order-independent and verify
    independently. Adding a witness seal does NOT change the bytes the sealer
    already signed — it just appends another signature over the same target.
    """

    envelope_data = envelope.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    # Legacy singular signature fields (kept as computed properties; they don't
    # appear in model_dump output since they're not real fields, but we strip
    # them defensively in case a caller copied them into a dict).
    envelope_data.pop("signature", None)
    envelope_data.pop("hybridSignature", None)

    # v3 (Gap 2): the entire ``operatorSeals`` list is EXCLUDED from the signing
    # target. Each operator signs the *envelope* (the work being attested:
    # document, rights, revision, claim, synthesis, provenance, integrity hashes)
    # — not the list of who else has attested. This is what makes witnessing
    # work: a witness appends their seal without changing the bytes the sealer
    # already signed. The seal list is post-hoc metadata; removing it from the
    # target keeps every existing signature valid as witnesses accumulate.
    envelope_data.pop("operatorSeals", None)

    target: dict[str, Any] = {
        "schemaVersion": "eternity.signing-target.v1",
        "artifactId": str(envelope.id),
        "payloadHash": payload_sha256_hex,
        "manifestHash": manifest_sha256_hex,
        "envelope": envelope_data,
    }
    if canonicalization_version:
        target["canonicalizationVersion"] = canonicalization_version
    return target


def sha256_hex(data: bytes) -> str:
    """Return lowercase SHA-256 digest for bytes payload."""

    return hashlib.sha256(data).hexdigest()
