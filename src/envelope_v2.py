"""Eternity v2 enterprise envelope wire codec (YAML frontmatter).

v2 is a presentation layer over the internal ``Artifact`` model and
``eternity.signing-target.v1`` signing bytes. Parsing reconstructs v1-shaped
envelopes with profile-specific sentinel ``generationContext`` values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import yaml

from src.artifact_serialization import _wrap_signature_lines, _yaml_literal_block, _yaml_quoted
from src.canonicalization import CANONICALIZATION_VERSION, canonicalize_body
from src.env_config import read_env_optional
from src.models import (
    Artifact,
    AttestationQa,
    AuthorAttestation,
    GenerationContext,
    Hyperparameters,
    OperatorSeal,
    Provenance,
    RegistrationCeremony,
    Revision,
    SignatureBlock,
    VerificationAnchor,
    WebAuthnAttestation,
)
from src.policies.license_text import resolve_license_text

SCHEMA_VERSION_V2 = "eternity.v3"
"""v3 wire format schema version.

The constant name ``SCHEMA_VERSION_V2`` is retained (the module is still
``envelope_v2.py``) for source stability; the value is the v3 schema label.
The internal model and the C2PA context assertion now both report
``eternity.v3``, fixing the v1/v2 drift (Flaw D).
"""
PROFILE_REGISTER = "antiphoria.register.v1"
PROFILE_SEAL = "antiphoria.seal.v1"

_ALLOWED_TOP_LEVEL = frozenset(
    {
        "antiphoria",
        "document",
        # v3 (Gap 1): revision block lives between document and rights.
        "revision",
        "rights",
        # v3 (Gap 2): operatorSeals replaces the old singular operator/signature.
        "operatorSeals",
        # Legacy v2 sections — still accepted for grandfathered reads:
        "operator",
        "claim",
        "synthesis",
        "integrity",
    }
)

_PROCESS_NARRATIVE_DISCLAIMER = "Operator-supplied narrative. Not machine-verified lineage."


def generation_context_for_source(
    source: Literal["human", "synthetic", "hybrid"],
) -> GenerationContext:
    """Return fixed sentinel generation context for v2 register/seal signing."""

    if source == "human":
        system_instruction = "Human-authored. No AI generation."
    elif source == "synthetic":
        system_instruction = "Machine-generated. Orchestrator declaration only."
    else:
        raise RuntimeError(f"No v2 sentinel generationContext for source '{source}'.")
    return GenerationContext(
        systemInstruction=system_instruction,
        prompt="N/A",
        hyperparameters=Hyperparameters(temperature=0.0, topP=1.0, topK=0),
    )


def profile_for_source(source: str) -> str:
    if source == "human":
        return PROFILE_REGISTER
    if source == "synthetic":
        return PROFILE_SEAL
    raise RuntimeError(f"v2 wire format does not support source '{source}'.")


def source_for_profile(profile: str) -> str:
    if profile == PROFILE_REGISTER:
        return "human"
    if profile == PROFILE_SEAL:
        return "synthetic"
    raise RuntimeError(f"Unknown or unsupported v2 profile '{profile}'.")


def resolve_envelope_wire_version(env_path: Any = None) -> str:  # noqa: ARG001
    """v3 stub. Always returns 'v3'. Wire-version selection was removed (v1
    renderer deleted, pre-release.md §1). Retained for API compatibility with
    any caller that still imports it; the env knob ``ENVELOPE_WIRE_VERSION`` is
    ignored.
    """
    return "v3"


def resolve_wire_version_for_artifact(
    artifact: Artifact,  # noqa: ARG001
    *,
    env_path: Any = None,  # noqa: ARG001
    wire_version: str | None = None,  # noqa: ARG001
) -> str:
    """v3 stub. Always returns 'v3'. See ``resolve_envelope_wire_version``."""
    return "v3"


def is_v2_wire_format(text: str) -> bool:
    """Return True when frontmatter uses the antiphoria enterprise layout.

    Name is retained for source compatibility. In v3 the layout is unchanged
    from v2 (same top-level sections); only the ``schemaVersion`` label differs
    (``eternity.v3`` for new seals, ``eternity.v2`` accepted as legacy input).
    Detection keys off the ``antiphoria:`` top-level block, not the schema
    label, so both v2 and v3 wire formats route here.
    """

    if not text.startswith("---\n"):
        return False
    delimiter_index = text.find("\n---\n", 4)
    if delimiter_index == -1:
        return False
    frontmatter = text[4:delimiter_index]
    return frontmatter.startswith("antiphoria:")


def detect_wire_version_from_markdown(text: str) -> str:
    return "v2" if is_v2_wire_format(text) else "v1"


def parse_sidecars_from_markdown(text: str) -> EnvelopeSidecars:
    """Extract integrity.sidecars paths from v2 frontmatter (empty for v1)."""

    if not is_v2_wire_format(text):
        return EnvelopeSidecars()
    delimiter_index = text.find("\n---\n", 4)
    if delimiter_index == -1:
        return EnvelopeSidecars()
    frontmatter_text = text[4:delimiter_index]
    loaded: Any = yaml.safe_load(frontmatter_text)
    if not isinstance(loaded, dict):
        return EnvelopeSidecars()
    integrity = loaded.get("integrity")
    if not isinstance(integrity, dict):
        return EnvelopeSidecars()
    sidecars = integrity.get("sidecars")
    if not isinstance(sidecars, dict):
        return EnvelopeSidecars()
    return EnvelopeSidecars(
        c2pa=sidecars.get("c2pa") if isinstance(sidecars.get("c2pa"), str) else None,
        process_narrative=(
            sidecars.get("processNarrative")
            if isinstance(sidecars.get("processNarrative"), str)
            else None
        ),
        ots=sidecars.get("ots") if isinstance(sidecars.get("ots"), str) else None,
    )


@dataclass(frozen=True)
class EnvelopeSidecars:
    """Render-time sidecar paths (not part of signing target)."""

    c2pa: str | None = None
    process_narrative: str | None = None
    ots: str | None = None
    tsa_provider: str | None = None


def _rights_block(policy_id: str, holder: str | None = None) -> tuple[str, str]:
    """Build (notice, statement) for a policy id.

    v3 (Flaw F): when ``holder`` is provided, license text is attributed to the
    author (the rights holder). When omitted, legacy v2 wording is emitted
    (Antiphoria as holder) — only for grandfathered compatibility.
    """
    text = resolve_license_text(policy_id, holder=holder)
    return text.notice, text.statement


def _ms_to_iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=UTC).isoformat()


def _iso_to_ms(iso_text: str) -> int:
    dt = datetime.fromisoformat(iso_text.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def _validate_v2_invariants(loaded: dict[str, Any]) -> None:
    for key in loaded:
        if key not in _ALLOWED_TOP_LEVEL:
            raise RuntimeError(f"Unknown top-level v2 section '{key}'.")

    antiphoria = loaded.get("antiphoria")
    if not isinstance(antiphoria, dict):
        raise RuntimeError("v2 envelope missing antiphoria section.")
    profile = antiphoria.get("profile")
    schema = antiphoria.get("schemaVersion")
    # v3 emits eternity.v3; eternity.v2 is accepted as legacy input only (the
    # two dev-run artifacts in the archive). v1 (the old flat schema) is not
    # routed here at all — see parsing.py.
    if schema not in ("eternity.v3", "eternity.v2"):
        raise RuntimeError(f"Unsupported antiphoria.schemaVersion '{schema}'.")

    claim = loaded.get("claim")
    if not isinstance(claim, dict):
        raise RuntimeError("v2 envelope missing claim section.")

    source = claim.get("source")
    speech_act = claim.get("speechAct")
    try:
        expected_source = source_for_profile(str(profile))
    except RuntimeError as exc:
        raise RuntimeError(str(exc)) from exc

    if source != expected_source:
        raise RuntimeError(f"Profile/source mismatch: profile={profile} claim.source={source}.")

    expected_speech = (
        "self-declaration" if profile == PROFILE_REGISTER else "orchestration-declaration"
    )
    if speech_act != expected_speech:
        raise RuntimeError(
            f"Profile/speechAct mismatch: profile={profile} claim.speechAct={speech_act}."
        )

    has_synthesis = "synthesis" in loaded and loaded["synthesis"] is not None
    if profile == PROFILE_REGISTER and has_synthesis:
        raise RuntimeError("register profile MUST NOT contain synthesis section.")
    if profile == PROFILE_SEAL and not has_synthesis:
        raise RuntimeError("seal profile MUST contain synthesis section.")


def _build_claim_statements_block(att: AuthorAttestation) -> str:
    lines = ["  statements:\n"]
    for index, qa in enumerate(att.attestations, start=1):
        q_block = _yaml_literal_block(qa.question, indent=8)
        lines.append(f"    - id: {index}\n")
        lines.append(f"      question: |-\n{q_block}\n")
        lines.append(f"      answer: {_yaml_quoted(qa.answer)}\n")
    return "".join(lines)


def _render_signature_block_yaml(
    block: SignatureBlock,
    *,
    indent: int,
) -> str:
    """Render one SignatureBlock as a YAML mapping at the given indent.

    The signature bytes are rendered as a literal block (``|``) with wrapped
    lines, matching the v2 wire format's conventions.
    """
    pad = " " * indent
    sig_lines = _wrap_signature_lines(block.cryptographic_signature)
    sig_yaml = "\n".join(f"{pad}  {line}" for line in sig_lines)
    canon_line = (
        f"{pad}canonicalization: {_yaml_quoted(block.payload_canonicalization)}\n"
        if block.payload_canonicalization
        else ""
    )
    return (
        f"{pad}algorithm: {_yaml_quoted(block.crypto_algorithm)}\n"
        f"{pad}signerFingerprint: {_yaml_quoted(block.verification_anchor.signer_fingerprint)}\n"
        f"{pad}artifactHash: {_yaml_quoted(block.artifact_hash)}\n"
        + canon_line
        + f"{pad}signature: |\n"
        f"{sig_yaml}\n"
    )


def _render_operator_seals_block(
    artifact: Artifact,
    primary_sealer_sig: SignatureBlock,
    hybrid_sealer_sig: SignatureBlock | None,
    *,
    rc: RegistrationCeremony,
    pseudonym: str,
    strength: str,
    webauthn_block: str,
) -> str:
    """Render the ``operatorSeals:`` YAML block (v3 Gap 2, Option A).

    Every seal — sealer and witnesses — has identical anatomy: pseudonymHash,
    role, sealedAt, ceremony, webauthn, attestationStrength, primary, hybrid.
    The block is the only place signatures appear in the envelope; the
    ``integrity`` block no longer carries a ``signatures:`` list.

    The resolved ``rc`` / ``pseudonym`` / ``strength`` / ``webauthn_block``
    are used for the *sealer* seal (index 0 with role=sealer) — they carry the
    fallback logic for legacy fixtures that lack ceremony on the seal itself.
    Witness seals (role=witness) render from their own self-contained fields.
    """
    lines = ["operatorSeals:"]
    for idx, seal in enumerate(artifact.operator_seals):
        is_sealer = seal.role == "sealer" or idx == 0
        seal_ceremony = seal.ceremony if seal.ceremony is not None and is_sealer else (
            rc if is_sealer else seal.ceremony
        )
        seal_pseudonym = (
            (seal.operator_pseudonym_hash or pseudonym) if is_sealer else seal.operator_pseudonym_hash
        )
        seal_strength = (
            (seal.attestation_strength or strength) if is_sealer else seal.attestation_strength
        )
        # For the sealer, prefer the resolved webauthn_block (string) — we
        # render it directly. Witnesses render from seal.webauthn_attestation.
        lines.append(
            f"  - operatorPseudonymHash: {_yaml_quoted(seal_pseudonym or '')}"
        )
        lines.append(f"    role: {_yaml_quoted(seal.role)}")
        lines.append(f"    sealedAt: {_yaml_quoted(seal.sealed_at)}")
        if seal_ceremony is not None:
            lines.append("    ceremony:")
            lines.append(
                f"      registeredAt: {_yaml_quoted(_ms_to_iso(seal_ceremony.registration_utc_ms))}"
            )
            lines.append(
                f"      orchestratorCommit: {_yaml_quoted(seal_ceremony.orchestrator_git_commit)}"
            )
        if is_sealer and webauthn_block:
            # webauthn_block is pre-indented ("    webauthn:\n      ...") for the
            # old operator: layout. Re-indent to match the operatorSeals layout
            # (6 spaces for the inner block). The block already starts with two
            # spaces; we need four more to nest under "  - ".
            for wa_line in webauthn_block.splitlines():
                lines.append(f"  {wa_line}")
        else:
            seal_wa = seal.webauthn_attestation
            if seal_wa is not None:
                lines.append("    webauthn:")
                lines.append(f"      credentialId: {_yaml_quoted(seal_wa.credential_id)}")
                lines.append(f"      clientDataJson: {_yaml_quoted(seal_wa.client_data_json)}")
                lines.append(f"      clientDataJsonHash: {_yaml_quoted(seal_wa.client_data_json_hash)}")
                lines.append(f"      authenticatorData: {_yaml_quoted(seal_wa.authenticator_data)}")
                lines.append(f"      signature: {_yaml_quoted(seal_wa.signature)}")
                lines.append(f"      fmt: {_yaml_quoted(seal_wa.fmt)}")
        if seal_strength is not None:
            lines.append(f"    attestationStrength: {_yaml_quoted(seal_strength)}")
        lines.append("    primary:")
        lines.append(_render_signature_block_yaml(seal.primary, indent=6))
        if seal.hybrid is not None:
            lines.append("    hybrid:")
            lines.append(_render_signature_block_yaml(seal.hybrid, indent=6))
    return "\n".join(lines) + "\n"


def render_artifact_markdown_v2(
    artifact: Artifact,
    body: str,
    *,
    ledger_request_id: str,
    sidecars: EnvelopeSidecars | None = None,
    env_path: Any = None,
) -> str:
    """Render eternity.v2 enterprise frontmatter + body."""

    if artifact.signature is None:
        raise RuntimeError("Signed artifact envelope is missing signature block.")

    profile = profile_for_source(artifact.provenance.source)
    sig = artifact.signature
    sidecars = sidecars or EnvelopeSidecars()
    tsa_provider = sidecars.tsa_provider or read_env_optional("RFC3161_TSA_URL", env_path=env_path)

    att = artifact.provenance.author_attestation
    if att is None:
        raise RuntimeError("v2 envelope requires author attestation in claim.")

    # v3 (Gap 2): ceremony / webauthn / attestation_strength live on the sealer's
    # OperatorSeal now. Fall back to Provenance for legacy callers that haven't
    # migrated yet (the model_validator maps old singular signatures into a
    # sealer OperatorSeal, so this fallback is mostly defensive).
    sealer_seal = next(
        (s for s in artifact.operator_seals if s.role == "sealer"),
        artifact.operator_seals[0] if artifact.operator_seals else None,
    )
    rc = sealer_seal.ceremony if sealer_seal is not None else None
    # v3: ceremony is normally set by register/seal via the notary. If absent
    # (test fixtures, legacy), we DON'T synthesize a placeholder — we render
    # only what's actually on the seal, so round-trip signing hashes stay
    # stable. The real register/seal path always sets ceremony.

    pseudonym = (
        sealer_seal.operator_pseudonym_hash
        if sealer_seal is not None and sealer_seal.operator_pseudonym_hash
        else ""
    )
    strength = (
        sealer_seal.attestation_strength
        if sealer_seal is not None
        else None
    )

    wa = sealer_seal.webauthn_attestation if sealer_seal is not None else None
    webauthn_block = ""
    if wa is not None:
        webauthn_block = (
            "  webauthn:\n"
            f"    credentialId: {_yaml_quoted(wa.credential_id)}\n"
            f"    clientDataJson: {_yaml_quoted(wa.client_data_json)}\n"
            f"    clientDataJsonHash: {_yaml_quoted(wa.client_data_json_hash)}\n"
            f"    authenticatorData: {_yaml_quoted(wa.authenticator_data)}\n"
            f"    signature: {_yaml_quoted(wa.signature)}\n"
            f"    fmt: {_yaml_quoted(wa.fmt)}\n"
        )

    classification_line = ""
    if att.attestation_mode == "interactive":
        classification_line = f"  classification: {_yaml_quoted(att.classification or 'fiction')}\n"
    claim_block = (
        "claim:\n"
        f"  speechAct: {_yaml_quoted(att.attestation_nature)}\n"
        f"  provenanceGrade: {_yaml_quoted(artifact.provenance.provenance_grade or 'declared')}\n"
        f"  source: {_yaml_quoted(artifact.provenance.source)}\n"
        f"{classification_line}"
        f"  mode: {_yaml_quoted(att.attestation_mode)}\n"
        f"{_build_claim_statements_block(att)}"
    )

    synthesis_block = ""
    if profile == PROFILE_SEAL:
        pn_hash = artifact.provenance.process_narrative_hash
        pn_sidecar = sidecars.process_narrative or (
            f"{ledger_request_id}.process.json" if pn_hash else None
        )
        models_lines = ""
        if artifact.provenance.models_used:
            models_lines = "  modelsUsed:\n"
            for model in artifact.provenance.models_used:
                models_lines += f"    - {_yaml_quoted(model)}\n"
        process_block = ""
        if pn_hash and pn_sidecar:
            process_block = (
                "  processNarrative:\n"
                f"    sidecar: {_yaml_quoted(pn_sidecar)}\n"
                f"    contentHash: {_yaml_quoted(pn_hash)}\n"
                "    verified: false\n"
                f"    disclaimer: {_yaml_quoted(_PROCESS_NARRATIVE_DISCLAIMER)}\n"
            )
        synthesis_block = (
            "synthesis:\n"
            f"  modelId: {_yaml_quoted(artifact.provenance.model_id)}\n"
            f"{models_lines}"
            f"{process_block}"
        )

    # v3 (Gap 2): signature rendering moved into _render_operator_seals_block
    # (each seal carries its own primary + hybrid signatures). The integrity
    # block carries only payloadHash, canonicalization, timestamps, sidecars.

    timestamps_yaml = ""
    if sig.rfc3161_token and sig.rfc3161_token.strip():
        token_lines = _wrap_signature_lines(sig.rfc3161_token)
        token_yaml = "\n".join(f"        {line}" for line in token_lines)
        provider = tsa_provider or "http://timestamp.digicert.com"
        timestamps_yaml = (
            "  timestamps:\n"
            "    - kind: rfc3161\n"
            f"      provider: {_yaml_quoted(provider)}\n"
            "      token: |\n"
            f"{token_yaml}\n"
        )

    sidecars_yaml = "  sidecars:\n"
    c2pa_name = sidecars.c2pa or f"{ledger_request_id}.c2pa"
    sidecars_yaml += f"    c2pa: {_yaml_quoted(c2pa_name)}\n"
    if sidecars.process_narrative:
        sidecars_yaml += f"    processNarrative: {_yaml_quoted(sidecars.process_narrative)}\n"
    if sidecars.ots:
        sidecars_yaml += f"    ots: {_yaml_quoted(sidecars.ots)}\n"

    policy_id = str(artifact.license)
    rights_holder = artifact.rights_holder
    rights_notice, rights_statement = _rights_block(policy_id, holder=rights_holder)
    stored_body = (
        canonicalize_body(body)
        if sig.payload_canonicalization == CANONICALIZATION_VERSION
        else body
    )

    return (
        "---\n"
        "antiphoria:\n"
        f"  schemaVersion: {_yaml_quoted(SCHEMA_VERSION_V2)}\n"
        f"  profile: {_yaml_quoted(profile)}\n"
        f"  pipelineVersion: {_yaml_quoted(artifact.provenance.engine_version)}\n"
        f"  ledgerRequestId: {_yaml_quoted(ledger_request_id)}\n"
        "document:\n"
        f"  artifactId: {_yaml_quoted(str(artifact.id))}\n"
        f"  title: {_yaml_quoted(artifact.title)}\n"
        f"  createdAt: {_yaml_quoted(artifact.timestamp.astimezone(UTC).isoformat())}\n"
        f"  contentType: {_yaml_quoted(artifact.content_type)}\n"
        + (
            # v3 (Gap 1): revision block lives between document and rights.
            # Absent on first version of a work; present on every supersession.
            "revision:\n"
            f"  chainRoot: {_yaml_quoted(artifact.revision.chain_root)}\n"
            f"  sequence: {artifact.revision.sequence}\n"
            f"  supersedes: {_yaml_quoted(artifact.revision.supersedes)}\n"
            f"  supersedesHash: {_yaml_quoted(artifact.revision.supersedes_hash)}\n"
            f"  reason: {_yaml_quoted(artifact.revision.reason)}\n"
            + (
                f"  note: {_yaml_quoted(artifact.revision.note)}\n"
                if artifact.revision.note
                else ""
            )
            if artifact.revision is not None
            else ""
        )
        + "rights:\n"
        f"  policyId: {_yaml_quoted(policy_id)}\n"
        + (f"  holder: {_yaml_quoted(rights_holder)}\n" if rights_holder else "")
        + f"  notice: {_yaml_quoted(rights_notice)}\n"
        f"  statement: {_yaml_quoted(rights_statement)}\n"
        + _render_operator_seals_block(
            artifact,
            sig,
            artifact.hybrid_signature,
            rc=rc,
            pseudonym=pseudonym,
            strength=strength,
            webauthn_block=webauthn_block,
        )
        + f"{claim_block}"
        f"{synthesis_block}"
        "integrity:\n"
        f"  payloadHash: {_yaml_quoted(sig.artifact_hash)}\n"
        f"  canonicalization: {_yaml_quoted(sig.payload_canonicalization or CANONICALIZATION_VERSION)}\n"
        f"{timestamps_yaml}"
        f"{sidecars_yaml}"
        "---\n"
        f"{stored_body}\n"
    )


def _parse_signatures(integrity: dict[str, Any]) -> tuple[SignatureBlock | None, SignatureBlock | None]:
    """Parse primary + hybrid signatures from the legacy ``integrity.signatures``
    list. v3 envelopes carry signatures in ``operatorSeals`` instead — when
    that's the case, ``integrity.signatures`` is absent and this returns
    ``(None, None)``. The caller then builds seals from ``operatorSeals``.
    """
    signatures = integrity.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return None, None

    primary: SignatureBlock | None = None
    hybrid: SignatureBlock | None = None
    rfc3161_token: str | None = None

    timestamps = integrity.get("timestamps")
    if isinstance(timestamps, list):
        for entry in timestamps:
            if not isinstance(entry, dict):
                continue
            if entry.get("kind") == "rfc3161":
                token = entry.get("token")
                if isinstance(token, str) and token.strip():
                    rfc3161_token = "".join(token.split())

    canon = integrity.get("canonicalization") or CANONICALIZATION_VERSION
    payload_hash = integrity.get("payloadHash")
    if not isinstance(payload_hash, str):
        raise RuntimeError("integrity.payloadHash is required.")

    for entry in signatures:
        if not isinstance(entry, dict):
            raise RuntimeError("integrity.signatures entries must be objects.")
        tier = entry.get("tier")
        algorithm = entry.get("algorithm")
        fingerprint = entry.get("signerFingerprint")
        signature = entry.get("signature")
        if not isinstance(algorithm, str) or not isinstance(fingerprint, str):
            raise RuntimeError("Signature entry missing algorithm or signerFingerprint.")
        if not isinstance(signature, str) or not signature.strip():
            raise RuntimeError("Signature entry missing signature bytes.")

        sig_block = SignatureBlock(
            cryptoAlgorithm=algorithm,
            artifactHash=payload_hash,
            cryptographicSignature="".join(signature.split()),
            verificationAnchor=VerificationAnchor(signerFingerprint=fingerprint),
            payloadCanonicalization=canon,
        )
        if tier == "primary":
            if rfc3161_token is not None:
                sig_block = sig_block.model_copy(update={"rfc3161_token": rfc3161_token})
            primary = sig_block
        elif tier == "hybrid":
            hybrid = sig_block
        else:
            raise RuntimeError(f"Unknown signature tier '{tier}'.")

    if primary is None:
        raise RuntimeError("integrity.signatures must include tier primary.")
    return primary, hybrid


def _signature_block_from_seal_dict(
    block_raw: dict[str, Any],
    *,
    default_payload_hash: str,
    default_canon: str | None,
) -> SignatureBlock:
    """Build a SignatureBlock from one ``primary:``/``hybrid:`` dict in an
    operatorSeals entry. The dict mirrors the legacy integrity.signatures shape
    (algorithm, signerFingerprint, signature, optional artifactHash/canonicalization).
    """
    algorithm = str(block_raw.get("algorithm", ""))
    fingerprint = str(block_raw.get("signerFingerprint", ""))
    signature_b64 = "".join(str(block_raw.get("signature", "")).split())
    artifact_hash = str(block_raw.get("artifactHash") or default_payload_hash)
    canon = block_raw.get("canonicalization") or default_canon
    return SignatureBlock(
        cryptoAlgorithm=algorithm,
        artifactHash=artifact_hash,
        cryptographicSignature=signature_b64,
        verificationAnchor=VerificationAnchor(signerFingerprint=fingerprint),
        payloadCanonicalization=canon,
    )


def _operator_seal_from_loaded(seal_raw: dict[str, Any]) -> OperatorSeal:
    """Build an OperatorSeal from one parsed ``operatorSeals:`` entry."""

    primary_raw = seal_raw.get("primary")
    if not isinstance(primary_raw, dict):
        raise RuntimeError("operatorSeals entry missing primary signature block.")
    # Default artifactHash/canonicalization come from the primary block if present,
    # otherwise empty/None — the caller typically supplies them via the integrity
    # block when falling back from the legacy shape.
    default_hash = str(primary_raw.get("artifactHash", ""))
    default_canon = primary_raw.get("canonicalization")
    primary = _signature_block_from_seal_dict(
        primary_raw,
        default_payload_hash=default_hash,
        default_canon=default_canon,
    )
    hybrid: SignatureBlock | None = None
    hybrid_raw = seal_raw.get("hybrid")
    if isinstance(hybrid_raw, dict):
        hybrid = _signature_block_from_seal_dict(
            hybrid_raw,
            default_payload_hash=default_hash,
            default_canon=default_canon,
        )

    # Ceremony
    ceremony_raw = seal_raw.get("ceremony")
    ceremony: RegistrationCeremony | None = None
    if isinstance(ceremony_raw, dict):
        registered_at = ceremony_raw.get("registeredAt")
        raw_pseudonym = seal_raw.get("operatorPseudonymHash")
        # Empty string → None (the pattern rejects ""). Honest "no pseudonym."
        if isinstance(raw_pseudonym, str) and not raw_pseudonym.strip():
            raw_pseudonym = None
        ceremony = RegistrationCeremony(
            registrationUtcMs=(
                _iso_to_ms(str(registered_at)) if isinstance(registered_at, str) else 0
            ),
            orchestratorGitCommit=str(ceremony_raw.get("orchestratorCommit", "")) or "unknown",
            operatorPseudonymHash=raw_pseudonym,
        )

    # WebAuthn
    webauthn: WebAuthnAttestation | None = None
    wa_raw = seal_raw.get("webauthn")
    if isinstance(wa_raw, dict):
        cred_id = wa_raw.get("credentialId")
        client_json = wa_raw.get("clientDataJson")
        client_hash = wa_raw.get("clientDataJsonHash")
        auth_data = wa_raw.get("authenticatorData")
        signature = wa_raw.get("signature")
        fmt = wa_raw.get("fmt")
        # v3 (Flaw A): clientDataJson required for real verification. Legacy v2
        # artifacts lack it — those parse with webauthn=None (honest skip).
        if client_json and all(
            isinstance(v, str) and v
            for v in (cred_id, client_hash, auth_data, signature, fmt)
        ):
            webauthn = WebAuthnAttestation(
                credentialId=cred_id,
                clientDataJson=client_json,
                clientDataJsonHash=client_hash,
                authenticatorData=auth_data,
                signature=signature,
                fmt=fmt,
            )

    strength = seal_raw.get("attestationStrength")
    if not isinstance(strength, str):
        strength = None

    seal_pseudonym = seal_raw.get("operatorPseudonymHash")
    if isinstance(seal_pseudonym, str) and not seal_pseudonym.strip():
        seal_pseudonym = None

    return OperatorSeal(
        operatorPseudonymHash=seal_pseudonym,
        role=str(seal_raw.get("role", "sealer")),  # type: ignore[arg-type]
        sealedAt=str(seal_raw.get("sealedAt", "")) or "unknown",
        ceremony=ceremony,
        webauthn=webauthn,
        attestationStrength=strength,  # type: ignore[arg-type]
        primary=primary,
        hybrid=hybrid,
    )


def _legacy_sealer_seal_from_operator(
    operator: dict[str, Any],
    primary_sig: SignatureBlock,
    hybrid_sig: SignatureBlock | None,
) -> OperatorSeal:
    """Build a single ``role="sealer"`` OperatorSeal from legacy v2 operator +
    integrity.signatures data. Used when an envelope has no ``operatorSeals:``
    block (legacy v2 artifacts grandfathered into v3)."""

    ceremony_raw = operator.get("ceremony")
    ceremony: RegistrationCeremony | None = None
    if isinstance(ceremony_raw, dict):
        registered_at = ceremony_raw.get("registeredAt")
        raw_pseudonym = operator.get("pseudonymHash")
        if isinstance(raw_pseudonym, str) and not raw_pseudonym.strip():
            raw_pseudonym = None
        ceremony = RegistrationCeremony(
            registrationUtcMs=(
                _iso_to_ms(str(registered_at)) if isinstance(registered_at, str) else 0
            ),
            orchestratorGitCommit=str(ceremony_raw.get("orchestratorCommit", "")) or "unknown",
            operatorPseudonymHash=raw_pseudonym,
        )

    # Legacy webauthn block (may lack clientDataJson — handled in parser).
    webauthn: WebAuthnAttestation | None = None
    wa_raw = operator.get("webauthn")
    if isinstance(wa_raw, dict):
        cred_id = wa_raw.get("credentialId")
        client_json = wa_raw.get("clientDataJson")
        client_hash = wa_raw.get("clientDataJsonHash")
        auth_data = wa_raw.get("authenticatorData")
        signature = wa_raw.get("signature")
        fmt = wa_raw.get("fmt")
        if client_json and all(
            isinstance(v, str) and v
            for v in (cred_id, client_hash, auth_data, signature, fmt)
        ):
            webauthn = WebAuthnAttestation(
                credentialId=cred_id,
                clientDataJson=client_json,
                clientDataJsonHash=client_hash,
                authenticatorData=auth_data,
                signature=signature,
                fmt=fmt,
            )

    strength = operator.get("attestationStrength")
    if not isinstance(strength, str):
        strength = None

    legacy_pseudonym = operator.get("pseudonymHash")
    if isinstance(legacy_pseudonym, str) and not legacy_pseudonym.strip():
        legacy_pseudonym = None

    return OperatorSeal(
        operatorPseudonymHash=legacy_pseudonym,
        role="sealer",
        sealedAt=str(ceremony_raw.get("registeredAt", "")) if isinstance(ceremony_raw, dict) else "" or "unknown",
        ceremony=ceremony,
        webauthn=webauthn,
        attestationStrength=strength,  # type: ignore[arg-type]
        primary=primary_sig,
        hybrid=hybrid_sig,
    )


def _artifact_from_v2_loaded(loaded: dict[str, Any]) -> Artifact:
    _validate_v2_invariants(loaded)

    document = loaded["document"]
    rights = loaded["rights"]
    # v3 (Gap 2): operator block is optional — superseded by operatorSeals.
    # Legacy v2 envelopes still carry it; v3 envelopes don't.
    operator = loaded.get("operator") or {}
    claim = loaded["claim"]
    integrity = loaded["integrity"]

    profile = loaded["antiphoria"]["profile"]
    source = source_for_profile(str(profile))

    attestations_raw = claim.get("statements") or []
    qa_list: list[AttestationQa] = []
    if isinstance(attestations_raw, list):
        for item in attestations_raw:
            if not isinstance(item, dict):
                continue
            question = item.get("question")
            answer = item.get("answer")
            if isinstance(question, str) and isinstance(answer, str):
                qa_list.append(AttestationQa(question=question, answer=answer))

    attestation_mode = claim.get("mode", "interactive")
    classification = claim.get("classification") if attestation_mode == "interactive" else None
    author_attestation = AuthorAttestation(
        attestationNature=claim["speechAct"],
        attestationMode=attestation_mode,
        classification=classification,
        attestations=qa_list if attestation_mode == "interactive" else [],
    )

    ceremony = operator.get("ceremony") or {}
    registered_at = ceremony.get("registeredAt")
    registration_ms = (
        _iso_to_ms(str(registered_at))
        if isinstance(registered_at, str)
        else int(ceremony.get("registrationUtcMs", 0))
    )
    # Coerce empty/whitespace pseudonymHash to None — the renderer emits "" when
    # the operator has no pseudonym salt configured, but the model field's strict
    # pattern (^[a-f0-9]{64}$) rejects empty strings. None is the honest value.
    raw_pseudonym_hash = operator.get("pseudonymHash")
    if isinstance(raw_pseudonym_hash, str) and not raw_pseudonym_hash.strip():
        raw_pseudonym_hash = None
    registration_ceremony = RegistrationCeremony(
        registrationUtcMs=registration_ms,
        orchestratorGitCommit=str(ceremony.get("orchestratorCommit", "")) or "unknown",
        operatorPseudonymHash=raw_pseudonym_hash,
    )

    webauthn_attestation: WebAuthnAttestation | None = None
    webauthn_raw = operator.get("webauthn")
    if isinstance(webauthn_raw, dict):
        cred_id = webauthn_raw.get("credentialId")
        client_json = webauthn_raw.get("clientDataJson")
        client_hash = webauthn_raw.get("clientDataJsonHash")
        auth_data = webauthn_raw.get("authenticatorData")
        signature = webauthn_raw.get("signature")
        fmt = webauthn_raw.get("fmt")
        # v3 (Flaw A): clientDataJson is required for verification. Legacy v2
        # artifacts don't carry it — those parse but cannot be cryptographically
        # verified (honest "captured-unverified" state).
        if client_json and all(
            isinstance(v, str) and v
            for v in (cred_id, client_hash, auth_data, signature, fmt)
        ):
            webauthn_attestation = WebAuthnAttestation(
                credentialId=cred_id,
                clientDataJson=client_json,
                clientDataJsonHash=client_hash,
                authenticatorData=auth_data,
                signature=signature,
                fmt=fmt,
            )

    raw_strength = operator.get("attestationStrength")
    if raw_strength == "legacy":
        raw_strength = "none"

    models_used = None
    process_hash = None
    model_id = "human" if source == "human" else "composite"
    synthesis = loaded.get("synthesis")
    if isinstance(synthesis, dict):
        model_id = str(synthesis.get("modelId") or model_id)
        raw_models = synthesis.get("modelsUsed")
        if isinstance(raw_models, list):
            models_used = [str(m) for m in raw_models]
        pn = synthesis.get("processNarrative")
        if isinstance(pn, dict):
            process_hash = pn.get("contentHash")

    primary_sig, hybrid_sig = _parse_signatures(integrity)

    # v3 (Gap 2): prefer the operatorSeals block; fall back to building a single
    # sealer seal from the legacy operator + integrity.signatures shape.
    operator_seals_raw = loaded.get("operatorSeals")
    parsed_seals: list[OperatorSeal] = []
    if isinstance(operator_seals_raw, list):
        for seal_raw in operator_seals_raw:
            if not isinstance(seal_raw, dict):
                continue
            parsed_seals.append(_operator_seal_from_loaded(seal_raw))

    # Legacy fallback: build a sealer seal from operator + integrity.signatures.
    # Only fires when no operatorSeals block was present AND primary_sig parsed.
    if not parsed_seals and primary_sig is not None:
        parsed_seals.append(
            _legacy_sealer_seal_from_operator(
                operator=operator,
                primary_sig=primary_sig,
                hybrid_sig=hybrid_sig,
            )
        )

    # v3 (Gap 1): optional revision block between document and rights.
    revision_raw = loaded.get("revision")
    revision_obj: Revision | None = None
    if isinstance(revision_raw, dict):
        rev_sequence = revision_raw.get("sequence")
        if not isinstance(rev_sequence, int) or rev_sequence < 2:
            raise RuntimeError(
                f"Invalid revision.sequence '{rev_sequence}'. Must be an integer >= 2."
            )
        revision_obj = Revision(
            chainRoot=str(revision_raw["chainRoot"]),
            sequence=rev_sequence,
            supersedes=str(revision_raw["supersedes"]),
            supersedesHash=str(revision_raw["supersedesHash"]),
            reason=str(revision_raw["reason"]),
            note=(
                None
                if revision_raw.get("note") is None
                else str(revision_raw["note"])
            ),
        )

    return Artifact(
        id=document["artifactId"],
        title=document["title"],
        timestamp=document["createdAt"],
        contentType=document.get("contentType", "text/markdown"),
        license=rights.get("policyId", "ARR"),
        rights_holder=rights.get("holder") if isinstance(rights.get("holder"), str) else None,
        revision=revision_obj,
        provenance=Provenance(
            source=source,
            engineVersion=loaded["antiphoria"].get(
                "pipelineVersion", "antiphoria-slop-provenance-v1.0.0"
            ),
            modelId=model_id,
            generationContext=generation_context_for_source(source),
            authorAttestation=author_attestation,
            provenanceGrade=claim.get("provenanceGrade"),
            modelsUsed=models_used,
            processNarrativeHash=process_hash,
        ),
        operatorSeals=parsed_seals,
    )


def parse_artifact_markdown_text_v2(text: str) -> tuple[Artifact, str]:
    """Parse eternity.v2 frontmatter into internal Artifact + body."""

    if "\x00" in text:
        raise RuntimeError("Artifact contains null bytes; invalid payload.")
    if not text.startswith("---\n"):
        raise RuntimeError("Artifact file is missing YAML frontmatter delimiter.")
    delimiter_index = text.find("\n---\n", 4)
    if delimiter_index == -1:
        raise RuntimeError("Artifact file has malformed YAML frontmatter.")
    frontmatter_text = text[4:delimiter_index]
    if re.search(r"&\w", frontmatter_text) or re.search(r"\*\w", frontmatter_text):
        raise RuntimeError("YAML frontmatter contains anchors or aliases; rejected for security.")
    payload_text = text[delimiter_index + len("\n---\n") :]
    payload = payload_text.strip()
    if not payload:
        raise RuntimeError("Artifact payload is empty after metadata stripping.")
    loaded: Any = yaml.safe_load(frontmatter_text)
    if not isinstance(loaded, dict):
        raise RuntimeError("Frontmatter YAML did not decode to an object.")
    try:
        envelope = _artifact_from_v2_loaded(loaded)
    except Exception as exc:
        raise RuntimeError(f"Failed to parse Eternity v2 envelope: {exc}") from exc
    return envelope, payload


def render_artifact_markdown_wire(
    artifact: Artifact,
    body: str,
    *,
    ledger_request_id: str,
    sidecars: EnvelopeSidecars | None = None,
    env_path: Any = None,
    wire_version: str | None = None,  # noqa: ARG001 — retained for API compat
) -> str:
    """Render artifact markdown. v3: always emits the v3 wire format.

    The ``wire_version`` argument is accepted but ignored — v1 wire rendering
    was removed in v3 (pre-release.md §1). Legacy v1/v2 artifacts remain
    *parseable* (see ``parse_artifact_markdown_text``) but new seals always
    emit the antiphoria enterprise layout (``eternity.v3`` schema label).
    """

    return render_artifact_markdown_v2(
        artifact,
        body,
        ledger_request_id=ledger_request_id,
        sidecars=sidecars,
        env_path=env_path,
    )
