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
    Provenance,
    RegistrationCeremony,
    SignatureBlock,
    VerificationAnchor,
    WebAuthnAttestation,
)
from src.policies.license_text import resolve_license_text

SCHEMA_VERSION_V2 = "eternity.v2"
PROFILE_REGISTER = "antiphoria.register.v1"
PROFILE_SEAL = "antiphoria.seal.v1"

_ALLOWED_TOP_LEVEL = frozenset(
    {"antiphoria", "document", "rights", "operator", "claim", "synthesis", "integrity"}
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


def resolve_envelope_wire_version(env_path: Any = None) -> str:
    raw = read_env_optional("ENVELOPE_WIRE_VERSION", env_path=env_path)
    if raw is None or raw.strip() == "":
        return "v2"
    version = raw.strip().lower()
    if version not in ("v1", "v2"):
        raise RuntimeError(f"Invalid ENVELOPE_WIRE_VERSION '{raw}'. Expected 'v1' or 'v2'.")
    return version


def resolve_wire_version_for_artifact(
    artifact: Artifact,
    *,
    env_path: Any = None,
    wire_version: str | None = None,
) -> str:
    """Pick v1 or v2 wire codec for an artifact.

    Register/seal artifacts carry author attestation and ceremony metadata;
    legacy generate/curate envelopes stay on v1 unless forced via env.
    """

    if wire_version is not None:
        return wire_version
    configured = resolve_envelope_wire_version(env_path)
    if configured == "v1":
        return "v1"
    prov = artifact.provenance
    if prov.author_attestation is not None and prov.registration_ceremony is not None:
        return "v2"
    return "v1"


def is_v2_wire_format(text: str) -> bool:
    """Return True when frontmatter uses eternity.v2 enterprise layout."""

    if not text.startswith("---\n"):
        return False
    delimiter_index = text.find("\n---\n", 4)
    if delimiter_index == -1:
        return False
    frontmatter = text[4:delimiter_index]
    if (
        'schemaVersion: "eternity.v2"' in frontmatter
        or "schemaVersion: 'eternity.v2'" in frontmatter
    ):
        return True
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


def _rights_block(policy_id: str) -> tuple[str, str]:
    text = resolve_license_text(policy_id)
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
    if schema != SCHEMA_VERSION_V2:
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

    rc = artifact.provenance.registration_ceremony
    if rc is None:
        raise RuntimeError("v2 envelope requires operator ceremony metadata.")

    pseudonym = rc.operator_pseudonym_hash or ""
    strength = artifact.provenance.attestation_strength or "none"
    registered_at = _ms_to_iso(rc.registration_utc_ms)

    webauthn_block = ""
    wa = artifact.provenance.webauthn_attestation
    if wa is not None:
        webauthn_block = (
            "  webauthn:\n"
            f"    credentialId: {_yaml_quoted(wa.credential_id)}\n"
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

    primary_sig_lines = _wrap_signature_lines(sig.cryptographic_signature)
    primary_yaml = "\n".join(f"        {line}" for line in primary_sig_lines)
    signatures_yaml = (
        "  signatures:\n"
        "    - tier: primary\n"
        f"      algorithm: {_yaml_quoted(sig.crypto_algorithm)}\n"
        f"      signerFingerprint: {_yaml_quoted(sig.verification_anchor.signer_fingerprint)}\n"
        "      signature: |\n"
        f"{primary_yaml}\n"
    )
    if artifact.hybrid_signature is not None:
        hs = artifact.hybrid_signature
        hybrid_lines = _wrap_signature_lines(hs.cryptographic_signature)
        hybrid_yaml = "\n".join(f"        {line}" for line in hybrid_lines)
        signatures_yaml += (
            "    - tier: hybrid\n"
            f"      algorithm: {_yaml_quoted(hs.crypto_algorithm)}\n"
            f"      signerFingerprint: {_yaml_quoted(hs.verification_anchor.signer_fingerprint)}\n"
            "      signature: |\n"
            f"{hybrid_yaml}\n"
        )

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
    rights_notice, rights_statement = _rights_block(policy_id)
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
        "rights:\n"
        f"  policyId: {_yaml_quoted(policy_id)}\n"
        f"  notice: {_yaml_quoted(rights_notice)}\n"
        f"  statement: {_yaml_quoted(rights_statement)}\n"
        "operator:\n"
        f"  pseudonymHash: {_yaml_quoted(pseudonym)}\n"
        f"  attestationStrength: {_yaml_quoted(strength)}\n"
        "  ceremony:\n"
        f"    registeredAt: {_yaml_quoted(registered_at)}\n"
        f"    orchestratorCommit: {_yaml_quoted(rc.orchestrator_git_commit)}\n"
        f"{webauthn_block}"
        f"{claim_block}"
        f"{synthesis_block}"
        "integrity:\n"
        f"  payloadHash: {_yaml_quoted(sig.artifact_hash)}\n"
        f"  canonicalization: {_yaml_quoted(sig.payload_canonicalization or CANONICALIZATION_VERSION)}\n"
        f"{signatures_yaml}"
        f"{timestamps_yaml}"
        f"{sidecars_yaml}"
        "---\n"
        f"{stored_body}\n"
    )


def _parse_signatures(integrity: dict[str, Any]) -> tuple[SignatureBlock, SignatureBlock | None]:
    signatures = integrity.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise RuntimeError("integrity.signatures must be a non-empty list.")

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


def _artifact_from_v2_loaded(loaded: dict[str, Any]) -> Artifact:
    _validate_v2_invariants(loaded)

    document = loaded["document"]
    rights = loaded["rights"]
    operator = loaded["operator"]
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
    registration_ceremony = RegistrationCeremony(
        registrationUtcMs=registration_ms,
        orchestratorGitCommit=str(ceremony.get("orchestratorCommit", "")),
        operatorPseudonymHash=operator.get("pseudonymHash"),
    )

    webauthn_attestation: WebAuthnAttestation | None = None
    webauthn_raw = operator.get("webauthn")
    if isinstance(webauthn_raw, dict):
        cred_id = webauthn_raw.get("credentialId")
        client_hash = webauthn_raw.get("clientDataJsonHash")
        auth_data = webauthn_raw.get("authenticatorData")
        signature = webauthn_raw.get("signature")
        fmt = webauthn_raw.get("fmt")
        if all(isinstance(v, str) and v for v in (cred_id, client_hash, auth_data, signature, fmt)):
            webauthn_attestation = WebAuthnAttestation(
                credentialId=cred_id,
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

    return Artifact(
        id=document["artifactId"],
        title=document["title"],
        timestamp=document["createdAt"],
        contentType=document.get("contentType", "text/markdown"),
        license=rights.get("policyId", "ARR"),
        provenance=Provenance(
            source=source,
            engineVersion=loaded["antiphoria"].get(
                "pipelineVersion", "antiphoria-slop-provenance-v1.0.0"
            ),
            modelId=model_id,
            generationContext=generation_context_for_source(source),
            authorAttestation=author_attestation,
            webauthnAttestation=webauthn_attestation,
            attestationStrength=raw_strength,
            registrationCeremony=registration_ceremony,
            provenanceGrade=claim.get("provenanceGrade"),
            modelsUsed=models_used,
            processNarrativeHash=process_hash,
        ),
        signature=primary_sig,
        hybridSignature=hybrid_sig,
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
    wire_version: str | None = None,
) -> str:
    """Render artifact markdown using configured or explicit wire version."""

    version = resolve_wire_version_for_artifact(
        artifact,
        env_path=env_path,
        wire_version=wire_version,
    )
    if version == "v2":
        return render_artifact_markdown_v2(
            artifact,
            body,
            ledger_request_id=ledger_request_id,
            sidecars=sidecars,
            env_path=env_path,
        )
    if version == "v1":
        from src.artifact_serialization import render_artifact_markdown

        return render_artifact_markdown(artifact, body)
    raise RuntimeError(f"Unsupported wire version '{version}'.")
