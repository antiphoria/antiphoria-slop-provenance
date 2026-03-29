"""Pure frontmatter artifact serialization. No PEM footers."""

from __future__ import annotations

import json
import textwrap

from src.canonicalization import CANONICALIZATION_VERSION, canonicalize_body
from src.models import Artifact


def _wrap_signature_lines(signature_base64: str, line_width: int = 76) -> list[str]:
    """Normalize and wrap base64 signature text for YAML blocks."""
    condensed = "".join(signature_base64.split())
    if not condensed:
        raise RuntimeError("Artifact signature cannot be empty.")
    return textwrap.wrap(condensed, width=line_width)


def _yaml_quoted(value: str) -> str:
    """Render one YAML-safe quoted scalar using JSON escaping rules."""
    return json.dumps(value, ensure_ascii=False)


def _yaml_literal_block(text: str, indent: int) -> str:
    """Render text using YAML literal block scalar semantics."""
    prefix = " " * indent
    lines = text.splitlines() or [text]
    return "\n".join(f"{prefix}{line}" for line in lines)


def _hybrid_signature_block(artifact: Artifact) -> str:
    """Render hybridSignature YAML block when present."""
    if artifact.hybrid_signature is None:
        return ""
    hs = artifact.hybrid_signature
    lines = _wrap_signature_lines(hs.cryptographic_signature)
    yaml_lines = "\n".join(f"    {line}" for line in lines)
    return (
        "hybridSignature:\n"
        f"  cryptoAlgorithm: {_yaml_quoted(hs.crypto_algorithm)}\n"
        f"  artifactHash: {_yaml_quoted(hs.artifact_hash)}\n"
        "  verificationAnchor:\n"
        f"    signerFingerprint: {_yaml_quoted(hs.verification_anchor.signer_fingerprint)}\n"
        "  cryptographicSignature: |\n"
        f"{yaml_lines}\n"
    )


def _rfc3161_token_block(rfc3161_token: str | None) -> str:
    """Render rfc3161Token YAML block when present."""
    if not rfc3161_token or not rfc3161_token.strip():
        return ""
    lines = _wrap_signature_lines(rfc3161_token)
    yaml_lines = "\n".join(f"    {line}" for line in lines)
    return f"  rfc3161Token: |\n{yaml_lines}\n"


def render_artifact_markdown(artifact: Artifact, body: str) -> str:
    """Render artifact as pure frontmatter + body. No PEM footers."""
    if artifact.signature is None:
        raise RuntimeError("Signed artifact envelope is missing signature block.")

    sig = artifact.signature
    signature_lines = _wrap_signature_lines(sig.cryptographic_signature)
    signature_block_yaml = "\n".join(f"    {line}" for line in signature_lines)

    prompt_block_yaml = _yaml_literal_block(
        artifact.provenance.generation_context.prompt,
        indent=6,
    )
    system_instruction_yaml = _yaml_literal_block(
        artifact.provenance.generation_context.system_instruction,
        indent=6,
    )

    curation_block: str
    if artifact.curation is not None:
        diff_block = _yaml_literal_block(artifact.curation.unified_diff, indent=6)
        curation_block = (
            "curation:\n"
            f"  differenceScore: {artifact.curation.difference_score:.2f}\n"
            "  unifiedDiff: |-\n"
            f"{diff_block}\n"
        )
    else:
        curation_block = "curation: null\n"

    if artifact.provenance.usage_metrics is not None:
        usage = artifact.provenance.usage_metrics
        usage_block = (
            "  usageMetrics:\n"
            f"    promptTokens: {usage.prompt_tokens}\n"
            f"    completionTokens: {usage.completion_tokens}\n"
            f"    totalTokens: {usage.total_tokens}\n"
        )
    else:
        usage_block = "  usageMetrics: null\n"

    if artifact.provenance.embedded_watermark is not None:
        watermark = artifact.provenance.embedded_watermark
        watermark_block = (
            "  embeddedWatermark:\n"
            f"    provider: {_yaml_quoted(watermark.provider)}\n"
            f"    status: {_yaml_quoted(watermark.status)}\n"
        )
    else:
        watermark_block = "  embeddedWatermark: null\n"

    if artifact.provenance.author_attestation is not None:
        att = artifact.provenance.author_attestation
        attestation_lines = [
            "  authorAttestation:\n",
            f"    classification: {_yaml_quoted(att.classification)}\n",
            "    attestations:\n",
        ]
        for qa in att.attestations:
            q_block = _yaml_literal_block(qa.question, indent=10)
            attestation_lines.append(f"      - question: |-\n{q_block}\n")
            attestation_lines.append(f"        answer: {_yaml_quoted(qa.answer)}\n")
        attestation_block = "".join(attestation_lines)
    else:
        attestation_block = "  authorAttestation: null\n"

    if artifact.provenance.webauthn_attestation is not None:
        wa = artifact.provenance.webauthn_attestation
        webauthn_block = (
            "  webauthnAttestation:\n"
            f"    credentialId: {_yaml_quoted(wa.credential_id)}\n"
            f"    clientDataJsonHash: {_yaml_quoted(wa.client_data_json_hash)}\n"
            f"    authenticatorData: {_yaml_quoted(wa.authenticator_data)}\n"
            f"    signature: {_yaml_quoted(wa.signature)}\n"
            f"    fmt: {_yaml_quoted(wa.fmt)}\n"
        )
    else:
        webauthn_block = "  webauthnAttestation: null\n"

    if artifact.provenance.attestation_strength is not None:
        attestation_strength_line = (
            f"  attestationStrength: {_yaml_quoted(artifact.provenance.attestation_strength)}\n"
        )
    else:
        attestation_strength_line = "  attestationStrength: null\n"

    if artifact.provenance.registration_ceremony is not None:
        rc = artifact.provenance.registration_ceremony
        machine_line = (
            f"    machineIdHash: {_yaml_quoted(rc.machine_id_hash)}\n"
            if rc.machine_id_hash is not None
            else "    machineIdHash: null\n"
        )
        ceremony_block = (
            "  registrationCeremony:\n"
            f"    registrationUtcMs: {rc.registration_utc_ms}\n"
            f"    orchestratorGitCommit: {_yaml_quoted(rc.orchestrator_git_commit)}\n"
            f"{machine_line}"
        )
    else:
        ceremony_block = "  registrationCeremony: null\n"

    public_key_uri_line = ""
    public_key_uri_line = ""
    if sig.verification_anchor.public_key_uri is not None:
        public_key_uri_line = (
            f"    publicKeyUri: {_yaml_quoted(str(sig.verification_anchor.public_key_uri))}\n"
        )

    payload_canon_line = (
        f"  payloadCanonicalization: {_yaml_quoted(sig.payload_canonicalization)}\n"
        if sig.payload_canonicalization
        else ""
    )

    stored_body = (
        canonicalize_body(body)
        if (sig and sig.payload_canonicalization == CANONICALIZATION_VERSION)
        else body
    )

    return (
        "---\n"
        f"schemaVersion: {_yaml_quoted(artifact.schema_version)}\n"
        f"id: {_yaml_quoted(str(artifact.id))}\n"
        f"title: {_yaml_quoted(artifact.title)}\n"
        f"timestamp: {_yaml_quoted(artifact.timestamp.isoformat())}\n"
        f"contentType: {_yaml_quoted(artifact.content_type)}\n"
        f"license: {_yaml_quoted(str(artifact.license))}\n"
        "provenance:\n"
        f"  source: {_yaml_quoted(artifact.provenance.source)}\n"
        f"  engineVersion: {_yaml_quoted(artifact.provenance.engine_version)}\n"
        f"  modelId: {_yaml_quoted(artifact.provenance.model_id)}\n"
        "  generationContext:\n"
        "    systemInstruction: |-\n"
        f"{system_instruction_yaml}\n"
        "    prompt: |-\n"
        f"{prompt_block_yaml}\n"
        "    hyperparameters:\n"
        f"      temperature: {artifact.provenance.generation_context.hyperparameters.temperature}\n"
        f"      topP: {artifact.provenance.generation_context.hyperparameters.top_p}\n"
        f"      topK: {artifact.provenance.generation_context.hyperparameters.top_k}\n"
        f"{usage_block}"
        f"{watermark_block}"
        f"{attestation_block}"
        f"{webauthn_block}"
        f"{attestation_strength_line}"
        f"{ceremony_block}"
        f"{curation_block}"
        "signature:\n"
        f"  cryptoAlgorithm: {_yaml_quoted(sig.crypto_algorithm)}\n"
        f"  artifactHash: {_yaml_quoted(sig.artifact_hash)}\n"
        f"{payload_canon_line}"
        "  verificationAnchor:\n"
        f"    signerFingerprint: {_yaml_quoted(sig.verification_anchor.signer_fingerprint)}\n"
        f"{public_key_uri_line}"
        "  cryptographicSignature: |\n"
        f"{signature_block_yaml}\n"
        f"{_rfc3161_token_block(sig.rfc3161_token)}"
        f"{_hybrid_signature_block(artifact)}"
        f"recordStatus: {_yaml_quoted(artifact.record_status)}\n"
        "---\n"
        f"{stored_body}\n"
    )
