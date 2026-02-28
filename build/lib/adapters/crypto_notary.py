"""Post-quantum notary adapter for Eternity v1 signed envelopes."""

from __future__ import annotations

import asyncio
import base64
import binascii
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import oqs

from src.adapters.c2pa_manifest import build_c2pa_sidecar_manifest
from src.events import EventBusPort, StoryCurated, StoryGenerated, StorySigned
from src.models import (
    Artifact,
    CRYPTO_ALGORITHM_ML_DSA_44,
    Curation,
    EmbeddedWatermark,
    GenerationContext,
    Hyperparameters,
    Provenance,
    SignatureBlock,
    UsageMetrics,
    VerificationAnchor,
    build_envelope_signing_target,
    canonical_json_bytes,
    sha256_hex,
)
from src.parsing import parse_artifact_markdown

_ML_DSA_ALGORITHM = "ML-DSA-44"
_ENV_KEY_CANDIDATES = ("PQC_PRIVATE_KEY_PATH", "OQS_PRIVATE_KEY_PATH")
_PUBLIC_ENV_KEY_CANDIDATES = ("PQC_PUBLIC_KEY_PATH", "OQS_PUBLIC_KEY_PATH")
_DEFAULT_ENGINE_VERSION = "slop-orchestrator-v1.0.0"
_DEFAULT_CONTENT_TYPE = "text/markdown"
_DEFAULT_LICENSE = "Antinomie-Hybrid-Proprietary"


def _read_env_value(env_key: str, env_path: Path) -> str:
    """Read a key from process environment or local `.env` file."""

    from os import getenv

    direct = getenv(env_key)
    if direct:
        return direct

    if not env_path.exists():
        raise RuntimeError(
            f"Missing required environment variable '{env_key}' and missing "
            f"env file at '{env_path}'."
        )

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == env_key:
            parsed = value.strip().strip("'\"")
            if parsed:
                return parsed
            raise RuntimeError(f"Environment key '{env_key}' is empty in .env.")

    raise RuntimeError(f"Missing required environment variable '{env_key}'.")


def _load_key_bytes(key_path: Path) -> bytes:
    """Load key bytes from `.pem` or raw-bytes key files."""

    if not key_path.exists():
        raise RuntimeError(f"PQC key file not found: '{key_path}'.")

    raw_bytes = key_path.read_bytes()
    if not raw_bytes:
        raise RuntimeError(f"PQC key file is empty: '{key_path}'.")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes

    if "-----BEGIN" in text and "-----END" in text:
        encoded_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("-----"):
                continue
            encoded_lines.append(stripped)
        encoded = "".join(encoded_lines)
        if not encoded:
            raise RuntimeError(
                f"PQC PEM key file is missing encoded payload: '{key_path}'."
            )
        try:
            return base64.b64decode(encoded, validate=True)
        except binascii.Error as exc:
            raise RuntimeError(
                f"PQC PEM key payload is invalid base64: '{key_path}'."
            ) from exc

    return raw_bytes


def _sign_ml_dsa(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message with ML-DSA using liboqs."""

    with oqs.Signature(_ML_DSA_ALGORITHM, secret_key=secret_key) as signer:
        return signer.sign(message)


class CryptoNotaryAdapter:
    """ML-DSA event adapter that notarizes generated or curated stories."""

    def __init__(
        self,
        event_bus: EventBusPort,
        env_path: Path | None = None,
        require_private_key: bool = True,
    ) -> None:
        self._event_bus = event_bus
        self._env_path = env_path or Path(".env")
        self._private_key: bytes | None = None
        if require_private_key:
            self._private_key = self._resolve_private_key()
        self._signer_fingerprint = self._resolve_signer_fingerprint()
        self._enable_c2pa = os.getenv("ENABLE_C2PA", "false").lower() == "true"

    async def start(self) -> None:
        """Subscribe to generation and curation events."""

        await self._event_bus.subscribe(StoryGenerated, self._on_story_generated)
        await self._event_bus.subscribe(StoryCurated, self._on_story_curated)

    def _resolve_private_key(self) -> bytes:
        """Resolve and load private key bytes from configured path."""

        private_key_path_value: str | None = None
        for env_key in _ENV_KEY_CANDIDATES:
            try:
                private_key_path_value = _read_env_value(env_key, self._env_path)
                break
            except RuntimeError:
                continue

        if private_key_path_value is None:
            expected = ", ".join(_ENV_KEY_CANDIDATES)
            raise RuntimeError(
                f"Missing private key path config. Define one of: {expected}."
            )

        key_path = Path(private_key_path_value)
        if not key_path.is_absolute():
            key_path = (self._env_path.parent / key_path).resolve()
        return _load_key_bytes(key_path)

    def _resolve_signer_fingerprint(self) -> str:
        """Resolve signer fingerprint from env or key hash fallback."""

        try:
            return _read_env_value("SIGNER_FINGERPRINT", self._env_path)
        except RuntimeError:
            if self._private_key is None:
                return "unknown"
            return sha256_hex(self._private_key)[:32]

    def _resolve_public_key(self) -> bytes:
        """Resolve and load ML-DSA public key bytes from configured path."""

        public_key_path_value: str | None = None
        for env_key in _PUBLIC_ENV_KEY_CANDIDATES:
            try:
                public_key_path_value = _read_env_value(env_key, self._env_path)
                break
            except RuntimeError:
                continue
        if public_key_path_value is None:
            expected = ", ".join(_PUBLIC_ENV_KEY_CANDIDATES)
            raise RuntimeError(
                f"Missing public key path config. Define one of: {expected}."
            )
        key_path = Path(public_key_path_value)
        if not key_path.is_absolute():
            key_path = (self._env_path.parent / key_path).resolve()
        return _load_key_bytes(key_path)

    async def _on_story_generated(self, event: StoryGenerated) -> None:
        """Sign generated content and emit a signed envelope event."""

        artifact = await self._build_signed_artifact(
            title=event.title,
            source="synthetic",
            model_id=event.model_id,
            body=event.body,
            prompt=event.prompt,
            system_instruction=event.system_instruction,
            temperature=event.temperature,
            top_p=event.top_p,
            top_k=event.top_k,
            usage_metrics=event.usage_metrics,
            embedded_watermark=event.embedded_watermark,
            content_type=event.content_type,
            license=event.license,
            curation=None,
        )
        await self._event_bus.emit(
            StorySigned(
                request_id=event.request_id,
                artifact=artifact,
                body=event.body,
                c2pa_manifest_hash=self._c2pa_manifest_hash(artifact, event.body),
            )
        )

    async def _on_story_curated(self, event: StoryCurated) -> None:
        """Sign curated content and emit a signed envelope event."""

        artifact = await self._build_signed_artifact(
            title=self._derive_title(event.curated_body),
            source="hybrid",
            model_id=event.model_id,
            body=event.curated_body,
            prompt=event.prompt,
            system_instruction="Human curation pass.",
            temperature=0.0,
            top_p=1.0,
            top_k=1,
            usage_metrics=None,
            embedded_watermark=None,
            content_type=_DEFAULT_CONTENT_TYPE,
            license=_DEFAULT_LICENSE,
            curation=event.curation_metadata,
        )
        await self._event_bus.emit(
            StorySigned(
                request_id=event.request_id,
                artifact=artifact,
                body=event.curated_body,
                c2pa_manifest_hash=self._c2pa_manifest_hash(
                    artifact,
                    event.curated_body,
                ),
            )
        )

    async def _build_signed_artifact(
        self,
        title: str,
        source: Literal["synthetic", "hybrid"],
        model_id: str,
        body: str,
        prompt: str,
        system_instruction: str,
        temperature: float,
        top_p: float,
        top_k: int,
        usage_metrics: UsageMetrics | None,
        embedded_watermark: EmbeddedWatermark | None,
        content_type: str,
        license: str,
        curation: Curation | None,
    ) -> Artifact:
        """Construct unsigned envelope, sign canonical target, attach signature."""

        if self._private_key is None:
            raise RuntimeError("Private key is required for signing operations.")
        payload_hash = sha256_hex(body.encode("utf-8"))
        unsigned_envelope = Artifact(
            title=title,
            timestamp=datetime.now(timezone.utc),
            contentType=content_type,
            license=license,
            provenance=Provenance(
                source=source,
                engineVersion=_DEFAULT_ENGINE_VERSION,
                modelId=model_id,
                generationContext=GenerationContext(
                    systemInstruction=system_instruction,
                    prompt=prompt,
                    hyperparameters=Hyperparameters(
                        temperature=temperature,
                        topP=top_p,
                        topK=top_k,
                    ),
                ),
                usageMetrics=usage_metrics,
                embeddedWatermark=embedded_watermark,
            ),
            curation=curation,
        )
        c2pa_manifest_hash = None
        if self._enable_c2pa:
            c2pa_manifest = build_c2pa_sidecar_manifest(unsigned_envelope, body)
            c2pa_manifest_hash = c2pa_manifest.manifest_hash
        signing_target = build_envelope_signing_target(
            envelope=unsigned_envelope,
            payload_sha256_hex=payload_hash,
            manifest_sha256_hex=c2pa_manifest_hash,
            prev_hash=None,
        )
        signing_hash = sha256_hex(canonical_json_bytes(signing_target))
        signature_bytes = await asyncio.to_thread(
            _sign_ml_dsa,
            self._private_key,
            signing_hash.encode("utf-8"),
        )
        signature = SignatureBlock(
            cryptoAlgorithm=CRYPTO_ALGORITHM_ML_DSA_44,
            artifactHash=payload_hash,
            cryptographicSignature=base64.b64encode(signature_bytes).decode("ascii"),
            verificationAnchor=VerificationAnchor(
                signerFingerprint=self._signer_fingerprint,
            ),
        )
        return unsigned_envelope.model_copy(update={"signature": signature})

    def _c2pa_manifest_hash(self, artifact: Artifact, body: str) -> str | None:
        """Return C2PA sidecar hash when C2PA dual-write is enabled."""

        if not self._enable_c2pa:
            return None
        return build_c2pa_sidecar_manifest(artifact, body).manifest_hash

    def verify_artifact(self, file_path: Path) -> bool:
        """Verify an Eternity v1 artifact against canonical signing target.

        Args:
            file_path: Markdown artifact file path.

        Returns:
            True when signature verification succeeds, otherwise False.
        """

        envelope, payload = parse_artifact_markdown(file_path)
        return self.verify_artifact_payload(
            envelope=envelope,
            payload=payload,
            manifest_hash=self._resolve_manifest_hash_for_artifact(file_path),
        )

    def verify_artifact_payload(
        self,
        envelope: Artifact,
        payload: str,
        manifest_hash: str | None,
    ) -> bool:
        """Verify a pre-parsed artifact payload against envelope signature."""

        if envelope.signature is None:
            raise RuntimeError("Artifact envelope is missing signature block.")
        payload_hash = sha256_hex(payload.encode("utf-8"))
        if payload_hash != envelope.signature.artifact_hash:
            raise RuntimeError("Payload hash mismatch against signed artifactHash.")
        signing_target = build_envelope_signing_target(
            envelope=envelope,
            payload_sha256_hex=payload_hash,
            manifest_sha256_hex=manifest_hash,
            prev_hash=None,
        )
        signing_hash = sha256_hex(canonical_json_bytes(signing_target))
        try:
            normalized_signature = "".join(
                envelope.signature.cryptographic_signature.split()
            )
            signature_bytes = base64.b64decode(normalized_signature, validate=True)
        except binascii.Error as exc:
            raise RuntimeError("Invalid base64 signature payload in artifact.") from exc
        public_key = self._resolve_public_key()
        with oqs.Signature(_ML_DSA_ALGORITHM) as verifier:
            is_valid = verifier.verify(
                signing_hash.encode("utf-8"),
                signature_bytes,
                public_key,
            )
        return bool(is_valid)

    def _resolve_manifest_hash_for_artifact(self, file_path: Path) -> str | None:
        """Resolve C2PA sidecar hash when a sibling .c2pa file exists."""

        sidecar_path = file_path.with_suffix(".c2pa")
        if not sidecar_path.exists():
            return None
        return sha256_hex(sidecar_path.read_bytes())

    def read_artifact_id(self, file_path: Path) -> str:
        """Read artifact UUID from Eternity envelope."""

        envelope, _ = parse_artifact_markdown(file_path)
        return str(envelope.id)

    @staticmethod
    def _derive_title(body: str) -> str:
        """Derive deterministic title from artifact body content."""

        first_line = body.strip().splitlines()[0].strip()
        candidate = first_line.strip("# ").strip()
        if not candidate:
            return "INCIDENT_UNTITLED"
        normalized = "_".join(candidate.split())[:80]
        return f"INCIDENT_{normalized.upper()}"
