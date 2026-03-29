"""Post-quantum notary adapter for Eternity v1 signed envelopes."""

from __future__ import annotations

import asyncio
import base64
import logging
import binascii
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import oqs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
    load_pem_public_key,
    PublicFormat,
)

from src.adapters.c2pa_manifest import (
    C2PAManifestArtifact,
    build_c2pa_sidecar_manifest,
)
from src.env_config import read_env_bool, read_env_optional, read_env_required
from src.events import (
    EventBusPort,
    StoryCurated,
    StoryGenerated,
    StoryHumanRegistered,
    StorySigned,
)
from src.policies.licensing import get_license_id
from src.canonicalization import CANONICALIZATION_VERSION, compute_payload_hash
from src.models import (
    Artifact,
    AuthorAttestation,
    CRYPTO_ALGORITHM_ED25519,
    CRYPTO_ALGORITHM_ML_DSA_44,
    Curation,
    EmbeddedWatermark,
    GenerationContext,
    Hyperparameters,
    Provenance,
    RegistrationCeremony,
    SignatureBlock,
    UsageMetrics,
    VerificationAnchor,
    WebAuthnAttestation,
    build_envelope_signing_target,
    canonical_json_bytes,
    sha256_hex,
)
from src.logging_config import bind_log_context, should_log_route
from src.parsing import parse_artifact_markdown

_adapter_logger = logging.getLogger("src.adapters.crypto_notary")
_ML_DSA_ALGORITHM = "ML-DSA-44"
_ENV_KEY_CANDIDATES = ("PQC_PRIVATE_KEY_PATH", "OQS_PRIVATE_KEY_PATH")
_PUBLIC_ENV_KEY_CANDIDATES = ("PQC_PUBLIC_KEY_PATH", "OQS_PUBLIC_KEY_PATH")
_ED25519_PRIVATE_KEY_ENV = "ED25519_PRIVATE_KEY_PATH"
_ED25519_PUBLIC_KEY_ENV = "ED25519_PUBLIC_KEY_PATH"
_DEFAULT_ENGINE_VERSION = "antiphoria-slop-provenance-v1.0.0"
_DEFAULT_CONTENT_TYPE = "text/markdown"


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
            raise RuntimeError(f"PQC PEM key file is missing encoded payload: '{key_path}'.")
        try:
            return base64.b64decode(encoded, validate=True)
        except binascii.Error as exc:
            raise RuntimeError(f"PQC PEM key payload is invalid base64: '{key_path}'.") from exc

    return raw_bytes


def _sign_ml_dsa(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message with ML-DSA using liboqs."""

    with oqs.Signature(_ML_DSA_ALGORITHM, secret_key=secret_key) as signer:
        return signer.sign(message)


def _sign_ed25519(private_key_bytes: bytes, message: bytes) -> bytes:
    """Sign a message with Ed25519 using cryptography."""

    key = _load_ed25519_private_key(private_key_bytes)
    return key.sign(message)


def _load_ed25519_private_key(private_key_bytes: bytes) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM or raw bytes."""

    try:
        if private_key_bytes.lstrip().startswith(b"-----BEGIN"):
            key = load_pem_private_key(private_key_bytes, password=None)
        else:
            key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    except Exception as exc:
        raise RuntimeError(f"Failed to load Ed25519 private key: {exc!r}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Key is not Ed25519")
    return key


def _ed25519_public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    """Extract raw public key bytes from Ed25519 private key."""

    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


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
        self._ed25519_private_key: bytes | None = None
        self._ed25519_signer_fingerprint: str | None = None
        if require_private_key:
            self._private_key = self._resolve_private_key()
            self._ed25519_private_key, self._ed25519_signer_fingerprint = (
                self._resolve_ed25519_key()
            )
        self._signer_fingerprint = self._resolve_signer_fingerprint()
        self._enable_c2pa = read_env_bool(
            "ENABLE_C2PA",
            default=False,
            env_path=self._env_path,
        )

    async def start(self) -> None:
        """Subscribe to generation and curation events."""

        await self._event_bus.subscribe(StoryGenerated, self._on_story_generated)
        await self._event_bus.subscribe(StoryCurated, self._on_story_curated)
        await self._event_bus.subscribe(StoryHumanRegistered, self._on_story_human_registered)

    def _resolve_private_key(self) -> bytes:
        """Resolve and load private key bytes from configured path."""

        private_key_path_value: str | None = None
        for env_key in _ENV_KEY_CANDIDATES:
            try:
                private_key_path_value = read_env_required(
                    env_key,
                    env_path=self._env_path,
                )
                break
            except RuntimeError:
                continue

        if private_key_path_value is None:
            expected = ", ".join(_ENV_KEY_CANDIDATES)
            raise RuntimeError(f"Missing private key path config. Define one of: {expected}.")

        key_path = Path(private_key_path_value)
        if not key_path.is_absolute():
            key_path = (self._env_path.parent / key_path).resolve()
        return _load_key_bytes(key_path)

    def _resolve_signer_fingerprint(self) -> str:
        """Resolve signer fingerprint from env or key hash fallback."""

        try:
            return read_env_required(
                "SIGNER_FINGERPRINT",
                env_path=self._env_path,
            )
        except RuntimeError:
            if self._private_key is None:
                return "unknown"
            return sha256_hex(self._private_key)[:32]

    def _resolve_ed25519_key(self) -> tuple[bytes, str]:
        """Resolve Ed25519 private key and fingerprint. Required for signing."""

        path_value = read_env_required(
            _ED25519_PRIVATE_KEY_ENV,
            env_path=self._env_path,
        )
        path_value = path_value.strip()
        if not path_value:
            raise RuntimeError(
                f"Missing required {_ED25519_PRIVATE_KEY_ENV}. "
                "Set it in .env or via scripts/run-secure.ps1 (vault must contain ed25519_private.pem)."
            )
        key_path = Path(path_value)
        if not key_path.is_absolute():
            key_path = (self._env_path.parent / key_path).resolve()
        if not key_path.exists():
            raise RuntimeError(
                f"Ed25519 private key not found: '{key_path}'. "
                "Mount the vault and ensure ed25519_private.pem exists."
            )
        key_bytes = key_path.read_bytes()
        if not key_bytes or not key_bytes.strip():
            raise RuntimeError(f"Ed25519 private key file is empty: '{key_path}'.")
        try:
            key = _load_ed25519_private_key(key_bytes)
            pub_bytes = _ed25519_public_key_bytes(key)
            fingerprint = sha256_hex(pub_bytes)[:32]
            return key_bytes, fingerprint
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"Failed to load Ed25519 private key from '{key_path}': {exc}"
            ) from exc

    def _resolve_public_key(self) -> bytes:
        """Resolve and load ML-DSA public key bytes from configured path."""

        public_key_path_value: str | None = None
        for env_key in _PUBLIC_ENV_KEY_CANDIDATES:
            try:
                public_key_path_value = read_env_required(
                    env_key,
                    env_path=self._env_path,
                )
                break
            except RuntimeError:
                continue
        if public_key_path_value is None:
            expected = ", ".join(_PUBLIC_ENV_KEY_CANDIDATES)
            raise RuntimeError(f"Missing public key path config. Define one of: {expected}.")
        key_path = Path(public_key_path_value)
        if not key_path.is_absolute():
            key_path = (self._env_path.parent / key_path).resolve()
        return _load_key_bytes(key_path)

    def _resolve_public_key_for_verification(self, envelope: Artifact) -> bytes:
        """Resolve public key for verification, supporting key rotation via signer_fingerprint.

        When envelope.signature.verification_anchor.signer_fingerprint is present, first
        checks PQC_PUBLIC_KEY_<fingerprint> (fingerprint sanitized for env: colons/dashes
        replaced with underscores). Enables historical verification after key rotation.
        """
        fingerprint: str | None = None
        if envelope.signature is not None:
            fingerprint = envelope.signature.verification_anchor.signer_fingerprint
        if fingerprint:
            sanitized = fingerprint.replace(":", "_").replace("-", "_")
            env_key = f"PQC_PUBLIC_KEY_{sanitized}"
            path_value = read_env_optional(env_key, env_path=self._env_path)
            if path_value:
                key_path = Path(path_value)
                if not key_path.is_absolute():
                    key_path = (self._env_path.parent / key_path).resolve()
                return _load_key_bytes(key_path)
        return self._resolve_public_key()

    async def _on_story_generated(self, event: StoryGenerated) -> None:
        """Sign generated content and emit a signed envelope event."""
        bind_log_context(request_id=event.request_id)

        artifact, c2pa_manifest = await self._build_signed_artifact(
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
            author_attestation=None,
        )
        if should_log_route("coarse"):
            _adapter_logger.info(
                "CryptoNotaryAdapter emitting StorySigned request_id=%s",
                event.request_id,
                extra={"request_id": str(event.request_id)},
            )
        await self._event_bus.emit(
            StorySigned(
                request_id=event.request_id,
                artifact=artifact,
                body=event.body,
                c2pa_manifest_hash=(None if c2pa_manifest is None else c2pa_manifest.manifest_hash),
                c2pa_manifest_bytes_b64=(
                    None
                    if c2pa_manifest is None
                    else base64.b64encode(c2pa_manifest.manifest_bytes).decode("ascii")
                ),
            )
        )

    async def _on_story_curated(self, event: StoryCurated) -> None:
        """Sign curated content and emit a signed envelope event."""
        bind_log_context(request_id=event.request_id)

        artifact, c2pa_manifest = await self._build_signed_artifact(
            title=(
                event.title if event.title is not None else self._derive_title(event.curated_body)
            ),
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
            license=get_license_id("hybrid"),
            curation=event.curation_metadata,
            author_attestation=None,
        )
        if should_log_route("coarse"):
            _adapter_logger.info(
                "CryptoNotaryAdapter emitting StorySigned request_id=%s",
                event.request_id,
                extra={"request_id": str(event.request_id)},
            )
        await self._event_bus.emit(
            StorySigned(
                request_id=event.request_id,
                artifact=artifact,
                body=event.curated_body,
                c2pa_manifest_hash=(None if c2pa_manifest is None else c2pa_manifest.manifest_hash),
                c2pa_manifest_bytes_b64=(
                    None
                    if c2pa_manifest is None
                    else base64.b64encode(c2pa_manifest.manifest_bytes).decode("ascii")
                ),
            )
        )

    async def _on_story_human_registered(self, event: StoryHumanRegistered) -> None:
        """Sign human-only content and emit a signed envelope event."""
        bind_log_context(request_id=event.request_id)

        artifact, c2pa_manifest = await self._build_signed_artifact(
            title=event.title,
            source="human",
            model_id="human",
            body=event.body,
            prompt="N/A",
            system_instruction="Human-authored. No AI generation.",
            temperature=0.0,
            top_p=1.0,
            top_k=0,
            usage_metrics=None,
            embedded_watermark=None,
            content_type=_DEFAULT_CONTENT_TYPE,
            license=event.license,
            curation=None,
            author_attestation=event.attestation,
            webauthn_attestation=event.webauthn_attestation,
            registration_ceremony=event.registration_ceremony,
        )
        if should_log_route("coarse"):
            _adapter_logger.info(
                "CryptoNotaryAdapter emitting StorySigned request_id=%s",
                event.request_id,
                extra={"request_id": str(event.request_id)},
            )
        await self._event_bus.emit(
            StorySigned(
                request_id=event.request_id,
                artifact=artifact,
                body=event.body,
                c2pa_manifest_hash=(None if c2pa_manifest is None else c2pa_manifest.manifest_hash),
                c2pa_manifest_bytes_b64=(
                    None
                    if c2pa_manifest is None
                    else base64.b64encode(c2pa_manifest.manifest_bytes).decode("ascii")
                ),
            )
        )

    async def _build_signed_artifact(
        self,
        title: str,
        source: Literal["synthetic", "hybrid", "human"],
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
        author_attestation: AuthorAttestation | None = None,
        webauthn_attestation: WebAuthnAttestation | None = None,
        registration_ceremony: RegistrationCeremony | None = None,
    ) -> tuple[Artifact, C2PAManifestArtifact | None]:
        """Construct unsigned envelope, sign canonical target, attach signature."""

        if self._private_key is None:
            raise RuntimeError("Private key is required for signing operations.")
        payload_hash = compute_payload_hash(body)
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
                authorAttestation=author_attestation,
                webauthnAttestation=webauthn_attestation,
                attestationStrength=(
                    "webauthn"
                    if webauthn_attestation
                    else ("legacy" if author_attestation else None)
                ),
                registrationCeremony=registration_ceremony,
            ),
            curation=curation,
        )
        c2pa_manifest: C2PAManifestArtifact | None = None
        if self._enable_c2pa:
            try:
                c2pa_manifest = build_c2pa_sidecar_manifest(
                    unsigned_envelope,
                    body,
                    env_path=self._env_path,
                )
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(
                    "C2PA sidecar generation failed while ENABLE_C2PA=true. "
                    "Aborting notarization (fail-closed). "
                    f"Underlying error: {exc!r}"
                ) from exc
        signing_target = build_envelope_signing_target(
            envelope=unsigned_envelope,
            payload_sha256_hex=payload_hash,
            manifest_sha256_hex=(None if c2pa_manifest is None else c2pa_manifest.manifest_hash),
            prev_hash=None,
            canonicalization_version=CANONICALIZATION_VERSION,
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
            payloadCanonicalization=CANONICALIZATION_VERSION,
        )
        hybrid_sig_bytes = await asyncio.to_thread(
            _sign_ed25519,
            self._ed25519_private_key,
            signing_hash.encode("utf-8"),
        )
        hybrid_signature = SignatureBlock(
            cryptoAlgorithm=CRYPTO_ALGORITHM_ED25519,
            artifactHash=payload_hash,
            cryptographicSignature=base64.b64encode(hybrid_sig_bytes).decode("ascii"),
            verificationAnchor=VerificationAnchor(
                signerFingerprint=self._ed25519_signer_fingerprint,
            ),
            payloadCanonicalization=CANONICALIZATION_VERSION,
        )
        return unsigned_envelope.model_copy(
            update={
                "signature": signature,
                "hybrid_signature": hybrid_signature,
            }
        ), c2pa_manifest

    def verify_artifact(
        self,
        file_path: Path,
        allow_redacted: bool = False,
    ) -> bool:
        """Verify an Eternity v1 artifact against canonical signing target.

        Args:
            file_path: Markdown artifact file path.
            allow_redacted: When True, use artifactHash from envelope instead of
                recomputing from body; skip payload hash check (for redacted artifacts).

        Returns:
            True when signature verification succeeds, otherwise False.
        """

        envelope, payload = parse_artifact_markdown(file_path)
        return self.verify_artifact_payload(
            envelope=envelope,
            payload=payload,
            manifest_hash=self._resolve_manifest_hash_for_artifact(file_path),
            allow_redacted=allow_redacted,
        )

    def verify_artifact_payload(
        self,
        envelope: Artifact,
        payload: str,
        manifest_hash: str | None,
        allow_redacted: bool = False,
    ) -> bool:
        """Verify a pre-parsed artifact payload against envelope signature."""

        if envelope.signature is None:
            raise RuntimeError("Artifact envelope is missing signature block.")
        payload_hash = compute_payload_hash(payload)
        if allow_redacted:
            payload_hash = envelope.signature.artifact_hash
        elif payload_hash != envelope.signature.artifact_hash:
            raise RuntimeError("Payload hash mismatch against signed artifactHash.")
        signing_target = build_envelope_signing_target(
            envelope=envelope,
            payload_sha256_hex=payload_hash,
            manifest_sha256_hex=manifest_hash,
            prev_hash=None,
            canonicalization_version=envelope.signature.payload_canonicalization,
        )
        signing_hash = sha256_hex(canonical_json_bytes(signing_target))
        try:
            normalized_signature = "".join(envelope.signature.cryptographic_signature.split())
            signature_bytes = base64.b64decode(normalized_signature, validate=True)
        except binascii.Error as exc:
            raise RuntimeError("Invalid base64 signature payload in artifact.") from exc
        public_key = self._resolve_public_key_for_verification(envelope)
        is_valid = self._verify_mldsa_signature(
            signing_hash=signing_hash,
            signature_bytes=signature_bytes,
            public_key=public_key,
        )
        if not is_valid:
            return False
        if envelope.hybrid_signature is not None:
            ed25519_pub = self._resolve_ed25519_public_key_for_verification(
                envelope.hybrid_signature
            )
            try:
                hybrid_sig_b64 = "".join(envelope.hybrid_signature.cryptographic_signature.split())
                hybrid_sig_bytes = base64.b64decode(hybrid_sig_b64, validate=True)
            except binascii.Error:
                return False
            if not self._verify_ed25519_signature(
                signing_hash=signing_hash,
                signature_bytes=hybrid_sig_bytes,
                public_key=ed25519_pub,
            ):
                return False
        # No legacy fallback: trailing newlines in prompt/systemInstruction would
        # allow signature malleability. Artifacts with folded YAML scalars must
        # be re-signed.
        return True

    @staticmethod
    def _verify_mldsa_signature(
        signing_hash: str,
        signature_bytes: bytes,
        public_key: bytes,
    ) -> bool:
        """Verify one ML-DSA signature over a canonical signing-hash string."""

        with oqs.Signature(_ML_DSA_ALGORITHM) as verifier:
            return bool(
                verifier.verify(
                    signing_hash.encode("utf-8"),
                    signature_bytes,
                    public_key,
                )
            )

    def _resolve_ed25519_public_key_for_verification(
        self,
        hybrid_sig: SignatureBlock,
    ) -> bytes:
        """Resolve Ed25519 public key for hybrid signature verification."""

        fingerprint = hybrid_sig.verification_anchor.signer_fingerprint
        sanitized = fingerprint.replace(":", "_").replace("-", "_")
        env_key = f"ED25519_PUBLIC_KEY_{sanitized}"
        path_value = read_env_optional(env_key, env_path=self._env_path)
        if not path_value:
            path_value = read_env_required(
                _ED25519_PUBLIC_KEY_ENV,
                env_path=self._env_path,
            )
        path_value = path_value.strip()
        if not path_value:
            raise RuntimeError(f"Missing {_ED25519_PUBLIC_KEY_ENV} for Ed25519 verification.")
        key_path = Path(path_value)
        if not key_path.is_absolute():
            key_path = (self._env_path.parent / key_path).resolve()
        if not key_path.exists():
            raise RuntimeError(
                f"Ed25519 public key not found: '{key_path}'. "
                f"Set {_ED25519_PUBLIC_KEY_ENV} in .env."
            )
        raw = key_path.read_bytes()
        try:
            if raw.lstrip().startswith(b"-----BEGIN"):
                key = load_pem_public_key(raw)
            else:
                key = Ed25519PublicKey.from_public_bytes(raw)
            return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"Failed to load Ed25519 public key from '{key_path}': {exc}"
            ) from exc

    @staticmethod
    def _verify_ed25519_signature(
        signing_hash: str,
        signature_bytes: bytes,
        public_key: bytes,
    ) -> bool:
        """Verify one Ed25519 signature over a canonical signing-hash string."""

        try:
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(
                signature_bytes,
                signing_hash.encode("utf-8"),
            )
            return True
        except Exception:  # noqa: BLE001
            return False

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

        lines = body.strip().splitlines()
        if not lines:
            return "INCIDENT_UNTITLED"
        first_line = lines[0].strip()
        candidate = first_line.strip("# ")
        if not candidate:
            return "INCIDENT_UNTITLED"
        normalized = "_".join(candidate.split())[:80]
        return f"INCIDENT_{normalized.upper()}"
