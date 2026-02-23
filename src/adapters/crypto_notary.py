"""Post-quantum signing adapter for artifact notarization.

This adapter consumes `StoryGenerated`, signs payload hashes using ML-DSA,
and emits `StorySigned` with strict frontmatter metadata.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
from pathlib import Path

import oqs

from src.events import EventBus, StoryGenerated, StorySigned
from src.models import Artifact, Provenance

_ML_DSA_ALGORITHM = "ML-DSA-44"
_ENV_KEY_CANDIDATES = ("PQC_PRIVATE_KEY_PATH", "OQS_PRIVATE_KEY_PATH")


def _read_env_value(env_key: str, env_path: Path) -> str:
    """Read a key from process environment or local `.env` file.

    Args:
        env_key: Environment variable name to resolve.
        env_path: Absolute path to the `.env` file.

    Returns:
        The resolved value.

    Raises:
        RuntimeError: If the value cannot be resolved.
    """

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


def _load_private_key_bytes(private_key_path: Path) -> bytes:
    """Load secret key bytes from `.pem` or raw-bytes key files.

    Args:
        private_key_path: Absolute or project-relative key file path.

    Returns:
        Raw secret key bytes expected by liboqs.

    Raises:
        RuntimeError: If file is missing or malformed.
    """

    if not private_key_path.exists():
        raise RuntimeError(f"PQC private key file not found: '{private_key_path}'.")

    raw_bytes = private_key_path.read_bytes()
    if not raw_bytes:
        raise RuntimeError(f"PQC private key file is empty: '{private_key_path}'.")

    # Accept PEM-like wrappers when key material is base64 encoded.
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
                f"PQC PEM key file is missing encoded payload: '{private_key_path}'."
            )
        try:
            return base64.b64decode(encoded, validate=True)
        except binascii.Error as exc:
            raise RuntimeError(
                f"PQC PEM key payload is invalid base64: '{private_key_path}'."
            ) from exc

    return raw_bytes


def _sign_ml_dsa(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message with ML-DSA using liboqs.

    Args:
        secret_key: Persistent ML-DSA secret key bytes.
        message: Message bytes to sign.

    Returns:
        Signature bytes.
    """

    with oqs.Signature(_ML_DSA_ALGORITHM, secret_key=secret_key) as signer:
        return signer.sign(message)


class CryptoNotaryAdapter:
    """ML-DSA event adapter that notarizes generated stories."""

    def __init__(self, event_bus: EventBus, env_path: Path | None = None) -> None:
        """Initialize notary adapter and load persistent private key.

        Args:
            event_bus: Event bus used for subscriptions and emissions.
            env_path: Optional absolute path to the `.env` file.
        """

        self._event_bus = event_bus
        self._env_path = env_path or Path(".env")
        self._private_key = self._resolve_private_key()

    async def start(self) -> None:
        """Subscribe to generated-story events."""

        await self._event_bus.subscribe(StoryGenerated, self._on_story_generated)

    def _resolve_private_key(self) -> bytes:
        """Resolve and load private key bytes from configured path.

        Returns:
            Raw private key bytes.

        Raises:
            RuntimeError: If no private key path configuration exists.
        """

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
        return _load_private_key_bytes(key_path)

    async def _on_story_generated(self, event: StoryGenerated) -> None:
        """Sign generated content hash and emit `StorySigned`.

        Args:
            event: Generated story payload.
        """

        artifact_hash = hashlib.sha256(event.body.encode("utf-8")).hexdigest()
        signature_bytes = await asyncio.to_thread(
            _sign_ml_dsa,
            self._private_key,
            artifact_hash.encode("utf-8"),
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        artifact = Artifact(
            title=event.title,
            provenance=Provenance(
                modelId=event.model_id,
                artifactHash=artifact_hash,
                cryptographicSignature=signature_b64,
            ),
        )

        await self._event_bus.emit(
            StorySigned(
                request_id=event.request_id,
                artifact=artifact,
                body=event.body,
            )
        )
