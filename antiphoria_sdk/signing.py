"""Signer + Verifier protocols and default hybrid implementations.

Default implementation: ML-DSA-44 (post-quantum) + Ed25519 (classical).
Signing produces two signatures; both must verify for success.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from antiphoria_sdk.types import Signature

_LOGGER = logging.getLogger(__name__)

try:
    import oqs  # type: ignore[import-untyped]

    _OQS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _OQS_AVAILABLE = False

_MLDSA_ALG = "ML-DSA-44"
_HYBRID_ALG = "ml-dsa-44+ed25519"


@runtime_checkable
class Signer(Protocol):
    """Minimal Signer contract. Fingerprint identifies the key."""

    public_key_fingerprint: str

    def sign(self, data: bytes) -> Signature: ...


@runtime_checkable
class Verifier(Protocol):
    """Minimal Verifier contract. Looks up keys internally by fingerprint."""

    def verify(self, data: bytes, signature: Signature) -> bool: ...


@dataclass(frozen=True)
class HybridKeys:
    """ML-DSA-44 + Ed25519 key material. Private halves optional for verify-only."""

    mldsa_public: bytes
    ed25519_public: bytes
    mldsa_private: bytes | None = None
    ed25519_private: bytes | None = None

    @property
    def fingerprint(self) -> str:
        """SHA-256 over the concatenated public keys, truncated to 32 hex chars."""
        h = hashlib.sha256()
        h.update(self.mldsa_public)
        h.update(self.ed25519_public)
        return h.hexdigest()[:32]

    def public_only(self) -> HybridKeys:
        return HybridKeys(
            mldsa_public=self.mldsa_public,
            ed25519_public=self.ed25519_public,
            mldsa_private=None,
            ed25519_private=None,
        )


def _require_oqs() -> None:
    if not _OQS_AVAILABLE:
        raise RuntimeError(
            "ML-DSA requires liboqs-python (import oqs). "
            "Install liboqs and pip install liboqs-python.",
        )


class HybridSigner:
    """Default Signer. Signs with both ML-DSA-44 and Ed25519."""

    def __init__(self, keys: HybridKeys) -> None:
        if keys.mldsa_private is None or keys.ed25519_private is None:
            raise ValueError("HybridSigner requires both private keys.")
        _require_oqs()
        self._keys = keys
        self._ed25519_priv = ed25519.Ed25519PrivateKey.from_private_bytes(
            keys.ed25519_private,
        )

    @property
    def public_key_fingerprint(self) -> str:
        return self._keys.fingerprint

    def sign(self, data: bytes) -> Signature:
        with oqs.Signature(_MLDSA_ALG, self._keys.mldsa_private) as sig:
            mldsa_sig = sig.sign(data)
        ed_sig = self._ed25519_priv.sign(data)
        return Signature(
            algorithm=_HYBRID_ALG,
            mldsa_signature_b64=base64.b64encode(mldsa_sig).decode("ascii"),
            ed25519_signature_b64=base64.b64encode(ed_sig).decode("ascii"),
            public_key_fingerprint=self._keys.fingerprint,
        )


class HybridVerifier:
    """Default Verifier. Resolves keys by fingerprint."""

    def __init__(self, keys_by_fingerprint: dict[str, HybridKeys]) -> None:
        _require_oqs()
        self._keys = dict(keys_by_fingerprint)

    def add_keys(self, keys: HybridKeys) -> None:
        self._keys[keys.fingerprint] = keys

    def verify(self, data: bytes, signature: Signature) -> bool:
        if signature.algorithm != _HYBRID_ALG:
            _LOGGER.warning("Unsupported algorithm: %s", signature.algorithm)
            return False
        keys = self._keys.get(signature.public_key_fingerprint)
        if keys is None:
            _LOGGER.warning(
                "No public key registered for fingerprint %s",
                signature.public_key_fingerprint,
            )
            return False
        try:
            mldsa_sig = base64.b64decode(signature.mldsa_signature_b64, validate=True)
            ed_sig = base64.b64decode(signature.ed25519_signature_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            _LOGGER.warning("Signature base64 decode failed: %s", exc)
            return False
        try:
            with oqs.Signature(_MLDSA_ALG) as v:
                mldsa_ok = bool(v.verify(data, mldsa_sig, keys.mldsa_public))
        except Exception:
            _LOGGER.exception("ML-DSA verify raised")
            return False
        try:
            ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(keys.ed25519_public)
            ed_pub.verify(ed_sig, data)
            ed_ok = True
        except InvalidSignature:
            _LOGGER.warning("Ed25519 signature invalid")
            ed_ok = False
        except Exception:
            _LOGGER.exception("Ed25519 verify raised")
            return False
        return mldsa_ok and ed_ok


def generate_ephemeral_keys() -> HybridKeys:
    """Create a fresh hybrid keypair. Use ONLY for tests/development.

    Chains sealed with ephemeral keys cannot be re-verified after the
    process exits unless the keys are persisted separately.
    """
    _require_oqs()
    _LOGGER.warning(
        "generate_ephemeral_keys() used. Chains will not be verifiable "
        "after this process exits unless keys are persisted.",
    )
    with oqs.Signature(_MLDSA_ALG) as sig:
        mldsa_pub = sig.generate_keypair()
        mldsa_priv = sig.export_secret_key()
    ed_priv_obj = ed25519.Ed25519PrivateKey.generate()
    ed_priv_bytes = ed_priv_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ed_pub_bytes = ed_priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return HybridKeys(
        mldsa_public=mldsa_pub,
        ed25519_public=ed_pub_bytes,
        mldsa_private=mldsa_priv,
        ed25519_private=ed_priv_bytes,
    )


_ENV_MLDSA_PRIV = "ANTIPHORIA_MLDSA_PRIVATE_KEY_B64"
_ENV_MLDSA_PUB = "ANTIPHORIA_MLDSA_PUBLIC_KEY_B64"
_ENV_ED_PRIV = "ANTIPHORIA_ED25519_PRIVATE_KEY_B64"
_ENV_ED_PUB = "ANTIPHORIA_ED25519_PUBLIC_KEY_B64"


def load_keys_from_env(*, require_private: bool = True) -> HybridKeys:
    """Load hybrid keys from base64-encoded environment variables."""

    def _req(name: str) -> bytes:
        v = os.environ.get(name)
        if not v:
            raise RuntimeError(f"Missing env var: {name}")
        try:
            return base64.b64decode(v, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise RuntimeError(f"Env var {name} is not valid base64: {exc}") from exc

    def _opt(name: str) -> bytes | None:
        v = os.environ.get(name)
        if not v:
            return None
        try:
            return base64.b64decode(v, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise RuntimeError(f"Env var {name} is not valid base64: {exc}") from exc

    mldsa_priv = _req(_ENV_MLDSA_PRIV) if require_private else _opt(_ENV_MLDSA_PRIV)
    ed_priv = _req(_ENV_ED_PRIV) if require_private else _opt(_ENV_ED_PRIV)
    return HybridKeys(
        mldsa_public=_req(_ENV_MLDSA_PUB),
        ed25519_public=_req(_ENV_ED_PUB),
        mldsa_private=mldsa_priv,
        ed25519_private=ed_priv,
    )
