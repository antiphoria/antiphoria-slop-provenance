"""Minimal oqs test stub to avoid native liboqs dependency in CI."""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

# Ephemeral pairs from generate_keypair() register here so verify() can check
# signatures; PEM/file keys are not registered and keep the legacy lax check.
_STUB_MLDSA_PUB_TO_SECRET: dict[bytes, bytes] = {}


class Signature:
    """Subset of liboqs Signature API for crypto_notary and antiphoria_sdk."""

    def __init__(
        self,
        algorithm: str,
        secret_key: bytes | None = None,
    ) -> None:
        self._algorithm = algorithm
        self._secret_key = secret_key or b""

    def __enter__(self) -> Signature:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: Any,
    ) -> None:
        _ = (exc_type, exc, traceback)

    def generate_keypair(self) -> bytes:
        """Match liboqs-python: generate and hold keypair for this instance."""

        self._secret_key = secrets.token_bytes(32)
        algo = self._algorithm.encode("utf-8", errors="replace")
        self._public_key = hashlib.sha256(algo + b"|" + self._secret_key).digest()
        _STUB_MLDSA_PUB_TO_SECRET[self._public_key] = self._secret_key
        return self._public_key

    def export_secret_key(self) -> bytes:
        if not self._secret_key:
            msg = "export_secret_key called before generate_keypair or without secret_key"
            raise RuntimeError(msg)
        return self._secret_key

    def sign(self, message: bytes) -> bytes:
        """Return deterministic pseudo-signature bytes for tests."""

        return self._digest(self._secret_key, message)

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Check stub-generated keys; lax fallback for file-loaded keys."""

        secret = _STUB_MLDSA_PUB_TO_SECRET.get(public_key)
        if secret is not None:
            return self._digest(secret, message) == signature
        return bool(signature and public_key)

    def _digest(self, key_material: bytes, message: bytes) -> bytes:
        prefix = self._algorithm.encode("utf-8", errors="replace")
        payload = b"|".join((prefix, key_material, message))
        return hashlib.sha256(payload).digest()


__all__ = ["Signature"]
