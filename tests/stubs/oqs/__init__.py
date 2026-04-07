"""Minimal oqs test stub to avoid native liboqs dependency in CI."""

from __future__ import annotations

import hashlib
from typing import Any


class Signature:
    """Small subset of liboqs Signature API used by crypto_notary."""

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

    def sign(self, message: bytes) -> bytes:
        """Return deterministic pseudo-signature bytes for tests."""

        return self._digest(self._secret_key, message)

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Return True when basic signature inputs are present for test flow."""

        _ = message
        return bool(signature and public_key)

    def _digest(self, key_material: bytes, message: bytes) -> bytes:
        prefix = self._algorithm.encode("utf-8", errors="replace")
        payload = b"|".join((prefix, key_material, message))
        return hashlib.sha256(payload).digest()


__all__ = ["Signature"]
