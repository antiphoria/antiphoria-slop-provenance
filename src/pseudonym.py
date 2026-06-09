"""Operator pseudonym salt: privacy-preserving cross-artifact author continuity."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from pathlib import Path

from src.env_config import read_env_optional

_PSEUDONYM_DOMAIN = b"antiphoria-operator-pseudonym-v1"
_MIN_SALT_BYTES = 16
_SALT_PATH_ENV = "OPERATOR_PSEUDONYM_SALT_PATH"
_SALT_VALUE_ENV = "OPERATOR_PSEUDONYM_SALT"


def _decode_salt_material(raw: str) -> bytes:
    """Decode configured salt material from base64url or raw UTF-8 bytes."""
    stripped = raw.strip()
    if not stripped:
        raise RuntimeError("Operator pseudonym salt is empty.")

    padding = "=" * ((4 - len(stripped) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(stripped + padding)
        if decoded:
            return decoded
    except (ValueError, binascii.Error):
        return stripped.encode("utf-8")

    return stripped.encode("utf-8")


def _validate_salt_bytes(salt: bytes) -> bytes:
    if len(salt) < _MIN_SALT_BYTES:
        raise RuntimeError(
            f"Operator pseudonym salt must be at least {_MIN_SALT_BYTES} bytes "
            f"after decoding (got {len(salt)})."
        )
    return salt


def resolve_pseudonym_salt(env_path: Path | None = None) -> tuple[bytes, str] | None:
    """Resolve operator pseudonym salt bytes and the raw configured text.

    Returns None when unset. Raises RuntimeError on weak or unreadable salt.
    """
    salt_path_value = read_env_optional(_SALT_PATH_ENV, env_path=env_path)
    if salt_path_value:
        path = Path(salt_path_value).expanduser()
        if not path.exists():
            raise RuntimeError(f"Operator pseudonym salt file not found: '{path}'.")
        raw_text = path.read_text(encoding="utf-8")
        salt_bytes = _validate_salt_bytes(_decode_salt_material(raw_text))
        return salt_bytes, raw_text.strip()

    salt_value = read_env_optional(_SALT_VALUE_ENV, env_path=env_path)
    if salt_value:
        salt_bytes = _validate_salt_bytes(_decode_salt_material(salt_value))
        return salt_bytes, salt_value.strip()

    return None


def derive_pseudonym_hash(salt: bytes) -> str:
    """Derive a stable operator pseudonym hash from secret salt bytes."""
    _validate_salt_bytes(salt)
    return hmac.new(salt, _PSEUDONYM_DOMAIN, hashlib.sha256).hexdigest()


def get_pseudonym_hash(env_path: Path | None = None) -> str | None:
    """Return operator pseudonym hash when salt is configured, else None."""
    resolved = resolve_pseudonym_salt(env_path)
    if resolved is None:
        return None
    salt_bytes, _ = resolved
    return derive_pseudonym_hash(salt_bytes)


def salt_appears_in_text(env_path: Path | None, text: str) -> bool:
    """Return True when configured salt material appears literally in text."""
    resolved = resolve_pseudonym_salt(env_path)
    if resolved is None:
        return False

    _, raw_text = resolved
    candidates = {raw_text}
    try:
        salt_bytes = _decode_salt_material(raw_text)
        candidates.add(base64.urlsafe_b64encode(salt_bytes).decode("ascii").rstrip("="))
        try:
            candidates.add(salt_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            pass
    except RuntimeError:
        pass

    return any(candidate and candidate in text for candidate in candidates)
