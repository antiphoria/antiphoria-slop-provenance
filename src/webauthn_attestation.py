"""WebAuthn/FIDO2 attestation for strong author non-repudiation.

Requires: pip install fido2 (or pip install .[webauthn])

CRITICAL: Set WEBAUTHN_RP_ID to your production domain (e.g. antiphoria-archive.com)
before registering credentials. WebAuthn binds credentials to the RP ID; using
localhost or a placeholder will prevent your future web exhibition from verifying
assertions. No default is provided to avoid attracting traffic to any service.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from src.env_config import get_project_env_path, read_env_optional, resolve_orchestrator_state_dir
from src.models import WebAuthnAttestation

_CREDENTIALS_FILE = ".webauthn-credentials.json"
_WEBAUTHN_PROVIDERS = frozenset({"hid", "platform"})


def _resolve_provider(env_path: Path | None = None) -> str:
    """Resolve WebAuthn provider: hid (USB key) or platform (Touch ID bridge)."""
    raw = read_env_optional("WEBAUTHN_PROVIDER", env_path=env_path)
    if not raw:
        return "hid"
    provider = raw.strip().lower()
    if provider in _WEBAUTHN_PROVIDERS:
        return provider
    return "hid"


def get_webauthn_provider(env_path: Path | None = None) -> str:
    """Public accessor for the active WebAuthn provider."""
    return _resolve_provider(env_path)


def _resolve_rp_id(env_path: Path | None = None) -> str | None:
    """Resolve RP ID from WEBAUTHN_RP_ID. Returns None if unset (WebAuthn disabled)."""
    rp_id = read_env_optional("WEBAUTHN_RP_ID", env_path=env_path)
    if not rp_id or not rp_id.strip():
        return None
    return rp_id.strip().lower()


def _get_credentials_path(
    *,
    env_path: Path | None = None,
    repo_path: Path | None = None,
) -> Path:
    """Return path to stored WebAuthn credentials (orchestrator state, not archive)."""
    resolved_env = env_path if env_path is not None else get_project_env_path()
    primary = resolve_orchestrator_state_dir(env_path=resolved_env) / _CREDENTIALS_FILE
    if primary.is_file():
        return primary
    if repo_path is not None:
        legacy = repo_path / _CREDENTIALS_FILE
        if legacy.is_file():
            return legacy
    return primary


def _load_credentials(path: Path) -> dict[str, Any]:
    """Load stored credentials from JSON file."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_credentials(path: Path, data: dict[str, Any]) -> None:
    """Save credentials to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_webauthn_assertion(
    challenge: bytes,
    repo_path: Path | None = None,
    env_path: Path | None = None,
) -> WebAuthnAttestation | None:
    """Get WebAuthn assertion from FIDO2 device or platform bridge.

    Returns None if WEBAUTHN_RP_ID is unset, fido2 is not installed, or no device.
    """
    rp_id = _resolve_rp_id(env_path)
    if not rp_id:
        return None
    if _resolve_provider(env_path) == "platform":
        from src.webauthn_bridge import get_assertion_platform

        return get_assertion_platform(challenge, repo_path=repo_path, env_path=env_path)
    try:
        from fido2.hid import CtapHidDevice
        from fido2.webauthn import (
            PublicKeyCredentialDescriptor,
            PublicKeyCredentialRequestOptions,
        )
    except ImportError:
        return None

    credentials_path = _get_credentials_path(env_path=env_path, repo_path=repo_path)
    stored = _load_credentials(credentials_path)
    allow_list = []
    if stored.get("credential_id"):
        cred_id_b64 = stored["credential_id"]
        padding = 4 - len(cred_id_b64) % 4
        if padding != 4:
            cred_id_b64 += "=" * padding
        allow_list.append(
            PublicKeyCredentialDescriptor(
                type="public-key",
                id=base64.urlsafe_b64decode(cred_id_b64),
            )
        )

    devs = list(CtapHidDevice.list_devices())
    if not devs:
        return None

    from fido2.client import Fido2Client

    client = Fido2Client(devs[0], f"https://{rp_id}")
    options = PublicKeyCredentialRequestOptions(
        challenge=challenge,
        rp_id=rp_id,
        allow_credentials=allow_list if allow_list else None,
    )
    try:
        assertion = client.get_assertion(options)
    except Exception:
        return None

    auth_data = assertion.auth_data
    client_data = assertion.client_data
    cred_id = base64.urlsafe_b64encode(assertion.credential_id).decode("ascii").rstrip("=")
    client_data_hash = hashlib.sha256(bytes(client_data)).hexdigest()
    auth_data_b64 = base64.urlsafe_b64encode(auth_data).decode("ascii").rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(assertion.signature).decode("ascii").rstrip("=")

    return WebAuthnAttestation(
        credentialId=cred_id,
        clientDataJsonHash=client_data_hash,
        authenticatorData=auth_data_b64,
        signature=sig_b64,
        fmt="none",
    )


def register_webauthn_credential(
    repo_path: Path | None = None,
    env_path: Path | None = None,
) -> bool:
    """Create and store a new WebAuthn credential.

    Returns True on success.
    """
    rp_id = _resolve_rp_id(env_path)
    if not rp_id:
        return False
    if _resolve_provider(env_path) == "platform":
        from src.webauthn_bridge import register_credential_platform

        return register_credential_platform(repo_path=repo_path, env_path=env_path)
    try:
        from fido2.hid import CtapHidDevice
        from fido2.webauthn import (
            PublicKeyCredentialCreationOptions,
            PublicKeyCredentialParameters,
            PublicKeyCredentialType,
        )
    except ImportError:
        return False

    devs = list(CtapHidDevice.list_devices())
    if not devs:
        return False

    from fido2.client import Fido2Client

    client = Fido2Client(devs[0], f"https://{rp_id}")
    challenge = os.urandom(32)
    options = PublicKeyCredentialCreationOptions(
        rp={"id": rp_id, "name": "Antiphoria"},
        user={
            "id": os.urandom(32),
            "name": f"author@{rp_id}",
            "displayName": "Author",
        },
        challenge=challenge,
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7,
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-257,
            ),
        ],
    )
    try:
        attestation, _ = client.make_credential(options)
    except Exception:
        return False

    cred_id = (
        base64.urlsafe_b64encode(attestation.auth_data.credential_data.credential_id)
        .decode("ascii")
        .rstrip("=")
    )
    pub_key = attestation.auth_data.credential_data.public_key
    pub_key_cose = bytes(pub_key) if hasattr(pub_key, "__bytes__") else pub_key
    if not isinstance(pub_key_cose, bytes):
        pub_key_cose = json.dumps(pub_key).encode("utf-8")
    pub_key_b64 = base64.urlsafe_b64encode(pub_key_cose).decode("ascii").rstrip("=")

    path = _get_credentials_path(env_path=env_path, repo_path=repo_path)
    _save_credentials(
        path,
        {
            "credential_id": cred_id,
            "public_key_cose_b64": pub_key_b64,
        },
    )
    return True
