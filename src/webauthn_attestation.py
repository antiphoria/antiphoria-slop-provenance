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


def _origin_matches_rp_id(origin: str, rp_id: str) -> bool:
    """True iff ``origin``'s host equals the RP ID or is a subdomain of it.

    WebAuthn requires the RP ID to be a registrable-domain suffix of the origin's
    effective domain. A naive ``origin.endswith(rp_id)`` is exploitable — e.g.
    ``https://evil-antiphoria.org`` ends with ``antiphoria.org`` but is a wholly
    different registrable domain. Parse the host and require an exact match or a
    dot-delimited subdomain match.
    """
    from urllib.parse import urlparse

    if not origin or not rp_id:
        return False
    host = (urlparse(origin).hostname or "").lower()
    rp = rp_id.lower()
    return host == rp or host.endswith("." + rp)


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
    client_data_bytes = bytes(client_data)
    cred_id = base64.urlsafe_b64encode(assertion.credential_id).decode("ascii").rstrip("=")
    client_data_b64 = base64.urlsafe_b64encode(client_data_bytes).decode("ascii").rstrip("=")
    client_data_hash = hashlib.sha256(client_data_bytes).hexdigest()
    auth_data_b64 = base64.urlsafe_b64encode(auth_data).decode("ascii").rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(assertion.signature).decode("ascii").rstrip("=")

    return WebAuthnAttestation(
        credentialId=cred_id,
        clientDataJson=client_data_b64,
        clientDataJsonHash=client_data_hash,
        authenticatorData=auth_data_b64,
        signature=sig_b64,
        fmt="none",
    )


def verify_webauthn_assertion(
    attestation: WebAuthnAttestation,
    *,
    expected_rp_id: str,
    expected_challenge_hash: bytes,
    credential_public_key_cose: bytes,
) -> bool:
    """Cryptographically verify a captured WebAuthn assertion. v3 (Flaw A).

    Replaces the previous "field-present" check with real verification:

    1. Decode ``authenticatorData`` → check ``rpIdHash == SHA-256(expected_rp_id)``,
       ``userPresent`` (UP) flag set, ``userVerified`` (UV) flag set.
    2. Decode ``clientDataJSON`` → check ``type == "webauthn"``, ``origin`` ends
       with the RP ID, and ``challenge == base64url(expected_challenge_hash)``.
    3. Verify the ES256 signature over ``authenticatorData || SHA-256(clientDataJSON)``
       using the COSE public key.

    Args:
        attestation: The captured assertion (from the envelope).
        expected_rp_id: The production RP ID (e.g. ``antiphoria.org``).
        expected_challenge_hash: The SHA-256 of the canonical body — what the
            challenge field in clientDataJSON must equal.
        credential_public_key_cose: The COSE-encoded public key for this
            credential (from the published registry / enrollment store).

    Returns:
        True only if every check passes. Any decode/verify failure returns False
        (never raises — callers treat this as a verdict, not an exception).
    """

    try:
        return _verify_webauthn_assertion_inner(
            attestation=attestation,
            expected_rp_id=expected_rp_id,
            expected_challenge_hash=expected_challenge_hash,
            credential_public_key_cose=credential_public_key_cose,
        )
    except Exception:  # noqa: BLE001 — verdict path; never raise
        return False


def _verify_webauthn_assertion_inner(
    attestation: WebAuthnAttestation,
    *,
    expected_rp_id: str,
    expected_challenge_hash: bytes,
    credential_public_key_cose: bytes,
) -> bool:
    """Inner verifier. Raises on decode/verify failure; outer wraps to False."""

    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    # --- 1. authenticatorData checks ---
    auth_data = base64.urlsafe_b64decode(attestation.authenticator_data + "=" * (-len(attestation.authenticator_data) % 4))
    if len(auth_data) < 37:
        return False
    rp_id_hash = auth_data[:32]
    if rp_id_hash != hashlib.sha256(expected_rp_id.encode("ascii")).digest():
        return False
    flags = auth_data[32]
    user_present = bool(flags & 0x01)
    user_verified = bool(flags & 0x04)
    if not user_present or not user_verified:
        return False

    # --- 2. clientDataJSON checks ---
    client_data_bytes = base64.urlsafe_b64decode(
        attestation.client_data_json + "=" * (-len(attestation.client_data_json) % 4)
    )
    # Confirm the stored hash matches (defence against the two fields disagreeing).
    if hashlib.sha256(client_data_bytes).digest().hex() != attestation.client_data_json_hash:
        return False
    client_data = json.loads(client_data_bytes.decode("utf-8"))
    if client_data.get("type") != "webauthn":
        return False
    origin = client_data.get("origin", "")
    if not _origin_matches_rp_id(origin, expected_rp_id):
        return False
    # The challenge in clientDataJSON is base64url-encoded bytes; the authenticator
    # receives exactly what the engine passed as the challenge — which is the
    # SHA-256 of the canonical body.
    challenge_b64url = client_data.get("challenge", "")
    challenge_padding = "=" * (-len(challenge_b64url) % 4)
    challenge_bytes = base64.urlsafe_b64decode(challenge_b64url + challenge_padding)
    if challenge_bytes != expected_challenge_hash:
        return False

    # --- 3. ES256 signature verification ---
    # The signed message is authenticatorData || SHA-256(clientDataJSON).
    signed_message = auth_data + hashlib.sha256(client_data_bytes).digest()
    signature_bytes = base64.urlsafe_b64decode(
        attestation.signature + "=" * (-len(attestation.signature) % 4)
    )

    # Decode the COSE key to an EC public key (P-256 / secp256r1 for alg -7 / ES256).
    # COSE_Key for EC2: {1: kty=2, 3: alg=-7, -1: crv=1 (P-256), -2: x, -3: y}.
    cose_key = json.loads(credential_public_key_cose.decode("utf-8")) if isinstance(
        credential_public_key_cose, (bytes, bytearray)
    ) and credential_public_key_cose[:1] in (b"{", b"[") else None
    if isinstance(credential_public_key_cose, (bytes, bytearray)):
        # Try CBOR first; fall back to JSON dict.
        try:
            import cbor2  # type: ignore

            cose_key = cbor2.loads(credential_public_key_cose)
        except ImportError:
            pass
    if cose_key is None and isinstance(credential_public_key_cose, (bytes, bytearray)):
        try:
            cose_key = json.loads(credential_public_key_cose.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
    if not isinstance(cose_key, dict):
        return False
    # COSE EC2 key — keys are integers in CBOR, possibly strings in JSON form.
    x_raw = cose_key.get(-2) or cose_key.get("-2")
    y_raw = cose_key.get(-3) or cose_key.get("-3")
    if x_raw is None or y_raw is None:
        return False
    x_bytes = x_raw if isinstance(x_raw, (bytes, bytearray)) else bytes(x_raw)
    y_bytes = y_raw if isinstance(y_raw, (bytes, bytearray)) else bytes(y_raw)
    pub_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x_bytes, "big"),
        y=int.from_bytes(y_bytes, "big"),
        curve=ec.SECP256R1(),
    )
    public_key = pub_numbers.public_key()

    # ES256 signature is a raw R||S pair (64 bytes for P-256); convert to DER.
    if len(signature_bytes) == 64:
        r = int.from_bytes(signature_bytes[:32], "big")
        s = int.from_bytes(signature_bytes[32:], "big")
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        signature_bytes = encode_dss_signature(r, s)
    # decode_dss_signature import kept for callers that pass DER; unused if raw.
    _ = decode_dss_signature  # noqa: F841

    public_key.verify(signature_bytes, signed_message, ec.ECDSA(hashes.SHA256()))
    return True


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
