"""Local browser bridge for macOS Touch ID (platform WebAuthn authenticator).

Serves a short-lived HTTP server on 127.0.0.1 so the CLI can delegate
navigator.credentials ceremonies to Chrome/Safari, which alone can reach
the Secure Enclave platform authenticator.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse

from src.env_config import read_env_optional
from src.models import WebAuthnAttestation
from src.webauthn_attestation import (
    _get_credentials_path,
    _load_credentials,
    _resolve_rp_id,
    _save_credentials,
)

CeremonyMode = Literal["create", "get"]
_BRIDGE_TOKEN_HEADER = "X-Bridge-Token"  # noqa: S105
_BRIDGE_PAGE_DEFAULT_URL = "https://antiphoria.org/bridge.html"
_MAX_CALLBACK_BODY = 65536
_DEFAULT_TIMEOUT_SEC = 60.0
_MAX_PORT_TRIES = 10


class WebAuthnAlreadyRegisteredError(Exception):
    """Platform passkey already registered for this ledger."""


def _resolve_bridge_page_url(env_path: Any = None) -> str:
    """Resolve the hosted ceremony page URL.

    Defaults to the production page. The page must be served from an HTTPS
    origin so the ceremony cannot be downgraded/MITM'd; a loopback host is
    permitted only for local testing.
    """
    url = (read_env_optional("WEBAUTHN_BRIDGE_URL", env_path=env_path) or _BRIDGE_PAGE_DEFAULT_URL).strip()
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    is_loopback = host in {"localhost", "127.0.0.1"}
    if parsed.scheme != "https" and not is_loopback:
        raise RuntimeError(
            "WEBAUTHN_BRIDGE_URL must use https (or a loopback host for local testing)."
        )
    return url


def _result_matches_mode(payload: dict[str, Any], mode: str) -> bool:
    """Confused-deputy guard: the result shape must match the requested mode."""
    response = payload.get("response")
    if not isinstance(response, dict):
        return False
    if mode == "create":
        return bool(response.get("attestationObject"))
    if mode == "get":
        return bool(response.get("signature") and response.get("authenticatorData"))
    return False


@dataclass
class _CeremonyState:
    mode: CeremonyMode
    rp_id: str
    challenge_b64url: str
    allow_credentials: list[dict[str, str]]
    user_id_b64url: str
    timeout_sec: float
    token: str
    done: threading.Event = field(default_factory=threading.Event)
    result: dict[str, Any] | None = None
    error: str | None = None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _resolve_bridge_port(env_path: Any = None) -> int | None:
    """Return configured port, or None to bind an ephemeral OS-assigned port."""
    raw = read_env_optional("WEBAUTHN_BRIDGE_PORT", env_path=env_path)
    if not raw:
        return None
    try:
        port = int(raw.strip())
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _bind_server(preferred_port: int | None) -> tuple[ThreadingHTTPServer, int]:
    if preferred_port is None or preferred_port == 0:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _BridgeHandler)
        return server, int(server.server_address[1])

    for offset in range(_MAX_PORT_TRIES):
        port = preferred_port + offset
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), _BridgeHandler)
            return server, int(server.server_address[1])
        except OSError:
            continue
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BridgeHandler)
    return server, int(server.server_address[1])


class _BridgeHandler(BaseHTTPRequestHandler):
    state: _CeremonyState

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    @property
    def _state(self) -> _CeremonyState:
        return self.server.ceremony_state  # type: ignore[attr-defined]

    @property
    def _bound_port(self) -> int:
        return int(self.server.server_address[1])

    def _valid_host(self) -> bool:
        host_header = self.headers.get("Host", "")
        if not host_header:
            return False
        host = host_header.split(":")[0].lower()
        if host not in {"localhost", "127.0.0.1"}:
            return False
        if ":" in host_header:
            try:
                port = int(host_header.rsplit(":", 1)[-1])
            except ValueError:
                return False
            return port == self._bound_port
        return True

    def _add_security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _send_status(self, status: int) -> None:
        self.send_response(status)
        self._add_security_headers()
        self.end_headers()

    def _reject(self) -> None:
        self._send_status(403)

    def _send_callback_done(self) -> None:
        body = (
            b"<!DOCTYPE html><meta charset=utf-8><title>Antiphoria</title>"
            b"<p>Ceremony complete. You can close this tab.</p>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_bounded_body(self) -> bytes | None:
        """Read the request body, enforcing a present and bounded Content-Length."""
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self._send_status(411)
            return None
        try:
            length = int(raw_len)
        except ValueError:
            self._send_status(400)
            return None
        if length < 0 or length > _MAX_CALLBACK_BODY:
            self._send_status(413)
            return None
        return self.rfile.read(length)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/callback":
            self.send_error(404)
            return
        if not self._valid_host():
            self._reject()
            return

        body = self._read_bounded_body()
        if body is None:
            return

        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        token = ""
        payload: Any = None
        if content_type == "application/x-www-form-urlencoded":
            try:
                fields = parse_qs(body.decode("utf-8"), keep_blank_values=True)
            except UnicodeDecodeError:
                self._send_status(400)
                return
            token = (fields.get("token") or [""])[0]
            result_b64 = (fields.get("result") or [""])[0]
            if result_b64:
                try:
                    payload = json.loads(_b64url_decode(result_b64).decode("utf-8"))
                except Exception:
                    self._send_status(400)
                    return
        else:
            token = self.headers.get(_BRIDGE_TOKEN_HEADER, "")
            try:
                payload = json.loads(body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_status(400)
                return

        if not hmac.compare_digest(token, self._state.token):
            self._reject()
            return

        state = self._state
        if not isinstance(payload, dict):
            state.error = "Malformed ceremony payload."
        elif payload.get("error"):
            state.error = str(payload["error"])
        elif not _result_matches_mode(payload, state.mode):
            state.error = f"Ceremony result does not match requested mode '{state.mode}'."
        else:
            state.result = payload
        state.done.set()
        self._send_callback_done()


def run_ceremony(
    mode: CeremonyMode,
    rp_id: str,
    challenge: bytes,
    allow_credentials: list[dict[str, str]] | None = None,
    *,
    port: int | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SEC,
    env_path: Any = None,
) -> dict[str, Any] | None:
    """Run a browser WebAuthn ceremony and return the credential payload.

    Opens the hosted ceremony page (https://antiphoria.org/bridge.html by
    default), passing the bridge token and ceremony parameters in the URL
    *fragment* so they never reach the page host's access logs. The page
    posts the result back to this loopback server's ``/callback`` endpoint.
    """
    bridge_url = _resolve_bridge_page_url(env_path)
    token = secrets.token_urlsafe(32)
    state = _CeremonyState(
        mode=mode,
        rp_id=rp_id,
        challenge_b64url=_b64url_encode(challenge),
        allow_credentials=allow_credentials or [],
        user_id_b64url=_b64url_encode(os.urandom(32)),
        timeout_sec=timeout,
        token=token,
    )

    server, bound_port = _bind_server(port)
    server.ceremony_state = state  # type: ignore[attr-defined]
    server.daemon_threads = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    params = {
        "token": token,
        "port": str(bound_port),
        "mode": mode,
        "challenge": state.challenge_b64url,
        "timeoutMs": str(int(timeout * 1000)),
    }
    if mode == "create":
        params["userId"] = state.user_id_b64url
    if allow_credentials:
        params["allowCredentials"] = _b64url_encode(
            json.dumps(allow_credentials).encode("utf-8")
        )

    try:
        webbrowser.open(f"{bridge_url}#{urlencode(params)}")
        if not state.done.wait(timeout=timeout):
            return None
        if state.error or state.result is None:
            return None
        if not _result_matches_mode(state.result, mode):
            return None
        return state.result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _parse_attestation_object(attestation_b64: str) -> tuple[str, str] | None:
    """Parse WebAuthn attestationObject CBOR into credential id and COSE public key."""
    try:
        from fido2 import cbor
        from fido2.webauthn import AuthenticatorData
    except ImportError:
        return None

    try:
        obj = cbor.decode(_b64url_decode(attestation_b64))
        auth_data = AuthenticatorData(obj["authData"])
        credential_data = auth_data.credential_data
        if credential_data is None:
            return None
        cred_id = _b64url_encode(credential_data.credential_id)
        pub_key = credential_data.public_key
        if hasattr(pub_key, "__bytes__"):
            pub_key_cose = bytes(pub_key)
        else:
            pub_key_cose = cbor.encode(dict(pub_key))
        pub_key_b64 = _b64url_encode(pub_key_cose)
    except Exception:
        return None
    return cred_id, pub_key_b64


def register_credential_platform(
    repo_path: Any = None,
    env_path: Any = None,
) -> bool:
    """Register a platform (Touch ID) passkey via the browser bridge."""
    rp_id = _resolve_rp_id(env_path)
    if not rp_id:
        return False

    cred_path = _get_credentials_path(env_path=env_path, repo_path=repo_path)
    if cred_path.exists():
        stored = _load_credentials(cred_path)
        if stored.get("credential_id"):
            raise WebAuthnAlreadyRegisteredError(
                f"WebAuthn credential already registered at '{cred_path}'. "
                "Delete that file and remove the macOS passkey in System Settings "
                "→ Passwords before re-registering."
            )

    payload = run_ceremony(
        mode="create",
        rp_id=rp_id,
        challenge=os.urandom(32),
        port=_resolve_bridge_port(env_path),
        env_path=env_path,
    )
    if not payload:
        return False

    attestation_b64 = payload.get("response", {}).get("attestationObject")
    if not attestation_b64:
        return False

    parsed = _parse_attestation_object(attestation_b64)
    if not parsed:
        return False
    cred_id, pub_key_b64 = parsed

    _save_credentials(
        cred_path,
        {
            "credential_id": cred_id,
            "public_key_cose_b64": pub_key_b64,
            "provider": "platform",
            "rp_id": rp_id,
        },
    )
    return True


def get_assertion_platform(
    challenge: bytes,
    repo_path: Any = None,
    env_path: Any = None,
) -> WebAuthnAttestation | None:
    """Get a platform (Touch ID) assertion bound to the given challenge."""
    rp_id = _resolve_rp_id(env_path)
    if not rp_id:
        return None

    credentials_path = _get_credentials_path(env_path=env_path, repo_path=repo_path)
    stored = _load_credentials(credentials_path)
    cred_id = stored.get("credential_id")
    if not cred_id:
        return None

    allow_credentials = [{"id": cred_id, "type": "public-key"}]
    payload = run_ceremony(
        mode="get",
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=allow_credentials,
        port=_resolve_bridge_port(env_path),
        env_path=env_path,
    )
    if not payload:
        return None

    response = payload.get("response", {})
    client_data_b64 = response.get("clientDataJSON")
    auth_data_b64 = response.get("authenticatorData")
    signature_b64 = response.get("signature")
    credential_id = payload.get("rawId") or payload.get("id")
    if not all([client_data_b64, auth_data_b64, signature_b64, credential_id]):
        return None

    try:
        client_data_bytes = _b64url_decode(client_data_b64)
        client_data_hash = hashlib.sha256(client_data_bytes).hexdigest()
    except Exception:
        return None

    return WebAuthnAttestation(
        credentialId=credential_id,
        clientDataJson=client_data_b64,
        clientDataJsonHash=client_data_hash,
        authenticatorData=auth_data_b64,
        signature=signature_b64,
        fmt="platform",
    )
