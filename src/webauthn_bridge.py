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
from urllib.parse import urlparse

from src.env_config import read_env_optional
from src.models import WebAuthnAttestation
from src.webauthn_attestation import (
    _get_credentials_path,
    _load_credentials,
    _resolve_rp_id,
    _save_credentials,
)

CeremonyMode = Literal["create", "get"]
PLATFORM_RP_ID = "localhost"
_BRIDGE_TOKEN_HEADER = "X-Bridge-Token"  # noqa: S105
_BRIDGE_CSP = (
    "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
)
_DEFAULT_TIMEOUT_SEC = 60.0
_MAX_PORT_TRIES = 10


class WebAuthnAlreadyRegisteredError(Exception):
    """Platform passkey already registered for this ledger."""


BRIDGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antiphoria Touch ID Bridge</title>
    <style>
        body { font-family: monospace; background: #111; color: #eee; padding: 40px; }
        pre { background: #000; padding: 20px; border: 1px solid #333; overflow-x: auto; white-space: pre-wrap; }
    </style>
</head>
<body>
    <h2>Antiphoria - Local WebAuthn Bridge</h2>
    <p id="status">Loading ceremony options...</p>
    <pre id="output">Awaiting Touch ID...</pre>
    <script>
        const bridgeToken = new URLSearchParams(location.search).get("token");
        if (!bridgeToken) {
            document.getElementById("status").textContent = "Missing bridge token.";
            throw new Error("Missing bridge token in URL.");
        }

        const bridgeHeaders = {
            "Content-Type": "application/json",
            "X-Bridge-Token": bridgeToken,
        };

        function b64urlToBytes(b64url) {
            const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
            const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
            const raw = atob(b64);
            const arr = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
            return arr;
        }

        function bytesToB64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = "";
            for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
            return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=/g, "");
        }

        async function postResult(payload) {
            const res = await fetch("/result", {
                method: "POST",
                headers: bridgeHeaders,
                body: JSON.stringify(payload),
            });
            if (!res.ok) throw new Error("Bridge rejected ceremony result.");
        }

        async function runCeremony() {
            const statusEl = document.getElementById("status");
            const outputEl = document.getElementById("output");
            try {
                const optionsRes = await fetch("/options", { headers: bridgeHeaders });
                if (!optionsRes.ok) throw new Error("Failed to load ceremony options.");
                const opts = await optionsRes.json();

                const challenge = b64urlToBytes(opts.challenge);
                const allowCredentials = (opts.allowCredentials || []).map((cred) => ({
                    type: "public-key",
                    id: b64urlToBytes(cred.id),
                }));

                let credential;
                if (opts.mode === "create") {
                    statusEl.textContent = "Touch ID registration — approve the macOS prompt.";
                    const userId = b64urlToBytes(opts.userId);
                    credential = await navigator.credentials.create({
                        publicKey: {
                            challenge,
                            rp: { name: "Antiphoria Local Bridge", id: opts.rpId },
                            user: {
                                id: userId,
                                name: "author@localhost",
                                displayName: "Author",
                            },
                            pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                            authenticatorSelection: {
                                authenticatorAttachment: "platform",
                                userVerification: "required",
                            },
                            timeout: opts.timeoutMs,
                            attestation: "none",
                        },
                    });
                } else {
                    statusEl.textContent = "Touch ID assertion — approve the macOS prompt.";
                    credential = await navigator.credentials.get({
                        publicKey: {
                            challenge,
                            rpId: opts.rpId,
                            allowCredentials: allowCredentials.length ? allowCredentials : undefined,
                            userVerification: "required",
                            timeout: opts.timeoutMs,
                        },
                    });
                }

                const payload = {
                    id: credential.id,
                    rawId: bytesToB64url(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
                        authenticatorData: bytesToB64url(credential.response.authenticatorData),
                        signature: bytesToB64url(credential.response.signature),
                    },
                };
                if (opts.mode === "create" && credential.response.attestationObject) {
                    payload.response.attestationObject = bytesToB64url(
                        credential.response.attestationObject
                    );
                }

                await postResult(payload);
                statusEl.textContent = "Ceremony complete. You can close this tab.";
                outputEl.textContent = JSON.stringify(payload, null, 2);
            } catch (err) {
                statusEl.textContent = "Ceremony failed.";
                outputEl.textContent =
                    "Error: " + err.message +
                    "\\n\\n(Did you cancel Touch ID, or run this outside localhost?)";
                try {
                    await postResult({ error: err.message || String(err) });
                } catch (_) {
                    /* ignore secondary failure */
                }
            }
        }

        runCeremony();
    </script>
</body>
</html>
"""


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

    def _authorized(self, *, require_token: bool) -> bool:
        if not self._valid_host():
            return False
        if not require_token:
            return True
        supplied = self.headers.get(_BRIDGE_TOKEN_HEADER, "")
        expected = self._state.token
        return hmac.compare_digest(supplied, expected)

    def _add_security_headers(self, *, html: bool = False) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if html:
            self.send_header("Content-Security-Policy", _BRIDGE_CSP)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers(html=True)
        self.end_headers()
        self.wfile.write(body)

    def _reject(self) -> None:
        self.send_response(403)
        self._add_security_headers()
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._authorized(require_token=False):
                self._reject()
                return
            self._send_html(200, BRIDGE_HTML)
            return
        if path == "/options":
            if not self._authorized(require_token=True):
                self._reject()
                return
            state = self._state
            self._send_json(
                200,
                {
                    "mode": state.mode,
                    "rpId": state.rp_id,
                    "challenge": state.challenge_b64url,
                    "allowCredentials": state.allow_credentials,
                    "userId": state.user_id_b64url,
                    "timeoutMs": int(state.timeout_sec * 1000),
                },
            )
            return
        self.send_error(404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/result":
            self.send_error(404)
            return
        if not self._authorized(require_token=True):
            self._reject()
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error(400)
            return

        state = self._state
        if payload.get("error"):
            state.error = str(payload["error"])
        else:
            state.result = payload
        state.done.set()
        self._send_json(200, {"ok": True})


def run_ceremony(
    mode: CeremonyMode,
    rp_id: str,
    challenge: bytes,
    allow_credentials: list[dict[str, str]] | None = None,
    *,
    port: int | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any] | None:
    """Run a browser WebAuthn ceremony and return the credential payload."""
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

    try:
        webbrowser.open(f"http://localhost:{bound_port}/?token={token}")
        if not state.done.wait(timeout=timeout):
            return None
        if state.error or state.result is None:
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
    if not _resolve_rp_id(env_path):
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
        rp_id=PLATFORM_RP_ID,
        challenge=os.urandom(32),
        port=_resolve_bridge_port(env_path),
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
            "rp_id": PLATFORM_RP_ID,
        },
    )
    return True


def get_assertion_platform(
    challenge: bytes,
    repo_path: Any = None,
    env_path: Any = None,
) -> WebAuthnAttestation | None:
    """Get a platform (Touch ID) assertion bound to the given challenge."""
    if not _resolve_rp_id(env_path):
        return None

    credentials_path = _get_credentials_path(env_path=env_path, repo_path=repo_path)
    stored = _load_credentials(credentials_path)
    cred_id = stored.get("credential_id")
    if not cred_id:
        return None

    allow_credentials = [{"id": cred_id, "type": "public-key"}]
    payload = run_ceremony(
        mode="get",
        rp_id=PLATFORM_RP_ID,
        challenge=challenge,
        allow_credentials=allow_credentials,
        port=_resolve_bridge_port(env_path),
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
        clientDataJsonHash=client_data_hash,
        authenticatorData=auth_data_b64,
        signature=signature_b64,
        fmt="platform",
    )
