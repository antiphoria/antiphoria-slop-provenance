"""Tests for the macOS Touch ID WebAuthn bridge hardening."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from src.webauthn_bridge import (
    _BRIDGE_TOKEN_HEADER,
    WebAuthnAlreadyRegisteredError,
    _bind_server,
    _CeremonyState,
    _parse_attestation_object,
    _resolve_bridge_port,
    register_credential_platform,
    run_ceremony,
)

_KNOWN_ATTESTATION_B64 = (
    "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2Nd"
    "AAAAAPv8MAcVTk7MjAtuAgVX170AFAnOQfdLgD-YuSPVVVg56d26qPOppQECAyYgASFYILIOF4A_ys-l14jxmZVN"
    "xGiYZzSAMF4wGXVB_-dAncquIlggHiCn1cJt_nz3QCpUYh-HL6xRMHWEhSO3On9ppTZCtfI"
)


def _start_test_server(token: str = "bridge-secret") -> tuple[object, int, threading.Thread]:
    state = _CeremonyState(
        mode="get",
        rp_id="localhost",
        challenge_b64url="Y2hhbGxlbmdl",
        allow_credentials=[],
        user_id_b64url="dXNlcg",
        timeout_sec=5.0,
        token=token,
    )
    server, port = _bind_server(None)
    server.ceremony_state = state  # type: ignore[attr-defined]
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


def _stop_test_server(server: object, thread: threading.Thread) -> None:
    server.shutdown()  # type: ignore[attr-defined]
    server.server_close()  # type: ignore[attr-defined]
    thread.join(timeout=2.0)


class WebAuthnBridgeSecurityTest(unittest.TestCase):
    """Validate bridge auth, host checks, and registration guards."""

    def test_resolve_bridge_port_defaults_to_ephemeral(self) -> None:
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("WEBAUTHN_RP_ID=localhost\n", encoding="utf-8")
            self.assertIsNone(_resolve_bridge_port(env_path=env_file))

    def test_bind_server_ephemeral_uses_os_assigned_port(self) -> None:
        server, port = _bind_server(None)
        self.assertNotEqual(port, 0)
        try:
            self.assertGreater(port, 0)
            self.assertEqual(int(server.server_address[1]), port)
        finally:
            server.server_close()

    def test_options_rejects_missing_token(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/options",
                headers={"Host": f"localhost:{port}"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            _stop_test_server(server, thread)

    def test_options_rejects_bad_host(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/options",
                headers={
                    "Host": f"evil.example:{port}",
                    _BRIDGE_TOKEN_HEADER: "bridge-secret",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            _stop_test_server(server, thread)

    def test_options_accepts_valid_token_and_host(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/options",
                headers={
                    "Host": f"localhost:{port}",
                    _BRIDGE_TOKEN_HEADER: "bridge-secret",
                },
            )
            with urllib.request.urlopen(req) as response:
                payload = json.loads(response.read().decode("utf-8"))
            self.assertEqual(payload["mode"], "get")
            self.assertEqual(payload["rpId"], "localhost")
            self.assertIn("Cache-Control", response.headers)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        finally:
            _stop_test_server(server, thread)

    def test_result_rejects_missing_token(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/result",
                data=b"{}",
                method="POST",
                headers={
                    "Host": f"localhost:{port}",
                    "Content-Type": "application/json",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            _stop_test_server(server, thread)

    def test_result_accepts_valid_token_and_host(self) -> None:
        server, port, thread = _start_test_server()
        try:
            payload = {
                "id": "cred",
                "rawId": "Y3JlZA",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                    "authenticatorData": "YXV0aERhdGE",
                    "signature": "c2ln",
                },
            }
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/result",
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers={
                    "Host": f"localhost:{port}",
                    "Content-Type": "application/json",
                    _BRIDGE_TOKEN_HEADER: "bridge-secret",
                },
            )
            with urllib.request.urlopen(req) as response:
                body = json.loads(response.read().decode("utf-8"))
            self.assertEqual(body, {"ok": True})
            self.assertTrue(server.ceremony_state.done.is_set())  # type: ignore[attr-defined]
        finally:
            _stop_test_server(server, thread)

    def test_root_serves_html_without_token_but_requires_valid_host(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/",
                headers={"Host": f"localhost:{port}"},
            )
            with urllib.request.urlopen(req) as response:
                html = response.read().decode("utf-8")
            self.assertIn("Antiphoria - Local WebAuthn Bridge", html)
            self.assertIn("X-Bridge-Token", html)
            self.assertIn("attestation: \"none\"", html)
            self.assertIn("Content-Security-Policy", response.headers)
            self.assertIn("connect-src 'self'", response.headers["Content-Security-Policy"])
        finally:
            _stop_test_server(server, thread)

    def test_parse_attestation_object_handles_none_attestation(self) -> None:
        parsed = _parse_attestation_object(_KNOWN_ATTESTATION_B64)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        cred_id, _pub_key_b64 = parsed
        self.assertEqual(cred_id, "Cc5B90uAP5i5I9VVWDnp3bqo86k")

    def test_register_credential_platform_rejects_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            cred_path = repo / ".webauthn-credentials.json"
            cred_path.write_text(
                json.dumps({"credential_id": "existing"}),
                encoding="utf-8",
            )
            with (
                patch("src.webauthn_bridge._resolve_rp_id", return_value="localhost"),
                self.assertRaises(WebAuthnAlreadyRegisteredError),
            ):
                register_credential_platform(repo_path=repo, env_path=None)

    def test_run_ceremony_requires_bridge_token_in_browser_flow(self) -> None:
        captured: dict[str, str] = {}

        def fake_open(url: str, new: int = 0, autoraise: bool = True) -> bool:
            captured["url"] = url
            port = url.split("localhost:")[1].split("/")[0]
            token = url.split("token=")[1]
            base = f"http://127.0.0.1:{port}"

            with self.assertRaises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(
                    urllib.request.Request(
                        f"{base}/options",
                        headers={"Host": f"localhost:{port}"},
                    )
                )
            self.assertEqual(missing.exception.code, 403)

            payload = {
                "id": "cred",
                "rawId": "Y3JlZA",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                    "authenticatorData": "YXV0aERhdGE",
                    "signature": "c2ln",
                },
            }
            urllib.request.urlopen(
                urllib.request.Request(
                    f"{base}/result",
                    data=json.dumps(payload).encode("utf-8"),
                    method="POST",
                    headers={
                        "Host": f"localhost:{port}",
                        "Content-Type": "application/json",
                        _BRIDGE_TOKEN_HEADER: token,
                    },
                )
            )
            return True

        with patch("webbrowser.open", fake_open):
            result = run_ceremony(
                "get",
                "localhost",
                b"challenge-bytes-here-1234567890ab",
                port=0,
                timeout=5,
            )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["id"], "cred")
        self.assertIn("token=", captured["url"])


if __name__ == "__main__":
    unittest.main()
