"""Tests for the macOS Touch ID WebAuthn bridge hardening (hosted-page flow)."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from src.webauthn_bridge import (
    _BRIDGE_TOKEN_HEADER,
    WebAuthnAlreadyRegisteredError,
    _bind_server,
    _CeremonyState,
    _parse_attestation_object,
    _resolve_bridge_page_url,
    _resolve_bridge_port,
    _result_matches_mode,
    register_credential_platform,
    run_ceremony,
)

_KNOWN_ATTESTATION_B64 = (
    "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2Nd"
    "AAAAAPv8MAcVTk7MjAtuAgVX170AFAnOQfdLgD-YuSPVVVg56d26qPOppQECAyYgASFYILIOF4A_ys-l14jxmZVN"
    "xGiYZzSAMF4wGXVB_-dAncquIlggHiCn1cJt_nz3QCpUYh-HL6xRMHWEhSO3On9ppTZCtfI"
)
_TEST_BRIDGE_HEADER = "bridge-secret"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _get_payload() -> dict:
    """A well-formed 'get' (assertion) result payload."""
    return {
        "id": "cred",
        "rawId": "Y3JlZA",
        "type": "public-key",
        "mode": "get",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
            "authenticatorData": "YXV0aERhdGE",
            "signature": "c2ln",
        },
    }


def _bridge_request(
    url: str,
    *,
    data: bytes | None = None,
    method: str | None = None,
    headers: dict[str, str] | None = None,
) -> urllib.request.Request:
    return urllib.request.Request(  # noqa: S310
        url,
        data=data,
        method=method,
        headers=headers or {},
    )


def _urlopen(req: urllib.request.Request) -> object:
    return urllib.request.urlopen(req)  # noqa: S310


def _start_test_server(
    *,
    mode: str = "get",
    bridge_header: str = _TEST_BRIDGE_HEADER,
) -> tuple[object, int, threading.Thread]:
    state = _CeremonyState(
        mode=mode,
        rp_id="antiphoria.org",
        challenge_b64url="Y2hhbGxlbmdl",
        allow_credentials=[],
        user_id_b64url="dXNlcg",
        timeout_sec=5.0,
        token=bridge_header,
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


class BridgePageUrlTest(unittest.TestCase):
    """Validate the hosted ceremony page URL resolver."""

    def test_defaults_to_production_https_page(self) -> None:
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("WEBAUTHN_RP_ID=antiphoria.org\n", encoding="utf-8")
            self.assertEqual(
                _resolve_bridge_page_url(env_path=env_file),
                "https://antiphoria.org/bridge.html",
            )

    def test_rejects_non_https_remote(self) -> None:
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "WEBAUTHN_BRIDGE_URL=http://evil.example/bridge.html\n", encoding="utf-8"
            )
            with self.assertRaises(RuntimeError):
                _resolve_bridge_page_url(env_path=env_file)

    def test_allows_http_loopback_for_testing(self) -> None:
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "WEBAUTHN_BRIDGE_URL=http://localhost:9000/bridge.html\n", encoding="utf-8"
            )
            self.assertEqual(
                _resolve_bridge_page_url(env_path=env_file),
                "http://localhost:9000/bridge.html",
            )


class ResultModeGuardTest(unittest.TestCase):
    """Confused-deputy guard: result shape must match the requested mode."""

    def test_create_requires_attestation_object(self) -> None:
        self.assertTrue(
            _result_matches_mode({"response": {"attestationObject": "x"}}, "create")
        )
        self.assertFalse(
            _result_matches_mode({"response": {"signature": "x"}}, "create")
        )

    def test_get_requires_signature_and_auth_data(self) -> None:
        self.assertTrue(
            _result_matches_mode(
                {"response": {"signature": "s", "authenticatorData": "a"}}, "get"
            )
        )
        self.assertFalse(_result_matches_mode({"response": {"signature": "s"}}, "get"))

    def test_missing_response_fails(self) -> None:
        self.assertFalse(_result_matches_mode({}, "get"))


class WebAuthnBridgeSecurityTest(unittest.TestCase):
    """Validate callback auth, host checks, and registration guards."""

    def test_resolve_bridge_port_defaults_to_ephemeral(self) -> None:
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("WEBAUTHN_RP_ID=antiphoria.org\n", encoding="utf-8")
            self.assertIsNone(_resolve_bridge_port(env_path=env_file))

    def test_bind_server_ephemeral_uses_os_assigned_port(self) -> None:
        server, port = _bind_server(None)
        self.assertNotEqual(port, 0)
        try:
            self.assertGreater(port, 0)
            self.assertEqual(int(server.server_address[1]), port)
        finally:
            server.server_close()

    def test_get_endpoints_are_gone(self) -> None:
        # No do_GET handler exists at all, so GET is an unsupported method (501).
        server, port, thread = _start_test_server()
        try:
            for path in ("/", "/options"):
                req = _bridge_request(
                    f"http://127.0.0.1:{port}{path}",
                    headers={"Host": f"localhost:{port}"},
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    _urlopen(req)
                self.assertEqual(ctx.exception.code, 501)
        finally:
            _stop_test_server(server, thread)

    def test_callback_rejects_missing_token(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = _bridge_request(
                f"http://127.0.0.1:{port}/callback",
                data=json.dumps(_get_payload()).encode("utf-8"),
                method="POST",
                headers={
                    "Host": f"localhost:{port}",
                    "Content-Type": "application/json",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                _urlopen(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            _stop_test_server(server, thread)

    def test_callback_rejects_bad_host(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = _bridge_request(
                f"http://127.0.0.1:{port}/callback",
                data=json.dumps(_get_payload()).encode("utf-8"),
                method="POST",
                headers={
                    "Host": f"evil.example:{port}",
                    "Content-Type": "application/json",
                    _BRIDGE_TOKEN_HEADER: _TEST_BRIDGE_HEADER,
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                _urlopen(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            _stop_test_server(server, thread)

    def test_callback_accepts_json_with_valid_token(self) -> None:
        server, port, thread = _start_test_server()
        try:
            req = _bridge_request(
                f"http://127.0.0.1:{port}/callback",
                data=json.dumps(_get_payload()).encode("utf-8"),
                method="POST",
                headers={
                    "Host": f"localhost:{port}",
                    "Content-Type": "application/json",
                    _BRIDGE_TOKEN_HEADER: _TEST_BRIDGE_HEADER,
                },
            )
            with _urlopen(req) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertTrue(server.ceremony_state.done.is_set())  # type: ignore[attr-defined]
            self.assertIsNotNone(server.ceremony_state.result)  # type: ignore[attr-defined]
        finally:
            _stop_test_server(server, thread)

    def test_callback_accepts_form_post_with_valid_token(self) -> None:
        server, port, thread = _start_test_server()
        try:
            result_b64 = _b64url(json.dumps(_get_payload()).encode("utf-8"))
            body = f"token={_TEST_BRIDGE_HEADER}&result={result_b64}".encode("utf-8")
            req = _bridge_request(
                f"http://127.0.0.1:{port}/callback",
                data=body,
                method="POST",
                headers={
                    "Host": f"localhost:{port}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            with _urlopen(req) as response:
                self.assertEqual(response.status, 200)
            self.assertTrue(server.ceremony_state.done.is_set())  # type: ignore[attr-defined]
            self.assertIsNotNone(server.ceremony_state.result)  # type: ignore[attr-defined]
        finally:
            _stop_test_server(server, thread)

    def test_callback_rejects_oversized_body(self) -> None:
        server, port, thread = _start_test_server()
        try:
            oversized = b"x" * (65536 + 1)
            req = _bridge_request(
                f"http://127.0.0.1:{port}/callback",
                data=oversized,
                method="POST",
                headers={
                    "Host": f"localhost:{port}",
                    "Content-Type": "application/json",
                    _BRIDGE_TOKEN_HEADER: _TEST_BRIDGE_HEADER,
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                _urlopen(req)
            self.assertEqual(ctx.exception.code, 413)
        finally:
            _stop_test_server(server, thread)

    def test_callback_rejects_result_mode_mismatch(self) -> None:
        # Server is in 'create' mode but receives a 'get'-shaped payload.
        server, port, thread = _start_test_server(mode="create")
        try:
            req = _bridge_request(
                f"http://127.0.0.1:{port}/callback",
                data=json.dumps(_get_payload()).encode("utf-8"),
                method="POST",
                headers={
                    "Host": f"localhost:{port}",
                    "Content-Type": "application/json",
                    _BRIDGE_TOKEN_HEADER: _TEST_BRIDGE_HEADER,
                },
            )
            with _urlopen(req) as response:
                self.assertEqual(response.status, 200)
            state = server.ceremony_state  # type: ignore[attr-defined]
            self.assertTrue(state.done.is_set())
            self.assertIsNone(state.result)
            self.assertIsNotNone(state.error)
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
                patch("src.webauthn_bridge._resolve_rp_id", return_value="antiphoria.org"),
                self.assertRaises(WebAuthnAlreadyRegisteredError),
            ):
                register_credential_platform(repo_path=repo, env_path=None)

    def test_run_ceremony_opens_hosted_page_and_accepts_callback(self) -> None:
        captured: dict[str, str] = {}

        def fake_open(url: str, new: int = 0, autoraise: bool = True) -> bool:
            captured["url"] = url
            split = urlsplit(url)
            frag = parse_qs(split.fragment)
            token = frag["token"][0]
            port = frag["port"][0]
            base = f"http://127.0.0.1:{port}"
            result_b64 = _b64url(json.dumps(_get_payload()).encode("utf-8"))
            body = f"token={token}&result={result_b64}".encode("utf-8")
            _urlopen(
                _bridge_request(
                    f"{base}/callback",
                    data=body,
                    method="POST",
                    headers={
                        "Host": f"localhost:{port}",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
            )
            return True

        with patch("webbrowser.open", fake_open):
            result = run_ceremony(
                "get",
                "antiphoria.org",
                b"challenge-bytes-here-1234567890ab",
                allow_credentials=[{"id": "cred", "type": "public-key"}],
                port=0,
                timeout=5,
            )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["id"], "cred")
        self.assertTrue(captured["url"].startswith("https://antiphoria.org/bridge.html#"))
        self.assertIn("token=", captured["url"])
        # Token rides in the fragment, never the query string.
        self.assertEqual(urlsplit(captured["url"]).query, "")

    def test_run_ceremony_rejects_mode_mismatched_result(self) -> None:
        def fake_open(url: str, new: int = 0, autoraise: bool = True) -> bool:
            split = urlsplit(url)
            frag = parse_qs(split.fragment)
            token = frag["token"][0]
            port = frag["port"][0]
            base = f"http://127.0.0.1:{port}"
            # 'create' was requested; return a 'get'-shaped payload.
            result_b64 = _b64url(json.dumps(_get_payload()).encode("utf-8"))
            body = f"token={token}&result={result_b64}".encode("utf-8")
            _urlopen(
                _bridge_request(
                    f"{base}/callback",
                    data=body,
                    method="POST",
                    headers={
                        "Host": f"localhost:{port}",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
            )
            return True

        with patch("webbrowser.open", fake_open):
            result = run_ceremony(
                "create",
                "antiphoria.org",
                b"challenge-bytes-here-1234567890ab",
                port=0,
                timeout=5,
            )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
