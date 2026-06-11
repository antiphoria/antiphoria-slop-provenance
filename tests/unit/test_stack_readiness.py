"""Unit tests for full-stack ceremony readiness checks."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from src.runtime.stack_readiness import assert_ceremony_stack_ready, check_ceremony_stack


class StackReadinessTest(unittest.TestCase):
    _ENV_KEYS = (
        "PQC_PRIVATE_KEY_PATH",
        "OQS_PRIVATE_KEY_PATH",
        "ED25519_PRIVATE_KEY_PATH",
        "WEBAUTHN_RP_ID",
        "RFC3161_TSA_URL",
        "RFC3161_CA_CERT_PATH",
        "ENABLE_OTS_FORGE",
        "ENABLE_C2PA",
        "C2PA_SIGN_CERT_CHAIN_PATH",
        "C2PA_PRIVATE_KEY_PATH",
    )

    def setUp(self) -> None:
        self._env_temp = tempfile.TemporaryDirectory()
        self._env_path = Path(self._env_temp.name) / ".env"
        self._repo_temp = tempfile.TemporaryDirectory()
        self._repo_path = Path(self._repo_temp.name)
        self._key_dir = Path(self._env_temp.name) / "keys"
        self._key_dir.mkdir()
        (self._key_dir / "pqc.key").write_bytes(b"pqc")
        (self._key_dir / "ed25519.pem").write_bytes(b"ed25519")
        (self._key_dir / "tsa-ca.pem").write_bytes(b"cert")
        self._saved_env = {key: os.environ.pop(key, None) for key in self._ENV_KEYS}

    def tearDown(self) -> None:
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._env_temp.cleanup()
        self._repo_temp.cleanup()

    def _write_env(self, lines: list[str]) -> None:
        self._env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_full_stack_ready_when_all_layers_configured(self) -> None:
        self._write_env(
            [
                f"PQC_PRIVATE_KEY_PATH={self._key_dir / 'pqc.key'}",
                f"ED25519_PRIVATE_KEY_PATH={self._key_dir / 'ed25519.pem'}",
                "WEBAUTHN_RP_ID=localhost",
                "RFC3161_TSA_URL=http://timestamp.digicert.com",
                f"RFC3161_CA_CERT_PATH={self._key_dir / 'tsa-ca.pem'}",
                "ENABLE_OTS_FORGE=false",
                "ENABLE_C2PA=false",
                f"ORCHESTRATOR_STATE_DIR={self._env_temp.name}/state",
            ]
        )
        state_dir = Path(self._env_temp.name) / "state"
        state_dir.mkdir()
        cred_path = state_dir / ".webauthn-credentials.json"
        cred_path.write_text('{"credential_id": "abc"}', encoding="utf-8")
        results = check_ceremony_stack(
            env_path=self._env_path,
            repository_path=self._repo_path,
            require_webauthn=True,
        )
        self.assertTrue(all(result.ok for result in results))

    def test_assert_raises_when_webauthn_credentials_missing(self) -> None:
        self._write_env(
            [
                f"PQC_PRIVATE_KEY_PATH={self._key_dir / 'pqc.key'}",
                f"ED25519_PRIVATE_KEY_PATH={self._key_dir / 'ed25519.pem'}",
                "WEBAUTHN_RP_ID=localhost",
                "RFC3161_TSA_URL=http://timestamp.digicert.com",
                f"RFC3161_CA_CERT_PATH={self._key_dir / 'tsa-ca.pem'}",
                "ENABLE_OTS_FORGE=false",
                "ENABLE_C2PA=false",
            ]
        )
        with self.assertRaises(RuntimeError):
            assert_ceremony_stack_ready(
                env_path=self._env_path,
                repository_path=self._repo_path,
                require_webauthn=True,
            )

    def test_webauthn_not_required_with_flag(self) -> None:
        self._write_env(
            [
                f"PQC_PRIVATE_KEY_PATH={self._key_dir / 'pqc.key'}",
                f"ED25519_PRIVATE_KEY_PATH={self._key_dir / 'ed25519.pem'}",
                "RFC3161_TSA_URL=http://timestamp.digicert.com",
                f"RFC3161_CA_CERT_PATH={self._key_dir / 'tsa-ca.pem'}",
                "ENABLE_OTS_FORGE=false",
                "ENABLE_C2PA=false",
            ]
        )
        assert_ceremony_stack_ready(
            env_path=self._env_path,
            repository_path=self._repo_path,
            require_webauthn=False,
        )


if __name__ == "__main__":
    unittest.main()
