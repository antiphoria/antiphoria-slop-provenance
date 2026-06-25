"""Tests for operator pseudonym salt derivation and guards."""

from __future__ import annotations

import base64
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from src.models import (
    Artifact,
    GenerationContext,
    Hyperparameters,
    Provenance,
    RegistrationCeremony,
    SignatureBlock,
    VerificationAnchor,
)
from src.pseudonym import (
    derive_pseudonym_hash,
    get_pseudonym_hash,
    resolve_pseudonym_salt,
    salt_appears_in_text,
)

_STRONG_SALT_B64 = base64.urlsafe_b64encode(b"a" * 32).decode("ascii").rstrip("=")
_WEAK_SALT = "short"


def _sample_artifact(ceremony: RegistrationCeremony | None) -> Artifact:
    return Artifact(
        title="Title",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        contentType="text/markdown",
        license="ARR",
        provenance=Provenance(
            source="human",
            engineVersion="v1",
            modelId="human",
            generationContext=GenerationContext(
                systemInstruction="si",
                prompt="N/A",
                hyperparameters=Hyperparameters(
                    temperature=0.0,
                    topP=1.0,
                    topK=0,
                ),
            ),
        ),
        signature=SignatureBlock(
            artifactHash="a" * 64,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="fp"),
        ),
    )


class PseudonymModuleTest(unittest.TestCase):
    def test_derive_pseudonym_hash_is_deterministic(self) -> None:
        salt = b"x" * 32
        first = derive_pseudonym_hash(salt)
        second = derive_pseudonym_hash(salt)
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[a-f0-9]{64}$")

    def test_different_salts_produce_different_hashes(self) -> None:
        self.assertNotEqual(
            derive_pseudonym_hash(b"a" * 32),
            derive_pseudonym_hash(b"b" * 32),
        )

    def test_entropy_floor_rejects_weak_salt(self) -> None:
        with self.assertRaises(RuntimeError, msg="at least 16 bytes"):
            derive_pseudonym_hash(_WEAK_SALT.encode("utf-8"))

    def test_unset_returns_none(self) -> None:
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("WEBAUTHN_RP_ID=localhost\n", encoding="utf-8")
            self.assertIsNone(get_pseudonym_hash(env_path=env_file))

    def test_env_var_produces_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            with patch.dict(os.environ, {"OPERATOR_PSEUDONYM_SALT": _STRONG_SALT_B64}, clear=True):
                digest = get_pseudonym_hash(env_path=env_file)
        self.assertIsNotNone(digest)
        assert digest is not None
        self.assertEqual(digest, derive_pseudonym_hash(b"a" * 32))

    def test_file_path_takes_precedence_over_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            salt_path = Path(temp_dir) / "pseudonym.salt"
            salt_path.write_text(_STRONG_SALT_B64, encoding="utf-8")
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "\n".join(
                    [
                        f"OPERATOR_PSEUDONYM_SALT_PATH={salt_path}",
                        f"OPERATOR_PSEUDONYM_SALT={base64.urlsafe_b64encode(b'b' * 32).decode().rstrip('=')}",
                    ]
                ),
                encoding="utf-8",
            )
            digest = get_pseudonym_hash(env_path=env_file)
        self.assertEqual(digest, derive_pseudonym_hash(b"a" * 32))

    def test_leak_guard_detects_raw_and_base64_forms(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            with patch.dict(os.environ, {"OPERATOR_PSEUDONYM_SALT": _STRONG_SALT_B64}, clear=True):
                self.assertTrue(salt_appears_in_text(env_file, f"prefix {_STRONG_SALT_B64} suffix"))
                self.assertTrue(salt_appears_in_text(env_file, "contains " + ("a" * 32)))

    def test_leak_guard_ignores_when_unset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            with patch.dict(os.environ, {}, clear=True):
                self.assertFalse(salt_appears_in_text(env_file, _STRONG_SALT_B64))

    def test_registration_ceremony_accepts_valid_hash(self) -> None:
        digest = derive_pseudonym_hash(b"z" * 32)
        ceremony = RegistrationCeremony(
            registrationUtcMs=1,
            orchestratorGitCommit="abc",
            operatorPseudonymHash=digest,
        )
        self.assertEqual(ceremony.operator_pseudonym_hash, digest)

    def test_registration_ceremony_rejects_invalid_hash(self) -> None:
        with self.assertRaises(ValidationError):
            RegistrationCeremony(
                registrationUtcMs=1,
                orchestratorGitCommit="abc",
                operatorPseudonymHash="not-a-valid-hash",
            )

    def test_resolve_pseudonym_salt_missing_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "OPERATOR_PSEUDONYM_SALT_PATH=/does/not/exist/pseudonym.salt\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError, msg="not found"):
                resolve_pseudonym_salt(env_path=env_file)


if __name__ == "__main__":
    unittest.main()
