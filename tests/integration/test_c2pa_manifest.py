"""Tests for C2PA sidecar generation behavior."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from src.canonicalization import compute_payload_hash
from src.adapters.c2pa_manifest import (
    _normalize_private_key_to_pkcs8,
    _SDK_CARRIER_FORMAT,
    _SDK_MARKDOWN_ASSERTION_LABEL,
    build_c2pa_validation_payload,
    build_c2pa_sidecar_manifest,
    build_sdk_bridge_payload,
    resolve_c2pa_mode,
    validate_c2pa_sidecar,
)
from src.models import (
    Artifact,
    GenerationContext,
    Hyperparameters,
    Provenance,
)


class _FakeC2paModule:
    last_payload: bytes | None = None
    last_format: str | None = None
    last_manifest_json: object | None = None
    reader_manifest_store: dict[str, object] | None = None

    class C2paSigningAlg:
        ES256 = "ES256"

    class C2paSignerInfo:
        def __init__(
            self,
            alg: object,
            sign_cert: bytes,
            private_key: bytes,
            ta_url: str | None,
        ) -> None:
            _ = (alg, sign_cert, private_key, ta_url)

    class Signer:
        @classmethod
        def from_info(cls, signer_info: object) -> "_FakeC2paModule.Signer":
            _ = signer_info
            return cls()

        def close(self) -> None:
            return None

    class Builder:
        def __init__(self, manifest_json: object) -> None:
            self._manifest_json = manifest_json

        @classmethod
        def get_supported_mime_types(cls) -> list[str]:
            _ = cls
            return ["image/jpeg", "text/xml", "application/xml"]

        @classmethod
        def from_json(cls, manifest_json: object) -> "_FakeC2paModule.Builder":
            if not isinstance(manifest_json, str):
                raise TypeError("from_json expects JSON string")
            return cls(manifest_json)

        def set_no_embed(self) -> None:
            return None

        def sign(
            self,
            signer: object,
            format: str,
            source: object,
            dest: object | None = None,
        ) -> bytes:
            _ = signer
            _FakeC2paModule.last_payload = source.read()
            _FakeC2paModule.last_format = format
            _FakeC2paModule.last_manifest_json = self._manifest_json
            if dest is not None:
                dest.write(b"FAKE-C2PA-SIDECAR")
            return b"FAKE-C2PA-SIDECAR"

        def close(self) -> None:
            return None

    class Reader:
        def __init__(
            self,
            asset_format: str,
            source: object,
            manifest_data: bytes | None = None,
        ) -> None:
            _ = (source, manifest_data)
            self._asset_format = asset_format

        def get_validation_state(self) -> str:
            _ = self._asset_format
            return "valid"

        def get_validation_results(self) -> dict[str, object]:
            return {}

        def json(self) -> str:
            if _FakeC2paModule.reader_manifest_store is None:
                raise RuntimeError("reader manifest store not configured")
            return json.dumps(_FakeC2paModule.reader_manifest_store)

        def close(self) -> None:
            return None


class C2PAManifestTest(unittest.TestCase):
    """Validate deterministic C2PA sidecar hashing."""

    def _build_artifact(self) -> Artifact:
        return Artifact(
            title="INCIDENT_TEST",
            timestamp=datetime.now(timezone.utc),
            contentType="text/markdown",
            license="CC0-1.0",
            provenance=Provenance(
                source="synthetic",
                engineVersion="antiphoria-slop-provenance-v1.0.0",
                modelId="gemini-2.5-flash",
                generationContext=GenerationContext(
                    systemInstruction="test",
                    prompt="test prompt",
                    hyperparameters=Hyperparameters(
                        temperature=0.1,
                        topP=0.9,
                        topK=5,
                    ),
                ),
            ),
        )

    def test_manifest_hash_is_stable_for_same_input(self) -> None:
        artifact = self._build_artifact()
        first = build_c2pa_sidecar_manifest(artifact, "payload", mode="mvp")
        second = build_c2pa_sidecar_manifest(artifact, "payload", mode="mvp")
        self.assertEqual(first.manifest_hash, second.manifest_hash)
        self.assertEqual(first.manifest_bytes, second.manifest_bytes)

    def test_mode_defaults_to_mvp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("", encoding="utf-8")
            self.assertEqual(resolve_c2pa_mode(env_path=env_path), "mvp")

    def test_sdk_mode_requires_certificate_paths(self) -> None:
        artifact = self._build_artifact()
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("C2PA_MODE=sdk\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                build_c2pa_sidecar_manifest(
                    artifact,
                    "payload",
                    env_path=env_path,
                )

    def test_normalize_private_key_accepts_ec_and_pkcs8(self) -> None:
        """EC PRIVATE KEY and PKCS#8 formats are normalized to PKCS#8."""
        key = ec.generate_private_key(ec.SECP256R1())
        ec_pem = key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,
            NoEncryption(),
        ).decode()
        self.assertIn("BEGIN EC PRIVATE KEY", ec_pem)
        pkcs8 = _normalize_private_key_to_pkcs8(ec_pem)
        self.assertIn("BEGIN PRIVATE KEY", pkcs8)
        self.assertNotIn("EC PRIVATE KEY", pkcs8)
        # PKCS#8 input passes through (idempotent)
        pkcs8_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        normalized = _normalize_private_key_to_pkcs8(pkcs8_pem)
        self.assertEqual(normalized, pkcs8_pem)

    def test_sdk_bridge_payload_is_deterministic(self) -> None:
        artifact = self._build_artifact()
        first = build_sdk_bridge_payload(artifact, "payload")
        second = build_sdk_bridge_payload(artifact, "payload")
        self.assertEqual(first.payload_format, "text/xml")
        self.assertEqual(first.payload_bytes, second.payload_bytes)
        self.assertIn(b"<payloadSha256>", first.payload_bytes)

    def test_sdk_provider_signs_bridge_payload_bytes(self) -> None:
        artifact = self._build_artifact()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            cert_path = temp_path / "cert.pem"
            key_path = temp_path / "key.pem"
            cert_path.write_text("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n")
            # Valid EC P-256 key (PKCS#8) for C2PA ES256; normalization accepts EC or PKCS#8
            key = ec.generate_private_key(ec.SECP256R1())
            key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
            key_path.write_text(key_pem)
            env_path = temp_path / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "C2PA_MODE=sdk",
                        f"C2PA_SIGN_CERT_CHAIN_PATH={cert_path}",
                        f"C2PA_PRIVATE_KEY_PATH={key_path}",
                        "C2PA_SIGNING_ALG=ES256",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            payload_bytes, payload_format = build_c2pa_validation_payload(
                artifact,
                "payload",
                mode="sdk",
            )
            self.assertEqual(payload_format, _SDK_CARRIER_FORMAT)
            with patch(
                "src.adapters.c2pa_manifest._load_c2pa_module",
                return_value=_FakeC2paModule,
            ):
                sidecar = build_c2pa_sidecar_manifest(
                    artifact,
                    "payload",
                    env_path=env_path,
                )

        self.assertEqual(sidecar.manifest_bytes, b"FAKE-C2PA-SIDECAR")
        self.assertEqual(_FakeC2paModule.last_format, _SDK_CARRIER_FORMAT)
        self.assertEqual(
            _FakeC2paModule.last_payload,
            payload_bytes,
        )
        self.assertIsInstance(_FakeC2paModule.last_manifest_json, str)
        manifest_json_obj = json.loads(_FakeC2paModule.last_manifest_json)
        assertions = manifest_json_obj["assertions"]
        markdown_assertion = next(
            assertion
            for assertion in assertions
            if assertion["label"] == _SDK_MARKDOWN_ASSERTION_LABEL
        )
        self.assertEqual(markdown_assertion["data"]["content"], "payload")
        self.assertEqual(
            markdown_assertion["data"]["payloadHash"],
            compute_payload_hash("payload"),
        )

    def test_sdk_validation_rejects_missing_markdown_assertion(self) -> None:
        artifact = self._build_artifact()
        payload = "payload"
        payload_bytes, payload_format = build_c2pa_validation_payload(
            artifact,
            payload,
            mode="sdk",
        )
        _FakeC2paModule.reader_manifest_store = {
            "active_manifest": "manifest-1",
            "manifests": {"manifest-1": {"assertions": []}},
        }
        with patch(
            "src.adapters.c2pa_manifest._load_c2pa_module",
            return_value=_FakeC2paModule,
        ):
            result = validate_c2pa_sidecar(
                payload_bytes=payload_bytes,
                manifest_bytes=b"fake-sidecar",
                content_type=artifact.content_type,
                payload_format=payload_format,
                body_for_mvp=payload,
            )
        self.assertFalse(result.valid)
        self.assertIn("missing or malformed", "; ".join(result.errors))

    def test_sdk_validation_rejects_payload_hash_mismatch(self) -> None:
        artifact = self._build_artifact()
        payload = "payload"
        payload_bytes, payload_format = build_c2pa_validation_payload(
            artifact,
            payload,
            mode="sdk",
        )
        _FakeC2paModule.reader_manifest_store = {
            "active_manifest": "manifest-1",
            "manifests": {
                "manifest-1": {
                    "assertions": [
                        {
                            "label": _SDK_MARKDOWN_ASSERTION_LABEL,
                            "data": {
                                "content": payload,
                                "payloadHash": "deadbeef",
                                "contentType": artifact.content_type,
                            },
                        }
                    ]
                }
            },
        }
        with patch(
            "src.adapters.c2pa_manifest._load_c2pa_module",
            return_value=_FakeC2paModule,
        ):
            result = validate_c2pa_sidecar(
                payload_bytes=payload_bytes,
                manifest_bytes=b"fake-sidecar",
                content_type=artifact.content_type,
                payload_format=payload_format,
                body_for_mvp=payload,
            )
        self.assertFalse(result.valid)
        self.assertIn("payloadHash mismatch", "; ".join(result.errors))

    def test_sdk_validation_accepts_canonicalized_content_mismatch(self) -> None:
        """Manifest stores raw body (CRLF); attested body is canonicalized (LF).

        Regression: commit stores canonicalize_body(body), C2PA stores raw.
        Validation must compare canonicalized forms, not raw strings.
        """
        artifact = self._build_artifact()
        raw_body = "hello\r\nworld  \r\n"
        canonical_body = "hello\nworld\n"
        payload_hash = compute_payload_hash(canonical_body)
        payload_bytes, payload_format = build_c2pa_validation_payload(
            artifact,
            canonical_body,
            mode="sdk",
        )
        _FakeC2paModule.reader_manifest_store = {
            "active_manifest": "manifest-1",
            "manifests": {
                "manifest-1": {
                    "assertions": [
                        {
                            "label": _SDK_MARKDOWN_ASSERTION_LABEL,
                            "data": {
                                "content": raw_body,
                                "payloadHash": payload_hash,
                                "contentType": artifact.content_type,
                            },
                        }
                    ]
                }
            },
        }
        with patch(
            "src.adapters.c2pa_manifest._load_c2pa_module",
            return_value=_FakeC2paModule,
        ):
            result = validate_c2pa_sidecar(
                payload_bytes=payload_bytes,
                manifest_bytes=b"fake-sidecar",
                content_type=artifact.content_type,
                payload_format=payload_format,
                body_for_mvp=canonical_body,
            )
        self.assertTrue(
            result.valid,
            f"Canonicalized comparison should pass: {result.errors}",
        )

    def test_sdk_validation_rejects_semantic_content_mismatch(self) -> None:
        """Different actual content (not just line endings) must fail."""
        artifact = self._build_artifact()
        body_a = "hello\n"
        body_b = "world\n"
        payload_hash = compute_payload_hash(body_a)
        payload_bytes, payload_format = build_c2pa_validation_payload(
            artifact,
            body_b,
            mode="sdk",
        )
        _FakeC2paModule.reader_manifest_store = {
            "active_manifest": "manifest-1",
            "manifests": {
                "manifest-1": {
                    "assertions": [
                        {
                            "label": _SDK_MARKDOWN_ASSERTION_LABEL,
                            "data": {
                                "content": body_a,
                                "payloadHash": payload_hash,
                                "contentType": artifact.content_type,
                            },
                        }
                    ]
                }
            },
        }
        with patch(
            "src.adapters.c2pa_manifest._load_c2pa_module",
            return_value=_FakeC2paModule,
        ):
            result = validate_c2pa_sidecar(
                payload_bytes=payload_bytes,
                manifest_bytes=b"fake-sidecar",
                content_type=artifact.content_type,
                payload_format=payload_format,
                body_for_mvp=body_b,
            )
        self.assertFalse(result.valid)
        self.assertIn("content mismatch", "; ".join(result.errors))


if __name__ == "__main__":
    unittest.main()
