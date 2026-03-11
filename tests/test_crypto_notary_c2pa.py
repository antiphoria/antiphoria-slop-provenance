"""Tests for C2PA-related notary behavior."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.events import InMemoryEventBus
from src.models import AuthorAttestation


class CryptoNotaryC2PATest(unittest.IsolatedAsyncioTestCase):
    """Validate fail-closed behavior when SDK sidecar generation fails."""

    async def test_fails_closed_when_c2pa_generation_errors(self) -> None:
        adapter = CryptoNotaryAdapter(
            event_bus=InMemoryEventBus(),
            require_private_key=False,
        )
        adapter._enable_c2pa = True
        adapter._private_key = b"placeholder-private-key"

        with patch(
            "src.adapters.crypto_notary.build_c2pa_sidecar_manifest",
            side_effect=RuntimeError("sdk-sidecar-failed"),
        ):
            with self.assertRaises(RuntimeError) as error_ctx:
                await adapter._build_signed_artifact(
                    title="INCIDENT_TEST",
                    source="synthetic",
                    model_id="gemini-2.5-flash",
                    body="payload body",
                    prompt="prompt",
                    system_instruction="system",
                    temperature=0.1,
                    top_p=0.9,
                    top_k=5,
                    usage_metrics=None,
                    embedded_watermark=None,
                    content_type="text/markdown",
                    license="CC0-1.0",
                    curation=None,
                )
        self.assertIn("fail-closed", str(error_ctx.exception))

    async def test_human_registration_with_attestation_produces_author_attestation_in_envelope(
        self,
    ) -> None:
        """Human registration with attestation seals authorAttestation into provenance."""

        attestation = AuthorAttestation(
            classification="satire",
            is_human=True,
            is_original_creation=True,
            is_independent_and_accurate=True,
            understands_cryptographic_permanence=True,
        )

        adapter = CryptoNotaryAdapter(
            event_bus=InMemoryEventBus(),
            require_private_key=False,
        )
        adapter._enable_c2pa = False
        adapter._private_key = b"x" * 256

        def _fake_sign(_sk: bytes, _msg: bytes) -> bytes:
            return b"fake-ml-dsa-signature-bytes-for-test"

        with patch("src.adapters.crypto_notary._sign_ml_dsa", _fake_sign):
            artifact, _ = await adapter._build_signed_artifact(
                title="Human Story",
                source="human",
                model_id="human",
                body="Human-authored content.",
                prompt="N/A",
                system_instruction="Human-authored. No AI generation.",
                temperature=0.0,
                top_p=1.0,
                top_k=0,
                usage_metrics=None,
                embedded_watermark=None,
                content_type="text/markdown",
                license="ARR",
                curation=None,
                author_attestation=attestation,
            )

        self.assertIsNotNone(artifact.provenance.author_attestation)
        self.assertEqual(
            artifact.provenance.author_attestation.classification, "satire"
        )
        self.assertIs(
            artifact.provenance.author_attestation.understands_cryptographic_permanence,
            True,
        )
        dumped = artifact.provenance.author_attestation.model_dump(by_alias=True)
        self.assertIn("authorAttestation", str(artifact.model_dump(by_alias=True)))


if __name__ == "__main__":
    unittest.main()
