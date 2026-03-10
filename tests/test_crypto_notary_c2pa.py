"""Tests for C2PA-related notary behavior."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.events import InMemoryEventBus


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


if __name__ == "__main__":
    unittest.main()
