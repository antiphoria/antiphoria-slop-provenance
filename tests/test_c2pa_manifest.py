"""Tests for C2PA sidecar generation behavior."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from src.adapters.c2pa_manifest import build_c2pa_sidecar_manifest
from src.models import Artifact, GenerationContext, Hyperparameters, Provenance


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
                engineVersion="slop-orchestrator-v1.0.0",
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
        first = build_c2pa_sidecar_manifest(artifact, "payload")
        second = build_c2pa_sidecar_manifest(artifact, "payload")
        self.assertEqual(first.manifest_hash, second.manifest_hash)
        self.assertEqual(first.manifest_bytes, second.manifest_bytes)


if __name__ == "__main__":
    unittest.main()
