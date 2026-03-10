"""Tests for C2PA sidecar generation behavior."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.adapters.c2pa_manifest import (
    build_c2pa_sidecar_manifest,
    resolve_c2pa_mode,
)
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


if __name__ == "__main__":
    unittest.main()
