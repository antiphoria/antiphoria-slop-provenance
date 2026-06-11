"""Tests for LLM-only seal command."""

from __future__ import annotations

import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import pygit2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from src import cli
from src.adapters.git_ledger import GitLedgerAdapter
from src.canonicalization import compute_payload_hash
from src.commands.pipeline import _load_process_narrative
from src.domain.events import StorySigned, StorySyntheticSealed
from src.envelope_v2 import render_artifact_markdown_wire
from src.infrastructure.event_bus import InMemoryEventBus
from src.models import (
    Artifact,
    AuthorAttestation,
    GenerationContext,
    Hyperparameters,
    Provenance,
    RegistrationCeremony,
    SignatureBlock,
    VerificationAnchor,
    canonical_json_bytes,
    sha256_hex,
)
from src.parsing import parse_artifact_markdown_text
from tests.support.stack_test_env import configure_minimal_ceremony_stack_env
from tests.support.v2_envelope_fixtures import (
    enrich_provenance_for_v2_wire,
    sample_registration_ceremony,
    sample_synthetic_attestation,
)


def _build_synthetic_story_signed_event(
    request_id: UUID,
    body: str,
    *,
    title: str = "LLM Research",
    models_used: list[str] | None = None,
    process_narrative_hash: str | None = None,
    process_narrative_bytes_b64: str | None = None,
    attestation: AuthorAttestation | None = None,
    registration_ceremony: RegistrationCeremony | None = None,
) -> StorySigned:
    """Build StorySigned with source=synthetic and seal metadata."""

    artifact_hash = compute_payload_hash(body)
    model_id = "undisclosed"
    if models_used:
        model_id = models_used[0] if len(models_used) == 1 else "composite"
    artifact = Artifact(
        title=title,
        timestamp=datetime.now(UTC),
        contentType="text/markdown",
        license="CC0-1.0",
        provenance=enrich_provenance_for_v2_wire(
            Provenance(
                source="synthetic",
                engineVersion="antiphoria-slop-provenance-v1.0.0",
                modelId=model_id,
                provenanceGrade="declared",
                modelsUsed=models_used,
                processNarrativeHash=process_narrative_hash,
                generationContext=GenerationContext(
                    systemInstruction="Machine-generated. Orchestrator declaration only.",
                    prompt="N/A",
                    hyperparameters=Hyperparameters(
                        temperature=0.0,
                        topP=1.0,
                        topK=0,
                    ),
                ),
                authorAttestation=attestation or sample_synthetic_attestation(),
                registrationCeremony=registration_ceremony or sample_registration_ceremony(),
            )
        ),
        signature=SignatureBlock(
            artifactHash=artifact_hash,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
        ),
    )
    return StorySigned(
        request_id=request_id,
        artifact=artifact,
        body=body,
        process_narrative_hash=process_narrative_hash,
        process_narrative_bytes_b64=process_narrative_bytes_b64,
    )


class SealCliTest(unittest.IsolatedAsyncioTestCase):
    """Validate LLM-only sealing and provenance sidecars."""

    def setUp(self) -> None:
        self._repo_temp = tempfile.TemporaryDirectory()
        self._repo_path = Path(self._repo_temp.name)
        pygit2.init_repository(str(self._repo_path), initial_head="master")
        self._old_enable_ots = os.getenv("ENABLE_OTS_FORGE")
        self._old_pqc_private_key_path = os.getenv("PQC_PRIVATE_KEY_PATH")
        self._old_ed25519_private_key_path = os.getenv("ED25519_PRIVATE_KEY_PATH")
        self._key_temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        key_dir = Path(self._key_temp.name)
        pqc_private_key_path = key_dir / "pqc-private.key"
        pqc_private_key_path.write_bytes(b"test-private-key-bytes")
        ed25519_private_key = Ed25519PrivateKey.generate()
        ed25519_private_key_path = key_dir / "ed25519-private.pem"
        ed25519_private_key_path.write_bytes(
            ed25519_private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
        os.environ["PQC_PRIVATE_KEY_PATH"] = str(pqc_private_key_path)
        os.environ["ED25519_PRIVATE_KEY_PATH"] = str(ed25519_private_key_path)
        configure_minimal_ceremony_stack_env(key_dir)

    def tearDown(self) -> None:
        if self._old_enable_ots is None:
            os.environ.pop("ENABLE_OTS_FORGE", None)
        else:
            os.environ["ENABLE_OTS_FORGE"] = self._old_enable_ots
        if self._old_pqc_private_key_path is None:
            os.environ.pop("PQC_PRIVATE_KEY_PATH", None)
        else:
            os.environ["PQC_PRIVATE_KEY_PATH"] = self._old_pqc_private_key_path
        if self._old_ed25519_private_key_path is None:
            os.environ.pop("ED25519_PRIVATE_KEY_PATH", None)
        else:
            os.environ["ED25519_PRIVATE_KEY_PATH"] = self._old_ed25519_private_key_path
        self._key_temp.cleanup()
        self._repo_temp.cleanup()

    def test_load_process_narrative_wraps_unverified_envelope(self) -> None:
        """Process narrative sidecar must carry verified=false marker."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"stepCount": 3}, f)
            narrative_path = Path(f.name)
        try:
            narrative_bytes, narrative_hash = _load_process_narrative(narrative_path)
            loaded = json.loads(narrative_bytes.decode("utf-8"))
            self.assertEqual(loaded["schemaVersion"], "process-narrative.v1")
            self.assertEqual(loaded["kind"], "operator-narrative")
            self.assertFalse(loaded["verified"])
            self.assertEqual(loaded["narrative"]["stepCount"], 3)
            self.assertEqual(narrative_hash, sha256_hex(narrative_bytes))
        finally:
            narrative_path.unlink(missing_ok=True)

    async def test_seal_non_interactive_captures_synthetic_event(self) -> None:
        """With --non-interactive, seal emits unattended orchestration declaration."""
        markdown_content = "Machine-generated research output."
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as f:
            f.write(markdown_content)
            artifact_path = Path(f.name)

        captured: list[StorySyntheticSealed] = []

        try:
            with patch("builtins.input") as mock_input:

                async def _fake_on_story_synthetic_sealed(
                    self: object, event: StorySyntheticSealed
                ) -> None:
                    captured.append(event)
                    signed = _build_synthetic_story_signed_event(
                        request_id=event.request_id,
                        body=event.body,
                        title=event.title,
                        models_used=event.models_used,
                        attestation=event.attestation,
                        registration_ceremony=event.registration_ceremony,
                    )
                    await self._event_bus.emit(signed)

                with patch(
                    "src.adapters.crypto_notary.CryptoNotaryAdapter._on_story_synthetic_sealed",
                    _fake_on_story_synthetic_sealed,
                ):
                    args = cli.build_parser().parse_args(
                        [
                            "seal",
                            "--file",
                            str(artifact_path),
                            "--repo-path",
                            str(self._repo_path),
                            "--title",
                            "Sealed LLM Text",
                            "--models",
                            "gemini-3.1-pro,composer-2.5",
                            "--non-interactive",
                        ]
                    )
                    buffer = io.StringIO()
                    with redirect_stdout(buffer):
                        exit_code = await cli._run_seal_command(args)

                self.assertEqual(exit_code, 0)
                mock_input.assert_not_called()
                self.assertEqual(len(captured), 1)
                sealed = captured[0]
                self.assertEqual(sealed.license, "CC0-1.0")
                self.assertEqual(sealed.models_used, ["gemini-3.1-pro", "composer-2.5"])
                att = sealed.attestation
                self.assertEqual(att.attestation_nature, "orchestration-declaration")
                self.assertEqual(att.attestation_mode, "unattended")
                self.assertIsNone(att.classification)
                self.assertEqual(att.attestations, [])
                self.assertIn("Sealing completed:", buffer.getvalue())
        finally:
            artifact_path.unlink(missing_ok=True)

    async def test_ledger_writes_process_narrative_sidecar(self) -> None:
        """Git ledger persists {id}.process.json when narrative bytes are supplied."""
        request_id = uuid4()
        body = "LLM output with process narrative."
        narrative = {
            "schemaVersion": "process-narrative.v1",
            "kind": "operator-narrative",
            "verified": False,
            "narrative": {"modelsUsed": ["gemini-3.1-pro"]},
        }
        narrative_bytes = canonical_json_bytes(narrative)
        narrative_hash = sha256_hex(narrative_bytes)

        event = _build_synthetic_story_signed_event(
            request_id=request_id,
            body=body,
            models_used=["gemini-3.1-pro"],
            process_narrative_hash=narrative_hash,
            process_narrative_bytes_b64=base64.b64encode(narrative_bytes).decode("ascii"),
        )

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        branch_ref = repo.lookup_reference(f"refs/heads/artifact/{request_id}")
        commit = repo[branch_ref.target]
        markdown_blob = repo[commit.tree[f"{request_id}.md"].id]
        markdown_text = bytes(markdown_blob.data).decode("utf-8")
        sidecar_blob = repo[commit.tree[f"{request_id}.process.json"].id]
        sidecar_text = bytes(sidecar_blob.data).decode("utf-8")

        self.assertIn('source: "synthetic"', markdown_text)
        self.assertIn('profile: "antiphoria.seal.v1"', markdown_text)
        self.assertIn('policyId: "CC0-1.0"', markdown_text)
        self.assertIn('provenanceGrade: "declared"', markdown_text)
        self.assertIn('speechAct: "orchestration-declaration"', markdown_text)
        self.assertIn(f'contentHash: "{narrative_hash}"', markdown_text)
        self.assertIn('"verified":false', sidecar_text)

        envelope, payload = parse_artifact_markdown_text(markdown_text)
        self.assertEqual(envelope.provenance.source, "synthetic")
        self.assertEqual(envelope.provenance.provenance_grade, "declared")
        self.assertEqual(envelope.provenance.process_narrative_hash, narrative_hash)
        self.assertEqual(payload, body)

    def test_sealed_provenance_round_trip_serialization(self) -> None:
        """Render and parse recover provenanceGrade, modelsUsed, and narrative hash."""
        body = "Sealed synthetic body."
        artifact_hash = compute_payload_hash(body)
        narrative_hash = "a" * 64
        artifact = Artifact(
            title="Round Trip",
            timestamp=datetime.now(UTC),
            contentType="text/markdown",
            license="CC0-1.0",
            provenance=enrich_provenance_for_v2_wire(
                Provenance(
                    source="synthetic",
                    engineVersion="antiphoria-slop-provenance-v1.0.0",
                    modelId="composite",
                    provenanceGrade="declared",
                    modelsUsed=["gemini-3.1-pro", "composer-2.5"],
                    processNarrativeHash=narrative_hash,
                    generationContext=GenerationContext(
                        systemInstruction="Machine-generated. Orchestrator declaration only.",
                        prompt="N/A",
                        hyperparameters=Hyperparameters(
                            temperature=0.0,
                            topP=1.0,
                            topK=0,
                        ),
                    ),
                    authorAttestation=sample_synthetic_attestation(),
                    registrationCeremony=sample_registration_ceremony(),
                )
            ),
            signature=SignatureBlock(
                artifactHash=artifact_hash,
                cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
                verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
            ),
        )
        markdown_text = render_artifact_markdown_wire(
            artifact,
            body,
            ledger_request_id=str(uuid4()),
        )
        envelope, payload = parse_artifact_markdown_text(markdown_text)
        self.assertEqual(envelope.provenance.provenance_grade, "declared")
        self.assertEqual(
            envelope.provenance.models_used,
            ["gemini-3.1-pro", "composer-2.5"],
        )
        self.assertEqual(envelope.provenance.process_narrative_hash, narrative_hash)
        self.assertEqual(payload, body)


if __name__ == "__main__":
    unittest.main()
