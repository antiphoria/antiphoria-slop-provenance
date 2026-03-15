"""Tests for human-only registration command."""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

import pygit2

from src import cli
from src.adapters.git_ledger import GitLedgerAdapter
from src.events import InMemoryEventBus, StoryHumanRegistered, StorySigned
from src.models import (
    Artifact,
    GenerationContext,
    Hyperparameters,
    Provenance,
    SignatureBlock,
    VerificationAnchor,
)
from src.parsing import parse_artifact_markdown_text


def _build_human_story_signed_event(
    request_id: UUID, body: str, title: str = "Human Authored Story"
) -> StorySigned:
    """Build StorySigned with source=human and sentinel provenance."""

    artifact_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    artifact = Artifact(
        title=title,
        timestamp=datetime.now(timezone.utc),
        contentType="text/markdown",
        license="ARR",
        provenance=Provenance(
            source="human",
            engineVersion="slop-orchestrator-v1.0.0",
            modelId="human",
            generationContext=GenerationContext(
                systemInstruction="Human-authored. No AI generation.",
                prompt="N/A",
                hyperparameters=Hyperparameters(
                    temperature=0.0,
                    topP=1.0,
                    topK=0,
                ),
            ),
        ),
        signature=SignatureBlock(
            artifactHash=artifact_hash,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(
                signerFingerprint="test-fingerprint"
            ),
        ),
    )
    return StorySigned(
        request_id=request_id,
        artifact=artifact,
        body=body,
    )


class RegisterCliTest(unittest.IsolatedAsyncioTestCase):
    """Validate human-only registration and provenance."""

    def setUp(self) -> None:
        self._repo_temp = tempfile.TemporaryDirectory()
        self._repo_path = Path(self._repo_temp.name)
        pygit2.init_repository(str(self._repo_path), initial_head="master")
        self._state_temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._state_db_path = Path(self._state_temp.name) / "state.db"
        self._old_state_db_path = os.getenv("STATE_DB_PATH")
        os.environ["STATE_DB_PATH"] = str(self._state_db_path)

    def tearDown(self) -> None:
        if self._old_state_db_path is None:
            os.environ.pop("STATE_DB_PATH", None)
        else:
            os.environ["STATE_DB_PATH"] = self._old_state_db_path
        self._state_temp.cleanup()
        self._repo_temp.cleanup()

    async def test_human_provenance_ledger_render_and_parse(self) -> None:
        """Ledger renders human provenance; parsed envelope has source human."""

        request_id = uuid4()
        body = "This is purely human-written content.\n\nNo AI involved."
        event = _build_human_story_signed_event(request_id=request_id, body=body)

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        branch_ref = repo.lookup_reference(f"refs/heads/artifact/{request_id}")
        commit = repo[branch_ref.target]
        blob = repo[commit.tree[f"{request_id}.md"].id]
        markdown_text = bytes(blob.data).decode("utf-8")

        self.assertIn('source: "human"', markdown_text)
        self.assertIn("modelId: \"human\"", markdown_text)
        self.assertIn("Human-authored. No AI generation.", markdown_text)
        self.assertIn("usageMetrics: null", markdown_text)
        self.assertIn("embeddedWatermark: null", markdown_text)
        self.assertIn("authorAttestation: null", markdown_text)
        self.assertIn("registrationCeremony: null", markdown_text)

        envelope, payload = parse_artifact_markdown_text(markdown_text)
        self.assertEqual(envelope.provenance.source, "human")
        self.assertEqual(envelope.provenance.model_id, "human")
        self.assertEqual(payload, body)

    async def test_register_cli_integration(self) -> None:
        """Register command commits human artifact; file contains source human."""

        markdown_content = "Purely human-written story.\n\nNo AI involved."
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as f:
            f.write(markdown_content)
            artifact_path = Path(f.name)

        try:
            async def _fake_on_story_human_registered(
                self: object, event: StoryHumanRegistered
            ) -> None:
                signed = _build_human_story_signed_event(
                    request_id=event.request_id,
                    body=event.body,
                    title=event.title,
                )
                await getattr(self, "_event_bus").emit(signed)

            with patch(
                "src.adapters.crypto_notary.CryptoNotaryAdapter._on_story_human_registered",
                _fake_on_story_human_registered,
            ):
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    args = cli.build_parser().parse_args(
                        [
                            "register",
                            "--file",
                            str(artifact_path),
                            "--repo-path",
                            str(self._repo_path),
                            "--title",
                            "My Human Story",
                            "--non-interactive",
                        ]
                    )
                    exit_code = await cli._run_register_command(args)

            self.assertEqual(exit_code, 0)
            output = buffer.getvalue()
            self.assertIn("Registration completed:", output)
            self.assertIn("request_id=", output)
            self.assertIn("commit=", output)

            repo = pygit2.Repository(str(self._repo_path))
            refs = [r for r in repo.references if r.startswith("refs/heads/artifact/")]
            self.assertGreater(len(refs), 0, "Expected at least one artifact branch")

            branch_ref = repo.lookup_reference(refs[0])
            commit = repo[branch_ref.target]
            request_id_str = refs[0].replace("refs/heads/artifact/", "")
            blob = repo[commit.tree[f"{request_id_str}.md"].id]
            markdown_text = bytes(blob.data).decode("utf-8")

            self.assertIn('source: "human"', markdown_text)
            self.assertIn("modelId: \"human\"", markdown_text)
            self.assertIn("My Human Story", markdown_text)

            # Attest passes (patch verifier to accept fake signature)
            with patch(
                "src.adapters.crypto_notary.CryptoNotaryAdapter.verify_artifact_payload",
                return_value=True,
            ):
                attest_args = cli.build_parser().parse_args(
                    [
                        "attest",
                        "--repo-path",
                        str(self._repo_path),
                        "--request-id",
                        request_id_str,
                    ]
                )
                attest_exit = await cli._run_attest_command(attest_args)
            self.assertEqual(attest_exit, 0, "Attest should pass")

            # Curate rejects human-registered artifacts
            artifact_file = self._repo_path / f"{request_id_str}.md"
            artifact_file.write_text(markdown_text, encoding="utf-8")
            curate_args = cli.build_parser().parse_args(
                [
                    "curate",
                    "--file",
                    str(artifact_file),
                    "--repo-path",
                    str(self._repo_path),
                ]
            )
            with self.assertRaises(RuntimeError) as ctx:
                await cli._run_curate_command(curate_args)
            self.assertIn("cannot be curated", str(ctx.exception))
        finally:
            artifact_path.unlink(missing_ok=True)

    async def test_register_non_interactive_skips_wizard(self) -> None:
        """With --non-interactive, input() is never called."""

        markdown_content = "Human-only content."
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as f:
            f.write(markdown_content)
            artifact_path = Path(f.name)

        try:
            with patch("builtins.input") as mock_input:
                async def _fake_on_story_human_registered(
                    self: object, event: StoryHumanRegistered
                ) -> None:
                    signed = _build_human_story_signed_event(
                        request_id=event.request_id,
                        body=event.body,
                        title=event.title,
                    )
                    await getattr(self, "_event_bus").emit(signed)

                with patch(
                    "src.adapters.crypto_notary.CryptoNotaryAdapter._on_story_human_registered",
                    _fake_on_story_human_registered,
                ):
                    args = cli.build_parser().parse_args(
                        [
                            "register",
                            "--file",
                            str(artifact_path),
                            "--repo-path",
                            str(self._repo_path),
                            "--title",
                            "Non-Interactive Test",
                            "--non-interactive",
                        ]
                    )
                    buffer = io.StringIO()
                    with redirect_stdout(buffer):
                        exit_code = await cli._run_register_command(args)

                self.assertEqual(exit_code, 0)
                mock_input.assert_not_called()
        finally:
            artifact_path.unlink(missing_ok=True)
