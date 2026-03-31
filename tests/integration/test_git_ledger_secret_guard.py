"""Tests for secret blocking in git ledger publication path."""

from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pygit2

from src.adapters.git_ledger import GitLedgerAdapter
from src.events import InMemoryEventBus, StorySigned
from src.models import (
    Artifact,
    GenerationContext,
    Hyperparameters,
    Provenance,
    SignatureBlock,
    VerificationAnchor,
)


def _build_story_signed_event(
    prompt: str,
    body: str = "Safe body text.",
    c2pa_manifest_bytes_b64: str | None = None,
    c2pa_manifest_hash: str | None = None,
    request_id: UUID | None = None,
) -> StorySigned:
    artifact = Artifact(
        title="Safe Artifact",
        timestamp=datetime.now(timezone.utc),
        contentType="text/markdown",
        license="CC-BY-4.0",
        provenance=Provenance(
            source="synthetic",
            engineVersion="test-engine",
            modelId="test-model",
            generationContext=GenerationContext(
                systemInstruction="Write a concise test story.",
                prompt=prompt,
                hyperparameters=Hyperparameters(
                    temperature=0.5,
                    topP=0.9,
                    topK=40,
                ),
            ),
        ),
        signature=SignatureBlock(
            artifactHash="a" * 64,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(
                signerFingerprint="unit-test-fingerprint",
            ),
        ),
    )
    return StorySigned(
        request_id=request_id or uuid4(),
        artifact=artifact,
        body=body,
        c2pa_manifest_hash=c2pa_manifest_hash,
        c2pa_manifest_bytes_b64=c2pa_manifest_bytes_b64,
    )


class GitLedgerSecretGuardTest(unittest.IsolatedAsyncioTestCase):
    """Validate secret rejection before publish commit."""

    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self._repo_path = Path(self._tempdir.name)
        pygit2.init_repository(str(self._repo_path), initial_head="master")
        self._adapter = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )

    def tearDown(self) -> None:
        self._tempdir.cleanup()

    async def test_rejects_prompt_containing_secret_pattern(self) -> None:
        event = _build_story_signed_event(
            (
                "Prompt with leaked key "
                "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # pragma: allowlist secret
            )
        )

        with self.assertRaises(RuntimeError):
            await self._adapter._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        with self.assertRaises(KeyError):
            repo.lookup_reference(f"refs/heads/artifact/{event.request_id}")

    async def test_commits_when_prompt_and_body_are_clean(self) -> None:
        event = _build_story_signed_event("Write a deterministic noir micro-story.")

        await self._adapter._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        reference = repo.lookup_reference(f"refs/heads/artifact/{event.request_id}")
        self.assertIsNotNone(reference)

    async def test_writes_exact_c2pa_sidecar_bytes_from_event(self) -> None:
        env_file = self._repo_path / ".env"
        env_file.write_text("ENABLE_C2PA=true\n", encoding="utf-8")
        adapter = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
            env_path=env_file,
        )
        sidecar_bytes = b"\x00\x01signed-c2pa-sidecar-bytes"
        event = _build_story_signed_event(
            "Write a deterministic noir micro-story.",
            c2pa_manifest_bytes_b64=base64.b64encode(sidecar_bytes).decode("ascii"),
            c2pa_manifest_hash=hashlib.sha256(sidecar_bytes).hexdigest(),
        )

        await adapter._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        reference = repo.lookup_reference(f"refs/heads/artifact/{event.request_id}")
        commit_obj = repo[reference.target]
        self.assertIsInstance(commit_obj, pygit2.Commit)
        sidecar_entry = commit_obj.tree[f"{event.request_id}.c2pa"]
        sidecar_blob = repo[sidecar_entry.id]
        self.assertEqual(bytes(sidecar_blob.data), sidecar_bytes)

    async def test_commits_without_c2pa_in_nested_artifacts_directory(self) -> None:
        adapter = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
            artifacts_directory="artifacts",
        )
        event = _build_story_signed_event("Write a deterministic noir micro-story.")

        await adapter._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        reference = repo.lookup_reference(f"refs/heads/artifact/{event.request_id}")
        commit_obj = repo[reference.target]
        self.assertIsInstance(commit_obj, pygit2.Commit)
        artifacts_entry = commit_obj.tree["artifacts"]
        artifacts_tree = repo[artifacts_entry.id]
        self.assertIn(f"{event.request_id}.md", artifacts_tree)
        self.assertNotIn(f"{event.request_id}.c2pa", artifacts_tree)

    async def test_nested_artifacts_directory_does_not_bleed_parent_entries(self) -> None:
        request_id = uuid4()
        repo = pygit2.Repository(str(self._repo_path))

        # Seed artifact branch with parent-level file under a/.
        parent_file = self._repo_path / "a" / "unrelated.txt"
        parent_file.parent.mkdir(parents=True, exist_ok=True)
        parent_file.write_text("do not duplicate me", encoding="utf-8")
        repo.index.add("a/unrelated.txt")
        repo.index.write()
        tree_id = repo.index.write_tree()
        signature = pygit2.Signature("Unit Test", "unit@test.local")
        branch_ref = f"refs/heads/artifact/{request_id}"
        repo.create_commit(
            branch_ref,
            signature,
            signature,
            "seed parent directory",
            tree_id,
            [],
        )
        repo.index.clear()
        repo.index.write()

        adapter = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
            artifacts_directory="a/b",
        )
        event = _build_story_signed_event(
            "Write a deterministic noir micro-story.",
            request_id=request_id,
        )
        await adapter._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        reference = repo.lookup_reference(branch_ref)
        commit_obj = repo[reference.target]
        self.assertIsInstance(commit_obj, pygit2.Commit)
        a_tree = repo[commit_obj.tree["a"].id]
        self.assertIn("unrelated.txt", a_tree)
        self.assertIn("b", a_tree)
        b_tree = repo[a_tree["b"].id]
        self.assertIn(f"{request_id}.md", b_tree)
        self.assertNotIn("unrelated.txt", b_tree)


if __name__ == "__main__":
    unittest.main()
