"""Tests for sync-transparency-log idempotent republish flow."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pygit2

from src.adapters.git_ledger import GitLedgerAdapter
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
from src.canonicalization import compute_payload_hash
from src.events import InMemoryEventBus, StorySigned
from src.models import (
    Artifact,
    GenerationContext,
    Hyperparameters,
    Provenance,
    SignatureBlock,
    VerificationAnchor,
)
from src.repository import SQLiteRepository
from src.services.provenance_service import ProvenanceService


def _make_response(body: bytes) -> object:
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _build_story_signed_event(request_id: UUID, body: str) -> StorySigned:
    artifact = Artifact(
        title="Sync Test Artifact",
        timestamp=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ),
        contentType="text/markdown",
        license="CC0-1.0",
        provenance=Provenance(
            source="synthetic",
            engineVersion="test-engine",
            modelId="test-model",
            generationContext=GenerationContext(
                systemInstruction="Test.",
                prompt="test",
                hyperparameters=Hyperparameters(
                    temperature=0.7,
                    topP=0.95,
                    topK=40,
                ),
            ),
        ),
        signature=SignatureBlock(
            artifactHash=compute_payload_hash(body),
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


class SyncTransparencyLogTest(unittest.IsolatedAsyncioTestCase):
    """Validate sync_transparency_log_to_remote idempotency and healing."""

    def setUp(self) -> None:
        self._repo_temp = tempfile.TemporaryDirectory()
        self._repo_path = Path(self._repo_temp.name)
        pygit2.init_repository(str(self._repo_path), initial_head="master")
        self._state_temp = tempfile.TemporaryDirectory(
            ignore_cleanup_errors=True
        )
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

    async def test_sync_publishes_when_entry_missing_in_remote(self) -> None:
        """When remote has no matching entry, sync publishes it."""
        request_id = uuid4()
        body = "Payload for sync publish test."
        event = _build_story_signed_event(request_id=request_id, body=body)

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        branch_ref = repo.lookup_reference(
            f"refs/heads/artifact/{request_id}"
        )
        branch_commit = repo[branch_ref.target]

        log_path = self._repo_path / ".provenance" / "transparency-log.jsonl"
        log_adapter = TransparencyLogAdapter(
            log_path=log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
            publish_supabase_format=True,
        )
        repository = SQLiteRepository(db_path=self._state_db_path)
        provenance_service = ProvenanceService(
            repository=repository,
            transparency_log_adapter=log_adapter,
            tsa_adapter=None,
            key_registry=KeyRegistryAdapter(repository=repository),
        )

        with patch("urllib.request.urlopen") as mock_urlopen:
            def fake_urlopen(request: object, timeout: float = 10.0) -> object:
                if getattr(request, "method", "GET") == "GET":
                    return _make_response(b"[]")
                return _make_response(b'[{"id": 1}]')

            mock_urlopen.side_effect = fake_urlopen
            provenance_service.anchor_committed_artifact(
                repository_path=self._repo_path,
                commit_oid=str(branch_commit.id),
                ledger_path=f"{request_id}.md",
                request_id=request_id,
            )

        with patch("urllib.request.urlopen") as mock_urlopen:
            def fake_urlopen(request: object, timeout: float = 10.0) -> object:
                if getattr(request, "method", "GET") == "GET":
                    return _make_response(b"[]")
                return _make_response(b'[{"id": 1}]')

            mock_urlopen.side_effect = fake_urlopen
            published, skipped = provenance_service.sync_transparency_log_to_remote(
                self._repo_path
            )

        self.assertEqual(published, 1)
        self.assertEqual(skipped, 0)

    async def test_sync_skips_when_entry_already_in_remote(self) -> None:
        """When remote has matching entry, sync skips (idempotent)."""
        request_id = uuid4()
        body = "Payload for sync skip test."
        event = _build_story_signed_event(request_id=request_id, body=body)

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        branch_ref = repo.lookup_reference(
            f"refs/heads/artifact/{request_id}"
        )
        branch_commit = repo[branch_ref.target]

        log_path = self._repo_path / ".provenance" / "transparency-log.jsonl"
        log_adapter = TransparencyLogAdapter(
            log_path=log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
            publish_supabase_format=True,
        )
        repository = SQLiteRepository(db_path=self._state_db_path)
        provenance_service = ProvenanceService(
            repository=repository,
            transparency_log_adapter=log_adapter,
            tsa_adapter=None,
            key_registry=KeyRegistryAdapter(repository=repository),
        )

        with patch("urllib.request.urlopen") as mock_urlopen:
            def fake_urlopen(request: object, timeout: float = 10.0) -> object:
                if getattr(request, "method", "GET") == "GET":
                    return _make_response(b"[]")
                return _make_response(b'[{"id": 1}]')

            mock_urlopen.side_effect = fake_urlopen
            provenance_service.anchor_committed_artifact(
                repository_path=self._repo_path,
                commit_oid=str(branch_commit.id),
                ledger_path=f"{request_id}.md",
                request_id=request_id,
            )

        artifact_hash = compute_payload_hash(body)
        log_content = provenance_service._read_branch_file(
            self._repo_path,
            f"refs/heads/artifact/{request_id}",
            ".provenance/transparency-log.jsonl",
        )
        entries = log_adapter.parse_entries_from_jsonl(log_content)
        self.assertEqual(len(entries), 1)
        entry_hash = entries[0].entry_hash

        with patch("urllib.request.urlopen") as mock_urlopen:
            def fake_urlopen(request: object, timeout: float = 10.0) -> object:
                if getattr(request, "method", "GET") == "GET":
                    return _make_response(
                        json.dumps([
                            {
                                "payload": {
                                    "artifactHash": artifact_hash,
                                    "entryHash": entry_hash,
                                },
                            },
                        ]).encode("utf-8")
                    )
                return _make_response(b'[{"id": 1}]')

            mock_urlopen.side_effect = fake_urlopen
            published, skipped = provenance_service.sync_transparency_log_to_remote(
                self._repo_path
            )

        self.assertEqual(published, 0)
        self.assertEqual(skipped, 1)


if __name__ == "__main__":
    unittest.main()
