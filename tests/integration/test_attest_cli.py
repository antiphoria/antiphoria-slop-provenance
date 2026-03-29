"""Tests for request-id attestation UX and branch-safe verification."""

from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pygit2

from src import cli
from src.adapters.git_ledger import GitLedgerAdapter
from src.canonicalization import compute_payload_hash
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
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
from src.services.verification_service import AuditReport, VerificationService


class _AllowAllVerifier:
    def verify_artifact_payload(
        self,
        envelope: Artifact,
        payload: str,
        manifest_hash: str | None,
    ) -> bool:
        _ = (envelope, payload, manifest_hash)
        return True


class _FakeVerificationService:
    def __init__(self, report: AuditReport) -> None:
        self._report = report

    def audit_committed_artifact(
        self,
        repository_path: Path,
        request_id: UUID,
        tsa_ca_cert_path: Path | None,
    ) -> AuditReport:
        _ = (repository_path, request_id, tsa_ca_cert_path)
        return self._report


def _build_story_signed_event(request_id: UUID, body: str) -> StorySigned:
    artifact = Artifact(
        title="Attestation Test Artifact",
        timestamp=datetime.now(timezone.utc),
        contentType="text/markdown",
        license="CC0-1.0",
        provenance=Provenance(
            source="synthetic",
            engineVersion="test-engine",
            modelId="test-model",
            generationContext=GenerationContext(
                systemInstruction="Write deterministic content.",
                prompt="test prompt",
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
            verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
        ),
    )
    return StorySigned(
        request_id=request_id,
        artifact=artifact,
        body=body,
    )


class AttestCliTest(unittest.IsolatedAsyncioTestCase):
    """Validate request-id-first attestation command behavior."""

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

    async def test_branch_audit_without_checkout_keeps_master_clean(self) -> None:
        request_id = uuid4()
        body = "Deterministic payload for branch attestation."
        event = _build_story_signed_event(request_id=request_id, body=body)

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        self.assertEqual(dict(repo.status()), {})

        branch_reference = repo.lookup_reference(f"refs/heads/artifact/{request_id}")
        branch_commit = repo[branch_reference.target]
        self.assertIsInstance(branch_commit, pygit2.Commit)

        repository = SQLiteRepository(db_path=self._state_db_path)
        log_adapter = TransparencyLogAdapter(
            log_path=self._repo_path / ".provenance" / "transparency-log.jsonl"
        )
        provenance_service = ProvenanceService(
            repository=repository,
            transparency_log_adapter=log_adapter,
            tsa_adapter=None,
            key_registry=KeyRegistryAdapter(repository=repository),
        )
        provenance_service.anchor_committed_artifact(
            repository_path=self._repo_path,
            commit_oid=str(branch_commit.id),
            ledger_path=f"{request_id}.md",
            request_id=request_id,
        )

        verification_service = VerificationService(
            repository=repository,
            transparency_log_adapter=log_adapter,
            tsa_adapter=None,
            key_registry=KeyRegistryAdapter(repository=repository),
            artifact_verifier=_AllowAllVerifier(),
        )
        report = verification_service.audit_committed_artifact(
            repository_path=self._repo_path,
            request_id=request_id,
            tsa_ca_cert_path=None,
        )

        self.assertTrue(report.envelope_valid)
        self.assertTrue(report.signature_valid)
        self.assertTrue(report.payload_hash_match)
        self.assertTrue(report.transparency_anchor_found)
        self.assertTrue(report.transparency_log_integrity)
        self.assertEqual(report.source_file, f"{request_id}.md")
        self.assertEqual(report.branch, f"artifact/{request_id}")
        self.assertEqual(report.ledger_path, f"{request_id}.md")
        self.assertIsNotNone(report.commit_oid)
        self.assertEqual(dict(repo.status()), {})

    async def test_audit_committed_artifact_sets_remote_anchor_verified_false_when_remote_empty(
        self,
    ) -> None:
        """When remote returns no rows, remote_anchor_verified is False."""
        request_id = uuid4()
        body = "Payload for remote verification test."
        event = _build_story_signed_event(request_id=request_id, body=body)

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        branch_reference = repo.lookup_reference(f"refs/heads/artifact/{request_id}")
        branch_commit = repo[branch_reference.target]

        repository = SQLiteRepository(db_path=self._state_db_path)
        log_adapter = TransparencyLogAdapter(
            log_path=self._repo_path / ".provenance" / "transparency-log.jsonl",
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            resp = MagicMock()
            resp.read.return_value = b'[{"id": 1, "payload": {}}]'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("urllib.request.urlopen", fake_urlopen):
            provenance_service = ProvenanceService(
                repository=repository,
                transparency_log_adapter=log_adapter,
                tsa_adapter=None,
                key_registry=KeyRegistryAdapter(repository=repository),
            )
            provenance_service.anchor_committed_artifact(
                repository_path=self._repo_path,
                commit_oid=str(branch_commit.id),
                ledger_path=f"{request_id}.md",
                request_id=request_id,
            )

        with patch.object(
            log_adapter,
            "fetch_remote_entries_by_artifact_hash",
            return_value=[],
        ):
            verification_service = VerificationService(
                repository=repository,
                transparency_log_adapter=log_adapter,
                tsa_adapter=None,
                key_registry=KeyRegistryAdapter(repository=repository),
                artifact_verifier=_AllowAllVerifier(),
            )
            report = verification_service.audit_committed_artifact(
                repository_path=self._repo_path,
                request_id=request_id,
                tsa_ca_cert_path=None,
            )

        self.assertFalse(report.remote_anchor_verified)
        self.assertIn(
            "Remote transparency log: no matching entry.",
            report.errors,
        )

    async def test_audit_committed_artifact_sets_remote_anchor_verified_false_when_remote_error(
        self,
    ) -> None:
        """When remote fetch raises RuntimeError, only remote_anchor_verified fails; signature etc. remain valid."""
        request_id = uuid4()
        body = "Payload for remote error test."
        event = _build_story_signed_event(request_id=request_id, body=body)

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        branch_reference = repo.lookup_reference(f"refs/heads/artifact/{request_id}")
        branch_commit = repo[branch_reference.target]

        def make_post_response(*args: object, **kwargs: object) -> object:
            resp = MagicMock()
            resp.read.return_value = b'[{"id": 1}]'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        repository = SQLiteRepository(db_path=self._state_db_path)
        log_adapter = TransparencyLogAdapter(
            log_path=self._repo_path / ".provenance" / "transparency-log.jsonl",
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", side_effect=make_post_response):
            provenance_service = ProvenanceService(
                repository=repository,
                transparency_log_adapter=log_adapter,
                tsa_adapter=None,
                key_registry=KeyRegistryAdapter(repository=repository),
            )
            provenance_service.anchor_committed_artifact(
                repository_path=self._repo_path,
                commit_oid=str(branch_commit.id),
                ledger_path=f"{request_id}.md",
                request_id=request_id,
            )

        network_error = RuntimeError(
            "Remote transparency log fetch failed for artifact_hash=xxx: Connection refused"
        )
        with patch.object(
            log_adapter,
            "fetch_remote_entries_by_artifact_hash",
            side_effect=network_error,
        ):
            verification_service = VerificationService(
                repository=repository,
                transparency_log_adapter=log_adapter,
                tsa_adapter=None,
                key_registry=KeyRegistryAdapter(repository=repository),
                artifact_verifier=_AllowAllVerifier(),
            )
            report = verification_service.audit_committed_artifact(
                repository_path=self._repo_path,
                request_id=request_id,
                tsa_ca_cert_path=None,
            )

        self.assertFalse(report.remote_anchor_verified)
        self.assertTrue(report.signature_valid)
        self.assertTrue(report.transparency_anchor_found)
        self.assertTrue(report.transparency_log_integrity)
        remote_errors = [e for e in report.errors if "Remote transparency log:" in e]
        self.assertTrue(len(remote_errors) >= 1)
        self.assertIn("Connection refused", remote_errors[0])

    async def test_audit_committed_artifact_sets_remote_anchor_verified_false_when_remote_tampered(
        self,
    ) -> None:
        """When remote returns tampered payload (metadata changed, entryHash unchanged), deep check rejects it."""
        request_id = uuid4()
        body = "Payload for tamper test."
        event = _build_story_signed_event(request_id=request_id, body=body)

        ledger = GitLedgerAdapter(
            event_bus=InMemoryEventBus(),
            repository_path=self._repo_path,
        )
        await ledger._on_story_signed(event)

        repo = pygit2.Repository(str(self._repo_path))
        branch_reference = repo.lookup_reference(f"refs/heads/artifact/{request_id}")
        branch_commit = repo[branch_reference.target]

        def make_post_response(*args: object, **kwargs: object) -> object:
            resp = MagicMock()
            resp.read.return_value = b'[{"id": 1}]'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        repository = SQLiteRepository(db_path=self._state_db_path)
        log_adapter = TransparencyLogAdapter(
            log_path=self._repo_path / ".provenance" / "transparency-log.jsonl",
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", side_effect=make_post_response):
            provenance_service = ProvenanceService(
                repository=repository,
                transparency_log_adapter=log_adapter,
                tsa_adapter=None,
                key_registry=KeyRegistryAdapter(repository=repository),
            )
            provenance_service.anchor_committed_artifact(
                repository_path=self._repo_path,
                commit_oid=str(branch_commit.id),
                ledger_path=f"{request_id}.md",
                request_id=request_id,
            )

        branch_ref = repo.lookup_reference(f"refs/heads/artifact/{request_id}")
        anchor_commit = repo[branch_ref.target]
        log_blob = repo[anchor_commit.tree[".provenance/transparency-log.jsonl"].id]
        log_text = bytes(log_blob.data).decode("utf-8")
        local_entry = json.loads(log_text.strip().splitlines()[-1])

        tampered_payload = dict(local_entry)
        tampered_payload["metadata"] = {"source": "humsan"}
        tampered_payload["entryHash"] = local_entry["entryHash"]

        def fetch_tampered(artifact_hash: str) -> list[dict]:
            _ = artifact_hash
            return [{"payload": tampered_payload}]

        with patch.object(
            log_adapter,
            "fetch_remote_entries_by_artifact_hash",
            side_effect=fetch_tampered,
        ):
            verification_service = VerificationService(
                repository=repository,
                transparency_log_adapter=log_adapter,
                tsa_adapter=None,
                key_registry=KeyRegistryAdapter(repository=repository),
                artifact_verifier=_AllowAllVerifier(),
            )
            report = verification_service.audit_committed_artifact(
                repository_path=self._repo_path,
                request_id=request_id,
                tsa_ca_cert_path=None,
            )

        self.assertFalse(report.remote_anchor_verified)
        self.assertTrue(report.signature_valid)
        self.assertTrue(report.transparency_anchor_found)
        self.assertTrue(report.transparency_log_integrity)
        self.assertIn("Remote transparency log: no matching entry.", report.errors)

    async def test_attest_warns_without_timestamp_when_non_strict(self) -> None:
        request_id = uuid4()
        report = AuditReport(
            artifact_id=str(uuid4()),
            request_id=str(request_id),
            source_file=f"{request_id}.md",
            envelope_valid=True,
            signature_valid=True,
            payload_hash_match=True,
            transparency_anchor_found=True,
            transparency_log_integrity=True,
            timestamp_found=False,
            timestamp_valid=False,
            key_status_at_signing_time="active",
            errors=["No RFC3161 timestamp token."],
            branch=f"artifact/{request_id}",
            commit_oid="abc123",
            ledger_path=f"{request_id}.md",
        )

        args = argparse.Namespace(
            repo_path=str(self._repo_path),
            request_id=str(request_id),
            strict=False,
            strict_c2pa=False,
            json=False,
            tsa_ca_cert_path=None,
        )
        with patch(
            "src.cli._build_provenance_services",
            return_value=(object(), _FakeVerificationService(report)),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = await cli._run_attest_command(args)

        self.assertEqual(exit_code, 0)
        self.assertIn("[WARN]", buffer.getvalue())

    async def test_attest_fails_without_timestamp_when_strict(self) -> None:
        request_id = uuid4()
        report = AuditReport(
            artifact_id=str(uuid4()),
            request_id=str(request_id),
            source_file=f"{request_id}.md",
            envelope_valid=True,
            signature_valid=True,
            payload_hash_match=True,
            transparency_anchor_found=True,
            transparency_log_integrity=True,
            timestamp_found=False,
            timestamp_valid=False,
            key_status_at_signing_time="active",
            errors=["No RFC3161 timestamp token."],
            branch=f"artifact/{request_id}",
            commit_oid="abc123",
            ledger_path=f"{request_id}.md",
        )

        args = argparse.Namespace(
            repo_path=str(self._repo_path),
            request_id=str(request_id),
            strict=True,
            strict_c2pa=False,
            json=False,
            tsa_ca_cert_path=None,
        )
        with patch(
            "src.cli._build_provenance_services",
            return_value=(object(), _FakeVerificationService(report)),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = await cli._run_attest_command(args)

        self.assertEqual(exit_code, 1)
        self.assertIn("[FAIL]", buffer.getvalue())

    async def test_attest_json_output_is_parseable(self) -> None:
        request_id = uuid4()
        report = AuditReport(
            artifact_id=str(uuid4()),
            request_id=str(request_id),
            source_file=f"{request_id}.md",
            envelope_valid=True,
            signature_valid=True,
            payload_hash_match=True,
            transparency_anchor_found=True,
            transparency_log_integrity=True,
            timestamp_found=False,
            timestamp_valid=False,
            key_status_at_signing_time="active",
            errors=["No RFC3161 timestamp token."],
            branch=f"artifact/{request_id}",
            commit_oid="abc123",
            ledger_path=f"{request_id}.md",
        )

        args = argparse.Namespace(
            repo_path=str(self._repo_path),
            request_id=str(request_id),
            strict=False,
            strict_c2pa=False,
            json=True,
            tsa_ca_cert_path=None,
        )
        with patch(
            "src.cli._build_provenance_services",
            return_value=(object(), _FakeVerificationService(report)),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = await cli._run_attest_command(args)

        self.assertEqual(exit_code, 0)
        loaded = json.loads(buffer.getvalue())
        self.assertEqual(loaded["verdict"], "WARN")
        self.assertIn("report", loaded)
        self.assertEqual(loaded["report"]["source_file"], f"{request_id}.md")

    async def test_attest_fails_with_strict_c2pa_when_sidecar_missing(
        self,
    ) -> None:
        request_id = uuid4()
        report = AuditReport(
            artifact_id=str(uuid4()),
            request_id=str(request_id),
            source_file=f"{request_id}.md",
            envelope_valid=True,
            signature_valid=True,
            payload_hash_match=True,
            transparency_anchor_found=True,
            transparency_log_integrity=True,
            timestamp_found=True,
            timestamp_valid=True,
            key_status_at_signing_time="active",
            c2pa_present=False,
            c2pa_valid=False,
            c2pa_validation_state=None,
            c2pa_errors=[],
            errors=[],
            branch=f"artifact/{request_id}",
            commit_oid="abc123",
            ledger_path=f"{request_id}.md",
        )
        args = argparse.Namespace(
            repo_path=str(self._repo_path),
            request_id=str(request_id),
            strict=False,
            strict_c2pa=True,
            json=False,
            tsa_ca_cert_path=None,
        )
        with patch(
            "src.cli._build_provenance_services",
            return_value=(object(), _FakeVerificationService(report)),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = await cli._run_attest_command(args)
        self.assertEqual(exit_code, 1)
        self.assertIn("[FAIL]", buffer.getvalue())

    async def test_attest_fails_with_strict_c2pa_when_sidecar_invalid(
        self,
    ) -> None:
        request_id = uuid4()
        report = AuditReport(
            artifact_id=str(uuid4()),
            request_id=str(request_id),
            source_file=f"{request_id}.md",
            envelope_valid=True,
            signature_valid=True,
            payload_hash_match=True,
            transparency_anchor_found=True,
            transparency_log_integrity=True,
            timestamp_found=True,
            timestamp_valid=True,
            key_status_at_signing_time="active",
            c2pa_present=True,
            c2pa_valid=False,
            c2pa_validation_state="invalid",
            c2pa_errors=["tampered sidecar"],
            errors=["C2PA sidecar semantic validation failed."],
            branch=f"artifact/{request_id}",
            commit_oid="abc123",
            ledger_path=f"{request_id}.md",
        )
        args = argparse.Namespace(
            repo_path=str(self._repo_path),
            request_id=str(request_id),
            strict=False,
            strict_c2pa=True,
            json=False,
            tsa_ca_cert_path=None,
        )
        with patch(
            "src.cli._build_provenance_services",
            return_value=(object(), _FakeVerificationService(report)),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = await cli._run_attest_command(args)
        self.assertEqual(exit_code, 1)
        self.assertIn("[FAIL]", buffer.getvalue())

    async def test_attest_passes_with_strict_c2pa_when_sidecar_valid(
        self,
    ) -> None:
        request_id = uuid4()
        report = AuditReport(
            artifact_id=str(uuid4()),
            request_id=str(request_id),
            source_file=f"{request_id}.md",
            envelope_valid=True,
            signature_valid=True,
            payload_hash_match=True,
            transparency_anchor_found=True,
            transparency_log_integrity=True,
            timestamp_found=True,
            timestamp_valid=True,
            key_status_at_signing_time="active",
            c2pa_present=True,
            c2pa_valid=True,
            c2pa_validation_state="valid",
            c2pa_errors=[],
            errors=[],
            branch=f"artifact/{request_id}",
            commit_oid="abc123",
            ledger_path=f"{request_id}.md",
        )
        args = argparse.Namespace(
            repo_path=str(self._repo_path),
            request_id=str(request_id),
            strict=False,
            strict_c2pa=True,
            json=False,
            tsa_ca_cert_path=None,
        )
        with patch(
            "src.cli._build_provenance_services",
            return_value=(object(), _FakeVerificationService(report)),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = await cli._run_attest_command(args)
        self.assertEqual(exit_code, 0)
        self.assertIn("[PASS]", buffer.getvalue())

    async def test_attest_fails_when_remote_anchor_verified_false(self) -> None:
        request_id = uuid4()
        report = AuditReport(
            artifact_id=str(uuid4()),
            request_id=str(request_id),
            source_file=f"{request_id}.md",
            envelope_valid=True,
            signature_valid=True,
            payload_hash_match=True,
            transparency_anchor_found=True,
            transparency_log_integrity=True,
            remote_anchor_verified=False,
            timestamp_found=True,
            timestamp_valid=True,
            key_status_at_signing_time="active",
            errors=["Remote transparency log: no matching entry."],
            branch=f"artifact/{request_id}",
            commit_oid="abc123",
            ledger_path=f"{request_id}.md",
        )
        args = argparse.Namespace(
            repo_path=str(self._repo_path),
            request_id=str(request_id),
            strict=False,
            strict_c2pa=False,
            json=False,
            tsa_ca_cert_path=None,
        )
        with patch(
            "src.cli._build_provenance_services",
            return_value=(object(), _FakeVerificationService(report)),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = await cli._run_attest_command(args)
        self.assertEqual(exit_code, 1)
        self.assertIn("[FAIL]", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
