"""Unit tests for archive catalog adapter and row builder."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pygit2

from src.adapters.catalog import (
    CatalogAdapter,
    build_catalog_row,
    collect_catalog_rows_from_repo,
)
from src.adapters.git_ledger import GitLedgerAdapter
from src.canonicalization import compute_payload_hash
from src.domain.events import StorySigned
from src.infrastructure.event_bus import InMemoryEventBus
from src.models import (
    Artifact,
    AttestationQa,
    AuthorAttestation,
    GenerationContext,
    Hyperparameters,
    Provenance,
    SignatureBlock,
    VerificationAnchor,
)
from tests.support.v2_envelope_fixtures import (
    enrich_provenance_for_v2_wire,
    sample_human_attestation,
    sample_registration_ceremony,
    sample_synthetic_attestation,
)


def _build_human_signed(request_id: UUID, body: str, title: str = "Human") -> StorySigned:
    artifact_hash = compute_payload_hash(body)
    artifact = Artifact(
        title=title,
        timestamp=datetime.now(UTC),
        contentType="text/markdown",
        license="ARR",
        provenance=enrich_provenance_for_v2_wire(
            Provenance(
                source="human",
                engineVersion="antiphoria-slop-provenance-v1.0.0",
                modelId="human",
                generationContext=GenerationContext(
                    systemInstruction="Human-authored. No AI generation.",
                    prompt="N/A",
                    hyperparameters=Hyperparameters(temperature=0.0, topP=1.0, topK=0),
                ),
                authorAttestation=sample_human_attestation(),
                registrationCeremony=sample_registration_ceremony(),
            )
        ),
        signature=SignatureBlock(
            artifactHash=artifact_hash,
            cryptographicSignature="ZmFrZS1zaWduYXR1cmU=",
            verificationAnchor=VerificationAnchor(signerFingerprint="test-fingerprint"),
        ),
    )
    return StorySigned(request_id=request_id, artifact=artifact, body=body)


def _build_synthetic_signed(request_id: UUID, body: str) -> StorySigned:
    artifact_hash = compute_payload_hash(body)
    artifact = Artifact(
        title="Synthetic",
        timestamp=datetime.now(UTC),
        contentType="text/markdown",
        license="CC0-1.0",
        provenance=enrich_provenance_for_v2_wire(
            Provenance(
                source="synthetic",
                engineVersion="antiphoria-slop-provenance-v1.0.0",
                modelId="gemini-3.1-pro",
                provenanceGrade="declared",
                generationContext=GenerationContext(
                    systemInstruction="Machine-generated.",
                    prompt="N/A",
                    hyperparameters=Hyperparameters(temperature=0.0, topP=1.0, topK=0),
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
    return StorySigned(request_id=request_id, artifact=artifact, body=body)


class CatalogAdapterTest(unittest.TestCase):
    """Validate catalog JSONL upsert/rebuild semantics."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self._repo_path = Path(self._temp.name)
        pygit2.init_repository(str(self._repo_path), initial_head="main")

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_upsert_replaces_existing_request_id(self) -> None:
        adapter = CatalogAdapter(repository_path=self._repo_path)
        request_id = str(uuid4())
        first = {
            "requestId": request_id,
            "title": "First",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "source": "human",
        }
        second = {**first, "title": "Second"}
        adapter.upsert_entry(first)
        adapter.upsert_entry(second)
        entries = adapter.read_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["title"], "Second")

    def test_rebuild_replaces_entire_catalog(self) -> None:
        adapter = CatalogAdapter(repository_path=self._repo_path)
        adapter.upsert_entry({"requestId": str(uuid4()), "title": "Old", "timestamp": "2026-01-01"})
        rows = [
            {"requestId": str(uuid4()), "title": "New A", "timestamp": "2026-02-01"},
            {"requestId": str(uuid4()), "title": "New B", "timestamp": "2026-03-01"},
        ]
        adapter.rebuild(rows)
        titles = {row["title"] for row in adapter.read_entries()}
        self.assertEqual(titles, {"New A", "New B"})

    def test_build_catalog_row_maps_human_and_synthetic_fields(self) -> None:
        human_id = uuid4()
        human_signed = _build_human_signed(human_id, "human body", title="Human")
        human_row = build_catalog_row(
            human_signed.artifact,
            human_id,
            f"artifact/{human_id}",
            "abc123",
            has_c2pa=False,
            has_process_narrative=False,
        )
        self.assertEqual(human_row["source"], "human")
        self.assertEqual(human_row["modelId"], "human")
        self.assertEqual(human_row["attestationNature"], "self-declaration")

        synthetic_signed = _build_synthetic_signed(uuid4(), "synthetic body")
        synthetic_row = build_catalog_row(
            synthetic_signed.artifact,
            synthetic_signed.request_id,
            f"artifact/{synthetic_signed.request_id}",
            "def456",
            has_c2pa=True,
            has_process_narrative=True,
        )
        self.assertEqual(synthetic_row["source"], "synthetic")
        self.assertEqual(synthetic_row["attestationNature"], "orchestration-declaration")
        self.assertEqual(synthetic_row["provenanceGrade"], "declared")
        self.assertTrue(synthetic_row["hasC2pa"])
        self.assertTrue(synthetic_row["hasProcessNarrative"])

    def test_collect_catalog_rows_from_repo_scans_artifact_branches(self) -> None:
        async def _run() -> None:
            request_id = uuid4()
            event = _build_human_signed(request_id, "branch scan body", title="Scan")
            ledger = GitLedgerAdapter(
                event_bus=InMemoryEventBus(),
                repository_path=self._repo_path,
            )
            await ledger._on_story_signed(event)

        import asyncio

        asyncio.run(_run())
        rows, skipped = collect_catalog_rows_from_repo(self._repo_path)
        self.assertEqual(skipped, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "human")
        self.assertEqual(rows[0]["title"], "Scan")


if __name__ == "__main__":
    unittest.main()
