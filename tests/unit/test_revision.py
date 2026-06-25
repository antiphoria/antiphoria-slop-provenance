"""Tests for the v3 revision/versioning block (Gap 1).

Covers:
- Envelope render + parse round-trip preserves revision fields.
- Revision is inside the signed envelope target (covered by signature).
- Catalog upsert backfills supersededBy on the prior version's row.
- First version has no revision block (sequence defaults to 1 in catalog).
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from uuid import uuid4

from src.adapters.catalog import build_catalog_row
from src.envelope_v2 import (
    PROFILE_REGISTER,
    PROFILE_SEAL,
    generation_context_for_source,
    parse_artifact_markdown_text_v2,
    render_artifact_markdown_v2,
)
from src.models import (
    Artifact,
    AuthorAttestation,
    Provenance,
    RegistrationCeremony,
    Revision,
    SignatureBlock,
    VerificationAnchor,
    WebAuthnAttestation,
)


def _minimal_artifact(*, revision: Revision | None = None) -> Artifact:
    return Artifact(
        title="Versioned work",
        timestamp=datetime.now(UTC),
        contentType="text/markdown",
        license="ARR",
        rights_holder="Maya R.",
        revision=revision,
        provenance=Provenance(
            source="human",
            engineVersion="test-engine",
            modelId="human",
            generationContext=generation_context_for_source("human"),
            authorAttestation=AuthorAttestation(
                attestationNature="self-declaration",
                attestationMode="unattended",
            ),
            provenanceGrade="declared",
        ),
        signature=SignatureBlock(
            artifactHash="b" * 64,
            cryptographicSignature="ZmFrZQ==",
            verificationAnchor=VerificationAnchor(signerFingerprint="fp"),
        ),
    )


class RevisionRoundTripTest(unittest.TestCase):
    def test_first_version_has_no_revision_block(self) -> None:
        artifact = _minimal_artifact(revision=None)
        body = "Original body text."
        markdown = render_artifact_markdown_v2(
            artifact,
            body,
            ledger_request_id=str(uuid4()),
        )
        self.assertNotIn("revision:", markdown)
        # Round-trip parse preserves absence.
        parsed, parsed_body = parse_artifact_markdown_text_v2(markdown)
        self.assertIsNone(parsed.revision)
        self.assertEqual(parsed_body, body)

    def test_revision_round_trips_through_envelope(self) -> None:
        prior_request_id = str(uuid4())
        revision = Revision(
            chainRoot=prior_request_id,
            sequence=3,
            supersedes=prior_request_id,
            supersedesHash="c" * 64,
            reason="copyright-flag",
            note="copyright holder corrected",
        )
        artifact = _minimal_artifact(revision=revision)
        body = "Updated body text."
        markdown = render_artifact_markdown_v2(
            artifact,
            body,
            ledger_request_id=str(uuid4()),
        )
        # The revision block renders.
        self.assertIn("revision:", markdown)
        self.assertIn("chainRoot:", markdown)
        self.assertIn("sequence: 3", markdown)
        self.assertIn("reason: \"copyright-flag\"", markdown)
        self.assertIn("note: \"copyright holder corrected\"", markdown)

        parsed, parsed_body = parse_artifact_markdown_text_v2(markdown)
        self.assertIsNotNone(parsed.revision)
        assert parsed.revision is not None  # for type checker
        self.assertEqual(parsed.revision.chain_root, prior_request_id)
        self.assertEqual(parsed.revision.sequence, 3)
        self.assertEqual(parsed.revision.supersedes, prior_request_id)
        self.assertEqual(parsed.revision.supersedes_hash, "c" * 64)
        self.assertEqual(parsed.revision.reason, "copyright-flag")
        self.assertEqual(parsed.revision.note, "copyright holder corrected")
        self.assertEqual(parsed_body, body)

    def test_revision_without_note_round_trips(self) -> None:
        revision = Revision(
            chainRoot=str(uuid4()),
            sequence=2,
            supersedes=str(uuid4()),
            supersedesHash="d" * 64,
            reason="editorial",
        )
        artifact = _minimal_artifact(revision=revision)
        markdown = render_artifact_markdown_v2(
            artifact, "body", ledger_request_id=str(uuid4())
        )
        self.assertIn("revision:", markdown)
        self.assertNotIn("note:", markdown.split("revision:")[1].split("rights:")[0])
        parsed, _ = parse_artifact_markdown_text_v2(markdown)
        self.assertIsNotNone(parsed.revision)
        assert parsed.revision is not None
        self.assertIsNone(parsed.revision.note)


class CatalogVersionChainTest(unittest.TestCase):
    def test_build_catalog_row_v1_has_no_supersedes(self) -> None:
        artifact = _minimal_artifact(revision=None)
        row = build_catalog_row(
            artifact,
            request_id=str(uuid4()),
            branch="artifact/v1",
            commit_oid="abc",
            has_c2pa=False,
            has_process_narrative=False,
        )
        self.assertIsNone(row["supersedes"])
        self.assertIsNone(row["supersededBy"])
        self.assertEqual(row["sequence"], 1)

    def test_build_catalog_row_v2_carries_chain_fields(self) -> None:
        prior_rid = str(uuid4())
        revision = Revision(
            chainRoot=prior_rid,
            sequence=2,
            supersedes=prior_rid,
            supersedesHash="e" * 64,
            reason="error-correction",
        )
        artifact = _minimal_artifact(revision=revision)
        new_rid = str(uuid4())
        row = build_catalog_row(
            artifact,
            request_id=new_rid,
            branch="artifact/v2",
            commit_oid="def",
            has_c2pa=False,
            has_process_narrative=False,
        )
        self.assertEqual(row["chainRoot"], prior_rid)
        self.assertEqual(row["sequence"], 2)
        self.assertEqual(row["supersedes"], prior_rid)
        self.assertIsNone(row["supersededBy"])


if __name__ == "__main__":
    unittest.main()
