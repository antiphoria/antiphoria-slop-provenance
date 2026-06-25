"""Tests for the local transparency log.

v3: all remote-publication tests were removed with the Supabase code
(pre-release.md §1). The two tests below cover the local hash-chain helpers
that remain.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.adapters.transparency_log import TransparencyLogAdapter


class TransparencyLogHashHelperTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._log_path = Path(self._tmp.name) / "transparency-log.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_entry_hash_matches_payload_hash_helper(self) -> None:
        adapter = TransparencyLogAdapter(log_path=self._log_path)

        entry, serializable = adapter.build_entry_record(
            artifact_hash="f" * 64,
            artifact_id="a" * 36,
            source_file="artifact.md",
            previous_entry_hash=None,
            request_id="b" * 36,
            metadata={"source": "human"},
            bitcoin_block_height=123,
        )
        computed = adapter.compute_expected_entry_hash_from_payload(serializable)
        self.assertEqual(computed, entry.entry_hash)

    def test_payload_hash_helper_normalizes_non_dict_metadata(self) -> None:
        payload = {
            "entryId": "id-1",
            "artifactHash": "a" * 64,
            "artifactId": "artifact-1",
            "requestId": "request-1",
            "sourceFile": "artifact.md",
            "previousEntryHash": None,
            "anchoredAt": "2026-01-01T00:00:00+00:00",
            "metadata": ["unexpected", "shape"],
        }
        normalized = dict(payload)
        normalized["metadata"] = {}

        hash_from_list = TransparencyLogAdapter.compute_expected_entry_hash_from_payload(payload)
        hash_from_dict = TransparencyLogAdapter.compute_expected_entry_hash_from_payload(normalized)
        self.assertEqual(hash_from_list, hash_from_dict)


if __name__ == "__main__":
    unittest.main()
