"""Tests for high-confidence secret detection helpers."""

from __future__ import annotations

import unittest

from src.secrets_guard import assert_secret_free, find_secret_findings


class SecretsGuardTest(unittest.TestCase):
    """Validate secret detection and blocking behavior."""

    def test_detects_google_api_key_pattern(self) -> None:
        findings = find_secret_findings(
            "Leaked key: AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # pragma: allowlist secret
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "google_api_key")

    def test_assert_secret_free_blocks_private_key_header(self) -> None:
        with self.assertRaises(RuntimeError):
            assert_secret_free(
                "artifact body",
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",  # pragma: allowlist secret
            )

    def test_assert_secret_free_allows_normal_story_text(self) -> None:
        assert_secret_free(
            "prompt",
            "Write a short micro-fiction story set in a monolithic city.",
        )


if __name__ == "__main__":
    unittest.main()
