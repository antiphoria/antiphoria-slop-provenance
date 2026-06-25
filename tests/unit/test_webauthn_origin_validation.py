"""Tests for WebAuthn origin <-> RP ID matching (v3 Flaw A hardening).

A naive ``origin.endswith(rp_id)`` check is exploitable: ``evil-antiphoria.org``
ends with ``antiphoria.org`` yet is a wholly different registrable domain. The
verifier must parse the host and require an exact or dot-delimited subdomain
match.
"""

from __future__ import annotations

import unittest

from src.webauthn_attestation import _origin_matches_rp_id

_RP_ID = "antiphoria.org"


class OriginMatchesRpIdTest(unittest.TestCase):
    def test_exact_origin_matches(self) -> None:
        self.assertTrue(_origin_matches_rp_id("https://antiphoria.org", _RP_ID))

    def test_subdomain_matches(self) -> None:
        self.assertTrue(_origin_matches_rp_id("https://www.antiphoria.org", _RP_ID))
        self.assertTrue(
            _origin_matches_rp_id("https://bridge.antiphoria.org", _RP_ID)
        )

    def test_origin_with_port_matches(self) -> None:
        self.assertTrue(_origin_matches_rp_id("https://antiphoria.org:443", _RP_ID))

    def test_prefix_lookalike_rejected(self) -> None:
        self.assertFalse(_origin_matches_rp_id("https://evil-antiphoria.org", _RP_ID))

    def test_suffix_lookalike_rejected(self) -> None:
        self.assertFalse(
            _origin_matches_rp_id("https://antiphoria.org.evil.com", _RP_ID)
        )

    def test_substring_without_boundary_rejected(self) -> None:
        self.assertFalse(_origin_matches_rp_id("https://notantiphoria.org", _RP_ID))

    def test_empty_or_malformed_rejected(self) -> None:
        self.assertFalse(_origin_matches_rp_id("", _RP_ID))
        self.assertFalse(_origin_matches_rp_id("not a url", _RP_ID))
        self.assertFalse(_origin_matches_rp_id("https://antiphoria.org", ""))

    def test_case_insensitive(self) -> None:
        self.assertTrue(_origin_matches_rp_id("https://Antiphoria.ORG", _RP_ID))


if __name__ == "__main__":
    unittest.main()
