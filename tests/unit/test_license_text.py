"""Unit tests for canonical license notice/statement text."""

from __future__ import annotations

import unittest

from src.policies.license_text import resolve_license_text


class LicenseTextTest(unittest.TestCase):
    def test_arr_register_text(self) -> None:
        text = resolve_license_text("ARR")
        self.assertEqual(text.notice, "© 2026 antiphoria. All Rights Reserved.")
        self.assertIn("Copyright © 2026 antiphoria. All rights reserved.", text.statement)
        self.assertIn("prior written permission from antiphoria", text.statement)

    def test_cc0_seal_text(self) -> None:
        text = resolve_license_text("CC0-1.0")
        self.assertEqual(text.notice, "🅍 CC0 1.0 • Public Domain • antiphoria")
        self.assertEqual(
            text.statement,
            "To the extent possible under law, antiphoria has waived all copyright and "
            "related or neighboring rights to this work under the CC0 1.0 Universal "
            "(CC0 1.0) Public Domain Dedication.",
        )

    def test_unknown_policy_fallback(self) -> None:
        text = resolve_license_text("CUSTOM-1.0")
        self.assertIn("CUSTOM-1.0", text.notice)
        self.assertIn("CUSTOM-1.0", text.statement)


if __name__ == "__main__":
    unittest.main()
