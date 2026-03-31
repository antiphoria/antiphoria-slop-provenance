"""Regression tests for key registry security invariants."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.adapters.key_registry import KeyRegistryAdapter
from src.repository.sqlite import SQLiteRepository


class KeyRegistryAdapterTest(unittest.TestCase):
    """Validate strict status and revocation behavior."""

    def test_rejects_unknown_status_values(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            db_path = Path(temp_dir) / "state.db"
            repository = SQLiteRepository(db_path=db_path)
            adapter = KeyRegistryAdapter(store=repository.keys)

            with self.assertRaises(RuntimeError):
                adapter.register_key(
                    fingerprint="fp-1",
                    key_version="v1",
                    status="invalid-status",
                )

            adapter.register_key(
                fingerprint="fp-1",
                key_version="v1",
                status="active",
            )
            with self.assertRaises(RuntimeError):
                adapter.set_status(fingerprint="fp-1", status="typo")

    def test_set_status_raises_on_unknown_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            db_path = Path(temp_dir) / "state.db"
            repository = SQLiteRepository(db_path=db_path)
            adapter = KeyRegistryAdapter(store=repository.keys)

            with self.assertRaises(RuntimeError):
                adapter.set_status(fingerprint="missing-fingerprint", status="revoked")

    def test_register_key_cannot_reactivate_revoked_key(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            db_path = Path(temp_dir) / "state.db"
            repository = SQLiteRepository(db_path=db_path)
            adapter = KeyRegistryAdapter(store=repository.keys)

            adapter.register_key(
                fingerprint="fp-2",
                key_version="v1",
                status="active",
            )
            adapter.set_status(fingerprint="fp-2", status="revoked")

            with self.assertRaises(RuntimeError):
                adapter.register_key(
                    fingerprint="fp-2",
                    key_version="v2",
                    status="active",
                )


if __name__ == "__main__":
    unittest.main()
