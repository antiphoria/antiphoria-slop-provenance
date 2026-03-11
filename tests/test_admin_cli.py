"""Tests for admin CLI commands (key revocation, etc.)."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from src import cli
from src.adapters.key_registry import KeyRegistryAdapter
from src.repository import SQLiteRepository


class AdminRevokeKeyTest(unittest.TestCase):
    """Validate admin revoke-key command behavior."""

    def test_revoke_key_raises_when_state_db_missing(self) -> None:
        """Revoke-key raises RuntimeError when state.db does not exist."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "nonexistent" / "state.db"
            args = cli.build_parser().parse_args(
                ["admin", "revoke-key", "--fingerprint", "abc123", "--state-db-path", str(db_path)]
            )
            with self.assertRaises(RuntimeError) as ctx:
                cli._run_admin_revoke_key_command(args)
            self.assertIn("State database not found", str(ctx.exception))
            self.assertIn(str(db_path), str(ctx.exception))

    def test_revoke_key_raises_when_fingerprint_not_found(self) -> None:
        """Revoke-key raises RuntimeError when fingerprint is not in registry."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_path = Path(tmp) / "state.db"
            repository = SQLiteRepository(db_path=db_path)
            key_registry = KeyRegistryAdapter(repository=repository)
            key_registry.register_key(fingerprint="known-fp", key_version="v1")
            del repository, key_registry

            args = cli.build_parser().parse_args(
                ["admin", "revoke-key", "--fingerprint", "unknown-fp", "--state-db-path", str(db_path)]
            )
            with self.assertRaises(RuntimeError) as ctx:
                cli._run_admin_revoke_key_command(args)
            self.assertIn("Key fingerprint not found", str(ctx.exception))
            self.assertIn("unknown-fp", str(ctx.exception))

    def test_revoke_key_succeeds_when_fingerprint_exists(self) -> None:
        """Revoke-key succeeds and updates status when fingerprint exists."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_path = Path(tmp) / "state.db"
            repository = SQLiteRepository(db_path=db_path)
            key_registry = KeyRegistryAdapter(repository=repository)
            key_registry.register_key(fingerprint="my-fp", key_version="v1")
            self.assertEqual(key_registry.get_status("my-fp"), "active")
            del repository, key_registry

            args = cli.build_parser().parse_args(
                ["admin", "revoke-key", "--fingerprint", "my-fp", "--state-db-path", str(db_path)]
            )
            result = cli._run_admin_revoke_key_command(args)
            self.assertEqual(result, 0)

            repository2 = SQLiteRepository(db_path=db_path)
            key_registry2 = KeyRegistryAdapter(repository=repository2)
            self.assertEqual(key_registry2.get_status("my-fp"), "revoked")
