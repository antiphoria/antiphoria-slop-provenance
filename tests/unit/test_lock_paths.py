"""Unit tests for repository-scoped lock path helper."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.lock_paths import build_repo_ref_lock_path


class LockPathHelperTest(unittest.TestCase):
    """Validate lock paths stay repo-local and deterministic."""

    def test_uses_dot_git_directory_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / ".git").mkdir()

            lock_path = build_repo_ref_lock_path(
                repo_path,
                "refs/heads/artifact/test-request",
            )

            self.assertEqual(
                lock_path.parent,
                repo_path / ".git" / "antiphoria-locks",
            )
            self.assertTrue(lock_path.parent.exists())
            self.assertTrue(lock_path.name.endswith(".lock"))
            self.assertIn("refs_heads_artifact_test-request", lock_path.name)

    def test_resolves_gitdir_pointer_from_dot_git_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / ".git-real").mkdir()
            (repo_path / ".git").write_text(
                "gitdir: .git-real\n",
                encoding="utf-8",
            )

            lock_path = build_repo_ref_lock_path(repo_path, "refs/heads/main")

            self.assertEqual(
                lock_path.parent,
                repo_path / ".git-real" / "antiphoria-locks",
            )
            self.assertTrue(lock_path.parent.exists())

    def test_falls_back_without_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)

            lock_path = build_repo_ref_lock_path(repo_path, "refs/heads/main")

            self.assertEqual(lock_path.parent, repo_path / ".antiphoria-locks")
            self.assertTrue(lock_path.parent.exists())

    def test_is_stable_for_same_repo_and_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / ".git").mkdir()

            first = build_repo_ref_lock_path(repo_path, "refs/heads/main")
            second = build_repo_ref_lock_path(repo_path, "refs/heads/main")
            other = build_repo_ref_lock_path(repo_path, "refs/heads/feature/x")

            self.assertEqual(first, second)
            self.assertNotEqual(first, other)


if __name__ == "__main__":
    unittest.main()
