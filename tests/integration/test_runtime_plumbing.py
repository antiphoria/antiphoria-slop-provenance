"""Regression tests for runtime plumbing behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from uuid import UUID, uuid4

import pygit2

from src.runtime.artifact_resolve import _resolve_artifact_branch_target


def _create_branch_artifact_commit(repo_path: Path, request_id: str) -> str:
    repo = pygit2.Repository(str(repo_path))
    tree_builder = repo.TreeBuilder()
    blob_oid = repo.create_blob(f"payload for {request_id}\n".encode("utf-8"))
    tree_builder.insert(f"{request_id}.md", blob_oid, pygit2.GIT_FILEMODE_BLOB)
    tree_oid = tree_builder.write()

    signature = pygit2.Signature("Runtime Test", "runtime.test@example.com")
    commit_oid = repo.create_commit(
        f"refs/heads/artifact/{request_id}",
        signature,
        signature,
        f"test: create artifact branch {request_id}",
        tree_oid,
        [],
    )
    return str(commit_oid)


class RuntimePlumbingTest(unittest.TestCase):
    """Validate runtime branch smoke checks and entrypoint imports."""

    def test_resolve_artifact_branch_target_finds_branch_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            pygit2.init_repository(str(repo_path), initial_head="master")
            request_id = str(uuid4())
            expected_commit = _create_branch_artifact_commit(repo_path, request_id)

            resolved = _resolve_artifact_branch_target(
                ledger_repo_path=repo_path,
                request_id=UUID(request_id),
            )

            self.assertEqual(
                resolved,
                (
                    f"artifact/{request_id}",
                    expected_commit,
                    f"{request_id}.md",
                ),
            )

    def test_resolve_artifact_branch_target_returns_none_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            pygit2.init_repository(str(repo_path), initial_head="master")
            request_id = uuid4()

            resolved = _resolve_artifact_branch_target(
                ledger_repo_path=repo_path,
                request_id=request_id,
            )
            self.assertIsNone(resolved)


if __name__ == "__main__":
    unittest.main()
