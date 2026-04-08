"""Regression tests for runtime plumbing behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from uuid import UUID, uuid4

import pygit2


def _resolve_artifact_branch_target(
    ledger_repo_path: Path,
    request_id: UUID,
) -> tuple[str, str, str] | None:
    """Return branch, commit, and path when artifact branch/blob exists."""

    try:
        repo = pygit2.Repository(str(ledger_repo_path))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(f"Invalid ledger git repository: '{ledger_repo_path}'.") from exc

    branch_name = f"artifact/{request_id}"
    ref_name = f"refs/heads/{branch_name}"
    try:
        reference = repo.lookup_reference(ref_name)
    except KeyError:
        return None

    commit_obj = repo[reference.target]
    if not isinstance(commit_obj, pygit2.Commit):
        raise RuntimeError(f"Branch ref '{ref_name}' does not point to a commit.")

    artifact_path = f"{request_id}.md"
    try:
        tree_entry = commit_obj.tree[artifact_path]
    except KeyError:
        return None

    blob_obj = repo[tree_entry.id]
    if not isinstance(blob_obj, pygit2.Blob):
        raise RuntimeError(f"Artifact path '{artifact_path}' on '{branch_name}' is not a blob.")
    return branch_name, str(commit_obj.id), artifact_path


def _create_branch_artifact_commit(repo_path: Path, request_id: str) -> str:
    repo = pygit2.Repository(str(repo_path))
    tree_builder = repo.TreeBuilder()
    blob_oid = repo.create_blob(f"payload for {request_id}\n".encode())
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
