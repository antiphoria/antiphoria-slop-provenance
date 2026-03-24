"""Shared artifact branch resolution for CLI and worker-style runtimes."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

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
        raise RuntimeError(
            f"Artifact path '{artifact_path}' on '{branch_name}' is not a blob."
        )
    return branch_name, str(commit_obj.id), artifact_path
