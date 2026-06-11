"""Git tree traversal utilities for path-based blob lookup.

pygit2 Tree[key] only accepts direct child names. Paths with slashes
(e.g. .provenance/transparency-log.jsonl) must be traversed by parts.
"""

from __future__ import annotations

from pathlib import Path

import pygit2

MAX_TREE_DEPTH = 256
_DEFAULT_BRANCH_NAMES = frozenset({"main", "master"})
_MANAGED_WORKTREE_PREFIX = ".provenance"


def _branch_short_name(ref_name: str) -> str:
    prefix = "refs/heads/"
    if ref_name.startswith(prefix):
        return ref_name[len(prefix) :]
    return ref_name


def _is_artifact_branch_ref(ref_name: str) -> bool:
    return _branch_short_name(ref_name).startswith("artifact/")


def _is_default_branch_ref(ref_name: str) -> bool:
    return _branch_short_name(ref_name) in _DEFAULT_BRANCH_NAMES


def _peel_ref_commit(repo: pygit2.Repository, ref_name: str) -> pygit2.Commit | None:
    try:
        ref = repo.lookup_reference(ref_name)
        commit = ref.peel(pygit2.Commit)
    except (KeyError, pygit2.GitError, ValueError):
        return None
    return commit if isinstance(commit, pygit2.Commit) else None


def _resolve_head_branch_ref(repo: pygit2.Repository) -> str | None:
    try:
        head_ref = repo.lookup_reference("HEAD")
    except KeyError:
        return None
    target = head_ref.target
    if isinstance(target, str) and target.startswith("refs/heads/"):
        return target
    return None


def _validate_relative_path(relative_path: str) -> None:
    """Reject path traversal and absolute paths."""
    path = Path(relative_path)
    if path.is_absolute() or relative_path.startswith("/"):
        raise ValueError("Absolute paths are not permitted.")
    for part in path.parts:
        if part in (".", ".."):
            raise ValueError("Path traversal ('.' or '..') is not permitted.")


def tree_get_blob(
    repo: pygit2.Repository,
    tree: pygit2.Tree,
    relative_path: str,
) -> pygit2.Blob | None:
    """Get blob at path by traversing tree. Returns None if path not found.

    Handles both single-part paths (e.g. uuid.md) and nested paths
    (e.g. .provenance/transparency-log.jsonl). pygit2 tree[key] only
    accepts direct child names; this walks the tree by path parts.
    Rejects path traversal (.., .) and absolute paths.
    """
    _validate_relative_path(relative_path)
    parts = Path(relative_path).parts
    if not parts:
        return None
    current: pygit2.Tree | None = tree
    for depth, part in enumerate(parts[:-1]):
        if depth >= MAX_TREE_DEPTH:
            return None
        if current is None or part not in current:
            return None
        entry = current[part]
        obj = repo[entry.id]
        if not isinstance(obj, pygit2.Tree):
            return None
        current = obj
    if current is None or parts[-1] not in current:
        return None
    entry = current[parts[-1]]
    obj = repo[entry.id]
    if not isinstance(obj, pygit2.Blob):
        return None
    return obj


def resolve_branch_init_parent(
    repo: pygit2.Repository,
    target_ref: str,
) -> tuple[list[pygit2.Oid], pygit2.Oid]:
    """Resolve parent commit(s) and tree when creating ``target_ref`` for the first time.

    Prefer branching from HEAD (when it points at ``main``/``master``), then ``main``,
    then ``master``, so provenance sidecars on an existing default branch are not dropped
    when ``CATALOG_REF`` / ``OTS_QUEUE_REF`` points at a ref that did not exist yet.

    Never inherit from ``artifact/*`` branches: those hold canonical artifact blobs and
    must not be copied onto the archive default branch.
    """

    candidate_refs: list[str] = []
    head_branch = _resolve_head_branch_ref(repo)
    if (
        head_branch is not None
        and head_branch != target_ref
        and _is_default_branch_ref(head_branch)
        and not _is_artifact_branch_ref(head_branch)
    ):
        candidate_refs.append(head_branch)
    for name in ("refs/heads/main", "refs/heads/master"):
        if name != target_ref and name not in candidate_refs:
            candidate_refs.append(name)

    for ref_name in candidate_refs:
        commit = _peel_ref_commit(repo, ref_name)
        if commit is not None:
            return [commit.id], commit.tree_id

    return [], repo.TreeBuilder().write()


def _collect_blob_paths(
    repo: pygit2.Repository,
    tree: pygit2.Tree,
    *,
    prefix: str = "",
) -> dict[str, pygit2.Blob]:
    """Map relative repo paths to blob objects under ``tree``."""

    paths: dict[str, pygit2.Blob] = {}
    for entry in tree:
        name = entry.name
        rel = f"{prefix}/{name}" if prefix else name
        obj = repo[entry.id]
        if isinstance(obj, pygit2.Tree):
            paths.update(_collect_blob_paths(repo, obj, prefix=rel))
        elif isinstance(obj, pygit2.Blob):
            paths[rel] = obj
    return paths


def _managed_worktree_paths(
    repo: pygit2.Repository,
    commit: pygit2.Commit,
) -> dict[str, pygit2.Blob]:
    all_paths = _collect_blob_paths(repo, commit.tree)
    prefix = _MANAGED_WORKTREE_PREFIX
    return {
        path: blob
        for path, blob in all_paths.items()
        if path == prefix or path.startswith(f"{prefix}/")
    }


def sync_default_branch_worktree(
    repo: pygit2.Repository,
    target_ref: str,
) -> None:
    """Mirror ``.provenance/*`` from ``target_ref`` into worktree and index.

    pygit2 commits update refs without touching the working tree or index.
    For managed non-bare archives, keep disk and index aligned with the default
    branch after each provenance commit so ``git status`` stays clean.
    """

    if not _is_default_branch_ref(target_ref) or repo.is_bare:
        return
    workdir_raw = repo.workdir
    if not workdir_raw:
        return
    commit = _peel_ref_commit(repo, target_ref)
    if commit is None:
        return

    workdir = Path(workdir_raw)
    managed_paths = _managed_worktree_paths(repo, commit)
    index = repo.index

    for rel_path, blob in managed_paths.items():
        full_path = workdir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(blob.data)
        index.add(rel_path)

    managed_dir = workdir / _MANAGED_WORKTREE_PREFIX
    if managed_dir.exists():
        expected = set(managed_paths.keys())
        for disk_path in managed_dir.rglob("*"):
            if not disk_path.is_file():
                continue
            rel = disk_path.relative_to(workdir).as_posix()
            if rel in expected:
                continue
            disk_path.unlink()
            try:
                index.remove(rel)
            except KeyError:
                pass

    index.write()


def ensure_branch_exists(
    repo: pygit2.Repository,
    target_ref: str,
    signature: pygit2.Signature,
    init_message: str,
) -> bool:
    """Create ``target_ref`` from an existing branch tip when missing.

    Returns True when a new ref was created.
    """

    try:
        ref = repo.lookup_reference(target_ref)
        ref.peel(pygit2.Commit)
        return False
    except (KeyError, pygit2.GitError, ValueError):
        pass
    parent_ids, tree_oid = resolve_branch_init_parent(repo, target_ref)
    repo.create_commit(
        target_ref,
        signature,
        signature,
        init_message,
        tree_oid,
        parent_ids,
    )
    sync_default_branch_worktree(repo, target_ref)
    return True


def commit_tree_file(
    repo: pygit2.Repository,
    target_ref: str,
    relative_path: str,
    content: bytes,
    message: str,
    signature: pygit2.Signature,
) -> bool:
    """Commit one blob at ``relative_path`` on ``target_ref``, preserving sibling paths.

    Returns True when a new commit was created.
    """

    _validate_relative_path(relative_path)
    ref = repo.lookup_reference(target_ref)
    parent = ref.peel(pygit2.Commit)

    path_parts = Path(relative_path).parts
    blob_oid = repo.create_blob(content)
    current_tree: pygit2.Tree | None = parent.tree
    tree_stack: list[pygit2.Tree | None] = [current_tree]
    for part in path_parts[:-1]:
        if current_tree is not None and part in current_tree:
            entry = current_tree[part]
            obj = repo[entry.id]
            current_tree = obj if isinstance(obj, pygit2.Tree) else None
        else:
            current_tree = None
        tree_stack.append(current_tree)

    current_oid = blob_oid
    current_mode = pygit2.GIT_FILEMODE_BLOB
    for index, part in reversed(list(enumerate(path_parts))):
        tree_builder = (
            repo.TreeBuilder(tree_stack[index])
            if tree_stack[index] is not None
            else repo.TreeBuilder()
        )
        tree_builder.insert(part, current_oid, current_mode)
        current_oid = tree_builder.write()
        current_mode = pygit2.GIT_FILEMODE_TREE

    if current_oid == parent.tree_id:
        return False
    repo.create_commit(
        target_ref,
        signature,
        signature,
        message,
        current_oid,
        [parent.id],
    )
    sync_default_branch_worktree(repo, target_ref)
    return True
