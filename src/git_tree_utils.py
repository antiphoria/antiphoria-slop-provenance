"""Git tree traversal utilities for path-based blob lookup.

pygit2 Tree[key] only accepts direct child names. Paths with slashes
(e.g. .provenance/transparency-log.jsonl) must be traversed by parts.
"""

from __future__ import annotations

from pathlib import Path

import pygit2

MAX_TREE_DEPTH = 256


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


def tree_get_entry(
    repo: pygit2.Repository,
    tree: pygit2.Tree,
    relative_path: str,
) -> pygit2.TreeEntry | None:
    """Get tree entry at path by traversing. Returns None if path not found.
    Rejects path traversal (.., .) and absolute paths."""
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
    return current[parts[-1]]
