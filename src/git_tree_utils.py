"""Git tree traversal utilities for path-based blob lookup.

pygit2 Tree[key] only accepts direct child names. Paths with slashes
(e.g. .provenance/transparency-log.jsonl) must be traversed by parts.
"""

from __future__ import annotations

from pathlib import Path

import pygit2


def tree_get_blob(
    repo: pygit2.Repository,
    tree: pygit2.Tree,
    relative_path: str,
) -> pygit2.Blob | None:
    """Get blob at path by traversing tree. Returns None if path not found.

    Handles both single-part paths (e.g. uuid.md) and nested paths
    (e.g. .provenance/transparency-log.jsonl). pygit2 tree[key] only
    accepts direct child names; this walks the tree by path parts.
    """
    parts = Path(relative_path).parts
    if not parts:
        return None
    current: pygit2.Tree | None = tree
    for part in parts[:-1]:
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
    """Get tree entry at path by traversing. Returns None if path not found."""
    parts = Path(relative_path).parts
    if not parts:
        return None
    current: pygit2.Tree | None = tree
    for part in parts[:-1]:
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
