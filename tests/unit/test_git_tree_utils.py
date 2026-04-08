"""Tests for git tree traversal utilities."""

from __future__ import annotations

from pathlib import Path

import pygit2
import pytest

from src.git_tree_utils import MAX_TREE_DEPTH, tree_get_blob


def _validate_relative_path(relative_path: str) -> None:
    """Reject path traversal and absolute paths (mirrors git_tree_utils)."""
    path = Path(relative_path)
    if path.is_absolute() or relative_path.startswith("/"):
        raise ValueError("Absolute paths are not permitted.")
    for part in path.parts:
        if part in (".", ".."):
            raise ValueError("Path traversal ('.' or '..') is not permitted.")


def _tree_get_entry(
    repo: pygit2.Repository,
    tree: pygit2.Tree,
    relative_path: str,
) -> pygit2.TreeEntry | None:
    """Get tree entry at path (test-local; production uses tree_get_blob only)."""
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


def _make_signature() -> pygit2.Signature:
    return pygit2.Signature("Test", "test@test.local")


def _get_parent_ids(repo: pygit2.Repository) -> list:
    """Get parent commit IDs for HEAD, or empty list if orphan."""
    try:
        commit = repo.revparse_single("HEAD")
        if isinstance(commit, pygit2.Commit):
            return [commit.id]
    except (KeyError, pygit2.GitError, ValueError):
        pass
    return []


@pytest.fixture
def repo_with_tree(tmp_path):
    """Build a repo with a commit containing nested tree structure."""
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    repo = pygit2.init_repository(str(repo_path), bare=False, initial_head="main")

    # Blobs
    blob_a = repo.create_blob(b"content a")
    blob_b = repo.create_blob(b"content b")
    blob_nested = repo.create_blob(b"nested content")

    # Inner tree: nested/file.txt
    tb_inner = repo.TreeBuilder()
    tb_inner.insert("file.txt", blob_nested, pygit2.GIT_FILEMODE_BLOB)
    tree_nested_oid = tb_inner.write()

    # Middle tree: dir/ with b.txt and nested/
    tb_dir = repo.TreeBuilder()
    tb_dir.insert("b.txt", blob_b, pygit2.GIT_FILEMODE_BLOB)
    tb_dir.insert("nested", tree_nested_oid, pygit2.GIT_FILEMODE_TREE)
    tree_dir_oid = tb_dir.write()

    # Root tree: a.txt, dir/
    tb_root = repo.TreeBuilder()
    tb_root.insert("a.txt", blob_a, pygit2.GIT_FILEMODE_BLOB)
    tb_root.insert("dir", tree_dir_oid, pygit2.GIT_FILEMODE_TREE)
    tree_root_oid = tb_root.write()

    sig = _make_signature()
    parents = _get_parent_ids(repo)
    repo.create_commit(
        "refs/heads/main",
        sig,
        sig,
        "test tree",
        tree_root_oid,
        parents,
    )
    return repo


@pytest.fixture
def repo_empty_tree(tmp_path):
    """Repo with a commit whose tree has no entries."""
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    repo = pygit2.init_repository(str(repo_path), bare=False, initial_head="main")
    tb = repo.TreeBuilder()
    tree_oid = tb.write()
    sig = _make_signature()
    parents = _get_parent_ids(repo)
    repo.create_commit("refs/heads/main", sig, sig, "empty", tree_oid, parents)
    return repo


@pytest.mark.parametrize(
    "relative_path,expected_blob_content",
    [
        ("", None),
        ("a.txt", b"content a"),
        ("dir/b.txt", b"content b"),
        ("dir/nested/file.txt", b"nested content"),
        ("dir/missing", None),
        ("missing.txt", None),
        ("dir/nested/missing", None),
    ],
)
def test_tree_get_blob(
    repo_with_tree,
    relative_path: str,
    expected_blob_content: bytes | None,
) -> None:
    """tree_get_blob returns blob or None for path traversal."""
    commit = repo_with_tree.revparse_single("HEAD")
    assert isinstance(commit, pygit2.Commit)
    tree = commit.tree

    result = tree_get_blob(repo_with_tree, tree, relative_path)

    if expected_blob_content is None:
        assert result is None
    else:
        assert result is not None
        assert bytes(result.data) == expected_blob_content


def test_tree_get_blob_empty_tree(repo_empty_tree) -> None:
    """tree_get_blob returns None for empty tree."""
    commit = repo_empty_tree.revparse_single("HEAD")
    assert isinstance(commit, pygit2.Commit)
    tree = commit.tree

    assert tree_get_blob(repo_empty_tree, tree, "") is None
    assert tree_get_blob(repo_empty_tree, tree, "a.txt") is None


@pytest.mark.parametrize(
    "relative_path,expected_entry",
    [
        ("", None),
        ("a.txt", True),
        ("dir/b.txt", True),
        ("dir/nested/file.txt", True),
        ("dir", True),
        ("dir/missing", None),
        ("missing", None),
    ],
)
def test_tree_get_entry(
    repo_with_tree,
    relative_path: str,
    expected_entry: bool | None,
) -> None:
    """tree_get_entry returns entry or None for path traversal."""
    commit = repo_with_tree.revparse_single("HEAD")
    assert isinstance(commit, pygit2.Commit)
    tree = commit.tree

    result = _tree_get_entry(repo_with_tree, tree, relative_path)

    if expected_entry is None:
        assert result is None
    else:
        assert result is not None


@pytest.mark.parametrize(
    "malicious_path",
    ["../a.txt", "../../etc/passwd", "/a.txt", "dir/../a.txt"],
)
def test_tree_get_blob_rejects_path_traversal(repo_with_tree, malicious_path: str) -> None:
    """tree_get_blob raises ValueError for path traversal or absolute paths."""
    commit = repo_with_tree.revparse_single("HEAD")
    assert isinstance(commit, pygit2.Commit)
    tree = commit.tree

    with pytest.raises(ValueError, match="not permitted"):
        tree_get_blob(repo_with_tree, tree, malicious_path)
