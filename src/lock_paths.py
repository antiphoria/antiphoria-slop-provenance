"""Shared helpers for repo-scoped lock file paths."""

from __future__ import annotations

import hashlib
from pathlib import Path

_LOCK_SUBDIRECTORY = "antiphoria-locks"


def _resolve_git_dir(repository_path: Path) -> Path | None:
    """Resolve the effective git dir for standard repos and worktrees."""

    git_path = repository_path / ".git"
    if git_path.is_dir():
        return git_path
    if not git_path.is_file():
        return None
    try:
        first_line = (
            git_path.read_text(encoding="utf-8").splitlines()[0].strip()
        )
    except (OSError, IndexError):
        return None
    if not first_line.lower().startswith("gitdir:"):
        return None
    git_dir_raw = first_line.split(":", 1)[1].strip()
    if not git_dir_raw:
        return None
    git_dir = Path(git_dir_raw)
    if git_dir.is_absolute():
        return git_dir
    return (repository_path / git_dir).resolve()


def build_repo_ref_lock_path(repository_path: Path, ref_name: str) -> Path:
    """Build deterministic lock path scoped to one repository + ref."""

    repo_root = repository_path.resolve()
    repo_hash = hashlib.sha256(str(repo_root).encode("utf-8")).hexdigest()[:16]
    safe_ref = ref_name.replace("/", "_")

    git_dir = _resolve_git_dir(repo_root)
    lock_dir = (
        git_dir / _LOCK_SUBDIRECTORY
        if git_dir is not None
        else repo_root / ".antiphoria-locks"
    )
    lock_dir.mkdir(parents=True, exist_ok=True)
    return lock_dir / f"{repo_hash}_{safe_ref}.lock"
