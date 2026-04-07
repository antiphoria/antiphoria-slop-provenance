"""Shared pytest fixtures for unit and integration tests.

Phase 0 fixtures: physical state, no mocks for pygit2/subprocess.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pygit2
import pytest

_OQS_STUB_DISABLE_ENV = "PYTEST_DISABLE_OQS_STUB"
_TESTS_ROOT = Path(__file__).resolve().parent
_OQS_STUB_PATH = _TESTS_ROOT / "stubs"

if os.getenv(_OQS_STUB_DISABLE_ENV) != "1" and _OQS_STUB_PATH.exists():
    oqs_stub_path = str(_OQS_STUB_PATH)
    if oqs_stub_path not in sys.path:
        sys.path.insert(0, oqs_stub_path)

from src.repository.sqlite import SQLiteRepository  # noqa: E402


@pytest.fixture
def empty_git_repo(tmp_path: Path) -> Path:
    """Real pygit2 repo on disk.

    No mocks. Use for GitLedgerAdapter, OtsQueueAdapter, ProvenanceService.
    """
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    pygit2.init_repository(str(repo_path), bare=False)
    return repo_path


@pytest.fixture
def fake_ots_binary(tmp_path: Path) -> Path:
    """Fake OTS CLI.

    MUST parse sys.argv: stamp writes sys.argv[2]+'.ots'; upgrade overwrites
    sys.argv[2].
    """
    script_content = """import sys
from pathlib import Path
if len(sys.argv) < 3:
    sys.exit(1)
cmd, path_str = sys.argv[1], sys.argv[2]
path = Path(path_str)
if cmd == "stamp":
    Path(path_str + ".ots").write_bytes(b"fake_ots_stamp_dummy")
elif cmd == "upgrade":
    path.write_bytes(b"fake_ots_upgraded_dummy")
else:
    sys.exit(1)
"""
    if sys.platform == "win32":
        exe = tmp_path / "fake_ots.cmd"
        script = tmp_path / "fake_ots.py"
        script.write_text(script_content, encoding="utf-8")
        exe.write_text(
            f'@"{sys.executable}" "{script}" %*\n',
            encoding="utf-8",
        )
    else:
        exe = tmp_path / "fake_ots"
        exe.write_text(
            f"#!{sys.executable}\n" + script_content,
            encoding="utf-8",
        )
        exe.chmod(0o755)
    return exe


@pytest.fixture
def temp_sqlite_db(tmp_path: Path) -> Path:
    """SQLite DB with schema initialized.

    MUST instantiate SQLiteRepository to create tables before yielding.
    """
    db_path = tmp_path / "state.db"
    SQLiteRepository(db_path=db_path)
    return db_path


@pytest.fixture
def temp_sqlite_repository(tmp_path: Path) -> SQLiteRepository:
    """SQLiteRepository instance with initialized schema."""
    db_path = tmp_path / "state.db"
    return SQLiteRepository(db_path=db_path)
