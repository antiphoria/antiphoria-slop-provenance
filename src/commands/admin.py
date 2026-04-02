"""Administrative CLI commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.adapters.key_registry import KeyRegistryAdapter
from src.env_config import get_project_env_path, resolve_artifact_db_path
from src.repository.sqlite import SQLiteRepository


def _run_admin_revoke_key_command(args: argparse.Namespace) -> int:
    """Revoke a signing key by fingerprint."""
    db_path = args.db_path
    if db_path is None:
        env_path = get_project_env_path()
        project_root = env_path.parent
        resolved = resolve_artifact_db_path(
            env_path=env_path,
            project_root=project_root,
        )
        db_path = (
            resolved
            if resolved is not None
            else (
                project_root / ".orchestrator-state" / "artifacts.db"
            ).resolve()
        )
    else:
        db_path = Path(db_path).resolve()

    if not db_path.exists():
        raise RuntimeError(f"State database not found at: {db_path}")

    repository = SQLiteRepository(db_path=db_path)
    key_registry = KeyRegistryAdapter(store=repository.keys)
    if key_registry.get_status(args.fingerprint) is None:
        raise RuntimeError(
            f"Key fingerprint not found in registry: {args.fingerprint}"
        )

    key_registry.set_status(fingerprint=args.fingerprint, status="revoked")
    print(f"Key revoked: fingerprint={args.fingerprint}")
    return 0
