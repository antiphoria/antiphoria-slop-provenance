"""Shared environment configuration helpers with `.env` fallback.

When env_path is None, resolution order:
  1. Explicit env_path (when passed by caller)
  2. PROJECT_ROOT env var (if set) + /.env - for systemd/Docker
  3. Path(".env") relative to CWD

Entrypoints (CLI, workers) should pass explicit env_path when CWD may differ.
"""

from __future__ import annotations

import os
from pathlib import Path


def _resolve_env_path(env_path: Path | None) -> Path:
    """Resolve .env path: explicit > PROJECT_ROOT > CWD."""
    if env_path is not None:
        return env_path
    project_root = os.getenv("PROJECT_ROOT")
    if project_root:
        return Path(project_root).resolve() / ".env"
    return Path(".env")


def read_env_optional(
    env_key: str,
    env_path: Path | None = None,
) -> str | None:
    """Read optional value. Process env overrides .env (12-Factor App)."""
    value = os.getenv(env_key)
    if value is not None:
        return value.strip().strip("'\"")

    resolved_env_path = _resolve_env_path(env_path)
    if resolved_env_path.exists():
        env_text = resolved_env_path.read_text(encoding="utf-8")
        for raw_line in env_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            if key.strip() != env_key:
                continue
            parsed = raw_value.strip().strip("'\"")
            return parsed if parsed else None

    return None


def read_env_required(env_key: str, env_path: Path | None = None) -> str:
    """Read required value from env/.env or raise a descriptive error."""

    value = read_env_optional(env_key, env_path=env_path)
    if value is None:
        raise RuntimeError(
            f"Missing required environment variable '{env_key}'."
        )
    return value


def read_env_bool(
    env_key: str,
    default: bool = False,
    env_path: Path | None = None,
) -> bool:
    """Read boolean flag from env/.env using common truthy/falsy values."""

    value = read_env_optional(env_key, env_path=env_path)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(
        f"Environment variable '{env_key}' must be a boolean value."
    )


def read_env_int(
    env_key: str,
    default: int,
    env_path: Path | None = None,
) -> int:
    """Read integer value from env/.env with strict validation."""

    value = read_env_optional(env_key, env_path=env_path)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(
            f"Environment variable '{env_key}' must be an integer."
        ) from exc


def get_project_env_path() -> Path:
    """Return path to .env at project root. Tries module location, then CWD."""
    candidates = [
        Path(__file__).resolve().parents[1] / ".env",  # editable install
        Path.cwd() / ".env",  # run from project root (e.g. non-editable install)
    ]
    project_root = os.getenv("PROJECT_ROOT")
    if project_root:
        candidates.insert(0, Path(project_root).resolve() / ".env")
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]  # caller may use for project_root even if .env missing


def resolve_artifact_db_path(
    env_path: Path | None = None,
    project_root: Path | None = None,
) -> Path | None:
    """Resolve artifact DB path from ARTIFACT_DB_PATH or ORCHESTRATOR_STATE_DIR.

    Returns None when neither is set (caller may use default).
    """
    raw = read_env_optional("ARTIFACT_DB_PATH", env_path=env_path)
    if raw:
        return Path(raw).resolve()
    state_dir = read_env_optional("ORCHESTRATOR_STATE_DIR", env_path=env_path)
    if state_dir:
        return Path(state_dir).resolve() / "artifacts.db"
    if project_root is not None:
        return (project_root / ".orchestrator-state" / "artifacts.db").resolve()
    return None


def resolve_state_db_path(
    env_path: Path | None = None,
    project_root: Path | None = None,
    service_name: str | None = None,
) -> Path | None:
    """Resolve per-service dedup DB path from STATE_DB_PATH or ORCHESTRATOR_STATE_DIR.

    When service_name is given and STATE_DB_PATH is not set, uses
    {ORCHESTRATOR_STATE_DIR}/dedup/{service_name}.db.
    Returns None when neither is set.
    """
    raw = read_env_optional("STATE_DB_PATH", env_path=env_path)
    if raw:
        return Path(raw).resolve()
    state_dir = read_env_optional("ORCHESTRATOR_STATE_DIR", env_path=env_path)
    if state_dir:
        base = Path(state_dir).resolve()
        if service_name:
            return base / "dedup" / f"{service_name}.db"
        return base / "state.db"
    if project_root is not None and service_name:
        return (
            project_root / ".orchestrator-state" / "dedup" / f"{service_name}.db"
        ).resolve()
    return None


def read_env_choice(
    env_key: str,
    allowed_values: tuple[str, ...],
    default: str,
    env_path: Path | None = None,
) -> str:
    """Read string enum value from env/.env with strict validation."""

    normalized_allowed = {value.lower(): value for value in allowed_values}
    if default.lower() not in normalized_allowed:
        raise RuntimeError(
            f"Default '{default}' is not in allowed values for '{env_key}'."
        )
    value = read_env_optional(env_key, env_path=env_path)
    if value is None:
        return normalized_allowed[default.lower()]
    normalized = value.strip().lower()
    if normalized not in normalized_allowed:
        allowed = ", ".join(allowed_values)
        raise RuntimeError(
            f"Environment variable '{env_key}' must be one of: {allowed}."
        )
    return normalized_allowed[normalized]
