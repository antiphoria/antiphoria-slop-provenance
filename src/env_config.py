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
    """Read optional value from local `.env`, then process env."""

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

    value = os.getenv(env_key)
    if value is not None and value.strip():
        return value.strip().strip("'\"")

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
