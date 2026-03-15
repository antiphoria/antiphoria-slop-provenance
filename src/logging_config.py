"""Logging granularity and request-scoped context for route tracing.

Provides coarse-to-fine trace levels and contextvars-based propagation
of request_id, command, and artifact_id for correlation across async boundaries.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from src.env_config import get_project_env_path, read_env_optional

_ALLOWED_GRANULARITIES = ("minimal", "standard", "coarse", "fine", "trace")
_DEFAULT_GRANULARITY = "standard"


@dataclass
class LogContextData:
    """Mutable container for log context fields."""

    request_id: str | None = None
    command: str | None = None
    artifact_id: str | None = None


_log_context_var: contextvars.ContextVar[LogContextData] = contextvars.ContextVar(
    "log_context",
    default=LogContextData(),
)


def get_trace_granularity(env_path: Path | None = None) -> str:
    """Return LOG_TRACE_GRANULARITY from env; default 'standard'.

    Valid values: minimal, standard, coarse, fine, trace.
    Invalid values fall back to standard.
    """
    raw = read_env_optional(
        "LOG_TRACE_GRANULARITY",
        env_path=env_path or get_project_env_path(),
    )
    if raw is None:
        return _DEFAULT_GRANULARITY
    normalized = raw.strip().lower()
    if normalized in _ALLOWED_GRANULARITIES:
        return normalized
    return _DEFAULT_GRANULARITY


def should_log_route(level: str, env_path: Path | None = None) -> bool:
    """Return True if route logs should be emitted at the given granularity.

    level: one of 'coarse', 'fine', 'trace'.
    coarse+ = coarse, fine, trace
    fine+ = fine, trace
    trace = trace only
    """
    gran = get_trace_granularity(env_path)
    if gran == "minimal" or gran == "standard":
        return False
    if level == "coarse":
        return gran in ("coarse", "fine", "trace")
    if level == "fine":
        return gran in ("fine", "trace")
    if level == "trace":
        return gran == "trace"
    return False


def get_log_context() -> LogContextData:
    """Return the current log context (request_id, command, artifact_id)."""
    return _log_context_var.get()


def bind_log_context(
    *,
    request_id: UUID | str | None = None,
    command: str | None = None,
    artifact_id: UUID | str | None = None,
) -> None:
    """Set log context fields for the current async context.

    Only updates fields that are explicitly passed (not None).
    """
    ctx = _log_context_var.get()
    new_ctx = LogContextData(
        request_id=str(request_id) if request_id is not None else ctx.request_id,
        command=command if command is not None else ctx.command,
        artifact_id=str(artifact_id) if artifact_id is not None else ctx.artifact_id,
    )
    _log_context_var.set(new_ctx)


def clear_log_context() -> None:
    """Reset log context to defaults."""
    _log_context_var.set(LogContextData())


def get_log_extra() -> dict[str, str]:
    """Return extra dict for logging, populated from LogContext when available."""
    ctx = get_log_context()
    extra: dict[str, str] = {}
    if ctx.request_id is not None:
        extra["request_id"] = ctx.request_id
    if ctx.command is not None:
        extra["command"] = ctx.command
    if ctx.artifact_id is not None:
        extra["artifact_id"] = ctx.artifact_id
    return extra


def redact_event_for_trace(event: Any) -> dict[str, Any]:
    """Build a redacted dict from an event for trace-level logging.

    Excludes: body, prompt, curated_body, raw key material, tokens.
    Truncates artifact_hash to 16 chars for readability.
    """
    if not hasattr(event, "model_dump"):
        return {"_type": type(event).__name__, "_raw": str(event)[:200]}

    skip_keys = {
        "body",
        "prompt",
        "curated_body",
        "c2pa_manifest_bytes_b64",
        "pending_ots_b64",
        "final_ots_b64",
        "token_base64",
        "usage_metrics",
    }
    raw = event.model_dump(mode="json")
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if k in skip_keys:
            out[k] = "<redacted>"
        elif k == "artifact_hash" and isinstance(v, str) and len(v) > 16:
            out[k] = f"{v[:16]}..."
        elif k == "artifact" and isinstance(v, dict):
            out[k] = {kk: vv for kk, vv in v.items() if kk not in skip_keys}
        else:
            out[k] = v
    out["_event_type"] = type(event).__name__
    return out
