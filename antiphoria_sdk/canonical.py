"""Canonical JSON serialization for chain records.

Uses RFC 8785 (JCS) via the `rfc8785` package when available.
Falls back to `json.dumps(sort_keys=True, separators=(',',':'))` otherwise
with a one-time warning. Production deployments should install rfc8785.
"""

from __future__ import annotations

import json
import logging
from typing import Any

_LOGGER = logging.getLogger(__name__)
_FALLBACK_WARNED = False

try:
    import rfc8785

    _JCS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _JCS_AVAILABLE = False


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize `obj` to canonical JSON bytes (UTF-8, no trailing newline).

    Deterministic: equal inputs produce byte-identical outputs across runs.
    """
    global _FALLBACK_WARNED
    if _JCS_AVAILABLE:
        return rfc8785.dumps(obj)
    if not _FALLBACK_WARNED:
        _LOGGER.warning(
            "rfc8785 not installed; using json.dumps(sort_keys=True) fallback. "
            "This is NOT strict JCS. Install rfc8785 for production.",
        )
        _FALLBACK_WARNED = True
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
