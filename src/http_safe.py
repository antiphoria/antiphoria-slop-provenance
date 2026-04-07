"""HTTP(S)-only helpers for urllib (auditable urlopen for Bandit S310)."""

from __future__ import annotations

import urllib.parse
import urllib.request
from typing import Any

_ALLOWED_HTTP_SCHEMES = frozenset(("http", "https"))


def ensure_allowed_http_url(url: str, *, context: str) -> None:
    """Reject non-http(s) URLs and URLs without a host."""

    parsed = urllib.parse.urlparse(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_HTTP_SCHEMES or not parsed.netloc:
        raise RuntimeError(f"{context} must use http/https with an explicit host. Got: {url!r}")


def build_http_request(
    url: str,
    *,
    context: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> urllib.request.Request:
    """Build a ``Request`` after scheme/host validation (Bandit S310)."""

    ensure_allowed_http_url(url, context=context)
    return urllib.request.Request(  # noqa: S310
        url,
        data=data,
        headers=dict(headers or {}),
        method=method,
    )


def open_http_urlopen(
    request: urllib.request.Request,
    *,
    timeout: float,
    context: str,
) -> Any:
    """Validate ``request.full_url`` then open it (no file/custom schemes)."""

    ensure_allowed_http_url(request.full_url, context=context)
    return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310
