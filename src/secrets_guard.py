"""High-confidence secret detection guard for publishable content."""

from __future__ import annotations

import re
from dataclasses import dataclass

_MAX_PREVIEW = 10


@dataclass(frozen=True)
class SecretFinding:
    """One high-confidence secret detector match."""

    detector: str
    preview: str


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("openai_key_like", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def _preview_secret(raw: str) -> str:
    """Return a masked secret preview for error diagnostics."""

    trimmed = raw.strip()
    if len(trimmed) <= (_MAX_PREVIEW * 2):
        return "***"
    return f"{trimmed[:_MAX_PREVIEW]}...{trimmed[-_MAX_PREVIEW:]}"


def find_secret_findings(text: str) -> list[SecretFinding]:
    """Detect secret-like strings in arbitrary text."""

    findings: list[SecretFinding] = []
    for detector, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                SecretFinding(detector=detector, preview=_preview_secret(match.group(0)))
            )
    return findings


def assert_secret_free(label: str, text: str) -> None:
    """Raise when high-confidence secret patterns are detected."""

    findings = find_secret_findings(text)
    if not findings:
        return
    detectors = sorted({finding.detector for finding in findings})
    previews = ", ".join(finding.preview for finding in findings[:2])
    raise RuntimeError(
        f"Secret-like content detected in '{label}'. "
        f"detectors={detectors}. previews={previews}. "
        "Publication has been blocked."
    )
