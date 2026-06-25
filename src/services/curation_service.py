"""Artifact helpers shared by CLI and provenance workflows.

Historically this module also held curation-specific logic; the `curate`
command was removed in v3 (pre-release.md §1) and replaced by supersession
versioning (Gap 1). The general artifact helpers below remain because
register/seal reuse them.
"""

from __future__ import annotations

import re
from pathlib import Path
from uuid import UUID


def extract_request_id_from_artifact_path(file_path: Path) -> UUID:
    """Extract request id from artifact filename."""

    try:
        return UUID(file_path.stem)
    except ValueError:
        match = re.match(r"^\d{8}T\d{6}Z_([0-9a-fA-F-]{36})\.md$", file_path.name)
        if match is None:
            raise RuntimeError(
                "Invalid artifact filename format. Expected "
                "'<request_id>.md' (preferred) or 'YYYYMMDDTHHMMSSZ_<request_id>.md'."
            ) from None
        return UUID(match.group(1))


def extract_markdown_body(markdown_text: str) -> str:
    """Remove frontmatter, returning raw artifact body. Body is everything after
    the second --- delimiter. No footer."""
    if "\x00" in markdown_text:
        raise RuntimeError("Artifact contains null bytes; invalid payload.")
    body = markdown_text
    if body.startswith("---\n"):
        second_delimiter_index = body.find("\n---\n", 4)
        if second_delimiter_index == -1:
            raise RuntimeError("Invalid markdown frontmatter block.")
        body = body[second_delimiter_index + len("\n---\n") :]
    stripped = body.strip()
    if not stripped:
        raise RuntimeError("Artifact body is empty after metadata stripping.")
    return stripped
