"""Curation helpers shared by CLI and provenance workflows."""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from uuid import UUID

from src.models import Curation


def extract_request_id_from_artifact_path(file_path: Path) -> UUID:
    """Extract request id from curated artifact filename."""

    try:
        return UUID(file_path.stem)
    except ValueError:
        match = re.match(r"^\d{8}T\d{6}Z_([0-9a-fA-F-]{36})\.md$", file_path.name)
        if match is None:
            raise RuntimeError(
                "Invalid curated artifact filename format. Expected "
                "'<request_id>.md' (preferred) or 'YYYYMMDDTHHMMSSZ_<request_id>.md'."
            )
        return UUID(match.group(1))


def extract_markdown_body(markdown_text: str) -> str:
    """Remove frontmatter and signature footer, returning raw artifact body."""

    body = markdown_text
    if body.startswith("---\n"):
        second_delimiter_index = body.find("\n---\n", 4)
        if second_delimiter_index == -1:
            raise RuntimeError("Invalid markdown frontmatter block.")
        body = body[second_delimiter_index + len("\n---\n") :]

    footer_marker = "\n-----BEGIN ANTINOMIE-INSTITUT ARTIFACT SIGNATURE-----"
    footer_index = body.find(footer_marker)
    if footer_index != -1:
        body = body[:footer_index]

    stripped = body.strip()
    if not stripped:
        raise RuntimeError("Curated artifact body is empty after metadata stripping.")
    return stripped


def build_curation_metadata(original_body: str, curated_body: str) -> Curation:
    """Calculate difference score and unified diff for curation analytics."""

    matcher = difflib.SequenceMatcher(None, original_body, curated_body)
    difference_score = round((1.0 - matcher.ratio()) * 100.0, 2)
    diff_lines = list(
        difflib.unified_diff(
            original_body.splitlines(),
            curated_body.splitlines(),
            fromfile="original",
            tofile="curated",
            lineterm="",
        )
    )
    unified_diff = "\n".join(diff_lines) if diff_lines else "--- original\n+++ curated"
    return Curation(differenceScore=difference_score, unifiedDiff=unified_diff)
