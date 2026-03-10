"""Shared parsing helpers for artifact markdown payloads."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.models import Artifact

_FOOTER_MARKERS: tuple[str, ...] = (
    "\n-----BEGIN ANTIPHORIA-INSTITUT ARTIFACT SIGNATURE-----",
)


def parse_artifact_markdown(file_path: Path) -> tuple[Artifact, str]:
    """Parse artifact markdown into strict envelope and body payload."""

    if not file_path.exists():
        raise RuntimeError(f"Artifact file not found: '{file_path}'.")
    text = file_path.read_text(encoding="utf-8")
    return parse_artifact_markdown_text(text)


def parse_artifact_markdown_text(text: str) -> tuple[Artifact, str]:
    """Parse artifact markdown text into strict envelope and body payload."""

    if not text.startswith("---\n"):
        raise RuntimeError("Artifact file is missing YAML frontmatter delimiter.")
    delimiter_index = text.find("\n---\n", 4)
    if delimiter_index == -1:
        raise RuntimeError("Artifact file has malformed YAML frontmatter.")
    frontmatter_text = text[4:delimiter_index]
    payload_text = text[delimiter_index + len("\n---\n"):]
    footer_index = -1
    for footer_marker in _FOOTER_MARKERS:
        candidate_index = payload_text.find(footer_marker)
        if candidate_index == -1:
            continue
        if footer_index == -1 or candidate_index < footer_index:
            footer_index = candidate_index

    if footer_index != -1:
        payload_text = payload_text[:footer_index]
    payload = payload_text.strip()
    if not payload:
        raise RuntimeError("Artifact payload is empty after metadata stripping.")
    loaded: Any = yaml.safe_load(frontmatter_text)
    if not isinstance(loaded, dict):
        raise RuntimeError("Frontmatter YAML did not decode to an object.")
    try:
        envelope = Artifact.model_validate(loaded)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Failed to parse Eternity envelope: {exc}") from exc
    return envelope, payload
