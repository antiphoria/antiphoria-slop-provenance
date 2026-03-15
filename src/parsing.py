"""Shared parsing helpers for artifact markdown payloads."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from src.models import Artifact

_FOOTER_MARKERS: tuple[str, ...] = (
    "\n-----BEGIN ANTIPHORIA ARTIFACT SIGNATURE-----",
)


def parse_artifact_markdown(file_path: Path) -> tuple[Artifact, str]:
    """Parse artifact markdown into strict envelope and body payload."""

    if not file_path.exists():
        raise RuntimeError(f"Artifact file not found: '{file_path}'.")
    text = file_path.read_text(encoding="utf-8")
    return parse_artifact_markdown_text(text)


def produce_redacted_artifact(text: str, placeholder: str) -> str:
    """Produce redacted artifact text with body replaced by placeholder.

    Preserves frontmatter and signature footer exactly; replaces body only.
    """
    text = _sanitize_null_bytes(text)
    if not text.startswith("---\n"):
        raise RuntimeError("Artifact file is missing YAML frontmatter delimiter.")
    delimiter_index = text.find("\n---\n", 4)
    if delimiter_index == -1:
        raise RuntimeError("Artifact file has malformed YAML frontmatter.")
    prefix = text[: delimiter_index + len("\n---\n")]
    rest = text[delimiter_index + len("\n---\n"):]
    footer_index = rest.rfind(_FOOTER_MARKERS[0])
    if footer_index != -1:
        body_section = placeholder + "\n"
        footer = rest[footer_index:]
        return prefix + body_section + footer
    return prefix + placeholder + "\n"


def _sanitize_null_bytes(text: str) -> str:
    """Remove null bytes that corrupt YAML parsing (e.g. from UTF-16 file copy)."""

    return text.replace("\x00", "")


def parse_artifact_markdown_text(text: str) -> tuple[Artifact, str]:
    """Parse artifact markdown text into strict envelope and body payload."""

    text = _sanitize_null_bytes(text)
    if not text.startswith("---\n"):
        raise RuntimeError("Artifact file is missing YAML frontmatter delimiter.")
    delimiter_index = text.find("\n---\n", 4)
    if delimiter_index == -1:
        raise RuntimeError("Artifact file has malformed YAML frontmatter.")
    frontmatter_text = text[4:delimiter_index]
    payload_text = text[delimiter_index + len("\n---\n"):]
    # Use rfind to locate the canonical footer (last occurrence). Prevents injection
    # attacks where an attacker embeds the marker in the body to truncate the payload.
    footer_index = -1
    for footer_marker in _FOOTER_MARKERS:
        candidate_index = payload_text.rfind(footer_marker)
        if candidate_index == -1:
            continue
        if footer_index == -1 or candidate_index > footer_index:
            footer_index = candidate_index

    # Extract RFC3161 from the discarded tail; tolerate Windows CRLF mangling
    rfc3161_token: str | None = None
    if footer_index != -1:
        tail_text = payload_text[footer_index:]
        match = re.search(
            r"-----BEGIN RFC3161 TIMESTAMP TOKEN-----\s*(.*?)\s*-----END RFC3161 TIMESTAMP TOKEN-----",
            tail_text,
            re.DOTALL,
        )
        if match:
            rfc3161_token = "".join(match.group(1).split())
        payload_text = payload_text[:footer_index]

    payload = payload_text.strip()
    if not payload:
        raise RuntimeError("Artifact payload is empty after metadata stripping.")
    loaded: Any = yaml.safe_load(frontmatter_text)
    if not isinstance(loaded, dict):
        raise RuntimeError("Frontmatter YAML did not decode to an object.")
    try:
        envelope = Artifact.model_validate(loaded)
        if rfc3161_token and envelope.signature is not None:
            updated_sig = envelope.signature.model_copy(
                update={"rfc3161_token": rfc3161_token}
            )
            envelope = envelope.model_copy(update={"signature": updated_sig})
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Failed to parse Eternity envelope: {exc}") from exc
    return envelope, payload
