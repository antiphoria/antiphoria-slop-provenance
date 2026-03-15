"""Tests for artifact markdown parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.models import Artifact
from src.parsing import (
    parse_artifact_markdown,
    parse_artifact_markdown_text,
    produce_redacted_artifact,
)

_MINIMAL_FRONTMATTER = """---
title: Test
timestamp: "2024-01-01T00:00:00"
contentType: "text/markdown"
license: ARR
provenance:
  source: synthetic
  engineVersion: v1
  modelId: id
  generationContext:
    systemInstruction: si
    prompt: p
    hyperparameters:
      temperature: 0.0
      topP: 1.0
      topK: 0
---
"""


@pytest.mark.parametrize(
    "text,match",
    [
        ("no delimiter", "missing YAML frontmatter delimiter"),
        ("---\nkey: 1\n", "malformed YAML frontmatter"),
        ("---\n{}\n---\n\n", "payload is empty"),
        ("---\nkey: 1\n---\n  \n", "payload is empty"),
    ],
)
def test_parse_artifact_markdown_text_raises(text: str, match: str) -> None:
    """parse_artifact_markdown_text raises RuntimeError for invalid input."""
    with pytest.raises(RuntimeError, match=match):
        parse_artifact_markdown_text(text)


def test_parse_artifact_markdown_text_null_bytes_stripped() -> None:
    """Null bytes in body are stripped before parsing."""
    text = f"{_MINIMAL_FRONTMATTER}content\x00with\x00nulls\n"
    envelope, payload = parse_artifact_markdown_text(text)
    assert isinstance(envelope, Artifact)
    assert "content" in payload and "with" in payload and "nulls" in payload
    assert "\x00" not in payload


def test_parse_artifact_markdown_text_valid() -> None:
    """parse_artifact_markdown_text returns envelope and body for valid input."""
    body = "Hello world.\n\nSecond paragraph."
    text = f"{_MINIMAL_FRONTMATTER}{body}\n"
    envelope, payload = parse_artifact_markdown_text(text)
    assert isinstance(envelope, Artifact)
    assert envelope.title == "Test"
    assert envelope.provenance.source == "synthetic"
    assert payload == body


def test_parse_artifact_markdown_text_frontmatter_not_dict_raises() -> None:
    """Frontmatter that decodes to non-dict raises RuntimeError."""
    text = "---\n- list\n- items\n---\nbody\n"
    with pytest.raises(RuntimeError, match="did not decode to an object"):
        parse_artifact_markdown_text(text)


def test_parse_artifact_markdown_text_invalid_envelope_raises() -> None:
    """Invalid Artifact schema raises RuntimeError."""
    text = "---\ntitle: x\ntimestamp: 2024-01-01\n---\nbody\n"
    with pytest.raises(RuntimeError, match="Failed to parse Eternity envelope"):
        parse_artifact_markdown_text(text)


@pytest.mark.parametrize(
    "text,placeholder,expected_prefix",
    [
        (
            "---\na: 1\n---\nbody\n",
            "[REDACTED]",
            "---\na: 1\n---\n[REDACTED]\n",
        ),
        (
            f"{_MINIMAL_FRONTMATTER}original body\n",
            "X",
            f"{_MINIMAL_FRONTMATTER}X\n",
        ),
    ],
)
def test_produce_redacted_artifact(text: str, placeholder: str, expected_prefix: str) -> None:
    """produce_redacted_artifact replaces body with placeholder."""
    result = produce_redacted_artifact(text, placeholder)
    assert result == expected_prefix


@pytest.mark.parametrize(
    "text,match",
    [
        ("no ---", "missing YAML frontmatter delimiter"),
        ("x\n---\ny\n---\nz", "missing YAML frontmatter delimiter"),
    ],
)
def test_produce_redacted_artifact_raises(text: str, match: str) -> None:
    """produce_redacted_artifact raises for invalid input."""
    with pytest.raises(RuntimeError, match=match):
        produce_redacted_artifact(text, "x")


def test_parse_artifact_markdown_file_not_found(tmp_path: Path) -> None:
    """parse_artifact_markdown raises when file does not exist."""
    missing = tmp_path / "missing.md"
    with pytest.raises(RuntimeError, match="Artifact file not found"):
        parse_artifact_markdown(missing)


def test_parse_artifact_markdown_from_file(tmp_path: Path) -> None:
    """parse_artifact_markdown reads from file and returns envelope and body."""
    body = "File content."
    text = f"{_MINIMAL_FRONTMATTER}{body}\n"
    path = tmp_path / "artifact.md"
    path.write_text(text, encoding="utf-8")
    envelope, payload = parse_artifact_markdown(path)
    assert isinstance(envelope, Artifact)
    assert payload == body
