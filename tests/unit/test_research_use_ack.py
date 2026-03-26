"""Tests for research/artistic use acknowledgment helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from src import research_use_ack as rua


def test_argv_requests_help_only() -> None:
    assert rua.argv_requests_help_only([]) is False
    assert rua.argv_requests_help_only(["-h"]) is True
    assert rua.argv_requests_help_only(["--help"]) is True
    assert rua.argv_requests_help_only(["generate", "--help"]) is True
    assert rua.argv_requests_help_only(["generate", "--prompt", "x"]) is False


def test_is_research_use_acknowledged_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK", raising=False)
    assert rua.is_research_use_acknowledged() is False
    monkeypatch.setenv("ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK", "1")
    assert rua.is_research_use_acknowledged() is True
    monkeypatch.setenv("ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK", "yes")
    assert rua.is_research_use_acknowledged() is True


def test_ack_file_roundtrip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK", raising=False)
    cfg = tmp_path / "antiphoria-slop-provenance"
    monkeypatch.setattr(rua, "_config_dir", lambda: cfg)
    assert rua.is_research_use_acknowledged() is False
    rua.write_research_use_acknowledgment()
    assert rua.is_research_use_acknowledged() is True
