"""Unit tests for Go vs Python OpenTimestamps CLI dialect handling."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import pytest

from src.adapters.ots_adapter import OTSAdapter, detect_ots_cli_dialect


def test_detect_python_dialect_from_help() -> None:
    dialect = detect_ots_cli_dialect("/fake/python/ots")
    assert dialect in ("go", "python")


def test_python_pending_verify_is_soft_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = OTSAdapter(ots_bin="fake-ots")
    adapter._dialect = "python"

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        _ = kwargs
        assert cmd[1:4] == ["verify", "-f", "payload.md"]
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="Calendar https://a.pool.opentimestamps.org: Pending confirmation in Bitcoin blockchain\n",
            stderr="",
        )

    monkeypatch.setattr("src.adapters.ots_adapter.subprocess.run", fake_run)
    ok, block_height = adapter.verify_ots_proof(
        payload_bytes=b"payload",
        ots_bytes=b"proof-bytes",
    )
    assert ok is False
    assert block_height is None


def test_python_pending_upgrade_is_soft_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = OTSAdapter(ots_bin="fake-ots")
    adapter._dialect = "python"
    pending_b64 = "cHJvb2Y="

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        _ = kwargs
        assert cmd[1:3] == ["upgrade", "proof.ots"]
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=cmd,
            output=b"",
            stderr=(
                b"Calendar https://btc.calendar.catallaxy.com: "
                b"Pending confirmation in Bitcoin blockchain\n"
            ),
        )

    monkeypatch.setattr("src.adapters.ots_adapter.subprocess.run", fake_run)
    upgraded, final_bytes, block_height = adapter.upgrade_ots_proof(
        pending_b64,
        payload_bytes=b"payload",
    )
    assert upgraded is True
    assert final_bytes == b"proof"
    assert block_height is None


def test_go_verify_uses_proof_then_payload_args(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = OTSAdapter(ots_bin="fake-ots")
    adapter._dialect = "go"
    captured: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        _ = kwargs
        captured.append(list(cmd))
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="Success! Bitcoin block 900000",
            stderr="",
        )

    monkeypatch.setattr("src.adapters.ots_adapter.subprocess.run", fake_run)
    ok, block_height = adapter.verify_ots_proof(
        payload_bytes=b"payload",
        ots_bytes=b"proof-bytes",
    )
    assert ok is True
    assert block_height == 900000
    assert captured[0][1:4] == ["verify", "payload.md.ots", "payload.md"]


def test_detect_dialect_from_help_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.adapters.ots_adapter.subprocess.run",
        MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["ots", "--help"],
                returncode=0,
                stdout="usage: ots [--whitelist URL] OpenTimestamps client.\n",
                stderr="",
            )
        ),
    )
    assert detect_ots_cli_dialect("/bin/ots") == "python"
