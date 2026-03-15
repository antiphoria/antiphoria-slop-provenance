"""OTS adapter tests using fake_ots_binary fixture (no subprocess mock)."""

from __future__ import annotations

import base64

import pytest

from src.adapters.ots_adapter import OTSAdapter


def test_request_ots_stamp_with_fake_binary(fake_ots_binary) -> None:
    """OTSAdapter.request_ots_stamp works with fake binary; reads .ots bytes from disk."""
    adapter = OTSAdapter(ots_bin=str(fake_ots_binary))
    payload = b"hello world"
    result = adapter.request_ots_stamp(payload)
    assert result == b"fake_ots_stamp_dummy"


def test_upgrade_ots_proof_with_fake_binary(fake_ots_binary) -> None:
    """OTSAdapter.upgrade_ots_proof works with fake binary; reads upgraded bytes from disk."""
    adapter = OTSAdapter(ots_bin=str(fake_ots_binary))
    pending_b64 = base64.b64encode(b"pending_proof").decode("ascii")
    upgraded, final_bytes, block_height = adapter.upgrade_ots_proof(
        pending_b64,
        payload_bytes=b"payload",
    )
    assert upgraded is True
    assert final_bytes == b"fake_ots_upgraded_dummy"
    assert block_height is None
