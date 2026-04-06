"""OTS queue adapter integration tests using empty_git_repo fixture."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from src.adapters.ots_queue import OtsQueueAdapter


@pytest.fixture
def ots_queue(empty_git_repo: Path) -> OtsQueueAdapter:
    """OtsQueueAdapter backed by empty_git_repo."""
    return OtsQueueAdapter(repository_path=empty_git_repo)


def test_append_pending(ots_queue: OtsQueueAdapter) -> None:
    """append_pending creates queue with valid JSONL pending event in git."""
    request_id = str(uuid4())
    ots_queue.append_pending(
        request_id=request_id,
        artifact_hash="a" * 64,
        pending_ots_b64="ZmFrZQ==",
    )
    rec = ots_queue.get_ots_forge_record(request_id)
    assert rec is not None
    assert rec.status == "PENDING"
    assert rec.artifact_hash == "a" * 64
    assert rec.request_id == request_id


def test_append_forged_after_pending(ots_queue: OtsQueueAdapter) -> None:
    """append_forged updates record; get_ots_forge_record returns FORGED."""
    request_id = str(uuid4())
    ots_queue.append_pending(
        request_id=request_id,
        artifact_hash="b" * 64,
        pending_ots_b64="ZmFrZQ==",
    )
    ots_queue.append_forged(
        request_id=request_id,
        bitcoin_block_height=900000,
        artifact_hash="b" * 64,
    )
    rec = ots_queue.get_ots_forge_record(request_id)
    assert rec is not None
    assert rec.status == "FORGED"
    assert rec.bitcoin_block_height == 900000


def test_append_failed(ots_queue: OtsQueueAdapter) -> None:
    """append_failed creates FAILED event with failure_reason."""
    request_id = str(uuid4())
    ots_queue.append_pending(
        request_id=request_id,
        artifact_hash="c" * 64,
        pending_ots_b64="ZmFrZQ==",
    )
    ots_queue.append_failed(
        request_id=request_id,
        failure_reason="OTS upgrade failed",
        artifact_hash="c" * 64,
    )
    rec = ots_queue.get_ots_forge_record(request_id)
    assert rec is not None
    assert rec.status == "FAILED"


def test_parse_events_merge_latest_wins(ots_queue: OtsQueueAdapter) -> None:
    """Latest event per request_id wins; pending then forged yields FORGED."""
    request_id = str(uuid4())
    ots_queue.append_pending(
        request_id=request_id,
        artifact_hash="d" * 64,
        pending_ots_b64="ZmFrZQ==",
    )
    ots_queue.append_forged(
        request_id=request_id,
        bitcoin_block_height=900001,
    )
    rec = ots_queue.get_ots_forge_record(request_id)
    assert rec is not None
    assert rec.status == "FORGED"


def test_get_pending_records(ots_queue: OtsQueueAdapter) -> None:
    """get_pending_records returns PENDING records, respects limit."""
    rid1, rid2 = str(uuid4()), str(uuid4())
    ots_queue.append_pending(rid1, "e" * 64, "ZmFrZQ==")
    ots_queue.append_pending(rid2, "f" * 64, "ZmFrZQ==")
    pending = ots_queue.get_pending_records(limit=10)
    assert len(pending) == 2
    ids = {r.request_id for r in pending}
    assert rid1 in ids and rid2 in ids
    limited = ots_queue.get_pending_records(limit=1)
    assert len(limited) == 1


def test_list_ots_forge_records_filter_by_status(ots_queue: OtsQueueAdapter) -> None:
    """list_ots_forge_records filters by status."""
    rid_pending = str(uuid4())
    rid_forged = str(uuid4())
    rid_failed = str(uuid4())
    ots_queue.append_pending(rid_pending, "1" * 64, "ZmFrZQ==")
    ots_queue.append_pending(rid_forged, "2" * 64, "ZmFrZQ==")
    ots_queue.append_forged(rid_forged, 900000)
    ots_queue.append_pending(rid_failed, "3" * 64, "ZmFrZQ==")
    ots_queue.append_failed(rid_failed, "reason")

    pending_list = ots_queue.list_ots_forge_records(status="PENDING")
    forged_list = ots_queue.list_ots_forge_records(status="FORGED")
    failed_list = ots_queue.list_ots_forge_records(status="FAILED")

    assert len(pending_list) == 1 and pending_list[0].request_id == rid_pending
    assert len(forged_list) == 1 and forged_list[0].request_id == rid_forged
    assert len(failed_list) == 1 and failed_list[0].request_id == rid_failed


def test_validate_jsonl_raises_on_invalid() -> None:
    """_validate_jsonl raises ValueError for invalid JSONL."""
    with pytest.raises(ValueError, match="Invalid JSONL"):
        OtsQueueAdapter._validate_jsonl('{"valid"}\n{invalid json}\n')
