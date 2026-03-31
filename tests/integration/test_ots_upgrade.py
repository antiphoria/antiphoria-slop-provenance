"""OTS upgrade exception-path: append_entry failure calls append_failed."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from uuid import uuid4

import pytest

from src.adapters.ots_queue import OtsQueueAdapter
from src.repository.sqlite import SQLiteRepository
from src.repository.types import OtsForgeRecord
from src.services.ots_upgrade import process_single_ots_record


class FakeOTSAdapter:
    """Returns success so flow reaches append_entry."""

    def upgrade_ots_proof(
        self,
        pending_ots_b64: str,
        payload_bytes: bytes | None = None,
        **kwargs: object,
    ) -> tuple[bool, bytes | None, int | None]:
        return True, b"fake_upgraded_proof", 123


class FailingTransparencyLogAdapter:
    """Raises on append_entry to simulate failure."""

    def append_entry(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated append_entry failure")


class FakeProvenanceService:
    """Returns payload bytes; _commit_branch_file_bytes no-op."""

    def get_artifact_payload_bytes_from_branch(
        self,
        repository_path: Path,
        request_id: object,
        ledger_path: str,
    ) -> bytes:
        return b"payload"

    def _commit_branch_file_bytes(
        self,
        repository_path: Path,
        ref_name: str,
        relative_path: str,
        payload_bytes: bytes,
        commit_message: str,
    ) -> None:
        pass


def _insert_artifact_record(repo: SQLiteRepository, request_id: str) -> None:
    """Insert minimal artifact record for process_single_ots_record."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    with repo._connect() as conn:
        conn.execute(
            """
            INSERT INTO artifact_records (
                request_id, status, title, prompt, body, model_id, artifact_hash,
                cryptographic_signature, ledger_path, commit_oid,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                request_id,
                "signed",
                "Test",
                "p",
                "body",
                "model",
                "a" * 64,
                "ZmFrZQ==",
                f"{request_id}.md",
                None,
                now,
                now,
            ),
        )


@pytest.mark.asyncio
async def test_process_single_ots_record_append_entry_failure_calls_append_failed(
    empty_git_repo: Path,
    temp_sqlite_repository: SQLiteRepository,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """transparency_log.append_entry raises -> append_failed called and logged."""
    caplog.set_level(logging.INFO)

    request_id = uuid4()
    _insert_artifact_record(temp_sqlite_repository, str(request_id))

    record = OtsForgeRecord(
        request_id=str(request_id),
        artifact_hash="a" * 64,
        status="PENDING",
        pending_ots_b64="ZmFrZQ==",
        final_ots_b64=None,
        bitcoin_block_height=None,
        created_at="2024-01-01T00:00:00",
        updated_at="2024-01-01T00:00:00",
    )

    ots_queue = OtsQueueAdapter(repository_path=empty_git_repo)
    ots_queue.append_pending(
        request_id=str(request_id),
        artifact_hash="a" * 64,
        pending_ots_b64="ZmFrZQ==",
    )

    await process_single_ots_record(
        semaphore=asyncio.Semaphore(1),
        record=record,
        artifact_store=temp_sqlite_repository.artifacts,
        transparency_store=temp_sqlite_repository.transparency,
        ots_queue=ots_queue,
        provenance_service=FakeProvenanceService(),
        ots_adapter=FakeOTSAdapter(),
        transparency_log_adapter=FailingTransparencyLogAdapter(),
        repository_path=empty_git_repo,
        bus=None,
    )

    assert "OTS furnace: marking request_id" in caplog.text
    assert "FAILED" in caplog.text

    rec = ots_queue.get_ots_forge_record(request_id)
    assert rec is not None
    assert rec.status == "FAILED"
