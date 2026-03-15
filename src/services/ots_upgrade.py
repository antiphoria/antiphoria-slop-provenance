"""Shared OTS upgrade logic for furnace and CLI.

This module has no transport-specific imports. Both the provenance worker
and the CLI import from here. When bus is None, the StoryForged emit is skipped.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import Any
from uuid import UUID

from src.adapters.ots_adapter import OTSAdapter
from src.adapters.ots_queue import OtsQueueAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
from src.events import StoryForged
from src.repository import OtsForgeRecord, SQLiteRepository
from src.services.provenance_service import ProvenanceService

_logger = logging.getLogger(__name__)


async def process_single_ots_record(
    semaphore: asyncio.Semaphore,
    record: OtsForgeRecord,
    repository: SQLiteRepository,
    ots_queue: OtsQueueAdapter,
    provenance_service: ProvenanceService,
    ots_adapter: OTSAdapter,
    transparency_log_adapter: TransparencyLogAdapter,
    repository_path: Path,
    ots_path_template: str = ".provenance/ots-{request_id}.ots",
    bus: Any = None,
) -> None:
    """Process one pending OTS record; on failure, mark FAILED and return.

    When bus is not None, emits StoryForged after successful upgrade.
    When bus is None (CLI path), skips the emit.
    """
    async with semaphore:
        try:
            request_id = UUID(record.request_id)
        except (ValueError, TypeError):
            _logger.warning(
                "OTS furnace: invalid request_id=%s, skipping",
                record.request_id,
            )
            return
        try:
            artifact_record = await asyncio.to_thread(
                repository.get_artifact_record, request_id
            )
            ledger_path = (
                artifact_record.ledger_path
                if artifact_record and artifact_record.ledger_path
                else f"{record.request_id}.md"
            )
            payload_bytes = await asyncio.to_thread(
                provenance_service.get_artifact_payload_bytes_from_branch,
                repository_path,
                request_id,
                ledger_path,
            )
            if payload_bytes is None:
                _logger.warning(
                    "OTS furnace: cannot read artifact for request_id=%s "
                    "(branch refs/heads/artifact/%s or %s not found in repo). "
                    "Ensure --repo-path points to the ledger repo where "
                    "artifacts were generated.",
                    record.request_id,
                    record.request_id,
                    ledger_path,
                )
                return

            upgraded, final_ots_bytes, block_height = await asyncio.to_thread(
                ots_adapter.upgrade_ots_proof,
                record.pending_ots_b64,
                payload_bytes=payload_bytes,
            )
            if not upgraded or final_ots_bytes is None:
                try:
                    await asyncio.to_thread(
                        ots_queue.append_failed,
                        request_id,
                        "OTS upgrade failed or proof did not verify",
                        artifact_hash=record.artifact_hash,
                    )
                except (ValueError, TypeError):
                    pass
                return

            ots_path = ots_path_template.format(request_id=record.request_id)
            ref_name = f"refs/heads/artifact/{record.request_id}"
            commit_message = f"provenance: OTS forged ({record.request_id})"

            # 1. Git FIRST
            await asyncio.to_thread(
                provenance_service._commit_branch_file_bytes,
                repository_path,
                ref_name,
                ots_path,
                final_ots_bytes,
                commit_message,
            )

            # 2. Append-Only Merkle Chain + mirror to SQLite
            try:
                entry = await asyncio.to_thread(
                    transparency_log_adapter.append_entry,
                    record.artifact_hash,
                    str(record.request_id),
                    ots_path,
                    record.request_id,
                    {
                        "event": "ots_forged",
                        "bitcoin_block_height": block_height,
                    },
                )
                await asyncio.to_thread(
                    repository.create_transparency_log_record,
                    entry.entry_id,
                    entry.artifact_hash,
                    entry.artifact_id,
                    entry.request_id,
                    entry.source_file,
                    str(transparency_log_adapter.log_path),
                    entry.previous_entry_hash,
                    entry.entry_hash,
                    entry.anchored_at,
                    entry.remote_receipt,
                )
            except Exception as exc:
                _logger.warning(
                    "OTS furnace: append_entry failed for request_id=%s: %s",
                    record.request_id,
                    exc,
                )

            # 3. OTS queue (Archive)
            final_b64 = base64.b64encode(final_ots_bytes).decode("ascii")
            await asyncio.to_thread(
                ots_queue.append_forged,
                request_id,
                block_height,
                artifact_hash=record.artifact_hash,
            )

            # 4. Emit (skip when bus is None, e.g. CLI path)
            if bus is not None:
                await bus.emit(
                    StoryForged(
                        request_id=request_id,
                        artifact_hash=record.artifact_hash,
                        bitcoin_block_height=block_height,
                        final_ots_b64=final_b64,
                    )
                )

        except Exception as exc:
            _logger.warning(
                "OTS furnace: marking request_id=%s FAILED after error: %s",
                record.request_id,
                exc,
            )
            try:
                await asyncio.to_thread(
                    ots_queue.append_failed,
                    request_id,
                    str(exc),
                    artifact_hash=record.artifact_hash,
                )
            except (ValueError, TypeError):
                _logger.warning(
                    "OTS furnace: cannot mark failed for invalid request_id=%s",  # noqa: E501
                    record.request_id,
                )
