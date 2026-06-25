"""Append-only transparency log adapter for artifact hash anchoring.

v3: remote publication (Supabase) was removed (pre-release.md §1). The
transparency log is now strictly local + Bitcoin-anchored via OTS. Bitcoin is
the only remote trust root; RFC3161 is the trusted-third-party time root; this
log is the local tamper-evident record. Three distinct layers, no vendor.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from filelock import FileLock

from src.models import canonical_json_bytes, sha256_hex

_logger = logging.getLogger(__name__)


def _hash_payload_from_parts(
    *,
    entry_id: Any,
    artifact_hash: Any,
    artifact_id: Any,
    request_id: Any,
    source_file: Any,
    previous_entry_hash: Any,
    anchored_at: Any,
    metadata: Any,
    bitcoin_block_height: Any,
) -> str:
    """Compute entry hash from one canonical payload builder."""

    hash_payload: dict[str, Any] = {
        "entryId": entry_id,
        "artifactHash": artifact_hash,
        "artifactId": artifact_id,
        "requestId": request_id,
        "sourceFile": source_file,
        "previousEntryHash": previous_entry_hash,
        "anchoredAt": anchored_at,
        "metadata": metadata if isinstance(metadata, dict) else {},
    }
    if bitcoin_block_height is not None:
        hash_payload["bitcoinBlockHeight"] = bitcoin_block_height
    return sha256_hex(canonical_json_bytes(hash_payload))


def _utc_now_iso() -> str:
    """Return current UTC timestamp as ISO-8601 string."""

    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class TransparencyLogEntry:
    """Immutable append-only transparency entry.

    `remote_receipt` is always None in v3 (Supabase publication removed). The
    field is retained so existing JSONL logs and the SQLite store schema keep
    parsing without migration.
    """

    entry_id: str
    artifact_hash: str
    artifact_id: str
    request_id: str | None
    source_file: str
    previous_entry_hash: str | None
    entry_hash: str
    anchored_at: str
    metadata: dict[str, Any]
    remote_receipt: str | None = None
    bitcoin_block_height: int | None = None


class TransparencyLogAdapter:
    """File-backed append-only local transparency log.

    v3: no remote publication. The log is canonical locally; Bitcoin (via OTS)
    is the only remote anchor. Each entry is hash-chained to the previous one
    (`previousEntryHash`), and the chain is re-verified on read.
    """

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path

    @property
    def log_path(self) -> Path:
        """Return append-only log file path."""

        return self._log_path

    def append_entry(
        self,
        artifact_hash: str,
        artifact_id: str,
        source_file: Path | str,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        bitcoin_block_height: int | None = None,
    ) -> TransparencyLogEntry:
        """Append a new hash anchor entry to the local log.

        Uses file locking to prevent interleaved writes from concurrent workers.
        """
        lock_path = Path(str(self._log_path) + ".lock")
        with FileLock(lock_path):
            previous_entry_hash = self._read_latest_entry_hash()
            entry, serializable = self.build_entry_record(
                artifact_hash=artifact_hash,
                artifact_id=artifact_id,
                source_file=source_file,
                previous_entry_hash=previous_entry_hash,
                request_id=request_id,
                metadata=metadata,
                bitcoin_block_height=bitcoin_block_height,
            )
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(serializable, sort_keys=True))
                log_file.write("\n")
        return entry

    def build_entry_record(
        self,
        artifact_hash: str,
        artifact_id: str,
        source_file: Path | str,
        previous_entry_hash: str | None,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        bitcoin_block_height: int | None = None,
    ) -> tuple[TransparencyLogEntry, dict[str, Any]]:
        """Build one transparency record without writing local files."""

        entry_id = str(uuid4())
        anchored_at = _utc_now_iso()
        source_file_str = str(source_file)
        payload = {
            "entryId": entry_id,
            "artifactHash": artifact_hash,
            "artifactId": artifact_id,
            "requestId": request_id,
            "sourceFile": source_file_str,
            "previousEntryHash": previous_entry_hash,
            "anchoredAt": anchored_at,
            "metadata": metadata or {},
        }
        if bitcoin_block_height is not None:
            payload["bitcoinBlockHeight"] = bitcoin_block_height
        entry_hash = _hash_payload_from_parts(
            entry_id=entry_id,
            artifact_hash=artifact_hash,
            artifact_id=artifact_id,
            request_id=request_id,
            source_file=source_file_str,
            previous_entry_hash=previous_entry_hash,
            anchored_at=anchored_at,
            metadata=metadata or {},
            bitcoin_block_height=bitcoin_block_height,
        )
        full_record = {**payload, "entryHash": entry_hash}
        serializable = {**full_record, "remoteReceipt": None}
        entry = TransparencyLogEntry(
            entry_id=entry_id,
            artifact_hash=artifact_hash,
            artifact_id=artifact_id,
            request_id=request_id,
            source_file=source_file_str,
            previous_entry_hash=previous_entry_hash,
            entry_hash=entry_hash,
            anchored_at=anchored_at,
            remote_receipt=None,
            metadata=metadata or {},
            bitcoin_block_height=bitcoin_block_height,
        )
        return entry, serializable

    def find_entries_by_artifact_hash(self, artifact_hash: str) -> list[TransparencyLogEntry]:
        """Return all log entries that match an artifact hash."""

        if not self._log_path.exists():
            return []
        entries = self.parse_entries_from_jsonl(self._log_path.read_text(encoding="utf-8"))
        return [entry for entry in entries if entry.artifact_hash == artifact_hash]

    def parse_entries_from_jsonl(self, jsonl_text: str) -> list[TransparencyLogEntry]:
        """Parse transparency entries from JSONL content in-memory.

        Malformed or incomplete lines are skipped and logged.
        """

        entries: list[TransparencyLogEntry] = []
        for i, raw in enumerate(jsonl_text.splitlines()):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                loaded = json.loads(stripped)
            except json.JSONDecodeError as exc:
                _logger.warning(
                    "Skipping malformed JSONL line %d: %s",
                    i + 1,
                    exc,
                )
                continue
            try:
                entries.append(self._entry_from_loaded_record(loaded))
            except (KeyError, TypeError) as exc:
                _logger.warning(
                    "Skipping JSONL line %d with missing or invalid keys: %s",
                    i + 1,
                    exc,
                )
                continue
        return entries

    def verify_integrity_entries(
        self,
        entries: list[TransparencyLogEntry],
        expected_first_previous: str | None = None,
    ) -> bool:
        """Verify hash-chain integrity for already parsed entries.

        When verifying a sub-chain (e.g. branch log chained to global), pass the
        expected previous_entry_hash for the first entry via expected_first_previous.
        """
        previous_entry_hash: str | None = expected_first_previous
        for entry in entries:
            if entry.previous_entry_hash != previous_entry_hash:
                return False
            expected_hash = self._expected_entry_hash(entry)
            if expected_hash != entry.entry_hash:
                return False
            previous_entry_hash = entry.entry_hash
        return True

    @staticmethod
    def _entry_from_loaded_record(loaded: dict[str, Any]) -> TransparencyLogEntry:
        metadata_loaded = loaded.get("metadata", {})
        metadata = metadata_loaded if isinstance(metadata_loaded, dict) else {}
        payload = {
            "entryId": str(loaded["entryId"]),
            "artifactHash": str(loaded["artifactHash"]),
            "artifactId": str(loaded["artifactId"]),
            "requestId": (
                None if loaded.get("requestId") is None else str(loaded.get("requestId"))
            ),
            "sourceFile": str(loaded["sourceFile"]),
            "previousEntryHash": (
                None
                if loaded.get("previousEntryHash") is None
                else str(loaded.get("previousEntryHash"))
            ),
            "anchoredAt": str(loaded["anchoredAt"]),
            "metadata": metadata,
            "entryHash": str(loaded["entryHash"]),
            "remoteReceipt": (
                None if loaded.get("remoteReceipt") is None else str(loaded.get("remoteReceipt"))
            ),
        }
        bbh = loaded.get("bitcoinBlockHeight")
        try:
            bitcoin_block_height = int(bbh) if bbh is not None else None
        except (TypeError, ValueError):
            bitcoin_block_height = None
        return TransparencyLogEntry(
            entry_id=payload["entryId"],
            artifact_hash=payload["artifactHash"],
            artifact_id=payload["artifactId"],
            request_id=payload["requestId"],
            source_file=payload["sourceFile"],
            previous_entry_hash=payload["previousEntryHash"],
            entry_hash=payload["entryHash"],
            anchored_at=payload["anchoredAt"],
            remote_receipt=payload["remoteReceipt"],
            metadata=payload["metadata"],
            bitcoin_block_height=bitcoin_block_height,
        )

    @staticmethod
    def _expected_entry_hash(entry: TransparencyLogEntry) -> str:
        return _hash_payload_from_parts(
            entry_id=entry.entry_id,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            request_id=entry.request_id,
            source_file=entry.source_file,
            previous_entry_hash=entry.previous_entry_hash,
            anchored_at=entry.anchored_at,
            metadata=entry.metadata,
            bitcoin_block_height=entry.bitcoin_block_height,
        )

    @staticmethod
    def compute_expected_entry_hash_from_payload(payload: dict[str, Any]) -> str:
        """Compute entryHash from payload dict. Retained for callers that build
        payloads in tests. In v3 (no remote) this is mostly used for self-checks.
        """
        return _hash_payload_from_parts(
            entry_id=payload.get("entryId"),
            artifact_hash=payload.get("artifactHash"),
            artifact_id=payload.get("artifactId"),
            request_id=payload.get("requestId"),
            source_file=payload.get("sourceFile"),
            previous_entry_hash=payload.get("previousEntryHash"),
            anchored_at=payload.get("anchoredAt"),
            metadata=payload.get("metadata"),
            bitcoin_block_height=payload.get("bitcoinBlockHeight"),
        )

    def _read_latest_entry_hash(self) -> str | None:
        """Read previous hash from the last local entry."""

        if not self._log_path.exists():
            return None
        file_size = self._log_path.stat().st_size
        if file_size <= 0:
            return None
        window_size = min(4096, file_size)
        while True:
            start = file_size - window_size
            with self._log_path.open("rb") as handle:
                handle.seek(start)
                chunk = handle.read(window_size)
            lines = chunk.splitlines()
            if start > 0 and lines:
                lines = lines[1:]
            for raw in reversed(lines):
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    loaded = json.loads(stripped.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                latest = loaded.get("entryHash")
                if latest is None:
                    continue
                return str(latest)
            if window_size >= file_size:
                break
            window_size = min(file_size, window_size * 2)
        return None
