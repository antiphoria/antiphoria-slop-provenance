"""Append-only transparency log adapter for artifact hash anchoring."""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.models import canonical_json_bytes, sha256_hex


def _utc_now_iso() -> str:
    """Return current UTC timestamp as ISO-8601 string."""

    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TransparencyLogEntry:
    """Immutable append-only transparency entry."""

    entry_id: str
    artifact_hash: str
    artifact_id: str
    request_id: str | None
    source_file: str
    previous_entry_hash: str | None
    entry_hash: str
    anchored_at: str
    remote_receipt: str | None


class TransparencyLogAdapter:
    """File-backed append-only log with optional remote publication."""

    def __init__(
        self,
        log_path: Path,
        publish_url: str | None = None,
        publish_timeout_sec: float = 10.0,
    ) -> None:
        self._log_path = log_path
        self._publish_url = publish_url
        self._publish_timeout_sec = publish_timeout_sec
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def log_path(self) -> Path:
        """Return append-only log file path."""

        return self._log_path

    def append_entry(
        self,
        artifact_hash: str,
        artifact_id: str,
        source_file: Path,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TransparencyLogEntry:
        """Append a new hash anchor entry and optionally publish it."""

        previous_entry_hash = self._read_latest_entry_hash()
        entry_id = str(uuid4())
        anchored_at = _utc_now_iso()
        payload = {
            "entryId": entry_id,
            "artifactHash": artifact_hash,
            "artifactId": artifact_id,
            "requestId": request_id,
            "sourceFile": str(source_file),
            "previousEntryHash": previous_entry_hash,
            "anchoredAt": anchored_at,
            "metadata": metadata or {},
        }
        entry_hash = sha256_hex(canonical_json_bytes(payload))
        full_record = {**payload, "entryHash": entry_hash}
        remote_receipt = self._publish_entry(full_record)
        serializable = {**full_record, "remoteReceipt": remote_receipt}
        with self._log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(serializable, sort_keys=True))
            log_file.write("\n")
        return TransparencyLogEntry(
            entry_id=entry_id,
            artifact_hash=artifact_hash,
            artifact_id=artifact_id,
            request_id=request_id,
            source_file=str(source_file),
            previous_entry_hash=previous_entry_hash,
            entry_hash=entry_hash,
            anchored_at=anchored_at,
            remote_receipt=remote_receipt,
        )

    def find_entries_by_artifact_hash(
        self, artifact_hash: str
    ) -> list[TransparencyLogEntry]:
        """Return all log entries that match an artifact hash."""

        if not self._log_path.exists():
            return []
        matches: list[TransparencyLogEntry] = []
        for raw in self._log_path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            loaded = json.loads(raw)
            if loaded.get("artifactHash") != artifact_hash:
                continue
            matches.append(
                TransparencyLogEntry(
                    entry_id=str(loaded["entryId"]),
                    artifact_hash=str(loaded["artifactHash"]),
                    artifact_id=str(loaded["artifactId"]),
                    request_id=(
                        None
                        if loaded.get("requestId") is None
                        else str(loaded.get("requestId"))
                    ),
                    source_file=str(loaded["sourceFile"]),
                    previous_entry_hash=(
                        None
                        if loaded.get("previousEntryHash") is None
                        else str(loaded.get("previousEntryHash"))
                    ),
                    entry_hash=str(loaded["entryHash"]),
                    anchored_at=str(loaded["anchoredAt"]),
                    remote_receipt=(
                        None
                        if loaded.get("remoteReceipt") is None
                        else str(loaded.get("remoteReceipt"))
                    ),
                )
            )
        return matches

    def verify_integrity(self) -> bool:
        """Verify hash chain integrity for all local entries."""

        if not self._log_path.exists():
            return True
        previous_entry_hash: str | None = None
        for raw in self._log_path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            loaded = json.loads(raw)
            payload = {
                "entryId": loaded["entryId"],
                "artifactHash": loaded["artifactHash"],
                "artifactId": loaded["artifactId"],
                "requestId": loaded.get("requestId"),
                "sourceFile": loaded["sourceFile"],
                "previousEntryHash": loaded.get("previousEntryHash"),
                "anchoredAt": loaded["anchoredAt"],
                "metadata": loaded.get("metadata", {}),
            }
            expected_hash = sha256_hex(canonical_json_bytes(payload))
            if expected_hash != loaded.get("entryHash"):
                return False
            if loaded.get("previousEntryHash") != previous_entry_hash:
                return False
            previous_entry_hash = str(loaded["entryHash"])
        return True

    def _read_latest_entry_hash(self) -> str | None:
        """Read previous hash from the last local entry."""

        if not self._log_path.exists():
            return None
        lines = self._log_path.read_text(encoding="utf-8").splitlines()
        for raw in reversed(lines):
            raw = raw.strip()
            if not raw:
                continue
            loaded = json.loads(raw)
            latest = loaded.get("entryHash")
            if latest is None:
                return None
            return str(latest)
        return None

    def _publish_entry(self, payload: dict[str, Any]) -> str | None:
        """Publish anchor payload to remote endpoint when configured."""

        if self._publish_url is None:
            return None
        request = urllib.request.Request(
            self._publish_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload).encode("utf-8"),
        )
        with urllib.request.urlopen(  # noqa: S310
            request,
            timeout=self._publish_timeout_sec,
        ) as response:
            return response.read().decode("utf-8").strip() or None
