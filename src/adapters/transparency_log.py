"""Append-only transparency log adapter for artifact hash anchoring."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.env_config import read_env_optional
from src.models import canonical_json_bytes, sha256_hex


def build_supabase_publish_config(
    publish_url: str | None,
    env_path: Path | None = None,
) -> tuple[dict[str, str], bool]:
    """Build Supabase auth headers and format flag when URL and key are set.

    Returns:
        (headers, use_supabase_format). Prefer SUPABASE_SERVICE_KEY over
        SUPABASE_ANON_KEY. If no key is set, returns ({}, False).
    """
    if not publish_url:
        return {}, False
    key = read_env_optional("SUPABASE_SERVICE_KEY", env_path=env_path)
    if key is None:
        key = read_env_optional("SUPABASE_ANON_KEY", env_path=env_path)
    if key is None:
        return {}, False
    return (
        {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Prefer": "return=representation",
        },
        True,
    )


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
    metadata: dict[str, Any]


class TransparencyLogAdapter:
    """File-backed append-only log with optional remote publication."""

    def __init__(
        self,
        log_path: Path,
        publish_url: str | None = None,
        publish_timeout_sec: float = 10.0,
        publish_headers: dict[str, str] | None = None,
        publish_supabase_format: bool = False,
    ) -> None:
        self._log_path = log_path
        self._publish_url = publish_url
        self._publish_timeout_sec = publish_timeout_sec
        self._publish_headers = publish_headers or {}
        self._publish_supabase_format = publish_supabase_format

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
    ) -> TransparencyLogEntry:
        """Append a new hash anchor entry and optionally publish it."""

        previous_entry_hash = self._read_latest_entry_hash()
        entry, serializable = self.build_entry_record(
            artifact_hash=artifact_hash,
            artifact_id=artifact_id,
            source_file=source_file,
            previous_entry_hash=previous_entry_hash,
            request_id=request_id,
            metadata=metadata,
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
        entry_hash = sha256_hex(canonical_json_bytes(payload))
        full_record = {**payload, "entryHash": entry_hash}
        remote_receipt = self._publish_entry(full_record)
        serializable = {**full_record, "remoteReceipt": remote_receipt}
        entry = TransparencyLogEntry(
            entry_id=entry_id,
            artifact_hash=artifact_hash,
            artifact_id=artifact_id,
            request_id=request_id,
            source_file=source_file_str,
            previous_entry_hash=previous_entry_hash,
            entry_hash=entry_hash,
            anchored_at=anchored_at,
            remote_receipt=remote_receipt,
            metadata=metadata or {},
        )
        return entry, serializable

    def find_entries_by_artifact_hash(
        self, artifact_hash: str
    ) -> list[TransparencyLogEntry]:
        """Return all log entries that match an artifact hash."""

        if not self._log_path.exists():
            return []
        entries = self.parse_entries_from_jsonl(
            self._log_path.read_text(encoding="utf-8")
        )
        return [entry for entry in entries if entry.artifact_hash == artifact_hash]

    def verify_integrity(self) -> bool:
        """Verify hash chain integrity for all local entries."""

        if not self._log_path.exists():
            return True
        entries = self.parse_entries_from_jsonl(
            self._log_path.read_text(encoding="utf-8")
        )
        return self.verify_integrity_entries(entries)

    def parse_entries_from_jsonl(self, jsonl_text: str) -> list[TransparencyLogEntry]:
        """Parse transparency entries from JSONL content in-memory."""

        entries: list[TransparencyLogEntry] = []
        for raw in jsonl_text.splitlines():
            stripped = raw.strip()
            if not stripped:
                continue
            loaded = json.loads(stripped)
            entries.append(self._entry_from_loaded_record(loaded))
        return entries

    def verify_integrity_entries(self, entries: list[TransparencyLogEntry]) -> bool:
        """Verify hash-chain integrity for already parsed entries."""

        previous_entry_hash: str | None = None
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
                None
                if loaded.get("requestId") is None
                else str(loaded.get("requestId"))
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
                None
                if loaded.get("remoteReceipt") is None
                else str(loaded.get("remoteReceipt"))
            ),
        }
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
        )

    @staticmethod
    def _expected_entry_hash(entry: TransparencyLogEntry) -> str:
        payload = {
            "entryId": entry.entry_id,
            "artifactHash": entry.artifact_hash,
            "artifactId": entry.artifact_id,
            "requestId": entry.request_id,
            "sourceFile": entry.source_file,
            "previousEntryHash": entry.previous_entry_hash,
            "anchoredAt": entry.anchored_at,
            "metadata": entry.metadata,
        }
        return sha256_hex(canonical_json_bytes(payload))

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
        headers: dict[str, str] = {"Content-Type": "application/json", **self._publish_headers}
        body = {"payload": payload} if self._publish_supabase_format else payload
        request = urllib.request.Request(
            self._publish_url,
            method="POST",
            headers=headers,
            data=json.dumps(body).encode("utf-8"),
        )
        with urllib.request.urlopen(  # noqa: S310
            request,
            timeout=self._publish_timeout_sec,
        ) as response:
            raw = response.read().decode("utf-8").strip()
            if not raw:
                return None
            return raw

    def fetch_remote_entries_by_artifact_hash(
        self, artifact_hash: str
    ) -> list[dict[str, Any]] | None:
        """Fetch remote transparency log rows by artifact hash.

        Returns None when remote is not configured (no publish_url or headers),
        or on HTTP/network/JSON error (could not verify - caller should skip).
        Returns [] on successful request with no matching rows (verified empty).
        Returns list of row dicts (each with 'payload' key) on success.
        """
        if self._publish_url is None or not self._publish_headers:
            return None
        query = urllib.parse.urlencode(
            [("payload->>artifactHash", f"eq.{artifact_hash}")]
        )
        url = f"{self._publish_url.rstrip('/')}?{query}"
        headers = {k: v for k, v in self._publish_headers.items() if k != "Prefer"}
        request = urllib.request.Request(url, method="GET", headers=headers)
        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=self._publish_timeout_sec,
            ) as response:
                raw = response.read().decode("utf-8").strip()
                if not raw:
                    return []
                data = json.loads(raw)
                if not isinstance(data, list):
                    return []
                return [row for row in data if isinstance(row, dict)]
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError):
            return None
