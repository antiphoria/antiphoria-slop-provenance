"""Append-only transparency log adapter for artifact hash anchoring."""

from __future__ import annotations

import json
import logging
import re
import socket
import urllib.error
from dataclasses import replace
from filelock import FileLock
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.env_config import read_env_optional
from src.models import canonical_json_bytes, sha256_hex

_logger = logging.getLogger(__name__)


def _sanitize_for_log(raw: str, max_len: int = 200) -> str:
    """Truncate and redact secret-like substrings before logging."""
    if not raw:
        return raw
    out = re.sub(
        r"(Bearer|apikey|Authorization)[=:\s]+[^\s]+",
        r"\1=***",
        raw,
        flags=re.IGNORECASE,
    )
    return out[:max_len] + "..." if len(out) > max_len else out


def build_supabase_publish_config(
    publish_url: str | None,
    env_path: Path | None = None,
) -> tuple[dict[str, str], bool]:
    """Build Supabase auth headers and format flag when URL and key are set.

    Returns:
        (headers, use_supabase_format). Prefer SUPABASE_SERVICE_KEY over
        SUPABASE_ANON_KEY. If no key is set and no URL, returns ({}, False).

    Raises:
        RuntimeError: When TRANSPARENCY_LOG_PUBLISH_URL is set but neither
            SUPABASE_SERVICE_KEY nor SUPABASE_ANON_KEY is set. Attestation
            cannot validate against the remote log without keys.
    """
    if not publish_url:
        return {}, False
    key = read_env_optional("SUPABASE_SERVICE_KEY", env_path=env_path)
    if key is None:
        key = read_env_optional("SUPABASE_ANON_KEY", env_path=env_path)
    if key is None:
        raise RuntimeError(
            "TRANSPARENCY_LOG_PUBLISH_URL is set but neither SUPABASE_SERVICE_KEY "
            "nor SUPABASE_ANON_KEY is set. Set one of these for attestation to "
            "validate against the remote transparency log."
        )
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


def publish_merkle_anchor(
    root_hash: str,
    entry_count: int,
    anchored_at: str,
    ots_path: str | None = None,
    bitcoin_block_height: int | None = None,
    publish_url: str | None = None,
    publish_headers: dict[str, str] | None = None,
    timeout_sec: float = 10.0,
) -> bool:
    """Publish Merkle anchor to Supabase merkle_anchors table.

    Returns True on success, False on soft-fail (e.g. network error).
    """
    if not publish_url or not publish_url.strip() or not publish_headers:
        return False
    payload = {
        "rootHash": root_hash,
        "entryCount": entry_count,
        "anchoredAt": anchored_at,
        "otsPath": ots_path,
        "bitcoinBlockHeight": bitcoin_block_height,
    }
    body = {"payload": payload}
    headers = {
        "Content-Type": "application/json",
        **publish_headers,
    }
    request = urllib.request.Request(
        publish_url,
        method="POST",
        headers=headers,
        data=json.dumps(body).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(  # noqa: S310
            request,
            timeout=min(timeout_sec, 5.0),
        ) as response:
            response.read()
            return True
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
            _logger.warning(
                "Merkle anchor publish soft-fail. Local anchor secure. HTTP %s: %s",
                exc.code,
                _sanitize_for_log(body or str(exc)),
            )
        except Exception:
            _logger.warning(
                "Merkle anchor publish soft-fail. Local anchor secure. Error: %s",
                _sanitize_for_log(str(exc)),
            )
        return False
    except (
        urllib.error.URLError,
        socket.timeout,
        ConnectionError,
    ) as exc:
        _logger.warning(
            "Merkle anchor publish soft-fail. Local anchor secure. Error: %s",
            _sanitize_for_log(str(exc)),
        )
        return False


def update_merkle_anchor_block_height(
    root_hash: str,
    bitcoin_block_height: int,
    publish_url: str | None = None,
    publish_headers: dict[str, str] | None = None,
    timeout_sec: float = 10.0,
) -> bool:
    """PATCH merkle_anchors row by rootHash to set bitcoinBlockHeight.

    Returns True on success, False on soft-fail.
    """
    if not publish_url or not publish_url.strip() or not publish_headers:
        return False
    query = urllib.parse.urlencode([("payload->>rootHash", f"eq.{root_hash}")])
    get_url = f"{publish_url.rstrip('/')}?{query}"
    headers = {k: v for k, v in publish_headers.items() if k != "Prefer"}
    req = urllib.request.Request(get_url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=min(timeout_sec, 5.0)) as resp:
            raw = resp.read().decode("utf-8").strip()
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        socket.timeout,
        ConnectionError,
    ) as exc:
        _logger.warning(
            "Merkle anchor fetch for update failed: %s",
            _sanitize_for_log(str(exc)),
        )
        return False
    if not raw:
        return False
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(rows, list) or len(rows) == 0:
        return False
    row = rows[0]
    if not isinstance(row, dict):
        return False
    payload = row.get("payload")
    if not isinstance(payload, dict):
        return False
    row_id = row.get("id")
    if row_id is None:
        return False
    payload = {**payload, "bitcoinBlockHeight": bitcoin_block_height}
    patch_url = f"{publish_url.rstrip('/')}?id=eq.{row_id}"
    body = {"payload": payload}
    headers = {
        "Content-Type": "application/json",
        **publish_headers,
    }
    req = urllib.request.Request(
        patch_url,
        method="PATCH",
        headers=headers,
        data=json.dumps(body).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(req, timeout=min(timeout_sec, 5.0)) as resp:
            resp.read()
        return True
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        socket.timeout,
        ConnectionError,
    ) as exc:
        _logger.warning(
            "Merkle anchor block height update failed: %s",
            _sanitize_for_log(str(exc)),
        )
        return False


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
    bitcoin_block_height: int | None = None


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

    def is_remote_configured(self) -> bool:
        """Return True when remote publish is configured (URL and auth headers)."""

        return bool(self._publish_url and self._publish_url.strip()) and bool(self._publish_headers)

    def append_entry(
        self,
        artifact_hash: str,
        artifact_id: str,
        source_file: Path | str,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        bitcoin_block_height: int | None = None,
    ) -> TransparencyLogEntry:
        """Append a new hash anchor entry and optionally publish it.

        Writes to local log before publishing to avoid remote-only desync.
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
                skip_remote=True,
            )
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(serializable, sort_keys=True))
                log_file.write("\n")
        receipt = self.publish_entry(serializable)
        return replace(entry, remote_receipt=receipt) if receipt else entry

    def publish_entry(self, record: dict[str, Any]) -> str | None:
        """Publish a transparency record to remote when configured.

        Call after local persistence to avoid remote-only desync.
        """
        return self._publish_entry(record)

    def build_entry_record(
        self,
        artifact_hash: str,
        artifact_id: str,
        source_file: Path | str,
        previous_entry_hash: str | None,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        bitcoin_block_height: int | None = None,
        skip_remote: bool = False,
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
        entry_hash = sha256_hex(canonical_json_bytes(payload))
        full_record = {**payload, "entryHash": entry_hash}
        remote_receipt = None if skip_remote else self._publish_entry(full_record)
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
            bitcoin_block_height=bitcoin_block_height,
        )
        return entry, serializable

    def find_entries_by_artifact_hash(self, artifact_hash: str) -> list[TransparencyLogEntry]:
        """Return all log entries that match an artifact hash."""

        if not self._log_path.exists():
            return []
        entries = self.parse_entries_from_jsonl(self._log_path.read_text(encoding="utf-8"))
        return [entry for entry in entries if entry.artifact_hash == artifact_hash]

    def verify_integrity(self) -> bool:
        """Verify hash chain integrity for all local entries."""

        if not self._log_path.exists():
            return True
        entries = self.parse_entries_from_jsonl(self._log_path.read_text(encoding="utf-8"))
        return self.verify_integrity_entries(entries)

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
        if entry.bitcoin_block_height is not None:
            payload["bitcoinBlockHeight"] = entry.bitcoin_block_height
        return sha256_hex(canonical_json_bytes(payload))

    @staticmethod
    def compute_expected_entry_hash_from_payload(payload: dict[str, Any]) -> str:
        """Compute entryHash from payload dict. Used for remote integrity verification."""
        hash_payload = {
            "entryId": payload.get("entryId"),
            "artifactHash": payload.get("artifactHash"),
            "artifactId": payload.get("artifactId"),
            "requestId": payload.get("requestId"),
            "sourceFile": payload.get("sourceFile"),
            "previousEntryHash": payload.get("previousEntryHash"),
            "anchoredAt": payload.get("anchoredAt"),
            "metadata": (
                payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            ),
        }
        bbh = payload.get("bitcoinBlockHeight")
        if bbh is not None:
            hash_payload["bitcoinBlockHeight"] = bbh
        return sha256_hex(canonical_json_bytes(hash_payload))

    def _read_latest_entry_hash(self) -> str | None:
        """Read previous hash from the last local entry."""

        if not self._log_path.exists():
            return None
        lines = self._log_path.read_text(encoding="utf-8").splitlines()
        for raw in reversed(lines):
            raw = raw.strip()
            if not raw:
                continue
            try:
                loaded = json.loads(raw)
            except json.JSONDecodeError:
                continue
            latest = loaded.get("entryHash")
            if latest is None:
                continue
            return str(latest)
        return None

    def _publish_entry(self, payload: dict[str, Any]) -> str | None:
        """Publish anchor payload to remote endpoint when configured."""

        if not self._publish_url or not self._publish_url.strip():
            return None
        headers: dict[str, str] = {"Content-Type": "application/json", **self._publish_headers}
        body = {"payload": payload} if self._publish_supabase_format else payload
        request = urllib.request.Request(
            self._publish_url,
            method="POST",
            headers=headers,
            data=json.dumps(body).encode("utf-8"),
        )
        aggressive_timeout = min(self._publish_timeout_sec, 3.0)
        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=aggressive_timeout,
            ) as response:
                raw = response.read().decode("utf-8").strip()
                if not raw:
                    return None
                return raw
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            socket.timeout,
            ConnectionError,
        ) as exc:
            _logger.warning(
                "Supabase broadcast soft-fail. Local anchor secure. Error: %s",
                _sanitize_for_log(str(exc)),
            )
            return None

    def entry_exists_in_remote(self, entry_hash: str, artifact_hash: str) -> bool:
        """Return True if remote has a row with this entry_hash (idempotency check)."""
        rows = self.fetch_remote_entries_by_artifact_hash(artifact_hash)
        if rows is None:
            return False
        for row in rows:
            payload = row.get("payload") or row.get("Payload")
            if isinstance(payload, dict) and payload.get("entryHash") == entry_hash:
                return True
        return False

    def republish_entry_if_missing(self, serializable: dict[str, Any]) -> tuple[bool, str]:
        """Publish entry to remote only if not already present. Idempotent.

        Returns:
            (published, message) - published=True if INSERT was performed.
        """
        entry_hash = serializable.get("entryHash")
        artifact_hash = serializable.get("artifactHash")
        if not entry_hash or not artifact_hash:
            return False, "Record missing entryHash or artifactHash"
        if not self.is_remote_configured():
            return False, "Remote publish not configured"
        if self.entry_exists_in_remote(entry_hash, artifact_hash):
            return False, "Already present"
        receipt = self._publish_entry(serializable)
        if receipt is None:
            return False, "Publish failed (network or server error)"
        return True, "Published"

    def fetch_remote_entries_by_artifact_hash(
        self, artifact_hash: str
    ) -> list[dict[str, Any]] | None:
        """Fetch remote transparency log rows by artifact hash.

        Returns None only when remote is not configured (no publish_url or headers).
        Returns [] on successful request with no matching rows (verified empty).
        Returns list of row dicts (each with 'payload' key) on success.

        Raises:
            RuntimeError: On HTTP/network/JSON error when remote is configured.
                Callers must not treat this as "skip verification" to prevent
                network-level bypass attacks.
        """
        if not (self._publish_url and self._publish_url.strip()) or not self._publish_headers:
            return None
        query = urllib.parse.urlencode([("payload->>artifactHash", f"eq.{artifact_hash}")])
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
        except urllib.error.HTTPError as exc:
            if exc.code in (500, 502, 503, 504):
                _logger.warning(
                    "Remote transparency log fetch failed (HTTP %s) for artifact_hash=%s",
                    exc.code,
                    artifact_hash,
                )
                return None
            raise RuntimeError(
                f"Remote transparency log fetch failed for artifact_hash={artifact_hash}: {exc}"
            ) from exc
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            _logger.warning(
                "Remote transparency log fetch failed (transient) for artifact_hash=%s: %s",
                artifact_hash,
                _sanitize_for_log(str(exc)),
            )
            return None
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Remote transparency log fetch failed for artifact_hash={artifact_hash}: {exc}"
            ) from exc
