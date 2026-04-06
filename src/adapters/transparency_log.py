"""Append-only transparency log adapter for artifact hash anchoring."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from filelock import FileLock

from src.env_config import read_env_optional
from src.models import canonical_json_bytes, sha256_hex

_logger = logging.getLogger(__name__)
_MAX_REMOTE_RESPONSE_BYTES = 1_048_576
_ALLOWED_OUTBOUND_SCHEMES = frozenset(("http", "https"))
_MAX_REMOTE_TIMEOUT_SEC = 5.0


def _sanitize_for_log(raw: str, max_len: int = 200) -> str:
    """Truncate and redact secret-like substrings before logging."""
    if not raw:
        return raw
    out = re.sub(r"Bearer\s+[^\s]+", "Bearer ***", raw, flags=re.IGNORECASE)
    out = re.sub(
        r"(apikey|Authorization)[=:\s]+[^\s]+",
        r"\1=***",
        out,
        flags=re.IGNORECASE,
    )
    return out[:max_len] + "..." if len(out) > max_len else out


def _read_response_bytes_bounded(
    response: Any,
    *,
    context: str,
    max_bytes: int = _MAX_REMOTE_RESPONSE_BYTES,
) -> bytes:
    """Read response bytes with an explicit hard size cap."""

    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise RuntimeError(
            f"{context} exceeded maximum allowed size ({max_bytes} bytes)."
        )
    return raw


def _normalize_remote_timeout(timeout_sec: float) -> float:
    """Return bounded timeout for all outbound transparency log calls."""

    if timeout_sec <= 0:
        return _MAX_REMOTE_TIMEOUT_SEC
    return min(timeout_sec, _MAX_REMOTE_TIMEOUT_SEC)


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


def _ensure_allowed_outbound_url(url: str, *, context: str) -> None:
    """Allow only explicit http(s) URLs for outbound remote operations."""

    parsed = urllib.parse.urlparse(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_OUTBOUND_SCHEMES or not parsed.netloc:
        raise RuntimeError(
            f"{context} must use http/https with an explicit host. "
            f"Got: {url!r}"
        )


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
    _ensure_allowed_outbound_url(
        publish_url,
        context="TRANSPARENCY_LOG_PUBLISH_URL",
    )
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

    return datetime.now(UTC).isoformat()


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
    Outbound timeout is capped by `_MAX_REMOTE_TIMEOUT_SEC`.
    """
    if not publish_url or not publish_url.strip() or not publish_headers:
        return False
    try:
        _ensure_allowed_outbound_url(
            publish_url,
            context="Merkle anchor publish_url",
        )
    except RuntimeError as exc:
        _logger.warning(
            "Merkle anchor publish soft-fail. Local anchor secure. Error: %s",
            _sanitize_for_log(str(exc)),
        )
        return False
    payload = {
        "rootHash": root_hash,
        "entryCount": entry_count,
        "anchoredAt": anchored_at,
        "otsPath": ots_path,
        "bitcoinBlockHeight": bitcoin_block_height,
    }
    request_body = {"payload": payload}
    headers = {
        "Content-Type": "application/json",
        **publish_headers,
    }
    request = urllib.request.Request(
        publish_url,
        method="POST",
        headers=headers,
        data=json.dumps(request_body).encode("utf-8"),
    )
    timeout = _normalize_remote_timeout(timeout_sec)
    try:
        with urllib.request.urlopen(  # noqa: S310
            request,
            timeout=timeout,
        ) as response:
            _read_response_bytes_bounded(
                response,
                context="Merkle anchor publish response",
            )
            return True
    except urllib.error.HTTPError as exc:
        try:
            error_body = _read_response_bytes_bounded(
                exc,
                context="Merkle anchor publish error body",
            ).decode("utf-8", errors="replace")
            _logger.warning(
                "Merkle anchor publish soft-fail. Local anchor secure. HTTP %s: %s",
                exc.code,
                _sanitize_for_log(error_body or str(exc)),
            )
        except RuntimeError:
            _logger.warning(
                "Merkle anchor publish soft-fail. Local anchor secure. Error: %s",
                _sanitize_for_log(str(exc)),
            )
        return False
    except (TimeoutError, urllib.error.URLError, ConnectionError) as exc:
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
    Outbound timeout is capped by `_MAX_REMOTE_TIMEOUT_SEC`.
    """
    if not publish_url or not publish_url.strip() or not publish_headers:
        return False
    try:
        _ensure_allowed_outbound_url(
            publish_url,
            context="Merkle anchor publish_url",
        )
    except RuntimeError as exc:
        _logger.warning(
            "Merkle anchor block height update failed: %s",
            _sanitize_for_log(str(exc)),
        )
        return False
    query = urllib.parse.urlencode([("payload->>rootHash", f"eq.{root_hash}")])
    get_url = f"{publish_url.rstrip('/')}?{query}"
    headers = {k: v for k, v in publish_headers.items() if k != "Prefer"}
    req = urllib.request.Request(get_url, method="GET", headers=headers)
    timeout = _normalize_remote_timeout(timeout_sec)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = _read_response_bytes_bounded(
                resp,
                context="Merkle anchor fetch response",
            ).decode("utf-8").strip()
    except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError, ConnectionError, RuntimeError) as exc:
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
    patch_query = urllib.parse.urlencode([("id", f"eq.{row_id}")])
    patch_url = f"{publish_url.rstrip('/')}?{patch_query}"
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _read_response_bytes_bounded(
                resp,
                context="Merkle anchor patch response",
            )
        return True
    except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError, ConnectionError, RuntimeError) as exc:
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
        if publish_url and publish_url.strip():
            _ensure_allowed_outbound_url(
                publish_url,
                context="Transparency log publish_url",
            )
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
        Remote publication and receipt persistence happen outside the append lock,
        so concurrent writers may publish out of local append order. The local
        hash chain remains canonical because `previousEntryHash` is computed from
        locked local state before any remote call.
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
        if not receipt:
            return entry
        self._persist_remote_receipt(entry_id=entry.entry_id, remote_receipt=receipt)
        return replace(entry, remote_receipt=receipt)

    def publish_entry(self, record: dict[str, Any]) -> str | None:
        """Publish a transparency record to remote when configured.

        Call after local persistence to avoid remote-only desync.
        This operation does not acquire the append lock.
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
        """Compute entryHash from payload dict. Used for remote integrity verification."""
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

    def _persist_remote_receipt(
        self,
        *,
        entry_id: str,
        remote_receipt: str,
    ) -> None:
        """Persist remote receipt for an existing local entry id."""

        lock_path = Path(str(self._log_path) + ".lock")
        with FileLock(lock_path):
            if not self._log_path.exists():
                _logger.warning(
                    "Cannot persist remote receipt; log file is missing entry_id=%s",
                    entry_id,
                )
                return
            lines = self._log_path.read_text(encoding="utf-8").splitlines()
            updated = False
            for index in range(len(lines) - 1, -1, -1):
                raw = lines[index].strip()
                if not raw:
                    continue
                try:
                    loaded = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if str(loaded.get("entryId")) != entry_id:
                    continue
                loaded["remoteReceipt"] = remote_receipt
                lines[index] = json.dumps(loaded, sort_keys=True)
                updated = True
                break
            if not updated:
                _logger.warning(
                    "Cannot persist remote receipt; entry_id=%s was not found in local log",
                    entry_id,
                )
                return
            rewritten = "\n".join(lines)
            if rewritten and not rewritten.endswith("\n"):
                rewritten += "\n"
            self._log_path.write_text(rewritten, encoding="utf-8")

    def _publish_entry(self, payload: dict[str, Any]) -> str | None:
        """Publish anchor payload to remote endpoint when configured."""

        if not self._publish_url or not self._publish_url.strip():
            return None
        try:
            _ensure_allowed_outbound_url(
                self._publish_url,
                context="Transparency log publish_url",
            )
        except RuntimeError as exc:
            _logger.warning(
                "Supabase broadcast soft-fail. Local anchor secure. Error: %s",
                _sanitize_for_log(str(exc)),
            )
            return None
        headers: dict[str, str] = {"Content-Type": "application/json", **self._publish_headers}
        body = {"payload": payload} if self._publish_supabase_format else payload
        request = urllib.request.Request(
            self._publish_url,
            method="POST",
            headers=headers,
            data=json.dumps(body).encode("utf-8"),
        )
        timeout = _normalize_remote_timeout(self._publish_timeout_sec)
        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=timeout,
            ) as response:
                raw = _read_response_bytes_bounded(
                    response,
                    context="Transparency publish response",
                ).decode("utf-8").strip()
                if not raw:
                    return None
                return raw
        except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError, ConnectionError, RuntimeError) as exc:
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
        try:
            _ensure_allowed_outbound_url(
                self._publish_url,
                context="Transparency log publish_url",
            )
        except RuntimeError as exc:
            raise RuntimeError(
                "Remote transparency log fetch failed for "
                f"artifact_hash={artifact_hash}: {_sanitize_for_log(str(exc))}"
            ) from exc
        query = urllib.parse.urlencode([("payload->>artifactHash", f"eq.{artifact_hash}")])
        url = f"{self._publish_url.rstrip('/')}?{query}"
        headers = {k: v for k, v in self._publish_headers.items() if k != "Prefer"}
        request = urllib.request.Request(url, method="GET", headers=headers)
        timeout = _normalize_remote_timeout(self._publish_timeout_sec)
        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=timeout,
            ) as response:
                raw = _read_response_bytes_bounded(
                    response,
                    context="Remote transparency log fetch response",
                ).decode("utf-8").strip()
                if not raw:
                    return []
                data = json.loads(raw)
                if not isinstance(data, list):
                    raise RuntimeError(
                        "Remote transparency log fetch returned unexpected non-list JSON body."
                    )
                return [row for row in data if isinstance(row, dict)]
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                "Remote transparency log fetch failed for "
                f"artifact_hash={artifact_hash} with HTTP {exc.code}"
            ) from exc
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            raise RuntimeError(
                "Remote transparency log fetch failed for "
                f"artifact_hash={artifact_hash}: {_sanitize_for_log(str(exc))}"
            ) from exc
        except RuntimeError as exc:
            raise RuntimeError(
                "Remote transparency log fetch failed for "
                f"artifact_hash={artifact_hash}: {_sanitize_for_log(str(exc))}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Remote transparency log fetch failed for artifact_hash={artifact_hash}: {exc}"
            ) from exc
