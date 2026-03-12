"""OpenTimestamps CLI adapter for Bitcoin anchoring.

Uses the `ots` CLI exclusively (no Python opentimestamps API) to avoid
bit-rotted dependencies. All operations run via subprocess with 60s timeout.
"""

from __future__ import annotations

import base64
import logging
import re
import subprocess
import tempfile
from pathlib import Path

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


class OTSAdapter:
    """CLI-only OpenTimestamps adapter."""

    def __init__(self, ots_bin: str = "ots") -> None:
        self._ots_bin = ots_bin

    def request_ots_stamp(
        self,
        payload_bytes: bytes,
        ots_bin: str | None = None,
        timeout: int = 60,
    ) -> bytes:
        """Stamp payload via CLI; return .ots proof bytes.

        Writes payload to temp file, runs `ots stamp`, reads `.ots` output.
        CLI hashes the file exactly once. No double-hash.
        """
        bin_ = ots_bin or self._ots_bin
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "payload.md"
            temp_path.write_bytes(payload_bytes)
            try:
                subprocess.run(
                    [bin_, "stamp", str(temp_path)],
                    check=True,
                    timeout=timeout,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                stderr_s = (e.stderr or b"").decode("utf-8", errors="replace")
                stdout_s = (e.stdout or b"").decode("utf-8", errors="replace")
                _logger.warning(
                    "ots stamp failed (exit %d): stderr=%s stdout=%s",
                    e.returncode,
                    _sanitize_for_log(stderr_s),
                    _sanitize_for_log(stdout_s),
                )
                raise
            except subprocess.TimeoutExpired as e:
                _logger.warning(
                    "ots stamp timed out after %s seconds", e.timeout
                )
                raise
            proof_path = temp_path.with_suffix(".md.ots")
            return proof_path.read_bytes()

    def upgrade_ots_proof(
        self,
        pending_ots_b64: str,
        payload_bytes: bytes | None = None,
        ots_bin: str | None = None,
        timeout: int = 60,
    ) -> tuple[bool, bytes | None, int | None]:
        """Upgrade pending proof via `ots upgrade`; optionally verify for block height.

        When payload_bytes is provided, runs `ots verify -f payload proof` after
        upgrade to extract bitcoin_block_height. Returns (upgraded, final_ots_bytes, block_height).
        """
        bin_ = ots_bin or self._ots_bin
        pending_bytes = base64.b64decode(pending_ots_b64, validate=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            proof_path = Path(temp_dir) / "proof.ots"
            proof_path.write_bytes(pending_bytes)
            try:
                subprocess.run(
                    [bin_, "upgrade", str(proof_path)],
                    check=True,
                    timeout=timeout,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                stderr_s = (e.stderr or b"").decode("utf-8", errors="replace")
                stdout_s = (e.stdout or b"").decode("utf-8", errors="replace")
                _logger.warning(
                    "ots upgrade failed (exit %d): stderr=%s stdout=%s",
                    e.returncode,
                    _sanitize_for_log(stderr_s),
                    _sanitize_for_log(stdout_s),
                )
                return False, None, None
            except subprocess.TimeoutExpired as e:
                _logger.warning(
                    "ots upgrade timed out after %s seconds", e.timeout
                )
                return False, None, None

            final_bytes = proof_path.read_bytes()

            block_height: int | None = None
            if payload_bytes is not None:
                ok, block_height = self._verify_ots_proof(
                    payload_bytes=payload_bytes,
                    ots_bytes=final_bytes,
                    ots_bin=bin_,
                    timeout=timeout,
                )
                # PUNK PATCH: If it doesn't verify on Bitcoin, it's NOT FORGED YET.
                if not ok or block_height is None:
                    return False, None, None

            return True, final_bytes, block_height

    def verify_ots_proof(
        self,
        payload_bytes: bytes,
        ots_bytes: bytes,
        ots_bin: str | None = None,
        timeout: int = 60,
    ) -> tuple[bool, int | None]:
        """Verify proof against payload; return (ok, block_height)."""
        return self._verify_ots_proof(
            payload_bytes=payload_bytes,
            ots_bytes=ots_bytes,
            ots_bin=ots_bin or self._ots_bin,
            timeout=timeout,
        )

    @staticmethod
    def _verify_ots_proof(
        payload_bytes: bytes,
        ots_bytes: bytes,
        ots_bin: str,
        timeout: int,
    ) -> tuple[bool, int | None]:
        """Run ots verify -f payload proof; parse block height from stdout."""
        with tempfile.TemporaryDirectory() as temp_dir:
            payload_path = Path(temp_dir) / "payload.md"
            proof_path = Path(temp_dir) / "proof.ots"
            payload_path.write_bytes(payload_bytes)
            proof_path.write_bytes(ots_bytes)
            try:
                result = subprocess.run(
                    [ots_bin, "verify", "-f", str(payload_path), str(proof_path)],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return False, None
            if result.returncode != 0:
                return False, None
            if "Success" not in (result.stdout or ""):
                return False, None
            match = re.search(r"block\s+(\d+)", result.stdout or "", re.IGNORECASE)
            block_height = int(match.group(1)) if match else None
            return True, block_height
