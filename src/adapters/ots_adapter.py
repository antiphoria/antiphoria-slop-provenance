"""OpenTimestamps CLI adapter for Bitcoin anchoring.

Uses the `ots` CLI exclusively (no Python opentimestamps API) to avoid
bit-rotted dependencies. All operations run via subprocess with 60s timeout.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from src.env_config import read_env_optional

_logger = logging.getLogger(__name__)


def build_ots_adapter(env_path: Path | None = None) -> OTSAdapter | None:
    """Build OTS adapter when ENABLE_OTS_FORGE is true.

    Returns None when OTS forging is disabled. Used by both provenance worker
    and CLI upgrade commands.
    """
    from src.env_config import read_env_bool

    if not read_env_bool("ENABLE_OTS_FORGE", default=False, env_path=env_path):
        return None
    ots_bin = resolve_ots_binary(env_path=env_path)
    return OTSAdapter(ots_bin=ots_bin)


def resolve_ots_binary(env_path: Path | None = None) -> str:
    """
    Resolve OTS binary with precedence:
    1. OTS_BIN env (explicit override)
    2. Bundled bin/ots[.exe] (project default)
    3. 'ots' (system PATH fallback)
    """
    base = Path(__file__).resolve().parents[2]  # project root

    # 1. Check for explicit environment override first
    env_override = read_env_optional("OTS_BIN", env_path=env_path)
    if env_override:
        override_path = Path(env_override)
        if not override_path.is_absolute():
            override_path = (base / override_path).resolve()
        if override_path.exists():
            return str(override_path)
        return env_override  # Let subprocess fail with clear error if missing

    # 2. Check for bundled binary
    exe_name = "ots.exe" if os.name == "nt" else "ots"
    bundled_path = base / "bin" / exe_name

    if bundled_path.exists():
        # Optional: Warn if Unix binary lacks execute permissions
        if os.name != "nt" and not os.access(bundled_path, os.X_OK):
            _logger.warning(
                "Bundled binary %s lacks executable permissions. "
                "Run: git update-index --chmod=+x bin/ots",
                bundled_path,
            )
        return str(bundled_path.resolve())

    # 3. Fallback to system PATH
    if shutil.which("ots"):
        return "ots"

    # No binary found
    raise FileNotFoundError(
        f"OTS binary not found. Missing bundled binary at {bundled_path} "
        "and 'ots' is not in PATH. Set OTS_BIN or install ots."
    )


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
                _logger.warning("ots stamp timed out after %s seconds", e.timeout)
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
            temp_path = Path(temp_dir)
            proof_path = temp_path / "proof.ots"
            proof_path.write_bytes(pending_bytes)
            try:
                subprocess.run(
                    [bin_, "upgrade", "proof.ots"],
                    check=True,
                    timeout=timeout,
                    capture_output=True,
                    cwd=temp_path,
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
                _logger.warning("ots upgrade timed out after %s seconds", e.timeout)
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
                # Upgrade succeeded; if verify fails, block not mined yet (soft failure).
                # Return (True, bytes, None) so caller leaves record PENDING instead of FAILED.
                if not ok or block_height is None:
                    return True, final_bytes, None

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
        """Run ots verify (Go dialect: proof then payload, no -f flag)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            payload_path = temp_path / "payload.md"
            proof_path = temp_path / "payload.md.ots"
            payload_path.write_bytes(payload_bytes)
            proof_path.write_bytes(ots_bytes)
            try:
                result = subprocess.run(
                    [ots_bin, "verify", "payload.md.ots", "payload.md"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=timeout,
                    cwd=temp_path,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return False, None
            if result.returncode != 0:
                _logger.warning(
                    "ots verify failed: returncode=%s stdout=%s stderr=%s",
                    result.returncode,
                    _sanitize_for_log(result.stdout or ""),
                    _sanitize_for_log(result.stderr or ""),
                )
                return False, None
            out = (result.stdout or "") + (result.stderr or "")
            if re.search(r"\binvalid\b", out, flags=re.IGNORECASE) or re.search(
                r"\bnot\s+valid\b", out, flags=re.IGNORECASE
            ):
                _logger.warning(
                    "ots verify: output indicates invalid proof stdout=%s stderr=%s",
                    _sanitize_for_log(result.stdout or ""),
                    _sanitize_for_log(result.stderr or ""),
                )
                return False, None
            has_success_marker = bool(
                re.search(r"\bSuccess\b", out)
                or re.search(r"timestamp validated", out, flags=re.IGNORECASE)
                or re.search(r"\bvalid\b", out, flags=re.IGNORECASE)
            )
            if not has_success_marker:
                _logger.warning(
                    "ots verify: no success marker in output stdout=%s stderr=%s",
                    _sanitize_for_log(result.stdout or ""),
                    _sanitize_for_log(result.stderr or ""),
                )
                return False, None
            match = re.search(r"block\s*\[?(\d+)\]?", out, re.IGNORECASE)
            block_height = int(match.group(1)) if match else None
            return True, block_height
