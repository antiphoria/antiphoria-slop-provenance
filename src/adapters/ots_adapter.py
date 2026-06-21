"""OpenTimestamps CLI adapter for Bitcoin anchoring.

Supports both the Go ``opentimestamps-client`` binary and the Python
``opentimestamps-client`` (``otsclient``) CLI shipped as ``.venv/bin/ots``.
Stamp/upgrade use the same subcommand shape; ``verify`` differs by dialect.

Trust: ``OTS_BIN`` (or the bundled ``bin/ots`` / PATH ``ots``) names the
executable used as argv[0]; arguments are fixed (``stamp``, ``upgrade``,
``verify``) and are not merged from user input. Treat the binary path as an
operator-controlled trust boundary (like ``OPENSSL_BIN``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from src.env_config import read_env_optional

_logger = logging.getLogger(__name__)

OtsCliDialect = Literal["go", "python"]
_OTS_PENDING_RE = re.compile(
    r"Pending confirmation in Bitcoin blockchain",
    flags=re.IGNORECASE,
)
_OTS_BITCOIN_NODE_ERROR_RE = re.compile(
    r"Could not connect to (?:local )?Bitcoin node",
    flags=re.IGNORECASE,
)
_OTS_INFO_SHA256_RE = re.compile(
    r"File sha256 hash:\s*([0-9a-f]{64})",
    flags=re.IGNORECASE,
)
_OTS_BITCOIN_ATTESTATION_RE = re.compile(
    r"BitcoinBlockHeaderAttestation\((\d+)\)",
)


def _ots_output_indicates_pending(out: str) -> bool:
    """True when calendar output means the proof is not forged yet."""
    return bool(_OTS_PENDING_RE.search(out))


def _ots_output_indicates_bitcoin_node_error(out: str) -> bool:
    """True when verify failed because no Bitcoin node/RPC is reachable."""
    return bool(_OTS_BITCOIN_NODE_ERROR_RE.search(out))


def _ots_global_cli_args(env_path: Path | None = None) -> list[str]:
    """Global ``ots`` flags inserted before the subcommand."""
    args: list[str] = []
    node = read_env_optional("OTS_BITCOIN_NODE", env_path=env_path)
    if node:
        args.extend(["--bitcoin-node", node])
    return args


def _ots_cli_path_must_be_file(path: Path) -> str:
    """Require a concrete OTS executable path (regular file)."""
    if not path.exists():
        raise FileNotFoundError(
            f"OTS binary not found at '{path}'. Set OTS_BIN or install the OpenTimestamps CLI."
        )
    if not path.is_file():
        raise RuntimeError(f"OTS binary path must be a regular file, not a directory: '{path}'")
    return str(path.resolve())


def build_ots_adapter(env_path: Path | None = None) -> OTSAdapter | None:
    """Build OTS adapter when ENABLE_OTS_FORGE is true.

    Returns None when OTS forging is disabled. Used by both provenance worker
    and CLI upgrade commands.
    """
    from src.env_config import read_env_bool

    if not read_env_bool("ENABLE_OTS_FORGE", default=True, env_path=env_path):
        return None
    ots_bin = resolve_ots_binary(env_path=env_path)
    return OTSAdapter(ots_bin=ots_bin, env_path=env_path)


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
        return _ots_cli_path_must_be_file(override_path)

    # 2. Check for bundled binary
    exe_name = "ots.exe" if os.name == "nt" else "ots"
    bundled_path = base / "bin" / exe_name

    if bundled_path.exists():
        resolved = _ots_cli_path_must_be_file(bundled_path)
        # Advisory only (not a security gate); see SECURITY.md.
        if os.name != "nt" and not os.access(bundled_path, os.X_OK):
            _logger.warning(
                "Bundled binary %s lacks executable permissions. "
                "Run: git update-index --chmod=+x bin/ots",
                bundled_path,
            )
        return resolved

    # 3. Fallback to system PATH
    which_ots = shutil.which("ots")
    if which_ots:
        return _ots_cli_path_must_be_file(Path(which_ots))

    # No binary found
    raise FileNotFoundError(
        f"OTS binary not found. Missing bundled binary at {bundled_path} "
        "and 'ots' is not in PATH. Set OTS_BIN or install ots."
    )


def detect_ots_cli_dialect(ots_bin: str) -> OtsCliDialect:
    """Detect Go vs Python OpenTimestamps CLI from ``--help`` output."""

    try:
        result = subprocess.run(  # noqa: S603
            [ots_bin, "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "go"
    help_text = (result.stdout or "") + (result.stderr or "")
    if "--whitelist" in help_text or "OpenTimestamps client." in help_text:
        return "python"
    return "go"


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

    def __init__(
        self,
        ots_bin: str = "ots",
        *,
        env_path: Path | None = None,
    ) -> None:
        self._ots_bin = ots_bin
        self._dialect = detect_ots_cli_dialect(ots_bin)
        self._env_path = env_path

    def _ots_cmd(self, *subcommand_args: str) -> list[str]:
        """Build argv: global flags, then subcommand args."""
        return [self._ots_bin, *_ots_global_cli_args(self._env_path), *subcommand_args]

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
                subprocess.run(  # noqa: S603
                    self._ots_cmd("stamp", str(temp_path)),
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
            if not proof_path.exists():
                raise RuntimeError(
                    f"ots stamp completed without creating proof file at '{proof_path}'."
                )
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
        try:
            pending_bytes = base64.b64decode(pending_ots_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError(
                "Invalid pending_ots_b64 payload: expected base64-encoded OTS proof bytes."
            ) from exc
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            proof_path = temp_path / "proof.ots"
            proof_path.write_bytes(pending_bytes)
            try:
                subprocess.run(  # noqa: S603
                    self._ots_cmd("upgrade", "proof.ots"),
                    check=True,
                    timeout=timeout,
                    capture_output=True,
                    cwd=temp_path,
                )
            except subprocess.CalledProcessError as e:
                stderr_s = (e.stderr or b"").decode("utf-8", errors="replace")
                stdout_s = (e.stdout or b"").decode("utf-8", errors="replace")
                out = stderr_s + stdout_s
                if _ots_output_indicates_pending(out):
                    _logger.info(
                        "ots upgrade still pending Bitcoin confirmation (exit %d)",
                        e.returncode,
                    )
                    return True, pending_bytes, None
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

            if not proof_path.exists():
                _logger.warning(
                    "ots upgrade completed without output proof file at %s",
                    proof_path,
                )
                return False, None, None
            final_bytes = proof_path.read_bytes()

            block_height: int | None = None
            if payload_bytes is not None:
                ok, block_height = self._verify_ots_proof(
                    payload_bytes=payload_bytes,
                    ots_bytes=final_bytes,
                    ots_bin=bin_,
                    dialect=self._dialect,
                    timeout=timeout,
                )
                # Upgrade succeeded; if verify fails without block height, leave PENDING.
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
            dialect=self._dialect,
            timeout=timeout,
        )

    def _verify_ots_proof_via_info(
        self,
        payload_bytes: bytes,
        ots_bytes: bytes,
        ots_bin: str,
        timeout: int,
    ) -> tuple[bool, int | None]:
        """Extract forged block height from ``ots info`` when verify needs Bitcoin RPC."""
        expected_digest = hashlib.sha256(payload_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            proof_path = temp_path / "proof.ots"
            proof_path.write_bytes(ots_bytes)
            try:
                result = subprocess.run(  # noqa: S603
                    self._ots_cmd("info", "proof.ots"),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=timeout,
                    cwd=temp_path,
                )
            except subprocess.TimeoutExpired as exc:
                _logger.warning("ots info timed out after %s seconds", exc.timeout)
                return False, None
            except OSError as exc:
                _logger.warning("ots info could not run %s: %s", ots_bin, exc)
                return False, None

            out = (result.stdout or "") + (result.stderr or "")
            if result.returncode != 0:
                _logger.warning(
                    "ots info failed (exit %d): stdout=%s stderr=%s",
                    result.returncode,
                    _sanitize_for_log(result.stdout or ""),
                    _sanitize_for_log(result.stderr or ""),
                )
                return False, None

            digest_match = _OTS_INFO_SHA256_RE.search(out)
            if digest_match is None:
                _logger.warning(
                    "ots info: no file digest in output stdout=%s stderr=%s",
                    _sanitize_for_log(result.stdout or ""),
                    _sanitize_for_log(result.stderr or ""),
                )
                return False, None
            if digest_match.group(1).lower() != expected_digest:
                _logger.warning(
                    "ots info digest mismatch: expected=%s got=%s",
                    expected_digest,
                    digest_match.group(1).lower(),
                )
                return False, None

            heights = [int(m) for m in _OTS_BITCOIN_ATTESTATION_RE.findall(out)]
            if not heights:
                return False, None

            block_height = max(heights)
            _logger.info(
                "ots verify via info fallback: bitcoin_block_height=%d (no local node)",
                block_height,
            )
            return True, block_height

    def _verify_ots_proof(
        self,
        payload_bytes: bytes,
        ots_bytes: bytes,
        ots_bin: str,
        dialect: OtsCliDialect,
        timeout: int,
    ) -> tuple[bool, int | None]:
        """Run ``ots verify`` using Go or Python CLI dialect."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            payload_path = temp_path / "payload.md"
            proof_path = temp_path / "payload.md.ots"
            payload_path.write_bytes(payload_bytes)
            proof_path.write_bytes(ots_bytes)
            if dialect == "python":
                verify_cmd = self._ots_cmd(
                    "verify",
                    "-f",
                    "payload.md",
                    "payload.md.ots",
                )
            else:
                verify_cmd = self._ots_cmd("verify", "payload.md.ots", "payload.md")
            try:
                result = subprocess.run(  # noqa: S603
                    verify_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=timeout,
                    cwd=temp_path,
                )
            except subprocess.TimeoutExpired as exc:
                _logger.warning("ots verify timed out after %s seconds", exc.timeout)
                return False, None
            except OSError as exc:
                _logger.warning("ots verify could not run %s: %s", ots_bin, exc)
                return False, None

            out = (result.stdout or "") + (result.stderr or "")
            if _ots_output_indicates_pending(out):
                return False, None

            if result.returncode != 0:
                if _ots_output_indicates_bitcoin_node_error(out):
                    return self._verify_ots_proof_via_info(
                        payload_bytes,
                        ots_bytes,
                        ots_bin,
                        timeout,
                    )
                if dialect == "python" and "usage:" in out:
                    _logger.warning(
                        "ots verify failed: Python CLI rejected args stdout=%s stderr=%s",
                        _sanitize_for_log(result.stdout or ""),
                        _sanitize_for_log(result.stderr or ""),
                    )
                else:
                    _logger.warning(
                        "ots verify failed: returncode=%s stdout=%s stderr=%s",
                        result.returncode,
                        _sanitize_for_log(result.stdout or ""),
                        _sanitize_for_log(result.stderr or ""),
                    )
                return False, None
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
            match = re.search(
                r"\bblock\b\s*\[?#?(\d{4,})\]?",
                out,
                re.IGNORECASE,
            )
            block_height = int(match.group(1)) if match else None
            return True, block_height
