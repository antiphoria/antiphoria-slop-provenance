"""RFC3161 timestamp adapter using OpenSSL query/verify primitives."""

from __future__ import annotations

import os
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TimestampVerification:
    """Verification outcome for one RFC3161 token."""

    ok: bool
    message: str


class RFC3161TSAAdapter:
    """Adapter for RFC3161 token request and verification."""

    def __init__(
        self,
        tsa_url: str | None,
        openssl_bin: str = "openssl",
        request_timeout_sec: float = 20.0,
    ) -> None:
        self._tsa_url = tsa_url
        self._openssl_bin = openssl_bin
        self._request_timeout_sec = request_timeout_sec

    @property
    def tsa_url(self) -> str | None:
        """Return configured TSA URL."""

        return self._tsa_url

    def request_timestamp_token(
        self,
        digest_hex: str,
        digest_algorithm: str = "sha256",
    ) -> bytes:
        """Request RFC3161 token for a digest hex string."""

        if self._tsa_url is None:
            raise RuntimeError("RFC3161 TSA URL is missing. Configure RFC3161_TSA_URL.")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            query_path = temp_path / "request.tsq"
            self._build_query_file(query_path, digest_hex, digest_algorithm)
            query_bytes = query_path.read_bytes()
            request = urllib.request.Request(
                self._tsa_url,
                method="POST",
                headers={
                    "Content-Type": "application/timestamp-query",
                    "Accept": "application/timestamp-reply",
                },
                data=query_bytes,
            )
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=self._request_timeout_sec,
            ) as response:
                token = response.read()
        if not token:
            raise RuntimeError("TSA returned empty RFC3161 token payload.")
        return token

    def verify_timestamp_token(
        self,
        digest_hex: str,
        token_bytes: bytes,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> TimestampVerification:
        """Verify token bytes against digest using OpenSSL ts verify."""

        if not token_bytes:
            return TimestampVerification(ok=False, message="Timestamp token is empty.")
        if tsa_ca_cert_path is None:
            return TimestampVerification(
                ok=False,
                message=(
                    "TSA CA certificate path is required for strict RFC3161 token "
                    "verification."
                ),
            )
        if not tsa_ca_cert_path.exists():
            return TimestampVerification(
                ok=False,
                message=f"TSA CA certificate file not found: '{tsa_ca_cert_path}'.",
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            query_path = temp_path / "request.tsq"
            response_path = temp_path / "response.tsr"
            response_path.write_bytes(token_bytes)
            self._build_query_file(query_path, digest_hex, digest_algorithm)
            command = [
                self._openssl_bin,
                "ts",
                "-verify",
                "-in",
                str(response_path),
                "-queryfile",
                str(query_path),
                "-CAfile",
                str(tsa_ca_cert_path),
            ]
            process = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )
        if process.returncode != 0:
            stderr = process.stderr.strip() or process.stdout.strip()
            return TimestampVerification(
                ok=False, message=stderr or "OpenSSL verify failed."
            )
        return TimestampVerification(ok=True, message="RFC3161 verification succeeded.")

    def _build_query_file(
        self,
        output_path: Path,
        digest_hex: str,
        digest_algorithm: str,
    ) -> None:
        """Build OpenSSL RFC3161 query file from digest hex."""

        command = [
            self._openssl_bin,
            "ts",
            "-query",
            "-digest",
            digest_hex,
            f"-{digest_algorithm}",
            "-cert",
            "-out",
            str(output_path),
        ]
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if process.returncode != 0:
            stderr = process.stderr.strip() or process.stdout.strip()
            raise RuntimeError(
                "OpenSSL ts query generation failed. Ensure OpenSSL is available. "
                f"Details: {stderr or '<no error output>'}"
            )
