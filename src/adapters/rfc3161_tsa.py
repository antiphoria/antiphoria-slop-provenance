"""RFC3161 timestamp adapter using OpenSSL query/verify primitives."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

_ALLOWED_DIGEST_ALGORITHMS = frozenset(("sha256", "sha384", "sha512", "md5"))


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
        untrusted_cert_path: Path | None = None,
        openssl_conf_path: Path | None = None,
    ) -> None:
        self._tsa_url = tsa_url
        self._openssl_bin = openssl_bin
        self._request_timeout_sec = request_timeout_sec
        self._untrusted_cert_path = untrusted_cert_path
        self._openssl_conf_path = openssl_conf_path

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
            raise RuntimeError(
                "RFC3161 TSA URL is missing. Configure RFC3161_TSA_URL."
            )
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
            raise RuntimeError(
                "TSA returned empty RFC3161 token payload. "
                f"Endpoint: '{self._tsa_url}'. Try another TSA endpoint."
            )
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
            return TimestampVerification(
                ok=False,
                message="Timestamp token is empty.",
            )
        ca_candidates, notes = self._resolve_ca_candidates(tsa_ca_cert_path)
        if not ca_candidates:
            details = " ".join(notes).strip()
            return TimestampVerification(
                ok=False,
                message=(
                    "No usable CA certificate bundle found for RFC3161 verification. "
                    f"{details}".strip()
                ),
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            response_path = temp_path / "response.tsr"
            response_path.write_bytes(token_bytes)
            configured_untrusted = self._resolve_untrusted_cert_path()
            embedded_untrusted = self._extract_embedded_untrusted_cert_bundle(
                response_path=response_path,
                output_path=temp_path / "embedded-chain.pem",
            )

            failures: list[str] = []
            for ca_path in ca_candidates:
                process = self._run_ts_verify(
                    response_path=response_path,
                    digest_hex=digest_hex,
                    digest_algorithm=digest_algorithm,
                    tsa_ca_cert_path=ca_path,
                    untrusted_cert_path=configured_untrusted,
                )
                if process.returncode == 0:
                    return TimestampVerification(
                        ok=True,
                        message=(
                            "RFC3161 verification succeeded "
                            f"using '{ca_path}'."
                        ),
                    )
                failures.append(
                    self._format_verify_failure(
                        process=process,
                        tsa_ca_cert_path=ca_path,
                        untrusted_cert_path=configured_untrusted,
                    )
                )

                if embedded_untrusted is None:
                    continue
                process_embedded = self._run_ts_verify(
                    response_path=response_path,
                    digest_hex=digest_hex,
                    digest_algorithm=digest_algorithm,
                    tsa_ca_cert_path=ca_path,
                    untrusted_cert_path=embedded_untrusted,
                )
                if process_embedded.returncode == 0:
                    return TimestampVerification(
                        ok=True,
                        message=(
                            "RFC3161 verification succeeded using embedded TSA chain "
                            f"and CA '{ca_path}'."
                        ),
                    )
                failures.append(
                    self._format_verify_failure(
                        process=process_embedded,
                        tsa_ca_cert_path=ca_path,
                        untrusted_cert_path=embedded_untrusted,
                    )
                )
            if notes:
                failures.extend(notes)

        if not failures:
            return TimestampVerification(
                ok=False,
                message="OpenSSL verify failed.",
            )
        return TimestampVerification(ok=False, message=" | ".join(failures))

    def _build_query_file(
        self,
        output_path: Path,
        digest_hex: str,
        digest_algorithm: str,
    ) -> None:
        """Build OpenSSL RFC3161 query file from digest hex."""
        if digest_algorithm not in _ALLOWED_DIGEST_ALGORITHMS:
            raise ValueError(f"Invalid digest_algorithm: {digest_algorithm!r}")

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
            encoding="utf-8",
            env=self._openssl_env(),
        )
        if process.returncode != 0:
            stderr = process.stderr.strip() or process.stdout.strip()
            raise RuntimeError(
                "OpenSSL ts query generation failed. Ensure OpenSSL is available. "
                f"Details: {stderr or '<no error output>'}"
            )

    def _run_ts_verify(
        self,
        response_path: Path,
        digest_hex: str,
        digest_algorithm: str,
        tsa_ca_cert_path: Path,
        untrusted_cert_path: Path | None,
    ) -> subprocess.CompletedProcess[str]:
        if digest_algorithm not in _ALLOWED_DIGEST_ALGORITHMS:
            raise ValueError(f"Invalid digest_algorithm: {digest_algorithm!r}")
        command = [
            self._openssl_bin,
            "ts",
            "-verify",
            "-in",
            str(response_path),
            "-digest",
            digest_hex,
            f"-{digest_algorithm}",
            "-CAfile",
            str(tsa_ca_cert_path),
        ]
        if untrusted_cert_path is not None:
            command.extend(["-untrusted", str(untrusted_cert_path)])
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self._openssl_env(),
        )

    def _extract_embedded_untrusted_cert_bundle(
        self,
        response_path: Path,
        output_path: Path,
    ) -> Path | None:
        token_path = output_path.with_suffix(".p7b")
        extract_token = subprocess.run(
            [
                self._openssl_bin,
                "ts",
                "-reply",
                "-in",
                str(response_path),
                "-token_out",
                "-out",
                str(token_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self._openssl_env(),
        )
        if extract_token.returncode != 0 or not token_path.exists():
            return None
        extract_certs = subprocess.run(
            [
                self._openssl_bin,
                "pkcs7",
                "-in",
                str(token_path),
                "-inform",
                "DER",
                "-print_certs",
                "-out",
                str(output_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self._openssl_env(),
        )
        if extract_certs.returncode != 0 or not output_path.exists():
            return None
        text = output_path.read_text(encoding="utf-8", errors="ignore")
        if "BEGIN CERTIFICATE" not in text:
            return None
        return output_path

    def _resolve_ca_candidates(
        self,
        tsa_ca_cert_path: Path | None,
    ) -> tuple[list[Path], list[str]]:
        candidates: list[Path] = []
        notes: list[str] = []

        if tsa_ca_cert_path is not None:
            if tsa_ca_cert_path.exists():
                candidates.append(tsa_ca_cert_path)
            else:
                notes.append(
                    f"Configured CA file missing: '{tsa_ca_cert_path}'."
                )

        certifi_path = self._resolve_certifi_ca_bundle()
        if certifi_path is not None and certifi_path not in candidates:
            candidates.append(certifi_path)
        elif certifi_path is None:
            notes.append("No certifi CA bundle available.")

        return candidates, notes

    def _resolve_untrusted_cert_path(self) -> Path | None:
        if self._untrusted_cert_path is None:
            return None
        if self._untrusted_cert_path.exists():
            return self._untrusted_cert_path
        return None

    @staticmethod
    def _resolve_certifi_ca_bundle() -> Path | None:
        try:
            import certifi
        except Exception:  # noqa: BLE001
            return None
        candidate = Path(certifi.where())
        if not candidate.exists():
            return None
        return candidate

    def _openssl_env(self) -> dict[str, str]:
        env = os.environ.copy()
        if env.get("OPENSSL_CONF"):
            return env

        candidates: list[Path] = []
        if self._openssl_conf_path is not None:
            candidates.append(self._openssl_conf_path)

        resolved_bin = shutil.which(self._openssl_bin)
        if resolved_bin is not None:
            openssl_bin_path = Path(resolved_bin)
            candidates.extend(
                [
                    openssl_bin_path.parent.parent / "openssl.cnf",
                    openssl_bin_path.parent.parent / "ssl" / "openssl.cnf",
                ]
            )

        for candidate in candidates:
            if candidate.exists():
                env["OPENSSL_CONF"] = str(candidate)
                break
        return env

    @staticmethod
    def _format_verify_failure(
        process: subprocess.CompletedProcess[str],
        tsa_ca_cert_path: Path,
        untrusted_cert_path: Path | None,
    ) -> str:
        details = process.stderr.strip() or process.stdout.strip() or "unknown error"
        if untrusted_cert_path is None:
            return f"verify failed with CA '{tsa_ca_cert_path}': {details}"
        return (
            "verify failed with "
            "CA "
            f"'{tsa_ca_cert_path}' + untrusted '{untrusted_cert_path}': "
            f"{details}"
        )
