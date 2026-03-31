"""Tests for RFC3161 TSA adapter verification behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from src.adapters.rfc3161_tsa import RFC3161TSAAdapter


class RFC3161TSAAdapterTest(unittest.TestCase):
    """Validate verification fallback and OpenSSL env resolution."""

    def test_verify_token_uses_embedded_chain_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ca_file = temp_path / "ca.pem"
            ca_file.write_text("dummy", encoding="utf-8")
            embedded_chain = temp_path / "embedded.pem"
            embedded_chain.write_text("dummy", encoding="utf-8")

            adapter = RFC3161TSAAdapter(tsa_url="https://example.invalid/tsr")

            with patch.object(adapter, "_build_query_file", return_value=None):
                with patch.object(
                    adapter,
                    "_resolve_ca_candidates",
                    return_value=([ca_file], []),
                ):
                    with patch.object(
                        adapter,
                        "_resolve_untrusted_cert_path",
                        return_value=None,
                    ):
                        with patch.object(
                            adapter,
                            "_extract_embedded_untrusted_cert_bundle",
                            return_value=embedded_chain,
                        ):
                            first = CompletedProcess(
                                args=[],
                                returncode=1,
                                stdout="",
                                stderr=("unable to get local issuer certificate"),
                            )
                            second = CompletedProcess(
                                args=[],
                                returncode=0,
                                stdout="Verification: OK",
                                stderr="",
                            )
                            with patch.object(
                                adapter,
                                "_run_ts_verify",
                                side_effect=[first, second],
                            ) as run_verify:
                                result = adapter.verify_timestamp_token(
                                    digest_hex="a" * 64,
                                    token_bytes=b"token",
                                    tsa_ca_cert_path=ca_file,
                                )

            self.assertTrue(result.ok)
            self.assertIn("embedded TSA chain", result.message)
            self.assertEqual(run_verify.call_count, 2)

    def test_verify_falls_back_to_certifi_bundle_when_ca_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            certifi_bundle = temp_path / "certifi.pem"
            certifi_bundle.write_text("bundle", encoding="utf-8")
            missing_ca = temp_path / "missing-ca.pem"
            adapter = RFC3161TSAAdapter(tsa_url="https://example.invalid/tsr")

            with patch.object(adapter, "_build_query_file", return_value=None):
                with patch.object(
                    adapter,
                    "_resolve_certifi_ca_bundle",
                    return_value=certifi_bundle,
                ):
                    with patch.object(
                        adapter,
                        "_resolve_untrusted_cert_path",
                        return_value=None,
                    ):
                        with patch.object(
                            adapter,
                            "_extract_embedded_untrusted_cert_bundle",
                            return_value=None,
                        ):
                            ok_process = CompletedProcess(
                                args=[],
                                returncode=0,
                                stdout="Verification: OK",
                                stderr="",
                            )
                            with patch.object(
                                adapter,
                                "_run_ts_verify",
                                return_value=ok_process,
                            ) as run_verify:
                                result = adapter.verify_timestamp_token(
                                    digest_hex="b" * 64,
                                    token_bytes=b"token",
                                    tsa_ca_cert_path=missing_ca,
                                )

            self.assertTrue(result.ok)
            called_ca = run_verify.call_args.kwargs["tsa_ca_cert_path"]
            self.assertEqual(called_ca, certifi_bundle)

    def test_openssl_env_discovers_adjacent_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            openssl_bin = temp_path / "Library" / "bin" / "openssl.exe"
            openssl_bin.parent.mkdir(parents=True, exist_ok=True)
            openssl_bin.write_text("", encoding="utf-8")
            openssl_conf = temp_path / "Library" / "openssl.cnf"
            openssl_conf.write_text(
                "openssl_conf = openssl_init",
                encoding="utf-8",
            )

            adapter = RFC3161TSAAdapter(tsa_url=None, openssl_bin="openssl")
            with patch(
                "src.adapters.rfc3161_tsa.shutil.which",
                return_value=str(openssl_bin),
            ):
                with patch.dict("os.environ", {}, clear=True):
                    env = adapter._openssl_env()

            self.assertEqual(env.get("OPENSSL_CONF"), str(openssl_conf))

    def test_md5_digest_algorithm_is_rejected(self) -> None:
        adapter = RFC3161TSAAdapter(tsa_url="https://example.invalid/tsr")
        with self.assertRaises(ValueError):
            adapter._build_query_file(
                output_path=Path("dummy.tsq"),
                digest_hex="a" * 32,
                digest_algorithm="md5",
            )


if __name__ == "__main__":
    unittest.main()
