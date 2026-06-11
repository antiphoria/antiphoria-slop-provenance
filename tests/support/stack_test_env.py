"""Minimal env for integration tests that run register/seal stack readiness."""

from __future__ import annotations

import os
from pathlib import Path


def configure_minimal_ceremony_stack_env(key_dir: Path) -> None:
    """Disable OTS/C2PA and provide TSA paths so stack readiness passes in tests."""

    tsa_ca = key_dir / "tsa-ca.pem"
    tsa_ca.write_bytes(b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
    os.environ["RFC3161_TSA_URL"] = "http://timestamp.digicert.com"
    os.environ["RFC3161_CA_CERT_PATH"] = str(tsa_ca)
    os.environ["ENABLE_OTS_FORGE"] = "false"
    os.environ["ENABLE_C2PA"] = "false"
