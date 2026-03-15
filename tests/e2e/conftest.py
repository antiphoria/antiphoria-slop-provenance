"""E2E test fixtures and helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def isolated_env(tmp_path: Path):
    """
    Hermetic environment for E2E tests.
    - Unique ledger + state dirs per test (tmp_path)
    - Git init in ledger
    - Explicit env overrides prevent project .env bleed (including real keys)
    """
    ledger_dir = tmp_path / "ledger"
    state_dir = tmp_path / "state"
    ledger_dir.mkdir()
    state_dir.mkdir()
    subprocess.run(
        ["git", "init"],
        cwd=ledger_dir,
        check=True,
        capture_output=True,
    )

    fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures"
    keys_dir = fixtures_dir / "keys"

    priv_path = keys_dir / "test_ml_dsa.priv"
    pub_path = keys_dir / "test_ml_dsa.pub"

    artifact_db = state_dir / "artifacts.db"
    env = os.environ.copy()
    env.update({
        "LEDGER_REPO_PATH": str(ledger_dir),
        "ORCHESTRATOR_STATE_DIR": str(state_dir),
        "ARTIFACT_DB_PATH": str(artifact_db),
        "GENERATOR_DUMMY_MODE": "true",
        "ENABLE_OTS_FORGE": "false",
        "ENABLE_C2PA": "false",
        "TRANSPARENCY_LOG_PUBLISH_URL": "",
        "RFC3161_TSA_URL": "",
        "PQC_PRIVATE_KEY_PATH": str(priv_path) if priv_path.exists() else "",
        "OQS_PUBLIC_KEY_PATH": str(pub_path) if pub_path.exists() else "",
        "C2PA_PRIVATE_KEY_PATH": "",
    })
    return env, ledger_dir, state_dir


@pytest.fixture
def tsa_mock(httpserver):
    """RFC3161 TSA mock using pytest-httpserver. Returns URL for RFC3161_TSA_URL."""
    fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures"
    tsr_path = fixtures_dir / "dummy.tsr"
    tsr_bytes = tsr_path.read_bytes() if tsr_path.exists() else b""
    httpserver.expect_request("/").respond_with_data(
        tsr_bytes, content_type="application/timestamp-reply"
    )
    return httpserver.url_for("/")


def run_cli(args: list[str], env: dict, timeout: int = 15) -> subprocess.CompletedProcess:
    """Run CLI via current Python. Guarantees exact source code under test."""
    return subprocess.run(
        [sys.executable, "-m", "src.cli"] + args,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_tool(
    module: str,
    args: list[str],
    env: dict,
    timeout: int = 15,
) -> subprocess.CompletedProcess:
    """Run module entry points (e.g. src.kafka.bootstrap, src.runtime.metrics_report)."""
    return subprocess.run(
        [sys.executable, "-m", module] + args,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
