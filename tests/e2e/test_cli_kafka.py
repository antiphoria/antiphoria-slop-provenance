"""Hermetic E2E tests for Kafka transport. Skipped when Kafka is unreachable."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.e2e.conftest import kafka_reachable, run_cli, run_tool

_KAFKA_SERVERS = "localhost:9094"


@pytest.mark.skipif(not kafka_reachable(_KAFKA_SERVERS), reason="Kafka not running")
def test_generate_kafka_emits_and_exits(isolated_env) -> None:
    """CLI emit only; assert exit 0, stdout contains queued."""
    env, ledger_dir, _ = isolated_env
    env["KAFKA_BOOTSTRAP_SERVERS"] = _KAFKA_SERVERS
    result = run_cli(
        [
            "generate",
            "--prompt",
            "E2E Kafka",
            "--repo-path",
            str(ledger_dir),
            "--transport",
            "kafka",
        ],
        env=env,
    )
    assert result.returncode == 0
    assert "queued" in (result.stdout or "").lower() or "request_id=" in (
        result.stdout or ""
    )


@pytest.mark.skipif(not kafka_reachable(_KAFKA_SERVERS), reason="Kafka not running")
def test_curate_kafka_emits(isolated_env) -> None:
    """Generate locally first; curate with --transport kafka; assert exit 0."""
    env, ledger_dir, _ = isolated_env
    env["KAFKA_BOOTSTRAP_SERVERS"] = _KAFKA_SERVERS

    gen_result = run_cli(
        [
            "generate",
            "--prompt",
            "E2E curate",
            "--repo-path",
            str(ledger_dir),
            "--transport",
            "local",
        ],
        env=env,
    )
    assert gen_result.returncode == 0

    import re

    match = re.search(r"request_id=([0-9a-f-]{36})", gen_result.stdout or "")
    assert match, f"request_id not found in: {gen_result.stdout}"
    request_id = match.group(1)
    artifact_path = ledger_dir / f"{request_id}.md"

    import subprocess

    artifact_content = subprocess.run(
        ["git", "-C", str(ledger_dir), "show", f"artifact/{request_id}:{request_id}.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
    ).stdout
    assert artifact_content, "Could not extract artifact"
    artifact_path.write_text(artifact_content, encoding="utf-8")

    curate_result = run_cli(
        [
            "curate",
            "--file",
            str(artifact_path),
            "--repo-path",
            str(ledger_dir),
            "--transport",
            "kafka",
        ],
        env=env,
    )
    assert curate_result.returncode == 0


@pytest.mark.skipif(not kafka_reachable(_KAFKA_SERVERS), reason="Kafka not running")
def test_register_kafka_emits(isolated_env) -> None:
    """slop-cli register ... --transport kafka; assert exit 0."""
    env, ledger_dir, _ = isolated_env
    env["KAFKA_BOOTSTRAP_SERVERS"] = _KAFKA_SERVERS

    plain_file = ledger_dir / "human.md"
    plain_file.write_text("# Human\n\nTest content.", encoding="utf-8")

    result = run_cli(
        [
            "register",
            "--file",
            str(plain_file),
            "--repo-path",
            str(ledger_dir),
            "--title",
            "Human E2E",
            "--license",
            "CC0-1.0",
            "--non-interactive",
            "--transport",
            "kafka",
        ],
        env=env,
    )
    assert result.returncode == 0


@pytest.mark.skipif(not kafka_reachable(_KAFKA_SERVERS), reason="Kafka not running")
def test_bootstrap_topics_exits_zero() -> None:
    """slop-bootstrap-topics --bootstrap-servers <servers>; assert exit 0."""
    env = os.environ.copy()
    env["KAFKA_BOOTSTRAP_SERVERS"] = _KAFKA_SERVERS
    result = run_tool(
        "src.kafka.bootstrap",
        ["--bootstrap-servers", _KAFKA_SERVERS],
        env=env,
    )
    assert result.returncode == 0


def test_metrics_empty_dir(tmp_path: Path) -> None:
    """slop-metrics --metrics-dir <tmp_path>; assert exit 0."""
    metrics_dir = tmp_path / "metrics"
    metrics_dir.mkdir()
    result = run_tool(
        "src.runtime.metrics_report",
        ["--metrics-dir", str(metrics_dir)],
        env=os.environ.copy(),
    )
    assert result.returncode == 0


@pytest.mark.skipif(not kafka_reachable(_KAFKA_SERVERS), reason="Kafka not running")
def test_replay_dlq_dry_run() -> None:
    """slop-replay-dlq --topic story.signed --max-messages 0; exits."""
    env = os.environ.copy()
    env["KAFKA_BOOTSTRAP_SERVERS"] = _KAFKA_SERVERS
    result = run_tool(
        "src.kafka.replay_dlq",
        ["--topic", "story.signed", "--max-messages", "0"],
        env=env,
    )
    assert result.returncode == 0
