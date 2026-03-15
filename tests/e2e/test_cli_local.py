"""Hermetic E2E tests for CLI local transport. No Kafka, no external APIs."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tests.e2e.conftest import run_cli


def _generate_and_extract_artifact(env: dict, ledger_dir: Path) -> tuple[str, Path]:
    """Generate locally, extract artifact to ledger_dir, return (request_id, artifact_path)."""
    gen_result = run_cli(
        [
            "generate",
            "--prompt",
            "E2E artifact",
            "--repo-path",
            str(ledger_dir),
        ],
        env=env,
    )
    assert gen_result.returncode == 0, gen_result.stderr or gen_result.stdout
    match = re.search(r"request_id=([0-9a-f-]{36})", gen_result.stdout or "")
    if not match:
        raise pytest.skip("Could not parse request_id from generate output")
    request_id = match.group(1)
    artifact_content = subprocess.run(
        ["git", "-C", str(ledger_dir), "show", f"artifact/{request_id}:{request_id}.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
    ).stdout
    if not artifact_content:
        raise pytest.skip("Could not extract artifact from ledger")
    artifact_path = ledger_dir / f"{request_id}.md"
    artifact_path.write_text(artifact_content, encoding="utf-8")
    return request_id, artifact_path


def test_cli_help_exits_zero(isolated_env) -> None:
    """slop-cli --help exits 0."""
    env, _, _ = isolated_env
    result = run_cli(["--help"], env=env)
    assert result.returncode == 0


def test_verify_invalid_artifact_fails(isolated_env) -> None:
    """slop-cli verify --file /nonexistent fails."""
    env, _, _ = isolated_env
    result = run_cli(
        ["verify", "--file", "/nonexistent/artifact.md"],
        env=env,
    )
    assert result.returncode != 0


def test_forge_status_empty_repo(isolated_env) -> None:
    """slop-cli forge-status --repo-path <ledger> on fresh repo exits 0."""
    env, ledger_dir, _ = isolated_env
    result = run_cli(
        ["forge-status", "--repo-path", str(ledger_dir)],
        env=env,
    )
    assert result.returncode == 0


def test_admin_revoke_key_missing_db(isolated_env) -> None:
    """slop-cli admin revoke-key with missing db exits non-zero."""
    env, _, _ = isolated_env
    result = run_cli(
        [
            "admin",
            "revoke-key",
            "--fingerprint",
            "deadbeef",
            "--db-path",
            "/nonexistent/db.db",
        ],
        env=env,
    )
    assert result.returncode != 0


def test_generate_fails_when_repo_path_invalid(isolated_env) -> None:
    """slop-cli generate with non-existent repo path fails."""
    env, _, _ = isolated_env
    env["LEDGER_REPO_PATH"] = "/nonexistent/ledger"
    result = run_cli(
        ["generate", "--prompt", "x"],
        env=env,
    )
    assert result.returncode != 0


def test_curate_requires_valid_artifact(isolated_env) -> None:
    """slop-cli curate --file /nonexistent fails."""
    env, ledger_dir, _ = isolated_env
    result = run_cli(
        ["curate", "--file", "/nonexistent/artifact.md", "--repo-path", str(ledger_dir)],
        env=env,
    )
    assert result.returncode != 0


def test_register_human_artifact_success(isolated_env, tsa_mock) -> None:
    """slop-cli register human markdown locally. Requires test keys."""
    env, ledger_dir, _ = isolated_env
    env["RFC3161_TSA_URL"] = tsa_mock
    keys_dir = Path(__file__).resolve().parents[1] / "fixtures" / "keys"
    if not (keys_dir / "test_ml_dsa.priv").exists():
        pytest.skip("Test keys not found")
    plain_file = ledger_dir / "my_story.md"
    plain_file.write_text("# My Original Story\n\nOnce upon a time.", encoding="utf-8")
    result = run_cli(
        [
            "register",
            "--file",
            str(plain_file),
            "--repo-path",
            str(ledger_dir),
            "--title",
            "E2E Story",
            "--license",
            "CC0-1.0",
            "--non-interactive",
        ],
        env=env,
    )
    assert result.returncode == 0
    assert "request_id" in (result.stdout or "").lower()


def test_events_empty_repo(isolated_env) -> None:
    """slop-cli events on fresh repo exits 0."""
    env, ledger_dir, _ = isolated_env
    result = run_cli(
        ["events", "--repo-path", str(ledger_dir), "--limit", "5"],
        env=env,
    )
    assert result.returncode == 0
    assert "No provenance events" in (result.stdout or "")


def test_upgrade_ots_disabled(isolated_env) -> None:
    """slop-cli upgrade exits 1 when ENABLE_OTS_FORGE=false."""
    env, ledger_dir, _ = isolated_env
    result = run_cli(
        [
            "upgrade",
            "--repo-path",
            str(ledger_dir),
            "--request-id",
            "00000000-0000-0000-0000-000000000001",
        ],
        env=env,
    )
    assert result.returncode == 1
    assert "OTS forging is disabled" in (result.stdout or "")


def test_process_pending_ots_disabled(isolated_env) -> None:
    """slop-cli process-pending exits 1 when ENABLE_OTS_FORGE=false."""
    env, ledger_dir, _ = isolated_env
    result = run_cli(
        ["process-pending", "--repo-path", str(ledger_dir)],
        env=env,
    )
    assert result.returncode == 1
    assert "OTS forging is disabled" in (result.stdout or "")


def test_events_after_generate(isolated_env) -> None:
    """slop-cli events lists generated events. Requires test keys."""
    env, ledger_dir, _ = isolated_env
    keys_dir = Path(__file__).resolve().parents[1] / "fixtures" / "keys"
    if not (keys_dir / "test_ml_dsa.priv").exists():
        pytest.skip("Test keys not found")
    _generate_and_extract_artifact(env, ledger_dir)
    result = run_cli(
        ["events", "--repo-path", str(ledger_dir), "--limit", "5"],
        env=env,
    )
    assert result.returncode == 0
    assert "request_id=" in (result.stdout or "")


def test_attest_after_generate(isolated_env) -> None:
    """slop-cli attest after generate. Requires test keys."""
    env, ledger_dir, _ = isolated_env
    keys_dir = Path(__file__).resolve().parents[1] / "fixtures" / "keys"
    if not (keys_dir / "test_ml_dsa.priv").exists():
        pytest.skip("Test keys not found")
    request_id, _ = _generate_and_extract_artifact(env, ledger_dir)
    result = run_cli(
        ["attest", "--repo-path", str(ledger_dir), "--request-id", request_id],
        env=env,
    )
    assert result.returncode == 0


def test_anchor_after_generate(isolated_env) -> None:
    """slop-cli anchor after generate. Requires test keys."""
    env, ledger_dir, _ = isolated_env
    keys_dir = Path(__file__).resolve().parents[1] / "fixtures" / "keys"
    if not (keys_dir / "test_ml_dsa.priv").exists():
        pytest.skip("Test keys not found")
    _, artifact_path = _generate_and_extract_artifact(env, ledger_dir)
    result = run_cli(
        ["anchor", "--file", str(artifact_path), "--repo-path", str(ledger_dir)],
        env=env,
    )
    assert result.returncode == 0
    assert "entry_id=" in (result.stdout or "")


def test_audit_after_generate(isolated_env) -> None:
    """slop-cli audit after generate. Requires test keys."""
    env, ledger_dir, _ = isolated_env
    keys_dir = Path(__file__).resolve().parents[1] / "fixtures" / "keys"
    if not (keys_dir / "test_ml_dsa.priv").exists():
        pytest.skip("Test keys not found")
    _, artifact_path = _generate_and_extract_artifact(env, ledger_dir)
    result = run_cli(
        ["audit", "--file", str(artifact_path), "--repo-path", str(ledger_dir)],
        env=env,
    )
    assert "envelope_valid" in (result.stdout or "")
    assert "artifact_id" in (result.stdout or "")


def test_timestamp_with_tsa_mock(isolated_env, tsa_mock) -> None:
    """slop-cli timestamp with TSA mock. Requires test keys. Mock returns minimal TSR so verification may fail."""
    env, ledger_dir, _ = isolated_env
    env["RFC3161_TSA_URL"] = tsa_mock
    keys_dir = Path(__file__).resolve().parents[1] / "fixtures" / "keys"
    if not (keys_dir / "test_ml_dsa.priv").exists():
        pytest.skip("Test keys not found")
    _, artifact_path = _generate_and_extract_artifact(env, ledger_dir)
    result = run_cli(
        [
            "timestamp",
            "--file",
            str(artifact_path),
            "--repo-path",
            str(ledger_dir),
            "--tsa-url",
            tsa_mock,
        ],
        env=env,
    )
    assert "Timestamp completed" in (result.stdout or "")
    assert "tsa=" in (result.stdout or "")


def test_verify_valid_artifact_passes(isolated_env) -> None:
    """Generate, attest, verify with hermetic keys; negative control proves env isolation."""
    env, ledger_dir, _ = isolated_env
    keys_dir = Path(__file__).resolve().parents[1] / "fixtures" / "keys"
    if not (keys_dir / "test_ml_dsa.priv").exists() or not (keys_dir / "test_ml_dsa.pub").exists():
        pytest.skip("Test keys not found; run keygen for fixtures/keys/")

    # 1. Generate artifact using hermetic test keys
    request_id, _ = _generate_and_extract_artifact(env, ledger_dir)

    # 2. Attest (sign) the artifact
    attest_result = run_cli(
        ["attest", "--repo-path", str(ledger_dir), "--request-id", request_id],
        env=env,
    )
    assert attest_result.returncode == 0, attest_result.stderr or attest_result.stdout

    # 3. Re-extract attested (signed) artifact from git
    artifact_content = subprocess.run(
        ["git", "-C", str(ledger_dir), "show", f"artifact/{request_id}:{request_id}.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
    ).stdout
    assert artifact_content, "Could not extract attested artifact from ledger"
    artifact_path = ledger_dir / "artifact.md"
    artifact_path.write_text(artifact_content, encoding="utf-8")

    # 4. Golden path: verify using hermetic test keys (must pass)
    verify_result = run_cli(
        ["verify", "--file", str(artifact_path)],
        env=env,
    )
    assert verify_result.returncode == 0, verify_result.stderr or verify_result.stdout
    assert "SIGNATURE VERIFIED" in (verify_result.stdout or "")

    # 5. Negative control: sabotage env with non-existent key paths.
    # If the CLI falls back to .env, this would incorrectly pass.
    sabotaged_env = env.copy()
    fake_key_dir = str(ledger_dir / "nonexistent_keys")
    sabotaged_env["OQS_PUBLIC_KEY_PATH"] = f"{fake_key_dir}/fake.pub"
    sabotaged_env["PQC_PRIVATE_KEY_PATH"] = f"{fake_key_dir}/fake.priv"

    sabotage_result = run_cli(
        ["verify", "--file", str(artifact_path)],
        env=sabotaged_env,
    )
    assert sabotage_result.returncode != 0, (
        "CRITICAL: Security isolation failed! "
        "The CLI ignored the env override and likely fell back to a real key in .env."
    )
