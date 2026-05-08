"""Minimal smoke tests for antiphoria_sdk."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from antiphoria_sdk import (
    HybridSigner,
    HybridVerifier,
    SealEngine,
    StepType,
    generate_ephemeral_keys,
    verify_chain,
)


@pytest.mark.asyncio
async def test_begin_seal_verify_roundtrip(tmp_path: Path) -> None:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(
        tmp_path,
        run_id="run-001",
        signer=signer,
        verifier=verifier,
    )
    genesis = await engine.begin_chain(research_brief={"title": "smoke"})
    assert genesis.step_index == 0
    assert genesis.previous_hash is None
    assert genesis.entry_hash.startswith("sha256:")

    step_dir = tmp_path / "steps" / "0001_pre_generator"
    step_dir.mkdir(parents=True)
    (step_dir / "intent.json").write_text(json.dumps({"prompt": "hello"}))

    receipt = await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/0001_pre_generator/intent.json"],
        metadata={"node": "generator"},
    )
    assert receipt.step_index == 1
    assert receipt.previous_hash == genesis.entry_hash

    r1 = await engine.verify_chain()
    assert r1.chain_intact, r1.summary()
    assert r1.total_steps == 2

    r2 = await verify_chain(tmp_path, "run-001", verifier=verifier)
    assert r2.chain_intact


@pytest.mark.asyncio
async def test_tamper_content_file_is_detected(tmp_path: Path) -> None:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(
        tmp_path,
        "r2",
        signer=signer,
        verifier=verifier,
    )
    await engine.begin_chain()
    content = tmp_path / "steps" / "001" / "file.txt"
    content.parent.mkdir(parents=True)
    content.write_text("original")
    await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/001/file.txt"],
        metadata={},
    )

    content.write_text("tampered")

    report = await engine.verify_chain()
    assert not report.chain_intact
    assert report.first_error_index == 1
    step = report.steps[1]
    assert not step.content_hashes_valid
    assert any("Content hash mismatch" in e for e in step.errors)


@pytest.mark.asyncio
async def test_tamper_chain_record_is_detected(tmp_path: Path) -> None:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(
        tmp_path,
        "r3",
        signer=signer,
        verifier=verifier,
    )
    await engine.begin_chain()
    step_dir = tmp_path / "steps" / "001"
    step_dir.mkdir(parents=True)
    (step_dir / "x.json").write_text("{}")
    await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/001/x.json"],
        metadata={"v": 1},
    )

    record_path = tmp_path / "chain" / "000001_PRE_GENERATOR.json"
    raw = json.loads(record_path.read_text())
    raw["metadata"]["v"] = 999
    record_path.write_text(json.dumps(raw))

    report = await engine.verify_chain()
    assert not report.chain_intact
    step = report.steps[1]
    assert not step.signature_valid or not step.canonical_form_valid


@pytest.mark.asyncio
async def test_resume_restores_latest_hash(tmp_path: Path) -> None:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(
        tmp_path,
        "r4",
        signer=signer,
        verifier=verifier,
    )
    await engine.begin_chain()
    sp = tmp_path / "steps" / "001"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("a")
    first = await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/001/a.txt"],
        metadata={},
    )

    engine2 = SealEngine.resume(
        tmp_path,
        "r4",
        signer=signer,
        verifier=verifier,
    )
    assert engine2.latest_step == 1
    assert engine2.latest_hash == first.entry_hash

    (sp / "b.txt").write_text("b")
    second = await engine2.seal(
        step_type=StepType.POST_GENERATOR,
        content_file_paths=["steps/001/b.txt"],
        metadata={},
    )
    assert second.previous_hash == first.entry_hash
