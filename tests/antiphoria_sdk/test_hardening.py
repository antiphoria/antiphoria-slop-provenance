"""Hardening tests for antiphoria_sdk: verifier gaps, paths, fingerprints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from antiphoria_sdk import (
    ChainError,
    ChainRecord,
    HybridSigner,
    HybridVerifier,
    SealEngine,
    Signature,
    StepType,
    generate_ephemeral_keys,
    verify_chain,
)
from antiphoria_sdk.canonical import canonical_json_bytes
from antiphoria_sdk.types import is_safe_relative_path


def _make_engine(tmp_path: Path, run_id: str = "rh") -> SealEngine:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})
    return SealEngine.create(tmp_path, run_id, signer=signer, verifier=verifier)


def test_is_safe_relative_path_rules() -> None:
    assert is_safe_relative_path("steps/0001/intent.json")
    assert is_safe_relative_path("a/b/c.txt")
    assert is_safe_relative_path("file.txt")

    assert not is_safe_relative_path("")
    assert not is_safe_relative_path("/abs/path")
    assert not is_safe_relative_path("../escape")
    assert not is_safe_relative_path("a/../b")
    assert not is_safe_relative_path("a/./b")
    assert not is_safe_relative_path("a//b")
    assert not is_safe_relative_path("a\\b")
    assert not is_safe_relative_path("C:foo")


@pytest.mark.asyncio
async def test_seal_rejects_unsafe_relative_path(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path, "rh1")
    await engine.begin_chain()
    with pytest.raises(ChainError):
        await engine.seal(
            step_type=StepType.PRE_GENERATOR,
            content_file_paths=["../escape.txt"],
            metadata={},
        )


@pytest.mark.asyncio
async def test_seal_rejects_absolute_outside_workspace(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    engine = _make_engine(tmp_path, "rh2")
    await engine.begin_chain()
    other = tmp_path_factory.mktemp("outside")
    outside_file = other / "x.txt"
    outside_file.write_text("nope")
    with pytest.raises(ChainError):
        await engine.seal(
            step_type=StepType.PRE_GENERATOR,
            content_file_paths=[str(outside_file)],
            metadata={},
        )


def test_chain_record_rejects_unsafe_content_path_key() -> None:
    sig = Signature(
        algorithm="ml-dsa-44+ed25519",
        mldsa_signature_b64="AA==",
        ed25519_signature_b64="AA==",
        public_key_fingerprint="0" * 32,
    )
    with pytest.raises(ValidationError):
        ChainRecord(
            sdk_version="0.2.0",
            run_id="r",
            step_index=0,
            step_type="GENESIS",
            content_file_hashes={"../escape": "sha256:" + "0" * 64},
            metadata={},
            previous_hash=None,
            timestamp="2024-01-01T00:00:00+00:00",
            signature=sig,
        )


def test_chain_record_rejects_invalid_previous_hash() -> None:
    sig = Signature(
        algorithm="ml-dsa-44+ed25519",
        mldsa_signature_b64="AA==",
        ed25519_signature_b64="AA==",
        public_key_fingerprint="0" * 32,
    )
    with pytest.raises(ValidationError):
        ChainRecord(
            sdk_version="0.2.0",
            run_id="r",
            step_index=1,
            step_type="PRE_GENERATOR",
            content_file_hashes={},
            metadata={},
            previous_hash="not-a-hash",
            timestamp="2024-01-01T00:00:00+00:00",
            signature=sig,
        )


@pytest.mark.asyncio
async def test_verify_rejects_non_genesis_at_step_zero(tmp_path: Path) -> None:
    """A signed-but-malformed chain whose first record is not GENESIS must fail verification."""
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(tmp_path, "rh3", signer=signer, verifier=verifier)
    await engine.begin_chain()
    sp = tmp_path / "steps" / "001"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("a")
    await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/001/a.txt"],
        metadata={},
    )

    genesis_path = tmp_path / "chain" / "000000_GENESIS.json"
    genesis_path.unlink()

    report = await engine.verify_chain()
    assert not report.chain_intact
    assert report.first_error_index == 0
    first = report.steps[0]
    assert any("First record must be" in e for e in first.errors)


@pytest.mark.asyncio
async def test_verify_rejects_genesis_at_non_zero_index(tmp_path: Path) -> None:
    """A second GENESIS record anywhere in the chain must trip the verifier."""
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})
    engine = SealEngine.create(tmp_path, "rh4", signer=signer, verifier=verifier)
    await engine.begin_chain()

    genesis_bytes = (tmp_path / "chain" / "000000_GENESIS.json").read_bytes()
    record_dict = json.loads(genesis_bytes.decode("utf-8"))
    record_dict["step_index"] = 1
    forged = ChainRecord.model_validate(record_dict)
    forged_bytes = canonical_json_bytes(forged.model_dump(mode="json"))
    (tmp_path / "chain" / "000001_GENESIS.json").write_bytes(forged_bytes)

    report = await engine.verify_chain()
    assert not report.chain_intact
    assert any("only allowed at step 0" in e for e in report.steps[1].errors)


@pytest.mark.asyncio
async def test_verify_rejects_unsafe_content_path_in_record(tmp_path: Path) -> None:
    """A hand-crafted record with a traversal path key must be rejected at verify time."""
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})
    engine = SealEngine.create(tmp_path, "rh5", signer=signer, verifier=verifier)
    await engine.begin_chain()

    genesis_path = tmp_path / "chain" / "000000_GENESIS.json"
    raw = json.loads(genesis_path.read_bytes().decode("utf-8"))
    raw["content_file_hashes"] = {"../escape": "sha256:" + "0" * 64}
    genesis_path.write_text(json.dumps(raw))

    report = await engine.verify_chain()
    assert not report.chain_intact
    assert any("Parse/validate error" in e for e in report.steps[0].errors)


class _BadFingerprintSigner:
    """A signer whose embedded signature fingerprint disagrees with its advertised one."""

    public_key_fingerprint = "a" * 32

    def sign(self, data: bytes) -> Signature:
        return Signature(
            algorithm="ml-dsa-44+ed25519",
            mldsa_signature_b64="AA==",
            ed25519_signature_b64="AA==",
            public_key_fingerprint="b" * 32,
        )


@pytest.mark.asyncio
async def test_fingerprint_binding_rejects_mismatch(tmp_path: Path) -> None:
    """If a signer returns a Signature whose fingerprint disagrees with its advertised one, fail."""
    keys = generate_ephemeral_keys()
    verifier = HybridVerifier({keys.fingerprint: keys})
    engine = SealEngine.create(
        tmp_path,
        "rh6",
        signer=_BadFingerprintSigner(),
        verifier=verifier,
    )
    with pytest.raises(ChainError, match="Signer fingerprint mismatch"):
        await engine.begin_chain()


@pytest.mark.asyncio
async def test_genesis_metadata_is_flat(tmp_path: Path) -> None:
    """research_brief is stored top-level in metadata, alongside other keys (no 'extra' wrapping)."""
    engine = _make_engine(tmp_path, "rh7")
    await engine.begin_chain(
        research_brief={"title": "x"},
        metadata={"author": "alice"},
    )
    raw = json.loads(
        (tmp_path / "chain" / "000000_GENESIS.json").read_bytes().decode("utf-8"),
    )
    assert raw["metadata"] == {"author": "alice", "research_brief": {"title": "x"}}


@pytest.mark.asyncio
async def test_genesis_rejects_reserved_key_collision(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path, "rh8")
    with pytest.raises(ValueError, match="research_brief is reserved"):
        await engine.begin_chain(
            research_brief={"a": 1},
            metadata={"research_brief": {"a": 2}},
        )


@pytest.mark.asyncio
async def test_verify_only_signer_cannot_be_used_for_writes(tmp_path: Path) -> None:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})
    engine = SealEngine.create(tmp_path, "rh9", signer=signer, verifier=verifier)
    await engine.begin_chain()

    report = await verify_chain(tmp_path, "rh9", verifier=verifier)
    assert report.chain_intact
    assert report.total_steps == 1


@pytest.mark.asyncio
async def test_atomic_write_uses_unique_tmp_file(tmp_path: Path) -> None:
    """A stale .json.tmp from a crashed prior step must not block a subsequent seal."""
    engine = _make_engine(tmp_path, "rh10")
    chain_dir = tmp_path / "chain"
    await engine.begin_chain()

    stale = chain_dir / "000001_PRE_GENERATOR.crashed.json.tmp"
    stale.write_bytes(b"stale leftover from a crashed prior run")

    sp = tmp_path / "steps" / "001"
    sp.mkdir(parents=True)
    (sp / "a.txt").write_text("a")
    receipt = await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/001/a.txt"],
        metadata={},
    )
    assert receipt.step_index == 1
    assert (chain_dir / "000001_PRE_GENERATOR.json").is_file()
    assert stale.exists()
