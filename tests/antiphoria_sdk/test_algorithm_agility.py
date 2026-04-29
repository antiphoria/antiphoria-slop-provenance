"""Algorithm-agility coverage for ``Signature``.

These tests pin down the contract introduced for D-1 (rotation prep):

* ``Signature.algorithm`` accepts the *family* of hybrid PQ + classical
  identifier strings, not just the literal ML-DSA-44 + Ed25519 suite,
  so that a chain produced by a future SDK release parses cleanly on
  older readers.
* ``Signature.key_id`` is a forward-compat rotation / epoch slot that
  defaults to ``None`` (so previously-written records still parse) and
  round-trips through canonical JSON when populated.
* :class:`HybridSigner` propagates the constructor-supplied ``key_id``
  onto every produced signature.
* Truly malformed algorithm strings (whitespace, mixed case, garbage)
  are still rejected by the schema.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from antiphoria_sdk import (
    HybridSigner,
    HybridVerifier,
    SealEngine,
    Signature,
    StepType,
    generate_ephemeral_keys,
)
from antiphoria_sdk.canonical import canonical_json_bytes


def _valid_signature_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "algorithm": "ml-dsa-44+ed25519",
        "mldsa_signature_b64": "AA==",
        "ed25519_signature_b64": "AA==",
        "public_key_fingerprint": "0" * 32,
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    "alg",
    [
        "ml-dsa-44+ed25519",
        "ml-dsa-65+ed25519",
        "ml-dsa-87+ed25519",
        "ed25519",
        "ml-dsa-44",
        "slh-dsa-sha2-128s+ed25519",
    ],
)
def test_signature_accepts_future_algorithm_strings(alg: str) -> None:
    """A future algorithm identifier must parse without raising.

    The schema's job is forward-compat parsing; *acceptance* belongs
    to the verifier (see ``HybridVerifier`` which still rejects
    anything other than its built-in suite).
    """
    sig = Signature(**_valid_signature_kwargs(algorithm=alg))
    assert sig.algorithm == alg


@pytest.mark.parametrize(
    "alg",
    [
        "",
        "ML-DSA-44+ED25519",
        "ml dsa 44",
        "ml-dsa-44+",
        "+ed25519",
        "ml-dsa-44+ed25519+",
        "a" * 65,
        "ml/dsa/44",
    ],
)
def test_signature_rejects_malformed_algorithm(alg: str) -> None:
    with pytest.raises(ValidationError):
        Signature(**_valid_signature_kwargs(algorithm=alg))


def test_signature_key_id_defaults_to_none_for_backward_compat() -> None:
    """Records produced before the field existed must still validate."""
    sig = Signature(**_valid_signature_kwargs())
    assert sig.key_id is None


def test_signature_key_id_round_trips_through_canonical_json() -> None:
    sig = Signature(**_valid_signature_kwargs(key_id="2026-Q2"))
    canon = canonical_json_bytes(sig.model_dump(mode="json"))
    restored = Signature.model_validate(json.loads(canon.decode("utf-8")))
    assert restored == sig
    assert restored.key_id == "2026-Q2"


@pytest.mark.parametrize(
    "key_id",
    [
        "",
        "has space",
        "has\ttab",
        "a" * 65,
    ],
)
def test_signature_rejects_malformed_key_id(key_id: str) -> None:
    with pytest.raises(ValidationError):
        Signature(**_valid_signature_kwargs(key_id=key_id))


def test_hybrid_signer_propagates_key_id() -> None:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys, key_id="factory-2026-Q2")
    sig = signer.sign(b"payload")
    assert sig.key_id == "factory-2026-Q2"
    assert sig.algorithm == "ml-dsa-44+ed25519"
    assert signer.key_id == "factory-2026-Q2"


def test_hybrid_signer_default_key_id_is_none() -> None:
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    sig = signer.sign(b"payload")
    assert sig.key_id is None
    assert signer.key_id is None


@pytest.mark.asyncio
async def test_seal_chain_records_carry_key_id_when_set(tmp_path: Path) -> None:
    """A chain produced by a key-id-tagged signer round-trips ``key_id``
    through canonical JSON and re-verifies cleanly."""
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys, key_id="factory-2026-Q2")
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(
        tmp_path,
        run_id="run-keyid",
        signer=signer,
        verifier=verifier,
    )
    await engine.begin_chain(research_brief={"title": "agility"})
    step_dir = tmp_path / "steps" / "0001"
    step_dir.mkdir(parents=True)
    (step_dir / "x.json").write_text("{}")
    await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/0001/x.json"],
        metadata={"node": "generator"},
    )

    raw = json.loads(
        (tmp_path / "chain" / "000000_GENESIS.json").read_bytes().decode("utf-8"),
    )
    assert raw["signature"]["key_id"] == "factory-2026-Q2"

    report = await engine.verify_chain()
    assert report.chain_intact, report.summary()


@pytest.mark.asyncio
async def test_seal_chain_omits_key_id_when_unset(tmp_path: Path) -> None:
    """When the signer has no ``key_id``, the field still appears in the
    canonical record (as ``null``) so the byte layout stays deterministic
    across runs."""
    keys = generate_ephemeral_keys()
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(
        tmp_path,
        run_id="run-no-keyid",
        signer=signer,
        verifier=verifier,
    )
    await engine.begin_chain()
    raw = json.loads(
        (tmp_path / "chain" / "000000_GENESIS.json").read_bytes().decode("utf-8"),
    )
    assert raw["signature"]["key_id"] is None

    report = await engine.verify_chain()
    assert report.chain_intact, report.summary()
