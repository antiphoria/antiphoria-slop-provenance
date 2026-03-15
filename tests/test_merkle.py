"""Unit tests for Merkle tree construction."""

from __future__ import annotations

import hashlib

import pytest

from src.merkle import build_merkle_proof, build_merkle_root, verify_merkle_proof


def test_build_merkle_root_empty() -> None:
    """Empty list returns SHA-256 of empty bytes."""
    result = build_merkle_root([])
    assert result == hashlib.sha256(b"").hexdigest()


def test_build_merkle_root_single() -> None:
    """Single entry returns that entry as root."""
    h = "a" * 64
    assert build_merkle_root([h]) == h


def test_build_merkle_root_two() -> None:
    """Two entries produce SHA-256(left + right)."""
    a, b = "a" * 64, "b" * 64
    expected = hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()
    assert build_merkle_root([a, b]) == expected


def test_build_merkle_root_three_duplicates_last() -> None:
    """Three entries: last is duplicated for pairing."""
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    ab = hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).digest()
    cc = hashlib.sha256(bytes.fromhex(c) + bytes.fromhex(c)).digest()
    root = hashlib.sha256(ab + cc).hexdigest()
    assert build_merkle_root([a, b, c]) == root


def test_build_merkle_root_deterministic() -> None:
    """Same inputs produce same root."""
    hashes = [f"{i:064x}" for i in range(5)]
    r1 = build_merkle_root(hashes)
    r2 = build_merkle_root(hashes)
    assert r1 == r2


def test_build_merkle_proof_single() -> None:
    """Single entry has empty proof."""
    h = "a" * 64
    proof = build_merkle_proof([h], 0)
    assert proof == []


def test_build_merkle_proof_two() -> None:
    """Two entries: proof for index 0 is [b], for index 1 is [a]."""
    a, b = "a" * 64, "b" * 64
    proof0 = build_merkle_proof([a, b], 0)
    proof1 = build_merkle_proof([a, b], 1)
    assert proof0 == [b]
    assert proof1 == [a]


def test_verify_merkle_proof_valid() -> None:
    """Valid proof verifies."""
    hashes = [f"{i:064x}" for i in range(4)]
    root = build_merkle_root(hashes)
    for i in range(4):
        proof = build_merkle_proof(hashes, i)
        assert verify_merkle_proof(hashes[i], proof, root, i)


def test_verify_merkle_proof_invalid_tampered_leaf() -> None:
    """Tampered leaf fails verification."""
    hashes = [f"{i:064x}" for i in range(4)]
    root = build_merkle_root(hashes)
    proof = build_merkle_proof(hashes, 0)
    tampered = "f" * 64
    assert not verify_merkle_proof(tampered, proof, root, 0)


def test_verify_merkle_proof_invalid_wrong_root() -> None:
    """Wrong root fails verification."""
    hashes = [f"{i:064x}" for i in range(4)]
    root = build_merkle_root(hashes)
    proof = build_merkle_proof(hashes, 0)
    wrong_root = "e" * 64
    assert not verify_merkle_proof(hashes[0], proof, wrong_root, 0)


def test_build_merkle_proof_raises_out_of_range() -> None:
    """build_merkle_proof raises for invalid index."""
    hashes = [f"{i:064x}" for i in range(3)]
    with pytest.raises(ValueError, match="out of range"):
        build_merkle_proof(hashes, 5)
    with pytest.raises(ValueError, match="out of range"):
        build_merkle_proof(hashes, -1)
