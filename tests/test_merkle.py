"""Unit tests for Merkle tree construction."""

from __future__ import annotations

import hashlib

import pytest

from src.merkle import build_merkle_root


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
