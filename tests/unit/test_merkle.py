"""Unit tests for Merkle tree construction."""

from __future__ import annotations

import hashlib

import pytest

from src.merkle import build_merkle_proof, build_merkle_root, verify_merkle_proof


def _h(s: str) -> str:
    return s * 64


@pytest.mark.parametrize(
    "hashes,expected",
    [
        ([], hashlib.sha256(b"").hexdigest()),
        ([_h("a")], _h("a")),
        (
            [_h("a"), _h("b")],
            hashlib.sha256(bytes.fromhex(_h("a")) + bytes.fromhex(_h("b"))).hexdigest(),
        ),
        (
            [_h("a"), _h("b"), _h("c")],
            hashlib.sha256(
                hashlib.sha256(bytes.fromhex(_h("a")) + bytes.fromhex(_h("b"))).digest()
                + hashlib.sha256(bytes.fromhex(_h("c")) + bytes.fromhex(_h("c"))).digest()
            ).hexdigest(),
        ),
    ],
)
def test_build_merkle_root(hashes: list[str], expected: str) -> None:
    assert build_merkle_root(hashes) == expected


def test_build_merkle_root_deterministic() -> None:
    hashes = [f"{i:064x}" for i in range(5)]
    r1 = build_merkle_root(hashes)
    r2 = build_merkle_root(hashes)
    assert r1 == r2


@pytest.mark.parametrize(
    "hashes,index,expected",
    [
        ([_h("a")], 0, []),
        ([_h("a"), _h("b")], 0, [_h("b")]),
        ([_h("a"), _h("b")], 1, [_h("a")]),
    ],
)
def test_build_merkle_proof(hashes: list[str], index: int, expected: list[str]) -> None:
    assert build_merkle_proof(hashes, index) == expected


@pytest.mark.parametrize(
    "hashes,index",
    [
        ([_h("a"), _h("b"), _h("c")], 5),
        ([_h("a"), _h("b"), _h("c")], -1),
    ],
)
def test_build_merkle_proof_raises(hashes: list[str], index: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        build_merkle_proof(hashes, index)


@pytest.mark.parametrize(
    "leaf,proof,root,index,expected",
    [
        (
            f"{0:064x}",
            build_merkle_proof([f"{i:064x}" for i in range(4)], 0),
            build_merkle_root([f"{i:064x}" for i in range(4)]),
            0,
            True,
        ),
        (
            "f" * 64,
            build_merkle_proof([f"{i:064x}" for i in range(4)], 0),
            build_merkle_root([f"{i:064x}" for i in range(4)]),
            0,
            False,
        ),
        (
            f"{0:064x}",
            build_merkle_proof([f"{i:064x}" for i in range(4)], 0),
            "e" * 64,
            0,
            False,
        ),
    ],
)
def test_verify_merkle_proof(
    leaf: str, proof: list[str], root: str, index: int, expected: bool
) -> None:
    assert verify_merkle_proof(leaf, proof, root, index) == expected


@pytest.mark.parametrize(
    "hashes",
    [
        [f"{i:064x}" for i in range(4)],
    ],
)
def test_verify_merkle_proof_valid_all_indices(hashes: list[str]) -> None:
    root = build_merkle_root(hashes)
    for i in range(len(hashes)):
        proof = build_merkle_proof(hashes, i)
        assert verify_merkle_proof(hashes[i], proof, root, i)


try:
    from hypothesis import given
    import hypothesis.strategies as st

    @given(
        st.lists(
            st.text(min_size=64, max_size=64, alphabet="0123456789abcdef"),
            min_size=1,
            max_size=32,
        )
    )
    def test_verify_merkle_proof_property(hashes: list[str]) -> None:
        root = build_merkle_root(hashes)
        for i in range(len(hashes)):
            proof = build_merkle_proof(hashes, i)
            assert verify_merkle_proof(hashes[i], proof, root, i)

except ImportError:
    pass
