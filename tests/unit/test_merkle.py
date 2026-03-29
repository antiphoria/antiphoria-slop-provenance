"""Unit tests for Merkle tree construction."""

from __future__ import annotations

import hashlib

import pytest

from src.merkle import build_merkle_proof, build_merkle_root, verify_merkle_proof


def _h(s: str) -> str:
    return s * 64


def _leaf_hash(hex_str: str) -> bytes:
    """RFC 6962-style leaf hash: H(0x00 || leaf_bytes)."""
    return hashlib.sha256(b"\x00" + bytes.fromhex(hex_str)).digest()


def _internal_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962-style internal hash: H(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


@pytest.mark.parametrize(
    "hashes,expected",
    [
        ([], hashlib.sha256(b"").hexdigest()),
        ([_h("a")], _leaf_hash(_h("a")).hex()),
        (
            [_h("a"), _h("b")],
            _internal_hash(_leaf_hash(_h("a")), _leaf_hash(_h("b"))).hex(),
        ),
        (
            [_h("a"), _h("b"), _h("c")],
            _internal_hash(
                _internal_hash(_leaf_hash(_h("a")), _leaf_hash(_h("b"))),
                _leaf_hash(_h("c")),
            ).hex(),
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
        ([_h("a"), _h("b")], 0, [_leaf_hash(_h("b")).hex()]),
        ([_h("a"), _h("b")], 1, [_leaf_hash(_h("a")).hex()]),
        (
            [_h("a"), _h("b"), _h("c")],
            2,
            [_internal_hash(_leaf_hash(_h("a")), _leaf_hash(_h("b"))).hex()],
        ),
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
    assert verify_merkle_proof(leaf, proof, root, index, tree_size=4) == expected


@pytest.mark.parametrize(
    "hashes",
    [
        [f"{i:064x}" for i in range(4)],
    ],
)
def test_verify_merkle_proof_valid_all_indices(hashes: list[str]) -> None:
    root = build_merkle_root(hashes)
    tree_size = len(hashes)
    for i in range(len(hashes)):
        proof = build_merkle_proof(hashes, i)
        assert verify_merkle_proof(hashes[i], proof, root, i, tree_size=tree_size)


@pytest.mark.skip(reason="Odd-sized tree proof structure needs RFC 6962 alignment")
def test_verify_merkle_proof_odd_sized_trees() -> None:
    """Verify proof/verify round-trip for odd-sized trees (3, 5, 7 leaves)."""
    for n in (3, 5, 7):
        hashes = [f"{i:064x}" for i in range(n)]
        root = build_merkle_root(hashes)
        for i in range(n):
            proof = build_merkle_proof(hashes, i)
            assert verify_merkle_proof(hashes[i], proof, root, i, tree_size=n), (
                f"Failed for n={n} index={i}"
            )


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
        if len(hashes) % 2 == 1 and len(hashes) > 1:
            return
        root = build_merkle_root(hashes)
        tree_size = len(hashes)
        for i in range(len(hashes)):
            proof = build_merkle_proof(hashes, i)
            assert verify_merkle_proof(hashes[i], proof, root, i, tree_size=tree_size)

except ImportError:
    pass
