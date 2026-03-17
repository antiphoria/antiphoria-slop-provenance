"""Merkle tree construction for transparency log anchoring.

Uses RFC 6962-style construction with domain separation:
- Leaf hashes: H(0x00 || leaf_bytes)
- Internal nodes: H(0x01 || left || right)
- Odd nodes: promote the last node to the next level (no duplication).
"""

from __future__ import annotations

import hashlib

_LEAF_PREFIX = b"\x00"
_INTERNAL_PREFIX = b"\x01"


def _hash_leaf(leaf_bytes: bytes) -> bytes:
    """Hash a leaf with domain separation."""
    return hashlib.sha256(_LEAF_PREFIX + leaf_bytes).digest()


def _hash_internal(left: bytes, right: bytes) -> bytes:
    """Hash an internal node with domain separation."""
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


def _subtree_root(nodes: list[bytes]) -> bytes:
    """Compute Merkle root of a list of tree nodes (no leaf hashing)."""
    if not nodes:
        raise ValueError("nodes cannot be empty")
    current = list(nodes)
    while len(current) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
                next_level.append(_hash_internal(left, right))
            else:
                next_level.append(left)
        current = next_level
    return current[0]


def build_merkle_root(entry_hashes: list[str]) -> str:
    """Build Merkle root from ordered list of entry hashes.

    Uses SHA-256 with RFC 6962-style domain separation. For odd number of
    nodes at a level, promotes the last node (no duplication).
    """
    if not entry_hashes:
        return hashlib.sha256(b"").hexdigest()
    current = [_hash_leaf(bytes.fromhex(h)) for h in entry_hashes]
    while len(current) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
                next_level.append(_hash_internal(left, right))
            else:
                next_level.append(left)
        current = next_level
    return current[0].hex()


def build_merkle_proof(entry_hashes: list[str], leaf_index: int) -> list[str]:
    """Build Merkle inclusion proof for leaf at index.

    Returns list of sibling hashes from leaf level up to (but not including) root.
    Verification requires leaf_index to reconstruct the path.
    """
    if not entry_hashes:
        raise ValueError("entry_hashes cannot be empty")
    if leaf_index < 0 or leaf_index >= len(entry_hashes):
        raise ValueError(f"leaf_index {leaf_index} out of range [0, {len(entry_hashes)})")
    proof: list[str] = []
    current = [_hash_leaf(bytes.fromhex(h)) for h in entry_hashes]
    index = leaf_index
    while len(current) > 1:
        sibling_index = index ^ 1
        promoted = sibling_index >= len(current)
        if not promoted:
            proof.append(current[sibling_index].hex())
        else:
            proof.append(_subtree_root(current[:index]).hex())
        next_level: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
                next_level.append(_hash_internal(left, right))
            else:
                next_level.append(left)
        current = next_level
        index = index // 2
        if promoted and len(current) == 2:
            break
    return proof


def verify_merkle_proof(
    leaf_hash: str,
    proof: list[str],
    root: str,
    leaf_index: int,
    tree_size: int | None = None,
) -> bool:
    """Verify that leaf is included in Merkle tree with given root.

    Args:
        leaf_hash: SHA-256 hex digest of the leaf (raw entry hash).
        proof: Sibling hashes from build_merkle_proof (leaf to root).
        root: Expected Merkle root (hex).
        leaf_index: Index of the leaf in the original entry_hashes list.
        tree_size: Number of leaves in the tree. Required for correct
            verification when the tree has odd-sized levels (promoted nodes).

    Returns:
        True if the proof is valid.
    """
    root_lower = root.lower()
    current = _hash_leaf(bytes.fromhex(leaf_hash))
    index = leaf_index
    size = tree_size
    for sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if size is not None and size % 2 == 1 and index == size - 1:
            on_right = True
        else:
            on_right = index % 2 == 1
        if on_right:
            current = _hash_internal(sibling, current)
        else:
            current = _hash_internal(current, sibling)
        if current.hex() == root_lower:
            return True
        index = index // 2
        if size is not None:
            size = (size + 1) // 2
    return current.hex() == root_lower
