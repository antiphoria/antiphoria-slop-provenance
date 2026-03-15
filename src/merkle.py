"""Merkle tree construction for transparency log anchoring."""

from __future__ import annotations

import hashlib


def build_merkle_root(entry_hashes: list[str]) -> str:
    """Build Merkle root from ordered list of entry hashes.

    Uses SHA-256. Pairs leaves, hashes pairs, repeats until single root.
    For odd number of nodes at a level, duplicates the last node.
    """
    if not entry_hashes:
        return hashlib.sha256(b"").hexdigest()
    current = [bytes.fromhex(h) for h in entry_hashes]
    while len(current) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            combined = left + right
            next_level.append(hashlib.sha256(combined).digest())
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
    current = [bytes.fromhex(h) for h in entry_hashes]
    index = leaf_index
    while len(current) > 1:
        sibling_index = index ^ 1
        if sibling_index < len(current):
            proof.append(current[sibling_index].hex())
        else:
            proof.append(current[-1].hex())
        next_level: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            combined = left + right
            next_level.append(hashlib.sha256(combined).digest())
        current = next_level
        index = index // 2
    return proof


def verify_merkle_proof(
    leaf_hash: str,
    proof: list[str],
    root: str,
    leaf_index: int,
) -> bool:
    """Verify that leaf is included in Merkle tree with given root.

    Args:
        leaf_hash: SHA-256 hex digest of the leaf.
        proof: Sibling hashes from build_merkle_proof (leaf to root).
        root: Expected Merkle root (hex).
        leaf_index: Index of the leaf in the original entry_hashes list.

    Returns:
        True if the proof is valid.
    """
    current = bytes.fromhex(leaf_hash)
    index = leaf_index
    for sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if index % 2 == 0:
            combined = current + sibling
        else:
            combined = sibling + current
        current = hashlib.sha256(combined).digest()
        index = index // 2
    return current.hex() == root.lower()
