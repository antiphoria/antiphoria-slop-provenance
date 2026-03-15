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
