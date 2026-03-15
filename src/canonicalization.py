"""Strict payload canonicalization for deterministic artifact hashing.

Ensures artifactHash is reproducible across platforms (Windows/Linux), editors,
and parsers. See docs/CANONICALIZATION.md for the full specification.
"""

from __future__ import annotations

import hashlib

CANONICALIZATION_VERSION = "eternity.canonicalization.v1"
"""Schema version for canonicalization; included in signing target."""


def compute_payload_hash(body: str) -> str:
    """Compute SHA-256 hex digest of body for artifactHash.

    Applies strict canonicalization per docs/CANONICALIZATION.md.
    """
    canonical_bytes = canonicalize_body_for_hash(body)
    return hashlib.sha256(canonical_bytes).hexdigest()


def canonicalize_body_for_hash(body: str) -> bytes:
    """Canonicalize markdown body for SHA-256 hashing.

    Applies the following transformations (in order):
    1. Strip UTF-8 BOM if present
    2. Normalize all line endings to LF (\\n)
    3. Trim trailing whitespace from each line
    4. Trim trailing whitespace and ensure single trailing newline at EOF

    Returns UTF-8 encoded bytes suitable for hashing.
    """
    if not isinstance(body, str):
        raise TypeError("body must be str")
    # Strip BOM
    if body.startswith("\ufeff"):
        body = body[1:]
    # Normalize line endings to \n
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    # Trim trailing whitespace per line
    lines = [line.rstrip() for line in body.splitlines()]
    # Join with \n and ensure single trailing newline (empty content stays empty)
    if not lines:
        return b""
    result = "\n".join(lines) + "\n"
    return result.encode("utf-8")


def canonicalize_body(body: str) -> str:
    """Return canonical string form of body for storage.

    Same transformations as canonicalize_body_for_hash, but returns str
    for writing to files. Ensures round-trip parse yields same hash.
    """
    return canonicalize_body_for_hash(body).decode("utf-8")
