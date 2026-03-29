"""Tests for payload canonicalization."""

from __future__ import annotations

import pytest

from src.canonicalization import (
    CANONICALIZATION_VERSION,
    canonicalize_body,
    canonicalize_body_for_hash,
    compute_payload_hash,
)


@pytest.mark.parametrize(
    "body,expected",
    [
        ("", b""),
        ("\ufeffx\n", b"x\n"),
        ("a\r\nb\r\n", b"a\nb\n"),
        ("a\rb\rc\r", b"a\nb\nc\n"),
        ("x\u200by\n", "x\u200by\n".encode("utf-8")),
        ("a \nb\t\t\n", b"a\nb\n"),
        ("content", b"content\n"),
        ("hello \U0001f600 world\n", "hello \U0001f600 world\n".encode("utf-8")),
        ("a\r\nb\nc\r", b"a\nb\nc\n"),
        ("  foo  \r\n  bar  \r\n", b"  foo\n  bar\n"),
    ],
)
def test_canonicalize_body_for_hash(body: str, expected: bytes) -> None:
    assert canonicalize_body_for_hash(body) == expected


@pytest.mark.parametrize("body", [0.0, None])
def test_canonicalize_body_for_hash_type_error(body: object) -> None:
    with pytest.raises((TypeError, AttributeError)):
        canonicalize_body_for_hash(body)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "body,expected_len",
    [
        ("a\r\nb\n", 64),
        ("", 64),
    ],
)
def test_compute_payload_hash_properties(body: str, expected_len: int) -> None:
    h = compute_payload_hash(body)
    assert len(h) == expected_len
    assert all(c in "0123456789abcdef" for c in h)


def test_compute_payload_hash_canonicalization_idempotence() -> None:
    assert compute_payload_hash("a\r\nb\n") == compute_payload_hash("a\nb\n")


def test_canonicalize_body_roundtrip() -> None:
    body = "  foo  \r\n  bar  \r\n"
    canonical_str = canonicalize_body(body)
    canonical_bytes = canonicalize_body_for_hash(body)
    assert canonical_str == canonical_bytes.decode("utf-8")


def test_version_constant() -> None:
    assert CANONICALIZATION_VERSION == "eternity.canonicalization.v1"
