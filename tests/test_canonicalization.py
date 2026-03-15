"""Tests for payload canonicalization."""

from __future__ import annotations

import pytest

from src.canonicalization import (
    CANONICALIZATION_VERSION,
    canonicalize_body,
    canonicalize_body_for_hash,
    compute_payload_hash,
)


def test_canonicalize_strips_bom() -> None:
    body = "\ufeffhello\nworld\n"
    result = canonicalize_body_for_hash(body)
    assert result == b"hello\nworld\n"


def test_canonicalize_normalizes_crlf() -> None:
    body = "line1\r\nline2\r\n"
    result = canonicalize_body_for_hash(body)
    assert result == b"line1\nline2\n"


def test_canonicalize_normalizes_cr() -> None:
    body = "a\rb\rc\r"
    result = canonicalize_body_for_hash(body)
    assert result == b"a\nb\nc\n"


def test_canonicalize_trims_trailing_whitespace_per_line() -> None:
    body = "line1   \nline2\t\t\n"
    result = canonicalize_body_for_hash(body)
    assert result == b"line1\nline2\n"


def test_canonicalize_ensures_single_trailing_newline() -> None:
    body = "content"
    result = canonicalize_body_for_hash(body)
    assert result == b"content\n"


def test_canonicalize_empty_stays_empty() -> None:
    body = ""
    result = canonicalize_body_for_hash(body)
    assert result == b""


def test_compute_payload_hash_canonical() -> None:
    body = "hello\r\nworld  \n"
    h = compute_payload_hash(body)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_compute_payload_hash_different_for_crlf_vs_lf() -> None:
    body_crlf = "a\r\nb\n"
    body_lf = "a\nb\n"
    h_crlf = compute_payload_hash(body_crlf)
    h_lf = compute_payload_hash(body_lf)
    assert h_crlf == h_lf  # Canonicalization normalizes both to same


def test_canonicalize_body_roundtrip() -> None:
    body = "  foo  \r\n  bar  \r\n"
    canonical_str = canonicalize_body(body)
    canonical_bytes = canonicalize_body_for_hash(body)
    assert canonical_str == canonical_bytes.decode("utf-8")


def test_version_constant() -> None:
    assert CANONICALIZATION_VERSION == "eternity.canonicalization.v1"
