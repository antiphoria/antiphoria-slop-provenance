"""Tests for transparency log adapter and Supabase publish."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    build_supabase_publish_config,
)


def _make_response(body: bytes) -> object:
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TransparencyLogPublishTest(unittest.TestCase):
    """Validate Supabase publish headers and payload format."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self._log_path = Path(self._temp.name) / "transparency-log.jsonl"

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_publish_sends_supabase_headers_and_wrapped_payload(self) -> None:
        """With Supabase config, POST has apikey, Prefer, and body is {"payload": ...}."""

        captured_request: list[object] = []

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            captured_request.append(request)
            return _make_response(b'[{"id": 1, "payload": {}}]')

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={
                "apikey": "test-key",
                "Authorization": "Bearer test-key",
                "Prefer": "return=representation",
            },
            publish_supabase_format=True,
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            entry, _ = adapter.build_entry_record(
                artifact_hash="a" * 64,
                artifact_id="b" * 36,
                source_file="artifact.md",
                previous_entry_hash=None,
                request_id="c" * 36,
                metadata={"source": "human"},
            )

        self.assertEqual(len(captured_request), 1)
        req = captured_request[0]
        header_items = {k.lower(): v for k, v in req.header_items()}
        self.assertEqual(header_items.get("content-type"), "application/json")
        self.assertEqual(header_items.get("apikey"), "test-key")
        self.assertEqual(header_items.get("authorization"), "Bearer test-key")
        self.assertEqual(header_items.get("prefer"), "return=representation")

        body = json.loads(req.data.decode("utf-8"))
        self.assertIn("payload", body)
        self.assertEqual(body["payload"]["artifactHash"], "a" * 64)
        self.assertEqual(body["payload"]["metadata"], {"source": "human"})

        self.assertIsNotNone(entry.remote_receipt)
        self.assertIn('"id": 1', entry.remote_receipt)

    def test_publish_without_headers_sends_raw_payload(self) -> None:
        """Without Supabase config, POST body is raw record, no auth headers."""

        captured_request: list[object] = []

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            captured_request.append(request)
            return _make_response(b"ok")

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://example.org/append",
            publish_headers=None,
            publish_supabase_format=False,
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            entry, _ = adapter.build_entry_record(
                artifact_hash="d" * 64,
                artifact_id="e" * 36,
                source_file="x.md",
                previous_entry_hash=None,
            )

        self.assertEqual(len(captured_request), 1)
        req = captured_request[0]
        header_items = {k.lower(): v for k, v in req.header_items()}
        self.assertNotIn("apikey", header_items)
        self.assertNotIn("prefer", header_items)

        body = json.loads(req.data.decode("utf-8"))
        self.assertNotIn("payload", body)
        self.assertEqual(body["artifactHash"], "d" * 64)
        self.assertEqual(entry.remote_receipt, "ok")


class BuildSupabaseConfigTest(unittest.TestCase):
    """Validate build_supabase_publish_config."""

    def test_returns_empty_when_no_url(self) -> None:
        headers, use_format = build_supabase_publish_config(None)
        self.assertEqual(headers, {})
        self.assertFalse(use_format)

    def test_raises_when_url_set_but_no_key(self) -> None:
        with patch("src.adapters.transparency_log.read_env_optional", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                build_supabase_publish_config("https://x.supabase.co/rest/v1/t")
        self.assertIn("SUPABASE_SERVICE_KEY", str(ctx.exception))
        self.assertIn("SUPABASE_ANON_KEY", str(ctx.exception))

    def test_returns_headers_when_key_set(self) -> None:
        with patch(
            "src.adapters.transparency_log.read_env_optional",
            side_effect=lambda k, **kw: "my-key" if "SUPABASE" in k else None,
        ):
            headers, use_format = build_supabase_publish_config("https://x.supabase.co/rest/v1/t")
        self.assertEqual(headers["apikey"], "my-key")
        self.assertEqual(headers["Authorization"], "Bearer my-key")
        self.assertEqual(headers["Prefer"], "return=representation")
        self.assertTrue(use_format)


class FetchRemoteEntriesTest(unittest.TestCase):
    """Validate fetch_remote_entries_by_artifact_hash."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self._log_path = Path(self._temp.name) / "transparency-log.jsonl"

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_returns_none_when_no_publish_url(self) -> None:
        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url=None,
            publish_headers={"apikey": "x"},
        )
        self.assertIsNone(
            adapter.fetch_remote_entries_by_artifact_hash("a" * 64)
        )

    def test_returns_none_when_no_headers(self) -> None:
        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={},
        )
        self.assertIsNone(
            adapter.fetch_remote_entries_by_artifact_hash("a" * 64)
        )

    def test_get_sends_correct_url_and_headers(self) -> None:
        captured_request: list[object] = []

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            captured_request.append(request)
            return _make_response(
                json.dumps([
                    {
                        "id": 42,
                        "payload": {
                            "artifactHash": "b" * 64,
                            "entryHash": "entry-hash-123",
                        },
                        "created_at": "2024-01-01T00:00:00Z",
                    },
                ]).encode("utf-8")
            )

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={
                "apikey": "test-key",
                "Authorization": "Bearer test-key",
            },
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            result = adapter.fetch_remote_entries_by_artifact_hash("b" * 64)

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["payload"]["entryHash"], "entry-hash-123")
        self.assertEqual(len(captured_request), 1)
        req = captured_request[0]
        self.assertEqual(req.method, "GET")
        self.assertIn("payload", req.full_url)
        self.assertIn("artifactHash", req.full_url)
        self.assertIn("eq.", req.full_url)
        self.assertIn("b" * 64, req.full_url)
        header_items = {k.lower(): v for k, v in req.header_items()}
        self.assertEqual(header_items.get("apikey"), "test-key")

    def test_returns_empty_list_when_no_matching_rows(self) -> None:
        """Successful fetch with no matches returns [] (verified empty), not None."""
        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            return _make_response(b"[]")

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            result = adapter.fetch_remote_entries_by_artifact_hash("d" * 64)
        self.assertEqual(result, [])

    def test_returns_none_on_transient_http_5xx(self) -> None:
        """HTTP 502/503/504 return None (transient) for attestation skip."""
        import urllib.error

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            raise urllib.error.HTTPError(
                "https://x", 500, "Internal Server Error", {}, None
            )

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            result = adapter.fetch_remote_entries_by_artifact_hash("c" * 64)
        self.assertIsNone(result)

    def test_returns_none_on_urlerror(self) -> None:
        """URLError (timeout, connection refused) returns None for attestation skip."""
        import urllib.error

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            raise urllib.error.URLError("Connection refused")

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            result = adapter.fetch_remote_entries_by_artifact_hash("e" * 64)
        self.assertIsNone(result)

    def test_raises_on_non_transient_http_error(self) -> None:
        """HTTP 4xx raises RuntimeError (non-transient)."""
        import urllib.error

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            raise urllib.error.HTTPError(
                "https://x", 404, "Not Found", {}, None
            )

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(RuntimeError) as ctx:
                adapter.fetch_remote_entries_by_artifact_hash("c" * 64)
        self.assertIn("Remote transparency log fetch failed", str(ctx.exception))
        self.assertIn("404", str(ctx.exception))

    def test_raises_on_json_decode_error(self) -> None:
        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            return _make_response(b"not valid json")

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(RuntimeError) as ctx:
                adapter.fetch_remote_entries_by_artifact_hash("f" * 64)
        self.assertIn("Remote transparency log fetch failed", str(ctx.exception))
