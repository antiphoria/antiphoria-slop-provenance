"""Tests for transparency log adapter and Supabase publish."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    _sanitize_for_log,
    build_supabase_publish_config,
    publish_merkle_anchor,
    update_merkle_anchor_block_height,
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

    def test_entry_hash_matches_payload_hash_helper(self) -> None:
        adapter = TransparencyLogAdapter(log_path=self._log_path)

        entry, serializable = adapter.build_entry_record(
            artifact_hash="f" * 64,
            artifact_id="a" * 36,
            source_file="artifact.md",
            previous_entry_hash=None,
            request_id="b" * 36,
            metadata={"source": "human"},
            bitcoin_block_height=123,
            skip_remote=True,
        )
        computed = adapter.compute_expected_entry_hash_from_payload(serializable)
        self.assertEqual(computed, entry.entry_hash)

    def test_payload_hash_helper_normalizes_non_dict_metadata(self) -> None:
        payload = {
            "entryId": "id-1",
            "artifactHash": "a" * 64,
            "artifactId": "artifact-1",
            "requestId": "request-1",
            "sourceFile": "artifact.md",
            "previousEntryHash": None,
            "anchoredAt": "2026-01-01T00:00:00+00:00",
            "metadata": ["unexpected", "shape"],
        }
        normalized = dict(payload)
        normalized["metadata"] = {}

        hash_from_list = TransparencyLogAdapter.compute_expected_entry_hash_from_payload(
            payload
        )
        hash_from_dict = TransparencyLogAdapter.compute_expected_entry_hash_from_payload(
            normalized
        )
        self.assertEqual(hash_from_list, hash_from_dict)

    def test_publish_soft_fails_when_response_exceeds_size_limit(self) -> None:
        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            _ = (request, timeout)
            return _make_response(b"x" * (1_048_576 + 1))

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://example.org/append",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
            publish_supabase_format=False,
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            entry, _ = adapter.build_entry_record(
                artifact_hash="f" * 64,
                artifact_id="a" * 36,
                source_file="artifact.md",
                previous_entry_hash=None,
            )

        self.assertIsNone(entry.remote_receipt)


class BuildSupabaseConfigTest(unittest.TestCase):
    """Validate build_supabase_publish_config."""

    def test_returns_empty_when_no_url(self) -> None:
        headers, use_format = build_supabase_publish_config(None)
        self.assertEqual(headers, {})
        self.assertFalse(use_format)

    def test_raises_when_url_set_but_no_key(self) -> None:
        with patch(
            "src.adapters.transparency_log.read_env_optional",
            return_value=None,
        ), self.assertRaises(RuntimeError) as ctx:
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

    def test_raises_when_publish_url_scheme_is_not_http(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            build_supabase_publish_config("file:///tmp/transparency")
        self.assertIn("http/https", str(ctx.exception))


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
        self.assertIsNone(adapter.fetch_remote_entries_by_artifact_hash("a" * 64))

    def test_returns_none_when_no_headers(self) -> None:
        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={},
        )
        self.assertIsNone(adapter.fetch_remote_entries_by_artifact_hash("a" * 64))

    def test_adapter_init_rejects_non_http_publish_url(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            TransparencyLogAdapter(
                log_path=self._log_path,
                publish_url="file:///tmp/transparency-log",
                publish_headers={"apikey": "x", "Authorization": "Bearer x"},
            )
        self.assertIn("http/https", str(ctx.exception))

    def test_get_sends_correct_url_and_headers(self) -> None:
        captured_request: list[object] = []

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            captured_request.append(request)
            return _make_response(
                json.dumps(
                    [
                        {
                            "id": 42,
                            "payload": {
                                "artifactHash": "b" * 64,
                                "entryHash": "entry-hash-123",
                            },
                            "created_at": "2024-01-01T00:00:00Z",
                        },
                    ]
                ).encode("utf-8")
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

    def test_raises_on_transient_http_5xx(self) -> None:
        """Transient HTTP errors raise (fail-closed) when remote is configured."""
        import urllib.error

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            raise urllib.error.HTTPError("https://x", 500, "Internal Server Error", {}, None)

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )

        with patch("urllib.request.urlopen", fake_urlopen), self.assertRaises(
            RuntimeError
        ) as ctx:
            adapter.fetch_remote_entries_by_artifact_hash("c" * 64)
        self.assertIn("Remote transparency log fetch failed", str(ctx.exception))

    def test_raises_on_urlerror(self) -> None:
        """URLError now raises (fail-closed) when remote is configured."""
        import urllib.error

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            raise urllib.error.URLError("Connection refused")

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", fake_urlopen), self.assertRaises(
            RuntimeError
        ) as ctx:
            adapter.fetch_remote_entries_by_artifact_hash("e" * 64)
        self.assertIn("Remote transparency log fetch failed", str(ctx.exception))

    def test_raises_on_non_transient_http_error(self) -> None:
        """HTTP 4xx raises RuntimeError (non-transient)."""
        import urllib.error

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            raise urllib.error.HTTPError("https://x", 404, "Not Found", {}, None)

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )

        with patch("urllib.request.urlopen", fake_urlopen), self.assertRaises(
            RuntimeError
        ) as ctx:
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
        with patch("urllib.request.urlopen", fake_urlopen), self.assertRaises(
            RuntimeError
        ) as ctx:
            adapter.fetch_remote_entries_by_artifact_hash("f" * 64)
        self.assertIn("Remote transparency log fetch failed", str(ctx.exception))

    def test_raises_when_response_body_exceeds_size_limit(self) -> None:
        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            _ = (request, timeout)
            return _make_response(b"x" * (1_048_576 + 1))

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", fake_urlopen), self.assertRaises(
            RuntimeError
        ) as ctx:
            adapter.fetch_remote_entries_by_artifact_hash("f" * 64)
        self.assertIn("exceeded maximum allowed size", str(ctx.exception))

    def test_fetch_rejects_runtime_invalid_scheme_before_network_call(self) -> None:
        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        adapter._publish_url = "file:///tmp/transparency-log"

        with patch("urllib.request.urlopen") as urlopen_mock, self.assertRaises(
            RuntimeError
        ) as ctx:
            adapter.fetch_remote_entries_by_artifact_hash("f" * 64)

        self.assertIn("http/https", str(ctx.exception))
        urlopen_mock.assert_not_called()


class EntryExistsInRemoteTest(unittest.TestCase):
    """Validate entry_exists_in_remote idempotency check."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self._log_path = Path(self._temp.name) / "transparency-log.jsonl"

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_returns_true_when_entry_hash_matches(self) -> None:
        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            return _make_response(
                json.dumps(
                    [
                        {
                            "payload": {
                                "artifactHash": "a" * 64,
                                "entryHash": "entry-123",
                            },
                        },
                    ]
                ).encode("utf-8")
            )

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            self.assertTrue(adapter.entry_exists_in_remote("entry-123", "a" * 64))

    def test_returns_false_when_no_matching_entry_hash(self) -> None:
        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            return _make_response(
                json.dumps(
                    [
                        {
                            "payload": {
                                "artifactHash": "a" * 64,
                                "entryHash": "other-entry",
                            },
                        },
                    ]
                ).encode("utf-8")
            )

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            self.assertFalse(adapter.entry_exists_in_remote("entry-123", "a" * 64))

    def test_returns_false_when_remote_not_configured(self) -> None:
        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url=None,
            publish_headers={},
        )
        self.assertFalse(adapter.entry_exists_in_remote("entry-123", "a" * 64))


class RepublishEntryIfMissingTest(unittest.TestCase):
    """Validate republish_entry_if_missing idempotent healing."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self._log_path = Path(self._temp.name) / "transparency-log.jsonl"

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_skips_when_entry_already_exists(self) -> None:
        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            return _make_response(
                json.dumps(
                    [
                        {
                            "payload": {
                                "artifactHash": "a" * 64,
                                "entryHash": "entry-123",
                            },
                        },
                    ]
                ).encode("utf-8")
            )

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
            publish_supabase_format=True,
        )
        serializable = {
            "entryHash": "entry-123",
            "artifactHash": "a" * 64,
            "entryId": "id-1",
            "artifactId": "art-1",
            "requestId": "req-1",
            "sourceFile": "x.md",
            "previousEntryHash": None,
            "anchoredAt": "2024-01-01T00:00:00Z",
            "metadata": {},
        }
        with patch("urllib.request.urlopen", fake_urlopen):
            published, msg = adapter.republish_entry_if_missing(serializable)
        self.assertFalse(published)
        self.assertIn("Already present", msg)

    def test_publishes_when_entry_missing(self) -> None:
        call_count = 0

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            nonlocal call_count
            call_count += 1
            if request.method == "GET":
                return _make_response(b"[]")
            return _make_response(b'[{"id": 1}]')

        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url="https://test.supabase.co/rest/v1/transparency_log",
            publish_headers={"apikey": "x", "Authorization": "Bearer x"},
            publish_supabase_format=True,
        )
        serializable = {
            "entryHash": "entry-456",
            "artifactHash": "b" * 64,
            "entryId": "id-2",
            "artifactId": "art-2",
            "requestId": "req-2",
            "sourceFile": "y.md",
            "previousEntryHash": None,
            "anchoredAt": "2024-01-01T00:00:00Z",
            "metadata": {},
        }
        with patch("urllib.request.urlopen", fake_urlopen):
            published, msg = adapter.republish_entry_if_missing(serializable)
        self.assertTrue(published)
        self.assertIn("Published", msg)
        self.assertEqual(call_count, 2)

    def test_returns_false_when_remote_not_configured(self) -> None:
        adapter = TransparencyLogAdapter(
            log_path=self._log_path,
            publish_url=None,
            publish_headers={},
        )
        serializable = {
            "entryHash": "entry-789",
            "artifactHash": "c" * 64,
        }
        published, msg = adapter.republish_entry_if_missing(serializable)
        self.assertFalse(published)
        self.assertIn("not configured", msg)


class TransparencyLogSanitizerTest(unittest.TestCase):
    """Validate secret redaction helper for log safety."""

    def test_sanitizes_bearer_token_value(self) -> None:
        redacted = _sanitize_for_log("Authorization: Bearer sk-secret-token")
        self.assertNotIn("sk-secret-token", redacted)
        self.assertNotIn("Bearer sk-secret-token", redacted)
        self.assertIn("***", redacted)


class MerkleAnchorPatchUrlEncodingTest(unittest.TestCase):
    """Validate row_id is URL-encoded in PATCH filter."""

    def test_patch_url_encodes_row_id(self) -> None:
        captured_requests: list[object] = []

        def fake_urlopen(request: object, timeout: float = 10.0) -> object:
            _ = timeout
            captured_requests.append(request)
            if getattr(request, "method", "GET") == "GET":
                body = json.dumps(
                    [
                        {
                            "id": "1&payload->>entryHash=eq.tampered",
                            "payload": {
                                "rootHash": "abc",
                                "entryCount": 1,
                                "anchoredAt": "2024-01-01T00:00:00Z",
                            },
                        }
                    ]
                ).encode("utf-8")
                return _make_response(body)
            return _make_response(b"{}")

        with patch("urllib.request.urlopen", fake_urlopen):
            ok = update_merkle_anchor_block_height(
                root_hash="abc",
                bitcoin_block_height=123,
                publish_url="https://test.supabase.co/rest/v1/merkle_anchors",
                publish_headers={"apikey": "k", "Authorization": "Bearer k"},
            )
        self.assertTrue(ok)
        self.assertGreaterEqual(len(captured_requests), 2)
        patch_request = captured_requests[1]
        patch_url = patch_request.full_url
        self.assertIn("id=eq.1%26payload-%3E%3EentryHash%3Deq.tampered", patch_url)
        self.assertNotIn("&payload->>entryHash=eq.tampered", patch_url)

    def test_publish_soft_fails_when_http_error_body_exceeds_size_limit(self) -> None:
        oversized_error = urllib.error.HTTPError(
            url="https://test.supabase.co/rest/v1/merkle_anchors",
            code=500,
            msg="Internal Server Error",
            hdrs=None,
            fp=io.BytesIO(b"x" * (1_048_576 + 1)),
        )

        with patch("urllib.request.urlopen", side_effect=oversized_error):
            ok = publish_merkle_anchor(
                root_hash="a" * 64,
                entry_count=1,
                anchored_at="2026-01-01T00:00:00+00:00",
                publish_url="https://test.supabase.co/rest/v1/merkle_anchors",
                publish_headers={"apikey": "k", "Authorization": "Bearer k"},
            )
        self.assertFalse(ok)

    def test_publish_rejects_invalid_scheme_without_network_call(self) -> None:
        with patch("urllib.request.urlopen") as urlopen_mock:
            ok = publish_merkle_anchor(
                root_hash="a" * 64,
                entry_count=1,
                anchored_at="2026-01-01T00:00:00+00:00",
                publish_url="file:///tmp/anchors",
                publish_headers={"apikey": "k", "Authorization": "Bearer k"},
            )
        self.assertFalse(ok)
        urlopen_mock.assert_not_called()

    def test_update_rejects_invalid_scheme_without_network_call(self) -> None:
        with patch("urllib.request.urlopen") as urlopen_mock:
            ok = update_merkle_anchor_block_height(
                root_hash="abc",
                bitcoin_block_height=123,
                publish_url="file:///tmp/anchors",
                publish_headers={"apikey": "k", "Authorization": "Bearer k"},
            )
        self.assertFalse(ok)
        urlopen_mock.assert_not_called()
