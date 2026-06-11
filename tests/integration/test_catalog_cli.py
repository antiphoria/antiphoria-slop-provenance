"""Integration tests for archive catalog upsert and CLI commands."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pygit2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from src import cli
from src.adapters.catalog import CatalogAdapter, collect_catalog_rows_from_repo
from src.domain.events import StoryHumanRegistered, StorySyntheticSealed
from tests.support.stack_test_env import configure_minimal_ceremony_stack_env

_INTEGRATION_DIR = Path(__file__).resolve().parent


def _load_integration_helper(module_name: str, attr: str):
    import importlib.util

    module_path = _INTEGRATION_DIR / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module '{module_name}'.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, attr)


_build_human_story_signed_event = _load_integration_helper(
    "test_register_cli",
    "_build_human_story_signed_event",
)
_build_synthetic_story_signed_event = _load_integration_helper(
    "test_seal_cli",
    "_build_synthetic_story_signed_event",
)


class CatalogCliTest(unittest.IsolatedAsyncioTestCase):
    """Validate catalog upsert on commit and catalog CLI."""

    def setUp(self) -> None:
        self._repo_temp = tempfile.TemporaryDirectory()
        self._repo_path = Path(self._repo_temp.name)
        pygit2.init_repository(str(self._repo_path), initial_head="main")
        self._old_enable_ots = os.getenv("ENABLE_OTS_FORGE")
        self._old_pqc_private_key_path = os.getenv("PQC_PRIVATE_KEY_PATH")
        self._old_ed25519_private_key_path = os.getenv("ED25519_PRIVATE_KEY_PATH")
        self._key_temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        key_dir = Path(self._key_temp.name)
        pqc_private_key_path = key_dir / "pqc-private.key"
        pqc_private_key_path.write_bytes(b"test-private-key-bytes")
        ed25519_private_key = Ed25519PrivateKey.generate()
        ed25519_private_key_path = key_dir / "ed25519-private.pem"
        ed25519_private_key_path.write_bytes(
            ed25519_private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
        os.environ["PQC_PRIVATE_KEY_PATH"] = str(pqc_private_key_path)
        os.environ["ED25519_PRIVATE_KEY_PATH"] = str(ed25519_private_key_path)
        configure_minimal_ceremony_stack_env(key_dir)

    def tearDown(self) -> None:
        if self._old_enable_ots is None:
            os.environ.pop("ENABLE_OTS_FORGE", None)
        else:
            os.environ["ENABLE_OTS_FORGE"] = self._old_enable_ots
        if self._old_pqc_private_key_path is None:
            os.environ.pop("PQC_PRIVATE_KEY_PATH", None)
        else:
            os.environ["PQC_PRIVATE_KEY_PATH"] = self._old_pqc_private_key_path
        if self._old_ed25519_private_key_path is None:
            os.environ.pop("ED25519_PRIVATE_KEY_PATH", None)
        else:
            os.environ["ED25519_PRIVATE_KEY_PATH"] = self._old_ed25519_private_key_path
        self._key_temp.cleanup()
        self._repo_temp.cleanup()

    async def test_register_and_seal_update_catalog_and_index_rebuild(self) -> None:
        human_request_id: UUID | None = None
        seal_request_id: UUID | None = None

        human_markdown = "Human catalog integration body."
        seal_markdown = "Synthetic catalog integration body."

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as human_file:
            human_file.write(human_markdown)
            human_path = Path(human_file.name)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as seal_file:
            seal_file.write(seal_markdown)
            seal_path = Path(seal_file.name)

        try:

            async def _fake_register(self: object, event: StoryHumanRegistered) -> None:
                nonlocal human_request_id
                human_request_id = event.request_id
                signed = _build_human_story_signed_event(
                    request_id=event.request_id,
                    body=event.body,
                    title=event.title,
                    attestation=event.attestation,
                    registration_ceremony=event.registration_ceremony,
                )
                await self._event_bus.emit(signed)

            with patch(
                "src.adapters.crypto_notary.CryptoNotaryAdapter._on_story_human_registered",
                _fake_register,
            ):
                register_args = cli.build_parser().parse_args(
                    [
                        "register",
                        "--file",
                        str(human_path),
                        "--repo-path",
                        str(self._repo_path),
                        "--title",
                        "Human Catalog Entry",
                        "--non-interactive",
                    ]
                )
                self.assertEqual(await cli._run_register_command(register_args), 0)

            async def _fake_seal(self: object, event: StorySyntheticSealed) -> None:
                nonlocal seal_request_id
                seal_request_id = event.request_id
                signed = _build_synthetic_story_signed_event(
                    request_id=event.request_id,
                    body=event.body,
                    title=event.title,
                    models_used=["gemini-3.1-pro"],
                    attestation=event.attestation,
                    registration_ceremony=event.registration_ceremony,
                )
                await self._event_bus.emit(signed)

            with patch(
                "src.adapters.crypto_notary.CryptoNotaryAdapter._on_story_synthetic_sealed",
                _fake_seal,
            ):
                seal_args = cli.build_parser().parse_args(
                    [
                        "seal",
                        "--file",
                        str(seal_path),
                        "--repo-path",
                        str(self._repo_path),
                        "--title",
                        "Synthetic Catalog Entry",
                        "--non-interactive",
                    ]
                )
                self.assertEqual(await cli._run_seal_command(seal_args), 0)

            adapter = CatalogAdapter(repository_path=self._repo_path)
            entries = adapter.read_entries()
            self.assertEqual(len(entries), 2)
            sources = {row["source"] for row in entries}
            self.assertEqual(sources, {"human", "synthetic"})

            list_args = cli.build_parser().parse_args(
                [
                    "catalog",
                    "list",
                    "--repo-path",
                    str(self._repo_path),
                    "--source",
                    "human",
                    "--json",
                ]
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                self.assertEqual(cli._run_catalog_list_command(list_args), 0)
            listed = json.loads(buffer.getvalue())
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["source"], "human")
            self.assertEqual(listed[0]["requestId"], str(human_request_id))

            adapter.rebuild([])
            self.assertEqual(adapter.read_entries(), [])

            index_args = cli.build_parser().parse_args(
                ["catalog", "index", "--repo-path", str(self._repo_path)]
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                self.assertEqual(cli._run_catalog_index_command(index_args), 0)
            self.assertIn("Catalog indexed:", buffer.getvalue())

            rebuilt_rows, skipped = collect_catalog_rows_from_repo(self._repo_path)
            self.assertEqual(skipped, 0)
            self.assertEqual(len(rebuilt_rows), 2)

            show_args = cli.build_parser().parse_args(
                [
                    "catalog",
                    "show",
                    "--repo-path",
                    str(self._repo_path),
                    "--request-id",
                    str(seal_request_id),
                    "--json",
                ]
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                self.assertEqual(cli._run_catalog_show_command(show_args), 0)
            shown = json.loads(buffer.getvalue())
            self.assertEqual(shown["requestId"], str(seal_request_id))
            self.assertEqual(shown["source"], "synthetic")
        finally:
            human_path.unlink(missing_ok=True)
            seal_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
