"""Tests for env configuration helpers and CLI defaults."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.cli import build_parser
from src.env_config import read_env_bool, read_env_choice, read_env_optional


class EnvConfigTest(unittest.TestCase):
    """Validate .env fallback and parser wiring."""

    def test_read_env_optional_uses_dotenv_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            env_file = temp_path / ".env"
            env_file.write_text(
                "GENERATOR_MODEL_ID=gemini-test-model\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                value = read_env_optional(
                    "GENERATOR_MODEL_ID",
                    env_path=env_file,
                )
        self.assertEqual(value, "gemini-test-model")

    def test_read_env_bool_parses_common_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            env_file = temp_path / ".env"
            env_file.write_text("ENABLE_C2PA=true\n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                enabled = read_env_bool(
                    "ENABLE_C2PA",
                    default=False,
                    env_path=env_file,
                )
        self.assertTrue(enabled)

    def test_generate_parser_uses_generator_model_env_default(self) -> None:
        with patch.dict(os.environ, {"GENERATOR_MODEL_ID": "gemini-via-env"}):
            parser = build_parser()
            args = parser.parse_args(
                [
                    "generate",
                    "--prompt",
                    "x",
                    "--repo-path",
                    "../repo",
                ]
            )
        self.assertEqual(args.model_id, "gemini-via-env")

    def test_read_env_choice_normalizes_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            env_file = temp_path / ".env"
            env_file.write_text("C2PA_MODE=SDK\n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                mode = read_env_choice(
                    "C2PA_MODE",
                    allowed_values=("mvp", "sdk"),
                    default="mvp",
                    env_path=env_file,
                )
        self.assertEqual(mode, "sdk")

    def test_read_env_choice_raises_for_invalid_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            env_file = temp_path / ".env"
            env_file.write_text("C2PA_MODE=broken\n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(RuntimeError):
                    read_env_choice(
                        "C2PA_MODE",
                        allowed_values=("mvp", "sdk"),
                        default="mvp",
                        env_path=env_file,
                    )


if __name__ == "__main__":
    unittest.main()
