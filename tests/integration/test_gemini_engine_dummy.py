"""Tests for Gemini adapter dummy-generation mode."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.adapters.gemini_engine import GeminiEngineAdapter
from src.events import InMemoryEventBus, StoryGenerated, StoryRequested


class GeminiEngineDummyModeTest(unittest.IsolatedAsyncioTestCase):
    """Validate quota-free dummy mode behavior and validation."""

    async def test_dummy_mode_emits_story_generated_without_api_key(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(
                "GENERATOR_DUMMY_MODE=true\nGENERATOR_DUMMY_DELAY_SEC=0\n",
                encoding="utf-8",
            )
            event_bus = InMemoryEventBus()
            adapter = GeminiEngineAdapter(
                event_bus=event_bus,
                model_id="gemini-2.5-flash",
                env_path=env_path,
            )
            received: list[StoryGenerated] = []

            async def _capture(event: StoryGenerated) -> None:
                received.append(event)

            await event_bus.subscribe(StoryGenerated, _capture)
            await adapter.start()

            requested = StoryRequested(prompt="quota-safe prompt")
            await event_bus.emit(requested)
            await event_bus.drain()

            self.assertEqual(len(received), 1)
            generated = received[0]
            self.assertEqual(generated.request_id, requested.request_id)
            self.assertEqual(generated.model_id, "gemini-2.5-flash")
            self.assertIn("# DUMMY INCIDENT", generated.body)
            self.assertIn("Prompt was: quota-safe prompt", generated.body)
            self.assertEqual(generated.usage_metrics.prompt_tokens, 2)
            self.assertGreater(generated.usage_metrics.completion_tokens, 0)

    def test_dummy_delay_must_be_numeric(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(
                "GENERATOR_DUMMY_MODE=true\nGENERATOR_DUMMY_DELAY_SEC=not-a-number\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "must be numeric"):
                _ = GeminiEngineAdapter(
                    event_bus=InMemoryEventBus(),
                    env_path=env_path,
                )

    def test_non_dummy_mode_still_requires_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(
                "GENERATOR_DUMMY_MODE=false\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "Missing required environment variable 'GOOGLE_API_KEY'",
                ):
                    _ = GeminiEngineAdapter(
                        event_bus=InMemoryEventBus(),
                        env_path=env_path,
                    )


if __name__ == "__main__":
    unittest.main()
