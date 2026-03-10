"""Google Gemini adapter for asynchronous text generation.

This adapter subscribes to `StoryRequested`, executes generation against
Google AI Studio, and emits `StoryGenerated` back into the event bus.
"""

from __future__ import annotations

import asyncio
from typing import Any
from pathlib import Path

from src.env_config import read_env_bool, read_env_optional, read_env_required
from src.events import EventBusPort, StoryGenerated, StoryRequested
from src.models import EmbeddedWatermark, UsageMetrics
from src.policies.licensing import get_license_id

_DEFAULT_MODEL_ID = "gemini-2.5-flash"
_DEFAULT_SYSTEM_INSTRUCTION = "You are a brutalist AI archivist."
_DEFAULT_TEMPERATURE = 0.7
_DEFAULT_TOP_P = 0.95
_DEFAULT_TOP_K = 40
_DEFAULT_CONTENT_TYPE = "text/markdown"
_DUMMY_MODE_ENV = "GENERATOR_DUMMY_MODE"
_DUMMY_DELAY_ENV = "GENERATOR_DUMMY_DELAY_SEC"
_DEFAULT_DUMMY_DELAY_SEC = 1.0


class GeminiEngineAdapter:
    """Event-driven Google AI Studio adapter.

    Attributes:
        event_bus: Shared asynchronous event bus instance.
        model_id: Google model identifier used for generation.
    """

    def __init__(
        self,
        event_bus: EventBusPort,
        model_id: str = _DEFAULT_MODEL_ID,
        env_path: Path | None = None,
    ) -> None:
        """Initialize adapter and configure Google API client.

        Args:
            event_bus: Event bus used for subscriptions and emissions.
            model_id: Google generation model identifier.
            env_path: Optional absolute path to a `.env` file.
        """

        self._event_bus = event_bus
        self._model_id = model_id
        self._env_path = env_path or Path(".env")
        self._dummy_mode = read_env_bool(
            _DUMMY_MODE_ENV,
            default=False,
            env_path=self._env_path,
        )
        self._dummy_delay_sec = self._read_dummy_delay_seconds()
        self._client: Any | None = None

        if not self._dummy_mode:
            api_key = read_env_required("GOOGLE_API_KEY", env_path=self._env_path)
            try:
                from google import genai
            except ImportError as exc:
                raise RuntimeError(
                    "google-genai is required for non-dummy generation mode."
                ) from exc
            self._client = genai.Client(api_key=api_key)

    async def start(self) -> None:
        """Subscribe to story request events."""

        await self._event_bus.subscribe(
            StoryRequested, self._on_story_requested
        )

    async def _on_story_requested(self, event: StoryRequested) -> None:
        """Generate text and emit `StoryGenerated`.

        Args:
            event: Input generation request event.
        """

        generated_text = await self._generate_text(event.prompt)
        prompt_tokens = len(event.prompt.split())
        completion_tokens = len(generated_text.split())

        title = self._derive_title(generated_text)
        await self._event_bus.emit(
            StoryGenerated(
                request_id=event.request_id,
                prompt=event.prompt,
                title=title,
                body=generated_text,
                model_id=self._model_id,
                system_instruction=_DEFAULT_SYSTEM_INSTRUCTION,
                temperature=_DEFAULT_TEMPERATURE,
                top_p=_DEFAULT_TOP_P,
                top_k=_DEFAULT_TOP_K,
                content_type=_DEFAULT_CONTENT_TYPE,
                license=get_license_id("synthetic"),
                usage_metrics=UsageMetrics(
                    promptTokens=prompt_tokens,
                    completionTokens=completion_tokens,
                    totalTokens=prompt_tokens + completion_tokens,
                ),
                embedded_watermark=EmbeddedWatermark(
                    provider="SynthID",
                    status="unknown",
                ),
            )
        )

    async def _generate_text(self, prompt: str) -> str:
        """Generate text from Gemini or dummy local generator."""

        if self._dummy_mode:
            await asyncio.sleep(self._dummy_delay_sec)
            return self._build_dummy_text(prompt)

        if self._client is None:
            raise RuntimeError("Gemini client is not initialized.")
        response = await asyncio.to_thread(
            self._client.models.generate_content,
            model=self._model_id,
            contents=prompt,
        )
        return self._extract_generated_text(response)

    @staticmethod
    def _build_dummy_text(prompt: str) -> str:
        """Build deterministic local text for quota-free pipeline tests."""

        return (
            "# DUMMY INCIDENT\n\n"
            "This is a local test artifact generated without external API calls.\n\n"
            f"Prompt was: {prompt}"
        )

    def _read_dummy_delay_seconds(self) -> float:
        """Resolve optional dummy generation delay in seconds."""

        raw_value = read_env_optional(_DUMMY_DELAY_ENV, env_path=self._env_path)
        if raw_value is None:
            return _DEFAULT_DUMMY_DELAY_SEC
        try:
            delay = float(raw_value)
        except ValueError as exc:
            raise RuntimeError(
                f"Environment variable '{_DUMMY_DELAY_ENV}' must be numeric."
            ) from exc
        if delay < 0:
            raise RuntimeError(
                f"Environment variable '{_DUMMY_DELAY_ENV}' must be >= 0."
            )
        return delay

    @staticmethod
    def _derive_title(body: str) -> str:
        """Derive a deterministic title from generated text.

        Args:
            body: Generated body content.

        Returns:
            Uppercase frontmatter title string.
        """

        first_line = body.strip().splitlines()[0].strip()
        candidate = first_line.strip("# ").strip()
        if not candidate:
            return "INCIDENT_UNTITLED"
        normalized = "_".join(candidate.split())[:80]
        return f"INCIDENT_{normalized.upper()}"

    @staticmethod
    def _extract_generated_text(response: object) -> str:
        """Extract textual content from Google GenAI response objects."""

        text = getattr(response, "text", None)
        if isinstance(text, str) and text.strip():
            return text.strip()

        parts: list[str] = []
        candidates = getattr(response, "candidates", None)
        if isinstance(candidates, list):
            for candidate in candidates:
                content = getattr(candidate, "content", None)
                content_parts = getattr(content, "parts", None)
                if not isinstance(content_parts, list):
                    continue
                for part in content_parts:
                    part_text = getattr(part, "text", None)
                    if isinstance(part_text, str) and part_text.strip():
                        parts.append(part_text.strip())

        if parts:
            return "\n".join(parts).strip()
        raise RuntimeError("Gemini returned an empty response payload.")
