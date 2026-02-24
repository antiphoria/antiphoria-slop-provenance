"""Google Gemini adapter for asynchronous text generation.

This adapter subscribes to `StoryRequested`, executes generation against
Google AI Studio, and emits `StoryGenerated` back into the event bus.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import google.generativeai as genai

from src.events import EventBus, StoryGenerated, StoryRequested
from src.models import EmbeddedWatermark, UsageMetrics

_DEFAULT_MODEL_ID = "gemini-2.5-flash"
_DEFAULT_SYSTEM_INSTRUCTION = "You are a brutalist AI archivist."
_DEFAULT_TEMPERATURE = 0.7
_DEFAULT_TOP_P = 0.95
_DEFAULT_TOP_K = 40
_DEFAULT_CONTENT_TYPE = "text/markdown"
_DEFAULT_LICENSE = "Antinomie-Hybrid-Proprietary"


def _read_env_value(env_key: str, env_path: Path) -> str:
    """Read a key from process environment or local `.env` file.

    Args:
        env_key: Environment variable name to resolve.
        env_path: Absolute path to the `.env` file.

    Returns:
        The resolved string value.

    Raises:
        RuntimeError: If the value cannot be resolved.
    """

    from os import getenv

    direct = getenv(env_key)
    if direct:
        return direct

    if not env_path.exists():
        raise RuntimeError(
            f"Missing required environment variable '{env_key}' and missing "
            f"env file at '{env_path}'."
        )

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == env_key:
            parsed = value.strip().strip("'\"")
            if parsed:
                return parsed
            raise RuntimeError(f"Environment key '{env_key}' is empty in .env.")

    raise RuntimeError(f"Missing required environment variable '{env_key}'.")


class GeminiEngineAdapter:
    """Event-driven Google AI Studio adapter.

    Attributes:
        event_bus: Shared asynchronous event bus instance.
        model_id: Google model identifier used for generation.
    """

    def __init__(
        self,
        event_bus: EventBus,
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

        api_key = _read_env_value("GOOGLE_API_KEY", self._env_path)
        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel(self._model_id)

    async def start(self) -> None:
        """Subscribe to story request events."""

        await self._event_bus.subscribe(StoryRequested, self._on_story_requested)

    async def _on_story_requested(self, event: StoryRequested) -> None:
        """Generate text and emit `StoryGenerated`.

        Args:
            event: Input generation request event.
        """

        response = await asyncio.to_thread(self._model.generate_content, event.prompt)

        generated_text = getattr(response, "text", None)
        if not generated_text or not generated_text.strip():
            raise RuntimeError("Gemini returned an empty response payload.")

        title = self._derive_title(generated_text)
        await self._event_bus.emit(
            StoryGenerated(
                request_id=event.request_id,
                prompt=event.prompt,
                title=title,
                body=generated_text.strip(),
                model_id=self._model_id,
                system_instruction=_DEFAULT_SYSTEM_INSTRUCTION,
                temperature=_DEFAULT_TEMPERATURE,
                top_p=_DEFAULT_TOP_P,
                top_k=_DEFAULT_TOP_K,
                content_type=_DEFAULT_CONTENT_TYPE,
                license=_DEFAULT_LICENSE,
                usage_metrics=UsageMetrics(
                    promptTokens=len(event.prompt.split()),
                    completionTokens=len(generated_text.split()),
                    totalTokens=len(event.prompt.split()) + len(generated_text.split()),
                ),
                embedded_watermark=EmbeddedWatermark(
                    provider="SynthID",
                    status="unknown",
                ),
            )
        )

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
