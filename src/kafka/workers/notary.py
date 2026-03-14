"""Kafka worker entrypoint for notary adapter."""

from __future__ import annotations

import asyncio

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.key_registry import KeyRegistryAdapter
from src.env_config import read_env_optional
from src.events import StorySigned
from src.kafka.runtime import build_kafka_bus
from src.runtime.service_runtime import (
    build_repository,
    configure_logging,
    run_until_cancelled,
)


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("notary-service")
    await bus.start()
    repository = build_repository()
    key_registry = KeyRegistryAdapter(repository=repository)

    async def _record_signed(event: StorySigned) -> None:
        if event.artifact.signature is None:
            raise RuntimeError("Signed artifact is missing signature block.")
        existing = await asyncio.to_thread(
            repository.get_artifact_record,
            event.request_id,
        )
        if existing is None:
            await asyncio.to_thread(
                repository.create_artifact_record,
                event.request_id,
                "signed",
                event.artifact,
                event.artifact.provenance.generation_context.prompt,
                event.body,
                event.artifact.provenance.model_id,
            )
        elif event.artifact.curation is not None:
            await asyncio.to_thread(
                repository.update_artifact_curation,
                event.request_id,
                event.body,
                event.artifact.signature.artifact_hash,
                event.artifact.signature.cryptographic_signature,
            )
        else:
            await asyncio.to_thread(
                repository.update_artifact_status,
                event.request_id,
                "signed",
            )

        await asyncio.to_thread(
            key_registry.register_key,
            event.artifact.signature.verification_anchor.signer_fingerprint,
            read_env_optional("SIGNING_KEY_VERSION"),
            "active",
            None,
        )

    await bus.subscribe(StorySigned, _record_signed)
    adapter = CryptoNotaryAdapter(event_bus=bus)
    await adapter.start()
    await run_until_cancelled("notary-service")


def main() -> int:
    """Run notary worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
