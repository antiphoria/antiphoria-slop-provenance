"""Replay tool for dead-letter Kafka topics."""

from __future__ import annotations

import argparse
import asyncio
import json

from src.env_config import read_env_optional


async def _replay(args: argparse.Namespace) -> int:
    try:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("aiokafka is required for DLQ replay.") from exc

    bootstrap_servers = (
        read_env_optional("KAFKA_BOOTSTRAP_SERVERS") or "localhost:9092"
    )
    dlq_topic = f"{args.topic}.dlq"
    consumer = AIOKafkaConsumer(
        dlq_topic,
        bootstrap_servers=bootstrap_servers,
        group_id=f"replay-{args.topic}",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
    )
    producer = AIOKafkaProducer(bootstrap_servers=bootstrap_servers)
    await consumer.start()
    await producer.start()
    replayed = 0
    try:
        async for message in consumer:
            payload = json.loads(message.value.decode("utf-8"))
            original_value = payload["value"].encode("utf-8")
            await producer.send_and_wait(
                args.topic, value=original_value, key=message.key
            )
            replayed += 1
            if replayed >= args.max_messages:
                break
    finally:
        await consumer.stop()
        await producer.stop()
    print(f"Replayed {replayed} messages from {dlq_topic} to {args.topic}.")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="slop-replay-dlq")
    parser.add_argument(
        "--topic", required=True, help="Base topic name to replay into."
    )
    parser.add_argument(
        "--max-messages",
        type=int,
        default=100,
        help="Maximum DLQ messages to replay.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    return asyncio.run(_replay(args))


if __name__ == "__main__":
    raise SystemExit(main())
