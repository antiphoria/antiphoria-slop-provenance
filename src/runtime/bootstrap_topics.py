"""Create Kafka topics for the distributed slop pipeline."""

from __future__ import annotations

import argparse
import asyncio

from src.env_config import read_env_optional


TOPICS: tuple[str, ...] = (
    "story.requested",
    "story.generated",
    "story.signed",
    "story.committed",
    "story.curated",
    "story.anchored",
    "story.timestamped",
    "story.audited",
)


async def _bootstrap_topics(bootstrap_servers: str, partitions: int) -> int:
    """Create required primary, retry, and dead-letter topics."""

    try:
        from aiokafka.admin import (  # type: ignore
            AIOKafkaAdminClient,
            NewTopic,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "aiokafka is required to bootstrap topics."
        ) from exc

    admin = AIOKafkaAdminClient(bootstrap_servers=bootstrap_servers)
    await admin.start()
    try:
        new_topics = []
        for topic in TOPICS:
            new_topics.append(
                NewTopic(
                    name=topic,
                    num_partitions=partitions,
                    replication_factor=1,
                )
            )
            new_topics.append(
                NewTopic(
                    name=f"{topic}.retry",
                    num_partitions=partitions,
                    replication_factor=1,
                )
            )
            new_topics.append(
                NewTopic(
                    name=f"{topic}.dlq",
                    num_partitions=partitions,
                    replication_factor=1,
                )
            )
        await admin.create_topics(new_topics, validate_only=False)
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "TopicAlreadyExistsError" not in message:
            raise
    finally:
        await admin.close()
    print(f"Kafka topics ready on {bootstrap_servers}.")
    return 0


def main() -> int:
    """CLI entrypoint for Kafka topic bootstrapping."""

    parser = argparse.ArgumentParser(prog="slop-bootstrap-topics")
    parser.add_argument(
        "--bootstrap-servers",
        default=(
            read_env_optional("KAFKA_BOOTSTRAP_SERVERS")
            or "localhost:9092"
        ),
        help="Kafka bootstrap servers.",
    )
    parser.add_argument(
        "--partitions",
        type=int,
        default=1,
        help="Partition count per topic.",
    )
    args = parser.parse_args()
    if args.partitions <= 0:
        raise RuntimeError("partitions must be a positive integer.")
    return asyncio.run(
        _bootstrap_topics(
            bootstrap_servers=args.bootstrap_servers,
            partitions=args.partitions,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
