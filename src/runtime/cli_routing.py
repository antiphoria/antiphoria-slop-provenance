"""Reusable command-routing helpers for CLI dispatch."""

from __future__ import annotations

import argparse
from collections.abc import Awaitable, Callable

AsyncCommandHandler = Callable[[argparse.Namespace], Awaitable[int]]
SyncCommandHandler = Callable[[argparse.Namespace], int]


async def dispatch_command(
    args: argparse.Namespace,
    async_handlers: dict[str, AsyncCommandHandler],
    sync_handlers: dict[str, SyncCommandHandler],
    admin_handlers: dict[str, SyncCommandHandler],
) -> int:
    """Dispatch one parsed command using handler maps."""

    async_handler = async_handlers.get(args.command)
    if async_handler is not None:
        return await async_handler(args)
    sync_handler = sync_handlers.get(args.command)
    if sync_handler is not None:
        return sync_handler(args)
    if args.command == "admin":
        admin_handler = admin_handlers.get(args.admin_command)
        if admin_handler is None:
            raise RuntimeError(
                f"Unsupported admin command: {args.admin_command}"
            )
        return admin_handler(args)
    raise RuntimeError(f"Unsupported command: {args.command}")
