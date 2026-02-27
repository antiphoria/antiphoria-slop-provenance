"""Tests for processed message deduplication persistence."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from src.repository import SQLiteRepository


class RepositoryDedupeTest(unittest.TestCase):
    """Validate idempotent message-marking behavior."""

    def test_try_mark_message_processed(self) -> None:
        fd, raw_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_path = Path(raw_path)
        repository = SQLiteRepository(db_path=db_path)
        first = repository.try_mark_message_processed(
            message_id="abc",
            consumer_name="ledger-service",
        )
        second = repository.try_mark_message_processed(
            message_id="abc",
            consumer_name="ledger-service",
        )
        self.assertTrue(first)
        self.assertFalse(second)


if __name__ == "__main__":
    unittest.main()
