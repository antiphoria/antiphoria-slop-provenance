"""Schema migration utility for state.db v2 reliability tables."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.repository import SQLiteRepository


def main() -> int:
    parser = argparse.ArgumentParser(prog="migrate-state-v2")
    parser.add_argument(
        "--db-path",
        default="state.db",
        help="Path to SQLite state database.",
    )
    args = parser.parse_args()
    db_path = Path(args.db_path).resolve()
    SQLiteRepository(db_path=db_path)
    print(f"Migration complete for {db_path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
