"""Module entry point for python -m scripts.gen_mldsa_keys."""

from pathlib import Path

import runpy


def __main__() -> None:
    runpy.run_path(
        Path(__file__).parent / "gen-mldsa-keys.py",
        run_name="__main__",
    )


if __name__ == "__main__":
    __main__()
