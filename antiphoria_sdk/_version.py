"""Single source of truth for the SDK version.

The version comes from installed package metadata (PEP 621 ``pyproject.toml``).
Running from a source tree without ``pip install -e .`` falls back to a
sentinel that makes the situation obvious in chain records.
"""

from __future__ import annotations

try:
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("antiphoria-slop-provenance")
    except PackageNotFoundError:  # pragma: no cover
        __version__ = "0.0.0+unknown"
except ImportError:  # pragma: no cover
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
