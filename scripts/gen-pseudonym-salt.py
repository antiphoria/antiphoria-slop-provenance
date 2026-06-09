#!/usr/bin/env python3
"""Generate a high-entropy operator pseudonym salt for pen-name continuity.

Writes a single-line base64url-encoded 32-byte secret. Store on an encrypted
vault (recommended) and point OPERATOR_PSEUDONYM_SALT_PATH at it.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_OUT = _PROJECT_ROOT / "keys" / "pseudonym.salt"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate operator pseudonym salt (32 random bytes, base64url)."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_DEFAULT_OUT,
        help=(
            "Output path (default: ./keys/pseudonym.salt). "
            "Prefer a vault path such as /Volumes/AntiphoriaVault/pseudonym.salt."
        ),
    )
    args = parser.parse_args()
    out_path: Path = args.out.expanduser().resolve()

    if out_path.exists():
        print(f"Refusing to overwrite existing salt file: '{out_path}'.", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    salt_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    out_path.write_text(f"{salt_b64}\n", encoding="utf-8")
    out_path.chmod(0o600)

    print("Operator pseudonym salt generated successfully.")
    print(f"  Salt file: {out_path}")
    print()
    print("Next steps:")
    print("  1. Move the salt file to your encrypted vault if not already there.")
    print("  2. Set OPERATOR_PSEUDONYM_SALT_PATH in .env to the vault path.")
    print("  3. Never commit the salt or embed it in artifact text.")
    print("  4. Losing the salt breaks cross-artifact continuity; rotate = new identity.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
