#!/usr/bin/env python3
"""Generate Ed25519 keypair for Slop Orchestrator hybrid signing.

Writes keys/ed25519_private.pem and keys/ed25519_public.pem (PEM format).
Run from project root or via: python scripts/gen-ed25519-keys.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Project root = parent of scripts/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_KEYS_DIR = _PROJECT_ROOT / "keys"


def main() -> int:
    _KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_path = _KEYS_DIR / "ed25519_private.pem"
    public_path = _KEYS_DIR / "ed25519_public.pem"

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    print("Ed25519 keys generated successfully.")
    print(f"  Private key: {private_path}")
    print(f"  Public key:  {public_path}")
    print()
    print("Next steps (BYOV):")
    print("  1. Copy ed25519_private.pem to vault at K:\\ed25519_private.pem")
    print("  2. Add ED25519_PUBLIC_KEY_PATH=./keys/ed25519_public.pem to .env")
    print("  3. SECURE CLEANUP: Delete keys/ed25519_private.pem from disk!")
    print("  4. Use run-secure.ps1 or run-secure.sh to run the app")
    return 0


if __name__ == "__main__":
    sys.exit(main())
