#!/usr/bin/env python3
"""Generate ML-DSA-44 keypair for Slop Orchestrator.

Writes keys/private.key and keys/public.key (raw bytes).
Run from project root or via: python scripts/gen-mldsa-keys.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Project root = parent of scripts/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_KEYS_DIR = _PROJECT_ROOT / "keys"
_ALGORITHM = "ML-DSA-44"


def main() -> int:
    import oqs

    _KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_path = _KEYS_DIR / "private.key"
    public_path = _KEYS_DIR / "public.key"

    with oqs.Signature(_ALGORITHM) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()

    private_path.write_bytes(secret_key)
    public_path.write_bytes(public_key)

    print("ML-DSA keys generated successfully.")
    print(f"  Private key: {private_path}")
    print(f"  Public key:  {public_path}")
    print()
    print("Next steps (BYOV):")
    print("  1. Run gen-c2pa-keys.ps1 (Windows) or gen-c2pa-keys.sh (Linux)")
    print("  2. Move c2pa-root-ca.key.pem to offline USB")
    print("  3. Create vault with private.key and c2pa-private-key.pem")
    print("  4. SECURE CLEANUP: Delete the plaintext private keys from the keys/ directory!")
    print("  5. Use scripts/run-secure.ps1 or scripts/run-secure.sh to run the app")
    return 0


if __name__ == "__main__":
    sys.exit(main())
