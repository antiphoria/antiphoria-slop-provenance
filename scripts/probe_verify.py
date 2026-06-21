#!/usr/bin/env python3
"""Phase-0 probe: verify the on-disk public keys validate the artifact signatures.

Confirms the keys at keys/public.key and keys/ed25519_public.pem are the ACTIVE
keys matching the fingerprints in the two example artifacts. If this passes, the
golden vectors are end-to-end consistent and the TS port has a complete target.

Run from the project root:
    .venv/bin/python scripts/probe_verify.py <artifact.md>
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from src.env_config import apply_liboqs_env_from_dotenv  # noqa: E402

apply_liboqs_env_from_dotenv()

import oqs  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from src.canonicalization import compute_payload_hash  # noqa: E402
from src.envelope_v2 import parse_artifact_markdown_text_v2  # noqa: E402
from src.models import (  # noqa: E402
    build_envelope_signing_target,
    canonical_json_bytes,
    sha256_hex,
)

_ML_DSA_ALG = "ML-DSA-44"


def _load_mldsa_pub() -> bytes:
    # keys/public.key is raw 1312-byte liboqs public key (no PEM).
    return (_PROJECT_ROOT / "keys" / "public.key").read_bytes()


def _load_ed25519_pub_raw() -> bytes:
    # keys/ed25519_public.pem is SPKI PEM; unwrap to raw 32 bytes.
    pem = (_PROJECT_ROOT / "keys" / "ed25519_public.pem").read_bytes()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit("ed25519_public.pem did not load as Ed25519PublicKey")
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def probe(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    artifact, body = parse_artifact_markdown_text_v2(text)

    payload_hash = compute_payload_hash(body)
    c2pa_sibling = path.with_suffix(".c2pa")
    manifest_hash = sha256_hex(c2pa_sibling.read_bytes()) if c2pa_sibling.exists() else None

    target = build_envelope_signing_target(
        envelope=artifact,
        payload_sha256_hex=payload_hash,
        manifest_sha256_hex=manifest_hash,
        prev_hash=None,
        canonicalization_version=artifact.signature.payload_canonicalization,
    )
    signing_hash = sha256_hex(canonical_json_bytes(target))
    msg = signing_hash.encode("utf-8")

    print(f"=== {path.name} ===")
    print(f"signing_hash : {signing_hash}")
    print(f"payload match: {artifact.signature.artifact_hash == payload_hash}")

    # ML-DSA verify
    mldsa_pub = _load_mldsa_pub()
    mldsa_sig = base64.b64decode("".join(artifact.signature.cryptographic_signature.split()))
    with oqs.Signature(_ML_DSA_ALG) as v:
        mldsa_ok = v.verify(msg, mldsa_sig, mldsa_pub)
    print(f"ML-DSA-44    : pubkey={len(mldsa_pub)}B sig={len(mldsa_sig)}B -> {'VALID' if mldsa_ok else 'INVALID'}")

    # Ed25519 verify
    ed_pub = _load_ed25519_pub_raw()
    ed_sig = base64.b64decode("".join(artifact.hybrid_signature.cryptographic_signature.split()))
    try:
        Ed25519PublicKey.from_public_bytes(ed_pub).verify(ed_sig, msg)
        ed_ok = True
    except Exception:
        ed_ok = False
    print(f"Ed25519      : pubkey={len(ed_pub)}B sig={len(ed_sig)}B -> {'VALID' if ed_ok else 'INVALID'}")
    print()


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: probe_verify.py <artifact.md> [...]", file=sys.stderr)
        return 2
    for arg in sys.argv[1:]:
        probe(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
