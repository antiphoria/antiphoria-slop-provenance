#!/usr/bin/env python3
"""Phase-0 probe: recompute the exact signing target for a v2 artifact using the
engine's OWN functions, and print the byte-exact JCS JSON + signing hash.

This proves the path: v2 markdown -> parsed Artifact -> signing-target dict ->
JCS bytes -> SHA-256 hex. The TS port must reproduce `signing_hash` exactly.

Run from the project root:
    .venv/bin/python scripts/probe_signing_target.py <artifact.md> [<artifact2.md> ...]

No verification is performed here — this is pure derivation of the signed bytes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Project root is parent of scripts/. Packages are imported as `src.*` and
# `antiphoria_sdk.*` per pyproject.toml ([tool.setuptools.packages.find]).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from src.env_config import apply_liboqs_env_from_dotenv  # noqa: E402

apply_liboqs_env_from_dotenv()

from src.canonicalization import (  # noqa: E402
    canonicalize_body_for_hash,
    compute_payload_hash,
)
from src.envelope_v2 import parse_artifact_markdown_text_v2  # noqa: E402
from src.models import (  # noqa: E402
    build_envelope_signing_target,
    canonical_json_bytes,
    sha256_hex,
)


def probe(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    artifact, body = parse_artifact_markdown_text_v2(text)

    payload_hash = compute_payload_hash(body)
    canon_body = canonicalize_body_for_hash(body)

    # manifest_hash: SHA-256 of the sibling .c2pa sidecar if present, else None.
    # Mirrors _resolve_manifest_hash_for_artifact (crypto_notary.py:801-807).
    c2pa_sibling = path.with_suffix(".c2pa")
    manifest_hash = sha256_hex(c2pa_sibling.read_bytes()) if c2pa_sibling.exists() else None

    target = build_envelope_signing_target(
        envelope=artifact,
        payload_sha256_hex=payload_hash,
        manifest_sha256_hex=manifest_hash,
        prev_hash=None,
        canonicalization_version=artifact.signature.payload_canonicalization if artifact.signature else None,
    )

    jcs_bytes = canonical_json_bytes(target)
    signing_hash = sha256_hex(jcs_bytes)

    print(f"=== {path.name} ===")
    print(f"artifactId           : {artifact.id}")
    print(f"title                : {artifact.title!r}")
    print(f"declared payloadHash : {artifact.signature.artifact_hash if artifact.signature else '<none>'}")
    print(f"recomputed payload   : {payload_hash}")
    print(f"payload match        : {(artifact.signature.artifact_hash == payload_hash) if artifact.signature else 'n/a'}")
    print(f"manifest hash (.c2pa): {manifest_hash}")
    print(f"canonical body bytes : {len(canon_body)} bytes")
    print(f"canonical body sha256: {hashlib.sha256(canon_body).hexdigest()}")
    print(f"primary fingerprint  : {artifact.signature.verification_anchor.signer_fingerprint if artifact.signature else '<none>'}")
    print(f"hybrid  fingerprint  : {artifact.hybrid_signature.verification_anchor.signer_fingerprint if artifact.hybrid_signature else '<none>'}")
    print(f"signing_hash (64hex) : {signing_hash}")
    print(f"jcs bytes length     : {len(jcs_bytes)}")
    print(f"jcs sha256           : {hashlib.sha256(jcs_bytes).hexdigest()}")
    print()
    print("--- envelope.model_dump (by_alias, exclude_none) ---")
    envelope_dump = artifact.model_dump(mode="json", by_alias=True, exclude_none=True)
    envelope_dump.pop("signature", None)
    envelope_dump.pop("hybridSignature", None)
    print(json.dumps(envelope_dump, indent=2, ensure_ascii=False))
    print()
    print("--- full signing target ---")
    print(json.dumps(target, indent=2, ensure_ascii=False))
    print()
    print("--- JCS-canonical signing target bytes (utf-8 decoded) ---")
    print(jcs_bytes.decode("utf-8"))
    print()


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: probe_signing_target.py <artifact.md> [...]", file=sys.stderr)
        return 2
    for arg in sys.argv[1:]:
        probe(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
