"""antiphoria_sdk: offline-first seal-chain provenance SDK.

Minimal usage:

    from antiphoria_sdk import (
        SealEngine,
        StepType,
        HybridSigner,
        HybridVerifier,
        generate_ephemeral_keys,
    )

    keys = generate_ephemeral_keys()  # tests only
    signer = HybridSigner(keys)
    verifier = HybridVerifier({keys.fingerprint: keys})

    engine = SealEngine.create(workspace, run_id="...", signer=signer, verifier=verifier)
    await engine.begin_chain(research_brief={"title": "..."})
    await engine.seal(
        step_type=StepType.PRE_GENERATOR,
        content_file_paths=["steps/0001_pre_generator/intent.json"],
        metadata={"prompt_hash": "..."},
    )
    report = await engine.verify_chain()
    assert report.chain_intact

Chain JSON records are separate from ``src`` markdown artifact format. To bridge
signing material to this repo's CLI keys, see docs/bridging-existing-lib.md.
"""

from __future__ import annotations

from antiphoria_sdk._version import __version__
from antiphoria_sdk.chain import (
    ChainError,
    ChainSequenceError,
    SealEngine,
    verify_chain,
)
from antiphoria_sdk.signing import (
    HybridKeys,
    HybridSigner,
    HybridVerifier,
    Signer,
    Verifier,
    generate_ephemeral_keys,
    load_keys_from_env,
)
from antiphoria_sdk.types import (
    ChainRecord,
    GenesisReceipt,
    SealReceipt,
    Signature,
    StepType,
    StepVerification,
    VerificationReport,
)

__all__ = [
    "__version__",
    "ChainRecord",
    "GenesisReceipt",
    "SealReceipt",
    "Signature",
    "StepType",
    "StepVerification",
    "VerificationReport",
    "ChainError",
    "ChainSequenceError",
    "SealEngine",
    "verify_chain",
    "HybridKeys",
    "HybridSigner",
    "HybridVerifier",
    "Signer",
    "Verifier",
    "generate_ephemeral_keys",
    "load_keys_from_env",
]
