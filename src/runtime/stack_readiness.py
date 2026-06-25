"""Pre-ceremony checks for full-stack register/seal pipelines."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.adapters.ots_adapter import resolve_ots_binary
from src.env_config import read_env_bool, read_env_optional
from src.webauthn_attestation import _CREDENTIALS_FILE, _get_credentials_path


@dataclass(frozen=True)
class StackCheckResult:
    name: str
    ok: bool
    message: str


def _resolve_env_path(env_path: Path, raw: str | None) -> Path | None:
    if raw is None or not raw.strip():
        return None
    path = Path(raw.strip())
    if not path.is_absolute():
        path = (env_path.parent / path).resolve()
    return path


def _check_signing_keys(env_path: Path) -> StackCheckResult:
    missing: list[str] = []
    for env_key in ("PQC_PRIVATE_KEY_PATH", "OQS_PRIVATE_KEY_PATH"):
        raw = read_env_optional(env_key, env_path=env_path)
        if raw:
            key_path = _resolve_env_path(env_path, raw)
            if key_path is None or not key_path.is_file():
                missing.append(f"{env_key} -> '{raw}' not found")
            break
    else:
        missing.append("PQC_PRIVATE_KEY_PATH or OQS_PRIVATE_KEY_PATH")

    ed25519_raw = read_env_optional("ED25519_PRIVATE_KEY_PATH", env_path=env_path)
    if not ed25519_raw:
        missing.append("ED25519_PRIVATE_KEY_PATH")
    else:
        ed25519_path = _resolve_env_path(env_path, ed25519_raw)
        if ed25519_path is None or not ed25519_path.is_file():
            missing.append(f"ED25519_PRIVATE_KEY_PATH -> '{ed25519_raw}' not found")

    if missing:
        return StackCheckResult(
            name="signing_keys",
            ok=False,
            message="Missing or unreadable signing keys: " + "; ".join(missing),
        )
    return StackCheckResult(name="signing_keys", ok=True, message="Vault signing keys present")


def _check_webauthn(
    env_path: Path,
    repository_path: Path,
    *,
    require_webauthn: bool,
) -> StackCheckResult:
    if not require_webauthn:
        return StackCheckResult(
            name="webauthn",
            ok=True,
            message="WebAuthn skipped (--no-webauthn)",
        )
    rp_id = read_env_optional("WEBAUTHN_RP_ID", env_path=env_path)
    if not rp_id or not rp_id.strip():
        return StackCheckResult(
            name="webauthn",
            ok=False,
            message=(
                "WEBAUTHN_RP_ID is unset. Set WEBAUTHN_RP_ID=localhost for Touch ID "
                "or run: slop-cli webauthn-register"
            ),
        )
    cred_path = _get_credentials_path(env_path=env_path, repo_path=repository_path)
    if not cred_path.is_file():
        state_dir = cred_path.parent
        return StackCheckResult(
            name="webauthn",
            ok=False,
            message=(
                f"No WebAuthn credentials at '{cred_path.name}'. Run: "
                f"slop-cli webauthn-register (stores under {state_dir})"
            ),
        )
    return StackCheckResult(
        name="webauthn",
        ok=True,
        message=f"WebAuthn credentials present ({_CREDENTIALS_FILE})",
    )


def _check_ots(env_path: Path) -> StackCheckResult:
    if not read_env_bool("ENABLE_OTS_FORGE", default=True, env_path=env_path):
        return StackCheckResult(
            name="ots",
            ok=True,
            message="OTS disabled (ENABLE_OTS_FORGE=false)",
        )
    try:
        ots_bin = resolve_ots_binary(env_path=env_path)
    except (FileNotFoundError, RuntimeError) as exc:
        return StackCheckResult(name="ots", ok=False, message=str(exc))
    return StackCheckResult(name="ots", ok=True, message=f"OTS binary: {ots_bin}")


def _check_tsa(env_path: Path) -> StackCheckResult:
    tsa_url = read_env_optional("RFC3161_TSA_URL", env_path=env_path)
    if not tsa_url or not tsa_url.strip():
        return StackCheckResult(
            name="rfc3161",
            ok=False,
            message="RFC3161_TSA_URL is unset",
        )
    ca_raw = read_env_optional("RFC3161_CA_CERT_PATH", env_path=env_path)
    if not ca_raw:
        return StackCheckResult(
            name="rfc3161",
            ok=False,
            message="RFC3161_CA_CERT_PATH is unset",
        )
    ca_path = _resolve_env_path(env_path, ca_raw)
    if ca_path is None or not ca_path.is_file():
        return StackCheckResult(
            name="rfc3161",
            ok=False,
            message=f"RFC3161 CA cert not found: '{ca_raw}'",
        )
    return StackCheckResult(
        name="rfc3161",
        ok=True,
        message=f"RFC3161 TSA configured ({tsa_url})",
    )


def _check_c2pa(env_path: Path) -> StackCheckResult:
    if not read_env_bool("ENABLE_C2PA", default=True, env_path=env_path):
        return StackCheckResult(
            name="c2pa",
            ok=True,
            message="C2PA disabled (ENABLE_C2PA=false)",
        )
    missing: list[str] = []
    for env_key in ("C2PA_SIGN_CERT_CHAIN_PATH", "C2PA_PRIVATE_KEY_PATH"):
        raw = read_env_optional(env_key, env_path=env_path)
        if not raw:
            missing.append(env_key)
            continue
        path = _resolve_env_path(env_path, raw)
        if path is None or not path.is_file():
            missing.append(f"{env_key} -> '{raw}' not found")
    if missing:
        return StackCheckResult(
            name="c2pa",
            ok=False,
            message="C2PA enabled but material missing: " + "; ".join(missing),
        )
    return StackCheckResult(name="c2pa", ok=True, message="C2PA enabled (mode=sdk)")


def check_ceremony_stack(
    *,
    env_path: Path,
    repository_path: Path,
    require_webauthn: bool = True,
) -> list[StackCheckResult]:
    """Run all stack readiness checks for register/seal."""

    return [
        _check_signing_keys(env_path),
        _check_webauthn(env_path, repository_path, require_webauthn=require_webauthn),
        _check_ots(env_path),
        _check_tsa(env_path),
        _check_c2pa(env_path),
    ]


def assert_ceremony_stack_ready(
    *,
    env_path: Path,
    repository_path: Path,
    require_webauthn: bool = True,
) -> None:
    """Print checklist and raise RuntimeError when any required layer is missing."""

    results = check_ceremony_stack(
        env_path=env_path,
        repository_path=repository_path,
        require_webauthn=require_webauthn,
    )
    print("\n" + "=" * 50)
    print("FULL-STACK READINESS CHECK")
    print("=" * 50)
    failures: list[str] = []
    for result in results:
        status = "OK" if result.ok else "FAIL"
        print(f"  [{status}] {result.name}: {result.message}")
        if not result.ok:
            failures.append(f"{result.name}: {result.message}")
    print("=" * 50 + "\n")
    if failures:
        raise RuntimeError(
            "Ceremony stack not ready. Fix the failures above before continuing.\n"
            + "\n".join(f"  - {item}" for item in failures)
        )
