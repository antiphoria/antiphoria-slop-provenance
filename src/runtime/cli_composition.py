"""Composition helpers shared by CLI entrypoints and workers."""

from __future__ import annotations

from pathlib import Path

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.ots_adapter import OTSAdapter, resolve_ots_binary
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    build_supabase_publish_config,
)
from src.env_config import (
    get_project_env_path,
    read_env_bool,
    read_env_optional,
    resolve_artifact_db_path,
)
from src.events import EventBus
from src.repository import SQLiteRepository
from src.services.provenance_service import ProvenanceService
from src.services.verification_service import VerificationService


def build_repository(env_path: Path | None = None) -> SQLiteRepository:
    """Build SQLite repository for shared artifact lifecycle state."""

    resolved_env = env_path or get_project_env_path()
    project_root = resolved_env.parent
    artifact_db_path = resolve_artifact_db_path(
        env_path=resolved_env,
        project_root=project_root,
    )
    if artifact_db_path is None:
        artifact_db_path = (
            project_root / ".orchestrator-state" / "artifacts.db"
        ).resolve()
    artifact_db_path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteRepository(db_path=artifact_db_path)


def build_provenance_services(
    repository: SQLiteRepository,
    repository_path: Path,
    tsa_url_override: str | None = None,
    env_path: Path | None = None,
) -> tuple[ProvenanceService, VerificationService]:
    """Build provenance + verification service graph for a repo path."""

    resolved_env = env_path or get_project_env_path()
    transparency_log_path = (
        repository_path / ".provenance" / "transparency-log.jsonl"
    )
    publish_url = read_env_optional(
        "TRANSPARENCY_LOG_PUBLISH_URL",
        env_path=resolved_env,
    )
    publish_headers, publish_supabase_format = build_supabase_publish_config(
        publish_url, env_path=resolved_env
    )
    transparency_log_adapter = TransparencyLogAdapter(
        log_path=transparency_log_path,
        publish_url=publish_url,
        publish_headers=publish_headers if publish_headers else None,
        publish_supabase_format=publish_supabase_format,
    )
    tsa_url = tsa_url_override or read_env_optional(
        "RFC3161_TSA_URL",
        env_path=resolved_env,
    )
    if tsa_url is not None and not tsa_url.strip():
        tsa_url = None
    tsa_untrusted_path = read_env_optional(
        "RFC3161_TSA_UNTRUSTED_CERT_PATH",
        env_path=resolved_env,
    )
    openssl_bin = read_env_optional("OPENSSL_BIN", env_path=resolved_env) or "openssl"
    openssl_conf = read_env_optional("OPENSSL_CONF", env_path=resolved_env)
    tsa_adapter = (
        None
        if tsa_url is None
        else RFC3161TSAAdapter(
            tsa_url=tsa_url,
            openssl_bin=openssl_bin,
            untrusted_cert_path=(
                None
                if tsa_untrusted_path is None
                else Path(tsa_untrusted_path).resolve()
            ),
            openssl_conf_path=(
                None if openssl_conf is None else Path(openssl_conf).resolve()
            ),
        )
    )
    key_registry = KeyRegistryAdapter(repository=repository)
    ots_adapter: OTSAdapter | None = None
    if read_env_bool("ENABLE_OTS_FORGE", default=False, env_path=resolved_env):
        ots_adapter = OTSAdapter(
            ots_bin=resolve_ots_binary(env_path=resolved_env)
        )
    provenance_service = ProvenanceService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=tsa_adapter,
        key_registry=key_registry,
        ots_adapter=ots_adapter,
        env_path=resolved_env,
    )
    verification_service = VerificationService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=tsa_adapter,
        key_registry=key_registry,
        artifact_verifier=CryptoNotaryAdapter(
            event_bus=EventBus(),
            env_path=resolved_env,
            require_private_key=False,
        ),
        ots_adapter=ots_adapter,
        env_path=resolved_env,
    )
    return provenance_service, verification_service


def resolve_tsa_ca_cert_path(
    explicit_path: str | None,
    env_path: Path | None = None,
) -> Path | None:
    """Resolve optional TSA CA cert path from CLI arg or env config."""

    resolved_env = env_path or get_project_env_path()
    raw_path = explicit_path or read_env_optional(
        "RFC3161_CA_CERT_PATH",
        env_path=resolved_env,
    )
    if raw_path is None:
        return None
    return Path(raw_path).resolve()
