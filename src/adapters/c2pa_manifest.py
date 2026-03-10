"""C2PA sidecar manifest providers and validation helpers."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
from typing import Any, Literal, Protocol

from src.env_config import (
    read_env_choice,
    read_env_optional,
    read_env_required,
)
from src.models import Artifact, canonical_json_bytes, sha256_hex

_C2PA_MODE_VALUES: tuple[str, ...] = ("mvp", "sdk")
_C2PA_ALGORITHM_VALUES: tuple[str, ...] = (
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "ED25519",
)
_DEFAULT_C2PA_MODE = "mvp"
_DEFAULT_C2PA_ALGORITHM = "ES256"
_DEFAULT_FORMAT_CANDIDATES: tuple[str, ...] = (
    "text/plain",
    "application/octet-stream",
)

C2PAMode = Literal["mvp", "sdk"]


@dataclass(frozen=True)
class C2PAManifestArtifact:
    """Generated C2PA sidecar payload and canonical hash."""

    manifest_bytes: bytes
    manifest_hash: str


@dataclass(frozen=True)
class C2PAManifestValidation:
    """Semantic C2PA validation result for one sidecar payload."""

    valid: bool
    validation_state: str | None
    errors: list[str]


@dataclass(frozen=True)
class C2PASdkSettings:
    """Configuration required for SDK-backed C2PA sidecar signing."""

    cert_chain_pem: str
    private_key_pem: str
    algorithm: str
    tsa_url: str | None
    asset_format_override: str | None


class C2PAManifestProvider(Protocol):
    """Provider contract for producing C2PA sidecar bytes."""

    def build(self, envelope: Artifact, body: str) -> C2PAManifestArtifact:
        """Build sidecar bytes and hash from one artifact envelope."""


class MvpC2PAManifestProvider:
    """Deterministic JSON sidecar provider used for MVP dual-write mode."""

    def build(self, envelope: Artifact, body: str) -> C2PAManifestArtifact:
        payload_hash = sha256_hex(body.encode("utf-8"))
        payload = {
            "c2paVersion": "2.3",
            "claimGenerator": envelope.provenance.engine_version,
            "title": envelope.title,
            "assertions": {
                "c2pa.actions": [
                    {
                        "action": "c2pa.created",
                        "digitalSourceType": (
                            "http://cv.iptc.org/newscodes/digitalsourcetype/"
                            "trainedAlgorithmicMedia"
                        ),
                        "when": envelope.timestamp.astimezone(
                            timezone.utc
                        ).isoformat(),
                    }
                ],
                "c2pa.asset": {
                    "artifactId": str(envelope.id),
                    "contentType": envelope.content_type,
                    "payloadHash": payload_hash,
                },
                "slopOrchestrator.context": {
                    "schemaVersion": envelope.schema_version,
                    "source": envelope.provenance.source,
                    "modelId": envelope.provenance.model_id,
                    "generatedAt": envelope.timestamp.isoformat(),
                },
            },
        }
        manifest_bytes = canonical_json_bytes(payload)
        return C2PAManifestArtifact(
            manifest_bytes=manifest_bytes,
            manifest_hash=sha256_hex(manifest_bytes),
        )


class SdkC2PAManifestProvider:
    """Validator-grade provider backed by the official c2pa-python SDK."""

    def __init__(self, settings: C2PASdkSettings) -> None:
        self._settings = settings

    def build(self, envelope: Artifact, body: str) -> C2PAManifestArtifact:
        c2pa = _load_c2pa_module()
        manifest_definition = self._manifest_definition(envelope, body)
        payload_bytes = body.encode("utf-8")
        candidate_formats = _candidate_asset_formats(
            content_type=envelope.content_type,
            format_override=self._settings.asset_format_override,
        )
        supported = _read_supported_formats(c2pa)
        if supported:
            filtered = [
                fmt for fmt in candidate_formats if fmt.lower() in supported
            ]
            if filtered:
                candidate_formats = filtered
        last_error: Exception | None = None
        for asset_format in candidate_formats:
            try:
                builder = c2pa.Builder.from_json(manifest_definition)
                try:
                    builder.set_no_embed()
                    signer = self._build_signer(c2pa)
                    try:
                        manifest_bytes = builder.sign(
                            signer=signer,
                            format=asset_format,
                            source=io.BytesIO(payload_bytes),
                            dest=io.BytesIO(),
                        )
                    finally:
                        signer.close()
                finally:
                    builder.close()
                return C2PAManifestArtifact(
                    manifest_bytes=manifest_bytes,
                    manifest_hash=sha256_hex(manifest_bytes),
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
        if last_error is not None:
            raise RuntimeError(
                "C2PA SDK sidecar build failed for all candidate formats. "
                f"candidates={candidate_formats}"
            ) from last_error
        raise RuntimeError(
            "C2PA SDK sidecar build failed without an error payload."
        )

    def _manifest_definition(
        self,
        envelope: Artifact,
        body: str,
    ) -> dict[str, Any]:
        """Build C2PA manifest JSON definition consumed by c2pa-python."""

        payload_hash = sha256_hex(body.encode("utf-8"))
        return {
            "claim_generator": envelope.provenance.engine_version,
            "title": envelope.title,
            "format": envelope.content_type,
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType": (
                                    "http://cv.iptc.org/newscodes/digitalsourcetype/"
                                    "trainedAlgorithmicMedia"
                                ),
                                "when": (
                                    envelope.timestamp.astimezone(
                                        timezone.utc
                                    ).isoformat()
                                ),
                            }
                        ]
                    },
                },
                {
                    "label": "org.antiphoria.asset",
                    "data": {
                        "artifactId": str(envelope.id),
                        "contentType": envelope.content_type,
                        "payloadHash": payload_hash,
                    },
                },
                {
                    "label": "org.antiphoria.context",
                    "data": {
                        "schemaVersion": envelope.schema_version,
                        "source": envelope.provenance.source,
                        "modelId": envelope.provenance.model_id,
                        "generatedAt": envelope.timestamp.isoformat(),
                    },
                },
            ],
        }

    def _build_signer(self, c2pa: Any) -> Any:
        """Create SDK signer from configured X.509 material."""

        signer_info = c2pa.C2paSignerInfo(
            alg=getattr(c2pa.C2paSigningAlg, self._settings.algorithm),
            sign_cert=self._settings.cert_chain_pem,
            private_key=self._settings.private_key_pem,
            ta_url=self._settings.tsa_url or "",
        )
        return c2pa.Signer.from_info(signer_info)


def resolve_c2pa_mode(
    env_path: Path | None = None,
    explicit_mode: C2PAMode | None = None,
) -> C2PAMode:
    """Resolve C2PA sidecar provider mode from env or explicit override."""

    if explicit_mode is not None:
        return explicit_mode
    return read_env_choice(
        "C2PA_MODE",
        allowed_values=_C2PA_MODE_VALUES,
        default=_DEFAULT_C2PA_MODE,
        env_path=env_path,
    )


def build_c2pa_manifest_provider(
    env_path: Path | None = None,
    mode: C2PAMode | None = None,
) -> C2PAManifestProvider:
    """Build provider for selected C2PA sidecar mode."""

    resolved_mode = resolve_c2pa_mode(env_path=env_path, explicit_mode=mode)
    if resolved_mode == "mvp":
        return MvpC2PAManifestProvider()
    return SdkC2PAManifestProvider(settings=_resolve_sdk_settings(env_path))


def build_c2pa_sidecar_manifest(
    envelope: Artifact,
    body: str,
    env_path: Path | None = None,
    mode: C2PAMode | None = None,
) -> C2PAManifestArtifact:
    """Build C2PA sidecar payload from artifact envelope and body."""

    provider = build_c2pa_manifest_provider(env_path=env_path, mode=mode)
    return provider.build(envelope, body)


def validate_c2pa_sidecar(
    payload_bytes: bytes,
    manifest_bytes: bytes,
    content_type: str,
    env_path: Path | None = None,
) -> C2PAManifestValidation:
    """Validate one sidecar manifest against one payload."""

    try:
        c2pa = _load_c2pa_module()
    except RuntimeError as exc:
        return C2PAManifestValidation(
            valid=False,
            validation_state=None,
            errors=[str(exc)],
        )
    candidate_formats = _candidate_asset_formats(
        content_type=content_type,
        format_override=read_env_optional(
            "C2PA_SDK_ASSET_FORMAT",
            env_path=env_path,
        ),
    )
    supported = _read_supported_formats(c2pa)
    if supported:
        filtered = [
            fmt for fmt in candidate_formats if fmt.lower() in supported
        ]
        if filtered:
            candidate_formats = filtered
    last_error: Exception | None = None
    for asset_format in candidate_formats:
        try:
            reader = c2pa.Reader(
                asset_format,
                io.BytesIO(payload_bytes),
                manifest_data=manifest_bytes,
            )
            try:
                validation_state = reader.get_validation_state()
                validation_results = reader.get_validation_results() or {}
            finally:
                reader.close()
            errors = _extract_validation_errors(validation_results)
            if validation_state == "valid" and not errors:
                return C2PAManifestValidation(
                    valid=True,
                    validation_state=validation_state,
                    errors=[],
                )
            return C2PAManifestValidation(
                valid=False,
                validation_state=validation_state,
                errors=errors
                or [
                    f"C2PA validation failed with state "
                    f"'{validation_state}'."
                ],
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
    if last_error is None:
        return C2PAManifestValidation(
            valid=False,
            validation_state=None,
            errors=[
                "C2PA validation failed for all candidate formats: "
                f"{candidate_formats}"
            ],
        )
    return C2PAManifestValidation(
        valid=False,
        validation_state=None,
        errors=[
            "C2PA validation failed for all candidate formats: "
            f"{candidate_formats}",
            str(last_error),
        ],
    )


def _resolve_sdk_settings(env_path: Path | None = None) -> C2PASdkSettings:
    """Resolve and validate SDK-side C2PA signer configuration."""

    cert_chain_path = _resolve_path(
        read_env_required("C2PA_SIGN_CERT_CHAIN_PATH", env_path=env_path),
        env_path=env_path,
    )
    private_key_path = _resolve_path(
        read_env_required("C2PA_PRIVATE_KEY_PATH", env_path=env_path),
        env_path=env_path,
    )
    cert_chain_pem = _read_text_required(
        cert_chain_path,
        purpose="C2PA signer certificate chain",
    )
    private_key_pem = _read_text_required(
        private_key_path,
        purpose="C2PA signer private key",
    )
    algorithm = read_env_choice(
        "C2PA_SIGNING_ALG",
        allowed_values=_C2PA_ALGORITHM_VALUES,
        default=_DEFAULT_C2PA_ALGORITHM,
        env_path=env_path,
    )
    return C2PASdkSettings(
        cert_chain_pem=cert_chain_pem,
        private_key_pem=private_key_pem,
        algorithm=algorithm,
        tsa_url=read_env_optional("C2PA_TSA_URL", env_path=env_path),
        asset_format_override=read_env_optional(
            "C2PA_SDK_ASSET_FORMAT",
            env_path=env_path,
        ),
    )


def _resolve_path(
    raw_path: str,
    env_path: Path | None = None,
) -> Path:
    """Resolve env-provided path as absolute path with .env-relative support."""

    path_obj = Path(raw_path)
    if path_obj.is_absolute():
        return path_obj
    base_path = Path(".") if env_path is None else env_path.parent
    return (base_path / path_obj).resolve()


def _read_text_required(path: Path, purpose: str) -> str:
    """Read required UTF-8 text file with strict presence validation."""

    if not path.exists():
        raise RuntimeError(f"{purpose} not found: '{path}'.")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise RuntimeError(f"{purpose} is empty: '{path}'.")
    return text


def _candidate_asset_formats(
    content_type: str,
    format_override: str | None,
) -> list[str]:
    """Build prioritized candidate list for SDK sign/verify format values."""

    candidates = [
        candidate
        for candidate in (
            format_override,
            content_type,
            *_DEFAULT_FORMAT_CANDIDATES,
        )
        if candidate is not None and candidate.strip()
    ]
    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(candidate)
    return deduped


def _read_supported_formats(c2pa_module: Any) -> set[str]:
    """Read SDK supported MIME list if available."""

    try:
        supported = c2pa_module.Builder.get_supported_mime_types()
    except Exception:  # noqa: BLE001
        return set()
    return {str(value).lower() for value in supported}


def _extract_validation_errors(validation_results: Any) -> list[str]:
    """Extract user-readable C2PA validation errors from reader payload."""

    if not isinstance(validation_results, dict):
        return []
    errors: list[str] = []
    direct_status = validation_results.get("validation_status")
    if isinstance(direct_status, list):
        for item in direct_status:
            if isinstance(item, dict):
                errors.append(json.dumps(item, sort_keys=True))
            else:
                errors.append(str(item))
    if errors:
        return errors
    failures = validation_results.get("failure")
    if isinstance(failures, list):
        for failure in failures:
            errors.append(str(failure))
    return errors


def _load_c2pa_module() -> Any:
    """Import c2pa-python lazily to keep MVP mode lightweight."""

    try:
        import c2pa  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "C2PA SDK mode requires dependency 'c2pa-python'. "
            "Install it and retry."
        ) from exc
    return c2pa
