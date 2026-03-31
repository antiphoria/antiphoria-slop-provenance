"""C2PA sidecar manifest providers and validation helpers."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
from typing import Any, Literal, Protocol
from xml.sax.saxutils import escape as _xml_escape

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from src.env_config import (
    read_env_choice,
    read_env_optional,
    read_env_required,
)
from src.canonicalization import canonicalize_body, compute_payload_hash
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
_SDK_BRIDGE_SCHEMA_VERSION = "antiphoria-slop-provenance.c2pa.bridge.v1"
_SDK_BRIDGE_FORMAT = "text/xml"
_SDK_CARRIER_FORMAT = "image/jpeg"
_SDK_MARKDOWN_ASSERTION_LABEL = "org.antiphoria.markdown"
_SDK_MINIMAL_JPEG_BYTES = bytes.fromhex(
    "FFD8FFDB004300030202020202030202020303030304060404040404080606050609080A0A090809090A0C0F0C0A0B0E0B09090D110D0E0F101011100A0C12131210130F101010FFC9000B080001000101011100FFCC000600101005FFDA0008010100003F00D2CF20FFD9"
)
_DEFAULT_FORMAT_CANDIDATES: tuple[str, ...] = (
    "text/markdown",
    "text/xml",
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


@dataclass(frozen=True)
class C2PASdkBridgePayload:
    """Deterministic XML payload used as SDK signing source."""

    payload_bytes: bytes
    payload_format: str


class C2PAManifestProvider(Protocol):
    """Provider contract for producing C2PA sidecar bytes."""

    def build(self, envelope: Artifact, body: str) -> C2PAManifestArtifact:
        """Build sidecar bytes and hash from one artifact envelope."""


class MvpC2PAManifestProvider:
    """Deterministic JSON sidecar provider used for MVP dual-write mode."""

    def build(self, envelope: Artifact, body: str) -> C2PAManifestArtifact:
        payload_hash = compute_payload_hash(body)
        payload = {
            "c2paVersion": "2.3",
            "claimGenerator": envelope.provenance.engine_version,
            "title": envelope.title,
            "assertions": {
                "c2pa.actions": [
                    {
                        "action": "c2pa.created",
                        "digitalSourceType": (
                            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
                        ),
                        "when": envelope.timestamp.astimezone(timezone.utc).isoformat(),
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
        manifest_definition = self._manifest_definition(
            envelope=envelope,
            body=body,
            bridge_format=_SDK_BRIDGE_FORMAT,
            asset_format=_SDK_CARRIER_FORMAT,
        )
        try:
            builder = c2pa.Builder.from_json(json.dumps(manifest_definition, sort_keys=True))
            try:
                builder.set_no_embed()
                signer = self._build_signer(c2pa)
                try:
                    manifest_bytes = builder.sign(
                        signer=signer,
                        format=_SDK_CARRIER_FORMAT,
                        source=io.BytesIO(_SDK_MINIMAL_JPEG_BYTES),
                        dest=io.BytesIO(),
                    )
                finally:
                    signer.close()
            finally:
                builder.close()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"C2PA SDK sidecar build failed while signing JPEG carrier: {exc!r}"
            ) from exc
        return C2PAManifestArtifact(
            manifest_bytes=manifest_bytes,
            manifest_hash=sha256_hex(manifest_bytes),
        )

    def _manifest_definition(
        self,
        envelope: Artifact,
        body: str,
        bridge_format: str,
        asset_format: str,
    ) -> dict[str, Any]:
        """Build C2PA manifest JSON definition consumed by c2pa-python."""

        payload_hash = compute_payload_hash(body)
        return {
            "claim_generator": envelope.provenance.engine_version,
            "title": envelope.title,
            "format": asset_format,
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType": (
                                    "http://cv.iptc.org/newscodes/"
                                    "digitalsourcetype/"
                                    "trainedAlgorithmicMedia"
                                ),
                                "when": (envelope.timestamp.astimezone(timezone.utc).isoformat()),
                            }
                        ]
                    },
                },
                {
                    "label": "org.antiphoria.asset",
                    "data": {
                        "artifactId": str(envelope.id),
                        "contentType": envelope.content_type,
                        "bridgeFormat": bridge_format,
                        "payloadHash": payload_hash,
                    },
                },
                {
                    "label": _SDK_MARKDOWN_ASSERTION_LABEL,
                    "data": {
                        "content": body,
                        "payloadHash": payload_hash,
                        "contentType": envelope.content_type,
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

        if self._settings.algorithm not in _C2PA_ALGORITHM_VALUES:
            raise RuntimeError(
                f"C2PA signing algorithm '{self._settings.algorithm}' is not "
                f"supported. Use one of: {', '.join(_C2PA_ALGORITHM_VALUES)}."
            )
        try:
            alg_constant = getattr(c2pa.C2paSigningAlg, self._settings.algorithm)
        except AttributeError as exc:
            raise RuntimeError(
                f"C2PA SDK does not support algorithm '{self._settings.algorithm}'. "
                f"Supported: {', '.join(_C2PA_ALGORITHM_VALUES)}."
            ) from exc
        signer_info = c2pa.C2paSignerInfo(
            alg=alg_constant,
            sign_cert=self._settings.cert_chain_pem.encode("utf-8"),
            private_key=self._settings.private_key_pem.encode("utf-8"),
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


def build_c2pa_validation_payload(
    envelope: Artifact,
    body: str,
    env_path: Path | None = None,
    mode: C2PAMode | None = None,
) -> tuple[bytes, str]:
    """Build payload bytes used for C2PA semantic verification."""

    resolved_mode = resolve_c2pa_mode(env_path=env_path, explicit_mode=mode)
    if resolved_mode == "sdk":
        _ = (envelope, body)
        return _SDK_MINIMAL_JPEG_BYTES, _SDK_CARRIER_FORMAT
    from src.canonicalization import canonicalize_body_for_hash

    payload_bytes = (
        canonicalize_body_for_hash(body)
        if (
            envelope.signature is not None
            and envelope.signature.payload_canonicalization == "eternity.canonicalization.v1"
        )
        else body.encode("utf-8")
    )
    return payload_bytes, envelope.content_type


def build_sdk_bridge_payload(
    envelope: Artifact,
    body: str,
) -> C2PASdkBridgePayload:
    """Build deterministic XML bridge payload from markdown artifact data."""

    payload_hash = compute_payload_hash(body)
    bridge_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<slopOrchestratorBridge>"
        f"<bridgeSchemaVersion>{_SDK_BRIDGE_SCHEMA_VERSION}</bridgeSchemaVersion>"
        f"<artifactId>{_xml_escape(str(envelope.id))}</artifactId>"
        f"<artifactSchemaVersion>{_xml_escape(envelope.schema_version)}</artifactSchemaVersion>"
        f"<artifactContentType>{_xml_escape(envelope.content_type)}</artifactContentType>"
        f"<artifactTitle>{_xml_escape(envelope.title)}</artifactTitle>"
        f"<artifactTimestamp>{_xml_escape(envelope.timestamp.isoformat())}</artifactTimestamp>"
        f"<payloadSha256>{payload_hash}</payloadSha256>"
        "<provenance>"
        f"<source>{_xml_escape(envelope.provenance.source)}</source>"
        f"<engineVersion>{_xml_escape(envelope.provenance.engine_version)}</engineVersion>"
        f"<modelId>{_xml_escape(envelope.provenance.model_id)}</modelId>"
        "</provenance>"
        "</slopOrchestratorBridge>"
    )
    return C2PASdkBridgePayload(
        payload_bytes=bridge_xml.encode("utf-8"),
        payload_format=_SDK_BRIDGE_FORMAT,
    )


def validate_c2pa_sidecar(
    payload_bytes: bytes,
    manifest_bytes: bytes,
    content_type: str,
    payload_format: str | None = None,
    env_path: Path | None = None,
    body_for_mvp: str | None = None,
) -> C2PAManifestValidation:
    """Validate one sidecar manifest against one payload.

    body_for_mvp is **required** when the manifest is MVP format (determined by
    _manifest_looks_like_mvp). payload_bytes may be a JPEG dummy carrier for SDK
    mode; for MVP, the actual markdown body must be passed via body_for_mvp for
    payload hash validation. Third-party callers must pass body_for_mvp when
    validating MVP sidecars; otherwise validation fails with a clear error.
    """

    mvp_result = _validate_mvp_manifest(manifest_bytes, body_for_mvp)
    if mvp_result is not None:
        return mvp_result

    mvp_requires_body = _manifest_looks_like_mvp(manifest_bytes)
    if mvp_requires_body and body_for_mvp is None:
        return C2PAManifestValidation(
            valid=False,
            validation_state="invalid",
            errors=[
                "MVP C2PA manifest requires artifact body for payload hash "
                "validation. Pass body_for_mvp when validating MVP sidecars."
            ],
        )

    try:
        c2pa = _load_c2pa_module()
    except RuntimeError as exc:
        return C2PAManifestValidation(
            valid=False,
            validation_state=None,
            errors=[str(exc)],
        )
    if payload_format == _SDK_CARRIER_FORMAT:
        return _validate_via_sdk_carrier(
            c2pa=c2pa,
            manifest_bytes=manifest_bytes,
            body_for_mvp=body_for_mvp,
        )
    return _validate_via_candidate_formats(
        c2pa=c2pa,
        payload_bytes=payload_bytes,
        manifest_bytes=manifest_bytes,
        content_type=content_type,
        payload_format=payload_format,
        env_path=env_path,
        body_for_mvp=body_for_mvp,
    )


def _run_sdk_reader(
    c2pa: Any,
    *,
    asset_format: str,
    payload_bytes: bytes,
    manifest_bytes: bytes,
) -> tuple[str | None, dict[str, Any], str]:
    """Run one SDK reader session and return validation outputs."""

    reader = c2pa.Reader(
        asset_format,
        io.BytesIO(payload_bytes),
        manifest_data=manifest_bytes,
    )
    try:
        validation_state = reader.get_validation_state()
        validation_results = reader.get_validation_results() or {}
        manifest_store_json = reader.json()
    finally:
        reader.close()
    return validation_state, validation_results, manifest_store_json


def _validate_via_sdk_carrier(
    c2pa: Any,
    manifest_bytes: bytes,
    body_for_mvp: str | None,
) -> C2PAManifestValidation:
    """Validate sidecar using the SDK JPEG carrier mode."""

    try:
        validation_state, validation_results, manifest_store_json = _run_sdk_reader(
            c2pa=c2pa,
            asset_format=_SDK_CARRIER_FORMAT,
            payload_bytes=_SDK_MINIMAL_JPEG_BYTES,
            manifest_bytes=manifest_bytes,
        )
    except Exception as exc:  # noqa: BLE001
        return C2PAManifestValidation(
            valid=False,
            validation_state=None,
            errors=[str(exc)],
        )

    errors = _extract_validation_errors(validation_results)
    state_ok = (validation_state or "").lower() == "valid"
    if not state_ok or errors:
        return C2PAManifestValidation(
            valid=False,
            validation_state=validation_state,
            errors=errors or [f"C2PA validation failed with state '{validation_state}'."],
        )
    markdown_assertion_errors = _validate_sdk_markdown_assertion(
        manifest_store_json=manifest_store_json,
        body=body_for_mvp,
    )
    if markdown_assertion_errors:
        return C2PAManifestValidation(
            valid=False,
            validation_state="invalid",
            errors=markdown_assertion_errors,
        )
    return C2PAManifestValidation(
        valid=True,
        validation_state=validation_state,
        errors=[],
    )


def _validate_via_candidate_formats(
    c2pa: Any,
    payload_bytes: bytes,
    manifest_bytes: bytes,
    content_type: str,
    payload_format: str | None,
    env_path: Path | None,
    body_for_mvp: str | None,
) -> C2PAManifestValidation:
    """Validate sidecar by trying candidate asset formats."""

    candidate_formats = _candidate_asset_formats(
        content_type=payload_format or content_type,
        format_override=read_env_optional(
            "C2PA_SDK_ASSET_FORMAT",
            env_path=env_path,
        ),
    )
    supported = _read_supported_formats(c2pa)
    if supported:
        filtered = [fmt for fmt in candidate_formats if fmt.lower() in supported]
        if filtered:
            candidate_formats = filtered

    last_error: Exception | None = None
    for asset_format in candidate_formats:
        try:
            validation_state, validation_results, manifest_store_json = _run_sdk_reader(
                c2pa=c2pa,
                asset_format=asset_format,
                payload_bytes=payload_bytes,
                manifest_bytes=manifest_bytes,
            )
            errors = _extract_validation_errors(validation_results)
            state_ok = (validation_state or "").lower() == "valid"
            if state_ok and not errors:
                if body_for_mvp is not None:
                    try:
                        manifest_store = json.loads(manifest_store_json)
                    except json.JSONDecodeError:
                        manifest_store = {}
                    if (
                        _read_assertion_data(
                            manifest_store=manifest_store,
                            label=_SDK_MARKDOWN_ASSERTION_LABEL,
                        )
                        is not None
                    ):
                        markdown_errors = _validate_sdk_markdown_assertion(
                            manifest_store_json=manifest_store_json,
                            body=body_for_mvp,
                        )
                        if markdown_errors:
                            return C2PAManifestValidation(
                                valid=False,
                                validation_state="invalid",
                                errors=markdown_errors,
                            )
                return C2PAManifestValidation(
                    valid=True,
                    validation_state=validation_state,
                    errors=[],
                )
            return C2PAManifestValidation(
                valid=False,
                validation_state=validation_state,
                errors=errors or [f"C2PA validation failed with state '{validation_state}'."],
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue

    if last_error is None:
        return C2PAManifestValidation(
            valid=False,
            validation_state=None,
            errors=[f"C2PA validation failed for all candidate formats: {candidate_formats}"],
        )
    return C2PAManifestValidation(
        valid=False,
        validation_state=None,
        errors=[
            f"C2PA validation failed for all candidate formats: {candidate_formats}",
            str(last_error),
        ],
    )


def _manifest_looks_like_mvp(manifest_bytes: bytes) -> bool:
    """Return True if manifest has MVP JSON structure (assertions.c2pa.asset)."""
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(manifest, dict):
        return False
    assertions = manifest.get("assertions")
    if not isinstance(assertions, dict):
        return False
    return "c2pa.asset" in assertions


def _validate_mvp_manifest(
    manifest_bytes: bytes,
    body: str | None,
) -> C2PAManifestValidation | None:
    """Validate MVP JSON manifest if applicable. Returns None if not MVP format."""

    if body is None:
        return None
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(manifest, dict):
        return None
    assertions = manifest.get("assertions")
    if not isinstance(assertions, dict):
        return None
    asset = assertions.get("c2pa.asset")
    if not isinstance(asset, dict):
        return None
    expected_hash = asset.get("payloadHash")
    if not isinstance(expected_hash, str):
        return None
    actual_hash = compute_payload_hash(body)
    if actual_hash != expected_hash:
        return C2PAManifestValidation(
            valid=False,
            validation_state="invalid",
            errors=[f"MVP payload hash mismatch: expected {expected_hash}, got {actual_hash}"],
        )
    return C2PAManifestValidation(
        valid=True,
        validation_state="valid",
        errors=[],
    )


def _validate_sdk_markdown_assertion(
    manifest_store_json: str,
    body: str | None,
) -> list[str]:
    """Validate custom SDK markdown assertion against canonical payload."""

    if body is None:
        return ["SDK C2PA validation requires artifact body for org.antiphoria.markdown checks."]
    try:
        manifest_store = json.loads(manifest_store_json)
    except json.JSONDecodeError as exc:
        return [f"Failed to parse C2PA manifest JSON: {exc}"]
    assertion_data = _read_assertion_data(
        manifest_store=manifest_store,
        label=_SDK_MARKDOWN_ASSERTION_LABEL,
    )
    if not isinstance(assertion_data, dict):
        return [f"SDK C2PA assertion '{_SDK_MARKDOWN_ASSERTION_LABEL}' missing or malformed."]
    errors: list[str] = []
    expected_hash = compute_payload_hash(body)
    stored_hash = assertion_data.get("payloadHash")
    # Compare canonicalized forms: C2PA stores raw body, commit stores canonicalized
    stored_content = assertion_data.get("content") or ""
    if canonicalize_body(stored_content) != canonicalize_body(body):
        errors.append("SDK markdown assertion content mismatch against artifact payload.")
    if assertion_data.get("payloadHash") != expected_hash:
        errors.append("SDK markdown assertion payloadHash mismatch against artifact payload hash.")
    return errors


def _read_assertion_data(manifest_store: Any, label: str) -> Any | None:
    """Read assertion data payload for active manifest label."""

    if not isinstance(manifest_store, dict):
        return None
    manifests = manifest_store.get("manifests")
    if not isinstance(manifests, dict) or not manifests:
        return None
    active_manifest_key = manifest_store.get("active_manifest")
    active_manifest: dict[str, Any] | None = None
    if isinstance(active_manifest_key, str):
        candidate = manifests.get(active_manifest_key)
        if isinstance(candidate, dict):
            active_manifest = candidate
    if active_manifest is None:
        first_candidate = next(
            (item for item in manifests.values() if isinstance(item, dict)),
            None,
        )
        if isinstance(first_candidate, dict):
            active_manifest = first_candidate
    if active_manifest is None:
        return None
    assertions = active_manifest.get("assertions")
    if isinstance(assertions, list):
        for assertion in assertions:
            if isinstance(assertion, dict) and assertion.get("label") == label:
                return assertion.get("data")
        return None
    if isinstance(assertions, dict):
        by_label = assertions.get(label)
        if isinstance(by_label, dict) and "data" in by_label:
            return by_label.get("data")
        return by_label
    return None


def _normalize_private_key_to_pkcs8(pem: str) -> str:
    """Normalize private key PEM to PKCS#8 for C2PA SDK compatibility.

    Accepts EC PRIVATE KEY, RSA PRIVATE KEY, or PRIVATE KEY formats.
    Returns PKCS#8 PEM (-----BEGIN PRIVATE KEY-----).
    """
    try:
        key = load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as exc:
        raise RuntimeError(f"C2PA private key could not be loaded: {exc}") from exc
    pkcs8_bytes = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    return pkcs8_bytes.decode("utf-8")


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
    raw_key_pem = _read_text_required(
        private_key_path,
        purpose="C2PA signer private key",
    )
    private_key_pem = _normalize_private_key_to_pkcs8(raw_key_pem)
    algorithm = read_env_choice(
        "C2PA_SIGNING_ALG",
        allowed_values=_C2PA_ALGORITHM_VALUES,
        default=_DEFAULT_C2PA_ALGORITHM,
        env_path=env_path,
    )
    tsa_url = read_env_optional("C2PA_TSA_URL", env_path=env_path)
    if not tsa_url:
        tsa_url = read_env_optional("RFC3161_TSA_URL", env_path=env_path)
    return C2PASdkSettings(
        cert_chain_pem=cert_chain_pem,
        private_key_pem=private_key_pem,
        algorithm=algorithm,
        tsa_url=tsa_url,
        asset_format_override=read_env_optional(
            "C2PA_SDK_ASSET_FORMAT",
            env_path=env_path,
        ),
    )


def _resolve_path(
    raw_path: str,
    env_path: Path | None = None,
) -> Path:
    """Resolve env-provided path with optional .env-relative base path."""

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
            "C2PA SDK mode requires dependency 'c2pa-python'. Install it and retry."
        ) from exc
    return c2pa
