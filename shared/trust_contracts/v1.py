"""Canonical Issue #291 trust and signing contracts.

This module deliberately contains no network or application imports.  The
contract is shared by offline signing, artifact custody, and public-key
verifiers.  Private key material is never represented in any contract.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TRUST_KEYRING_SCHEMA_VERSION = "web-bridge-trust-keyring-v1"
SIGNING_REQUEST_SCHEMA_VERSION = "web-bridge-signing-request-v1"
SIGNED_ARTIFACT_SCHEMA_VERSION = "web-bridge-signed-artifact-v1"
KEY_DOMAINS = (
    "research",
    "map_acceptance",
    "c_fast_acceptance",
    "runtime_authorization",
    "execution_permit",
)
_DOMAIN_SET = frozenset(KEY_DOMAINS)
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION_RE = re.compile(r"^v[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NON_AUTHORITATIVE_FIELDS = (
    "sensitive_material_present",
    "packet_is_authority",
    "receipt_is_authority",
    "outcome_is_authority",
    "bundle_is_execution_authority",
    "official_forward_claimed",
    "production",
    "live",
    "countable_forward",
    "control_authorized",
    "deployment_authorized",
    "deployment_mutation_authorized",
    "execution_authorized",
    "simnow_execution_authorized",
    "runtime_activation_authorized",
    "readiness_authorized",
    "order_authorized",
    "permit_authorized",
    "position_authorized",
    "trading_authorized",
    "rpc_authorized",
    "network_query_authorized",
    "write_probe_authorized",
    "database_mutation_authorized",
    "collection_authorized",
    "execution_quality_collection_authorized",
    "strategy_activation_authorized",
    "replacement_authorized",
    "dynamic_selection_allowed",
    "replay_allowed",
    "automatic_promotion_authorized",
    "production_allowed",
    "production_authorized",
    "live_trading_authorized",
    "live_allowed",
    "web_bridge_rpc_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "network_authorized",
    "authority_granted",
    "signing_requested",
    "custody_published",
)


class ContractError(ValueError):
    """Raised when a trust/signing contract is malformed or unsafe."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


def canonical_json(value: Any) -> bytes:
    """Return the one canonical byte representation used for all hashes."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractError("CANONICAL_JSON_INVALID") from exc


def canonical_json_line(value: Any) -> bytes:
    return canonical_json(value) + b"\n"


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def assert_non_authoritative(value: Any) -> None:
    """Reject any nested attempt to turn a Phase-B artifact into authority."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in NON_AUTHORITATIVE_FIELDS and item is not False:
                raise ContractError("TRUST_AUTHORITY_FLAG_MUST_BE_FALSE")
            assert_non_authoritative(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            assert_non_authoritative(item)


def _timestamp(value: Any, code: str) -> datetime:
    text = _require_string(value, code, max_bytes=128)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(code) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractError(code)
    return parsed.astimezone(timezone.utc)


def _require_string(value: Any, code: str, *, max_bytes: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > max_bytes
    ):
        raise ContractError(code)
    return value


def _require_sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ContractError(code)
    return value


def _decode_public_key(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ContractError("TRUST_PUBLIC_KEY_ENCODING_INVALID")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContractError("TRUST_PUBLIC_KEY_ENCODING_INVALID") from exc
    if len(raw) != 32:
        raise ContractError("TRUST_PUBLIC_KEY_LENGTH_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ContractError("TRUST_PUBLIC_KEY_INVALID") from exc
    return raw


def validate_keyring(
    payload: Mapping[str, Any],
    *,
    expected_domain: str | None = None,
) -> dict[str, Any]:
    """Validate one domain's public-only keyring.

    A verifier must select the key named by the signed artifact.  This
    function intentionally does not support an implicit "try all keys"
    fallback.  A keyring may contain retired keys for audit, but only one key
    can be active and retired keys are never accepted by ``verify_signed``.
    """

    if not isinstance(payload, Mapping):
        raise ContractError("TRUST_KEYRING_ROOT_INVALID")
    if set(payload) != {"schema_version", "domain", "key_version", "keys"}:
        raise ContractError("TRUST_KEYRING_FIELDS_INVALID")
    if payload.get("schema_version") != TRUST_KEYRING_SCHEMA_VERSION:
        raise ContractError("TRUST_KEYRING_SCHEMA_INVALID")
    domain = payload.get("domain")
    if domain not in _DOMAIN_SET:
        raise ContractError("TRUST_KEYRING_DOMAIN_INVALID")
    if expected_domain is not None and domain != expected_domain:
        raise ContractError("TRUST_KEYRING_DOMAIN_MISMATCH")
    key_version = _require_string(
        payload.get("key_version"), "TRUST_KEY_VERSION_INVALID", max_bytes=64
    )
    if _VERSION_RE.fullmatch(key_version) is None:
        raise ContractError("TRUST_KEY_VERSION_INVALID")
    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ContractError("TRUST_KEYRING_KEYS_INVALID")

    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_material: set[bytes] = set()
    active_count = 0
    for item in keys:
        if not isinstance(item, Mapping):
            raise ContractError("TRUST_KEY_ENTRY_INVALID")
        if set(item) != {"key_id", "domain", "purpose", "public_key_base64", "status"}:
            raise ContractError("TRUST_KEY_ENTRY_FIELDS_INVALID")
        key_id = _require_string(
            item.get("key_id"), "TRUST_KEY_ID_INVALID", max_bytes=128
        )
        if _KEY_ID_RE.fullmatch(key_id) is None or key_id in seen_ids:
            raise ContractError("TRUST_KEY_ID_COLLISION")
        seen_ids.add(key_id)
        if item.get("domain") != domain:
            raise ContractError("TRUST_KEY_DOMAIN_MISMATCH")
        purpose = _require_string(
            item.get("purpose"), "TRUST_KEY_PURPOSE_INVALID", max_bytes=128
        )
        status = item.get("status")
        if status not in {"active", "retired"}:
            raise ContractError("TRUST_KEY_STATUS_INVALID")
        material = _decode_public_key(item.get("public_key_base64"))
        if material in seen_material:
            raise ContractError("TRUST_KEY_MATERIAL_COLLISION")
        seen_material.add(material)
        if status == "active":
            active_count += 1
        normalized.append(
            {
                "key_id": key_id,
                "domain": domain,
                "purpose": purpose,
                "public_key_base64": item["public_key_base64"],
                "status": status,
            }
        )
    if active_count != 1:
        raise ContractError("TRUST_KEYRING_ACTIVE_KEY_COUNT_INVALID")
    return {
        "schema_version": TRUST_KEYRING_SCHEMA_VERSION,
        "domain": domain,
        "key_version": key_version,
        "keys": normalized,
    }


def validate_domain_keyrings(
    keyrings: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate the complete five-domain set with no fallback/reuse."""

    if set(keyrings) != _DOMAIN_SET:
        raise ContractError("TRUST_DOMAIN_SET_INVALID")
    result: dict[str, dict[str, Any]] = {}
    global_ids: set[str] = set()
    global_material: set[bytes] = set()
    for domain in KEY_DOMAINS:
        ring = validate_keyring(keyrings[domain], expected_domain=domain)
        for entry in ring["keys"]:
            if entry["key_id"] in global_ids:
                raise ContractError("TRUST_KEY_ID_CROSS_DOMAIN_COLLISION")
            material = _decode_public_key(entry["public_key_base64"])
            if material in global_material:
                raise ContractError("TRUST_KEY_MATERIAL_CROSS_DOMAIN_COLLISION")
            global_ids.add(entry["key_id"])
            global_material.add(material)
        result[domain] = ring
    return result


def _read_exact(path: Path, *, max_bytes: int = 4 * 1024 * 1024) -> bytes:
    """Read one regular file without following a symlink or accepting swaps."""

    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ContractError("TRUST_FILE_NOT_REGULAR")
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise ContractError("TRUST_FILE_SIZE_INVALID")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            raw = bytearray()
            while len(raw) <= max_bytes:
                chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = path.lstat()
        def identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_gid,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )
        if len({identity(item) for item in (before, opened, after, final)}) != 1:
            raise ContractError("TRUST_FILE_CHANGED_DURING_READ")
        if len(raw) != opened.st_size or not raw:
            raise ContractError("TRUST_FILE_SIZE_CHANGED")
        return bytes(raw)
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("TRUST_FILE_READ_FAILED") from exc


def load_keyring(
    path: str | os.PathLike[str],
    *,
    expected_domain: str,
    expected_raw_sha256: str | None = None,
) -> tuple[dict[str, Any], bytes, str]:
    raw = _read_exact(Path(path))
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("TRUST_KEYRING_JSON_INVALID") from exc
    if raw != canonical_json_line(payload):
        raise ContractError("TRUST_KEYRING_NOT_EXACT_CANONICAL")
    ring = validate_keyring(payload, expected_domain=expected_domain)
    digest = sha256_bytes(raw)
    if expected_raw_sha256 is not None and digest != expected_raw_sha256:
        raise ContractError("TRUST_KEYRING_PIN_MISMATCH")
    return ring, raw, digest


def _unsigned_signed_artifact(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def signing_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return bytes covered by an Ed25519 signature.

    ``signature`` is excluded, but signer identity and the full artifact
    envelope remain covered, preventing cross-domain or cross-key replay.
    """

    if not isinstance(payload, Mapping):
        raise ContractError("SIGNED_ARTIFACT_ROOT_INVALID")
    return canonical_json(_unsigned_signed_artifact(payload))


def build_signing_request(
    artifact: Mapping[str, Any],
    *,
    domain: str,
    key_id: str,
    key_version: str,
    request_id: str,
    requested_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Create the only input accepted by the offline signer."""

    from shared.artifact_contracts.v1 import validate_artifact_envelope

    envelope = validate_artifact_envelope(artifact)
    if domain not in _DOMAIN_SET:
        raise ContractError("SIGNING_REQUEST_DOMAIN_INVALID")
    if envelope["trust_domain"] != domain:
        raise ContractError("SIGNING_REQUEST_ARTIFACT_DOMAIN_MISMATCH")
    key_id = _require_string(key_id, "SIGNING_REQUEST_KEY_ID_INVALID", max_bytes=128)
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise ContractError("SIGNING_REQUEST_KEY_ID_INVALID")
    key_version = _require_string(
        key_version, "SIGNING_REQUEST_KEY_VERSION_INVALID", max_bytes=64
    )
    if _VERSION_RE.fullmatch(key_version) is None:
        raise ContractError("SIGNING_REQUEST_KEY_VERSION_INVALID")
    request_id = _require_string(
        request_id, "SIGNING_REQUEST_ID_INVALID", max_bytes=192
    )
    if _KEY_ID_RE.fullmatch(request_id) is None:
        raise ContractError("SIGNING_REQUEST_ID_INVALID")
    requested_at = _require_string(
        requested_at, "SIGNING_REQUEST_TIME_INVALID", max_bytes=128
    )
    expires_at = _require_string(
        expires_at, "SIGNING_REQUEST_EXPIRY_INVALID", max_bytes=128
    )
    request = {
        "schema_version": SIGNING_REQUEST_SCHEMA_VERSION,
        "request_id": request_id,
        "domain": domain,
        "key_id": key_id,
        "key_version": key_version,
        "requested_at": requested_at,
        "expires_at": expires_at,
        "artifact": envelope,
    }
    return validate_signing_request(request)


def validate_signing_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    from shared.artifact_contracts.v1 import validate_artifact_envelope

    if not isinstance(payload, Mapping):
        raise ContractError("SIGNING_REQUEST_ROOT_INVALID")
    if set(payload) != {
        "schema_version",
        "request_id",
        "domain",
        "key_id",
        "key_version",
        "requested_at",
        "expires_at",
        "artifact",
    }:
        raise ContractError("SIGNING_REQUEST_FIELDS_INVALID")
    if payload.get("schema_version") != SIGNING_REQUEST_SCHEMA_VERSION:
        raise ContractError("SIGNING_REQUEST_SCHEMA_INVALID")
    domain = payload.get("domain")
    if domain not in _DOMAIN_SET:
        raise ContractError("SIGNING_REQUEST_DOMAIN_INVALID")
    request_id = _require_string(
        payload.get("request_id"), "SIGNING_REQUEST_ID_INVALID", max_bytes=192
    )
    if _KEY_ID_RE.fullmatch(request_id) is None:
        raise ContractError("SIGNING_REQUEST_ID_INVALID")
    key_id = _require_string(
        payload.get("key_id"), "SIGNING_REQUEST_KEY_ID_INVALID", max_bytes=128
    )
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise ContractError("SIGNING_REQUEST_KEY_ID_INVALID")
    key_version = _require_string(
        payload.get("key_version"), "SIGNING_REQUEST_KEY_VERSION_INVALID", max_bytes=64
    )
    if _VERSION_RE.fullmatch(key_version) is None:
        raise ContractError("SIGNING_REQUEST_KEY_VERSION_INVALID")
    requested_at = _timestamp(
        payload.get("requested_at"), "SIGNING_REQUEST_TIME_INVALID"
    )
    expires_at = _timestamp(payload.get("expires_at"), "SIGNING_REQUEST_EXPIRY_INVALID")
    if expires_at <= requested_at:
        raise ContractError("SIGNING_REQUEST_EXPIRY_INVALID")
    artifact = payload.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ContractError("SIGNING_REQUEST_ARTIFACT_MISSING")
    envelope = validate_artifact_envelope(artifact)
    if envelope["trust_domain"] != domain:
        raise ContractError("SIGNING_REQUEST_ARTIFACT_DOMAIN_MISMATCH")
    assert_non_authoritative(envelope)
    return dict(payload) | {"artifact": envelope}


def build_signed_artifact(
    request: Mapping[str, Any],
    *,
    signature_base64: str,
) -> dict[str, Any]:
    validated = validate_signing_request(request)
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContractError("SIGNED_ARTIFACT_SIGNATURE_INVALID") from exc
    if len(signature) != 64:
        raise ContractError("SIGNED_ARTIFACT_SIGNATURE_INVALID")
    return {
        "schema_version": SIGNED_ARTIFACT_SCHEMA_VERSION,
        "request_id": validated["request_id"],
        "domain": validated["domain"],
        "signer_key_id": validated["key_id"],
        "signer_key_version": validated["key_version"],
        "requested_at": validated["requested_at"],
        "expires_at": validated["expires_at"],
        "artifact": validated["artifact"],
        "signature": signature_base64,
    }


def _active_key(ring: Mapping[str, Any], key_id: str) -> tuple[dict[str, Any], bytes]:
    matches = [entry for entry in ring["keys"] if entry["key_id"] == key_id]
    if len(matches) != 1:
        raise ContractError("TRUST_KEY_ID_NOT_FOUND")
    entry = matches[0]
    if entry["status"] != "active":
        raise ContractError("TRUST_KEY_NOT_ACTIVE")
    return entry, _decode_public_key(entry["public_key_base64"])


def verify_signed_artifact(
    payload: Mapping[str, Any],
    *,
    keyring: Mapping[str, Any],
    expected_domain: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify one signed artifact with explicit domain/key selection."""

    if not isinstance(payload, Mapping):
        raise ContractError("SIGNED_ARTIFACT_ROOT_INVALID")
    if set(payload) != {
        "schema_version",
        "request_id",
        "domain",
        "signer_key_id",
        "signer_key_version",
        "requested_at",
        "expires_at",
        "artifact",
        "signature",
    }:
        raise ContractError("SIGNED_ARTIFACT_FIELDS_INVALID")
    if payload.get("schema_version") != SIGNED_ARTIFACT_SCHEMA_VERSION:
        raise ContractError("SIGNED_ARTIFACT_SCHEMA_INVALID")
    domain = payload.get("domain")
    if domain != expected_domain:
        raise ContractError("SIGNED_ARTIFACT_DOMAIN_MISMATCH")
    ring = validate_keyring(keyring, expected_domain=expected_domain)
    key_id = _require_string(
        payload.get("signer_key_id"), "SIGNED_ARTIFACT_KEY_ID_INVALID", max_bytes=128
    )
    key_version = _require_string(
        payload.get("signer_key_version"),
        "SIGNED_ARTIFACT_KEY_VERSION_INVALID",
        max_bytes=64,
    )
    if key_version != ring["key_version"]:
        raise ContractError("SIGNED_ARTIFACT_KEY_VERSION_MISMATCH")
    entry, material = _active_key(ring, key_id)
    if entry["domain"] != domain:
        raise ContractError("SIGNED_ARTIFACT_KEY_DOMAIN_MISMATCH")
    signature_raw = payload.get("signature")
    if not isinstance(signature_raw, str):
        raise ContractError("SIGNED_ARTIFACT_SIGNATURE_MISSING")
    try:
        signature = base64.b64decode(signature_raw, validate=True)
        if len(signature) != 64:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(material).verify(
            signature, signing_bytes(payload)
        )
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise ContractError("SIGNED_ARTIFACT_SIGNATURE_INVALID") from exc
    artifact = payload.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ContractError("SIGNED_ARTIFACT_ENVELOPE_MISSING")
    from shared.artifact_contracts.v1 import (
        validate_artifact_envelope,  # local import avoids a cycle
    )

    envelope = validate_artifact_envelope(artifact)
    if envelope["trust_domain"] != domain:
        raise ContractError("SIGNED_ARTIFACT_ENVELOPE_DOMAIN_MISMATCH")
    requested_at = _timestamp(
        payload.get("requested_at"), "SIGNED_ARTIFACT_TIME_INVALID"
    )
    expires_at = _timestamp(payload.get("expires_at"), "SIGNED_ARTIFACT_EXPIRY_INVALID")
    if expires_at <= requested_at:
        raise ContractError("SIGNED_ARTIFACT_EXPIRY_INVALID")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < requested_at or current > expires_at:
        raise ContractError("SIGNED_ARTIFACT_OUTSIDE_VALIDITY")
    assert_non_authoritative(envelope)
    return dict(payload)
