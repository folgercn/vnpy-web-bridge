#!/usr/bin/env python3
"""Verify signed query-v3 build/registry provenance v2 offline."""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    validate_json_schema,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
PROVENANCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-build-registry-provenance-v2.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-build-registry-provenance-receipt-v2.schema.json"
)
CONTENT_ATTESTATION_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v3-image-attestation-v1.schema.json"
)
SOURCE_MANIFEST_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v3-source-manifest-v1.schema.json"
)
CONTENT_VERIFIER_PATH = (
    ROOT / "scripts/c_fast_t1/verify_query_v3_image_attestation.py"
)

SCHEMA_VERSION = "commodity_c_fast_t1_build_registry_provenance_v2"
RECEIPT_SCHEMA_VERSION = (
    "commodity_c_fast_t1_build_registry_provenance_receipt_v2"
)
CONTENT_ATTESTATION_SCHEMA_VERSION = (
    "commodity_c_fast_t1_query_v3_image_attestation_v1"
)
KEYRING_VERSION = (
    "commodity_c_fast_t1_build_registry_provenance_trusted_keys_v1"
)
KEY_PURPOSE = "t1_build_registry_provenance_signer"
T1_KEYRING_VERSION = "commodity_c_fast_t1_trusted_keys_v1"
T1_KEY_PURPOSE = "t1_audit_release_signer"
L3_KEYRING_VERSION = (
    "commodity_c_fast_readonly_deployment_trusted_keys_v1"
)
L3_KEY_PURPOSE = "readonly_deployment_release_signer"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
PURPOSE = "c_fast_t1_query_v3_external_build_registry_provenance"
SIGNING_TOOL_SOURCE_PATH = (
    "scripts/commodity_c_fast_t1_build_registry_provenance_sign_v2.py"
)
SIGNING_TOOL_IDENTITY_SCOPE = (
    "SIGNED_AND_INDEPENDENTLY_PINNED_SOURCE_IDENTITY_"
    "NOT_RUNTIME_BYTES_OR_EXECUTION_ATTESTATION"
)
EXTERNAL_FACT_SCOPE = (
    "SIGNED_EXTERNAL_ASSERTION_NOT_INDEPENDENTLY_REVERIFIED_BY_OFFLINE_VERIFIER"
)
RECEIPT_STATUS = (
    "SIGNED_QUERY_V3_BUILD_REGISTRY_ASSERTIONS_VERIFIED_NO_RUNTIME_AUTHORITY"
)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_BUILD_DURATION = timedelta(hours=6)
MAX_ISSUANCE_DELAY = timedelta(hours=24)
MAX_FUTURE_SKEW = timedelta(minutes=5)
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

FALSE_AUTHORITY_FIELDS = (
    "sensitive_material_present",
    "authority_granted",
    "readiness_authorized",
    "ready_for_human_t1_release_signature_only",
    "network_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "production_query_authorized",
    "write_probe_authorized",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "replacement_authorized",
    "production_authorized",
    "dynamic_selection_allowed",
    "automatic_promotion_authorized",
    "t1_executed",
    "production_queried",
    "dispatch_changed",
)
ZERO_FACT_FIELDS = (
    "database_mutations",
    "orders_sent",
    "positions_modified",
)


class BuildRegistryProvenanceV2Error(RuntimeError):
    """Expected fail-closed provenance-v2 validation error."""


def unsigned_provenance_payload(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "signature"
    }


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compare(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise BuildRegistryProvenanceV2Error(
            f"{label} binding mismatch"
        )


def _validate_sha256(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or SHA256_PATTERN.fullmatch(value) is None
    ):
        raise BuildRegistryProvenanceV2Error(
            f"{label} must be a lowercase SHA256"
        )


def _validate_commit(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or COMMIT_PATTERN.fullmatch(value) is None
    ):
        raise BuildRegistryProvenanceV2Error(
            f"{label} must be a lowercase 40-character commit SHA"
        )


def _read_file(
    path: Path,
    label: str,
    *,
    private: bool = False,
) -> bytes:
    try:
        return read_regular_file_strict(
            path,
            label,
            private=private,
            limit=MAX_JSON_BYTES,
        )
    except OneShotError as exc:
        raise BuildRegistryProvenanceV2Error(str(exc)) from exc


def _load_json(
    path: Path,
    label: str,
    *,
    private: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    raw = _read_file(path, label, private=private)
    try:
        return raw, parse_json_bytes(raw, label)
    except OneShotError as exc:
        raise BuildRegistryProvenanceV2Error(str(exc)) from exc


def _validate_schema(
    payload: dict[str, Any],
    schema_path: Path,
    label: str,
) -> None:
    try:
        validate_json_schema(payload, schema_path, label)
    except OneShotError as exc:
        raise BuildRegistryProvenanceV2Error(str(exc)) from exc


def _runtime_file_hashes() -> dict[str, str]:
    """Return verifier-side identities; deliberately never reads a signer."""
    return {
        "provenance_verifier_sha256": _hash_bytes(
            _read_file(VERIFIER_PATH, "provenance v2 verifier")
        ),
        "provenance_schema_sha256": _hash_bytes(
            _read_file(PROVENANCE_SCHEMA_PATH, "provenance v2 schema")
        ),
        "receipt_schema_sha256": _hash_bytes(
            _read_file(RECEIPT_SCHEMA_PATH, "provenance v2 receipt schema")
        ),
        "content_attestation_schema_sha256": _hash_bytes(
            _read_file(
                CONTENT_ATTESTATION_SCHEMA_PATH,
                "query-v3 content attestation schema",
            )
        ),
        "content_verifier_sha256": _hash_bytes(
            _read_file(CONTENT_VERIFIER_PATH, "query-v3 content verifier")
        ),
        "source_manifest_schema_sha256": _hash_bytes(
            _read_file(
                SOURCE_MANIFEST_SCHEMA_PATH,
                "query-v3 source manifest schema",
            )
        ),
    }


def add_runtime_file_hashes(
    payload: dict[str, Any],
) -> dict[str, Any]:
    result = dict(payload)
    result.update(_runtime_file_hashes())
    return result


def _validate_runtime_file_hashes(payload: dict[str, Any]) -> None:
    for field, actual in _runtime_file_hashes().items():
        _compare(actual, str(payload[field]), field)


def _load_public_keyset(
    keyring: dict[str, Any],
    signer_key_id: str,
) -> tuple[Ed25519PublicKey, set[str]]:
    if set(keyring) != {"schema_version", "keys"}:
        raise BuildRegistryProvenanceV2Error(
            "trusted keyring fields are invalid"
        )
    if keyring["schema_version"] != KEYRING_VERSION:
        raise BuildRegistryProvenanceV2Error(
            "trusted keyring schema version is invalid"
        )
    entries = keyring["keys"]
    if (
        not isinstance(entries, list)
        or not entries
        or len(entries) > 32
    ):
        raise BuildRegistryProvenanceV2Error(
            "trusted keyring must contain 1 to 32 keys"
        )
    matched: Ed25519PublicKey | None = None
    hashes: set[str] = set()
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise BuildRegistryProvenanceV2Error(
                "trusted key entry fields are invalid"
            )
        key_id = str(entry["key_id"])
        if ID_PATTERN.fullmatch(key_id) is None or key_id in seen:
            raise BuildRegistryProvenanceV2Error(
                "trusted key_id is invalid or duplicated"
            )
        seen.add(key_id)
        if entry["purpose"] != KEY_PURPOSE:
            raise BuildRegistryProvenanceV2Error(
                "trusted key purpose is invalid"
            )
        try:
            raw = base64.b64decode(
                entry["public_key_base64"],
                validate=True,
            )
            if len(raw) != 32:
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise BuildRegistryProvenanceV2Error(
                "trusted Ed25519 public key is invalid"
            ) from exc
        public_key_sha256 = _hash_bytes(raw)
        if public_key_sha256 in hashes:
            raise BuildRegistryProvenanceV2Error(
                "trusted keyring duplicates public-key material"
            )
        hashes.add(public_key_sha256)
        if key_id == signer_key_id:
            matched = public_key
    if matched is None:
        raise BuildRegistryProvenanceV2Error(
            "provenance signer key is not trusted"
        )
    return matched, hashes


def _all_public_key_hashes(
    keyring: dict[str, Any],
    label: str,
    *,
    expected_schema_version: str,
    expected_purpose: str,
) -> set[str]:
    if set(keyring) != {"schema_version", "keys"}:
        raise BuildRegistryProvenanceV2Error(
            f"{label} fields are invalid"
        )
    if keyring["schema_version"] != expected_schema_version:
        raise BuildRegistryProvenanceV2Error(
            f"{label} schema version is invalid"
        )
    entries = keyring["keys"]
    if (
        not isinstance(entries, list)
        or not entries
        or len(entries) > 128
    ):
        raise BuildRegistryProvenanceV2Error(
            f"{label} must contain 1 to 128 keys"
        )
    hashes: set[str] = set()
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise BuildRegistryProvenanceV2Error(
                f"{label} key fields are invalid"
            )
        key_id = str(entry["key_id"])
        if ID_PATTERN.fullmatch(key_id) is None or key_id in seen:
            raise BuildRegistryProvenanceV2Error(
                f"{label} key_id is invalid or duplicated"
            )
        seen.add(key_id)
        if entry["purpose"] != expected_purpose:
            raise BuildRegistryProvenanceV2Error(
                f"{label} key purpose is invalid"
            )
        try:
            raw = base64.b64decode(
                entry["public_key_base64"],
                validate=True,
            )
        except (ValueError, TypeError, binascii.Error) as exc:
            raise BuildRegistryProvenanceV2Error(
                f"{label} public key is invalid"
            ) from exc
        if len(raw) != 32:
            raise BuildRegistryProvenanceV2Error(
                f"{label} public key must contain 32 bytes"
            )
        public_key_sha256 = _hash_bytes(raw)
        if public_key_sha256 in hashes:
            raise BuildRegistryProvenanceV2Error(
                f"{label} duplicates a public key"
            )
        hashes.add(public_key_sha256)
    return hashes


def load_excluded_authority_key_facts(
    *,
    t1_keyring_path: Path,
    expected_t1_keyring_sha256: str,
    l3_keyring_path: Path,
    expected_l3_keyring_sha256: str,
) -> tuple[list[str], dict[str, str]]:
    _validate_sha256(
        expected_t1_keyring_sha256,
        "expected T1 keyring SHA256",
    )
    _validate_sha256(
        expected_l3_keyring_sha256,
        "expected L3 keyring SHA256",
    )
    _t1_raw, t1_keyring = _load_json(
        t1_keyring_path,
        "excluded T1 authority keyring",
        private=True,
    )
    _l3_raw, l3_keyring = _load_json(
        l3_keyring_path,
        "excluded L3 authority keyring",
        private=True,
    )
    actual_t1 = _hash_bytes(canonical_json(t1_keyring))
    actual_l3 = _hash_bytes(canonical_json(l3_keyring))
    _compare(
        actual_t1,
        expected_t1_keyring_sha256,
        "independently pinned T1 authority keyring",
    )
    _compare(
        actual_l3,
        expected_l3_keyring_sha256,
        "independently pinned L3 authority keyring",
    )
    t1_hashes = _all_public_key_hashes(
        t1_keyring,
        "excluded T1 authority keyring",
        expected_schema_version=T1_KEYRING_VERSION,
        expected_purpose=T1_KEY_PURPOSE,
    )
    l3_hashes = _all_public_key_hashes(
        l3_keyring,
        "excluded L3 authority keyring",
        expected_schema_version=L3_KEYRING_VERSION,
        expected_purpose=L3_KEY_PURPOSE,
    )
    if t1_hashes & l3_hashes:
        raise BuildRegistryProvenanceV2Error(
            "T1 and L3 authority key domains reuse a public key"
        )
    combined = sorted(t1_hashes | l3_hashes)
    if len(combined) < 2:
        raise BuildRegistryProvenanceV2Error(
            "at least two distinct T1/L3 authority keys are required"
        )
    return combined, {
        "t1_release_keyring_sha256": actual_t1,
        "l3_release_keyring_sha256": actual_l3,
    }


def _validate_signer_independence(
    payload: dict[str, Any],
    provenance_public_key_hashes: set[str],
    excluded_authority_key_hashes: list[str],
    excluded_authority_keyring_sha256s: dict[str, str],
) -> None:
    signed_hashes = payload["excluded_authority_public_key_sha256s"]
    if signed_hashes != sorted(excluded_authority_key_hashes):
        raise BuildRegistryProvenanceV2Error(
            "excluded authority public-key hashes do not match"
        )
    if len(excluded_authority_key_hashes) < 2:
        raise BuildRegistryProvenanceV2Error(
            "at least two excluded authority public keys are required"
        )
    if (
        payload["excluded_authority_keyring_sha256s"]
        != excluded_authority_keyring_sha256s
    ):
        raise BuildRegistryProvenanceV2Error(
            "excluded authority keyring hashes do not match"
        )
    if provenance_public_key_hashes & set(excluded_authority_key_hashes):
        raise BuildRegistryProvenanceV2Error(
            "provenance keyring reuses an excluded authority public key"
        )


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("PENDING_")
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    return False


def _validate_permission_floor(payload: dict[str, Any]) -> None:
    for field in FALSE_AUTHORITY_FIELDS:
        if payload[field] is not False:
            raise BuildRegistryProvenanceV2Error(
                f"forbidden authority granted: {field}"
            )
    for field in ZERO_FACT_FIELDS:
        if type(payload[field]) is not int or payload[field] != 0:
            raise BuildRegistryProvenanceV2Error(
                f"non-zero execution fact is forbidden: {field}"
            )


def _validate_signing_tool_source_identity(
    payload: dict[str, Any],
    *,
    expected_signing_tool_source_sha256: str,
    expected_signing_tool_source_commit_sha: str,
) -> None:
    _validate_sha256(
        expected_signing_tool_source_sha256,
        "expected signing-tool source SHA256",
    )
    _validate_commit(
        expected_signing_tool_source_commit_sha,
        "expected signing-tool source commit",
    )
    identity = payload["signing_tool_source_identity"]
    if (
        identity["path"] != SIGNING_TOOL_SOURCE_PATH
        or identity["verification_scope"] != SIGNING_TOOL_IDENTITY_SCOPE
    ):
        raise BuildRegistryProvenanceV2Error(
            "signing-tool source identity scope is invalid"
        )
    _compare(
        str(identity["sha256"]),
        expected_signing_tool_source_sha256,
        "independently pinned signing-tool source SHA256",
    )
    _compare(
        str(identity["source_commit_sha"]),
        expected_signing_tool_source_commit_sha,
        "independently pinned signing-tool source commit",
    )


def _validate_content_bindings(
    payload: dict[str, Any],
    content_raw: bytes,
    content: dict[str, Any],
) -> None:
    _validate_schema(
        content,
        CONTENT_ATTESTATION_SCHEMA_PATH,
        "query-v3 OCI content attestation",
    )
    if (
        content.get("schema_version")
        != CONTENT_ATTESTATION_SCHEMA_VERSION
    ):
        raise BuildRegistryProvenanceV2Error(
            "query-v3 content attestation schema version is invalid"
        )
    _compare(
        _hash_bytes(content_raw),
        payload["content_attestation_raw_sha256"],
        "content attestation raw SHA256",
    )
    _compare(
        _hash_bytes(canonical_json(content)),
        payload["content_attestation_canonical_sha256"],
        "content attestation canonical SHA256",
    )
    direct_bindings = {
        "runtime_source_commit_sha": "source_commit_sha",
        "source_bundle_archive_sha256": "source_bundle_archive_sha256",
        "source_manifest_raw_sha256": "source_manifest_raw_sha256",
        "source_manifest_canonical_sha256": (
            "source_manifest_canonical_sha256"
        ),
        "source_manifest_schema_sha256": (
            "source_manifest_schema_sha256"
        ),
        "oci_layout_archive_sha256": "oci_layout_archive_sha256",
        "containerfile_sha256": "containerfile_sha256",
        "image_reference": "image_reference",
        "image_digest": "image_digest",
        "image_id": "image_id",
        "runtime_bundle_index_sha256": "runtime_bundle_index_sha256",
        "content_attestation_schema_sha256": (
            "attestation_schema_sha256"
        ),
        "content_verifier_sha256": "verifier_sha256",
    }
    for provenance_field, content_field in direct_bindings.items():
        _compare(
            str(payload[provenance_field]),
            str(content[content_field]),
            provenance_field,
        )
    runtime_bundle_index = _hash_bytes(
        canonical_json(content["runtime_bundle_sha256"])
    )
    _compare(
        runtime_bundle_index,
        str(content["runtime_bundle_index_sha256"]),
        "content runtime bundle self-index",
    )


def _validate_time_order(
    payload: dict[str, Any],
    content: dict[str, Any],
    *,
    now: datetime,
) -> None:
    issued_at = parse_datetime(payload["issued_at"], "issued_at")
    build_started = parse_datetime(
        payload["build"]["started_at"],
        "build.started_at",
    )
    build_completed = parse_datetime(
        payload["build"]["completed_at"],
        "build.completed_at",
    )
    pushed_at = parse_datetime(
        payload["registry"]["pushed_at"],
        "registry.pushed_at",
    )
    observed_at = parse_datetime(
        payload["registry"]["observed_at"],
        "registry.observed_at",
    )
    content_captured = parse_datetime(
        content["evidence_captured_at"],
        "content.evidence_captured_at",
    )
    if not build_started < build_completed:
        raise BuildRegistryProvenanceV2Error(
            "build start must precede completion"
        )
    if build_completed - build_started > MAX_BUILD_DURATION:
        raise BuildRegistryProvenanceV2Error(
            "build duration exceeds six hours"
        )
    if not build_completed <= pushed_at <= observed_at <= issued_at:
        raise BuildRegistryProvenanceV2Error(
            "build, push, observation and issuance times are inconsistent"
        )
    if not build_completed <= content_captured <= issued_at:
        raise BuildRegistryProvenanceV2Error(
            "content attestation capture time is inconsistent"
        )
    newest_evidence = max(observed_at, content_captured)
    if issued_at - newest_evidence > MAX_ISSUANCE_DELAY:
        raise BuildRegistryProvenanceV2Error(
            "provenance was issued more than 24 hours after evidence"
        )
    if issued_at > now + MAX_FUTURE_SKEW:
        raise BuildRegistryProvenanceV2Error(
            "provenance issued_at is in the future"
        )


def _aware_utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise BuildRegistryProvenanceV2Error(
            "now must include an explicit timezone"
        )
    return now.astimezone(timezone.utc)


def validate_provenance_semantics(
    payload: dict[str, Any],
    content_raw: bytes,
    content: dict[str, Any],
    *,
    expected_runtime_source_commit_sha: str,
    expected_image_digest: str,
    expected_signing_tool_source_sha256: str,
    expected_signing_tool_source_commit_sha: str,
    now: datetime | None = None,
) -> None:
    if _contains_placeholder(payload):
        raise BuildRegistryProvenanceV2Error(
            "PENDING_ placeholders are forbidden"
        )
    if payload["schema_version"] != SCHEMA_VERSION:
        raise BuildRegistryProvenanceV2Error(
            "provenance v2 schema version is invalid"
        )
    if (
        payload["candidate_id"] != CANDIDATE_ID
        or payload["purpose"] != PURPOSE
        or payload["external_fact_scope"] != EXTERNAL_FACT_SCOPE
    ):
        raise BuildRegistryProvenanceV2Error(
            "provenance identity or scope is invalid"
        )
    for field in ("provenance_id", "signer_key_id"):
        if ID_PATTERN.fullmatch(str(payload[field])) is None:
            raise BuildRegistryProvenanceV2Error(f"{field} is invalid")
    _validate_commit(
        expected_runtime_source_commit_sha,
        "expected runtime source commit",
    )
    if OCI_DIGEST_PATTERN.fullmatch(expected_image_digest) is None:
        raise BuildRegistryProvenanceV2Error(
            "expected image digest is invalid"
        )
    _compare(
        payload["runtime_source_commit_sha"],
        expected_runtime_source_commit_sha,
        "expected runtime source commit",
    )
    _compare(
        payload["image_digest"],
        expected_image_digest,
        "expected image digest",
    )
    _validate_permission_floor(payload)
    _validate_signing_tool_source_identity(
        payload,
        expected_signing_tool_source_sha256=(
            expected_signing_tool_source_sha256
        ),
        expected_signing_tool_source_commit_sha=(
            expected_signing_tool_source_commit_sha
        ),
    )
    _validate_runtime_file_hashes(payload)
    _validate_content_bindings(payload, content_raw, content)

    build = payload["build"]
    registry = payload["registry"]
    _compare(
        build["output_oci_layout_archive_sha256"],
        payload["oci_layout_archive_sha256"],
        "build OCI layout archive",
    )
    _compare(
        build["output_image_digest"],
        payload["image_digest"],
        "build image digest",
    )
    _compare(
        build["output_image_id"],
        payload["image_id"],
        "build image ID",
    )
    _compare(
        registry["manifest_digest"],
        payload["image_digest"],
        "registry manifest digest",
    )
    _compare(
        registry["immutable_reference"],
        payload["image_reference"],
        "registry immutable reference",
    )
    _compare(
        f"{registry['repository']}@{payload['image_digest']}",
        payload["image_reference"],
        "registry repository/digest reference",
    )
    try:
        _validate_time_order(
            payload,
            content,
            now=_aware_utc_now(now),
        )
    except OneShotError as exc:
        raise BuildRegistryProvenanceV2Error(str(exc)) from exc


def verify_provenance(
    provenance_path: Path,
    trusted_keyring_path: Path,
    content_attestation_path: Path,
    *,
    expected_trusted_keyring_sha256: str,
    expected_runtime_source_commit_sha: str,
    expected_image_digest: str,
    expected_signing_tool_source_sha256: str,
    expected_signing_tool_source_commit_sha: str,
    excluded_authority_key_hashes: list[str],
    excluded_authority_keyring_sha256s: dict[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    provenance_raw, provenance = _load_json(
        provenance_path,
        "signed query-v3 build and registry provenance v2",
    )
    _keyring_raw, keyring = _load_json(
        trusted_keyring_path,
        "build and registry provenance trusted keyring",
        private=True,
    )
    content_raw, content = _load_json(
        content_attestation_path,
        "query-v3 OCI content attestation",
    )
    _validate_schema(
        provenance,
        PROVENANCE_SCHEMA_PATH,
        "signed query-v3 build and registry provenance v2",
    )
    _validate_sha256(
        expected_trusted_keyring_sha256,
        "expected trusted keyring SHA256",
    )
    keyring_sha256 = _hash_bytes(canonical_json(keyring))
    _compare(
        keyring_sha256,
        expected_trusted_keyring_sha256,
        "independently pinned trusted keyring",
    )
    _compare(
        keyring_sha256,
        provenance["trusted_keyring_sha256"],
        "provenance trusted keyring",
    )
    public_key, provenance_key_hashes = _load_public_keyset(
        keyring,
        str(provenance["signer_key_id"]),
    )
    _validate_signer_independence(
        provenance,
        provenance_key_hashes,
        excluded_authority_key_hashes,
        excluded_authority_keyring_sha256s,
    )
    try:
        signature = base64.b64decode(
            provenance["signature"],
            validate=True,
        )
        if len(signature) != 64:
            raise ValueError
        public_key.verify(
            signature,
            canonical_json(unsigned_provenance_payload(provenance)),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise BuildRegistryProvenanceV2Error(
            "build and registry provenance v2 signature is invalid"
        ) from exc
    validate_provenance_semantics(
        provenance,
        content_raw,
        content,
        expected_runtime_source_commit_sha=(
            expected_runtime_source_commit_sha
        ),
        expected_image_digest=expected_image_digest,
        expected_signing_tool_source_sha256=(
            expected_signing_tool_source_sha256
        ),
        expected_signing_tool_source_commit_sha=(
            expected_signing_tool_source_commit_sha
        ),
        now=now,
    )
    verified_at = _aware_utc_now(now)
    identity = provenance["signing_tool_source_identity"]
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "status": RECEIPT_STATUS,
        "provenance_id": provenance["provenance_id"],
        "verified_at": verified_at.isoformat(),
        "signed_provenance_raw_sha256": _hash_bytes(provenance_raw),
        "signed_provenance_canonical_sha256": _hash_bytes(
            canonical_json(provenance)
        ),
        "content_attestation_raw_sha256": _hash_bytes(content_raw),
        "content_attestation_canonical_sha256": _hash_bytes(
            canonical_json(content)
        ),
        "trusted_keyring_sha256": keyring_sha256,
        "excluded_authority_keyring_sha256s": (
            provenance["excluded_authority_keyring_sha256s"]
        ),
        "excluded_authority_public_key_sha256s": (
            provenance["excluded_authority_public_key_sha256s"]
        ),
        "signer_key_id": provenance["signer_key_id"],
        "signer_public_key_sha256": _hash_bytes(
            public_key.public_bytes_raw()
        ),
        "signing_tool_source_path": identity["path"],
        "signing_tool_source_commit_sha": identity[
            "source_commit_sha"
        ],
        "signing_tool_source_sha256": identity["sha256"],
        "signing_tool_source_pin_verified": True,
        "signing_tool_source_bytes_revalidated_at_runtime": False,
        "signing_tool_execution_independently_verified": False,
        "runtime_source_commit_sha": provenance[
            "runtime_source_commit_sha"
        ],
        "source_bundle_archive_sha256": provenance[
            "source_bundle_archive_sha256"
        ],
        "source_manifest_canonical_sha256": provenance[
            "source_manifest_canonical_sha256"
        ],
        "image_reference": provenance["image_reference"],
        "image_digest": provenance["image_digest"],
        "signed_build_assertion_verified": True,
        "signed_registry_assertion_verified": True,
        "external_facts_independently_reverified": False,
        "receipt_is_authority": False,
        **{field: False for field in FALSE_AUTHORITY_FIELDS},
        **{field: 0 for field in ZERO_FACT_FIELDS},
    }
    _validate_schema(
        receipt,
        RECEIPT_SCHEMA_PATH,
        "build and registry provenance v2 receipt",
    )
    return receipt


def write_json_create_only(
    path: Path,
    payload: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                payload,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    directory = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument("--expected-trusted-keyring-sha256", required=True)
    parser.add_argument("--content-attestation", type=Path, required=True)
    parser.add_argument(
        "--expected-runtime-source-commit-sha",
        required=True,
    )
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument(
        "--expected-signing-tool-source-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-signing-tool-source-commit-sha",
        required=True,
    )
    parser.add_argument("--t1-authority-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-t1-authority-keyring-sha256",
        required=True,
    )
    parser.add_argument("--l3-authority-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-l3-authority-keyring-sha256",
        required=True,
    )
    parser.add_argument("--json-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        excluded_hashes, excluded_keyring_hashes = (
            load_excluded_authority_key_facts(
                t1_keyring_path=args.t1_authority_keyring,
                expected_t1_keyring_sha256=(
                    args.expected_t1_authority_keyring_sha256
                ),
                l3_keyring_path=args.l3_authority_keyring,
                expected_l3_keyring_sha256=(
                    args.expected_l3_authority_keyring_sha256
                ),
            )
        )
        receipt = verify_provenance(
            args.provenance,
            args.trusted_keyring,
            args.content_attestation,
            expected_trusted_keyring_sha256=(
                args.expected_trusted_keyring_sha256
            ),
            expected_runtime_source_commit_sha=(
                args.expected_runtime_source_commit_sha
            ),
            expected_image_digest=args.expected_image_digest,
            expected_signing_tool_source_sha256=(
                args.expected_signing_tool_source_sha256
            ),
            expected_signing_tool_source_commit_sha=(
                args.expected_signing_tool_source_commit_sha
            ),
            excluded_authority_key_hashes=excluded_hashes,
            excluded_authority_keyring_sha256s=excluded_keyring_hashes,
        )
        if args.json_output is not None:
            write_json_create_only(args.json_output, receipt)
    except (
        BuildRegistryProvenanceV2Error,
        OSError,
        ValueError,
    ) as exc:
        print(
            f"build/registry provenance v2 verification failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"status={receipt['status']}")
    print(f"provenance_id={receipt['provenance_id']}")
    print("readiness_authorized=false")
    print("production_query_authorized=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
