#!/usr/bin/env python3
"""Offline verification for C_FAST query-v3 exact-evidence P0 acceptance v2."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
from pathlib import Path
import re
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from commodity_c_fast_readonly_deployment_outcome import (
    OUTCOME_KEYRING_VERSION,
    OUTCOME_KEY_PURPOSE,
    unsigned_outcome_payload,
)
from commodity_c_fast_readonly_deployment_release import (
    TRUSTED_KEYRING_VERSION as L3_KEYRING_VERSION,
    TRUSTED_KEY_PURPOSE as L3_KEY_PURPOSE,
    unsigned_release_payload as unsigned_l3_release_payload,
)
from commodity_c_fast_t1_build_registry_provenance import (
    KEYRING_VERSION as PROVENANCE_KEYRING_VERSION,
    KEY_PURPOSE as PROVENANCE_KEY_PURPOSE,
    unsigned_provenance_payload,
)
from commodity_c_fast_t1_one_shot import (
    ArtifactPaths,
    EVIDENCE_SCHEMA_PATH,
    LEGACY_EVIDENCE_SCHEMA_PATH,
    MANIFEST_SCHEMA_PATH,
    MAX_JSON_BYTES,
    READONLY_PROOF_SCHEMA_PATH,
    OneShotError,
    VerifiedRelease,
    canonical_json,
    parse_child_invocation_bytes,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    release_attempt_id,
    validate_completed_outputs,
    validate_json_schema,
)
from commodity_c_fast_t1_query_v3 import (
    AUDIT_SCRIPT_PATH,
    CHILD_STARTED_SCHEMA_PATH,
    CONSUME_SCHEMA_PATH,
    FALSE_AUTHORITY_FIELDS as QUERY_FALSE_AUTHORITY_FIELDS,
    PARENT_RUNNER_PATH,
    QUERY_CHILD_PATH,
    QUERY_KEYRING_SCHEMA_PATH,
    READINESS_SCHEMA_PATH,
    READINESS_VERIFIER_PATH,
    RELEASE_PURPOSE,
    RELEASE_SCHEMA_PATH,
    RELEASE_SCHEMA_VERSION,
    TERMINAL_SCHEMA_PATH,
    TRUE_AUTHORITY_FIELDS as QUERY_TRUE_AUTHORITY_FIELDS,
    TRUSTED_KEY_PURPOSE as QUERY_KEY_PURPOSE,
)


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-p0-acceptance-v2.schema.json"
)
CONTENT_ATTESTATION_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-image-attestation-v1.schema.json"
)
PROVENANCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-build-registry-provenance-v1.schema.json"
)
OUTCOME_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-readonly-deployment-outcome-v1.schema.json"
)
L3_RELEASE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-readonly-deployment-release-v1.schema.json"
)

ACCEPTANCE_SCHEMA_VERSION = "commodity_c_fast_p0_acceptance_v2"
ACCEPTANCE_PURPOSE = "c_fast_query_v3_p0_exact_evidence_acceptance"
ACCEPTANCE_KEYRING_VERSION = (
    "commodity_c_fast_p0_acceptance_v2_trusted_keys_v1"
)
ACCEPTANCE_KEY_PURPOSE = "c_fast_query_v3_p0_acceptance_v2_signer"
QUERY_KEYRING_VERSION = "commodity_c_fast_t1_query_v3_trusted_keys_v1"
T1_KEYRING_VERSION = "commodity_c_fast_t1_trusted_keys_v1"
T1_KEY_PURPOSE = "t1_audit_release_signer"
EXTERNAL_CUSTODY_IDENTITY_VERSION = (
    "commodity_c_fast_p0_external_custody_identity_v1"
)
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
TERMINAL_PASS_STATE = "COMPLETED_EVIDENCE_P0_PASS"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TERMINAL_OVERHEAD = timedelta(minutes=5)

BUNDLE_FILE_ORDER = (
    "query_release",
    "query_trusted_keyring",
    "readiness_packet",
    "content_attestation",
    "provenance",
    "provenance_trusted_keyring",
    "t1_trusted_keyring",
    "l3_trusted_keyring",
    "l3_release",
    "outcome",
    "outcome_trusted_keyring",
    "manifest",
    "consume_marker",
    "child_launch_marker",
    "audit_child_invocation",
    "pre_connect_gate",
    "query_child_invocation",
    "terminal_seal",
    "audit_json",
    "audit_csv",
    "audit_markdown",
    "readonly_proof",
)
JSON_BUNDLE_FILES = frozenset(BUNDLE_FILE_ORDER) - {
    "audit_csv",
    "audit_markdown",
}
UPSTREAM_PIN_FIELDS = {
    "query": "query_trusted_keyring_sha256",
    "provenance": "provenance_trusted_keyring_sha256",
    "t1": "t1_trusted_keyring_sha256",
    "l3": "l3_trusted_keyring_sha256",
    "outcome": "outcome_trusted_keyring_sha256",
}
ACCEPTANCE_FALSE_AUTHORITY_FIELDS = (
    "acceptance_is_authority",
    "query_authorized",
    "t1_one_shot_child_launch_authorized",
    "replay_allowed",
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
    "web_bridge_rpc_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "strategy_activation_authorized",
    "replacement_authorized",
    "production_authorized",
    "automatic_promotion_authorized",
    "dynamic_selection_allowed",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "readonly_principal_deployment_authorized",
    "readonly_secret_file_installation_authorized",
    "questdb_restart_authorized",
    "questdb_recreate_authorized",
    "questdb_image_change_authorized",
    "writer_identity_mutation_authorized",
    "writer_secret_mutation_authorized",
    "network_mutation_authorized",
    "unscoped_deployment_mutation_authorized",
    "web_bridge_deployment_authorized",
)


class P0AcceptanceV2Error(RuntimeError):
    """Expected fail-closed acceptance-v2 error."""


@dataclass(frozen=True)
class P0BundleV2Paths:
    query_release: Path
    query_trusted_keyring: Path
    readiness_packet: Path
    content_attestation: Path
    provenance: Path
    provenance_trusted_keyring: Path
    t1_trusted_keyring: Path
    l3_trusted_keyring: Path
    l3_release: Path
    outcome: Path
    outcome_trusted_keyring: Path
    manifest: Path
    consume_marker: Path
    child_launch_marker: Path
    audit_child_invocation: Path
    pre_connect_gate: Path
    query_child_invocation: Path
    terminal_seal: Path
    audit_json: Path
    audit_csv: Path
    audit_markdown: Path
    readonly_proof: Path
    external_custody_identity: Path


@dataclass(frozen=True)
class VerifiedP0BundleV2:
    payloads: dict[str, Any]
    raw_sha256: dict[str, str]
    canonical_sha256: dict[str, str]
    artifact_sha256: dict[str, str]
    bundle_index_sha256: str
    keyring_sha256: dict[str, str]
    upstream_public_key_materials: frozenset[bytes]
    external_custody_identity: dict[str, Any]
    external_custody_identity_raw_sha256: str
    external_custody_identity_canonical_sha256: str


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compare(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise P0AcceptanceV2Error(f"{label} binding mismatch")


def _validate_sha256(value: str, label: str) -> None:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise P0AcceptanceV2Error(f"{label} must be a lowercase SHA256")


def unsigned_acceptance_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def acceptance_sha256(payload: dict[str, Any]) -> str:
    return _hash(canonical_json(payload))


def acceptance_id_for_terminal(terminal_raw_sha256: str) -> str:
    _validate_sha256(terminal_raw_sha256, "query terminal raw")
    return f"p0-v2-accept-{terminal_raw_sha256}"


def _load_keyring(
    payload: dict[str, Any],
    *,
    expected_version: str,
    required_purpose: str,
    key_id: str | None,
    label: str,
) -> tuple[Ed25519PublicKey | None, frozenset[bytes]]:
    if set(payload) != {"schema_version", "keys"}:
        raise P0AcceptanceV2Error(f"{label} fields are invalid")
    if payload["schema_version"] != expected_version:
        raise P0AcceptanceV2Error(f"{label} schema version is invalid")
    entries = payload["keys"]
    if not isinstance(entries, list) or not entries:
        raise P0AcceptanceV2Error(f"{label} must contain keys")
    seen_ids: set[str] = set()
    materials: set[bytes] = set()
    selected: bytes | None = None
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise P0AcceptanceV2Error(f"{label} key entry is invalid")
        current_id = str(entry["key_id"])
        if current_id in seen_ids:
            raise P0AcceptanceV2Error(f"{label} contains duplicate key_id")
        seen_ids.add(current_id)
        if entry["purpose"] != required_purpose:
            raise P0AcceptanceV2Error(f"{label} key purpose is invalid")
        try:
            raw = base64.b64decode(
                str(entry["public_key_base64"]),
                validate=True,
            )
            if len(raw) != 32:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise P0AcceptanceV2Error(
                f"{label} Ed25519 public key is invalid"
            ) from exc
        if raw in materials:
            raise P0AcceptanceV2Error(
                f"{label} reuses public-key material across key IDs"
            )
        materials.add(raw)
        if current_id == key_id:
            selected = raw
    if key_id is not None and selected is None:
        raise P0AcceptanceV2Error(f"{label} signer key is not trusted")
    return (
        Ed25519PublicKey.from_public_bytes(selected)
        if selected is not None
        else None,
        frozenset(materials),
    )


def _verify_ed25519(
    public_key: Ed25519PublicKey,
    signature_text: Any,
    message: bytes,
    label: str,
) -> None:
    try:
        signature = base64.b64decode(str(signature_text), validate=True)
        if len(signature) != 64:
            raise ValueError
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise P0AcceptanceV2Error(f"{label} signature is invalid") from exc


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def require_independent_acceptance_signer(
    upstream_public_key_materials: frozenset[bytes],
    acceptance_signer: Ed25519PublicKey,
) -> None:
    signer = _public_key_bytes(acceptance_signer)
    if any(
        hmac.compare_digest(signer, upstream)
        for upstream in upstream_public_key_materials
    ):
        raise P0AcceptanceV2Error(
            "acceptance-v2 signer reuses an active or unused upstream key"
        )


def _read_bundle_raw(paths: P0BundleV2Paths) -> dict[str, bytes]:
    limits = {
        name: (
            MAX_ARTIFACT_BYTES
            if name
            in {
                "audit_json",
                "audit_csv",
                "audit_markdown",
                "readonly_proof",
            }
            else MAX_JSON_BYTES
        )
        for name in BUNDLE_FILE_ORDER
    }
    private_roles = {
        "query_trusted_keyring",
        "provenance_trusted_keyring",
        "t1_trusted_keyring",
        "l3_trusted_keyring",
        "outcome_trusted_keyring",
    }
    identities: dict[tuple[int, int], str] = {}
    result: dict[str, bytes] = {}
    for name in BUNDLE_FILE_ORDER:
        path = getattr(paths, name)
        observed = path.stat()
        identity = (observed.st_dev, observed.st_ino)
        if identity in identities:
            raise P0AcceptanceV2Error(
                f"bundle roles {identities[identity]} and {name} alias"
            )
        identities[identity] = name
        result[name] = read_regular_file_strict(
            path,
            name,
            limit=limits[name],
            private=name in private_roles,
        )
    return result


def _bundle_index_sha256(raw_files: dict[str, bytes]) -> str:
    if tuple(raw_files) != BUNDLE_FILE_ORDER:
        raise P0AcceptanceV2Error("query-v3 bundle file order is invalid")
    parsed = _parse_payloads(raw_files)
    index = {
        "schema_version": "commodity_c_fast_p0_bundle_index_v2",
        "files": [
            {
                "name": name,
                "size_bytes": len(raw_files[name]),
                "raw_sha256": _hash(raw_files[name]),
                "canonical_sha256": (
                    _hash(canonical_json(parsed[name]))
                    if name in JSON_BUNDLE_FILES
                    else None
                ),
            }
            for name in BUNDLE_FILE_ORDER
        ],
    }
    return _hash(canonical_json(index))


def _parse_payloads(raw_files: dict[str, bytes]) -> dict[str, Any]:
    invocations = {"audit_child_invocation", "query_child_invocation"}
    return {
        name: (
            parse_child_invocation_bytes(raw_files[name], name)
            if name in invocations
            else parse_json_bytes(raw_files[name], name)
        )
        for name in JSON_BUNDLE_FILES
    }


def _expected_readiness_binding(
    readiness: dict[str, Any],
    *,
    raw_sha256: str,
    canonical_sha256: str,
) -> dict[str, Any]:
    runtime = readiness["t1_runtime"]
    provenance = readiness["build_registry_provenance"]
    outcome = readiness["readonly_deployment_outcome"]
    return {
        "packet_id": readiness["packet_id"],
        "packet_raw_sha256": raw_sha256,
        "packet_canonical_sha256": canonical_sha256,
        "generated_at": readiness["generated_at"],
        "expires_at": readiness["expires_at"],
        "content_attestation_raw_sha256": runtime[
            "content_attestation_raw_sha256"
        ],
        "content_attestation_canonical_sha256": runtime[
            "content_attestation_canonical_sha256"
        ],
        "provenance_raw_sha256": provenance[
            "signed_provenance_raw_sha256"
        ],
        "provenance_canonical_sha256": provenance[
            "signed_provenance_canonical_sha256"
        ],
        "provenance_signer_public_key_sha256": provenance[
            "signer_public_key_sha256"
        ],
        "outcome_raw_sha256": outcome["signed_outcome_raw_sha256"],
        "outcome_canonical_sha256": outcome[
            "signed_outcome_canonical_sha256"
        ],
        "outcome_signer_public_key_sha256": outcome[
            "signer_public_key_sha256"
        ],
    }


def _readiness_source_index(
    readiness: dict[str, Any],
    *,
    raw_sha256: str,
    canonical_sha256: str,
) -> str:
    return _hash(
        canonical_json(
            {
                "readiness_packet_raw_sha256": raw_sha256,
                "readiness_packet_canonical_sha256": canonical_sha256,
                "t1_runtime": readiness["t1_runtime"],
                "build_registry_provenance": readiness[
                    "build_registry_provenance"
                ],
                "readonly_deployment_outcome": readiness[
                    "readonly_deployment_outcome"
                ],
            }
        )
    )


def _validate_query_release(
    release: dict[str, Any],
    readiness: dict[str, Any],
    raw_sha256: dict[str, str],
    canonical_sha256: dict[str, str],
) -> tuple[datetime, datetime, datetime]:
    if (
        release.get("schema_version") != RELEASE_SCHEMA_VERSION
        or release.get("purpose") != RELEASE_PURPOSE
        or release.get("candidate_id") != CANDIDATE_ID
    ):
        raise P0AcceptanceV2Error("query-v3 release identity is invalid")
    validate_json_schema(release, RELEASE_SCHEMA_PATH, "query-v3 release")
    if (
        release["schema_version"] != RELEASE_SCHEMA_VERSION
        or release["purpose"] != RELEASE_PURPOSE
        or release["candidate_id"] != CANDIDATE_ID
        or release["parent_issue_number"] != 114
        or release["issue_number"] != 135
    ):
        raise P0AcceptanceV2Error("query-v3 release identity is invalid")
    if release["attempt_id"] != release_attempt_id(release["release_id"]):
        raise P0AcceptanceV2Error("query-v3 release attempt_id is invalid")
    if (
        not str(release["human_signature"]).strip()
        or str(release["human_signature"]).strip().startswith("PENDING_")
        or not str(release["reviewer_role"]).strip()
        or str(release["reviewer_role"]).strip().startswith("PENDING_")
    ):
        raise P0AcceptanceV2Error("query-v3 final human review is missing")
    issued_at = parse_datetime(release["issued_at"], "release.issued_at")
    not_before = parse_datetime(release["not_before"], "release.not_before")
    expires_at = parse_datetime(release["expires_at"], "release.expires_at")
    readiness_generated = parse_datetime(
        readiness["generated_at"],
        "readiness.generated_at",
    )
    readiness_expires = parse_datetime(
        readiness["expires_at"],
        "readiness.expires_at",
    )
    if (
        not readiness_generated <= issued_at <= not_before < expires_at
        or expires_at - issued_at > timedelta(minutes=10)
        or expires_at > readiness_expires
    ):
        raise P0AcceptanceV2Error("historical release/readiness time is invalid")
    expected_binding = _expected_readiness_binding(
        readiness,
        raw_sha256=raw_sha256["readiness_packet"],
        canonical_sha256=canonical_sha256["readiness_packet"],
    )
    if release["readiness"] != expected_binding:
        raise P0AcceptanceV2Error("release does not bind exact readiness")
    if (
        release["readiness_source_bundle_index_sha256"]
        != _readiness_source_index(
            readiness,
            raw_sha256=raw_sha256["readiness_packet"],
            canonical_sha256=canonical_sha256["readiness_packet"],
        )
        or release["namespaces"]
        != {
            **readiness["source_namespaces"],
            **readiness["digest_namespaces"],
        }
    ):
        raise P0AcceptanceV2Error(
            "release readiness source index/namespace is invalid"
        )
    if any(release[field] is not True for field in QUERY_TRUE_AUTHORITY_FIELDS):
        raise P0AcceptanceV2Error("release lacks narrow query-v3 authority")
    if any(
        release[field] is not False for field in QUERY_FALSE_AUTHORITY_FIELDS
    ):
        raise P0AcceptanceV2Error("release grants forbidden authority")
    return not_before, expires_at, readiness_expires


def _validate_exact_sources(
    payloads: dict[str, Any],
    raw_sha256: dict[str, str],
    canonical_sha256: dict[str, str],
) -> None:
    readiness = payloads["readiness_packet"]
    content = payloads["content_attestation"]
    provenance = payloads["provenance"]
    l3_release = payloads["l3_release"]
    outcome = payloads["outcome"]
    expected_identities = (
        (
            readiness,
            "schema_version",
            "commodity_c_fast_t1_readiness_v2",
            "readiness-v2 packet",
        ),
        (
            content,
            "schema_version",
            "commodity_c_fast_t1_image_attestation_v1",
            "content attestation",
        ),
        (
            provenance,
            "schema_version",
            "commodity_c_fast_t1_build_registry_provenance_v1",
            "signed provenance",
        ),
        (
            provenance,
            "purpose",
            "c_fast_t1_external_build_registry_provenance",
            "signed provenance",
        ),
        (
            l3_release,
            "schema_version",
            "commodity_c_fast_readonly_deployment_release_v1",
            "signed L3 deployment release",
        ),
        (
            l3_release,
            "purpose",
            "c_fast_questdb_readonly_principal_deployment",
            "signed L3 deployment release",
        ),
        (
            outcome,
            "schema_version",
            "commodity_c_fast_readonly_deployment_outcome_v1",
            "signed deployment outcome",
        ),
        (
            outcome,
            "purpose",
            "c_fast_questdb_readonly_deployment_post_outcome",
            "signed deployment outcome",
        ),
    )
    for payload, field, expected, label in expected_identities:
        if payload.get(field) != expected:
            raise P0AcceptanceV2Error(f"{label} identity is invalid")
    validate_json_schema(
        readiness,
        READINESS_SCHEMA_PATH,
        "readiness-v2 packet",
    )
    validate_json_schema(
        content,
        CONTENT_ATTESTATION_SCHEMA_PATH,
        "content attestation",
    )
    validate_json_schema(
        provenance,
        PROVENANCE_SCHEMA_PATH,
        "signed provenance",
    )
    validate_json_schema(
        l3_release,
        L3_RELEASE_SCHEMA_PATH,
        "signed L3 deployment release",
    )
    validate_json_schema(
        outcome,
        OUTCOME_SCHEMA_PATH,
        "signed deployment outcome",
    )
    runtime = readiness["t1_runtime"]
    provenance_binding = readiness["build_registry_provenance"]
    outcome_binding = readiness["readonly_deployment_outcome"]
    pairs = {
        "content attestation raw": (
            raw_sha256["content_attestation"],
            runtime["content_attestation_raw_sha256"],
        ),
        "content attestation canonical": (
            canonical_sha256["content_attestation"],
            runtime["content_attestation_canonical_sha256"],
        ),
        "provenance raw": (
            raw_sha256["provenance"],
            provenance_binding["signed_provenance_raw_sha256"],
        ),
        "provenance canonical": (
            canonical_sha256["provenance"],
            provenance_binding["signed_provenance_canonical_sha256"],
        ),
        "outcome raw": (
            raw_sha256["outcome"],
            outcome_binding["signed_outcome_raw_sha256"],
        ),
        "L3 release raw": (
            raw_sha256["l3_release"],
            outcome_binding["release_raw_sha256"],
        ),
        "L3 release canonical": (
            canonical_sha256["l3_release"],
            outcome_binding["release_canonical_sha256"],
        ),
        "outcome canonical": (
            canonical_sha256["outcome"],
            outcome_binding["signed_outcome_canonical_sha256"],
        ),
    }
    for label, (actual, expected) in pairs.items():
        _compare(actual, expected, label)
    for field in (
        "content_attestation_raw_sha256",
        "content_attestation_canonical_sha256",
    ):
        expected = (
            raw_sha256["content_attestation"]
            if field.endswith("raw_sha256")
            else canonical_sha256["content_attestation"]
        )
        _compare(provenance[field], expected, f"provenance {field}")
    if (
        content["source_commit_sha"]
        != readiness["source_namespaces"]["t1_runtime_source_commit_sha"]
        or content["image_digest"]
        != readiness["digest_namespaces"]["t1_runtime_image_digest"]
        or provenance["runtime_source_commit_sha"]
        != readiness["source_namespaces"]["t1_runtime_source_commit_sha"]
        or provenance["image_digest"]
        != readiness["digest_namespaces"]["t1_runtime_image_digest"]
        or outcome["outcome_contract_source_commit_assertion"]
        != readiness["source_namespaces"][
            "outcome_contract_source_commit_assertion"
        ]
        or outcome["questdb_image_digest"]
        != readiness["digest_namespaces"]["questdb_image_digest"]
        or outcome["release_raw_sha256"] != raw_sha256["l3_release"]
        or outcome["release_canonical_sha256"]
        != canonical_sha256["l3_release"]
        or l3_release["questdb_target_identity_sha256"]
        != outcome["questdb_target_identity_sha256"]
    ):
        raise P0AcceptanceV2Error("readiness exact source namespace mismatch")


def _verify_key_domains(
    payloads: dict[str, Any],
    expected_keyring_sha256: dict[str, str],
    readiness: dict[str, Any],
) -> tuple[dict[str, str], frozenset[bytes]]:
    for domain, value in expected_keyring_sha256.items():
        if domain not in UPSTREAM_PIN_FIELDS:
            raise P0AcceptanceV2Error("unexpected keyring pin domain")
        _validate_sha256(value, f"independently pinned {domain} keyring")
    if set(expected_keyring_sha256) != set(UPSTREAM_PIN_FIELDS):
        raise P0AcceptanceV2Error("all five keyring pins are required")
    specs = {
        "query": (
            "query_trusted_keyring",
            QUERY_KEYRING_VERSION,
            QUERY_KEY_PURPOSE,
            payloads["query_release"]["signer_key_id"],
        ),
        "provenance": (
            "provenance_trusted_keyring",
            PROVENANCE_KEYRING_VERSION,
            PROVENANCE_KEY_PURPOSE,
            payloads["provenance"]["signer_key_id"],
        ),
        "t1": (
            "t1_trusted_keyring",
            T1_KEYRING_VERSION,
            T1_KEY_PURPOSE,
            None,
        ),
        "l3": (
            "l3_trusted_keyring",
            L3_KEYRING_VERSION,
            L3_KEY_PURPOSE,
            payloads["l3_release"]["signer_key_id"],
        ),
        "outcome": (
            "outcome_trusted_keyring",
            OUTCOME_KEYRING_VERSION,
            OUTCOME_KEY_PURPOSE,
            payloads["outcome"]["signer_key_id"],
        ),
    }
    hashes: dict[str, str] = {}
    materials_by_domain: dict[str, frozenset[bytes]] = {}
    selected: dict[str, Ed25519PublicKey] = {}
    for domain, (name, version, purpose, key_id) in specs.items():
        payload = payloads[name]
        digest = _hash(canonical_json(payload))
        _compare(
            digest,
            expected_keyring_sha256[domain],
            f"independently pinned {domain} keyring",
        )
        public_key, materials = _load_keyring(
            payload,
            expected_version=version,
            required_purpose=purpose,
            key_id=str(key_id) if key_id is not None else None,
            label=f"{domain} keyring",
        )
        hashes[domain] = digest
        materials_by_domain[domain] = materials
        if public_key is not None:
            selected[domain] = public_key
    if any(
        left & right
        for index, left in enumerate(materials_by_domain.values())
        for right in list(materials_by_domain.values())[index + 1 :]
    ):
        raise P0AcceptanceV2Error(
            "query/upstream authority key domains reuse public material"
        )
    release = payloads["query_release"]
    provenance = payloads["provenance"]
    outcome = payloads["outcome"]
    expected_bindings = {
        "query": release["trusted_keyring_sha256"],
        "provenance": readiness["build_registry_provenance"][
            "provenance_keyring_sha256"
        ],
        "t1": readiness["build_registry_provenance"][
            "t1_authority_keyring_sha256"
        ],
        "l3": readiness["build_registry_provenance"][
            "l3_authority_keyring_sha256"
        ],
        "outcome": readiness["readonly_deployment_outcome"][
            "outcome_keyring_sha256"
        ],
    }
    for domain, expected in expected_bindings.items():
        _compare(hashes[domain], expected, f"{domain} source keyring")
    if (
        provenance["trusted_keyring_sha256"] != hashes["provenance"]
        or provenance["excluded_authority_keyring_sha256s"]
        != {
            "t1_release_keyring_sha256": hashes["t1"],
            "l3_release_keyring_sha256": hashes["l3"],
        }
        or outcome["outcome_keyring_sha256"] != hashes["outcome"]
        or outcome["release_keyring_sha256"] != hashes["l3"]
        or outcome["t1_keyring_sha256"] != hashes["t1"]
    ):
        raise P0AcceptanceV2Error("signed upstream keyring binding mismatch")
    _verify_ed25519(
        selected["query"],
        release["signature"],
        canonical_json(
            {key: value for key, value in release.items() if key != "signature"}
        ),
        "query-v3 release",
    )
    _verify_ed25519(
        selected["provenance"],
        provenance["signature"],
        canonical_json(unsigned_provenance_payload(provenance)),
        "provenance",
    )
    _verify_ed25519(
        selected["l3"],
        payloads["l3_release"]["signature"],
        canonical_json(
            unsigned_l3_release_payload(payloads["l3_release"])
        ),
        "L3 deployment release",
    )
    _verify_ed25519(
        selected["outcome"],
        outcome["signature"],
        canonical_json(unsigned_outcome_payload(outcome)),
        "deployment outcome",
    )
    signer_hashes = {
        "provenance": _hash(_public_key_bytes(selected["provenance"])),
        "outcome": _hash(_public_key_bytes(selected["outcome"])),
    }
    if (
        signer_hashes["provenance"]
        != readiness["build_registry_provenance"][
            "signer_public_key_sha256"
        ]
        or signer_hashes["outcome"]
        != readiness["readonly_deployment_outcome"][
            "signer_public_key_sha256"
        ]
    ):
        raise P0AcceptanceV2Error("readiness signer key binding mismatch")
    return hashes, frozenset().union(*materials_by_domain.values())


def _validate_runtime_bindings(release: dict[str, Any]) -> None:
    expected_files = {
        "parent_runner_sha256": PARENT_RUNNER_PATH,
        "query_child_sha256": QUERY_CHILD_PATH,
        "release_schema_sha256": RELEASE_SCHEMA_PATH,
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "child_started_schema_sha256": CHILD_STARTED_SCHEMA_PATH,
        "terminal_schema_sha256": TERMINAL_SCHEMA_PATH,
        "readiness_verifier_sha256": READINESS_VERIFIER_PATH,
        "readiness_schema_sha256": READINESS_SCHEMA_PATH,
        "query_keyring_schema_sha256": QUERY_KEYRING_SCHEMA_PATH,
        "audit_script_sha256": AUDIT_SCRIPT_PATH,
        "manifest_schema_sha256": MANIFEST_SCHEMA_PATH,
        "evidence_schema_sha256": EVIDENCE_SCHEMA_PATH,
        "legacy_evidence_schema_sha256": LEGACY_EVIDENCE_SCHEMA_PATH,
        "readonly_proof_schema_sha256": READONLY_PROOF_SCHEMA_PATH,
    }
    for field, path in expected_files.items():
        raw = read_regular_file_strict(
            path,
            field,
            limit=MAX_ARTIFACT_BYTES,
        )
        _compare(_hash(raw), release[field], field)


def _validate_consume_and_terminal(
    payloads: dict[str, Any],
    raw_sha256: dict[str, str],
    canonical_sha256: dict[str, str],
    keyring_sha256: dict[str, str],
    *,
    not_before: datetime,
    expires_at: datetime,
) -> None:
    release = payloads["query_release"]
    readiness = payloads["readiness_packet"]
    consume = payloads["consume_marker"]
    launch = payloads["child_launch_marker"]
    terminal = payloads["terminal_seal"]
    identities = (
        (
            consume,
            "commodity_c_fast_t1_query_consume_v3",
            "c_fast_t1_query_v3_consume_before_final_revalidation",
            "query-v3 consume",
        ),
        (
            launch,
            "commodity_c_fast_t1_query_child_started_v3",
            "c_fast_t1_one_shot_child_launch_claim_before_network",
            "query-v3 child launch",
        ),
        (
            terminal,
            "commodity_c_fast_t1_query_terminal_v3",
            "c_fast_t1_readonly_query_v3_terminal",
            "query-v3 terminal",
        ),
    )
    for payload, version, purpose, label in identities:
        if (
            payload.get("schema_version") != version
            or payload.get("purpose") != purpose
            or payload.get("candidate_id") != CANDIDATE_ID
        ):
            raise P0AcceptanceV2Error(f"{label} identity is invalid")
    validate_json_schema(consume, CONSUME_SCHEMA_PATH, "query-v3 consume")
    validate_json_schema(
        launch,
        CHILD_STARTED_SCHEMA_PATH,
        "query-v3 child launch",
    )
    validate_json_schema(terminal, TERMINAL_SCHEMA_PATH, "query-v3 terminal")
    for source in (consume, launch, terminal):
        if (
            source["candidate_id"] != CANDIDATE_ID
            or source["release_id"] != release["release_id"]
            or source["attempt_id"] != release["attempt_id"]
        ):
            raise P0AcceptanceV2Error("query-v3 identity splice detected")
    common = {
        "release_raw_sha256": raw_sha256["query_release"],
        "release_canonical_sha256": canonical_sha256["query_release"],
        "readiness_packet_raw_sha256": raw_sha256["readiness_packet"],
        "readiness_packet_canonical_sha256": canonical_sha256[
            "readiness_packet"
        ],
        "manifest_raw_sha256": raw_sha256["manifest"],
        "manifest_canonical_sha256": canonical_sha256["manifest"],
    }
    for field, expected in common.items():
        for source in (consume, terminal):
            if source[field] != expected:
                raise P0AcceptanceV2Error(f"{field} source mismatch")
        launch_field = (
            field
            if not field.startswith("readiness_")
            else field
        )
        if launch[launch_field] != expected:
            raise P0AcceptanceV2Error(f"child launch {field} mismatch")
    for field in (
        "content_attestation_raw_sha256",
        "content_attestation_canonical_sha256",
        "provenance_raw_sha256",
        "provenance_canonical_sha256",
        "outcome_raw_sha256",
        "outcome_canonical_sha256",
    ):
        if consume[field] != release["readiness"][field]:
            raise P0AcceptanceV2Error(f"consume {field} mismatch")
        if terminal[field] != release["readiness"][field]:
            raise P0AcceptanceV2Error(f"terminal {field} mismatch")
    if (
        consume["readiness_packet_id"] != readiness["packet_id"]
        or consume["trusted_keyring_sha256"] != keyring_sha256["query"]
        or launch["trusted_keyring_sha256"] != keyring_sha256["query"]
        or launch["consume_marker_raw_sha256"]
        != raw_sha256["consume_marker"]
        or launch["consume_marker_canonical_sha256"]
        != canonical_sha256["consume_marker"]
        or terminal["consume_marker_raw_sha256"]
        != raw_sha256["consume_marker"]
        or terminal["consume_marker_canonical_sha256"]
        != canonical_sha256["consume_marker"]
        or terminal["query_child_launch_marker_raw_sha256"]
        != raw_sha256["child_launch_marker"]
        or terminal["query_child_launch_marker_canonical_sha256"]
        != canonical_sha256["child_launch_marker"]
    ):
        raise P0AcceptanceV2Error("consume/launch/terminal exact binding mismatch")
    for field in (
        "custody_identity_sha256",
        "custody_path_sha256",
    ):
        if consume[field] != release[field] or launch[field] != release[field]:
            raise P0AcceptanceV2Error(f"{field} mismatch")
    if (
        consume["consume_precedes_final_revalidation"] is not True
        or consume["query_started"] is not False
        or consume["production_queried"] is not False
        or consume["consume_is_authority"] is not False
        or consume["replay_allowed"] is not False
        or launch["launch_claim_precedes_network"] is not True
        or launch["query_started"] is not False
        or launch["production_queried"] is not False
        or launch["launch_claim_is_authority"] is not False
        or launch["replay_allowed"] is not False
    ):
        raise P0AcceptanceV2Error("consume/launch authority semantics are invalid")
    if (
        terminal["terminal_state"] != TERMINAL_PASS_STATE
        or terminal["error_code"] is not None
        or terminal["child_exit_code"] != 0
        or terminal["query_execution_state"] != "COMPLETED"
        or terminal["production_query_attempted"] is not True
        or terminal["production_query_completed"] is not True
        or terminal["p0_pass"] is not True
        or terminal["proof_verified"] is not True
        or terminal["write_probe_attempted"] is not False
        or terminal["database_mutations_observed"] != 0
        or terminal["web_bridge_rpc_calls"] != 0
        or terminal["orders_sent"] != 0
        or terminal["positions_modified"] != 0
        or terminal["dispatch_changed"] is not False
        or terminal["terminal_is_authority"] is not False
        or terminal["p0_acceptance_authorized"] is not False
        or terminal["replay_allowed"] is not False
        or terminal["terminal_integrity_scope"]
        != "CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY"
    ):
        raise P0AcceptanceV2Error(
            "only completed query-v3 P0 PASS terminal is acceptable"
        )
    consumed_at = parse_datetime(consume["consumed_at"], "consume.consumed_at")
    started_at = parse_datetime(terminal["started_at"], "terminal.started_at")
    final_at = parse_datetime(
        terminal["final_revalidation_at"],
        "terminal.final_revalidation_at",
    )
    ended_at = parse_datetime(terminal["ended_at"], "terminal.ended_at")
    if (
        not not_before <= consumed_at < expires_at
        or started_at != consumed_at
        or not started_at <= final_at <= ended_at
        or ended_at - started_at
        > timedelta(seconds=release["max_runtime_seconds"])
        + MAX_TERMINAL_OVERHEAD
    ):
        raise P0AcceptanceV2Error("query-v3 historical timeline is invalid")


def _flag_values(invocation: Any, *, label: str) -> dict[str, str]:
    if (
        not isinstance(invocation, list)
        or len(invocation) < 5
        or not all(isinstance(value, str) for value in invocation)
        or invocation[1] != "-I"
        or len(invocation[3:]) % 2 != 0
    ):
        raise P0AcceptanceV2Error(f"{label} structure is invalid")
    values: dict[str, str] = {}
    for index in range(3, len(invocation), 2):
        flag = invocation[index]
        if not flag.startswith("--") or flag in values:
            raise P0AcceptanceV2Error(f"{label} flags are invalid")
        values[flag] = invocation[index + 1]
    return values


def _validate_invocations(
    payloads: dict[str, Any],
    raw_sha256: dict[str, str],
    canonical_sha256: dict[str, str],
    keyring_sha256: dict[str, str],
) -> None:
    release = payloads["query_release"]
    readiness = payloads["readiness_packet"]
    consume = payloads["consume_marker"]
    terminal = payloads["terminal_seal"]
    audit_invocation = payloads["audit_child_invocation"]
    gate = payloads["pre_connect_gate"]
    query_invocation = payloads["query_child_invocation"]
    terminal_bindings = {
        "audit_child_invocation_raw_sha256": raw_sha256[
            "audit_child_invocation"
        ],
        "audit_child_invocation_canonical_sha256": canonical_sha256[
            "audit_child_invocation"
        ],
        "pre_connect_gate_raw_sha256": raw_sha256["pre_connect_gate"],
        "pre_connect_gate_canonical_sha256": canonical_sha256[
            "pre_connect_gate"
        ],
        "query_child_invocation_raw_sha256": raw_sha256[
            "query_child_invocation"
        ],
        "query_child_invocation_canonical_sha256": canonical_sha256[
            "query_child_invocation"
        ],
    }
    for field, expected in terminal_bindings.items():
        if terminal[field] != expected:
            raise P0AcceptanceV2Error(f"terminal {field} mismatch")
    audit_values = _flag_values(
        audit_invocation,
        label="audit child invocation",
    )
    query_values = _flag_values(
        query_invocation,
        label="query child invocation",
    )
    expected_audit_flags = {
        "--manifest",
        "--start",
        "--end",
        "--dsn-file",
        "--expected-endpoint-identity-sha256",
        "--expected-manifest-sha256",
        "--json-output",
        "--csv-output",
        "--markdown-output",
        "--readonly-proof-output",
        "--pre-connect-query-gate",
        "--expected-pre-connect-gate-raw-sha256",
        "--expected-pre-connect-gate-canonical-sha256",
    }
    expected_query_flags = {
        "--audit-invocation",
        "--expected-provenance-pin",
        "--expected-t1-pin",
        "--expected-query-v3-pin",
        "--expected-l3-pin",
        "--expected-outcome-pin",
        "--expected-custody",
        "--expected-release-id",
        "--expected-attempt-id",
        "--expected-release-raw-sha256",
        "--expected-release-canonical-sha256",
        "--expected-consume-raw-sha256",
        "--expected-consume-canonical-sha256",
        "--expected-gate-raw-sha256",
        "--expected-gate-canonical-sha256",
    }
    if set(audit_values) != expected_audit_flags:
        raise P0AcceptanceV2Error("audit invocation flag allowlist mismatch")
    if set(query_values) != expected_query_flags:
        raise P0AcceptanceV2Error("query invocation flag allowlist mismatch")
    for invocation, script_name, label in (
        (
            audit_invocation,
            "commodity_c_fast_l1_l5_audit.py",
            "audit child invocation",
        ),
        (
            query_invocation,
            "commodity_c_fast_t1_query_child_v3.py",
            "query child invocation",
        ),
    ):
        executable = Path(invocation[0])
        script = Path(invocation[2])
        if (
            not executable.is_absolute()
            or not script.is_absolute()
            or ".." in script.parts
            or script.name != script_name
        ):
            raise P0AcceptanceV2Error(f"{label} executable path is invalid")
    required_audit = {
        "--start": release["audit_window"]["start"],
        "--end": release["audit_window"]["end_exclusive"],
        "--expected-endpoint-identity-sha256": release[
            "endpoint_identity_sha256"
        ],
        "--expected-manifest-sha256": release[
            "manifest_canonical_sha256"
        ],
        "--expected-pre-connect-gate-raw-sha256": raw_sha256[
            "pre_connect_gate"
        ],
        "--expected-pre-connect-gate-canonical-sha256": canonical_sha256[
            "pre_connect_gate"
        ],
    }
    for flag, expected in required_audit.items():
        if audit_values.get(flag) != expected:
            raise P0AcceptanceV2Error(f"audit invocation {flag} mismatch")
    if audit_invocation[-4:] != [
        "--expected-pre-connect-gate-raw-sha256",
        raw_sha256["pre_connect_gate"],
        "--expected-pre-connect-gate-canonical-sha256",
        canonical_sha256["pre_connect_gate"],
    ]:
        raise P0AcceptanceV2Error("audit gate binding must be terminal flags")
    audit_core = audit_invocation[:-4]
    expected_gate = {
        "schema_version": "commodity_c_fast_t1_pre_connect_gate_v3",
        "purpose": "c_fast_t1_last_active_pin_gate_before_dsn",
        "audit_script_raw_sha256": release["audit_script_sha256"],
        "audit_invocation_core_raw_sha256": _hash(canonical_json(audit_core)),
        "audit_invocation_core_canonical_sha256": _hash(
            canonical_json(audit_core)
        ),
        "release_raw_sha256": raw_sha256["query_release"],
        "release_canonical_sha256": canonical_sha256["query_release"],
        "readiness_raw_sha256": raw_sha256["readiness_packet"],
        "readiness_canonical_sha256": canonical_sha256["readiness_packet"],
        "manifest_raw_sha256": raw_sha256["manifest"],
        "manifest_canonical_sha256": canonical_sha256["manifest"],
        "consume_marker_raw_sha256": raw_sha256["consume_marker"],
        "consume_marker_canonical_sha256": canonical_sha256["consume_marker"],
        "provenance_keyring_sha256": keyring_sha256["provenance"],
        "t1_authority_keyring_sha256": keyring_sha256["t1"],
        "query_v3_authority_keyring_sha256": keyring_sha256["query"],
        "l3_authority_keyring_sha256": keyring_sha256["l3"],
        "outcome_keyring_sha256": keyring_sha256["outcome"],
    }
    for field, expected in expected_gate.items():
        if gate.get(field) != expected:
            raise P0AcceptanceV2Error(f"pre-connect gate {field} mismatch")
    expected_gate_fields = {
        "schema_version",
        "purpose",
        "audit_script_raw_sha256",
        "audit_invocation_path",
        "audit_invocation_core_raw_sha256",
        "audit_invocation_core_canonical_sha256",
        "release_path",
        "release_raw_sha256",
        "release_canonical_sha256",
        "readiness_path",
        "readiness_raw_sha256",
        "readiness_canonical_sha256",
        "manifest_source_path",
        "manifest_raw_sha256",
        "manifest_canonical_sha256",
        "consume_marker_raw_sha256",
        "consume_marker_canonical_sha256",
        "provenance_keyring_sha256",
        "t1_authority_keyring_sha256",
        "query_v3_authority_keyring_sha256",
        "l3_authority_keyring_sha256",
        "outcome_keyring_sha256",
        "packet_custody_path",
    }
    if set(gate) != expected_gate_fields:
        raise P0AcceptanceV2Error("pre-connect gate fields are invalid")
    required_query = {
        "--expected-provenance-pin": keyring_sha256["provenance"],
        "--expected-t1-pin": keyring_sha256["t1"],
        "--expected-query-v3-pin": keyring_sha256["query"],
        "--expected-l3-pin": keyring_sha256["l3"],
        "--expected-outcome-pin": keyring_sha256["outcome"],
        "--expected-release-id": release["release_id"],
        "--expected-attempt-id": release["attempt_id"],
        "--expected-release-raw-sha256": raw_sha256["query_release"],
        "--expected-release-canonical-sha256": canonical_sha256[
            "query_release"
        ],
        "--expected-consume-raw-sha256": raw_sha256["consume_marker"],
        "--expected-consume-canonical-sha256": canonical_sha256[
            "consume_marker"
        ],
        "--expected-gate-raw-sha256": raw_sha256["pre_connect_gate"],
        "--expected-gate-canonical-sha256": canonical_sha256[
            "pre_connect_gate"
        ],
    }
    for flag, expected in required_query.items():
        if query_values.get(flag) != expected:
            raise P0AcceptanceV2Error(f"query invocation {flag} mismatch")
    if (
        query_values["--audit-invocation"] != gate["audit_invocation_path"]
        or query_values["--expected-custody"] != gate["packet_custody_path"]
        or audit_values["--pre-connect-query-gate"]
        != str(Path(gate["audit_invocation_path"]).with_name(
            "pre-connect-query-gate-v3.json"
        ))
    ):
        raise P0AcceptanceV2Error(
            "gate/audit/query invocation path chain mismatch"
        )
    for value in (
        gate["audit_invocation_path"],
        gate["release_path"],
        gate["readiness_path"],
        gate["manifest_source_path"],
        gate["packet_custody_path"],
        audit_values["--manifest"],
        audit_values["--dsn-file"],
        audit_values["--json-output"],
        audit_values["--csv-output"],
        audit_values["--markdown-output"],
        audit_values["--readonly-proof-output"],
        audit_values["--pre-connect-query-gate"],
    ):
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise P0AcceptanceV2Error(
                "gate/invocation paths must be absolute and normalized"
            )
    output_paths = {
        audit_values["--json-output"],
        audit_values["--csv-output"],
        audit_values["--markdown-output"],
        audit_values["--readonly-proof-output"],
    }
    if len(output_paths) != 4:
        raise P0AcceptanceV2Error("audit output paths must not alias")
    if consume["trusted_keyring_sha256"] != keyring_sha256["query"]:
        raise P0AcceptanceV2Error("consume query authority pin mismatch")
    if readiness["build_registry_provenance"][
        "provenance_keyring_sha256"
    ] != keyring_sha256["provenance"]:
        raise P0AcceptanceV2Error("readiness provenance pin mismatch")


def _validate_completed_artifacts(
    paths: P0BundleV2Paths,
    payloads: dict[str, Any],
    raw_files: dict[str, bytes],
    keyring_sha256: dict[str, str],
) -> dict[str, str]:
    release = payloads["query_release"]
    manifest = payloads["manifest"]
    validate_json_schema(manifest, MANIFEST_SCHEMA_PATH, "audit manifest")
    if (
        release["manifest_raw_sha256"] != _hash(raw_files["manifest"])
        or release["manifest_canonical_sha256"]
        != _hash(canonical_json(manifest))
        or release["snapshot_id"] != manifest["snapshot_id"]
        or release["audit_window"] != manifest["audit_window"]
    ):
        raise P0AcceptanceV2Error("release exact manifest binding mismatch")
    legacy_payload = dict(release)
    legacy_payload["manifest_sha256"] = release["manifest_canonical_sha256"]
    bundle_files = {
        "scripts/commodity_c_fast_t1_query_child_v3.py": read_regular_file_strict(
            QUERY_CHILD_PATH,
            "query child",
            limit=MAX_ARTIFACT_BYTES,
        ),
        "scripts/commodity_c_fast_l1_l5_audit.py": read_regular_file_strict(
            AUDIT_SCRIPT_PATH,
            "audit script",
            limit=MAX_ARTIFACT_BYTES,
        ),
        str(MANIFEST_SCHEMA_PATH.relative_to(ROOT)): read_regular_file_strict(
            MANIFEST_SCHEMA_PATH,
            "manifest schema",
            limit=MAX_ARTIFACT_BYTES,
        ),
        str(EVIDENCE_SCHEMA_PATH.relative_to(ROOT)): read_regular_file_strict(
            EVIDENCE_SCHEMA_PATH,
            "evidence schema",
            limit=MAX_ARTIFACT_BYTES,
        ),
        str(
            LEGACY_EVIDENCE_SCHEMA_PATH.relative_to(ROOT)
        ): read_regular_file_strict(
            LEGACY_EVIDENCE_SCHEMA_PATH,
            "legacy evidence schema",
            limit=MAX_ARTIFACT_BYTES,
        ),
        str(
            READONLY_PROOF_SCHEMA_PATH.relative_to(ROOT)
        ): read_regular_file_strict(
            READONLY_PROOF_SCHEMA_PATH,
            "readonly proof schema",
            limit=MAX_ARTIFACT_BYTES,
        ),
    }
    verified_release = VerifiedRelease(
        payload=legacy_payload,
        release_sha256=_hash(canonical_json(release)),
        keyring_sha256=keyring_sha256["query"],
        manifest=manifest,
        bundle_files=bundle_files,
    )
    artifact_paths = ArtifactPaths(
        audit_json=paths.audit_json,
        audit_csv=paths.audit_csv,
        audit_markdown=paths.audit_markdown,
        readonly_proof=paths.readonly_proof,
    )
    try:
        p0_pass, hashes = validate_completed_outputs(
            artifact_paths,
            verified_release,
            0,
        )
    except OneShotError as exc:
        raise P0AcceptanceV2Error(
            f"query-v3 completed output validation failed: {exc}"
        ) from exc
    initial = {
        name: _hash(raw_files[name])
        for name in (
            "audit_json",
            "audit_csv",
            "audit_markdown",
            "readonly_proof",
        )
    }
    if p0_pass is not True or hashes != initial:
        raise P0AcceptanceV2Error(
            "query-v3 artifacts are partial, late, or changed"
        )
    if hashes != payloads["terminal_seal"]["artifact_sha256"]:
        raise P0AcceptanceV2Error("terminal artifact hash mismatch")
    evidence_time = parse_datetime(
        payloads["audit_json"]["generated_at"],
        "audit evidence generated_at",
    )
    proof_time = parse_datetime(
        payloads["readonly_proof"]["generated_at"],
        "readonly proof generated_at",
    )
    started_at = parse_datetime(
        payloads["terminal_seal"]["started_at"],
        "terminal started_at",
    )
    ended_at = parse_datetime(
        payloads["terminal_seal"]["ended_at"],
        "terminal ended_at",
    )
    if not started_at <= evidence_time <= proof_time <= ended_at:
        raise P0AcceptanceV2Error("artifact generation timeline is invalid")
    return hashes


def _validate_external_custody_identity(payload: dict[str, Any]) -> None:
    if set(payload) != {
        "schema_version",
        "custody_id",
        "asserted_archive_type",
        "archive_locator_sha256",
        "independent_from_t1_runner",
        "immutability_asserted",
    }:
        raise P0AcceptanceV2Error("external custody identity fields invalid")
    if (
        payload["schema_version"] != EXTERNAL_CUSTODY_IDENTITY_VERSION
        or ID_PATTERN.fullmatch(str(payload["custody_id"])) is None
        or payload["asserted_archive_type"]
        not in {"ASSERTED_WORM", "ASSERTED_APPEND_ONLY"}
        or payload["independent_from_t1_runner"] is not True
        or payload["immutability_asserted"] is not True
    ):
        raise P0AcceptanceV2Error("external custody identity is invalid")
    _validate_sha256(
        str(payload["archive_locator_sha256"]),
        "external archive locator",
    )


def verify_query_v3_bundle(
    paths: P0BundleV2Paths,
    *,
    expected_keyring_sha256: dict[str, str],
) -> VerifiedP0BundleV2:
    raw_files = _read_bundle_raw(paths)
    payloads = _parse_payloads(raw_files)
    raw_sha256 = {name: _hash(raw) for name, raw in raw_files.items()}
    canonical_sha256 = {
        name: _hash(canonical_json(payloads[name]))
        for name in JSON_BUNDLE_FILES
    }
    _validate_exact_sources(payloads, raw_sha256, canonical_sha256)
    not_before, expires_at, _readiness_expires = _validate_query_release(
        payloads["query_release"],
        payloads["readiness_packet"],
        raw_sha256,
        canonical_sha256,
    )
    keyring_sha256, upstream_materials = _verify_key_domains(
        payloads,
        expected_keyring_sha256,
        payloads["readiness_packet"],
    )
    _validate_runtime_bindings(payloads["query_release"])
    _validate_consume_and_terminal(
        payloads,
        raw_sha256,
        canonical_sha256,
        keyring_sha256,
        not_before=not_before,
        expires_at=expires_at,
    )
    _validate_invocations(
        payloads,
        raw_sha256,
        canonical_sha256,
        keyring_sha256,
    )
    artifact_sha256 = _validate_completed_artifacts(
        paths,
        payloads,
        raw_files,
        keyring_sha256,
    )
    external_raw = read_regular_file_strict(
        paths.external_custody_identity,
        "external custody identity",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    external_identity = parse_json_bytes(
        external_raw,
        "external custody identity",
    )
    _validate_external_custody_identity(external_identity)
    if _read_bundle_raw(paths) != raw_files:
        raise P0AcceptanceV2Error(
            "query-v3 bundle changed during historical verification"
        )
    return VerifiedP0BundleV2(
        payloads=payloads,
        raw_sha256=raw_sha256,
        canonical_sha256=canonical_sha256,
        artifact_sha256=artifact_sha256,
        bundle_index_sha256=_bundle_index_sha256(raw_files),
        keyring_sha256=keyring_sha256,
        upstream_public_key_materials=upstream_materials,
        external_custody_identity=external_identity,
        external_custody_identity_raw_sha256=_hash(external_raw),
        external_custody_identity_canonical_sha256=_hash(
            canonical_json(external_identity)
        ),
    )


def validate_acceptance_bindings(
    acceptance: dict[str, Any],
    verified: VerifiedP0BundleV2,
) -> None:
    validate_json_schema(
        acceptance,
        ACCEPTANCE_SCHEMA_PATH,
        "P0 acceptance v2",
    )
    if (
        acceptance["schema_version"] != ACCEPTANCE_SCHEMA_VERSION
        or acceptance["purpose"] != ACCEPTANCE_PURPOSE
        or acceptance["candidate_id"] != CANDIDATE_ID
        or acceptance["parent_issue_number"] != 114
        or acceptance["issue_number"] != 136
    ):
        raise P0AcceptanceV2Error("acceptance-v2 identity is invalid")
    terminal = verified.payloads["terminal_seal"]
    release = verified.payloads["query_release"]
    consume = verified.payloads["consume_marker"]
    expected_id = acceptance_id_for_terminal(
        verified.raw_sha256["terminal_seal"]
    )
    if acceptance["acceptance_id"] != expected_id:
        raise P0AcceptanceV2Error(
            "acceptance_id does not bind exact query terminal"
        )
    if (
        not str(acceptance["reviewer_role"]).strip()
        or str(acceptance["reviewer_role"]).strip().startswith("PENDING_")
        or not str(acceptance["human_signature"]).strip()
        or str(acceptance["human_signature"]).strip().startswith("PENDING_")
    ):
        raise P0AcceptanceV2Error("final acceptance human review is missing")
    expected_scalars = {
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "readiness_packet_id": verified.payloads["readiness_packet"][
            "packet_id"
        ],
        "snapshot_id": release["snapshot_id"],
        "terminal_state": TERMINAL_PASS_STATE,
        "consumed_at": consume["consumed_at"],
        "started_at": terminal["started_at"],
        "final_revalidation_at": terminal["final_revalidation_at"],
        "ended_at": terminal["ended_at"],
        "bundle_index_sha256": verified.bundle_index_sha256,
    }
    for field, expected in expected_scalars.items():
        if acceptance[field] != expected:
            raise P0AcceptanceV2Error(f"acceptance {field} mismatch")
    if acceptance["audit_window"] != release["audit_window"]:
        raise P0AcceptanceV2Error("acceptance audit_window mismatch")
    if acceptance["keyring_sha256"] != verified.keyring_sha256:
        raise P0AcceptanceV2Error("acceptance keyring pins mismatch")
    if acceptance["bundle_raw_sha256"] != verified.raw_sha256:
        raise P0AcceptanceV2Error("acceptance raw bundle hashes mismatch")
    if acceptance["bundle_canonical_sha256"] != verified.canonical_sha256:
        raise P0AcceptanceV2Error("acceptance canonical bundle hashes mismatch")
    if acceptance["artifact_sha256"] != verified.artifact_sha256:
        raise P0AcceptanceV2Error("acceptance artifact hashes mismatch")
    archive = acceptance["external_archive"]
    identity = verified.external_custody_identity
    expected_archive = {
        "custody_id": identity["custody_id"],
        "asserted_archive_type": identity["asserted_archive_type"],
        "archive_locator_sha256": identity["archive_locator_sha256"],
        "custody_identity_raw_sha256": (
            verified.external_custody_identity_raw_sha256
        ),
        "custody_identity_canonical_sha256": (
            verified.external_custody_identity_canonical_sha256
        ),
        "archived_bundle_index_sha256": verified.bundle_index_sha256,
        "independent_custody_asserted": True,
        "immutability_asserted": True,
    }
    for field, expected in expected_archive.items():
        if archive[field] != expected:
            raise P0AcceptanceV2Error(f"external archive {field} mismatch")
    ended_at = parse_datetime(terminal["ended_at"], "terminal.ended_at")
    archived_at = parse_datetime(archive["archived_at"], "archive.archived_at")
    accepted_at = parse_datetime(
        acceptance["accepted_at"],
        "acceptance.accepted_at",
    )
    if not ended_at <= archived_at <= accepted_at:
        raise P0AcceptanceV2Error("archive/acceptance timeline is invalid")
    if acceptance["external_archive_verification_state"] != (
        "HUMAN_ASSERTION_NOT_MACHINE_VERIFIED"
    ):
        raise P0AcceptanceV2Error("external archive verification state invalid")
    if (
        acceptance["p0_accepted"] is not True
        or acceptance["p0_acceptance_scope"]
        != "HISTORICAL_QUERY_V3_EXACT_EVIDENCE_ONLY"
        or acceptance["source_terminal_integrity_scope"]
        != "CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY"
        or any(
            acceptance[field] is not False
            for field in ACCEPTANCE_FALSE_AUTHORITY_FIELDS
        )
    ):
        raise P0AcceptanceV2Error(
            "acceptance-v2 grants forbidden runtime/trading authority"
        )


def _load_acceptance_keyring(
    path: Path,
    *,
    expected_sha256: str,
    key_id: str,
) -> tuple[Ed25519PublicKey, frozenset[bytes], str]:
    _validate_sha256(
        expected_sha256,
        "independently pinned acceptance-v2 keyring",
    )
    raw = read_regular_file_strict(
        path,
        "acceptance-v2 trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    payload = parse_json_bytes(raw, "acceptance-v2 trusted keyring")
    digest = _hash(canonical_json(payload))
    _compare(
        digest,
        expected_sha256,
        "independently pinned acceptance-v2 keyring",
    )
    public_key, materials = _load_keyring(
        payload,
        expected_version=ACCEPTANCE_KEYRING_VERSION,
        required_purpose=ACCEPTANCE_KEY_PURPOSE,
        key_id=key_id,
        label="acceptance-v2 keyring",
    )
    assert public_key is not None
    return public_key, materials, digest


def verify_signed_acceptance(
    acceptance_path: Path,
    acceptance_keyring_path: Path,
    paths: P0BundleV2Paths,
    *,
    expected_acceptance_keyring_sha256: str,
    expected_keyring_sha256: dict[str, str],
) -> tuple[dict[str, Any], str]:
    acceptance_raw = read_regular_file_strict(
        acceptance_path,
        "signed P0 acceptance v2",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    acceptance = parse_json_bytes(
        acceptance_raw,
        "signed P0 acceptance v2",
    )
    verified = verify_query_v3_bundle(
        paths,
        expected_keyring_sha256=expected_keyring_sha256,
    )
    validate_acceptance_bindings(acceptance, verified)
    public_key, acceptance_materials, keyring_digest = _load_acceptance_keyring(
        acceptance_keyring_path,
        expected_sha256=expected_acceptance_keyring_sha256,
        key_id=str(acceptance["signer_key_id"]),
    )
    if acceptance_materials & verified.upstream_public_key_materials:
        raise P0AcceptanceV2Error(
            "acceptance-v2 keyring reuses an active or unused upstream key"
        )
    require_independent_acceptance_signer(
        verified.upstream_public_key_materials,
        public_key,
    )
    _compare(
        keyring_digest,
        acceptance["acceptance_keyring_sha256"],
        "acceptance-v2 keyring",
    )
    _verify_ed25519(
        public_key,
        acceptance["signature"],
        canonical_json(unsigned_acceptance_payload(acceptance)),
        "P0 acceptance v2",
    )
    return acceptance, acceptance_sha256(acceptance)


def add_bundle_arguments(parser: argparse.ArgumentParser) -> None:
    for name in BUNDLE_FILE_ORDER:
        parser.add_argument(
            f"--{name.replace('_', '-')}",
            type=Path,
            required=True,
        )
    parser.add_argument(
        "--external-custody-identity",
        type=Path,
        required=True,
    )
    for domain in UPSTREAM_PIN_FIELDS:
        parser.add_argument(
            f"--expected-{domain}-keyring-sha256",
            required=True,
        )


def paths_from_args(args: argparse.Namespace) -> P0BundleV2Paths:
    return P0BundleV2Paths(
        **{
            name: getattr(args, name)
            for name in BUNDLE_FILE_ORDER
        },
        external_custody_identity=args.external_custody_identity,
    )


def expected_keyring_hashes_from_args(
    args: argparse.Namespace,
) -> dict[str, str]:
    return {
        domain: getattr(args, f"expected_{domain}_keyring_sha256")
        for domain in UPSTREAM_PIN_FIELDS
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument(
        "--acceptance-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-acceptance-keyring-sha256",
        required=True,
    )
    add_bundle_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        acceptance, digest = verify_signed_acceptance(
            args.acceptance,
            args.acceptance_trusted_keyring,
            paths_from_args(args),
            expected_acceptance_keyring_sha256=(
                args.expected_acceptance_keyring_sha256
            ),
            expected_keyring_sha256=expected_keyring_hashes_from_args(args),
        )
    except (
        P0AcceptanceV2Error,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"P0 acceptance v2 verification failed: {exc}", file=sys.stderr)
        return 2
    print("P0 acceptance v2 verification: PASS")
    print(f"acceptance_id: {acceptance['acceptance_id']}")
    print(f"acceptance_sha256: {digest}")
    print("p0_acceptance_scope: HISTORICAL_QUERY_V3_EXACT_EVIDENCE_ONLY")
    print("collection_authorized: false")
    print("runtime_activation_authorized: false")
    print("trading_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
