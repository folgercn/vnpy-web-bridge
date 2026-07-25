#!/usr/bin/env python3
"""Execute one human-authorized C_FAST T1 production readonly query."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from commodity_c_fast_readonly_deployment_outcome import (
    add_post_arguments,
    add_source_arguments,
)
from commodity_c_fast_t1_one_shot import (
    AUDIT_SCRIPT_PATH,
    EVIDENCE_SCHEMA_PATH,
    LEGACY_EVIDENCE_SCHEMA_PATH,
    MANIFEST_SCHEMA_PATH,
    READONLY_PROOF_SCHEMA_PATH,
    ArtifactPaths,
    OneShotError,
    VerifiedRelease,
    artifact_hashes,
    build_child_invocation,
    canonical_json,
    child_environment,
    custody_entry_exists,
    custody_path_sha256,
    open_custody_guard,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_at,
    read_regular_file_strict,
    release_attempt_id,
    stage_verified_audit_bundle,
    validate_completed_outputs,
    validate_custody_identity,
    validate_json_schema,
    validate_private_dsn_metadata,
    verify_staged_audit_bundle,
    write_json_create_only_at,
)
from commodity_c_fast_t1_readiness_v2 import (
    ReadinessInputs,
    ReadinessPins,
    ReadinessV2Error,
    VerifiedReadinessPacket,
    _read_production_pins,
    inputs_from_args,
    verify_active_readiness_pins,
    verify_existing_readiness_packet,
)
from commodity_c_fast_t1_release_v2_foundation import (
    _readiness_binding,
    readiness_source_bundle_index,
)


ROOT = Path(__file__).resolve().parents[1]
PARENT_RUNNER_PATH = Path(__file__).resolve()
QUERY_CHILD_PATH = ROOT / "scripts/commodity_c_fast_t1_query_child_v3.py"
RELEASE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-one-shot-query-release-v3.schema.json"
)
CONSUME_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-consume-v3.schema.json"
)
TERMINAL_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-terminal-v3.schema.json"
)
READINESS_VERIFIER_PATH = (
    ROOT / "scripts/commodity_c_fast_t1_readiness_v2.py"
)
READINESS_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-readiness-v2.schema.json"
)

RELEASE_SCHEMA_VERSION = "commodity_c_fast_t1_one_shot_query_release_v3"
RELEASE_PURPOSE = "c_fast_t1_exact_readiness_readonly_query_authority_v3"
TRUSTED_KEY_PURPOSE = "t1_exact_readonly_query_v3_release_signer"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MAX_RELEASE_TTL = timedelta(minutes=10)
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

TRUE_AUTHORITY_FIELDS = (
    "t1_one_shot_child_launch_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "local_query_evidence_write_authorized",
)
FALSE_AUTHORITY_FIELDS = (
    "write_probe_authorized",
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
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "strategy_activation_authorized",
    "replacement_authorized",
    "production_authorized",
    "dynamic_selection_allowed",
    "automatic_promotion_authorized",
    "p0_acceptance_authorized",
    "replay_allowed",
)


class QueryV3Error(RuntimeError):
    """Expected fail-closed query-v3 error."""


class QueryChildLaunchError(QueryV3Error):
    """The bootstrap process was not created, so no query could start."""


@dataclass(frozen=True)
class VerifiedQueryRelease:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    keyring_sha256: str
    readiness: VerifiedReadinessPacket
    legacy: VerifiedRelease
    release_bytes: bytes
    readiness_bytes: bytes
    manifest_bytes: bytes


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise QueryV3Error(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def unsigned_release_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def _load_query_public_key(
    keyring: dict[str, Any],
    key_id: str,
) -> tuple[Ed25519PublicKey, bytes]:
    if set(keyring) != {"schema_version", "keys"}:
        raise QueryV3Error("query keyring fields are invalid")
    if keyring["schema_version"] != "commodity_c_fast_t1_trusted_keys_v1":
        raise QueryV3Error("query keyring schema version is invalid")
    entries = keyring["keys"]
    if not isinstance(entries, list) or not entries:
        raise QueryV3Error("query keyring must contain at least one key")
    match: dict[str, Any] | None = None
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise QueryV3Error("query keyring entry fields are invalid")
        current_id = str(entry["key_id"])
        if current_id in seen:
            raise QueryV3Error("query keyring contains duplicate key_id")
        seen.add(current_id)
        if current_id == key_id:
            match = entry
    if match is None or match["purpose"] != TRUSTED_KEY_PURPOSE:
        raise QueryV3Error("query release signer purpose is not authorized")
    try:
        raw = base64.b64decode(match["public_key_base64"], validate=True)
        if len(raw) != 32:
            raise ValueError("wrong public key length")
        return Ed25519PublicKey.from_public_bytes(raw), raw
    except (TypeError, ValueError) as exc:
        raise QueryV3Error("query Ed25519 public key is invalid") from exc


def validate_release_semantics(
    payload: dict[str, Any],
    readiness: VerifiedReadinessPacket,
    *,
    now: datetime,
) -> None:
    try:
        validate_json_schema(payload, RELEASE_SCHEMA_PATH, "T1 query v3 release")
    except OneShotError as exc:
        raise QueryV3Error(str(exc)) from exc
    if (
        payload["schema_version"] != RELEASE_SCHEMA_VERSION
        or payload["purpose"] != RELEASE_PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
    ):
        raise QueryV3Error("query release identity is invalid")
    if not hmac.compare_digest(
        payload["attempt_id"],
        release_attempt_id(payload["release_id"]),
    ):
        raise QueryV3Error("attempt_id does not match release_id")
    if (
        not str(payload["human_signature"]).strip()
        or str(payload["human_signature"]).startswith("PENDING_")
        or not str(payload["reviewer_role"]).strip()
    ):
        raise QueryV3Error("final human review fields are required")
    current = _utc(now, "verification time")
    try:
        issued_at = parse_datetime(payload["issued_at"], "issued_at")
        not_before = parse_datetime(payload["not_before"], "not_before")
        expires_at = parse_datetime(payload["expires_at"], "expires_at")
        readiness_generated = parse_datetime(
            readiness.payload["generated_at"],
            "readiness.generated_at",
        )
        readiness_expires = parse_datetime(
            readiness.payload["expires_at"],
            "readiness.expires_at",
        )
    except OneShotError as exc:
        raise QueryV3Error(str(exc)) from exc
    if not issued_at <= not_before <= current < expires_at:
        raise QueryV3Error("query release is not currently active")
    if readiness_generated > issued_at:
        raise QueryV3Error("query release predates readiness")
    if expires_at - issued_at > MAX_RELEASE_TTL:
        raise QueryV3Error("query release TTL cannot exceed 10 minutes")
    if expires_at > readiness_expires:
        raise QueryV3Error("query release cannot outlive readiness")
    if current + timedelta(
        seconds=payload["minimum_launch_margin_seconds"]
    ) >= expires_at:
        raise QueryV3Error("query release has insufficient launch margin")
    if payload["readiness"] != _readiness_binding(readiness):
        raise QueryV3Error("query release does not bind exact readiness")
    if any(payload[field] is not True for field in TRUE_AUTHORITY_FIELDS):
        raise QueryV3Error("query release lacks narrow readonly authority")
    if any(payload[field] is not False for field in FALSE_AUTHORITY_FIELDS):
        raise QueryV3Error("query release grants forbidden authority")


def verify_query_release(
    release_path: Path,
    keyring_path: Path,
    manifest_path: Path,
    readiness_packet_path: Path,
    readiness_inputs: ReadinessInputs,
    pins: ReadinessPins,
    *,
    now: datetime,
    require_root_owned_parent: bool = True,
) -> VerifiedQueryRelease:
    current = _utc(now, "verification time")
    readiness = verify_existing_readiness_packet(
        readiness_inputs,
        pins,
        readiness_packet_path,
        now=current,
        require_root_owned_parent=require_root_owned_parent,
    )
    try:
        custody = pins.packet_custody_path.resolve(strict=True)
        if release_path.parent.resolve(strict=True) != custody:
            raise QueryV3Error("query release is outside pinned custody")
        guard = open_custody_guard(
            custody,
            require_root_owned_parent=require_root_owned_parent,
        )
        try:
            release_raw = read_regular_file_at(
                guard,
                release_path.name,
                "signed T1 query v3 release",
            )
            release = parse_json_bytes(
                release_raw,
                "signed T1 query v3 release",
            )
            readiness_raw = read_regular_file_at(
                guard,
                readiness_packet_path.name,
                "exact T1 readiness v2 packet",
            )
            if _hash(readiness_raw) != readiness.raw_sha256:
                raise QueryV3Error("readiness raw bytes changed after verification")
            validate_release_semantics(release, readiness, now=current)
            validate_custody_identity(
                guard,
                release["custody_identity_sha256"],
            )
        finally:
            guard.close()
        keyring_raw = read_regular_file_strict(
            keyring_path,
            "T1 query v3 keyring",
            private=True,
        )
        keyring = parse_json_bytes(keyring_raw, "T1 query v3 keyring")
        manifest_raw = read_regular_file_strict(
            manifest_path,
            "T1 audit manifest",
        )
        manifest = parse_json_bytes(manifest_raw, "T1 audit manifest")
    except (OneShotError, OSError) as exc:
        raise QueryV3Error(str(exc)) from exc
    keyring_sha256 = _hash(canonical_json(keyring))
    if (
        keyring_sha256 != pins.t1_authority_keyring_sha256
        or keyring_sha256 != release["trusted_keyring_sha256"]
    ):
        raise QueryV3Error("query keyring does not match active T1 pin")
    public_key, public_raw = _load_query_public_key(
        keyring,
        release["signer_key_id"],
    )
    try:
        signature = base64.b64decode(release["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("wrong signature length")
        public_key.verify(
            signature,
            canonical_json(unsigned_release_payload(release)),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise QueryV3Error("query release signature is invalid") from exc
    signer_hash = _hash(public_raw)
    if signer_hash in {
        release["readiness"]["provenance_signer_public_key_sha256"],
        release["readiness"]["outcome_signer_public_key_sha256"],
    }:
        raise QueryV3Error("query signer reuses an upstream signing key")

    expected_files = {
        "parent_runner_sha256": PARENT_RUNNER_PATH,
        "query_child_sha256": QUERY_CHILD_PATH,
        "release_schema_sha256": RELEASE_SCHEMA_PATH,
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "terminal_schema_sha256": TERMINAL_SCHEMA_PATH,
        "readiness_verifier_sha256": READINESS_VERIFIER_PATH,
        "readiness_schema_sha256": READINESS_SCHEMA_PATH,
        "audit_script_sha256": AUDIT_SCRIPT_PATH,
        "manifest_schema_sha256": MANIFEST_SCHEMA_PATH,
        "evidence_schema_sha256": EVIDENCE_SCHEMA_PATH,
        "legacy_evidence_schema_sha256": LEGACY_EVIDENCE_SCHEMA_PATH,
        "readonly_proof_schema_sha256": READONLY_PROOF_SCHEMA_PATH,
    }
    raw_files: dict[str, bytes] = {}
    for field, path in expected_files.items():
        raw = read_regular_file_strict(path, field, limit=MAX_ARTIFACT_BYTES)
        if _hash(raw) != release[field]:
            raise QueryV3Error(f"{field} does not match frozen runtime")
        raw_files[field] = raw
    packet = readiness.payload
    if (
        release["pin_root_path_sha256"] != packet["pin_root_path_sha256"]
        or release["custody_path_sha256"] != custody_path_sha256(custody)
        or release["readiness_source_bundle_index_sha256"]
        != readiness_source_bundle_index(readiness)
        or release["namespaces"]
        != {**packet["source_namespaces"], **packet["digest_namespaces"]}
    ):
        raise QueryV3Error("query release pin/namespace binding is invalid")
    try:
        validate_json_schema(manifest, MANIFEST_SCHEMA_PATH, "T1 audit manifest")
    except OneShotError as exc:
        raise QueryV3Error(str(exc)) from exc
    if (
        release["manifest_raw_sha256"] != _hash(manifest_raw)
        or release["manifest_canonical_sha256"]
        != _hash(canonical_json(manifest))
        or release["snapshot_id"] != manifest["snapshot_id"]
        or release["audit_window"] != manifest["audit_window"]
    ):
        raise QueryV3Error("query release does not bind exact manifest")
    try:
        l3_release = parse_json_bytes(
            read_regular_file_strict(
                readiness_inputs.outcome_source.release,
                "readonly deployment release",
            ),
            "readonly deployment release",
        )
    except OneShotError as exc:
        raise QueryV3Error(str(exc)) from exc
    if (
        release["endpoint_identity_sha256"]
        != packet["readonly_deployment_outcome"][
            "questdb_target_identity_sha256"
        ]
        or release["endpoint_identity_sha256"]
        != l3_release["questdb_target_identity_sha256"]
        or release["questdb_build_sha256"]
        != l3_release["questdb_build_sha256"]
    ):
        raise QueryV3Error("query target/build binding is invalid")

    legacy_payload = dict(release)
    legacy_payload["manifest_sha256"] = release["manifest_canonical_sha256"]
    bundle_files = {
        "scripts/commodity_c_fast_t1_query_child_v3.py": raw_files[
            "query_child_sha256"
        ],
        "scripts/commodity_c_fast_l1_l5_audit.py": raw_files[
            "audit_script_sha256"
        ],
        "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json": raw_files[
            "manifest_schema_sha256"
        ],
        "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json": raw_files[
            "evidence_schema_sha256"
        ],
        "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json": raw_files[
            "legacy_evidence_schema_sha256"
        ],
        "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json": raw_files[
            "readonly_proof_schema_sha256"
        ],
    }
    legacy = VerifiedRelease(
        payload=legacy_payload,
        release_sha256=_hash(canonical_json(release)),
        keyring_sha256=keyring_sha256,
        manifest=manifest,
        bundle_files=bundle_files,
    )
    return VerifiedQueryRelease(
        payload=release,
        raw_sha256=_hash(release_raw),
        canonical_sha256=_hash(canonical_json(release)),
        keyring_sha256=keyring_sha256,
        readiness=readiness,
        legacy=legacy,
        release_bytes=release_raw,
        readiness_bytes=readiness_raw,
        manifest_bytes=manifest_raw,
    )


def _consume_payload(
    verified: VerifiedQueryRelease,
    consumed_at: datetime,
) -> dict[str, Any]:
    release = verified.payload
    readiness = release["readiness"]
    return {
        "schema_version": "commodity_c_fast_t1_query_consume_v3",
        "purpose": "c_fast_t1_query_v3_consume_before_final_revalidation",
        "candidate_id": CANDIDATE_ID,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "release_raw_sha256": verified.raw_sha256,
        "release_canonical_sha256": verified.canonical_sha256,
        "consumed_at": _utc(consumed_at, "consume time").isoformat(),
        "readiness_packet_id": readiness["packet_id"],
        "readiness_packet_raw_sha256": readiness["packet_raw_sha256"],
        "readiness_packet_canonical_sha256": readiness[
            "packet_canonical_sha256"
        ],
        "content_attestation_raw_sha256": readiness[
            "content_attestation_raw_sha256"
        ],
        "content_attestation_canonical_sha256": readiness[
            "content_attestation_canonical_sha256"
        ],
        "provenance_raw_sha256": readiness["provenance_raw_sha256"],
        "provenance_canonical_sha256": readiness[
            "provenance_canonical_sha256"
        ],
        "outcome_raw_sha256": readiness["outcome_raw_sha256"],
        "outcome_canonical_sha256": readiness[
            "outcome_canonical_sha256"
        ],
        "manifest_raw_sha256": release["manifest_raw_sha256"],
        "manifest_canonical_sha256": release["manifest_canonical_sha256"],
        "trusted_keyring_sha256": verified.keyring_sha256,
        "custody_identity_sha256": release["custody_identity_sha256"],
        "custody_path_sha256": release["custody_path_sha256"],
        "consume_precedes_final_revalidation": True,
        "query_started": False,
        "production_queried": False,
        "consume_is_authority": False,
        "replay_allowed": False,
    }


def _empty_hashes() -> dict[str, str | None]:
    return {
        "audit_json": None,
        "audit_csv": None,
        "audit_markdown": None,
        "readonly_proof": None,
    }


def _terminal(
    verified: VerifiedQueryRelease,
    *,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    audit_invocation_raw_sha256: str | None,
    audit_invocation_canonical_sha256: str | None,
    pre_connect_gate_raw_sha256: str | None,
    pre_connect_gate_canonical_sha256: str | None,
    query_invocation_raw_sha256: str | None,
    query_invocation_canonical_sha256: str | None,
    started_at: datetime,
    final_revalidation_at: datetime | None,
    ended_at: datetime,
    terminal_state: str,
    error_code: str | None,
    child_exit_code: int | None,
    hashes: dict[str, str | None],
    p0_pass: bool | None,
    proof_verified: bool,
) -> dict[str, Any]:
    pre_child = terminal_state in {
        "BLOCKED_FINAL_REVALIDATION_PRE_CHILD",
        "FAILED_CHILD_LAUNCH_PRE_QUERY",
    }
    completed = terminal_state in {
        "COMPLETED_EVIDENCE_P0_PASS",
        "COMPLETED_EVIDENCE_P0_BLOCKED",
    }
    release = verified.payload
    readiness = release["readiness"]
    if ended_at < started_at:
        raise QueryV3Error("terminal timeline moved backwards")
    if final_revalidation_at is not None and not (
        started_at <= final_revalidation_at <= ended_at
    ):
        raise QueryV3Error("terminal final revalidation timeline is invalid")
    if not pre_child and final_revalidation_at is None:
        raise QueryV3Error("launched query terminal lacks final revalidation")
    terminal = {
        "schema_version": "commodity_c_fast_t1_query_terminal_v3",
        "purpose": "c_fast_t1_readonly_query_v3_terminal",
        "candidate_id": CANDIDATE_ID,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "terminal_state": terminal_state,
        "error_code": error_code,
        "release_raw_sha256": verified.raw_sha256,
        "release_canonical_sha256": verified.canonical_sha256,
        "consume_marker_raw_sha256": consume_raw_sha256,
        "consume_marker_canonical_sha256": consume_canonical_sha256,
        "readiness_packet_raw_sha256": release["readiness"][
            "packet_raw_sha256"
        ],
        "readiness_packet_canonical_sha256": release["readiness"][
            "packet_canonical_sha256"
        ],
        "content_attestation_raw_sha256": readiness[
            "content_attestation_raw_sha256"
        ],
        "content_attestation_canonical_sha256": readiness[
            "content_attestation_canonical_sha256"
        ],
        "provenance_raw_sha256": readiness["provenance_raw_sha256"],
        "provenance_canonical_sha256": readiness[
            "provenance_canonical_sha256"
        ],
        "outcome_raw_sha256": readiness["outcome_raw_sha256"],
        "outcome_canonical_sha256": readiness[
            "outcome_canonical_sha256"
        ],
        "manifest_raw_sha256": release["manifest_raw_sha256"],
        "manifest_canonical_sha256": release["manifest_canonical_sha256"],
        "audit_child_invocation_raw_sha256": audit_invocation_raw_sha256,
        "audit_child_invocation_canonical_sha256": (
            audit_invocation_canonical_sha256
        ),
        "pre_connect_gate_raw_sha256": pre_connect_gate_raw_sha256,
        "pre_connect_gate_canonical_sha256": (
            pre_connect_gate_canonical_sha256
        ),
        "query_child_invocation_raw_sha256": query_invocation_raw_sha256,
        "query_child_invocation_canonical_sha256": (
            query_invocation_canonical_sha256
        ),
        "child_exit_code": child_exit_code,
        "started_at": _utc(started_at, "start time").isoformat(),
        "final_revalidation_at": (
            _utc(
                final_revalidation_at,
                "final revalidation time",
            ).isoformat()
            if final_revalidation_at is not None
            else None
        ),
        "ended_at": _utc(ended_at, "end time").isoformat(),
        "query_execution_state": (
            "NOT_STARTED"
            if pre_child
            else "COMPLETED" if completed else "OUTCOME_UNKNOWN"
        ),
        "production_query_attempted": not pre_child,
        "production_query_completed": True if completed else False if pre_child else None,
        "artifact_sha256": hashes,
        "p0_pass": p0_pass,
        "proof_verified": proof_verified,
        "write_probe_attempted": False,
        "database_mutations_observed": 0 if proof_verified else None,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "terminal_is_authority": False,
        "p0_acceptance_authorized": False,
        "terminal_integrity_scope": (
            "CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY"
        ),
        "replay_allowed": False,
    }
    try:
        validate_json_schema(terminal, TERMINAL_SCHEMA_PATH, "query terminal")
    except OneShotError as exc:
        raise QueryV3Error(str(exc)) from exc
    return terminal


def _assert_same(
    expected: VerifiedQueryRelease,
    actual: VerifiedQueryRelease,
) -> None:
    if actual != expected:
        raise QueryV3Error("release/readiness changed during protected use")


def build_query_child_invocation(
    pins: ReadinessPins,
    staged_child: Path,
    audit_invocation_path: Path,
    gate_raw_sha256: str,
    gate_canonical_sha256: str,
) -> list[str]:
    return [
        str(Path(sys.executable).resolve(strict=True)),
        str(staged_child.resolve(strict=False)),
        "--audit-invocation",
        str(audit_invocation_path.resolve(strict=False)),
        "--expected-provenance-pin",
        pins.provenance_keyring_sha256,
        "--expected-t1-pin",
        pins.t1_authority_keyring_sha256,
        "--expected-l3-pin",
        pins.l3_authority_keyring_sha256,
        "--expected-outcome-pin",
        pins.outcome_keyring_sha256,
        "--expected-custody",
        str(pins.packet_custody_path.resolve(strict=True)),
        "--expected-gate-raw-sha256",
        gate_raw_sha256,
        "--expected-gate-canonical-sha256",
        gate_canonical_sha256,
    ]


def build_pre_connect_gate(
    verified: VerifiedQueryRelease,
    pins: ReadinessPins,
    *,
    audit_invocation: list[str],
    audit_invocation_path: Path,
    release_path: Path,
    readiness_path: Path,
    manifest_source_path: Path,
) -> dict[str, Any]:
    invocation_raw = canonical_json(audit_invocation)
    return {
        "schema_version": "commodity_c_fast_t1_pre_connect_gate_v3",
        "purpose": "c_fast_t1_last_active_pin_gate_before_dsn",
        "audit_script_raw_sha256": verified.payload["audit_script_sha256"],
        "audit_invocation_path": str(audit_invocation_path),
        "audit_invocation_raw_sha256": _hash(invocation_raw),
        "audit_invocation_canonical_sha256": _hash(
            canonical_json(audit_invocation)
        ),
        "release_path": str(release_path),
        "release_raw_sha256": verified.raw_sha256,
        "release_canonical_sha256": verified.canonical_sha256,
        "readiness_path": str(readiness_path),
        "readiness_raw_sha256": verified.readiness.raw_sha256,
        "readiness_canonical_sha256": verified.readiness.canonical_sha256,
        "manifest_source_path": str(manifest_source_path),
        "manifest_raw_sha256": verified.payload["manifest_raw_sha256"],
        "manifest_canonical_sha256": verified.payload[
            "manifest_canonical_sha256"
        ],
        "provenance_keyring_sha256": pins.provenance_keyring_sha256,
        "t1_authority_keyring_sha256": pins.t1_authority_keyring_sha256,
        "l3_authority_keyring_sha256": pins.l3_authority_keyring_sha256,
        "outcome_keyring_sha256": pins.outcome_keyring_sha256,
        "packet_custody_path": str(
            pins.packet_custody_path.resolve(strict=True)
        ),
    }


def run_query_child(
    invocation: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.Popen(
            invocation,
            cwd=cwd,
            env=child_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        raise QueryChildLaunchError(
            "query child could not be created"
        ) from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_query_process_group(process)
        raise
    except KeyboardInterrupt:
        _terminate_query_process_group(process)
        raise
    return subprocess.CompletedProcess(
        invocation,
        process.returncode,
        stdout,
        stderr,
    )


def _terminate_query_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def execute_verified_query(
    verified: VerifiedQueryRelease,
    pins: ReadinessPins,
    dsn_file: Path,
    revalidator: Callable[[datetime], VerifiedQueryRelease],
    *,
    clock: Callable[[], datetime],
    child_executor: Callable[..., subprocess.CompletedProcess[str]] = run_query_child,
    output_validator: Callable[
        [ArtifactPaths, VerifiedRelease, int],
        tuple[bool, dict[str, str]],
    ] = validate_completed_outputs,
    require_root_owned_parent: bool = True,
) -> tuple[int, dict[str, Any]]:
    custody = pins.packet_custody_path.resolve(strict=True)
    guard = open_custody_guard(
        custody,
        require_root_owned_parent=require_root_owned_parent,
    )
    release = verified.payload
    consume_name = f"{release['attempt_id']}.query-consumed-v3.json"
    terminal_name = f"{release['attempt_id']}.query-terminal-v3.json"
    try:
        if custody_entry_exists(guard, consume_name):
            raise QueryV3Error("query release is already consumed")
        if custody_entry_exists(guard, terminal_name):
            raise QueryV3Error("query terminal exists without consume")
        if custody_entry_exists(guard, release["attempt_id"]):
            raise QueryV3Error("query attempt directory already exists")
        validate_private_dsn_metadata(dsn_file)

        preconsume_at = _utc(clock(), "pre-consume time")
        preconsume = revalidator(preconsume_at)
        _assert_same(verified, preconsume)
        consumed_at = _utc(clock(), "consume time")
        if consumed_at < preconsume_at:
            raise QueryV3Error("consume clock moved backwards")
        validate_release_semantics(
            preconsume.payload,
            preconsume.readiness,
            now=consumed_at,
        )
        verify_active_readiness_pins(pins)
        consume = _consume_payload(preconsume, consumed_at)
        consume_raw_sha256 = write_json_create_only_at(
            guard,
            consume_name,
            consume,
            CONSUME_SCHEMA_PATH,
            "T1 query v3 consume",
        )
        consume_raw = read_regular_file_at(
            guard,
            consume_name,
            "T1 query v3 consume",
        )
        if (
            _hash(consume_raw) != consume_raw_sha256
            or parse_json_bytes(consume_raw, "T1 query v3 consume") != consume
        ):
            raise QueryV3Error("consume exact-byte reopen failed")
        consume_canonical_sha256 = _hash(canonical_json(consume))

        audit_invocation_raw_sha256: str | None = None
        audit_invocation_canonical_sha256: str | None = None
        pre_connect_gate_raw_sha256: str | None = None
        pre_connect_gate_canonical_sha256: str | None = None
        query_invocation_raw_sha256: str | None = None
        query_invocation_canonical_sha256: str | None = None
        final_at: datetime | None = None
        execution_legacy = verified.legacy
        attempt_dir = custody / release["attempt_id"]
        artifacts_dir = attempt_dir / "artifacts"
        paths = ArtifactPaths(
            audit_json=artifacts_dir / "audit.json",
            audit_csv=artifacts_dir / "audit.csv",
            audit_markdown=artifacts_dir / "audit.md",
            readonly_proof=artifacts_dir / "readonly-proof.json",
        )
        try:
            os.mkdir(release["attempt_id"], mode=0o700, dir_fd=guard.descriptor)
            os.fsync(guard.descriptor)
            bundle_root = attempt_dir / "verified-bundle"
            staged_audit = (
                bundle_root / "scripts/commodity_c_fast_l1_l5_audit.py"
            )
            staged_manifest = bundle_root / "release/manifest.json"
            audit_invocation_path = (
                bundle_root / "release/child-invocation.json"
            )
            query_invocation_path = (
                bundle_root / "release/query-child-invocation-v3.json"
            )
            gate_path = (
                bundle_root / "release/pre-connect-query-gate-v3.json"
            )
            staged_release = (
                bundle_root / "release/query-release-v3.json"
            )
            staged_readiness = (
                bundle_root / "release/readiness-v2.json"
            )
            staged_manifest_source = (
                bundle_root / "release/manifest-source.json"
            )
            staged_child = (
                bundle_root / "scripts/commodity_c_fast_t1_query_child_v3.py"
            )
            audit_invocation = build_child_invocation(
                verified.legacy.payload,
                staged_audit,
                staged_manifest,
                dsn_file,
                paths,
            )
            audit_invocation[0] = os.path.abspath(sys.executable)
            audit_invocation.extend(
                ["--pre-connect-query-gate", str(gate_path)]
            )
            gate = build_pre_connect_gate(
                verified,
                pins,
                audit_invocation=audit_invocation,
                audit_invocation_path=audit_invocation_path,
                release_path=staged_release,
                readiness_path=staged_readiness,
                manifest_source_path=staged_manifest_source,
            )
            gate_bytes = canonical_json(gate)
            query_invocation = build_query_child_invocation(
                pins,
                staged_child,
                audit_invocation_path,
                _hash(gate_bytes),
                _hash(canonical_json(gate)),
            )
            derived_files = dict(verified.legacy.bundle_files)
            derived_files.update(
                {
                    "release/query-release-v3.json": verified.release_bytes,
                    "release/readiness-v2.json": verified.readiness_bytes,
                    "release/manifest-source.json": verified.manifest_bytes,
                    "release/pre-connect-query-gate-v3.json": gate_bytes,
                    "release/query-child-invocation-v3.json": canonical_json(
                        query_invocation
                    ),
                }
            )
            execution_legacy = replace(
                verified.legacy,
                bundle_files=derived_files,
            )
            (
                bundle_root,
                _,
                _,
                _,
                audit_invocation_path,
            ) = stage_verified_audit_bundle(
                execution_legacy,
                attempt_dir,
                audit_invocation,
            )
            verify_staged_audit_bundle(
                execution_legacy,
                bundle_root,
                audit_invocation,
            )
            audit_invocation_raw = read_regular_file_strict(
                audit_invocation_path,
                "staged audit invocation",
            )
            query_invocation_raw = read_regular_file_strict(
                query_invocation_path,
                "staged query-child invocation",
            )
            gate_raw = read_regular_file_strict(
                gate_path,
                "staged pre-connect query gate",
            )
            audit_invocation_raw_sha256 = _hash(audit_invocation_raw)
            audit_invocation_canonical_sha256 = _hash(
                canonical_json(audit_invocation)
            )
            query_invocation_raw_sha256 = _hash(query_invocation_raw)
            query_invocation_canonical_sha256 = _hash(
                canonical_json(query_invocation)
            )
            pre_connect_gate_raw_sha256 = _hash(gate_raw)
            pre_connect_gate_canonical_sha256 = _hash(
                canonical_json(gate)
            )
        except (OSError, OneShotError, QueryV3Error):
            observed_end = _utc(clock(), "terminal time")
            terminal = _terminal(
                verified,
                consume_raw_sha256=consume_raw_sha256,
                consume_canonical_sha256=consume_canonical_sha256,
                audit_invocation_raw_sha256=(
                    audit_invocation_raw_sha256
                ),
                audit_invocation_canonical_sha256=(
                    audit_invocation_canonical_sha256
                ),
                pre_connect_gate_raw_sha256=(
                    pre_connect_gate_raw_sha256
                ),
                pre_connect_gate_canonical_sha256=(
                    pre_connect_gate_canonical_sha256
                ),
                query_invocation_raw_sha256=(
                    query_invocation_raw_sha256
                ),
                query_invocation_canonical_sha256=(
                    query_invocation_canonical_sha256
                ),
                started_at=consumed_at,
                final_revalidation_at=None,
                ended_at=max(consumed_at, observed_end),
                terminal_state="FAILED_CHILD_LAUNCH_PRE_QUERY",
                error_code=(
                    "NON_MONOTONIC_CLOCK"
                    if observed_end < consumed_at
                    else "VERIFIED_BUNDLE_STAGE_FAILED"
                ),
                child_exit_code=None,
                hashes=artifact_hashes(paths),
                p0_pass=None,
                proof_verified=False,
            )
            write_json_create_only_at(
                guard,
                terminal_name,
                terminal,
                TERMINAL_SCHEMA_PATH,
                "T1 query v3 terminal",
            )
            return 2, terminal

        final_at = _utc(clock(), "final revalidation time")
        try:
            if final_at < consumed_at:
                raise QueryV3Error("final revalidation clock moved backwards")
            final = revalidator(final_at)
            _assert_same(preconsume, final)
            validate_release_semantics(
                final.payload,
                final.readiness,
                now=final_at,
            )
            verify_staged_audit_bundle(
                execution_legacy,
                bundle_root,
                audit_invocation,
            )
            verify_active_readiness_pins(pins)
        except (
            OSError,
            OneShotError,
            QueryV3Error,
            ReadinessV2Error,
            ValueError,
        ):
            observed_end = _utc(clock(), "terminal time")
            terminal = _terminal(
                verified,
                consume_raw_sha256=consume_raw_sha256,
                consume_canonical_sha256=consume_canonical_sha256,
                audit_invocation_raw_sha256=(
                    audit_invocation_raw_sha256
                ),
                audit_invocation_canonical_sha256=(
                    audit_invocation_canonical_sha256
                ),
                pre_connect_gate_raw_sha256=(
                    pre_connect_gate_raw_sha256
                ),
                pre_connect_gate_canonical_sha256=(
                    pre_connect_gate_canonical_sha256
                ),
                query_invocation_raw_sha256=(
                    query_invocation_raw_sha256
                ),
                query_invocation_canonical_sha256=(
                    query_invocation_canonical_sha256
                ),
                started_at=consumed_at,
                final_revalidation_at=None,
                ended_at=max(consumed_at, observed_end),
                terminal_state="BLOCKED_FINAL_REVALIDATION_PRE_CHILD",
                error_code=(
                    "NON_MONOTONIC_CLOCK"
                    if observed_end < consumed_at
                    else "FINAL_REVALIDATION_FAILED"
                ),
                child_exit_code=None,
                hashes=artifact_hashes(paths),
                p0_pass=None,
                proof_verified=False,
            )
            write_json_create_only_at(
                guard,
                terminal_name,
                terminal,
                TERMINAL_SCHEMA_PATH,
                "T1 query v3 terminal",
            )
            return 2, terminal

        result: subprocess.CompletedProcess[str] | None = None
        try:
            result = child_executor(
                query_invocation,
                cwd=bundle_root,
                timeout=release["max_runtime_seconds"],
            )
            if result.returncode == 78:
                state = "FAILED_CHILD_LAUNCH_PRE_QUERY"
                error = "CHILD_ACTIVE_PIN_BOUNDARY_BLOCKED"
                child_code: int | None = None
                hashes = artifact_hashes(paths)
                p0_pass = None
                proof_verified = False
                exit_code = 2
            elif result.returncode not in {0, 1}:
                state = "FAILED_CHILD"
                error = "CHILD_EXIT_NON_AUDIT"
                child_code = result.returncode
                hashes = artifact_hashes(paths)
                p0_pass = None
                proof_verified = False
                exit_code = 2
            else:
                child_code = result.returncode
                try:
                    p0_pass, complete = output_validator(
                        paths,
                        execution_legacy,
                        result.returncode,
                    )
                    verify_staged_audit_bundle(
                        execution_legacy,
                        bundle_root,
                        audit_invocation,
                    )
                except (
                    OSError,
                    OneShotError,
                    QueryV3Error,
                    KeyError,
                    TypeError,
                    ValueError,
                ):
                    state = "FAILED_OUTPUT_VALIDATION"
                    error = "OUTPUT_VALIDATION_FAILED"
                    hashes = artifact_hashes(paths)
                    p0_pass = None
                    proof_verified = False
                    exit_code = 2
                else:
                    state = (
                        "COMPLETED_EVIDENCE_P0_PASS"
                        if p0_pass
                        else "COMPLETED_EVIDENCE_P0_BLOCKED"
                    )
                    error = None
                    hashes = complete
                    proof_verified = True
                    exit_code = 0 if p0_pass else 1
        except QueryChildLaunchError:
            state = "FAILED_CHILD_LAUNCH_PRE_QUERY"
            error = "CHILD_PROCESS_CREATE_FAILED"
            child_code = None
            hashes = artifact_hashes(paths)
            p0_pass = None
            proof_verified = False
            exit_code = 2
        except subprocess.TimeoutExpired:
            state = "TIMED_OUT_OUTCOME_UNKNOWN"
            error = "CHILD_TIMEOUT_OUTCOME_UNKNOWN"
            child_code = None
            hashes = artifact_hashes(paths)
            p0_pass = None
            proof_verified = False
            exit_code = 2
        except KeyboardInterrupt:
            state = "INTERRUPTED_OUTCOME_UNKNOWN"
            error = "RUNNER_INTERRUPTED_OUTCOME_UNKNOWN"
            child_code = None
            hashes = artifact_hashes(paths)
            p0_pass = None
            proof_verified = False
            exit_code = 2
        except Exception:
            state = "FAILED_CHILD"
            error = "CHILD_EXECUTION_OUTCOME_UNKNOWN"
            child_code = None
            hashes = artifact_hashes(paths)
            p0_pass = None
            proof_verified = False
            exit_code = 2
        observed_end = _utc(clock(), "terminal time")
        if final_at is None:
            raise QueryV3Error("child path lacks final revalidation time")
        timeline_floor = max(consumed_at, final_at)
        if observed_end < timeline_floor:
            state = (
                "FAILED_CHILD_LAUNCH_PRE_QUERY"
                if state == "FAILED_CHILD_LAUNCH_PRE_QUERY"
                else "FAILED_OUTPUT_VALIDATION"
            )
            error = "NON_MONOTONIC_CLOCK_OUTCOME_UNKNOWN"
            child_code = None
            hashes = artifact_hashes(paths)
            p0_pass = None
            proof_verified = False
            exit_code = 2
        terminal = _terminal(
            verified,
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            audit_invocation_raw_sha256=audit_invocation_raw_sha256,
            audit_invocation_canonical_sha256=(
                audit_invocation_canonical_sha256
            ),
            pre_connect_gate_raw_sha256=pre_connect_gate_raw_sha256,
            pre_connect_gate_canonical_sha256=(
                pre_connect_gate_canonical_sha256
            ),
            query_invocation_raw_sha256=query_invocation_raw_sha256,
            query_invocation_canonical_sha256=(
                query_invocation_canonical_sha256
            ),
            started_at=consumed_at,
            final_revalidation_at=final_at,
            ended_at=max(timeline_floor, observed_end),
            terminal_state=state,
            error_code=error,
            child_exit_code=child_code,
            hashes=hashes,
            p0_pass=p0_pass,
            proof_verified=proof_verified,
        )
        write_json_create_only_at(
            guard,
            terminal_name,
            terminal,
            TERMINAL_SCHEMA_PATH,
            "T1 query v3 terminal",
        )
        return exit_code, terminal
    except (FileExistsError, OneShotError) as exc:
        raise QueryV3Error(str(exc)) from exc
    finally:
        guard.close()


def verify_and_execute_query(
    release_path: Path,
    keyring_path: Path,
    manifest_path: Path,
    dsn_file: Path,
    readiness_packet_path: Path,
    readiness_inputs: ReadinessInputs,
    pins: ReadinessPins,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    child_executor: Callable[..., subprocess.CompletedProcess[str]] = run_query_child,
    output_validator: Callable[
        [ArtifactPaths, VerifiedRelease, int],
        tuple[bool, dict[str, str]],
    ] = validate_completed_outputs,
    require_root_owned_parent: bool = True,
) -> tuple[int, dict[str, Any]]:
    initial = verify_query_release(
        release_path,
        keyring_path,
        manifest_path,
        readiness_packet_path,
        readiness_inputs,
        pins,
        now=_utc(clock(), "initial verification time"),
        require_root_owned_parent=require_root_owned_parent,
    )

    def revalidator(at: datetime) -> VerifiedQueryRelease:
        current = verify_query_release(
            release_path,
            keyring_path,
            manifest_path,
            readiness_packet_path,
            readiness_inputs,
            pins,
            now=at,
            require_root_owned_parent=require_root_owned_parent,
        )
        _assert_same(initial, current)
        return current

    return execute_verified_query(
        initial,
        pins,
        dsn_file,
        revalidator,
        clock=clock,
        child_executor=child_executor,
        output_validator=output_validator,
        require_root_owned_parent=require_root_owned_parent,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query-release", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--dsn-file", type=Path, required=True)
    parser.add_argument("--readiness-packet", type=Path, required=True)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--oci-layout-archive", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--content-attestation", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--provenance-keyring", type=Path, required=True)
    parser.add_argument("--t1-keyring", type=Path, required=True)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--outcome-keyring", type=Path, required=True)
    parser.add_argument("--expected-t1-runtime-source-commit-sha", required=True)
    parser.add_argument("--expected-t1-runtime-image-digest", required=True)
    parser.add_argument("--expected-l3-contract-source-commit-sha", required=True)
    parser.add_argument(
        "--expected-outcome-contract-source-commit-assertion",
        required=True,
    )
    parser.add_argument("--expected-questdb-image-digest", required=True)
    add_source_arguments(parser)
    add_post_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pins = _read_production_pins()
        exit_code, terminal = verify_and_execute_query(
            args.query_release,
            args.trusted_keyring,
            args.manifest,
            args.dsn_file,
            args.readiness_packet,
            inputs_from_args(args),
            pins,
        )
    except (OSError, OneShotError, QueryV3Error, ReadinessV2Error) as exc:
        print(f"T1 query v3 blocked: {exc}", file=sys.stderr)
        return 2
    print(f"terminal_state={terminal['terminal_state']}")
    print(f"attempt_id={terminal['attempt_id']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
