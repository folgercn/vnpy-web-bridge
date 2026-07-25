#!/usr/bin/env python3
"""Verify and consume a C_FAST T1 release-v2 foundation without querying."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from commodity_c_fast_t1_one_shot import (
    MANIFEST_SCHEMA_PATH,
    OneShotError,
    _load_trusted_public_key,
    canonical_json,
    custody_entry_exists,
    custody_path_sha256,
    load_json_strict,
    open_custody_guard,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_at,
    read_regular_file_strict,
    validate_custody_identity,
    validate_json_schema,
    write_json_create_only_at,
)
from commodity_c_fast_t1_readiness_v2 import (
    ReadinessInputs,
    ReadinessPins,
    ReadinessV2Error,
    VerifiedReadinessPacket,
    verify_existing_readiness_packet,
)


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = Path(__file__).resolve()
RELEASE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-one-shot-release-v2.schema.json"
)
CONSUME_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-consume-v2.schema.json"
)
HARNESS_TERMINAL_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-harness-terminal-v2.schema.json"
)
READINESS_VERIFIER_PATH = (
    ROOT / "scripts/commodity_c_fast_t1_readiness_v2.py"
)
READINESS_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-readiness-v2.schema.json"
)

RELEASE_SCHEMA_VERSION = "commodity_c_fast_t1_one_shot_release_v2"
RELEASE_PURPOSE = "c_fast_l1_l5_t1_release_v2_foundation_no_query"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MAX_RELEASE_TTL = timedelta(minutes=10)

ACTUAL_AUTHORITY_FIELDS = (
    "foundation_is_authority",
    "packet_is_authority",
    "authority_granted",
    "readiness_authorized",
    "t1_one_shot_child_launch_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "local_audit_artifact_write_authorized",
    "network_authorized",
    "production_query_authorized",
    "readonly_query_authorized",
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
    "replay_allowed",
)


class ReleaseV2FoundationError(RuntimeError):
    """Expected fail-closed foundation verification error."""


@dataclass(frozen=True)
class VerifiedReleaseV2:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    readiness: VerifiedReadinessPacket


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReleaseV2FoundationError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def release_attempt_id(release_id: str) -> str:
    return "attempt-" + _hash(release_id.encode("utf-8"))


def unsigned_release_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def readiness_source_bundle_index(
    readiness: VerifiedReadinessPacket,
) -> str:
    packet = readiness.payload
    exact_sources = {
        "readiness_packet_raw_sha256": readiness.raw_sha256,
        "readiness_packet_canonical_sha256": readiness.canonical_sha256,
        "t1_runtime": packet["t1_runtime"],
        "build_registry_provenance": packet["build_registry_provenance"],
        "readonly_deployment_outcome": packet[
            "readonly_deployment_outcome"
        ],
    }
    return _hash(canonical_json(exact_sources))


def _readiness_binding(
    readiness: VerifiedReadinessPacket,
) -> dict[str, Any]:
    packet = readiness.payload
    runtime = packet["t1_runtime"]
    provenance = packet["build_registry_provenance"]
    outcome = packet["readonly_deployment_outcome"]
    return {
        "packet_id": packet["packet_id"],
        "packet_raw_sha256": readiness.raw_sha256,
        "packet_canonical_sha256": readiness.canonical_sha256,
        "generated_at": packet["generated_at"],
        "expires_at": packet["expires_at"],
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


def validate_release_semantics(
    payload: dict[str, Any],
    readiness: VerifiedReadinessPacket,
    *,
    now: datetime,
) -> None:
    validate_json_schema(payload, RELEASE_SCHEMA_PATH, "T1 release v2")
    if (
        payload["schema_version"] != RELEASE_SCHEMA_VERSION
        or payload["purpose"] != RELEASE_PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
    ):
        raise ReleaseV2FoundationError("release identity is invalid")
    if not hmac.compare_digest(
        payload["attempt_id"],
        release_attempt_id(payload["release_id"]),
    ):
        raise ReleaseV2FoundationError(
            "attempt_id does not match release_id"
        )
    human_signature = str(payload["human_signature"]).strip()
    if not human_signature or human_signature.startswith("PENDING_"):
        raise ReleaseV2FoundationError(
            "human_signature must contain final human text"
        )
    if not str(payload["reviewer_role"]).strip():
        raise ReleaseV2FoundationError("reviewer_role must not be empty")
    current = _utc(now, "verification time")
    try:
        issued_at = parse_datetime(payload["issued_at"], "issued_at")
        not_before = parse_datetime(payload["not_before"], "not_before")
        expires_at = parse_datetime(payload["expires_at"], "expires_at")
        readiness_generated_at = parse_datetime(
            readiness.payload["generated_at"],
            "readiness.generated_at",
        )
        readiness_expires_at = parse_datetime(
            readiness.payload["expires_at"],
            "readiness.expires_at",
        )
    except OneShotError as exc:
        raise ReleaseV2FoundationError(str(exc)) from exc
    if not issued_at <= not_before <= current < expires_at:
        raise ReleaseV2FoundationError("release is not currently active")
    if readiness_generated_at > issued_at:
        raise ReleaseV2FoundationError(
            "release cannot predate its readiness packet"
        )
    if expires_at - issued_at > MAX_RELEASE_TTL:
        raise ReleaseV2FoundationError("release TTL cannot exceed 10 minutes")
    if expires_at > readiness_expires_at:
        raise ReleaseV2FoundationError(
            "release cannot outlive its readiness packet"
        )
    margin = timedelta(seconds=payload["minimum_launch_margin_seconds"])
    if current + margin >= expires_at:
        raise ReleaseV2FoundationError(
            "release has insufficient launch margin"
        )
    if payload["readiness"] != _readiness_binding(readiness):
        raise ReleaseV2FoundationError(
            "release does not bind the exact readiness packet"
        )
    if any(payload[field] is not False for field in ACTUAL_AUTHORITY_FIELDS):
        raise ReleaseV2FoundationError(
            "foundation release attempts to grant actual authority"
        )


def verify_release(
    release_path: Path,
    keyring_path: Path,
    manifest_path: Path,
    readiness_packet_path: Path,
    readiness_inputs: ReadinessInputs,
    pins: ReadinessPins,
    *,
    now: datetime,
    require_root_owned_parent: bool = True,
) -> VerifiedReleaseV2:
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
            raise ReleaseV2FoundationError(
                "release is outside the pinned custody"
            )
        guard = open_custody_guard(
            custody,
            require_root_owned_parent=require_root_owned_parent,
        )
        try:
            release_raw = read_regular_file_at(
                guard,
                release_path.name,
                "signed T1 release v2",
            )
            release = parse_json_bytes(release_raw, "signed T1 release v2")
            validate_release_semantics(release, readiness, now=current)
            validate_custody_identity(
                guard,
                release["custody_identity_sha256"],
            )
        finally:
            guard.close()
        keyring_raw = read_regular_file_strict(
            keyring_path,
            "T1 release v2 keyring",
            private=True,
        )
        keyring = parse_json_bytes(keyring_raw, "T1 release v2 keyring")
        manifest_raw = read_regular_file_strict(
            manifest_path,
            "T1 audit manifest",
        )
        manifest = parse_json_bytes(manifest_raw, "T1 audit manifest")
    except (OneShotError, OSError) as exc:
        raise ReleaseV2FoundationError(str(exc)) from exc

    verified = VerifiedReleaseV2(
        payload=release,
        raw_sha256=_hash(release_raw),
        canonical_sha256=_hash(canonical_json(release)),
        readiness=readiness,
    )
    keyring_sha256 = _hash(canonical_json(keyring))
    if (
        keyring_sha256 != pins.t1_authority_keyring_sha256
        or keyring_sha256 != release["trusted_keyring_sha256"]
    ):
        raise ReleaseV2FoundationError(
            "release keyring does not match the readiness pin"
        )
    try:
        public_key = _load_trusted_public_key(
            keyring,
            release["signer_key_id"],
        )
        signature = base64.b64decode(release["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("wrong Ed25519 signature length")
        public_key.verify(
            signature,
            canonical_json(unsigned_release_payload(release)),
        )
    except (InvalidSignature, OneShotError, ValueError) as exc:
        raise ReleaseV2FoundationError(
            "T1 release v2 Ed25519 signature is invalid"
        ) from exc

    expected_files = {
        "runner_sha256": RUNNER_PATH,
        "release_schema_sha256": RELEASE_SCHEMA_PATH,
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "harness_terminal_schema_sha256": HARNESS_TERMINAL_SCHEMA_PATH,
        "readiness_verifier_sha256": READINESS_VERIFIER_PATH,
        "readiness_schema_sha256": READINESS_SCHEMA_PATH,
    }
    for field, path in expected_files.items():
        actual = _hash(read_regular_file_strict(path, field))
        if actual != release[field]:
            raise ReleaseV2FoundationError(
                f"{field} does not match the frozen runtime file"
            )
    packet = readiness.payload
    if (
        release["pin_root_path_sha256"]
        != packet["pin_root_path_sha256"]
        or release["custody_path_sha256"] != custody_path_sha256(custody)
        or release["readiness_source_bundle_index_sha256"]
        != readiness_source_bundle_index(readiness)
        or release["namespaces"]
        != {
            **packet["source_namespaces"],
            **packet["digest_namespaces"],
        }
    ):
        raise ReleaseV2FoundationError(
            "release pins or readiness namespaces do not match"
        )
    validate_json_schema(manifest, MANIFEST_SCHEMA_PATH, "T1 audit manifest")
    if (
        release["manifest_raw_sha256"] != _hash(manifest_raw)
        or release["manifest_canonical_sha256"]
        != _hash(canonical_json(manifest))
        or release["snapshot_id"] != manifest["snapshot_id"]
        or release["audit_window"] != manifest["audit_window"]
    ):
        raise ReleaseV2FoundationError(
            "release does not bind the exact audit manifest"
        )
    try:
        l3_release = load_json_strict(
            readiness_inputs.outcome_source.release,
            "readonly deployment release",
        )
    except OneShotError as exc:
        raise ReleaseV2FoundationError(str(exc)) from exc
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
        raise ReleaseV2FoundationError(
            "release QuestDB identity/build binding is invalid"
        )
    return verified


def _consume_payload(
    verified: VerifiedReleaseV2,
    *,
    consumed_at: datetime,
) -> dict[str, Any]:
    release = verified.payload
    readiness = release["readiness"]
    return {
        "schema_version": "commodity_c_fast_t1_consume_v2",
        "purpose": "c_fast_t1_release_v2_foundation_consume_no_query",
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
        "readiness_source_bundle_index_sha256": release[
            "readiness_source_bundle_index_sha256"
        ],
        "manifest_raw_sha256": release["manifest_raw_sha256"],
        "manifest_canonical_sha256": release[
            "manifest_canonical_sha256"
        ],
        "trusted_keyring_sha256": release["trusted_keyring_sha256"],
        "custody_identity_sha256": release["custody_identity_sha256"],
        "custody_path_sha256": release["custody_path_sha256"],
        "harness_only": True,
        "consume_is_authority": False,
        "query_started": False,
        "production_queried": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "replay_allowed": False,
    }


def _terminal_payload(
    verified: VerifiedReleaseV2,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    *,
    started_at: datetime,
    ended_at: datetime,
    success: bool,
) -> dict[str, Any]:
    release = verified.payload
    readiness = release["readiness"]
    return {
        "schema_version": "commodity_c_fast_t1_harness_terminal_v2",
        "purpose": "c_fast_t1_release_v2_foundation_harness_no_query",
        "candidate_id": CANDIDATE_ID,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "terminal_state": (
            "HARNESS_REVALIDATED_NO_QUERY"
            if success
            else "FAILED_FINAL_READINESS_REVALIDATION_NO_QUERY"
        ),
        "error_code": None if success else "READINESS_REVALIDATION_FAILED",
        "release_raw_sha256": verified.raw_sha256,
        "release_canonical_sha256": verified.canonical_sha256,
        "consume_marker_raw_sha256": consume_raw_sha256,
        "consume_marker_canonical_sha256": consume_canonical_sha256,
        "readiness_packet_raw_sha256": readiness[
            "packet_raw_sha256"
        ],
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
        "readiness_source_bundle_index_sha256": release[
            "readiness_source_bundle_index_sha256"
        ],
        "manifest_raw_sha256": release["manifest_raw_sha256"],
        "manifest_canonical_sha256": release[
            "manifest_canonical_sha256"
        ],
        "started_at": _utc(started_at, "start time").isoformat(),
        "ended_at": _utc(ended_at, "end time").isoformat(),
        "final_revalidation_completed_at": (
            _utc(ended_at, "end time").isoformat() if success else None
        ),
        "query_execution_state": "NOT_STARTED",
        "child_launched": False,
        "production_queried": False,
        "write_probe_attempted": False,
        "database_mutations": 0,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
        "terminal_is_authority": False,
        "harness_result_is_t1_success": False,
        "harness_result_is_p0_success": False,
        "query_terminal_compatible": False,
        "p0_acceptance_authorized": False,
        "replay_allowed": False,
    }


def _execute_no_query_harness(
    verified: VerifiedReleaseV2,
    pins: ReadinessPins,
    final_revalidator: Callable[[datetime], VerifiedReadinessPacket],
    *,
    clock: Callable[[], datetime],
    require_root_owned_parent: bool = True,
) -> tuple[int, dict[str, Any]]:
    """Burn one attempt, revalidate readiness, and emit a NO_QUERY terminal."""
    custody = pins.packet_custody_path.resolve(strict=True)
    guard = open_custody_guard(
        custody,
        require_root_owned_parent=require_root_owned_parent,
    )
    consume_name = f"{verified.payload['attempt_id']}.consumed-v2.json"
    terminal_name = (
        f"{verified.payload['attempt_id']}.harness-terminal-v2.json"
    )
    try:
        if custody_entry_exists(guard, consume_name):
            raise ReleaseV2FoundationError(
                "release attempt is already consumed and cannot replay"
            )
        if custody_entry_exists(guard, terminal_name):
            raise ReleaseV2FoundationError(
                "harness terminal exists without a consume marker"
            )
        started_at = _utc(clock(), "consume time")
        consume = _consume_payload(verified, consumed_at=started_at)
        consume_raw_sha256 = write_json_create_only_at(
            guard,
            consume_name,
            consume,
            CONSUME_SCHEMA_PATH,
            "T1 release v2 consume marker",
        )
        consume_raw = read_regular_file_at(
            guard,
            consume_name,
            "T1 release v2 consume marker",
        )
        if (
            _hash(consume_raw) != consume_raw_sha256
            or parse_json_bytes(consume_raw, "T1 release v2 consume marker")
            != consume
        ):
            raise ReleaseV2FoundationError(
                "exact consume marker re-open verification failed"
            )
        consume_canonical_sha256 = _hash(canonical_json(consume))
        final_time = _utc(clock(), "final revalidation time")
        success = False
        try:
            final = final_revalidator(final_time)
            success = (
                final.payload == verified.readiness.payload
                and final.raw_sha256 == verified.readiness.raw_sha256
                and final.canonical_sha256
                == verified.readiness.canonical_sha256
            )
            if success:
                validate_release_semantics(
                    verified.payload,
                    final,
                    now=final_time,
                )
        except (
            OneShotError,
            ReadinessV2Error,
            ReleaseV2FoundationError,
            OSError,
            ValueError,
        ):
            success = False
        ended_at = _utc(clock(), "terminal time")
        terminal = _terminal_payload(
            verified,
            consume_raw_sha256,
            consume_canonical_sha256,
            started_at=started_at,
            ended_at=ended_at,
            success=success,
        )
        write_json_create_only_at(
            guard,
            terminal_name,
            terminal,
            HARNESS_TERMINAL_SCHEMA_PATH,
            "T1 release v2 harness terminal",
        )
        return (0 if success else 2), terminal
    except (OneShotError, FileExistsError) as exc:
        raise ReleaseV2FoundationError(str(exc)) from exc
    finally:
        guard.close()


def verify_and_execute_no_query_harness(
    release_path: Path,
    keyring_path: Path,
    manifest_path: Path,
    readiness_packet_path: Path,
    readiness_inputs: ReadinessInputs,
    pins: ReadinessPins,
    *,
    clock: Callable[[], datetime],
    require_root_owned_parent: bool = True,
) -> tuple[int, dict[str, Any]]:
    """Use the only public harness path: verify, consume, verify again."""
    verified = verify_release(
        release_path,
        keyring_path,
        manifest_path,
        readiness_packet_path,
        readiness_inputs,
        pins,
        now=_utc(clock(), "initial verification time"),
        require_root_owned_parent=require_root_owned_parent,
    )

    def final_revalidator(at: datetime) -> VerifiedReadinessPacket:
        final_verified = verify_release(
            release_path,
            keyring_path,
            manifest_path,
            readiness_packet_path,
            readiness_inputs,
            pins,
            now=at,
            require_root_owned_parent=require_root_owned_parent,
        )
        if (
            final_verified.raw_sha256 != verified.raw_sha256
            or final_verified.canonical_sha256
            != verified.canonical_sha256
        ):
            raise ReleaseV2FoundationError(
                "release changed before final harness revalidation"
            )
        return final_verified.readiness

    return _execute_no_query_harness(
        verified,
        pins,
        final_revalidator,
        clock=clock,
        require_root_owned_parent=require_root_owned_parent,
    )
