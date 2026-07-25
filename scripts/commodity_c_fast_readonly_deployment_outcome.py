#!/usr/bin/env python3
"""Verify one independently signed C_FAST readonly deployment outcome."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import commodity_c_fast_readonly_deployment_release as release_module
from commodity_c_fast_readonly_deployment_release import (
    DeploymentEvidencePaths,
    DeploymentReleaseError,
    RECEIPT_REQUIRED_FALSE_FIELDS,
    RECEIPT_REQUIRED_ZERO_FIELDS,
    _load_json,
    _parse_time,
    _require_aware_datetime,
    _validate_schema,
    canonical_json,
)
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    custody_path_sha256,
    open_custody_guard,
    parse_json_bytes,
    read_regular_file_at,
    read_regular_file_strict,
    read_root_owned_deployment_pin,
    write_json_create_only_at,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
SCHEMA_DIR = ROOT / "docs/schemas"
OUTCOME_SCHEMA_PATH = (
    SCHEMA_DIR / "commodity-c-fast-readonly-deployment-outcome-v1.schema.json"
)
POST_SCHEMA_PATHS = {
    "execution": SCHEMA_DIR
    / "commodity-c-fast-readonly-deployment-execution-v1.schema.json",
    "writer_post": SCHEMA_DIR
    / "commodity-c-fast-readonly-deployment-writer-post-v1.schema.json",
    "health_post": SCHEMA_DIR
    / "commodity-c-fast-readonly-deployment-health-post-v1.schema.json",
    "backlog_post": SCHEMA_DIR
    / "commodity-c-fast-readonly-deployment-backlog-post-v1.schema.json",
    "principal_secret_post": SCHEMA_DIR
    / "commodity-c-fast-readonly-deployment-principal-secret-post-v1.schema.json",
    "network_post": SCHEMA_DIR
    / "commodity-c-fast-readonly-deployment-network-post-v1.schema.json",
}

OUTCOME_SCHEMA_VERSION = "commodity_c_fast_readonly_deployment_outcome_v1"
OUTCOME_PURPOSE = "c_fast_questdb_readonly_deployment_post_outcome"
OUTCOME_KEYRING_VERSION = (
    "commodity_c_fast_readonly_deployment_outcome_trusted_keys_v1"
)
OUTCOME_KEY_PURPOSE = "readonly_deployment_outcome_signer"
T1_KEYRING_VERSION = "commodity_c_fast_t1_trusted_keys_v1"
T1_KEY_PURPOSE = "t1_audit_release_signer"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_OUTCOME_SIGNING_LAG = timedelta(hours=24)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IMAGE_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
OUTCOME_PIN_ROOT = Path("/run/c-fast-readonly-deployment-outcome-pins")
OUTCOME_KEYRING_PIN_PATH = OUTCOME_PIN_ROOT / "outcome-keyring.sha256"
RELEASE_KEYRING_PIN_PATH = OUTCOME_PIN_ROOT / "release-keyring.sha256"
T1_KEYRING_PIN_PATH = OUTCOME_PIN_ROOT / "t1-keyring.sha256"

POST_VERSIONS = {
    "execution": "commodity_c_fast_readonly_deployment_execution_v1",
    "writer_post": "commodity_c_fast_readonly_deployment_writer_post_v1",
    "health_post": "commodity_c_fast_readonly_deployment_health_post_v1",
    "backlog_post": "commodity_c_fast_readonly_deployment_backlog_post_v1",
    "principal_secret_post": (
        "commodity_c_fast_readonly_deployment_principal_secret_post_v1"
    ),
    "network_post": "commodity_c_fast_readonly_deployment_network_post_v1",
}

OUTCOME_TRUE_FIELDS = (
    "raw_signed_release_required_for_audit",
    "deployment_executed",
    "restart_executed",
    "writer_continuity_verified",
    "post_restart_health_verified",
    "backlog_drain_verified",
    "readonly_principal_verified",
    "secret_file_verified",
    "isolated_network_verified",
)
OUTCOME_FALSE_FIELDS = (
    "dispatch_changed",
    "receipt_is_authority",
    "outcome_is_authority",
    "replay_allowed",
    "readiness_authorized",
    "readonly_principal_deployment_authorized",
    "readonly_secret_file_installation_authorized",
    "questdb_restart_authorized",
    "questdb_recreate_authorized",
    "questdb_image_change_authorized",
    "writer_identity_mutation_authorized",
    "writer_secret_mutation_authorized",
    "network_mutation_authorized",
    "unscoped_deployment_mutation_authorized",
    "production_query_authorized",
    "readonly_query_authorized",
    "collection_authorized",
    "write_probe_authorized",
    "database_mutation_authorized",
    "order_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "strategy_activation_authorized",
    "automatic_promotion_authorized",
    "web_bridge_deployment_authorized",
    "deployment_mutation_authorized",
    "runtime_activation_authorized",
    "dynamic_selection_allowed",
    "replacement_authorized",
    "production_authorized",
)
OUTCOME_ZERO_FIELDS = (
    "production_queries_executed",
    "readonly_queries_executed",
    "write_probes_attempted",
    "database_mutations",
    "web_bridge_rpc_calls",
    "orders_sent",
    "positions_modified",
)


class DeploymentOutcomeError(RuntimeError):
    """Expected fail-closed outcome verification error."""


@dataclass(frozen=True)
class OutcomeSourcePaths:
    release: Path
    release_keyring: Path
    consume_marker: Path
    receipt: Path
    pre_evidence: DeploymentEvidencePaths


@dataclass(frozen=True)
class PostEvidencePaths:
    execution: Path
    writer_post: Path
    health_post: Path
    backlog_post: Path
    principal_secret_post: Path
    network_post: Path

    def as_dict(self) -> dict[str, Path]:
        return {name: getattr(self, name) for name in POST_SCHEMA_PATHS}


@dataclass(frozen=True)
class VerifiedSourceChain:
    release: dict[str, Any]
    consume: dict[str, Any]
    receipt: dict[str, Any]
    release_raw_sha256: str
    release_canonical_sha256: str
    consume_raw_sha256: str
    receipt_raw_sha256: str
    pre_evidence_raw_sha256: dict[str, str]
    pre_evidence_bundle_index_sha256: str
    release_signer_public_bytes: bytes
    consume_marker_path: Path


@dataclass(frozen=True)
class VerifiedPostBundle:
    payloads: dict[str, dict[str, Any]]
    raw_sha256: dict[str, str]
    bundle_index_sha256: str


@dataclass(frozen=True)
class VerifiedDeploymentOutcome:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    outcome_signer_public_key_sha256: str
    source: VerifiedSourceChain
    post: VerifiedPostBundle


def unsigned_outcome_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def validate_outcome_custody_path(
    outcome_path: Path,
    source: VerifiedSourceChain,
) -> None:
    expected_name = f"{source.release['attempt_id']}.deployment-outcome.json"
    try:
        outcome_parent = outcome_path.parent.resolve(strict=True)
        custody_parent = source.consume_marker_path.parent.resolve(strict=True)
    except OSError as exc:
        raise DeploymentOutcomeError(
            "deployment outcome custody cannot be resolved"
        ) from exc
    if outcome_path.name != expected_name or outcome_parent != custody_parent:
        raise DeploymentOutcomeError(
            "deployment outcome must use the exact signed custody path"
        )


def read_signed_outcome_from_custody(
    outcome_path: Path,
    source: VerifiedSourceChain,
) -> tuple[bytes, dict[str, Any]]:
    validate_outcome_custody_path(outcome_path, source)
    try:
        guard = open_custody_guard(
            outcome_path.parent,
            require_root_owned_parent=False,
        )
        try:
            release_module.validate_custody_identity(
                guard,
                source.release["custody_identity_sha256"],
            )
            raw = read_regular_file_at(
                guard,
                outcome_path.name,
                "signed deployment outcome",
            )
        finally:
            os.close(guard.descriptor)
        return raw, parse_json_bytes(raw, "signed deployment outcome")
    except (OneShotError, DeploymentReleaseError) as exc:
        raise DeploymentOutcomeError(str(exc)) from exc


def write_signed_outcome_create_only(
    outcome_path: Path,
    payload: dict[str, Any],
    source: VerifiedSourceChain,
) -> None:
    validate_outcome_custody_path(outcome_path, source)
    try:
        guard = open_custody_guard(
            outcome_path.parent,
            require_root_owned_parent=False,
        )
        try:
            release_module.validate_custody_identity(
                guard,
                source.release["custody_identity_sha256"],
            )
            write_json_create_only_at(
                guard,
                outcome_path.name,
                payload,
                OUTCOME_SCHEMA_PATH,
                "signed deployment outcome",
            )
        finally:
            os.close(guard.descriptor)
    except FileExistsError as exc:
        raise DeploymentOutcomeError(
            "deployment outcome already exists; replay is forbidden"
        ) from exc
    except (OneShotError, DeploymentReleaseError) as exc:
        raise DeploymentOutcomeError(str(exc)) from exc


def _sha256_file(path: Path, label: str) -> str:
    try:
        raw = read_regular_file_strict(path, label, limit=MAX_JSON_BYTES)
    except OneShotError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    return hashlib.sha256(raw).hexdigest()


def _load_public_keys(
    path: Path,
    *,
    expected_sha256: str,
    expected_version: str,
    purpose: str,
    label: str,
) -> tuple[dict[str, bytes], str]:
    try:
        _raw, keyring = _load_json(path, label, private=True)
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    if set(keyring) != {"schema_version", "keys"}:
        raise DeploymentOutcomeError(f"{label} fields are invalid")
    if keyring["schema_version"] != expected_version:
        raise DeploymentOutcomeError(f"{label} version is invalid")
    if not isinstance(keyring["keys"], list) or not keyring["keys"]:
        raise DeploymentOutcomeError(f"{label} must contain keys")
    actual_sha256 = hashlib.sha256(canonical_json(keyring)).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise DeploymentOutcomeError(
            f"{label} does not match independent canonical pin"
        )
    result: dict[str, bytes] = {}
    for entry in keyring["keys"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"key_id", "purpose", "public_key_base64"}
        ):
            raise DeploymentOutcomeError(f"{label} key entry is invalid")
        if entry["purpose"] != purpose:
            raise DeploymentOutcomeError(
                f"{label} contains a wrong-purpose authority key"
            )
        key_id = str(entry["key_id"])
        if key_id in result:
            raise DeploymentOutcomeError(f"{label} contains duplicate key_id")
        try:
            raw = base64.b64decode(
                entry["public_key_base64"],
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise DeploymentOutcomeError(
                f"{label} contains invalid public key"
            ) from exc
        if len(raw) != 32:
            raise DeploymentOutcomeError(
                f"{label} public key must contain 32 bytes"
            )
        result[key_id] = raw
    if not result:
        raise DeploymentOutcomeError(
            f"{label} contains no {purpose} authority key"
        )
    return result, actual_sha256


def _read_json_raw(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = read_regular_file_strict(path, label, limit=MAX_JSON_BYTES)
        payload = parse_json_bytes(raw, label)
    except OneShotError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    return raw, payload


def _validate_receipt_chain(
    source: OutcomeSourcePaths,
    *,
    expected_release_keyring_sha256: str,
    expected_release_source_commit_sha: str,
    expected_questdb_image_digest: str,
) -> VerifiedSourceChain:
    consume_raw, consume = _read_json_raw(
        source.consume_marker,
        "readonly deployment consume marker",
    )
    receipt_raw, receipt = _read_json_raw(
        source.receipt,
        "readonly deployment receipt",
    )
    try:
        _validate_schema(
            consume,
            release_module.CONSUME_SCHEMA_PATH,
            "readonly deployment consume marker",
        )
        _validate_schema(
            receipt,
            release_module.RECEIPT_SCHEMA_PATH,
            "readonly deployment receipt",
        )
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    consumed_at = _parse_time(consume["consumed_at"], "consumed_at")
    try:
        verified = release_module.verify_release(
            source.release,
            source.release_keyring,
            source.pre_evidence,
            source_commit_sha=expected_release_source_commit_sha,
            questdb_image_digest=expected_questdb_image_digest,
            pinned_keyring_sha256=expected_release_keyring_sha256,
            now=consumed_at,
        )
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    release = verified.payload
    release_raw_sha256 = verified.release_raw_sha256
    release_canonical_sha256 = verified.release_canonical_sha256
    consume_raw_sha256 = hashlib.sha256(consume_raw).hexdigest()
    receipt_raw_sha256 = hashlib.sha256(receipt_raw).hexdigest()

    consume_name = f"{release['attempt_id']}.deployment-consumed.json"
    receipt_name = f"{release['attempt_id']}.deployment-receipt.json"
    try:
        consume_parent = source.consume_marker.parent.resolve(strict=True)
        receipt_parent = source.receipt.parent.resolve(strict=True)
    except OSError as exc:
        raise DeploymentOutcomeError(
            "consume/receipt custody cannot be resolved"
        ) from exc
    if (
        source.consume_marker.name != consume_name
        or source.receipt.name != receipt_name
        or consume_parent != receipt_parent
    ):
        raise DeploymentOutcomeError(
            "consume/receipt are not exact attempt custody entries"
        )
    try:
        actual_custody_path_sha256 = custody_path_sha256(consume_parent)
        guard = open_custody_guard(
            consume_parent,
            require_root_owned_parent=False,
        )
        try:
            release_module.validate_custody_identity(
                guard,
                release["custody_identity_sha256"],
            )
            guarded_consume_raw = read_regular_file_at(
                guard,
                consume_name,
                "readonly deployment consume marker",
            )
            guarded_receipt_raw = read_regular_file_at(
                guard,
                receipt_name,
                "readonly deployment receipt",
            )
        finally:
            os.close(guard.descriptor)
    except (OneShotError, DeploymentReleaseError) as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    if actual_custody_path_sha256 != release["custody_path_sha256"]:
        raise DeploymentOutcomeError(
            "consume/receipt custody path does not match signed release"
        )
    if guarded_consume_raw != consume_raw or guarded_receipt_raw != receipt_raw:
        raise DeploymentOutcomeError(
            "consume/receipt changed during custody verification"
        )

    shared = {
        "candidate_id": CANDIDATE_ID,
        "release_id": release["release_id"],
        "attempt_id": release["attempt_id"],
        "release_raw_sha256": release_raw_sha256,
        "release_canonical_sha256": release_canonical_sha256,
        "evidence_bundle_index_sha256": (
            verified.evidence_bundle_index_sha256
        ),
    }
    for field, value in shared.items():
        if consume.get(field) != value or receipt.get(field) != value:
            raise DeploymentOutcomeError(
                f"consume/receipt {field} does not match signed release"
            )
    if consume["trusted_keyring_sha256"] != expected_release_keyring_sha256:
        raise DeploymentOutcomeError(
            "consume marker release keyring binding is invalid"
        )
    if consume["source_commit_sha"] != expected_release_source_commit_sha:
        raise DeploymentOutcomeError(
            "consume marker source commit binding is invalid"
        )
    if consume["questdb_image_digest"] != expected_questdb_image_digest:
        raise DeploymentOutcomeError(
            "consume marker QuestDB image binding is invalid"
        )
    if consume["custody_identity_sha256"] != release["custody_identity_sha256"]:
        raise DeploymentOutcomeError(
            "consume marker custody identity binding is invalid"
        )
    if consume["custody_path_sha256"] != release["custody_path_sha256"]:
        raise DeploymentOutcomeError(
            "consume marker custody path binding is invalid"
        )
    if receipt["consume_marker_raw_sha256"] != consume_raw_sha256:
        raise DeploymentOutcomeError(
            "receipt does not bind exact consume marker bytes"
        )
    if receipt["verified_at"] != consume["consumed_at"]:
        raise DeploymentOutcomeError(
            "receipt verified_at must equal consumed_at"
        )
    if receipt["signer_key_id"] != release["signer_key_id"]:
        raise DeploymentOutcomeError(
            "receipt release signer binding is invalid"
        )
    if receipt["signer_key_purpose"] != release_module.TRUSTED_KEY_PURPOSE:
        raise DeploymentOutcomeError(
            "receipt release signer purpose is invalid"
        )
    if receipt["signature_verified"] is not True:
        raise DeploymentOutcomeError("receipt must record verified signature")
    for field in RECEIPT_REQUIRED_FALSE_FIELDS:
        if receipt[field] is not False:
            raise DeploymentOutcomeError(
                f"receipt attempts to grant forbidden {field}"
            )
    for field in RECEIPT_REQUIRED_ZERO_FIELDS:
        if type(receipt[field]) is not int or receipt[field] != 0:
            raise DeploymentOutcomeError(
                f"receipt {field} must remain exact integer zero"
            )
    if consume["replay_allowed"] is not False:
        raise DeploymentOutcomeError("consume marker replay must be false")
    if consume["deployment_executed"] is not False:
        raise DeploymentOutcomeError(
            "consume marker must remain a pre-execution record"
        )

    release_keys, _release_keyring_sha256 = _load_public_keys(
        source.release_keyring,
        expected_sha256=expected_release_keyring_sha256,
        expected_version=release_module.TRUSTED_KEYRING_VERSION,
        purpose=release_module.TRUSTED_KEY_PURPOSE,
        label="readonly deployment release keyring",
    )
    try:
        release_signer_public = release_keys[str(release["signer_key_id"])]
    except KeyError as exc:
        raise DeploymentOutcomeError(
            "release signer is absent from pinned release keyring"
        ) from exc
    return VerifiedSourceChain(
        release=release,
        consume=consume,
        receipt=receipt,
        release_raw_sha256=release_raw_sha256,
        release_canonical_sha256=release_canonical_sha256,
        consume_raw_sha256=consume_raw_sha256,
        receipt_raw_sha256=receipt_raw_sha256,
        pre_evidence_raw_sha256=verified.evidence_raw_sha256,
        pre_evidence_bundle_index_sha256=(
            verified.evidence_bundle_index_sha256
        ),
        release_signer_public_bytes=release_signer_public,
        consume_marker_path=source.consume_marker,
    )


def _parse_aware(value: Any, label: str) -> datetime:
    try:
        return _parse_time(value, label)
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc


def verify_post_bundle(
    source: VerifiedSourceChain,
    pre_paths: DeploymentEvidencePaths,
    paths: PostEvidencePaths,
) -> VerifiedPostBundle:
    payloads: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    for name, path in paths.as_dict().items():
        raw, payload = _read_json_raw(path, f"{name} evidence")
        try:
            _validate_schema(
                payload,
                POST_SCHEMA_PATHS[name],
                f"{name} evidence",
            )
        except DeploymentReleaseError as exc:
            raise DeploymentOutcomeError(str(exc)) from exc
        if payload["schema_version"] != POST_VERSIONS[name]:
            raise DeploymentOutcomeError(f"{name} schema version is invalid")
        if release_module._contains_sensitive_value(payload):
            raise DeploymentOutcomeError(
                f"{name} contains forbidden sensitive material"
            )
        payloads[name] = payload
        hashes[name] = hashlib.sha256(raw).hexdigest()

    release = source.release
    for name, payload in payloads.items():
        expected_common = {
            "candidate_id": CANDIDATE_ID,
            "release_id": release["release_id"],
            "attempt_id": release["attempt_id"],
            "release_raw_sha256": source.release_raw_sha256,
            "consume_marker_raw_sha256": source.consume_raw_sha256,
            "receipt_raw_sha256": source.receipt_raw_sha256,
        }
        for field, expected in expected_common.items():
            if payload[field] != expected:
                raise DeploymentOutcomeError(
                    f"{name} {field} binding is invalid"
                )

    execution = payloads["execution"]
    if execution["contract_source_commit_sha"] != release["source_commit_sha"]:
        raise DeploymentOutcomeError(
            "execution record source commit binding is invalid"
        )
    if execution["deployment_plan_raw_sha256"] != source.pre_evidence_raw_sha256[
        "deployment_plan"
    ]:
        raise DeploymentOutcomeError(
            "execution record deployment-plan binding is invalid"
        )
    for field in (
        "questdb_target_identity_sha256",
        "questdb_image_digest_before",
        "questdb_image_digest_after",
    ):
        expected = (
            release["questdb_target_identity_sha256"]
            if field == "questdb_target_identity_sha256"
            else release["questdb_image_digest"]
        )
        if execution[field] != expected:
            raise DeploymentOutcomeError(f"execution {field} is invalid")
    if (
        execution["questdb_container_identity_sha256_before"]
        != execution["questdb_container_identity_sha256_after"]
    ):
        raise DeploymentOutcomeError(
            "QuestDB container identity changed across restart"
        )

    consumed_at = _parse_aware(source.consume["consumed_at"], "consumed_at")
    not_before = _parse_aware(release["not_before"], "not_before")
    expires_at = _parse_aware(release["expires_at"], "expires_at")
    started_at = _parse_aware(
        execution["deployment_started_at"],
        "deployment_started_at",
    )
    secret_installed_at = _parse_aware(
        execution["secret_installed_at"],
        "secret_installed_at",
    )
    restart_started_at = _parse_aware(
        execution["restart_started_at"],
        "restart_started_at",
    )
    restart_completed_at = _parse_aware(
        execution["restart_completed_at"],
        "restart_completed_at",
    )
    ended_at = _parse_aware(
        execution["deployment_ended_at"],
        "deployment_ended_at",
    )
    if not (
        not_before
        <= consumed_at
        <= started_at
        <= secret_installed_at
        <= restart_started_at
        <= restart_completed_at
        <= ended_at
        < expires_at
    ):
        raise DeploymentOutcomeError(
            "deployment execution time chain is invalid"
        )
    if (
        ended_at - started_at
    ).total_seconds() > release["max_deployment_seconds"]:
        raise DeploymentOutcomeError(
            "deployment execution exceeds signed duration"
        )

    writer_pre_raw, writer_pre = _read_json_raw(
        pre_paths.writer_continuity_pre_evidence,
        "writer continuity pre evidence",
    )
    _writer_contract_raw, writer_contract = _read_json_raw(
        pre_paths.writer_continuity_post_evidence,
        "writer continuity post contract",
    )
    writer = payloads["writer_post"]
    if (
        hashlib.sha256(writer_pre_raw).hexdigest()
        != source.pre_evidence_raw_sha256[
            "writer_continuity_pre_evidence"
        ]
        or hashlib.sha256(_writer_contract_raw).hexdigest()
        != source.pre_evidence_raw_sha256[
            "writer_continuity_post_evidence"
        ]
    ):
        raise DeploymentOutcomeError(
            "writer pre/contract evidence changed after release verification"
        )
    if (
        writer["writer_continuity_pre_evidence_raw_sha256"]
        != hashlib.sha256(writer_pre_raw).hexdigest()
        or writer["writer_continuity_post_contract_raw_sha256"]
        != source.pre_evidence_raw_sha256[
            "writer_continuity_post_evidence"
        ]
        or writer["questdb_target_identity_sha256"]
        != release["questdb_target_identity_sha256"]
        or writer["writer_identity_sha256"]
        != writer_pre["writer_identity_sha256"]
        or writer["writer_last_commit_lag_seconds"]
        > writer_contract["max_commit_lag_seconds"]
        or writer["writer_queue_depth_delta"]
        != writer["writer_queue_depth"] - writer_pre["writer_queue_depth"]
        or writer["writer_queue_depth_delta"]
        > writer_contract["max_queue_depth_delta"]
    ):
        raise DeploymentOutcomeError(
            "writer post evidence bindings are invalid"
        )
    same_commit = (
        writer["writer_last_commit_id_sha256"]
        == writer_pre["writer_last_commit_id_sha256"]
    )
    if writer["commit_progress_state"] != "SAME" or not same_commit:
        raise DeploymentOutcomeError(
            "writer SAME commit relation is invalid"
        )

    backlog_pre_raw, _backlog_pre = _read_json_raw(
        pre_paths.backlog_evidence,
        "backlog pre evidence",
    )
    backlog = payloads["backlog_post"]
    if (
        hashlib.sha256(backlog_pre_raw).hexdigest()
        != source.pre_evidence_raw_sha256["backlog_evidence"]
        or backlog["backlog_pre_evidence_raw_sha256"]
        != hashlib.sha256(backlog_pre_raw).hexdigest()
        or backlog["questdb_target_identity_sha256"]
        != release["questdb_target_identity_sha256"]
    ):
        raise DeploymentOutcomeError(
            "backlog post evidence bindings are invalid"
        )
    principal = payloads["principal_secret_post"]
    principal_expected = {
        "questdb_target_identity_sha256": release[
            "questdb_target_identity_sha256"
        ],
        "readonly_principal_identity_sha256": release[
            "readonly_principal_identity_sha256"
        ],
        "secret_file_path_sha256": release["secret_file_path_sha256"],
        "owner_uid": release["secret_file_expected_owner_uid"],
        "owner_gid": release["secret_file_expected_owner_gid"],
        "mode": release["secret_file_expected_mode"],
    }
    for field, expected in principal_expected.items():
        if principal[field] != expected:
            raise DeploymentOutcomeError(
                f"principal/secret {field} binding is invalid"
            )
    network = payloads["network_post"]
    network_expected = {
        "isolated_network_identity_sha256": release[
            "isolated_network_identity_sha256"
        ],
        "runner_member_identity_sha256": release[
            "isolated_network_runner_member_identity_sha256"
        ],
        "questdb_member_identity_sha256": release[
            "isolated_network_questdb_member_identity_sha256"
        ],
        "member_count": release["isolated_network_expected_member_count"],
        "driver": release["isolated_network_driver_required"],
    }
    for field, expected in network_expected.items():
        if network[field] != expected:
            raise DeploymentOutcomeError(
                f"network post {field} binding is invalid"
            )
    if (
        network["runner_member_identity_sha256"]
        == network["questdb_member_identity_sha256"]
    ):
        raise DeploymentOutcomeError(
            "network post member identities must differ"
        )

    for name in (
        "writer_post",
        "health_post",
        "backlog_post",
        "principal_secret_post",
        "network_post",
    ):
        captured_at = _parse_aware(
            payloads[name]["captured_at"],
            f"{name}.captured_at",
        )
        if not restart_completed_at <= captured_at <= ended_at:
            raise DeploymentOutcomeError(
                f"{name} was not captured after restart and before end"
            )
    health = payloads["health_post"]
    if (
        health["questdb_target_identity_sha256"]
        != release["questdb_target_identity_sha256"]
        or _parse_aware(health["captured_at"], "health captured_at")
        - restart_completed_at
        > timedelta(seconds=120)
    ):
        raise DeploymentOutcomeError(
            "health post evidence recovery binding is invalid"
        )

    bundle_index = hashlib.sha256(canonical_json(hashes)).hexdigest()
    return VerifiedPostBundle(
        payloads=payloads,
        raw_sha256=hashes,
        bundle_index_sha256=bundle_index,
    )


def _runtime_bindings() -> tuple[str, dict[str, str]]:
    verifier_sha256 = _sha256_file(VERIFIER_PATH, "outcome verifier")
    schemas = {
        name: _sha256_file(path, f"{name} schema")
        for name, path in POST_SCHEMA_PATHS.items()
    }
    return verifier_sha256, schemas


def expected_outcome_payload(
    draft: dict[str, Any],
    source: VerifiedSourceChain,
    post: VerifiedPostBundle,
    *,
    outcome_keyring_sha256: str,
    t1_keyring_sha256: str,
    outcome_source_commit_assertion: str,
) -> dict[str, Any]:
    execution = post.payloads["execution"]
    verifier_sha256, post_schema_sha256 = _runtime_bindings()
    fixed: dict[str, Any] = {
        "schema_version": OUTCOME_SCHEMA_VERSION,
        "purpose": OUTCOME_PURPOSE,
        "candidate_id": CANDIDATE_ID,
        "issue_number": 114,
        "outcome_id": f"readonly-outcome-{post.bundle_index_sha256}",
        "outcome_keyring_sha256": outcome_keyring_sha256,
        "release_keyring_sha256": source.release["trusted_keyring_sha256"],
        "t1_keyring_sha256": t1_keyring_sha256,
        "outcome_contract_source_commit_assertion": (
            outcome_source_commit_assertion
        ),
        "release_source_commit_sha": source.release["source_commit_sha"],
        "verifier_sha256": verifier_sha256,
        "outcome_schema_sha256": _sha256_file(
            OUTCOME_SCHEMA_PATH,
            "outcome schema",
        ),
        "post_schema_sha256": post_schema_sha256,
        "release_id": source.release["release_id"],
        "attempt_id": source.release["attempt_id"],
        "questdb_target_identity_sha256": source.release[
            "questdb_target_identity_sha256"
        ],
        "questdb_image_digest": source.release["questdb_image_digest"],
        "release_raw_sha256": source.release_raw_sha256,
        "release_canonical_sha256": source.release_canonical_sha256,
        "consume_marker_raw_sha256": source.consume_raw_sha256,
        "receipt_raw_sha256": source.receipt_raw_sha256,
        "pre_evidence_bundle_index_sha256": (
            source.pre_evidence_bundle_index_sha256
        ),
        "pre_evidence_raw_sha256": source.pre_evidence_raw_sha256,
        "post_evidence_raw_sha256": post.raw_sha256,
        "post_evidence_bundle_index_sha256": post.bundle_index_sha256,
        "consumed_at": source.consume["consumed_at"],
        "verified_at": source.receipt["verified_at"],
        "deployment_started_at": execution["deployment_started_at"],
        "restart_started_at": execution["restart_started_at"],
        "restart_completed_at": execution["restart_completed_at"],
        "deployment_ended_at": execution["deployment_ended_at"],
        "deployment_outcome_state": "SUCCEEDED_POSTCHECKS_VERIFIED",
        "deployment_executed": True,
        "restart_executed": True,
        "restart_count": 1,
        "writer_continuity_verified": True,
        "post_restart_health_verified": True,
        "backlog_drain_verified": True,
        "readonly_principal_verified": True,
        "secret_file_verified": True,
        "isolated_network_verified": True,
        "production_queries_executed": execution[
            "production_queries_executed"
        ],
        "readonly_queries_executed": execution[
            "readonly_queries_executed"
        ],
        "write_probes_attempted": execution["write_probes_attempted"],
        "database_mutations": execution["database_mutations"],
        "web_bridge_rpc_calls": execution["web_bridge_rpc_calls"],
        "orders_sent": execution["orders_sent"],
        "positions_modified": execution["positions_modified"],
        "dispatch_changed": execution["dispatch_changed"],
        "receipt_is_authority": False,
        "outcome_is_authority": False,
        "raw_signed_release_required_for_audit": True,
        "replay_allowed": False,
        "readiness_authorized": False,
        "readonly_principal_deployment_authorized": False,
        "readonly_secret_file_installation_authorized": False,
        "questdb_restart_authorized": False,
        "questdb_recreate_authorized": False,
        "questdb_image_change_authorized": False,
        "writer_identity_mutation_authorized": False,
        "writer_secret_mutation_authorized": False,
        "network_mutation_authorized": False,
        "unscoped_deployment_mutation_authorized": False,
        "production_query_authorized": False,
        "readonly_query_authorized": False,
        "collection_authorized": False,
        "write_probe_authorized": False,
        "database_mutation_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "strategy_activation_authorized": False,
        "automatic_promotion_authorized": False,
        "web_bridge_deployment_authorized": False,
        "deployment_mutation_authorized": False,
        "runtime_activation_authorized": False,
        "dynamic_selection_allowed": False,
        "replacement_authorized": False,
        "production_authorized": False,
    }
    payload = dict(draft)
    payload.update(fixed)
    return payload


def validate_outcome_semantics(
    payload: dict[str, Any],
    *,
    now: datetime,
) -> None:
    if payload["schema_version"] != OUTCOME_SCHEMA_VERSION:
        raise DeploymentOutcomeError("outcome schema version is invalid")
    if payload["purpose"] != OUTCOME_PURPOSE:
        raise DeploymentOutcomeError("outcome purpose is invalid")
    if not COMMIT_PATTERN.fullmatch(
        str(payload["outcome_contract_source_commit_assertion"])
    ):
        raise DeploymentOutcomeError(
            "outcome contract source commit assertion is invalid"
        )
    human_signature = str(payload["human_signature"]).strip()
    if not human_signature or human_signature.startswith("PENDING_"):
        raise DeploymentOutcomeError(
            "human_signature must contain final human text"
        )
    issued_at = _parse_aware(payload["issued_at"], "issued_at")
    ended_at = _parse_aware(payload["deployment_ended_at"], "deployment_ended_at")
    normalized_now = _require_aware_datetime(now, "now").astimezone(timezone.utc)
    if not ended_at <= issued_at <= normalized_now:
        raise DeploymentOutcomeError(
            "outcome must be issued after deployment and not in the future"
        )
    if issued_at - ended_at > MAX_OUTCOME_SIGNING_LAG:
        raise DeploymentOutcomeError(
            "outcome signing lag cannot exceed 24 hours"
        )
    if payload["deployment_outcome_state"] != "SUCCEEDED_POSTCHECKS_VERIFIED":
        raise DeploymentOutcomeError("outcome is not a successful post-check")
    if type(payload["restart_count"]) is not int or payload["restart_count"] != 1:
        raise DeploymentOutcomeError("restart_count must be exact integer one")
    if any(payload[field] is not True for field in OUTCOME_TRUE_FIELDS):
        raise DeploymentOutcomeError(
            "outcome is missing a required verified fact"
        )
    if any(payload[field] is not False for field in OUTCOME_FALSE_FIELDS):
        raise DeploymentOutcomeError(
            "outcome attempts to grant forbidden authority"
        )
    if any(
        type(payload[field]) is not int or payload[field] != 0
        for field in OUTCOME_ZERO_FIELDS
    ):
        raise DeploymentOutcomeError(
            "outcome side-effect counters must be exact integer zero"
        )


def verify_signed_outcome(
    outcome_path: Path,
    outcome_keyring_path: Path,
    t1_keyring_path: Path,
    source_paths: OutcomeSourcePaths,
    post_paths: PostEvidencePaths,
    *,
    expected_outcome_keyring_sha256: str,
    expected_release_keyring_sha256: str,
    expected_t1_keyring_sha256: str,
    expected_outcome_source_commit_sha: str,
    expected_release_source_commit_sha: str,
    expected_questdb_image_digest: str,
    now: datetime | None = None,
) -> VerifiedDeploymentOutcome:
    try:
        current_time = (
            datetime.now(timezone.utc)
            if now is None
            else _require_aware_datetime(now, "now")
        )
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    source = _validate_receipt_chain(
        source_paths,
        expected_release_keyring_sha256=expected_release_keyring_sha256,
        expected_release_source_commit_sha=expected_release_source_commit_sha,
        expected_questdb_image_digest=expected_questdb_image_digest,
    )
    post = verify_post_bundle(source, source_paths.pre_evidence, post_paths)
    _raw, payload = read_signed_outcome_from_custody(outcome_path, source)
    try:
        _validate_schema(
            payload,
            OUTCOME_SCHEMA_PATH,
            "signed deployment outcome",
        )
    except DeploymentReleaseError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    validate_outcome_semantics(payload, now=current_time)
    expected = expected_outcome_payload(
        {
            key: payload[key]
            for key in (
                "issued_at",
                "signer_key_id",
                "signer_key_purpose",
                "signer_type",
                "reviewer_role",
                "human_signature",
            )
        },
        source,
        post,
        outcome_keyring_sha256=expected_outcome_keyring_sha256,
        t1_keyring_sha256=expected_t1_keyring_sha256,
        outcome_source_commit_assertion=expected_outcome_source_commit_sha,
    )
    for key, expected_value in expected.items():
        if payload.get(key) != expected_value:
            raise DeploymentOutcomeError(
                f"outcome {key} does not match exact verified evidence"
            )

    outcome_keys, _outcome_hash = _load_public_keys(
        outcome_keyring_path,
        expected_sha256=expected_outcome_keyring_sha256,
        expected_version=OUTCOME_KEYRING_VERSION,
        purpose=OUTCOME_KEY_PURPOSE,
        label="readonly deployment outcome keyring",
    )
    t1_keys, _t1_hash = _load_public_keys(
        t1_keyring_path,
        expected_sha256=expected_t1_keyring_sha256,
        expected_version=T1_KEYRING_VERSION,
        purpose=T1_KEY_PURPOSE,
        label="T1 trusted keyring",
    )
    try:
        outcome_public = outcome_keys[str(payload["signer_key_id"])]
    except KeyError as exc:
        raise DeploymentOutcomeError(
            "outcome signer is absent from pinned outcome keyring"
        ) from exc
    forbidden_public_keys = {
        source.release_signer_public_bytes,
        *t1_keys.values(),
    }
    if outcome_public in forbidden_public_keys:
        raise DeploymentOutcomeError(
            "outcome signer must be independent from release and T1 signers"
        )
    try:
        signature = base64.b64decode(payload["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(outcome_public).verify(
            signature,
            canonical_json(unsigned_outcome_payload(payload)),
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise DeploymentOutcomeError(
            "deployment outcome signature is invalid"
        ) from exc
    return VerifiedDeploymentOutcome(
        payload=payload,
        raw_sha256=hashlib.sha256(_raw).hexdigest(),
        canonical_sha256=hashlib.sha256(
            canonical_json(payload)
        ).hexdigest(),
        outcome_signer_public_key_sha256=hashlib.sha256(
            outcome_public
        ).hexdigest(),
        source=source,
        post=post,
    )


def add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--release-keyring", type=Path, required=True)
    parser.add_argument("--consume-marker", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    release_module.add_evidence_arguments(parser)


def add_post_arguments(parser: argparse.ArgumentParser) -> None:
    for name in POST_SCHEMA_PATHS:
        parser.add_argument(
            f"--{name.replace('_', '-')}",
            dest=name,
            type=Path,
            required=True,
        )


def source_paths_from_args(args: argparse.Namespace) -> OutcomeSourcePaths:
    return OutcomeSourcePaths(
        release=args.release,
        release_keyring=args.release_keyring,
        consume_marker=args.consume_marker,
        receipt=args.receipt,
        pre_evidence=release_module.evidence_paths_from_args(args),
    )


def post_paths_from_args(args: argparse.Namespace) -> PostEvidencePaths:
    return PostEvidencePaths(
        **{name: getattr(args, name) for name in POST_SCHEMA_PATHS}
    )


def read_production_keyring_pins() -> tuple[str, str, str]:
    try:
        info = OUTCOME_PIN_ROOT.lstat()
    except OSError as exc:
        raise DeploymentOutcomeError(
            "fixed readonly deployment outcome pin root is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise DeploymentOutcomeError(
            "outcome pin root must be root:root, non-symlink and not writable"
        )
    try:
        values = tuple(
            read_root_owned_deployment_pin(path, label)
            for path, label in (
                (OUTCOME_KEYRING_PIN_PATH, "outcome keyring pin"),
                (RELEASE_KEYRING_PIN_PATH, "release keyring pin"),
                (T1_KEYRING_PIN_PATH, "T1 keyring pin"),
            )
        )
    except OneShotError as exc:
        raise DeploymentOutcomeError(str(exc)) from exc
    if any(SHA256_PATTERN.fullmatch(value) is None for value in values):
        raise DeploymentOutcomeError(
            "outcome keyring pins must be exact lowercase SHA256"
        )
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--outcome-keyring", type=Path, required=True)
    parser.add_argument("--t1-keyring", type=Path, required=True)
    parser.add_argument("--expected-outcome-source-commit-sha", required=True)
    parser.add_argument("--expected-release-source-commit-sha", required=True)
    parser.add_argument("--expected-questdb-image-digest", required=True)
    add_source_arguments(parser)
    add_post_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        (
            outcome_keyring_pin,
            release_keyring_pin,
            t1_keyring_pin,
        ) = read_production_keyring_pins()
        verified = verify_signed_outcome(
            args.outcome,
            args.outcome_keyring,
            args.t1_keyring,
            source_paths_from_args(args),
            post_paths_from_args(args),
            expected_outcome_keyring_sha256=outcome_keyring_pin,
            expected_release_keyring_sha256=release_keyring_pin,
            expected_t1_keyring_sha256=t1_keyring_pin,
            expected_outcome_source_commit_sha=(
                args.expected_outcome_source_commit_sha
            ),
            expected_release_source_commit_sha=(
                args.expected_release_source_commit_sha
            ),
            expected_questdb_image_digest=(
                args.expected_questdb_image_digest
            ),
        )
    except (DeploymentOutcomeError, OSError, ValueError) as exc:
        print(f"readonly deployment outcome verification failed: {exc}", file=sys.stderr)
        return 2
    print("readonly deployment post-outcome verified")
    print(f"outcome_id={verified.payload['outcome_id']}")
    print(f"canonical_sha256={verified.canonical_sha256}")
    print("readiness_authorized=false")
    print("collection_authorized=false")
    print("trading_authorized=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
