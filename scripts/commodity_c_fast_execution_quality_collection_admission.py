#!/usr/bin/env python3
"""Offline verifier for one C_FAST execution-quality collection admission."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import re
import sys
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.commodity_c_fast_execution_policy import (  # noqa: E402
    CFastExecutionPolicyFreezeError,
    SIGNER_KEY_PURPOSE as POLICY_KEY_PURPOSE,
    verify_execution_policy_freeze_v2_raw_chain,
)
from commodity_c_fast_p0_acceptance_v2 import (  # noqa: E402
    P0AcceptanceV2Error,
    P0BundleV2Paths,
    VerifiedP0BundleV2,
    _load_acceptance_keyring,
    _load_keyring,
    add_bundle_arguments,
    acceptance_sha256,
    canonical_json,
    expected_keyring_hashes_from_args,
    paths_from_args,
    validate_acceptance_bindings,
    verify_query_v3_bundle,
    verify_signed_acceptance,
)
from commodity_c_fast_t1_one_shot import (  # noqa: E402
    MAX_JSON_BYTES,
    OneShotError,
    custody_entry_exists,
    custody_path_sha256,
    open_custody_guard,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_at,
    read_regular_file_strict,
    read_root_owned_deployment_pin,
    validate_custody_identity,
    validate_json_schema,
    write_json_create_only_at,
)


VERIFIER_PATH = Path(__file__).resolve()
RELEASE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-execution-quality-collection-admission-v1.schema.json"
)
KEYRING_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-execution-quality-collection-admission-trusted-keys-v1.schema.json"
)
CONSUME_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-execution-quality-collection-admission-consume-v1.schema.json"
)
TERMINAL_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-execution-quality-collection-admission-terminal-v1.schema.json"
)

SCHEMA_VERSION = (
    "commodity_c_fast_execution_quality_collection_admission_v1"
)
PURPOSE = "c_fast_execution_quality_collection_admission_offline_review"
KEYRING_VERSION = (
    "commodity_c_fast_execution_quality_collection_admission_trusted_keys_v1"
)
KEY_PURPOSE = "c_fast_execution_quality_collection_admission_signer"
CONSUME_VERSION = (
    "commodity_c_fast_execution_quality_collection_admission_consume_v1"
)
TERMINAL_VERSION = (
    "commodity_c_fast_execution_quality_collection_admission_terminal_v1"
)
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
SUCCESS_STATE = "ADMISSION_VERIFIED_FOR_SEPARATE_RUNTIME_RELEASE_ONLY"
FAILURE_STATE = "FAILED_FINAL_REVALIDATION_NO_COLLECTION"
MAX_RELEASE_TTL = timedelta(minutes=10)
MINIMUM_FINAL_REVALIDATION_MARGIN_SECONDS = 30
MAX_POLICY_BYTES = 64 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")

FALSE_AUTHORITY_FIELDS = (
    "admission_is_runtime_authority",
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "network_authorized",
    "query_authorized",
    "web_bridge_rpc_authorized",
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
    "replay_allowed",
)


class CollectionAdmissionError(RuntimeError):
    """Expected fail-closed collection-admission error."""


@dataclass(frozen=True)
class AdmissionSources:
    policy_receipt: Any
    policy_v1_payload: dict[str, Any]
    policy_v2_payload: dict[str, Any]
    policy_v1_raw_sha256: str
    policy_v1_canonical_sha256: str
    policy_v2_raw_sha256: str
    policy_v2_canonical_sha256: str
    policy_keyring_sha256: str
    policy_public_key_materials: frozenset[bytes]
    acceptance: dict[str, Any]
    acceptance_raw_sha256: str
    acceptance_canonical_sha256: str
    acceptance_keyring_sha256: str
    acceptance_public_key_materials: frozenset[bytes]
    bundle: VerifiedP0BundleV2

    @property
    def upstream_public_key_materials(self) -> frozenset[bytes]:
        return frozenset().union(
            self.policy_public_key_materials,
            self.acceptance_public_key_materials,
            self.bundle.upstream_public_key_materials,
        )


@dataclass(frozen=True)
class VerifiedAdmission:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    keyring_sha256: str
    sources: AdmissionSources


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compare(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise CollectionAdmissionError(f"{label} binding mismatch")


def _validate_sha256(value: Any, label: str) -> str:
    text = str(value)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise CollectionAdmissionError(
            f"{label} must be one lowercase SHA256"
        )
    return text


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CollectionAdmissionError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def admission_attempt_id(release_id: str) -> str:
    if ID_PATTERN.fullmatch(release_id) is None:
        raise CollectionAdmissionError("release_id is invalid")
    return "collection-admission-attempt-" + hashlib.sha256(
        release_id.encode("utf-8")
    ).hexdigest()


def unsigned_admission_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def admission_sha256(payload: dict[str, Any]) -> str:
    return _hash(canonical_json(payload))


def _read_policy_keyring(
    path: Path,
    *,
    expected_sha256: str,
) -> tuple[dict[str, Any], frozenset[bytes], str, bytes]:
    expected = _validate_sha256(
        expected_sha256,
        "independently pinned policy keyring",
    )
    raw = read_regular_file_strict(
        path,
        "execution-quality policy trusted keyring",
        limit=MAX_POLICY_BYTES,
        private=True,
    )
    payload = parse_json_bytes(
        raw,
        "execution-quality policy trusted keyring",
    )
    digest = _hash(canonical_json(payload))
    _compare(digest, expected, "execution-quality policy keyring pin")
    if not payload:
        raise CollectionAdmissionError("policy keyring must contain keys")
    materials: set[bytes] = set()
    for key_id, entry in payload.items():
        if (
            not isinstance(key_id, str)
            or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id) is None
            or not isinstance(entry, dict)
            or set(entry) != {"public_key_base64", "purpose"}
            or entry["purpose"] != POLICY_KEY_PURPOSE
        ):
            raise CollectionAdmissionError("policy keyring entry is invalid")
        try:
            material = base64.b64decode(
                str(entry["public_key_base64"]),
                validate=True,
            )
            if len(material) != 32:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(material)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise CollectionAdmissionError(
                "policy keyring public key is invalid"
            ) from exc
        if material in materials:
            raise CollectionAdmissionError(
                "policy keyring reuses public-key material"
            )
        materials.add(material)
    return payload, frozenset(materials), digest, raw


def _load_admission_keyring(
    path: Path,
    *,
    expected_sha256: str,
    key_id: str,
) -> tuple[Ed25519PublicKey, frozenset[bytes], str]:
    expected = _validate_sha256(
        expected_sha256,
        "independently pinned admission keyring",
    )
    raw = read_regular_file_strict(
        path,
        "collection-admission trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    payload = parse_json_bytes(
        raw,
        "collection-admission trusted keyring",
    )
    validate_json_schema(
        payload,
        KEYRING_SCHEMA_PATH,
        "collection-admission trusted keyring",
    )
    digest = _hash(canonical_json(payload))
    _compare(digest, expected, "collection-admission keyring pin")
    public_key, materials = _load_keyring(
        payload,
        expected_version=KEYRING_VERSION,
        required_purpose=KEY_PURPOSE,
        key_id=key_id,
        label="collection-admission keyring",
    )
    assert public_key is not None
    return public_key, materials, digest


def verify_admission_sources(
    *,
    policy_v1_path: Path,
    policy_v2_path: Path,
    policy_keyring_path: Path,
    expected_policy_keyring_sha256: str,
    acceptance_path: Path,
    acceptance_keyring_path: Path,
    expected_acceptance_keyring_sha256: str,
    bundle_paths: P0BundleV2Paths,
    expected_upstream_keyring_sha256: dict[str, str],
) -> AdmissionSources:
    (
        policy_keyring,
        policy_materials,
        policy_pin,
        policy_keyring_raw,
    ) = _read_policy_keyring(
        policy_keyring_path,
        expected_sha256=expected_policy_keyring_sha256,
    )
    policy_v1_raw = read_regular_file_strict(
        policy_v1_path,
        "signed execution-quality policy freeze v1",
        limit=MAX_POLICY_BYTES,
    )
    policy_v2_raw = read_regular_file_strict(
        policy_v2_path,
        "signed execution-quality policy freeze v2",
        limit=MAX_POLICY_BYTES,
    )
    policy_receipt = verify_execution_policy_freeze_v2_raw_chain(
        policy_v2_raw,
        superseded_freeze_raw=policy_v1_raw,
        trusted_public_keys=policy_keyring,
        expected_trusted_public_keys_sha256=policy_pin,
    )
    _compare(
        _hash(policy_v1_raw),
        policy_receipt.supersedes_freeze_raw_sha256,
        "verified policy v1 raw bytes",
    )
    _compare(
        _hash(policy_v2_raw),
        policy_receipt.freeze_raw_sha256,
        "verified policy v2 raw bytes",
    )
    policy_v1 = parse_json_bytes(policy_v1_raw, "policy freeze v1")
    policy_v2 = parse_json_bytes(policy_v2_raw, "policy freeze v2")
    if policy_receipt.policy_rule_completeness != (
        "COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"
    ):
        raise CollectionAdmissionError("policy v2 rules are incomplete")

    acceptance, acceptance_digest = verify_signed_acceptance(
        acceptance_path,
        acceptance_keyring_path,
        bundle_paths,
        expected_acceptance_keyring_sha256=(
            expected_acceptance_keyring_sha256
        ),
        expected_keyring_sha256=expected_upstream_keyring_sha256,
    )
    bundle = verify_query_v3_bundle(
        bundle_paths,
        expected_keyring_sha256=expected_upstream_keyring_sha256,
    )
    validate_acceptance_bindings(acceptance, bundle)
    acceptance_public, acceptance_materials, acceptance_pin = (
        _load_acceptance_keyring(
            acceptance_keyring_path,
            expected_sha256=expected_acceptance_keyring_sha256,
            key_id=str(acceptance["signer_key_id"]),
        )
    )
    del acceptance_public
    acceptance_raw = read_regular_file_strict(
        acceptance_path,
        "signed P0 acceptance v2",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    acceptance_reparsed = parse_json_bytes(
        acceptance_raw,
        "signed P0 acceptance v2",
    )
    if acceptance_reparsed != acceptance:
        raise CollectionAdmissionError(
            "P0 acceptance changed during source verification"
        )
    if acceptance_digest != acceptance_sha256(acceptance):
        raise CollectionAdmissionError("P0 acceptance digest changed")

    domains = (
        policy_materials,
        acceptance_materials,
        bundle.upstream_public_key_materials,
    )
    for index, left in enumerate(domains):
        for right in domains[index + 1 :]:
            if left & right:
                raise CollectionAdmissionError(
                    "policy/P0 key domains reuse public-key material"
                )
    if (
        read_regular_file_strict(
            policy_v1_path,
            "signed execution-quality policy freeze v1",
            limit=MAX_POLICY_BYTES,
        )
        != policy_v1_raw
        or read_regular_file_strict(
            policy_v2_path,
            "signed execution-quality policy freeze v2",
            limit=MAX_POLICY_BYTES,
        )
        != policy_v2_raw
        or read_regular_file_strict(
            policy_keyring_path,
            "execution-quality policy trusted keyring",
            limit=MAX_POLICY_BYTES,
            private=True,
        )
        != policy_keyring_raw
    ):
        raise CollectionAdmissionError(
            "policy raw chain changed during source verification"
        )
    return AdmissionSources(
        policy_receipt=policy_receipt,
        policy_v1_payload=policy_v1,
        policy_v2_payload=policy_v2,
        policy_v1_raw_sha256=_hash(policy_v1_raw),
        policy_v1_canonical_sha256=_hash(canonical_json(policy_v1)),
        policy_v2_raw_sha256=_hash(policy_v2_raw),
        policy_v2_canonical_sha256=_hash(canonical_json(policy_v2)),
        policy_keyring_sha256=policy_pin,
        policy_public_key_materials=policy_materials,
        acceptance=acceptance,
        acceptance_raw_sha256=_hash(acceptance_raw),
        acceptance_canonical_sha256=acceptance_digest,
        acceptance_keyring_sha256=acceptance_pin,
        acceptance_public_key_materials=acceptance_materials,
        bundle=bundle,
    )


def expected_source_binding(sources: AdmissionSources) -> dict[str, Any]:
    policy = sources.policy_receipt
    acceptance = sources.acceptance
    return {
        "policy": {
            "v1_freeze_id": policy.supersedes_freeze_id,
            "v1_freeze_sha256": policy.supersedes_freeze_sha256,
            "v1_raw_sha256": sources.policy_v1_raw_sha256,
            "v1_canonical_sha256": (
                sources.policy_v1_canonical_sha256
            ),
            "v2_freeze_id": policy.freeze_id,
            "v2_freeze_sha256": policy.freeze_sha256,
            "v2_raw_sha256": sources.policy_v2_raw_sha256,
            "v2_canonical_sha256": (
                sources.policy_v2_canonical_sha256
            ),
            "trusted_keyring_sha256": sources.policy_keyring_sha256,
            "policy_id": policy.policy_id,
            "policy_hash": policy.policy_hash,
            "policy_rule_completeness": (
                "COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"
            ),
        },
        "p0": {
            "acceptance_id": acceptance["acceptance_id"],
            "acceptance_raw_sha256": (
                sources.acceptance_raw_sha256
            ),
            "acceptance_canonical_sha256": (
                sources.acceptance_canonical_sha256
            ),
            "acceptance_keyring_sha256": (
                sources.acceptance_keyring_sha256
            ),
            "release_id": acceptance["release_id"],
            "attempt_id": acceptance["attempt_id"],
            "terminal_state": acceptance["terminal_state"],
            "bundle_raw_sha256": sources.bundle.raw_sha256,
            "bundle_canonical_sha256": sources.bundle.canonical_sha256,
            "artifact_sha256": sources.bundle.artifact_sha256,
            "bundle_index_sha256": sources.bundle.bundle_index_sha256,
        },
    }


def _validate_runtime_bindings(payload: dict[str, Any]) -> None:
    paths = {
        "verifier_sha256": VERIFIER_PATH,
        "release_schema_sha256": RELEASE_SCHEMA_PATH,
        "trusted_keyring_schema_sha256": KEYRING_SCHEMA_PATH,
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "terminal_schema_sha256": TERMINAL_SCHEMA_PATH,
    }
    for field, path in paths.items():
        _compare(
            str(payload[field]),
            _hash(
                read_regular_file_strict(
                    path,
                    f"collection-admission runtime {field}",
                    limit=MAX_JSON_BYTES,
                )
            ),
            f"collection-admission runtime {field}",
        )


def _validate_custody_binding(
    payload: dict[str, Any],
    *,
    custody_dir: Path,
    pinned_custody_path: Path,
    pinned_custody_identity_sha256: str,
    require_root_owned_parent: bool,
) -> None:
    expected_identity = _validate_sha256(
        pinned_custody_identity_sha256,
        "independently pinned custody identity",
    )
    if pinned_custody_path.is_symlink():
        raise CollectionAdmissionError(
            "immutable custody path pin must not name a symlink"
        )
    try:
        requested = custody_dir.resolve(strict=True)
        pinned = pinned_custody_path.resolve(strict=True)
    except OSError as exc:
        raise CollectionAdmissionError(
            "cannot resolve collection-admission custody"
        ) from exc
    if requested != pinned:
        raise CollectionAdmissionError(
            "custody directory does not match the immutable path pin"
        )
    _compare(
        str(payload["custody_path_sha256"]),
        custody_path_sha256(pinned),
        "collection-admission custody path",
    )
    _compare(
        str(payload["custody_identity_sha256"]),
        expected_identity,
        "collection-admission custody identity pin",
    )
    guard = open_custody_guard(
        custody_dir,
        require_root_owned_parent=require_root_owned_parent,
    )
    try:
        validate_custody_identity(guard, expected_identity)
    finally:
        guard.close()


def validate_admission_bindings(
    payload: dict[str, Any],
    sources: AdmissionSources,
    *,
    custody_dir: Path,
    pinned_custody_path: Path,
    pinned_custody_identity_sha256: str,
    require_root_owned_parent: bool,
    now: datetime,
) -> None:
    validate_json_schema(
        payload,
        RELEASE_SCHEMA_PATH,
        "collection-admission release",
    )
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["purpose"] != PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
        or payload["parent_issue_number"] != 114
        or payload["issue_number"] != 140
        or payload["attempt_id"]
        != admission_attempt_id(str(payload["release_id"]))
    ):
        raise CollectionAdmissionError(
            "collection-admission identity is invalid"
        )
    reviewer_role = str(payload["reviewer_role"]).strip()
    human_signature = str(payload["human_signature"]).strip()
    if (
        not reviewer_role
        or reviewer_role.startswith("PENDING_")
        or not human_signature
        or human_signature.startswith("PENDING_")
    ):
        raise CollectionAdmissionError(
            "collection-admission human review is missing"
        )
    issued_at = parse_datetime(payload["issued_at"], "admission.issued_at")
    not_before = parse_datetime(
        payload["not_before"],
        "admission.not_before",
    )
    expires_at = parse_datetime(
        payload["expires_at"],
        "admission.expires_at",
    )
    current = _utc(now, "admission verification time")
    if not issued_at <= not_before < expires_at:
        raise CollectionAdmissionError(
            "admission release time ordering is invalid"
        )
    if expires_at - issued_at > MAX_RELEASE_TTL:
        raise CollectionAdmissionError(
            "admission release TTL exceeds ten minutes"
        )
    if not not_before <= current < expires_at:
        raise CollectionAdmissionError(
            "admission release is not active"
        )
    margin = timedelta(
        seconds=int(payload["minimum_final_revalidation_margin_seconds"])
    )
    if current + margin >= expires_at:
        raise CollectionAdmissionError(
            "admission release lacks final revalidation margin"
        )
    accepted_at = parse_datetime(
        sources.acceptance["accepted_at"],
        "P0 acceptance accepted_at",
    )
    if accepted_at > issued_at:
        raise CollectionAdmissionError(
            "admission was issued before signed P0 acceptance"
        )
    if payload["source_binding"] != expected_source_binding(sources):
        raise CollectionAdmissionError(
            "collection-admission exact source binding mismatch"
        )
    _validate_custody_binding(
        payload,
        custody_dir=custody_dir,
        pinned_custody_path=pinned_custody_path,
        pinned_custody_identity_sha256=(
            pinned_custody_identity_sha256
        ),
        require_root_owned_parent=require_root_owned_parent,
    )
    if (
        payload["admission_fact_frozen"] is not True
        or payload["p0_accepted"] is not True
        or payload["policy_rules_complete"] is not True
        or payload["raw_signed_sources_required"] is not True
        or payload["startup_recovery_exact_revalidation_required"]
        is not True
        or payload["admission_scope"]
        != "OFFLINE_FACT_FOR_SEPARATE_RUNTIME_RELEASE_ONLY"
        or any(payload[field] is not False for field in FALSE_AUTHORITY_FIELDS)
    ):
        raise CollectionAdmissionError(
            "collection-admission grants forbidden runtime authority"
        )
    _validate_runtime_bindings(payload)


def _verify_signature(
    payload: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> None:
    try:
        signature = base64.b64decode(
            str(payload["signature"]),
            validate=True,
        )
        if len(signature) != 64:
            raise ValueError
        public_key.verify(
            signature,
            canonical_json(unsigned_admission_payload(payload)),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise CollectionAdmissionError(
            "collection-admission signature is invalid"
        ) from exc


def verify_signed_admission(
    release_path: Path,
    admission_keyring_path: Path,
    *,
    expected_admission_keyring_sha256: str,
    policy_v1_path: Path,
    policy_v2_path: Path,
    policy_keyring_path: Path,
    expected_policy_keyring_sha256: str,
    acceptance_path: Path,
    acceptance_keyring_path: Path,
    expected_acceptance_keyring_sha256: str,
    bundle_paths: P0BundleV2Paths,
    expected_upstream_keyring_sha256: dict[str, str],
    custody_dir: Path,
    pinned_custody_path: Path,
    pinned_custody_identity_sha256: str,
    require_root_owned_parent: bool,
    now: datetime,
) -> VerifiedAdmission:
    release_raw = read_regular_file_strict(
        release_path,
        "signed collection-admission release",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    release = parse_json_bytes(
        release_raw,
        "signed collection-admission release",
    )
    sources = verify_admission_sources(
        policy_v1_path=policy_v1_path,
        policy_v2_path=policy_v2_path,
        policy_keyring_path=policy_keyring_path,
        expected_policy_keyring_sha256=(
            expected_policy_keyring_sha256
        ),
        acceptance_path=acceptance_path,
        acceptance_keyring_path=acceptance_keyring_path,
        expected_acceptance_keyring_sha256=(
            expected_acceptance_keyring_sha256
        ),
        bundle_paths=bundle_paths,
        expected_upstream_keyring_sha256=(
            expected_upstream_keyring_sha256
        ),
    )
    validate_admission_bindings(
        release,
        sources,
        custody_dir=custody_dir,
        pinned_custody_path=pinned_custody_path,
        pinned_custody_identity_sha256=(
            pinned_custody_identity_sha256
        ),
        require_root_owned_parent=require_root_owned_parent,
        now=now,
    )
    public_key, admission_materials, keyring_pin = (
        _load_admission_keyring(
            admission_keyring_path,
            expected_sha256=expected_admission_keyring_sha256,
            key_id=str(release["signer_key_id"]),
        )
    )
    if release["admission_keyring_sha256"] != keyring_pin:
        raise CollectionAdmissionError(
            "collection-admission keyring binding mismatch"
        )
    if admission_materials & sources.upstream_public_key_materials:
        raise CollectionAdmissionError(
            "collection-admission keyring reuses an upstream key"
        )
    _verify_signature(release, public_key)
    second_raw = read_regular_file_strict(
        release_path,
        "signed collection-admission release",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    if second_raw != release_raw:
        raise CollectionAdmissionError(
            "collection-admission release changed during verification"
        )
    return VerifiedAdmission(
        payload=release,
        raw_sha256=_hash(release_raw),
        canonical_sha256=admission_sha256(release),
        keyring_sha256=keyring_pin,
        sources=sources,
    )


def _same_verified(
    initial: VerifiedAdmission,
    final: VerifiedAdmission,
) -> bool:
    return (
        initial.payload == final.payload
        and initial.raw_sha256 == final.raw_sha256
        and initial.canonical_sha256 == final.canonical_sha256
        and initial.keyring_sha256 == final.keyring_sha256
        and expected_source_binding(initial.sources)
        == expected_source_binding(final.sources)
    )


def _consume_payload(
    verified: VerifiedAdmission,
    consumed_at: datetime,
) -> dict[str, Any]:
    return {
        "schema_version": CONSUME_VERSION,
        "purpose": "c_fast_collection_admission_consume_before_final_revalidation",
        "candidate_id": CANDIDATE_ID,
        "release_id": verified.payload["release_id"],
        "attempt_id": verified.payload["attempt_id"],
        "consumed_at": _utc(consumed_at, "consume time").isoformat(),
        "release_raw_sha256": verified.raw_sha256,
        "release_canonical_sha256": verified.canonical_sha256,
        "admission_keyring_sha256": verified.keyring_sha256,
        "source_binding_sha256": _hash(
            canonical_json(verified.payload["source_binding"])
        ),
        "custody_path_sha256": verified.payload["custody_path_sha256"],
        "custody_identity_sha256": (
            verified.payload["custody_identity_sha256"]
        ),
        "consume_is_authority": False,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "database_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "replay_allowed": False,
    }


def _terminal_payload(
    verified: VerifiedAdmission,
    *,
    consume_raw_sha256: str,
    consume_canonical_sha256: str,
    started_at: datetime,
    ended_at: datetime,
    final_revalidation_at: datetime | None,
    success: bool,
    error_code: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": TERMINAL_VERSION,
        "purpose": "c_fast_collection_admission_offline_terminal",
        "candidate_id": CANDIDATE_ID,
        "release_id": verified.payload["release_id"],
        "attempt_id": verified.payload["attempt_id"],
        "terminal_state": SUCCESS_STATE if success else FAILURE_STATE,
        "error_code": error_code,
        "started_at": _utc(started_at, "terminal started_at").isoformat(),
        "final_revalidation_at": (
            _utc(
                final_revalidation_at,
                "terminal final_revalidation_at",
            ).isoformat()
            if final_revalidation_at is not None
            else None
        ),
        "ended_at": _utc(ended_at, "terminal ended_at").isoformat(),
        "release_raw_sha256": verified.raw_sha256,
        "release_canonical_sha256": verified.canonical_sha256,
        "consume_raw_sha256": consume_raw_sha256,
        "consume_canonical_sha256": consume_canonical_sha256,
        "source_binding_sha256": _hash(
            canonical_json(verified.payload["source_binding"])
        ),
        "custody_path_sha256": verified.payload["custody_path_sha256"],
        "custody_identity_sha256": (
            verified.payload["custody_identity_sha256"]
        ),
        "p0_acceptance_raw_sha256": (
            verified.sources.acceptance_raw_sha256
        ),
        "policy_v1_raw_sha256": (
            verified.sources.policy_v1_raw_sha256
        ),
        "policy_v2_raw_sha256": (
            verified.sources.policy_v2_raw_sha256
        ),
        "admission_fact_frozen": success,
        "terminal_is_runtime_authority": False,
        "collection_authorized": False,
        "execution_quality_collection_authorized": False,
        "runtime_activation_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "network_authorized": False,
        "query_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "database_mutations_observed": 0,
        "web_bridge_rpc_calls": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }


def execute_offline_admission(
    initial: VerifiedAdmission,
    revalidator: Callable[[datetime], VerifiedAdmission],
    *,
    custody_dir: Path,
    pinned_custody_path: Path,
    pinned_custody_identity_sha256: str,
    require_root_owned_parent: bool,
    clock: Callable[[], datetime],
) -> tuple[int, dict[str, Any]]:
    custody = custody_dir.resolve(strict=True)
    if custody != pinned_custody_path.resolve(strict=True):
        raise CollectionAdmissionError(
            "custody directory does not match the immutable path pin"
        )
    guard = open_custody_guard(
        custody_dir,
        require_root_owned_parent=require_root_owned_parent,
    )
    consume_name = f"{initial.payload['attempt_id']}.admission-consumed.json"
    terminal_name = f"{initial.payload['attempt_id']}.admission-terminal.json"
    try:
        validate_custody_identity(
            guard,
            pinned_custody_identity_sha256,
        )
        if custody_entry_exists(guard, consume_name):
            raise CollectionAdmissionError(
                "collection-admission attempt is already consumed"
            )
        if custody_entry_exists(guard, terminal_name):
            raise CollectionAdmissionError(
                "collection-admission terminal exists without consume"
            )
        preconsume_time = _utc(
            clock(),
            "admission pre-consume revalidation time",
        )
        consumption_verified = revalidator(preconsume_time)
        if not _same_verified(initial, consumption_verified):
            raise CollectionAdmissionError(
                "exact admission chain changed before consume"
            )
        validate_admission_bindings(
            consumption_verified.payload,
            consumption_verified.sources,
            custody_dir=custody,
            pinned_custody_path=pinned_custody_path,
            pinned_custody_identity_sha256=(
                pinned_custody_identity_sha256
            ),
            require_root_owned_parent=require_root_owned_parent,
            now=preconsume_time,
        )
        started_at = _utc(clock(), "admission consume time")
        if started_at < preconsume_time:
            raise CollectionAdmissionError(
                "consume time precedes pre-consume revalidation"
            )
        validate_admission_bindings(
            consumption_verified.payload,
            consumption_verified.sources,
            custody_dir=custody,
            pinned_custody_path=pinned_custody_path,
            pinned_custody_identity_sha256=(
                pinned_custody_identity_sha256
            ),
            require_root_owned_parent=require_root_owned_parent,
            now=started_at,
        )
        consume = _consume_payload(consumption_verified, started_at)
        consume_raw_sha256 = write_json_create_only_at(
            guard,
            consume_name,
            consume,
            CONSUME_SCHEMA_PATH,
            "collection-admission consume marker",
        )
        consume_raw = read_regular_file_at(
            guard,
            consume_name,
            "collection-admission consume marker",
        )
        if (
            _hash(consume_raw) != consume_raw_sha256
            or parse_json_bytes(
                consume_raw,
                "collection-admission consume marker",
            )
            != consume
        ):
            raise CollectionAdmissionError(
                "collection-admission consume reopen failed"
            )
        consume_canonical_sha256 = _hash(canonical_json(consume))
        final_time = _utc(clock(), "admission final revalidation time")
        success = False
        error_code: str | None = "FINAL_REVALIDATION_FAILED"
        if final_time < started_at:
            error_code = "NON_MONOTONIC_CLOCK"
        else:
            try:
                final = revalidator(final_time)
                if not _same_verified(consumption_verified, final):
                    raise CollectionAdmissionError(
                        "exact admission chain changed after consume"
                    )
                validate_admission_bindings(
                    final.payload,
                    final.sources,
                    custody_dir=custody,
                    pinned_custody_path=pinned_custody_path,
                    pinned_custody_identity_sha256=(
                        pinned_custody_identity_sha256
                    ),
                    require_root_owned_parent=(
                        require_root_owned_parent
                    ),
                    now=final_time,
                )
                success = True
                error_code = None
            except (
                CFastExecutionPolicyFreezeError,
                CollectionAdmissionError,
                OneShotError,
                P0AcceptanceV2Error,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ):
                success = False
        observed_end = _utc(clock(), "admission terminal time")
        if observed_end < max(started_at, final_time):
            success = False
            error_code = "NON_MONOTONIC_CLOCK"
        ended_at = max(started_at, final_time, observed_end)
        guard.assert_path_identity()
        validate_custody_identity(
            guard,
            pinned_custody_identity_sha256,
        )
        terminal = _terminal_payload(
            consumption_verified,
            consume_raw_sha256=consume_raw_sha256,
            consume_canonical_sha256=consume_canonical_sha256,
            started_at=started_at,
            ended_at=ended_at,
            final_revalidation_at=final_time if success else None,
            success=success,
            error_code=error_code,
        )
        write_json_create_only_at(
            guard,
            terminal_name,
            terminal,
            TERMINAL_SCHEMA_PATH,
            "collection-admission terminal",
        )
        return (0 if success else 2), terminal
    except (FileExistsError, OneShotError) as exc:
        raise CollectionAdmissionError(str(exc)) from exc
    finally:
        guard.close()


def add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy-v1", type=Path, required=True)
    parser.add_argument("--policy-v2", type=Path, required=True)
    parser.add_argument("--policy-trusted-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-policy-keyring-sha256",
        required=True,
    )
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


def source_kwargs_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "policy_v1_path": args.policy_v1,
        "policy_v2_path": args.policy_v2,
        "policy_keyring_path": args.policy_trusted_keyring,
        "expected_policy_keyring_sha256": (
            args.expected_policy_keyring_sha256
        ),
        "acceptance_path": args.acceptance,
        "acceptance_keyring_path": args.acceptance_trusted_keyring,
        "expected_acceptance_keyring_sha256": (
            args.expected_acceptance_keyring_sha256
        ),
        "bundle_paths": paths_from_args(args),
        "expected_upstream_keyring_sha256": (
            expected_keyring_hashes_from_args(args)
        ),
    }


def custody_pins_from_args(
    args: argparse.Namespace,
) -> tuple[Path, str]:
    path = Path(
        read_root_owned_deployment_pin(
            args.custody_path_pin,
            "collection-admission custody path pin",
        )
    )
    identity = _validate_sha256(
        read_root_owned_deployment_pin(
            args.custody_identity_pin,
            "collection-admission custody identity pin",
        ),
        "collection-admission custody identity pin",
    )
    return path, identity


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument(
        "--admission-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-admission-keyring-sha256",
        required=True,
    )
    parser.add_argument("--custody-dir", type=Path, required=True)
    parser.add_argument("--custody-path-pin", type=Path, required=True)
    parser.add_argument(
        "--custody-identity-pin",
        type=Path,
        required=True,
    )
    add_source_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_kwargs = source_kwargs_from_args(args)

    def revalidate(now: datetime) -> VerifiedAdmission:
        pinned_path, pinned_identity = custody_pins_from_args(args)
        return verify_signed_admission(
            args.release,
            args.admission_trusted_keyring,
            expected_admission_keyring_sha256=(
                args.expected_admission_keyring_sha256
            ),
            custody_dir=args.custody_dir,
            pinned_custody_path=pinned_path,
            pinned_custody_identity_sha256=pinned_identity,
            require_root_owned_parent=True,
            now=now,
            **source_kwargs,
        )

    try:
        initial_path, initial_identity = custody_pins_from_args(args)
        initial = verify_signed_admission(
            args.release,
            args.admission_trusted_keyring,
            expected_admission_keyring_sha256=(
                args.expected_admission_keyring_sha256
            ),
            custody_dir=args.custody_dir,
            pinned_custody_path=initial_path,
            pinned_custody_identity_sha256=initial_identity,
            require_root_owned_parent=True,
            now=datetime.now(timezone.utc),
            **source_kwargs,
        )
        exit_code, terminal = execute_offline_admission(
            initial,
            revalidate,
            custody_dir=args.custody_dir,
            pinned_custody_path=initial_path,
            pinned_custody_identity_sha256=initial_identity,
            require_root_owned_parent=True,
            clock=lambda: datetime.now(timezone.utc),
        )
    except (
        CFastExecutionPolicyFreezeError,
        CollectionAdmissionError,
        OneShotError,
        P0AcceptanceV2Error,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"collection-admission verification failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"terminal_state={terminal['terminal_state']}")
    print(f"attempt_id={terminal['attempt_id']}")
    print("collection_authorized=false")
    print("runtime_activation_authorized=false")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
