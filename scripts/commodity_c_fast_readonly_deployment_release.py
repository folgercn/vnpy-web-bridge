#!/usr/bin/env python3
"""Consume one signed C_FAST QuestDB readonly deployment release offline."""

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
import stat
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from commodity_c_fast_t1_one_shot import (
    CustodyGuard,
    OneShotError,
    canonical_json,
    custody_entry_exists,
    custody_path_sha256,
    open_custody_guard,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_at,
    read_regular_file_strict,
    read_root_owned_deployment_pin,
    validate_json_schema,
    write_json_create_only_at,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
RELEASE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-readonly-deployment-release-v1.schema.json"
)
CONSUME_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-readonly-deployment-consume-v1.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-readonly-deployment-receipt-v1.schema.json"
)

CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
RELEASE_SCHEMA_VERSION = (
    "commodity_c_fast_readonly_deployment_release_v1"
)
CONSUME_SCHEMA_VERSION = (
    "commodity_c_fast_readonly_deployment_consume_v1"
)
RECEIPT_SCHEMA_VERSION = (
    "commodity_c_fast_readonly_deployment_receipt_v1"
)
RELEASE_PURPOSE = "c_fast_questdb_readonly_principal_deployment"
TRUSTED_KEYRING_VERSION = (
    "commodity_c_fast_readonly_deployment_trusted_keys_v1"
)
TRUSTED_KEY_PURPOSE = "readonly_deployment_release_signer"
CUSTODY_IDENTITY_VERSION = (
    "commodity_c_fast_readonly_deployment_custody_identity_v1"
)
ISOLATED_NETWORK_ATTESTATION_VERSION = (
    "commodity_c_fast_readonly_isolated_network_attestation_v1"
)
CUSTODY_IDENTITY_FILENAME = "readonly-deployment-custody-identity.json"
MAX_RELEASE_TTL = timedelta(hours=2)
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

RELEASE_REQUIRED_TRUE_FIELDS = (
    "secret_file_regular_file_required",
    "principal_must_differ_from_admin",
    "writer_continuity_required",
    "post_restart_health_required",
    "backlog_drain_required",
    "rollback_required",
    "isolated_network_required",
    "isolated_network_internal_required",
    "readonly_principal_deployment_authorized",
    "readonly_secret_file_installation_authorized",
    "questdb_restart_authorized",
)
RELEASE_REQUIRED_FALSE_FIELDS = (
    "secret_file_symlink_allowed",
    "secret_content_read_authorized",
    "global_pgwire_readonly_allowed",
    "instance_readonly_allowed",
    "isolated_network_unexpected_members_allowed",
    "isolated_network_docker_socket_connectivity_allowed",
    "isolated_network_rpc_connectivity_allowed",
    "isolated_network_trading_connectivity_allowed",
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
    "replay_allowed",
    "receipt_is_authority",
)
RECEIPT_REQUIRED_FALSE_FIELDS = (
    *RELEASE_REQUIRED_FALSE_FIELDS,
    "authority_granted",
    "deployment_executed",
    "readonly_principal_deployment_authorized",
    "readonly_secret_file_installation_authorized",
    "questdb_restart_authorized",
    "deployment_mutation_authorized",
    "runtime_activation_authorized",
    "dynamic_selection_allowed",
    "replacement_authorized",
    "production_authorized",
    "dispatch_changed",
)
RECEIPT_REQUIRED_ZERO_FIELDS = (
    "database_mutations",
    "orders_sent",
    "positions_modified",
)

DEPLOYMENT_PIN_ROOT = Path(
    "/run/c-fast-readonly-deployment-pins"
)
DEPLOYMENT_KEYRING_PIN_PATH = (
    DEPLOYMENT_PIN_ROOT / "trusted-keyring.sha256"
)
DEPLOYMENT_CUSTODY_PIN_PATH = DEPLOYMENT_PIN_ROOT / "custody.path"

EVIDENCE_FILE_FIELDS = (
    (
        "questdb_image_attestation",
        "questdb_image_attestation_raw_sha256",
    ),
    (
        "readonly_principal_identity_attestation",
        "readonly_principal_identity_attestation_raw_sha256",
    ),
    (
        "secret_file_identity_attestation",
        "secret_file_identity_attestation_raw_sha256",
    ),
    (
        "writer_continuity_pre_evidence",
        "writer_continuity_pre_evidence_raw_sha256",
    ),
    (
        "writer_continuity_post_evidence",
        "writer_continuity_post_evidence_raw_sha256",
    ),
    ("health_evidence", "health_evidence_raw_sha256"),
    ("backlog_evidence", "backlog_evidence_raw_sha256"),
    ("rollback_plan", "rollback_plan_raw_sha256"),
    (
        "root_pin_identity_attestation",
        "root_pin_identity_attestation_raw_sha256",
    ),
    (
        "custody_path_identity_attestation",
        "custody_path_identity_attestation_raw_sha256",
    ),
    (
        "isolated_network_attestation",
        "isolated_network_attestation_raw_sha256",
    ),
    ("deployment_plan", "deployment_plan_raw_sha256"),
)


class DeploymentReleaseError(RuntimeError):
    """Expected fail-closed deployment release error."""


@dataclass(frozen=True)
class DeploymentEvidencePaths:
    questdb_image_attestation: Path
    readonly_principal_identity_attestation: Path
    secret_file_identity_attestation: Path
    writer_continuity_pre_evidence: Path
    writer_continuity_post_evidence: Path
    health_evidence: Path
    backlog_evidence: Path
    rollback_plan: Path
    root_pin_identity_attestation: Path
    custody_path_identity_attestation: Path
    isolated_network_attestation: Path
    deployment_plan: Path

    def as_dict(self) -> dict[str, Path]:
        return {
            name: getattr(self, name)
            for name, _release_field in EVIDENCE_FILE_FIELDS
        }


@dataclass(frozen=True)
class VerifiedDeploymentRelease:
    payload: dict[str, Any]
    release_raw_sha256: str
    release_canonical_sha256: str
    keyring_sha256: str
    evidence_raw_sha256: dict[str, str]
    evidence_bundle_index_sha256: str


def unsigned_release_payload(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key != "signature"
    }


def release_attempt_id(release_id: str) -> str:
    return "attempt-" + hashlib.sha256(
        release_id.encode("utf-8")
    ).hexdigest()


def pin_root_path_sha256() -> str:
    return hashlib.sha256(
        str(DEPLOYMENT_PIN_ROOT).encode("utf-8")
    ).hexdigest()


def validate_pin_root_identity(
    expected_identity: tuple[int, int, int, int, int] | None = None,
) -> tuple[int, int, int, int, int]:
    try:
        info = DEPLOYMENT_PIN_ROOT.lstat()
    except OSError as exc:
        raise DeploymentReleaseError(
            "readonly deployment pin root is unavailable"
        ) from exc
    identity = (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        stat.S_IFMT(info.st_mode),
    )
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise DeploymentReleaseError(
            "pin root must be a root-owned non-symlink directory "
            "that is not group/world writable"
        )
    if expected_identity is not None and identity != expected_identity:
        raise DeploymentReleaseError(
            "readonly deployment pin root identity changed"
        )
    return identity


def _sha256_file(path: Path, label: str) -> str:
    try:
        raw = read_regular_file_strict(
            path,
            label,
            limit=MAX_EVIDENCE_BYTES,
        )
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc
    return hashlib.sha256(raw).hexdigest()


def _validate_schema(
    payload: Any,
    schema_path: Path,
    label: str,
) -> None:
    try:
        validate_json_schema(payload, schema_path, label)
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc


def _load_json(
    path: Path,
    label: str,
    *,
    private: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = read_regular_file_strict(
            path,
            label,
            limit=MAX_JSON_BYTES,
            private=private,
        )
        return raw, parse_json_bytes(raw, label)
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc


def _parse_time(value: Any, label: str) -> datetime:
    try:
        return parse_datetime(value, label)
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc


def _require_aware_datetime(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise DeploymentReleaseError(
            f"{label} must be timezone-aware"
        )
    return value


def _load_trusted_public_key(
    keyring: dict[str, Any],
    key_id: str,
) -> Ed25519PublicKey:
    if set(keyring) != {"schema_version", "keys"}:
        raise DeploymentReleaseError(
            "trusted keyring fields are invalid"
        )
    if keyring["schema_version"] != TRUSTED_KEYRING_VERSION:
        raise DeploymentReleaseError(
            "trusted keyring schema version is invalid"
        )
    keys = keyring["keys"]
    if not isinstance(keys, list) or not keys:
        raise DeploymentReleaseError(
            "trusted keyring must contain at least one key"
        )
    matched: dict[str, Any] | None = None
    seen: set[str] = set()
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != {
            "key_id",
            "purpose",
            "public_key_base64",
        }:
            raise DeploymentReleaseError(
                "trusted keyring entry fields are invalid"
            )
        current_id = entry["key_id"]
        if (
            not isinstance(current_id, str)
            or ID_PATTERN.fullmatch(current_id) is None
            or current_id in seen
        ):
            raise DeploymentReleaseError(
                "trusted keyring key_id is invalid or duplicated"
            )
        seen.add(current_id)
        if entry["purpose"] != TRUSTED_KEY_PURPOSE:
            raise DeploymentReleaseError(
                "trusted keyring contains a wrong-purpose key"
            )
        if current_id == key_id:
            matched = entry
    if matched is None:
        raise DeploymentReleaseError(
            "deployment release signer key is not trusted"
        )
    try:
        raw = base64.b64decode(
            str(matched["public_key_base64"]),
            validate=True,
        )
        if len(raw) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, binascii.Error) as exc:
        raise DeploymentReleaseError(
            "trusted Ed25519 public key is invalid"
        ) from exc


def validate_release_semantics(
    payload: dict[str, Any],
    *,
    now: datetime,
) -> None:
    if payload["schema_version"] != RELEASE_SCHEMA_VERSION:
        raise DeploymentReleaseError(
            "deployment release schema version is invalid"
        )
    if payload["purpose"] != RELEASE_PURPOSE:
        raise DeploymentReleaseError(
            "deployment release purpose is invalid"
        )
    release_id = str(payload["release_id"])
    if ID_PATTERN.fullmatch(release_id) is None:
        raise DeploymentReleaseError("release_id is invalid")
    expected_attempt_id = release_attempt_id(release_id)
    if not hmac.compare_digest(
        str(payload["attempt_id"]),
        expected_attempt_id,
    ):
        raise DeploymentReleaseError(
            "attempt_id does not match the SHA256 of release_id"
        )
    human_signature = str(payload["human_signature"]).strip()
    if not human_signature or human_signature.startswith("PENDING_"):
        raise DeploymentReleaseError(
            "human_signature must contain final human text"
        )
    if not str(payload["reviewer_role"]).strip():
        raise DeploymentReleaseError(
            "reviewer_role must not be empty"
        )

    issued_at = _parse_time(payload["issued_at"], "issued_at")
    not_before = _parse_time(payload["not_before"], "not_before")
    expires_at = _parse_time(payload["expires_at"], "expires_at")
    if not issued_at <= not_before < expires_at:
        raise DeploymentReleaseError(
            "release times must satisfy issued_at <= not_before < expires_at"
        )
    if expires_at - issued_at > MAX_RELEASE_TTL:
        raise DeploymentReleaseError(
            "deployment release TTL cannot exceed 2 hours"
        )
    normalized_now = _require_aware_datetime(
        now,
        "now",
    ).astimezone(timezone.utc)
    if normalized_now < not_before:
        raise DeploymentReleaseError(
            "deployment release is not active yet"
        )
    if normalized_now >= expires_at:
        raise DeploymentReleaseError(
            "deployment release has expired"
        )

    if not hmac.compare_digest(
        payload["pin_root_path_sha256"],
        pin_root_path_sha256(),
    ):
        raise DeploymentReleaseError(
            "pin root path identity does not match the fixed runtime path"
        )
    for field in (
        "issue_number",
        "secret_file_expected_owner_uid",
        "secret_file_expected_owner_gid",
        "isolated_network_expected_member_count",
        "max_deployment_seconds",
        "allowed_restart_count",
        "rollback_deadline_seconds",
    ):
        if type(payload[field]) is not int:
            raise DeploymentReleaseError(
                f"{field} must be an integer JSON literal"
            )

    if any(
        payload[field] is not True
        for field in RELEASE_REQUIRED_TRUE_FIELDS
    ):
        raise DeploymentReleaseError(
            "release is missing a mandatory readonly deployment guard"
        )
    if any(
        payload[field] is not False
        for field in RELEASE_REQUIRED_FALSE_FIELDS
    ):
        raise DeploymentReleaseError(
            "release attempts to grant forbidden authority"
        )


def validate_runtime_file_bindings(
    release: dict[str, Any],
) -> None:
    bindings = (
        ("verifier_sha256", VERIFIER_PATH),
        ("release_schema_sha256", RELEASE_SCHEMA_PATH),
        ("consume_schema_sha256", CONSUME_SCHEMA_PATH),
        ("receipt_schema_sha256", RECEIPT_SCHEMA_PATH),
    )
    for field, path in bindings:
        actual = _sha256_file(path, field)
        if not hmac.compare_digest(actual, release[field]):
            raise DeploymentReleaseError(
                f"{field} does not match the exact runtime file"
            )


def verify_evidence_bundle(
    release: dict[str, Any],
    paths: DeploymentEvidencePaths,
) -> tuple[dict[str, str], str]:
    actual_hashes: dict[str, str] = {}
    evidence_payloads: dict[str, dict[str, Any]] = {}
    path_map = paths.as_dict()
    for name, release_field in EVIDENCE_FILE_FIELDS:
        try:
            raw = read_regular_file_strict(
                path_map[name],
                name,
                limit=MAX_EVIDENCE_BYTES,
            )
            evidence_payloads[name] = parse_json_bytes(raw, name)
        except OneShotError as exc:
            raise DeploymentReleaseError(str(exc)) from exc
        actual = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual, release[release_field]):
            raise DeploymentReleaseError(
                f"{release_field} does not match exact evidence bytes"
            )
        actual_hashes[name] = actual
    bundle_index = hashlib.sha256(
        canonical_json(actual_hashes)
    ).hexdigest()
    if not hmac.compare_digest(
        bundle_index,
        release["evidence_bundle_index_sha256"],
    ):
        raise DeploymentReleaseError(
            "evidence bundle index does not match release"
        )
    validate_identity_attestations(release, evidence_payloads)
    return actual_hashes, bundle_index


def _require_exact_fields(
    payload: dict[str, Any],
    expected: set[str],
    label: str,
) -> None:
    if set(payload) != expected:
        raise DeploymentReleaseError(
            f"{label} fields are invalid"
        )


def validate_identity_attestations(
    release: dict[str, Any],
    evidence: dict[str, dict[str, Any]],
) -> None:
    image = evidence["questdb_image_attestation"]
    _require_exact_fields(
        image,
        {
            "schema_version",
            "attestation_id",
            "contract_source_commit_sha",
            "questdb_image_digest",
            "questdb_target_identity_sha256",
            "questdb_build_sha256",
            "external_verification_asserted",
        },
        "QuestDB image attestation",
    )
    if (
        image["schema_version"]
        != "commodity_c_fast_questdb_image_attestation_v1"
        or ID_PATTERN.fullmatch(str(image["attestation_id"])) is None
        or image["contract_source_commit_sha"]
        != release["source_commit_sha"]
        or image["questdb_image_digest"]
        != release["questdb_image_digest"]
        or image["questdb_target_identity_sha256"]
        != release["questdb_target_identity_sha256"]
        or image["questdb_build_sha256"]
        != release["questdb_build_sha256"]
        or image["external_verification_asserted"] is not True
    ):
        raise DeploymentReleaseError(
            "QuestDB image attestation bindings are invalid"
        )

    principal = evidence[
        "readonly_principal_identity_attestation"
    ]
    _require_exact_fields(
        principal,
        {
            "schema_version",
            "attestation_id",
            "readonly_principal_identity_sha256",
            "principal_differs_from_admin",
            "principal_name_included",
            "secret_included",
        },
        "readonly principal identity attestation",
    )
    if (
        principal["schema_version"]
        != "commodity_c_fast_readonly_principal_identity_attestation_v1"
        or ID_PATTERN.fullmatch(
            str(principal["attestation_id"])
        )
        is None
        or principal["readonly_principal_identity_sha256"]
        != release["readonly_principal_identity_sha256"]
        or principal["principal_differs_from_admin"] is not True
        or principal["principal_name_included"] is not False
        or principal["secret_included"] is not False
    ):
        raise DeploymentReleaseError(
            "readonly principal identity attestation bindings are invalid"
        )

    secret_file = evidence["secret_file_identity_attestation"]
    _require_exact_fields(
        secret_file,
        {
            "schema_version",
            "attestation_id",
            "secret_file_path_sha256",
            "owner_uid",
            "owner_gid",
            "mode",
            "regular_file",
            "symlink",
            "secret_content_included",
        },
        "secret file identity attestation",
    )
    if (
        secret_file["schema_version"]
        != "commodity_c_fast_readonly_secret_file_identity_attestation_v1"
        or ID_PATTERN.fullmatch(
            str(secret_file["attestation_id"])
        )
        is None
        or secret_file["secret_file_path_sha256"]
        != release["secret_file_path_sha256"]
        or type(secret_file["owner_uid"]) is not int
        or secret_file["owner_uid"]
        != release["secret_file_expected_owner_uid"]
        or type(secret_file["owner_gid"]) is not int
        or secret_file["owner_gid"]
        != release["secret_file_expected_owner_gid"]
        or secret_file["mode"]
        != release["secret_file_expected_mode"]
        or secret_file["regular_file"] is not True
        or secret_file["symlink"] is not False
        or secret_file["secret_content_included"] is not False
    ):
        raise DeploymentReleaseError(
            "secret file identity attestation bindings are invalid"
        )

    network = evidence["isolated_network_attestation"]
    _require_exact_fields(
        network,
        {
            "schema_version",
            "attestation_id",
            "isolated_network_identity_sha256",
            "driver",
            "internal",
            "runner_member_identity_sha256",
            "questdb_member_identity_sha256",
            "member_count",
            "unexpected_member_identity_sha256s",
            "docker_socket_connectivity",
            "rpc_connectivity",
            "trading_connectivity",
        },
        "isolated network attestation",
    )
    runner_identity = network["runner_member_identity_sha256"]
    questdb_identity = network["questdb_member_identity_sha256"]
    if (
        network["schema_version"]
        != ISOLATED_NETWORK_ATTESTATION_VERSION
        or ID_PATTERN.fullmatch(
            str(network["attestation_id"])
        )
        is None
        or network["isolated_network_identity_sha256"]
        != release["isolated_network_identity_sha256"]
        or network["driver"]
        != release["isolated_network_driver_required"]
        or network["internal"] is not True
        or runner_identity
        != release[
            "isolated_network_runner_member_identity_sha256"
        ]
        or questdb_identity
        != release[
            "isolated_network_questdb_member_identity_sha256"
        ]
        or runner_identity == questdb_identity
        or type(network["member_count"]) is not int
        or network["member_count"]
        != release["isolated_network_expected_member_count"]
        or network["unexpected_member_identity_sha256s"] != []
        or network["docker_socket_connectivity"] is not False
        or network["rpc_connectivity"] is not False
        or network["trading_connectivity"] is not False
    ):
        raise DeploymentReleaseError(
            "isolated network attestation bindings are invalid"
        )


def verify_release(
    release_path: Path,
    keyring_path: Path,
    evidence_paths: DeploymentEvidencePaths,
    *,
    source_commit_sha: str,
    questdb_image_digest: str,
    pinned_keyring_sha256: str,
    now: datetime | None = None,
) -> VerifiedDeploymentRelease:
    current_time = (
        datetime.now(timezone.utc)
        if now is None
        else _require_aware_datetime(now, "now")
    )
    release_raw, release = _load_json(
        release_path,
        "signed readonly deployment release",
    )
    _keyring_raw, keyring = _load_json(
        keyring_path,
        "readonly deployment trusted keyring",
        private=True,
    )
    _validate_schema(
        release,
        RELEASE_SCHEMA_PATH,
        "signed readonly deployment release",
    )
    validate_release_semantics(release, now=current_time)
    validate_runtime_file_bindings(release)

    if not SHA256_PATTERN.fullmatch(pinned_keyring_sha256):
        raise DeploymentReleaseError(
            "deployment-pinned keyring SHA256 is invalid"
        )
    keyring_sha256 = hashlib.sha256(
        canonical_json(keyring)
    ).hexdigest()
    if not hmac.compare_digest(
        keyring_sha256,
        pinned_keyring_sha256,
    ):
        raise DeploymentReleaseError(
            "trusted keyring does not match the independent deployment pin"
        )
    if not hmac.compare_digest(
        keyring_sha256,
        release["trusted_keyring_sha256"],
    ):
        raise DeploymentReleaseError(
            "trusted keyring SHA256 does not match release"
        )
    public_key = _load_trusted_public_key(
        keyring,
        str(release["signer_key_id"]),
    )
    try:
        signature = base64.b64decode(
            release["signature"],
            validate=True,
        )
        if len(signature) != 64:
            raise ValueError
        public_key.verify(
            signature,
            canonical_json(unsigned_release_payload(release)),
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise DeploymentReleaseError(
            "readonly deployment release signature is invalid"
        ) from exc

    if not re.fullmatch(r"^[0-9a-f]{40}$", source_commit_sha):
        raise DeploymentReleaseError(
            "runtime source commit assertion is invalid"
        )
    if not hmac.compare_digest(
        source_commit_sha,
        release["source_commit_sha"],
    ):
        raise DeploymentReleaseError(
            "source commit does not match release"
        )
    if IMAGE_DIGEST_PATTERN.fullmatch(questdb_image_digest) is None:
        raise DeploymentReleaseError(
            "runtime QuestDB image digest assertion is invalid"
        )
    if not hmac.compare_digest(
        questdb_image_digest,
        release["questdb_image_digest"],
    ):
        raise DeploymentReleaseError(
            "QuestDB image digest does not match release"
        )

    evidence_hashes, bundle_index = verify_evidence_bundle(
        release,
        evidence_paths,
    )
    return VerifiedDeploymentRelease(
        payload=release,
        release_raw_sha256=hashlib.sha256(
            release_raw
        ).hexdigest(),
        release_canonical_sha256=hashlib.sha256(
            canonical_json(release)
        ).hexdigest(),
        keyring_sha256=keyring_sha256,
        evidence_raw_sha256=evidence_hashes,
        evidence_bundle_index_sha256=bundle_index,
    )


def validate_custody_identity(
    guard: CustodyGuard,
    expected_sha256: str,
) -> None:
    try:
        raw = read_regular_file_at(
            guard,
            CUSTODY_IDENTITY_FILENAME,
            "readonly deployment custody identity",
        )
        identity = parse_json_bytes(
            raw,
            "readonly deployment custody identity",
        )
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc
    if set(identity) != {"schema_version", "custody_id"}:
        raise DeploymentReleaseError(
            "readonly deployment custody identity fields are invalid"
        )
    if identity["schema_version"] != CUSTODY_IDENTITY_VERSION:
        raise DeploymentReleaseError(
            "readonly deployment custody identity version is invalid"
        )
    if ID_PATTERN.fullmatch(str(identity["custody_id"])) is None:
        raise DeploymentReleaseError(
            "readonly deployment custody_id is invalid"
        )
    actual = hashlib.sha256(canonical_json(identity)).hexdigest()
    if not hmac.compare_digest(actual, expected_sha256):
        raise DeploymentReleaseError(
            "readonly deployment custody identity does not match release"
        )


def consume_release(
    args: argparse.Namespace,
    *,
    now: datetime | None = None,
    pinned_keyring_sha256: str | None = None,
    pinned_custody_path: Path | None = None,
) -> dict[str, Any]:
    current_time = (
        datetime.now(timezone.utc)
        if now is None
        else _require_aware_datetime(now, "now")
    )
    try:
        if pinned_keyring_sha256 is None or pinned_custody_path is None:
            pin_root_identity = validate_pin_root_identity()
        else:
            pin_root_identity = None
        effective_keyring_pin = (
            read_root_owned_deployment_pin(
                DEPLOYMENT_KEYRING_PIN_PATH,
                "readonly deployment keyring pin",
            )
            if pinned_keyring_sha256 is None
            else pinned_keyring_sha256
        )
        effective_custody_path = (
            Path(
                read_root_owned_deployment_pin(
                    DEPLOYMENT_CUSTODY_PIN_PATH,
                    "readonly deployment custody path pin",
                )
            )
            if pinned_custody_path is None
            else pinned_custody_path
        )
        if pin_root_identity is not None:
            validate_pin_root_identity(pin_root_identity)
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc

    verified = verify_release(
        args.release,
        args.trusted_keyring,
        evidence_paths_from_args(args),
        source_commit_sha=args.source_commit_sha,
        questdb_image_digest=args.questdb_image_digest,
        pinned_keyring_sha256=effective_keyring_pin,
        now=current_time,
    )
    release = verified.payload
    try:
        requested_custody = args.custody_dir.resolve(strict=True)
        pinned_custody = effective_custody_path.resolve(strict=True)
    except OSError as exc:
        raise DeploymentReleaseError(
            "cannot resolve deployment-pinned custody"
        ) from exc
    if requested_custody != pinned_custody:
        raise DeploymentReleaseError(
            "custody directory does not match immutable deployment pin"
        )
    try:
        actual_custody_path_sha256 = custody_path_sha256(
            pinned_custody
        )
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc
    if not hmac.compare_digest(
        actual_custody_path_sha256,
        release["custody_path_sha256"],
    ):
        raise DeploymentReleaseError(
            "custody path SHA256 does not match release"
        )
    try:
        guard = open_custody_guard(
            args.custody_dir,
            require_root_owned_parent=pinned_custody_path is None,
        )
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc
    try:
        validate_custody_identity(
            guard,
            release["custody_identity_sha256"],
        )
        consume_name = (
            f"{release['attempt_id']}.deployment-consumed.json"
        )
        receipt_name = (
            f"{release['attempt_id']}.deployment-receipt.json"
        )
        if custody_entry_exists(guard, consume_name):
            raise DeploymentReleaseError(
                "RELEASE_ALREADY_CONSUMED_REPLAY_FORBIDDEN"
            )
        if custody_entry_exists(guard, receipt_name):
            raise DeploymentReleaseError(
                "receipt exists without a consume marker"
            )
        consume_marker = {
            "schema_version": CONSUME_SCHEMA_VERSION,
            "candidate_id": CANDIDATE_ID,
            "release_id": release["release_id"],
            "attempt_id": release["attempt_id"],
            "release_raw_sha256": verified.release_raw_sha256,
            "release_canonical_sha256": (
                verified.release_canonical_sha256
            ),
            "consumed_at": current_time.isoformat(),
            "trusted_keyring_sha256": verified.keyring_sha256,
            "source_commit_sha": release["source_commit_sha"],
            "questdb_image_digest": release["questdb_image_digest"],
            "evidence_bundle_index_sha256": (
                verified.evidence_bundle_index_sha256
            ),
            "custody_identity_sha256": (
                release["custody_identity_sha256"]
            ),
            "custody_path_sha256": release["custody_path_sha256"],
            "replay_allowed": False,
            "deployment_executed": False,
        }
        try:
            consume_marker_raw_sha256 = write_json_create_only_at(
                guard,
                consume_name,
                consume_marker,
                CONSUME_SCHEMA_PATH,
                "readonly deployment consume marker",
            )
        except FileExistsError as exc:
            raise DeploymentReleaseError(
                "release was concurrently consumed"
            ) from exc
        receipt = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "candidate_id": CANDIDATE_ID,
            "release_id": release["release_id"],
            "attempt_id": release["attempt_id"],
            "release_raw_sha256": verified.release_raw_sha256,
            "release_canonical_sha256": (
                verified.release_canonical_sha256
            ),
            "consume_marker_raw_sha256": (
                consume_marker_raw_sha256
            ),
            "evidence_bundle_index_sha256": (
                verified.evidence_bundle_index_sha256
            ),
            "verified_at": current_time.isoformat(),
            "signer_key_id": release["signer_key_id"],
            "signer_key_purpose": TRUSTED_KEY_PURPOSE,
            "signature_verified": True,
            "receipt_authority_state": (
                "NON_AUTHORITATIVE_OFFLINE_VERIFICATION_RECEIPT"
            ),
            "receipt_is_authority": False,
            "raw_signed_release_required_for_any_action": True,
            "authority_granted": False,
            "replay_allowed": False,
            "deployment_executed": False,
            "secret_file_symlink_allowed": False,
            "secret_content_read_authorized": False,
            "global_pgwire_readonly_allowed": False,
            "instance_readonly_allowed": False,
            "isolated_network_unexpected_members_allowed": False,
            "isolated_network_docker_socket_connectivity_allowed": (
                False
            ),
            "isolated_network_rpc_connectivity_allowed": False,
            "isolated_network_trading_connectivity_allowed": False,
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
            "database_mutations": 0,
            "orders_sent": 0,
            "positions_modified": 0,
            "dispatch_changed": False,
        }
        try:
            write_json_create_only_at(
                guard,
                receipt_name,
                receipt,
                RECEIPT_SCHEMA_PATH,
                "readonly deployment verification receipt",
            )
        except FileExistsError as exc:
            raise DeploymentReleaseError(
                "verification receipt already exists"
            ) from exc
        return receipt
    except OneShotError as exc:
        raise DeploymentReleaseError(str(exc)) from exc
    finally:
        guard.close()


def add_evidence_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    for name, _release_field in EVIDENCE_FILE_FIELDS:
        parser.add_argument(
            "--" + name.replace("_", "-"),
            type=Path,
            required=True,
        )


def evidence_paths_from_args(
    args: argparse.Namespace,
) -> DeploymentEvidencePaths:
    return DeploymentEvidencePaths(
        **{
            name: getattr(args, name)
            for name, _release_field in EVIDENCE_FILE_FIELDS
        }
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument("--custody-dir", type=Path, required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--questdb-image-digest", required=True)
    add_evidence_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        receipt = consume_release(args)
    except (DeploymentReleaseError, OSError, ValueError) as exc:
        print(
            f"readonly deployment release verification failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print("readonly deployment release consumed offline")
    print(f"release_id={receipt['release_id']}")
    print(f"attempt_id={receipt['attempt_id']}")
    print(f"receipt_authority_state={receipt['receipt_authority_state']}")
    print("deployment_executed=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
