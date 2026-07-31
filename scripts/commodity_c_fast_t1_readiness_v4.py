#!/usr/bin/env python3
"""Derive a non-authoritative C_FAST query-v4 readiness packet."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from itertools import combinations
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from c_fast_t1.verify_query_v4_image_attestation import (
    QueryV4ImageAttestationError,
    verify_query_v4_image_evidence,
)
from commodity_c_fast_readonly_deployment_outcome import (
    OUTCOME_FALSE_FIELDS,
    OUTCOME_KEYRING_VERSION,
    OUTCOME_KEY_PURPOSE,
    OUTCOME_ZERO_FIELDS,
    DeploymentOutcomeError,
    OutcomeSourcePaths,
    PostEvidencePaths,
    add_post_arguments,
    add_source_arguments,
    post_paths_from_args,
    source_paths_from_args,
    verify_signed_outcome,
)
from commodity_c_fast_t1_build_registry_provenance_v3 import (
    FALSE_AUTHORITY_FIELDS as PROVENANCE_FALSE_AUTHORITY_FIELDS,
)
from commodity_c_fast_t1_build_registry_provenance_v3 import (
    KEYRING_VERSION as PROVENANCE_KEYRING_VERSION,
)
from commodity_c_fast_t1_build_registry_provenance_v3 import (
    KEY_PURPOSE as PROVENANCE_KEY_PURPOSE,
)
from commodity_c_fast_t1_build_registry_provenance_v3 import (
    L3_KEYRING_VERSION,
    L3_KEY_PURPOSE,
    T1_KEYRING_VERSION,
    T1_KEY_PURPOSE,
)
from commodity_c_fast_t1_build_registry_provenance_v3 import (
    ZERO_FACT_FIELDS as PROVENANCE_ZERO_FACT_FIELDS,
)
from commodity_c_fast_t1_build_registry_provenance_v3 import (
    BuildRegistryProvenanceV3Error,
    load_excluded_authority_key_facts,
    verify_provenance,
)
from commodity_c_fast_t1_one_shot import (
    OneShotError,
    canonical_json,
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
SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-readiness-v4.schema.json"
)
QUERY_V5_KEYRING_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v5-trusted-keys-v1.schema.json"
)
PIN_ROOT = Path("/run/c-fast-t1-readiness-v4-pins")
PIN_MANIFEST_PATH = PIN_ROOT / "pin-set.manifest.json"
PIN_PATHS = {
    "provenance_keyring_sha256": PIN_ROOT / "provenance-keyring.sha256",
    "provenance_signing_tool_source_sha256": (
        PIN_ROOT / "provenance-signing-tool-source.sha256"
    ),
    "provenance_signing_tool_source_commit_sha": (
        PIN_ROOT / "provenance-signing-tool-source.commit"
    ),
    "provenance_signer_dependency_manifest_sha256": (
        PIN_ROOT / "provenance-signer-dependency-manifest.sha256"
    ),
    "provenance_signer_runtime_image_digest": (
        PIN_ROOT / "provenance-signer-runtime-image.digest"
    ),
    "query_v5_authority_keyring_sha256": (
        PIN_ROOT / "query-v5-authority-keyring.sha256"
    ),
    "t1_authority_keyring_sha256": (
        PIN_ROOT / "t1-authority-keyring.sha256"
    ),
    "l3_authority_keyring_sha256": (
        PIN_ROOT / "l3-authority-keyring.sha256"
    ),
    "outcome_keyring_sha256": PIN_ROOT / "outcome-keyring.sha256",
    "packet_custody_path": PIN_ROOT / "packet-custody.path",
}

SCHEMA_VERSION = "commodity_c_fast_t1_readiness_v4"
PIN_MANIFEST_VERSION = "commodity_c_fast_t1_readiness_v4_pin_set_v1"
CUSTODY_IDENTITY_VERSION = (
    "commodity_c_fast_t1_readiness_v4_custody_identity_v1"
)
CUSTODY_IDENTITY_FILENAME = "custody-identity.json"
STATUS = "READY_FOR_QUERY_RELEASE_V5_HUMAN_SIGNATURE_ONLY"
QUERY_V5_KEYRING_SCHEMA_VERSION = (
    "commodity_c_fast_t1_query_v5_trusted_keys_v1"
)
QUERY_V5_KEY_PURPOSE = "t1_exact_readonly_query_v5_release_signer"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
PARENT_ISSUE_NUMBER = 114
ISSUE_NUMBER = 216
PACKET_TTL = timedelta(minutes=15)
MAX_OUTCOME_AGE = timedelta(hours=1)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_OCI_BYTES = 256 * 1024 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")

PIN_MANIFEST_VALUE_FIELDS = (
    "provenance_keyring_sha256",
    "provenance_signing_tool_source_sha256",
    "provenance_signing_tool_source_commit_sha",
    "provenance_signer_dependency_manifest_sha256",
    "provenance_signer_runtime_image_digest",
    "query_v5_authority_keyring_sha256",
    "t1_authority_keyring_sha256",
    "l3_authority_keyring_sha256",
    "outcome_keyring_sha256",
    "packet_custody_path",
)
PIN_MANIFEST_FIELDS = (
    "schema_version",
    "generation_id",
    *PIN_MANIFEST_VALUE_FIELDS,
    "packet_custody_id",
    "packet_custody_identity_sha256",
    "packet_custody_directory_identity_sha256",
    "evidence_join_identity_sha256",
)

FALSE_AUTHORITY_FIELDS = (
    "sensitive_material_present",
    "packet_is_authority",
    "receipt_is_authority",
    "outcome_is_authority",
    "authority_granted",
    "readiness_authorized",
    "ready_for_human_t1_release_signature_only",
    "ready_for_human_query_release_signature_only",
    "replay_allowed",
    "network_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "production_query_authorized",
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
    "collection_authorized",
    "execution_quality_collection_authorized",
    "runtime_activation_authorized",
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
    "t1_executed",
    "production_queried",
    "readonly_query_authorized",
    "web_bridge_deployment_authorized",
    "t1_one_shot_child_launch_authorized",
    "local_query_evidence_write_authorized",
    "web_bridge_rpc_authorized",
    "p0_acceptance_authorized",
    "dispatch_changed",
)
ZERO_FACT_FIELDS = (
    "production_queries_executed",
    "readonly_queries_executed",
    "write_probes_attempted",
    "database_mutations",
    "web_bridge_rpc_calls",
    "orders_sent",
    "positions_modified",
)
READINESS_V4_REQUIRED_FALSE_FIELDS = frozenset(
    {
        "t1_one_shot_child_launch_authorized",
        "local_query_evidence_write_authorized",
        "web_bridge_rpc_authorized",
        "p0_acceptance_authorized",
    }
)

if (
    not set(OUTCOME_FALSE_FIELDS).issubset(FALSE_AUTHORITY_FIELDS)
    or not set(PROVENANCE_FALSE_AUTHORITY_FIELDS).issubset(
        FALSE_AUTHORITY_FIELDS
    )
    or not set(OUTCOME_ZERO_FIELDS).issubset(ZERO_FACT_FIELDS)
    or not set(PROVENANCE_ZERO_FACT_FIELDS).issubset(ZERO_FACT_FIELDS)
    or not READINESS_V4_REQUIRED_FALSE_FIELDS.issubset(
        FALSE_AUTHORITY_FIELDS
    )
):
    raise RuntimeError(
        "readiness-v4 deny matrix does not cover upstream evidence contracts"
    )


class ReadinessV4Error(RuntimeError):
    """Expected fail-closed readiness-v4 derivation error."""


@dataclass(frozen=True)
class ReadinessPins:
    pin_set_generation_id: str
    pin_set_manifest_sha256: str
    pin_root_identity_sha256: str
    provenance_keyring_sha256: str
    provenance_signing_tool_source_sha256: str
    provenance_signing_tool_source_commit_sha: str
    provenance_signer_dependency_manifest_sha256: str
    provenance_signer_runtime_image_digest: str
    query_v5_authority_keyring_sha256: str
    t1_authority_keyring_sha256: str
    l3_authority_keyring_sha256: str
    outcome_keyring_sha256: str
    packet_custody_path: Path
    packet_custody_id: str
    packet_custody_identity_sha256: str
    packet_custody_directory_identity_sha256: str
    evidence_join_identity_sha256: str


@dataclass(frozen=True)
class ReadinessInputs:
    external_image_evidence: Path
    source_bundle_archive: Path
    oci_layout_archive: Path
    content_attestation: Path
    provenance: Path
    provenance_keyring: Path
    query_v5_keyring: Path
    t1_keyring: Path
    outcome: Path
    outcome_keyring: Path
    outcome_source: OutcomeSourcePaths
    post_evidence: PostEvidencePaths
    t1_runtime_source_commit_sha: str
    t1_runtime_image_digest: str
    l3_contract_source_commit_sha: str
    outcome_contract_source_commit_assertion: str
    questdb_image_digest: str


@dataclass(frozen=True)
class VerifiedReadinessPacket:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pin_root_path_sha256() -> str:
    return _hash_bytes(str(PIN_ROOT).encode("utf-8"))


def _require_root_owned_directory_chain(path: Path, *, label: str) -> None:
    if not path.is_absolute():
        raise ReadinessV4Error(f"{label} must be absolute")
    for current in (path, *path.parents):
        try:
            info = current.lstat()
        except OSError as exc:
            raise ReadinessV4Error(
                f"{label} ancestor is unavailable: {current}"
            ) from exc
        mode = stat.S_IMODE(info.st_mode)
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or mode & 0o022
        ):
            raise ReadinessV4Error(
                f"{label} ancestor must be a root-owned non-symlink "
                "directory and not group/world writable"
            )


def _directory_identity_sha256(
    path: Path,
    *,
    label: str,
    require_root_owner: bool,
) -> str:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReadinessV4Error(f"{label} is unavailable") from exc
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReadinessV4Error(f"{label} must be a non-symlink directory")
    if require_root_owner:
        _require_root_owned_directory_chain(path, label=label)
    return _hash_bytes(
        canonical_json(
            {
                "resolved_path": str(resolved),
                "device": info.st_dev,
                "inode": info.st_ino,
                "owner_uid": info.st_uid,
                "mode": mode,
                "file_type": stat.S_IFMT(info.st_mode),
            }
        )
    )


def _pin_root_identity_sha256() -> str:
    return _directory_identity_sha256(
        PIN_ROOT,
        label="readiness-v4 pin root",
        require_root_owner=True,
    )


def _custody_directory_identity_sha256(guard: Any) -> str:
    device, inode, owner_uid, mode, file_type = guard.identity
    return _hash_bytes(
        canonical_json(
            {
                "resolved_path": str(guard.path.resolve(strict=True)),
                "device": device,
                "inode": inode,
                "owner_uid": owner_uid,
                "mode": mode,
                "file_type": file_type,
            }
        )
    )


def _read_packet_custody_facts(
    path: Path,
    *,
    require_root_owned_parent_chain: bool = False,
) -> tuple[str, str, str]:
    if require_root_owned_parent_chain:
        _require_root_owned_directory_chain(
            path.parent,
            label="readiness-v4 custody parent chain",
        )
    try:
        guard = open_custody_guard(
            path,
            require_root_owned_parent=False,
        )
        try:
            raw = read_regular_file_at(
                guard,
                CUSTODY_IDENTITY_FILENAME,
                "readiness-v4 custody identity",
            )
            identity = parse_json_bytes(
                raw,
                "readiness-v4 custody identity",
            )
            directory_identity_sha256 = (
                _custody_directory_identity_sha256(guard)
            )
        finally:
            guard.close()
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if (
        set(identity) != {"schema_version", "custody_id"}
        or identity.get("schema_version") != CUSTODY_IDENTITY_VERSION
        or ID_PATTERN.fullmatch(str(identity.get("custody_id"))) is None
    ):
        raise ReadinessV4Error(
            "readiness-v4 custody identity fields are invalid"
        )
    return (
        str(identity["custody_id"]),
        _hash_bytes(canonical_json(identity)),
        directory_identity_sha256,
    )


def _read_root_owned_pin_manifest() -> tuple[bytes, dict[str, Any]]:
    try:
        raw = read_regular_file_strict(
            PIN_MANIFEST_PATH,
            "readiness-v4 pin-set manifest",
            limit=16384,
        )
        info = PIN_MANIFEST_PATH.lstat()
        manifest = parse_json_bytes(raw, "readiness-v4 pin-set manifest")
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    except OSError as exc:
        raise ReadinessV4Error(
            "readiness-v4 pin-set manifest is unavailable"
        ) from exc
    if (
        info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or set(manifest) != set(PIN_MANIFEST_FIELDS)
        or manifest.get("schema_version") != PIN_MANIFEST_VERSION
    ):
        raise ReadinessV4Error(
            "readiness-v4 pin-set manifest ownership or fields are invalid"
        )
    return raw, manifest


def _require_aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReadinessV4Error(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _read(
    path: Path,
    label: str,
    *,
    limit: int = MAX_JSON_BYTES,
    private: bool = False,
) -> bytes:
    try:
        return read_regular_file_strict(
            path,
            label,
            limit=limit,
            private=private,
        )
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc


def _load_json(
    path: Path,
    label: str,
    *,
    private: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    raw = _read(path, label, private=private)
    try:
        return raw, parse_json_bytes(raw, label)
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc


def _validate_pins(pins: ReadinessPins) -> None:
    for field in (
        "pin_set_manifest_sha256",
        "pin_root_identity_sha256",
        "provenance_keyring_sha256",
        "provenance_signing_tool_source_sha256",
        "provenance_signer_dependency_manifest_sha256",
        "query_v5_authority_keyring_sha256",
        "t1_authority_keyring_sha256",
        "l3_authority_keyring_sha256",
        "outcome_keyring_sha256",
        "packet_custody_identity_sha256",
        "packet_custody_directory_identity_sha256",
        "evidence_join_identity_sha256",
    ):
        if SHA256_PATTERN.fullmatch(str(getattr(pins, field))) is None:
            raise ReadinessV4Error(f"{field} must be a lowercase SHA256")
    if ID_PATTERN.fullmatch(str(pins.pin_set_generation_id)) is None:
        raise ReadinessV4Error("pin_set_generation_id is invalid")
    if ID_PATTERN.fullmatch(str(pins.packet_custody_id)) is None:
        raise ReadinessV4Error("packet_custody_id is invalid")
    if COMMIT_PATTERN.fullmatch(
        str(pins.provenance_signing_tool_source_commit_sha)
    ) is None:
        raise ReadinessV4Error(
            "provenance_signing_tool_source_commit_sha is invalid"
        )
    if OCI_DIGEST_PATTERN.fullmatch(
        str(pins.provenance_signer_runtime_image_digest)
    ) is None:
        raise ReadinessV4Error(
            "provenance_signer_runtime_image_digest is invalid"
        )
    if not pins.packet_custody_path.is_absolute():
        raise ReadinessV4Error("packet custody path must be absolute")


def _validate_expected_namespaces(inputs: ReadinessInputs) -> None:
    for field in (
        "t1_runtime_source_commit_sha",
        "l3_contract_source_commit_sha",
        "outcome_contract_source_commit_assertion",
    ):
        if COMMIT_PATTERN.fullmatch(str(getattr(inputs, field))) is None:
            raise ReadinessV4Error(f"{field} is invalid")
    for field in (
        "t1_runtime_image_digest",
        "questdb_image_digest",
    ):
        if OCI_DIGEST_PATTERN.fullmatch(str(getattr(inputs, field))) is None:
            raise ReadinessV4Error(f"{field} is invalid")


def _validate_outcome_freshness_for_packet_window(
    generated_at: datetime,
    expires_at: datetime,
    outcome_issued_at: datetime,
    deployment_ended_at: datetime,
) -> None:
    if (
        not deployment_ended_at <= outcome_issued_at <= generated_at
        or expires_at - outcome_issued_at > MAX_OUTCOME_AGE
        or expires_at - deployment_ended_at > MAX_OUTCOME_AGE
    ):
        raise ReadinessV4Error(
            "deployment outcome is stale or has an invalid time relation"
        )


def _read_production_pins() -> ReadinessPins:
    pin_root_identity_before = _pin_root_identity_sha256()
    manifest_raw_before, manifest_before = (
        _read_root_owned_pin_manifest()
    )
    try:
        values = {
            field: read_root_owned_deployment_pin(path, field)
            for field, path in PIN_PATHS.items()
        }
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    custody_path = Path(values["packet_custody_path"])
    (
        custody_id,
        custody_identity_sha256,
        custody_directory_identity_sha256,
    ) = _read_packet_custody_facts(
        custody_path,
        require_root_owned_parent_chain=True,
    )
    manifest_raw_after, manifest_after = _read_root_owned_pin_manifest()
    pin_root_identity_after = _pin_root_identity_sha256()
    if (
        manifest_raw_before != manifest_raw_after
        or manifest_before != manifest_after
        or pin_root_identity_before != pin_root_identity_after
    ):
        raise ReadinessV4Error(
            "readiness-v4 pin snapshot changed while it was being read"
        )
    if any(
        str(manifest_before[field]) != values[field]
        for field in PIN_MANIFEST_VALUE_FIELDS
    ):
        raise ReadinessV4Error(
            "readiness-v4 individual pins do not match one atomic generation"
        )
    if (
        manifest_before["packet_custody_id"] != custody_id
        or not hmac.compare_digest(
            str(manifest_before["packet_custody_identity_sha256"]),
            custody_identity_sha256,
        )
        or not hmac.compare_digest(
            str(
                manifest_before[
                    "packet_custody_directory_identity_sha256"
                ]
            ),
            custody_directory_identity_sha256,
        )
    ):
        raise ReadinessV4Error(
            "readiness-v4 custody identity or directory identity does not "
            "match root-owned pins"
        )
    pins = ReadinessPins(
        pin_set_generation_id=str(manifest_before["generation_id"]),
        pin_set_manifest_sha256=_hash_bytes(
            canonical_json(manifest_before)
        ),
        pin_root_identity_sha256=pin_root_identity_before,
        provenance_keyring_sha256=values["provenance_keyring_sha256"],
        provenance_signing_tool_source_sha256=values[
            "provenance_signing_tool_source_sha256"
        ],
        provenance_signing_tool_source_commit_sha=values[
            "provenance_signing_tool_source_commit_sha"
        ],
        provenance_signer_dependency_manifest_sha256=values[
            "provenance_signer_dependency_manifest_sha256"
        ],
        provenance_signer_runtime_image_digest=values[
            "provenance_signer_runtime_image_digest"
        ],
        query_v5_authority_keyring_sha256=values[
            "query_v5_authority_keyring_sha256"
        ],
        t1_authority_keyring_sha256=values[
            "t1_authority_keyring_sha256"
        ],
        l3_authority_keyring_sha256=values[
            "l3_authority_keyring_sha256"
        ],
        outcome_keyring_sha256=values["outcome_keyring_sha256"],
        packet_custody_path=custody_path,
        packet_custody_id=custody_id,
        packet_custody_identity_sha256=custody_identity_sha256,
        packet_custody_directory_identity_sha256=(
            custody_directory_identity_sha256
        ),
        evidence_join_identity_sha256=str(
            manifest_before["evidence_join_identity_sha256"]
        ),
    )
    _validate_pins(pins)
    return pins


def _reload_and_match_active_pins(
    derived_pins: ReadinessPins,
) -> tuple[ReadinessPins, Path]:
    active_pins = _read_production_pins()
    _validate_pins(active_pins)
    try:
        derived_custody = derived_pins.packet_custody_path.resolve(
            strict=True
        )
        active_custody = active_pins.packet_custody_path.resolve(strict=True)
    except OSError as exc:
        raise ReadinessV4Error("packet custody cannot be resolved") from exc
    if derived_pins != active_pins or derived_custody != active_custody:
        raise ReadinessV4Error(
            "active readiness-v4 pins changed before protected use"
        )
    return active_pins, active_custody


def verify_active_readiness_pins(derived_pins: ReadinessPins) -> None:
    """Fail closed unless the derived pins still match active root pins."""
    _validate_pins(derived_pins)
    _reload_and_match_active_pins(derived_pins)


def _load_keyring_public_hashes(
    path: Path,
    expected_sha256: str,
    *,
    expected_schema_version: str,
    expected_purpose: str,
    label: str,
    schema_path: Path | None = None,
) -> frozenset[str]:
    _raw, keyring = _load_json(path, label, private=True)
    if schema_path is not None:
        try:
            validate_json_schema(keyring, schema_path, label)
        except OneShotError as exc:
            raise ReadinessV4Error(str(exc)) from exc
    if (
        set(keyring) != {"schema_version", "keys"}
        or keyring["schema_version"] != expected_schema_version
        or not isinstance(keyring["keys"], list)
        or not keyring["keys"]
        or not hmac.compare_digest(
            _hash_bytes(canonical_json(keyring)),
            expected_sha256,
        )
    ):
        raise ReadinessV4Error(f"{label} identity is invalid")
    hashes: set[str] = set()
    key_ids: set[str] = set()
    for entry in keyring["keys"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"key_id", "purpose", "public_key_base64"}
            or entry["purpose"] != expected_purpose
        ):
            raise ReadinessV4Error(f"{label} key entry is invalid")
        key_id = str(entry["key_id"])
        if key_id in key_ids:
            raise ReadinessV4Error(f"{label} contains duplicate key_id")
        key_ids.add(key_id)
        try:
            material = base64.b64decode(
                entry["public_key_base64"],
                validate=True,
            )
        except (TypeError, ValueError, binascii.Error) as exc:
            raise ReadinessV4Error(
                f"{label} public key is invalid"
            ) from exc
        if len(material) != 32:
            raise ReadinessV4Error(
                f"{label} public key must contain 32 bytes"
            )
        if not hmac.compare_digest(
            base64.b64encode(material).decode("ascii"),
            str(entry["public_key_base64"]),
        ):
            raise ReadinessV4Error(
                f"{label} public key encoding is not canonical"
            )
        material_hash = _hash_bytes(material)
        if material_hash in hashes:
            raise ReadinessV4Error(f"{label} duplicates public key material")
        hashes.add(material_hash)
    return frozenset(hashes)


def _validate_complete_key_domains(
    inputs: ReadinessInputs,
    pins: ReadinessPins,
    provenance_receipt: dict[str, Any],
    outcome_signer_hash: str,
) -> None:
    provenance_hashes = _load_keyring_public_hashes(
        inputs.provenance_keyring,
        pins.provenance_keyring_sha256,
        expected_schema_version=PROVENANCE_KEYRING_VERSION,
        expected_purpose=PROVENANCE_KEY_PURPOSE,
        label="query-v4 provenance-v3 keyring",
    )
    outcome_hashes = _load_keyring_public_hashes(
        inputs.outcome_keyring,
        pins.outcome_keyring_sha256,
        expected_schema_version=OUTCOME_KEYRING_VERSION,
        expected_purpose=OUTCOME_KEY_PURPOSE,
        label="readonly deployment outcome keyring",
    )
    t1_hashes = _load_keyring_public_hashes(
        inputs.t1_keyring,
        pins.t1_authority_keyring_sha256,
        expected_schema_version=T1_KEYRING_VERSION,
        expected_purpose=T1_KEY_PURPOSE,
        label="T1 authority keyring",
    )
    l3_hashes = _load_keyring_public_hashes(
        inputs.outcome_source.release_keyring,
        pins.l3_authority_keyring_sha256,
        expected_schema_version=L3_KEYRING_VERSION,
        expected_purpose=L3_KEY_PURPOSE,
        label="L3 authority keyring",
    )
    query_v5_hashes = _load_keyring_public_hashes(
        inputs.query_v5_keyring,
        pins.query_v5_authority_keyring_sha256,
        expected_schema_version=QUERY_V5_KEYRING_SCHEMA_VERSION,
        expected_purpose=QUERY_V5_KEY_PURPOSE,
        label="query-v5 authority keyring",
        schema_path=QUERY_V5_KEYRING_SCHEMA_PATH,
    )
    domains = {
        "provenance": provenance_hashes,
        "T1": t1_hashes,
        "query-v5": query_v5_hashes,
        "L3": l3_hashes,
        "outcome": outcome_hashes,
    }
    receipt_authority_hashes = frozenset(
        provenance_receipt["excluded_authority_public_key_sha256s"]
    )
    if (
        provenance_receipt["signer_public_key_sha256"]
        not in provenance_hashes
        or outcome_signer_hash not in outcome_hashes
        or receipt_authority_hashes != t1_hashes | l3_hashes
        or any(
            left_hashes & right_hashes
            for (_left_name, left_hashes), (
                _right_name,
                right_hashes,
            ) in combinations(domains.items(), 2)
        )
    ):
        raise ReadinessV4Error(
            "provenance, T1, query-v5, L3 and outcome key domains must "
            "be disjoint"
        )


def _evidence_join_identity_sha256(
    inputs: ReadinessInputs,
    content: dict[str, Any],
    provenance_receipt: dict[str, Any],
    outcome_payload: dict[str, Any],
    outcome_raw_sha256: str,
    outcome_canonical_sha256: str,
) -> str:
    return _hash_bytes(
        canonical_json(
            {
                "schema_version": (
                    "commodity_c_fast_t1_readiness_v4_evidence_join_v1"
                ),
                "candidate_id": CANDIDATE_ID,
                "t1_runtime_source_commit_sha": (
                    inputs.t1_runtime_source_commit_sha
                ),
                "t1_runtime_image_digest": (
                    inputs.t1_runtime_image_digest
                ),
                "content_attestation_canonical_sha256": _hash_bytes(
                    canonical_json(content)
                ),
                "signed_provenance_canonical_sha256": provenance_receipt[
                    "signed_provenance_canonical_sha256"
                ],
                "signed_provenance_raw_sha256": provenance_receipt[
                    "signed_provenance_raw_sha256"
                ],
                "l3_contract_source_commit_sha": (
                    inputs.l3_contract_source_commit_sha
                ),
                "outcome_contract_source_commit_assertion": (
                    inputs.outcome_contract_source_commit_assertion
                ),
                "questdb_image_digest": inputs.questdb_image_digest,
                "signed_outcome_canonical_sha256": outcome_canonical_sha256,
                "signed_outcome_raw_sha256": outcome_raw_sha256,
                "release_id": outcome_payload["release_id"],
                "attempt_id": outcome_payload["attempt_id"],
                "questdb_target_identity_sha256": outcome_payload[
                    "questdb_target_identity_sha256"
                ],
            }
        )
    )


def _packet_identity(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        field: packet[field]
        for field in (
            "generated_at",
            "expires_at",
            "verifier_sha256",
            "schema_sha256",
            "pin_root_path_sha256",
            "pin_root_identity_sha256",
            "pin_set_generation_id",
            "pin_set_manifest_sha256",
            "packet_custody_path_sha256",
            "packet_custody_id",
            "packet_custody_identity_sha256",
            "packet_custody_directory_identity_sha256",
            "evidence_join_identity_sha256",
            "source_namespaces",
            "digest_namespaces",
            "t1_runtime",
            "build_registry_provenance",
            "query_release_authority",
            "readonly_deployment_outcome",
        )
    }


def _packet_storage_bytes(packet: dict[str, Any]) -> bytes:
    rendered = json.dumps(
        packet,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    if not rendered.endswith("\n"):
        rendered += "\n"
    return rendered.encode("utf-8")


def _custody_path_hash(path: Path) -> str:
    try:
        return custody_path_sha256(path)
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc


def _validate_packet(packet: dict[str, Any]) -> None:
    try:
        validate_json_schema(packet, SCHEMA_PATH, "query-v4 readiness-v4 packet")
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if packet["status"] != STATUS or packet["blocking_reasons"] != []:
        raise ReadinessV4Error(
            "readiness-v4 status or blocker derivation is invalid"
        )
    if packet["ready_for_query_release_v5_human_signature_only"] is not True:
        raise ReadinessV4Error(
            "query-release-v5 human-signature-only fact is missing"
        )
    if any(packet[field] is not False for field in FALSE_AUTHORITY_FIELDS):
        raise ReadinessV4Error("readiness-v4 packet attempts to grant authority")
    if any(
        type(packet[field]) is not int or packet[field] != 0
        for field in ZERO_FACT_FIELDS
    ):
        raise ReadinessV4Error(
            "readiness-v4 packet contains non-zero side effects"
        )
    try:
        generated_at = parse_datetime(packet["generated_at"], "generated_at")
        expires_at = parse_datetime(packet["expires_at"], "expires_at")
        outcome_issued_at = parse_datetime(
            packet["readonly_deployment_outcome"]["outcome_issued_at"],
            "readonly_deployment_outcome.outcome_issued_at",
        )
        deployment_ended_at = parse_datetime(
            packet["readonly_deployment_outcome"]["deployment_ended_at"],
            "readonly_deployment_outcome.deployment_ended_at",
        )
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if expires_at - generated_at != PACKET_TTL:
        raise ReadinessV4Error(
            "readiness-v4 packet TTL is not exactly 15 minutes"
        )
    _validate_outcome_freshness_for_packet_window(
        generated_at,
        expires_at,
        outcome_issued_at,
        deployment_ended_at,
    )
    expected_id = "readiness-v4-" + _hash_bytes(
        canonical_json(_packet_identity(packet))
    )
    if packet["packet_id"] != expected_id:
        raise ReadinessV4Error(
            "readiness-v4 packet ID does not bind exact facts"
        )
    if (
        packet["verifier_sha256"]
        != _hash_bytes(_read(VERIFIER_PATH, "readiness-v4 verifier"))
        or packet["schema_sha256"]
        != _hash_bytes(_read(SCHEMA_PATH, "readiness-v4 schema"))
        or packet["pin_root_path_sha256"] != pin_root_path_sha256()
    ):
        raise ReadinessV4Error("readiness-v4 runtime binding is invalid")


def _verify_query_v4_content(
    inputs: ReadinessInputs,
) -> tuple[bytes, dict[str, Any], bytes, bytes, bytes]:
    content_raw, content = _load_json(
        inputs.content_attestation,
        "exact query-v4 content attestation",
    )
    external_raw = _read(
        inputs.external_image_evidence,
        "query-v4 external image evidence",
    )
    source_bundle_raw = _read(
        inputs.source_bundle_archive,
        "query-v4 source bundle archive",
        limit=MAX_SOURCE_BUNDLE_BYTES,
    )
    oci_raw = _read(
        inputs.oci_layout_archive,
        "query-v4 OCI layout archive",
        limit=MAX_OCI_BYTES,
    )
    try:
        regenerated = verify_query_v4_image_evidence(
            inputs.external_image_evidence,
            inputs.source_bundle_archive,
            inputs.oci_layout_archive,
            inputs.t1_runtime_source_commit_sha,
        )
    except QueryV4ImageAttestationError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if regenerated != content:
        raise ReadinessV4Error(
            "supplied query-v4 content attestation is not the exact "
            "regenerated report"
        )
    checks = content.get("checks")
    if (
        content.get("image_digest") != inputs.t1_runtime_image_digest
        or content.get("source_commit_sha")
        != inputs.t1_runtime_source_commit_sha
        or content.get("external_evidence_sha256")
        != _hash_bytes(external_raw)
        or content.get("source_bundle_archive_sha256")
        != _hash_bytes(source_bundle_raw)
        or content.get("oci_layout_archive_sha256") != _hash_bytes(oci_raw)
        or not isinstance(checks, dict)
        or checks.get("source_commit_assertion_bound") is not True
        or checks.get("git_binary_required") is not False
        or checks.get("git_commit_independently_resolved") is not False
        or checks.get("runtime_bundle_matches_source_bundle") is not True
    ):
        raise ReadinessV4Error(
            "query-v4 content attestation namespace or raw binding mismatch"
        )
    return content_raw, content, external_raw, source_bundle_raw, oci_raw


def derive_readiness_packet(
    inputs: ReadinessInputs,
    pins: ReadinessPins,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_pins(pins)
    verify_active_readiness_pins(pins)
    _validate_expected_namespaces(inputs)
    generated_at = _require_aware(
        datetime.now(timezone.utc) if now is None else now,
        "now",
    )
    (
        content_raw,
        content,
        external_raw,
        source_bundle_raw,
        oci_raw,
    ) = _verify_query_v4_content(inputs)

    try:
        excluded_key_hashes, excluded_keyring_hashes = (
            load_excluded_authority_key_facts(
                t1_keyring_path=inputs.t1_keyring,
                expected_t1_keyring_sha256=(
                    pins.t1_authority_keyring_sha256
                ),
                l3_keyring_path=inputs.outcome_source.release_keyring,
                expected_l3_keyring_sha256=(
                    pins.l3_authority_keyring_sha256
                ),
            )
        )
        provenance_receipt = verify_provenance(
            inputs.provenance,
            inputs.provenance_keyring,
            inputs.content_attestation,
            expected_trusted_keyring_sha256=(
                pins.provenance_keyring_sha256
            ),
            expected_runtime_source_commit_sha=(
                inputs.t1_runtime_source_commit_sha
            ),
            expected_image_digest=inputs.t1_runtime_image_digest,
            expected_signing_tool_source_sha256=(
                pins.provenance_signing_tool_source_sha256
            ),
            expected_signing_tool_source_commit_sha=(
                pins.provenance_signing_tool_source_commit_sha
            ),
            expected_signer_dependency_manifest_sha256=(
                pins.provenance_signer_dependency_manifest_sha256
            ),
            expected_signer_runtime_image_digest=(
                pins.provenance_signer_runtime_image_digest
            ),
            excluded_authority_key_hashes=excluded_key_hashes,
            excluded_authority_keyring_sha256s=excluded_keyring_hashes,
            now=generated_at,
        )
    except BuildRegistryProvenanceV3Error as exc:
        raise ReadinessV4Error(str(exc)) from exc

    content_raw_sha256 = _hash_bytes(content_raw)
    expected_receipt_bindings = {
        "content_attestation_raw_sha256": content_raw_sha256,
        "content_attestation_canonical_sha256": _hash_bytes(
            canonical_json(content)
        ),
        "runtime_source_commit_sha": inputs.t1_runtime_source_commit_sha,
        "source_bundle_archive_sha256": _hash_bytes(source_bundle_raw),
        "source_manifest_canonical_sha256": content[
            "source_manifest_canonical_sha256"
        ],
        "image_reference": content["image_reference"],
        "image_digest": inputs.t1_runtime_image_digest,
        "signing_tool_source_sha256": (
            pins.provenance_signing_tool_source_sha256
        ),
        "signing_tool_source_commit_sha": (
            pins.provenance_signing_tool_source_commit_sha
        ),
        "signer_dependency_manifest_sha256": (
            pins.provenance_signer_dependency_manifest_sha256
        ),
        "signer_runtime_image_digest": (
            pins.provenance_signer_runtime_image_digest
        ),
    }
    if any(
        provenance_receipt.get(field) != expected
        for field, expected in expected_receipt_bindings.items()
    ) or (
        provenance_receipt.get("signing_tool_source_pin_verified") is not True
        or provenance_receipt.get(
            "signing_tool_source_bytes_revalidated_at_runtime"
        )
        is not False
        or provenance_receipt.get(
            "signing_tool_execution_independently_verified"
        )
        is not False
        or provenance_receipt.get(
            "signer_dependency_manifest_pin_verified"
        )
        is not True
        or provenance_receipt.get(
            "signer_runtime_image_digest_pin_verified"
        )
        is not True
        or provenance_receipt.get(
            "signer_runtime_execution_independently_verified"
        )
        is not False
        or provenance_receipt.get("signed_build_assertion_verified")
        is not True
        or provenance_receipt.get("signed_registry_assertion_verified")
        is not True
        or provenance_receipt.get("external_facts_independently_reverified")
        is not False
    ):
        raise ReadinessV4Error(
            "provenance-v3 receipt does not bind the exact query-v4 runtime"
        )

    try:
        outcome = verify_signed_outcome(
            inputs.outcome,
            inputs.outcome_keyring,
            inputs.t1_keyring,
            inputs.outcome_source,
            inputs.post_evidence,
            expected_outcome_keyring_sha256=pins.outcome_keyring_sha256,
            expected_release_keyring_sha256=(
                pins.l3_authority_keyring_sha256
            ),
            expected_t1_keyring_sha256=pins.t1_authority_keyring_sha256,
            expected_outcome_source_commit_sha=(
                inputs.outcome_contract_source_commit_assertion
            ),
            expected_release_source_commit_sha=(
                inputs.l3_contract_source_commit_sha
            ),
            expected_questdb_image_digest=inputs.questdb_image_digest,
            now=generated_at,
        )
    except DeploymentOutcomeError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    outcome_payload = outcome.payload
    provenance_signer_hash = provenance_receipt[
        "signer_public_key_sha256"
    ]
    outcome_signer_hash = outcome.outcome_signer_public_key_sha256
    _validate_complete_key_domains(
        inputs,
        pins,
        provenance_receipt,
        outcome_signer_hash,
    )
    if (
        SHA256_PATTERN.fullmatch(str(provenance_signer_hash)) is None
        or SHA256_PATTERN.fullmatch(str(outcome_signer_hash)) is None
        or outcome_payload["questdb_image_digest"]
        != inputs.questdb_image_digest
        or outcome_payload["release_source_commit_sha"]
        != inputs.l3_contract_source_commit_sha
        or outcome_payload["outcome_contract_source_commit_assertion"]
        != inputs.outcome_contract_source_commit_assertion
    ):
        raise ReadinessV4Error(
            "deployment outcome signer or namespace mismatch"
        )
    try:
        outcome_issued_at = parse_datetime(
            outcome_payload["issued_at"],
            "outcome.issued_at",
        )
        deployment_ended_at = parse_datetime(
            outcome_payload["deployment_ended_at"],
            "outcome.deployment_ended_at",
        )
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    expires_at = generated_at + PACKET_TTL
    _validate_outcome_freshness_for_packet_window(
        generated_at,
        expires_at,
        outcome_issued_at,
        deployment_ended_at,
    )
    evidence_join_identity_sha256 = _evidence_join_identity_sha256(
        inputs,
        content,
        provenance_receipt,
        outcome_payload,
        outcome.raw_sha256,
        outcome.canonical_sha256,
    )
    if not hmac.compare_digest(
        evidence_join_identity_sha256,
        pins.evidence_join_identity_sha256,
    ):
        raise ReadinessV4Error(
            "query-v4 content/provenance and deployment outcome do not "
            "match the root-pinned evidence join identity"
        )

    source_namespaces = {
        "t1_runtime_source_commit_sha": inputs.t1_runtime_source_commit_sha,
        "provenance_signing_tool_source_commit_sha": (
            pins.provenance_signing_tool_source_commit_sha
        ),
        "l3_contract_source_commit_sha": (
            inputs.l3_contract_source_commit_sha
        ),
        "outcome_contract_source_commit_assertion": (
            inputs.outcome_contract_source_commit_assertion
        ),
    }
    digest_namespaces = {
        "t1_runtime_image_digest": inputs.t1_runtime_image_digest,
        "questdb_image_digest": inputs.questdb_image_digest,
    }
    t1_runtime = {
        "content_attestation_raw_sha256": content_raw_sha256,
        "content_attestation_canonical_sha256": _hash_bytes(
            canonical_json(content)
        ),
        "external_image_evidence_raw_sha256": _hash_bytes(external_raw),
        "source_bundle_archive_raw_sha256": _hash_bytes(source_bundle_raw),
        "source_manifest_raw_sha256": content[
            "source_manifest_raw_sha256"
        ],
        "source_manifest_canonical_sha256": content[
            "source_manifest_canonical_sha256"
        ],
        "oci_layout_archive_raw_sha256": _hash_bytes(oci_raw),
        "image_reference": content["image_reference"],
        "image_id": content["image_id"],
        "runtime_bundle_index_sha256": content[
            "runtime_bundle_index_sha256"
        ],
        "content_verifier_sha256": content["verifier_sha256"],
        "content_attestation_schema_sha256": content[
            "attestation_schema_sha256"
        ],
        "source_manifest_schema_sha256": content[
            "source_manifest_schema_sha256"
        ],
        "source_commit_assertion_bound": True,
        "git_binary_required": False,
        "source_root_required": False,
        "git_commit_independently_resolved": False,
    }
    build_registry = {
        "signed_provenance_raw_sha256": provenance_receipt[
            "signed_provenance_raw_sha256"
        ],
        "signed_provenance_canonical_sha256": provenance_receipt[
            "signed_provenance_canonical_sha256"
        ],
        "provenance_keyring_sha256": pins.provenance_keyring_sha256,
        "provenance_signing_tool_source_sha256": (
            pins.provenance_signing_tool_source_sha256
        ),
        "provenance_signing_tool_source_commit_sha": (
            pins.provenance_signing_tool_source_commit_sha
        ),
        "signer_dependency_manifest_sha256": (
            pins.provenance_signer_dependency_manifest_sha256
        ),
        "signer_runtime_image_digest": (
            pins.provenance_signer_runtime_image_digest
        ),
        "t1_authority_keyring_sha256": pins.t1_authority_keyring_sha256,
        "l3_authority_keyring_sha256": pins.l3_authority_keyring_sha256,
        "signer_key_id": provenance_receipt["signer_key_id"],
        "signer_public_key_sha256": provenance_signer_hash,
        "signing_tool_source_pin_verified": True,
        "signing_tool_source_bytes_revalidated_at_runtime": False,
        "signing_tool_execution_independently_verified": False,
        "signer_dependency_manifest_pin_verified": True,
        "signer_runtime_image_digest_pin_verified": True,
        "signer_runtime_execution_independently_verified": False,
        "signed_build_assertion_verified": True,
        "signed_registry_assertion_verified": True,
        "external_facts_independently_reverified": False,
    }
    query_release_authority = {
        "trusted_keyring_sha256": pins.query_v5_authority_keyring_sha256,
        "trusted_keyring_schema_version": QUERY_V5_KEYRING_SCHEMA_VERSION,
        "key_purpose": QUERY_V5_KEY_PURPOSE,
        "complete_key_domain_disjoint": True,
        "release_signed": False,
        "release_authority_granted": False,
    }
    deployment = {
        "signed_outcome_raw_sha256": outcome.raw_sha256,
        "signed_outcome_canonical_sha256": outcome.canonical_sha256,
        "outcome_keyring_sha256": pins.outcome_keyring_sha256,
        "signer_key_id": outcome_payload["signer_key_id"],
        "signer_public_key_sha256": outcome_signer_hash,
        "release_raw_sha256": outcome.source.release_raw_sha256,
        "release_canonical_sha256": (
            outcome.source.release_canonical_sha256
        ),
        "consume_marker_raw_sha256": outcome.source.consume_raw_sha256,
        "receipt_raw_sha256": outcome.source.receipt_raw_sha256,
        "pre_evidence_bundle_index_sha256": (
            outcome.source.pre_evidence_bundle_index_sha256
        ),
        "post_evidence_bundle_index_sha256": outcome.post.bundle_index_sha256,
        "release_id": outcome_payload["release_id"],
        "attempt_id": outcome_payload["attempt_id"],
        "questdb_target_identity_sha256": outcome_payload[
            "questdb_target_identity_sha256"
        ],
        "outcome_issued_at": outcome_payload["issued_at"],
        "deployment_ended_at": outcome_payload["deployment_ended_at"],
        "deployment_executed": True,
        "restart_count": 1,
    }
    identity = {
        "generated_at": generated_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "verifier_sha256": _hash_bytes(
            _read(VERIFIER_PATH, "readiness-v4 verifier")
        ),
        "schema_sha256": _hash_bytes(
            _read(SCHEMA_PATH, "readiness-v4 schema")
        ),
        "pin_root_path_sha256": pin_root_path_sha256(),
        "pin_root_identity_sha256": pins.pin_root_identity_sha256,
        "pin_set_generation_id": pins.pin_set_generation_id,
        "pin_set_manifest_sha256": pins.pin_set_manifest_sha256,
        "packet_custody_path_sha256": _custody_path_hash(
            pins.packet_custody_path
        ),
        "packet_custody_id": pins.packet_custody_id,
        "packet_custody_identity_sha256": (
            pins.packet_custody_identity_sha256
        ),
        "packet_custody_directory_identity_sha256": (
            pins.packet_custody_directory_identity_sha256
        ),
        "evidence_join_identity_sha256": evidence_join_identity_sha256,
        "source_namespaces": source_namespaces,
        "digest_namespaces": digest_namespaces,
        "t1_runtime": t1_runtime,
        "build_registry_provenance": build_registry,
        "query_release_authority": query_release_authority,
        "readonly_deployment_outcome": deployment,
    }
    packet_id = "readiness-v4-" + _hash_bytes(canonical_json(identity))
    packet: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "candidate_id": CANDIDATE_ID,
        "parent_issue_number": PARENT_ISSUE_NUMBER,
        "issue_number": ISSUE_NUMBER,
        "packet_id": packet_id,
        **identity,
        "requirements": {
            "requires_query_release_v5": True,
            "query_release_v4_accepted": False,
            "readiness_v3_accepted": False,
            "p0_preflight_v2_accepted_as_readiness": False,
            "raw_readiness_packet_binding_required": True,
            "human_signature_required": True,
            "one_shot_runtime_required": True,
        },
        "blocking_reasons": [],
        "ready_for_query_release_v5_human_signature_only": True,
        **{field: False for field in FALSE_AUTHORITY_FIELDS},
        **{field: 0 for field in ZERO_FACT_FIELDS},
    }
    _validate_packet(packet)
    verify_active_readiness_pins(pins)
    return packet


def _packet_binds_active_pins(
    packet: dict[str, Any],
    pins: ReadinessPins,
    custody: Path,
) -> bool:
    build = packet["build_registry_provenance"]
    deployment = packet["readonly_deployment_outcome"]
    try:
        (
            custody_id,
            custody_identity_sha256,
            custody_directory_identity_sha256,
        ) = _read_packet_custody_facts(custody)
    except ReadinessV4Error:
        return False
    return (
        packet["pin_root_identity_sha256"]
        == pins.pin_root_identity_sha256
        and packet["pin_set_generation_id"]
        == pins.pin_set_generation_id
        and packet["pin_set_manifest_sha256"]
        == pins.pin_set_manifest_sha256
        and packet["packet_custody_path_sha256"]
        == _custody_path_hash(custody)
        and packet["packet_custody_id"] == pins.packet_custody_id
        and packet["packet_custody_id"] == custody_id
        and packet["packet_custody_identity_sha256"]
        == pins.packet_custody_identity_sha256
        and packet["packet_custody_identity_sha256"]
        == custody_identity_sha256
        and packet["packet_custody_directory_identity_sha256"]
        == pins.packet_custody_directory_identity_sha256
        and packet["packet_custody_directory_identity_sha256"]
        == custody_directory_identity_sha256
        and packet["evidence_join_identity_sha256"]
        == pins.evidence_join_identity_sha256
        and build["provenance_keyring_sha256"]
        == pins.provenance_keyring_sha256
        and build["provenance_signing_tool_source_sha256"]
        == pins.provenance_signing_tool_source_sha256
        and build["provenance_signing_tool_source_commit_sha"]
        == pins.provenance_signing_tool_source_commit_sha
        and build["signer_dependency_manifest_sha256"]
        == pins.provenance_signer_dependency_manifest_sha256
        and build["signer_runtime_image_digest"]
        == pins.provenance_signer_runtime_image_digest
        and packet["query_release_authority"]["trusted_keyring_sha256"]
        == pins.query_v5_authority_keyring_sha256
        and build["t1_authority_keyring_sha256"]
        == pins.t1_authority_keyring_sha256
        and build["l3_authority_keyring_sha256"]
        == pins.l3_authority_keyring_sha256
        and deployment["outcome_keyring_sha256"]
        == pins.outcome_keyring_sha256
    )


def write_packet_create_only(
    packet: dict[str, Any],
    pins: ReadinessPins,
    output: Path,
    *,
    require_root_owned_parent: bool = True,
    now: datetime | None = None,
) -> str:
    _validate_pins(pins)
    _validate_packet(packet)
    write_time = _require_aware(
        datetime.now(timezone.utc) if now is None else now,
        "write time",
    )
    try:
        generated_at = parse_datetime(packet["generated_at"], "generated_at")
        expires_at = parse_datetime(packet["expires_at"], "expires_at")
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if not generated_at <= write_time < expires_at:
        raise ReadinessV4Error(
            "readiness-v4 packet is not current at create-only write time"
        )
    active_pins, active_custody = _reload_and_match_active_pins(pins)
    expected_name = f"{packet['packet_id']}.json"
    try:
        output_parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise ReadinessV4Error("packet custody cannot be resolved") from exc
    if not _packet_binds_active_pins(packet, active_pins, active_custody):
        raise ReadinessV4Error(
            "readiness-v4 packet does not bind active pins and custody"
        )
    if output.name != expected_name or output_parent != active_custody:
        raise ReadinessV4Error(
            "readiness-v4 output must use exact pinned custody and packet ID"
        )
    try:
        guard = open_custody_guard(
            active_custody,
            require_root_owned_parent=require_root_owned_parent,
        )
        created = False
        try:
            raw_sha256 = write_json_create_only_at(
                guard,
                expected_name,
                packet,
                SCHEMA_PATH,
                "query-v4 readiness-v4 packet",
            )
            created = True
            final_pins, final_custody = _reload_and_match_active_pins(
                active_pins
            )
            if (
                final_custody != active_custody
                or not _packet_binds_active_pins(
                    packet,
                    final_pins,
                    final_custody,
                )
            ):
                raise ReadinessV4Error(
                    "active readiness-v4 pins changed during protected write"
                )
            return raw_sha256
        except Exception:
            if created:
                try:
                    os.unlink(expected_name, dir_fd=guard.descriptor)
                    os.fsync(guard.descriptor)
                except OSError as cleanup_exc:
                    raise ReadinessV4Error(
                        "readiness-v4 protected write failed and the "
                        "new packet could not be removed"
                    ) from cleanup_exc
            raise
        finally:
            guard.close()
    except (OneShotError, FileExistsError) as exc:
        raise ReadinessV4Error(str(exc)) from exc


def verify_existing_readiness_packet(
    inputs: ReadinessInputs,
    pins: ReadinessPins,
    packet_path: Path,
    *,
    now: datetime | None = None,
    require_root_owned_parent: bool = True,
) -> VerifiedReadinessPacket:
    _validate_pins(pins)
    active_pins, active_custody = _reload_and_match_active_pins(pins)
    current_time = _require_aware(
        datetime.now(timezone.utc) if now is None else now,
        "verification time",
    )
    try:
        supplied_parent = packet_path.parent.resolve(strict=True)
    except OSError as exc:
        raise ReadinessV4Error("packet custody cannot be resolved") from exc
    if supplied_parent != active_custody:
        raise ReadinessV4Error(
            "readiness-v4 packet is outside exact pinned custody"
        )
    try:
        guard = open_custody_guard(
            active_custody,
            require_root_owned_parent=require_root_owned_parent,
        )
        try:
            raw = read_regular_file_at(
                guard,
                packet_path.name,
                "existing query-v4 readiness-v4 packet",
            )
        finally:
            guard.close()
        packet = parse_json_bytes(
            raw,
            "existing query-v4 readiness-v4 packet",
        )
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if not hmac.compare_digest(raw, _packet_storage_bytes(packet)):
        raise ReadinessV4Error(
            "existing readiness-v4 packet bytes are not the exact "
            "canonical storage encoding"
        )
    _validate_packet(packet)
    if packet_path.name != f"{packet['packet_id']}.json":
        raise ReadinessV4Error(
            "readiness-v4 packet filename does not match packet ID"
        )
    if not _packet_binds_active_pins(packet, active_pins, active_custody):
        raise ReadinessV4Error(
            "readiness-v4 packet does not match active pins and custody"
        )
    try:
        generated_at = parse_datetime(packet["generated_at"], "generated_at")
        expires_at = parse_datetime(packet["expires_at"], "expires_at")
        outcome_issued_at = parse_datetime(
            packet["readonly_deployment_outcome"]["outcome_issued_at"],
            "outcome_issued_at",
        )
        deployment_ended_at = parse_datetime(
            packet["readonly_deployment_outcome"]["deployment_ended_at"],
            "deployment_ended_at",
        )
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if not generated_at <= current_time < expires_at:
        raise ReadinessV4Error(
            "readiness-v4 packet is not currently active"
        )
    if (
        current_time - outcome_issued_at > MAX_OUTCOME_AGE
        or current_time - deployment_ended_at > MAX_OUTCOME_AGE
    ):
        raise ReadinessV4Error(
            "deployment outcome is stale at readiness-v4 consumption"
        )
    regenerated = derive_readiness_packet(
        inputs,
        active_pins,
        now=generated_at,
    )
    if regenerated != packet:
        raise ReadinessV4Error(
            "existing readiness-v4 packet is not the exact re-derived object"
        )
    final_pins, final_custody = _reload_and_match_active_pins(active_pins)
    if not _packet_binds_active_pins(
        packet,
        final_pins,
        final_custody,
    ):
        raise ReadinessV4Error(
            "readiness-v4 packet does not match final active pin snapshot"
        )
    try:
        guard = open_custody_guard(
            final_custody,
            require_root_owned_parent=require_root_owned_parent,
        )
        try:
            final_raw = read_regular_file_at(
                guard,
                packet_path.name,
                "existing query-v4 readiness-v4 packet final re-read",
            )
        finally:
            guard.close()
    except OneShotError as exc:
        raise ReadinessV4Error(str(exc)) from exc
    if not hmac.compare_digest(final_raw, raw):
        raise ReadinessV4Error(
            "existing readiness-v4 packet changed during verification"
        )
    _reload_and_match_active_pins(final_pins)
    return VerifiedReadinessPacket(
        payload=packet,
        raw_sha256=_hash_bytes(raw),
        canonical_sha256=_hash_bytes(canonical_json(packet)),
    )


def inputs_from_args(args: argparse.Namespace) -> ReadinessInputs:
    return ReadinessInputs(
        external_image_evidence=args.external_image_evidence,
        source_bundle_archive=args.source_bundle_archive,
        oci_layout_archive=args.oci_layout_archive,
        content_attestation=args.content_attestation,
        provenance=args.provenance,
        provenance_keyring=args.provenance_keyring,
        query_v5_keyring=args.query_v5_keyring,
        t1_keyring=args.t1_keyring,
        outcome=args.outcome,
        outcome_keyring=args.outcome_keyring,
        outcome_source=source_paths_from_args(args),
        post_evidence=post_paths_from_args(args),
        t1_runtime_source_commit_sha=(
            args.expected_t1_runtime_source_commit_sha
        ),
        t1_runtime_image_digest=args.expected_t1_runtime_image_digest,
        l3_contract_source_commit_sha=(
            args.expected_l3_contract_source_commit_sha
        ),
        outcome_contract_source_commit_assertion=(
            args.expected_outcome_contract_source_commit_assertion
        ),
        questdb_image_digest=args.expected_questdb_image_digest,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--source-bundle-archive", type=Path, required=True)
    parser.add_argument("--oci-layout-archive", type=Path, required=True)
    parser.add_argument("--content-attestation", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--provenance-keyring", type=Path, required=True)
    parser.add_argument("--query-v5-keyring", type=Path, required=True)
    parser.add_argument("--t1-keyring", type=Path, required=True)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--outcome-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-t1-runtime-source-commit-sha",
        required=True,
    )
    parser.add_argument("--expected-t1-runtime-image-digest", required=True)
    parser.add_argument(
        "--expected-l3-contract-source-commit-sha",
        required=True,
    )
    parser.add_argument(
        "--expected-outcome-contract-source-commit-assertion",
        required=True,
    )
    parser.add_argument("--expected-questdb-image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    add_source_arguments(parser)
    add_post_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pins = _read_production_pins()
        verify_active_readiness_pins(pins)
        packet = derive_readiness_packet(inputs_from_args(args), pins)
        raw_sha256 = write_packet_create_only(packet, pins, args.output)
    except (ReadinessV4Error, OSError, ValueError) as exc:
        print(f"query-v4 readiness-v4 derivation failed: {exc}", file=sys.stderr)
        return 2
    print(f"status={packet['status']}")
    print(f"packet_id={packet['packet_id']}")
    print(f"packet_raw_sha256={raw_sha256}")
    print("authority_granted=false")
    print("production_query_authorized=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
