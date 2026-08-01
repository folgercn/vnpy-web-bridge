#!/usr/bin/env python3
"""Offline verifier for the query-v6 signed authority foundation.

The foundation freezes every query-v5 runtime blocker, but deliberately grants
no query authority.  This module has no DSN input, consume operation, network
client, or child-launch capability.  A later runtime contract must reverify the
same bindings before it can define any irreversible lifecycle transition.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping
from zoneinfo import ZoneInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import commodity_c_fast_t1_query_v5_release as query_v5
import commodity_c_fast_t1_readiness_v4 as readiness_v4
from commodity_c_fast_readonly_deployment_outcome import (
    DeploymentOutcomeError,
    OutcomeSourcePaths,
    PostEvidencePaths,
    verify_signed_outcome,
)
from commodity_c_fast_readonly_deployment_release import (
    DeploymentEvidencePaths,
)
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
SIGNER_PATH = VERIFIER_PATH.with_name("commodity_c_fast_t1_query_v6_sign.py")
RELEASE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-one-shot-query-release-v6.schema.json"
)
KEYRING_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v6-trusted-keys-v1.schema.json"
)
DSN_IDENTITY_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-query-v6-dsn-file-identity-v1.schema.json"
)
READINESS_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-readiness-v4.schema.json"
)
L3_OUTCOME_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-readonly-deployment-outcome-v1.schema.json"
)
QUERY_MANIFEST_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json"
)
RUNTIME_PIN_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v5-runtime-pin-set-v1.schema.json"
)
RUNTIME_RUNNER_PATH = ROOT / "scripts/commodity_c_fast_t1_query_v5_runtime.py"
QUERY_CHILD_PATH = ROOT / "scripts/commodity_c_fast_t1_query_child_v4.py"
AUDIT_SCRIPT_PATH = ROOT / "scripts/commodity_c_fast_l1_l5_audit_v4.py"
CONSUME_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-consume-v5.schema.json"
)
CHILD_STARTED_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-child-started-v5.schema.json"
)
TERMINAL_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-terminal-v5.schema.json"
)
READONLY_PROOF_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
)

RELEASE_VERSION = "commodity_c_fast_t1_one_shot_query_release_v6"
RELEASE_PURPOSE = "c_fast_t1_query_v6_signed_authority_foundation_no_query"
KEYRING_VERSION = "commodity_c_fast_t1_query_v6_trusted_keys_v1"
KEY_PURPOSE = "t1_query_v6_authority_foundation_signer"
DSN_IDENTITY_VERSION = "commodity_c_fast_t1_query_v6_dsn_file_identity_v1"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
AUTHORITY_STATE = "FOUNDATION_ONLY_NO_QUERY_AUTHORITY"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_RELEASE_TTL = timedelta(minutes=10)
EXPECTED_PRODUCTS = frozenset({"ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn"})
REQUIRED_SESSION_WINDOWS = (
    "night_open",
    "night_session",
    "day_open",
    "day_session",
)
CHINA_TZ = ZoneInfo("Asia/Shanghai")
CANONICAL_SESSION_CLOCKS = {
    "night_open": ("21:00:00", "21:02:05", "night"),
    "night_session": ("21:10:00", "21:20:00", "night"),
    "day_open": ("09:00:00", "09:02:05", "day"),
    "day_session": ("09:10:00", "09:20:00", "day"),
}
ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

FALSE_AUTHORITY_FIELDS = (
    "foundation_is_authority",
    "authority_granted",
    "readiness_authorized",
    "release_consumption_authorized",
    "t1_one_shot_child_launch_authorized",
    "network_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "production_query_authorized",
    "readonly_query_authorized",
    "local_query_evidence_write_authorized",
    "write_probe_authorized",
    "database_mutation_authorized",
    "deployment_mutation_authorized",
    "readonly_principal_deployment_authorized",
    "readonly_secret_file_installation_authorized",
    "questdb_restart_authorized",
    "questdb_recreate_authorized",
    "questdb_image_change_authorized",
    "network_mutation_authorized",
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
)
FALSE_FACT_FIELDS = (
    "release_consumed",
    "custody_opened",
    "dsn_metadata_read",
    "dsn_secret_read",
    "query_child_started",
    "network_attempted",
    "production_query_attempted",
    "production_query_completed",
    "dispatch_changed",
)
ZERO_FACT_FIELDS = (
    "queries_executed",
    "database_mutations",
    "web_bridge_rpc_calls",
    "orders_sent",
    "positions_modified",
)


class QueryV6AuthorityError(RuntimeError):
    """Expected fail-closed query-v6 authority validation error."""


@dataclass(frozen=True)
class JsonArtifact:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str


@dataclass(frozen=True)
class AuthorityEvidence:
    readiness: JsonArtifact
    l3_outcome: JsonArtifact
    query_manifest: JsonArtifact
    runtime_pin_manifest: JsonArtifact
    dsn_identity_attestation: JsonArtifact
    verified_domain_public_key_hashes: frozenset[str] = frozenset()


@dataclass(frozen=True)
class VerifiedAuthorityFoundation:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    signer_public_key_sha256: str
    evidence: AuthorityEvidence
    provenance: query_v5.VerifiedProvenance


@dataclass(frozen=True)
class OfflineVerificationPaths:
    release_path: Path
    release_keyring_path: Path
    provenance_path: Path
    provenance_keyring_path: Path
    composition_path: Path
    final_oci_layout_path: Path
    composition_replay: query_v5.CompositionReplayInputs
    readiness_path: Path
    l3_outcome_path: Path
    query_manifest_path: Path
    runtime_pin_manifest_path: Path
    dsn_identity_attestation_path: Path
    expected_release_keyring_sha256: str
    expected_provenance_keyring_sha256: str
    expected_source_commit_sha: str
    expected_image_digest: str
    readiness_inputs: readiness_v4.ReadinessInputs


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unsigned_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def release_attempt_id(release_id: str) -> str:
    if ID_RE.fullmatch(release_id) is None:
        raise QueryV6AuthorityError("release_id is invalid")
    return f"attempt-{sha256_bytes(release_id.encode('utf-8'))}"


def _contains_pending(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("PENDING_")
    if isinstance(value, list):
        return any(_contains_pending(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_pending(item) for item in value.values())
    return False


def _same(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise QueryV6AuthorityError(f"{label} binding mismatch")


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise QueryV6AuthorityError(f"{label} must include an explicit timezone")
    return value.astimezone(timezone.utc)


def _read_bytes(path: Path, label: str, *, private: bool = False) -> bytes:
    try:
        return read_regular_file_strict(
            path,
            label,
            private=private,
            limit=MAX_JSON_BYTES,
        )
    except OneShotError as exc:
        raise QueryV6AuthorityError(str(exc)) from exc


def _schema_sha256(path: Path, label: str) -> str:
    return sha256_bytes(_read_bytes(path, label))


def _source_sha256(path: Path, label: str) -> str:
    return sha256_bytes(_read_bytes(path, label))


def _load_json_artifact(
    path: Path,
    schema_path: Path,
    label: str,
    *,
    private: bool = False,
) -> JsonArtifact:
    raw = _read_bytes(path, label, private=private)
    try:
        payload = parse_json_bytes(raw, label)
        validate_json_schema(payload, schema_path, label)
    except OneShotError as exc:
        raise QueryV6AuthorityError(str(exc)) from exc
    if _contains_pending(payload):
        raise QueryV6AuthorityError(f"{label} contains PENDING_ placeholders")
    return JsonArtifact(
        payload=payload,
        raw_sha256=sha256_bytes(raw),
        canonical_sha256=sha256_bytes(canonical_json(payload)),
    )


def _validate_query_manifest(manifest: dict[str, Any]) -> None:
    targets = manifest["targets"]
    products = [str(target["product"]) for target in targets]
    if len(products) != 10 or set(products) != EXPECTED_PRODUCTS:
        raise QueryV6AuthorityError(
            "query manifest must contain each frozen product exactly once"
        )
    contracts: dict[str, set[str]] = {}
    all_contracts: set[str] = set()
    for target in targets:
        product = str(target["product"])
        current = str(target["exact_contract"])
        previous = target["previous_exact_contract"]
        allowed = {current}
        if target["roll_expected"]:
            if not isinstance(previous, str) or previous == current:
                raise QueryV6AuthorityError(
                    "roll target requires a distinct previous exact contract"
                )
            allowed.add(previous)
        elif previous is not None:
            raise QueryV6AuthorityError(
                "non-roll target must not carry a previous exact contract"
            )
        if all_contracts & allowed:
            raise QueryV6AuthorityError("query manifest exact contracts are duplicated")
        all_contracts.update(allowed)
        contracts[product] = allowed
    seen: set[tuple[str, str]] = set()
    for window in manifest["execution_windows"]:
        pair = (str(window["product"]), str(window["exact_contract"]))
        if pair[0] not in contracts or pair[1] not in contracts[pair[0]]:
            raise QueryV6AuthorityError(
                "execution window is outside the frozen exact-contract set"
            )
        seen.add(pair)
    required = {(product, contract) for product, values in contracts.items() for contract in values}
    if not required.issubset(seen):
        raise QueryV6AuthorityError(
            "query manifest lacks an execution window for a frozen contract"
        )
    try:
        start = parse_datetime(manifest["audit_window"]["start"], "audit start")
        end = parse_datetime(
            manifest["audit_window"]["end_exclusive"], "audit end"
        )
        trading_day = datetime.strptime(
            str(manifest["audit_window"]["trading_day"]), "%Y%m%d"
        ).date()
        times = [
            parse_datetime(window["execution_time"], "execution time")
            for window in manifest["execution_windows"]
        ]
        sessions = []
        for name in REQUIRED_SESSION_WINDOWS:
            raw = manifest["session_windows"][name]
            session_start = parse_datetime(
                raw["start"], f"session_windows.{name}.start"
            )
            session_end = parse_datetime(
                raw["end_exclusive"],
                f"session_windows.{name}.end_exclusive",
            )
            if not session_start < session_end:
                raise QueryV6AuthorityError(
                    f"session window {name} end must be later than start"
                )
            if session_start < start or session_end > end:
                raise QueryV6AuthorityError(
                    f"session window {name} is outside signed audit window"
                )
            sessions.append((name, session_start, session_end))
    except (OneShotError, ValueError) as exc:
        raise QueryV6AuthorityError(str(exc)) from exc
    if not start < end or any(not start <= value < end for value in times):
        raise QueryV6AuthorityError("query manifest time window is invalid")
    ordered_sessions = sorted(sessions, key=lambda item: item[1])
    for previous, current in zip(ordered_sessions, ordered_sessions[1:]):
        if current[1] < previous[2]:
            raise QueryV6AuthorityError(
                f"session windows overlap: {previous[0]}/{current[0]}"
            )
    for name, session_start, session_end in sessions:
        start_clock, end_clock, day_role = CANONICAL_SESSION_CLOCKS[name]
        local_start = session_start.astimezone(CHINA_TZ)
        local_end = session_end.astimezone(CHINA_TZ)
        if (
            local_start.strftime("%H:%M:%S") != start_clock
            or local_end.strftime("%H:%M:%S") != end_clock
            or local_start.date() != local_end.date()
        ):
            raise QueryV6AuthorityError(
                f"session window {name} is not the canonical China-time window"
            )
        if day_role == "day" and local_start.date() != trading_day:
            raise QueryV6AuthorityError(
                f"session window {name} must fall on signed trading_day"
            )
        if day_role == "night":
            days_before = (trading_day - local_start.date()).days
            if days_before < 1 or days_before > 3:
                raise QueryV6AuthorityError(
                    f"session window {name} must precede signed trading_day"
                )


def dsn_identity_sha256(payload: Mapping[str, Any]) -> str:
    core_fields = (
        "schema_version",
        "attestation_id",
        "observed_at",
        "dsn_file_absolute_path_sha256",
        "device",
        "inode",
        "owner_uid",
        "owner_gid",
        "mode",
        "link_count",
        "size_bytes",
        "expected_readonly_principal_sha256",
        "expected_endpoint_identity_sha256",
    )
    return sha256_bytes(canonical_json({field: payload[field] for field in core_fields}))


def _validate_dsn_identity(payload: dict[str, Any]) -> None:
    if payload["schema_version"] != DSN_IDENTITY_VERSION:
        raise QueryV6AuthorityError("DSN identity generation is invalid")
    _same(
        str(payload["dsn_file_identity_sha256"]),
        dsn_identity_sha256(payload),
        "DSN file identity",
    )
    for field in (
        "dsn_secret_included",
        "dsn_content_hash_included",
        "dsn_secret_read",
        "network_accessed",
        "authority_granted",
    ):
        if payload[field] is not False:
            raise QueryV6AuthorityError(f"forbidden DSN attestation fact: {field}")


def _readiness_runtime_identity_candidate(
    readiness_path: Path,
) -> readiness_v4.ReadinessRuntimeIdentity:
    candidate = _load_json_artifact(
        readiness_path,
        READINESS_SCHEMA_PATH,
        "readiness-v4 runtime identity candidate",
    ).payload["readiness_runtime"]
    values = {
        field: candidate[field]
        for field in readiness_v4.ReadinessRuntimeIdentity.__dataclass_fields__
    }
    try:
        return readiness_v4.ReadinessRuntimeIdentity(**values)
    except (KeyError, TypeError, ValueError) as exc:
        raise QueryV6AuthorityError(
            "readiness-v4 runtime identity candidate is invalid"
        ) from exc


def _verified_readiness_key_materials(
    inputs: readiness_v4.ReadinessInputs,
    pins: readiness_v4.ReadinessPins,
) -> frozenset[str]:
    specs = (
        (
            inputs.provenance_keyring,
            pins.provenance_keyring_sha256,
            readiness_v4.PROVENANCE_KEYRING_VERSION,
            readiness_v4.PROVENANCE_KEY_PURPOSE,
            "readiness-v4 provenance keyring",
            None,
        ),
        (
            inputs.query_v5_keyring,
            pins.query_v5_authority_keyring_sha256,
            readiness_v4.QUERY_V5_KEYRING_SCHEMA_VERSION,
            readiness_v4.QUERY_V5_KEY_PURPOSE,
            "readiness-v4 query-v5 keyring",
            readiness_v4.QUERY_V5_KEYRING_SCHEMA_PATH,
        ),
        (
            inputs.t1_keyring,
            pins.t1_authority_keyring_sha256,
            readiness_v4.T1_KEYRING_VERSION,
            readiness_v4.T1_KEY_PURPOSE,
            "readiness-v4 T1 keyring",
            None,
        ),
        (
            inputs.outcome_source.release_keyring,
            pins.l3_authority_keyring_sha256,
            readiness_v4.L3_KEYRING_VERSION,
            readiness_v4.L3_KEY_PURPOSE,
            "readiness-v4 L3 keyring",
            None,
        ),
        (
            inputs.outcome_keyring,
            pins.outcome_keyring_sha256,
            readiness_v4.OUTCOME_KEYRING_VERSION,
            readiness_v4.OUTCOME_KEY_PURPOSE,
            "readiness-v4 outcome keyring",
            None,
        ),
    )
    materials: set[str] = set()
    for path, expected, version, purpose, label, schema_path in specs:
        materials.update(
            readiness_v4._load_keyring_public_hashes(
                path,
                expected,
                expected_schema_version=version,
                expected_purpose=purpose,
                label=label,
                schema_path=schema_path,
            )
        )
    return frozenset(materials)


def load_authority_evidence(
    readiness_path: Path,
    l3_outcome_path: Path,
    query_manifest_path: Path,
    runtime_pin_manifest_path: Path,
    dsn_identity_attestation_path: Path,
    *,
    readiness_inputs: readiness_v4.ReadinessInputs,
    now: datetime,
    require_root_owned_parent: bool = True,
) -> AuthorityEvidence:
    try:
        if (
            readiness_inputs.outcome.resolve(strict=True)
            != l3_outcome_path.resolve(strict=True)
        ):
            raise QueryV6AuthorityError(
                "readiness-v4 and query-v6 L3 outcome paths differ"
            )
        pins = readiness_v4._read_production_pins()
        verified_readiness = readiness_v4.verify_existing_readiness_packet(
            readiness_inputs,
            pins,
            _readiness_runtime_identity_candidate(readiness_path),
            readiness_path,
            now=now,
            require_root_owned_parent=require_root_owned_parent,
        )
        verified_l3 = verify_signed_outcome(
            l3_outcome_path,
            readiness_inputs.outcome_keyring,
            readiness_inputs.t1_keyring,
            readiness_inputs.outcome_source,
            readiness_inputs.post_evidence,
            expected_outcome_keyring_sha256=pins.outcome_keyring_sha256,
            expected_release_keyring_sha256=pins.l3_authority_keyring_sha256,
            expected_t1_keyring_sha256=pins.t1_authority_keyring_sha256,
            expected_outcome_source_commit_sha=(
                readiness_inputs.outcome_contract_source_commit_assertion
            ),
            expected_release_source_commit_sha=(
                readiness_inputs.l3_contract_source_commit_sha
            ),
            expected_questdb_image_digest=(
                readiness_inputs.questdb_image_digest
            ),
            now=now,
        )
        verified_key_materials = _verified_readiness_key_materials(
            readiness_inputs,
            pins,
        )
        readiness_v4.verify_active_readiness_pins(pins)
    except (
        OSError,
        DeploymentOutcomeError,
        readiness_v4.ReadinessV4Error,
        ValueError,
    ) as exc:
        raise QueryV6AuthorityError(
            f"readiness-v4/L3 full replay failed: {exc}"
        ) from exc
    evidence = AuthorityEvidence(
        readiness=JsonArtifact(
            payload=verified_readiness.payload,
            raw_sha256=verified_readiness.raw_sha256,
            canonical_sha256=verified_readiness.canonical_sha256,
        ),
        l3_outcome=JsonArtifact(
            payload=verified_l3.payload,
            raw_sha256=verified_l3.raw_sha256,
            canonical_sha256=verified_l3.canonical_sha256,
        ),
        query_manifest=_load_json_artifact(
            query_manifest_path, QUERY_MANIFEST_SCHEMA_PATH, "query manifest"
        ),
        runtime_pin_manifest=_load_json_artifact(
            runtime_pin_manifest_path,
            RUNTIME_PIN_SCHEMA_PATH,
            "query-v5 runtime pin manifest",
            private=True,
        ),
        dsn_identity_attestation=_load_json_artifact(
            dsn_identity_attestation_path,
            DSN_IDENTITY_SCHEMA_PATH,
            "secret-free DSN identity attestation",
            private=True,
        ),
        verified_domain_public_key_hashes=verified_key_materials,
    )
    readiness = evidence.readiness.payload
    for field, value in readiness.items():
        if (
            (field.endswith("_authorized") or field.endswith("_is_authority"))
            and value is not False
        ):
            raise QueryV6AuthorityError(
                f"readiness-v4 authority floor violated: {field}"
            )
    for field in (
        "production_queries_executed",
        "readonly_queries_executed",
        "write_probes_attempted",
        "database_mutations",
        "web_bridge_rpc_calls",
        "orders_sent",
        "positions_modified",
    ):
        if type(readiness[field]) is not int or readiness[field] != 0:
            raise QueryV6AuthorityError(f"readiness-v4 fact is non-zero: {field}")
    if readiness["authority_granted"] is not False:
        raise QueryV6AuthorityError("readiness-v4 granted authority")
    _validate_query_manifest(evidence.query_manifest.payload)
    _validate_dsn_identity(evidence.dsn_identity_attestation.payload)
    runtime_pin = evidence.runtime_pin_manifest.payload
    if runtime_pin["code_only_blocked"] is not True or runtime_pin["authority_granted"] is not False:
        raise QueryV6AuthorityError("runtime pin manifest is not code-only blocked")
    l3 = evidence.l3_outcome
    outcome_binding = readiness["readonly_deployment_outcome"]
    _same(
        str(outcome_binding["signed_outcome_raw_sha256"]),
        l3.raw_sha256,
        "readiness/L3 raw",
    )
    _same(
        str(outcome_binding["signed_outcome_canonical_sha256"]),
        l3.canonical_sha256,
        "readiness/L3 canonical",
    )
    return evidence


def _absolute_custody_path(value: str) -> str:
    candidate = PurePosixPath(value)
    if (
        not candidate.is_absolute()
        or value != str(candidate)
        or ".." in candidate.parts
        or value == "/"
    ):
        raise QueryV6AuthorityError("custody_absolute_path is not normalized absolute")
    return value


def expected_runtime_bindings(
    provenance: query_v5.VerifiedProvenance,
    evidence: AuthorityEvidence,
    *,
    custody_absolute_path: str,
) -> dict[str, Any]:
    custody_path = _absolute_custody_path(custody_absolute_path)
    readiness = evidence.readiness.payload
    runtime_pin = evidence.runtime_pin_manifest.payload
    dsn = evidence.dsn_identity_attestation.payload
    l3 = evidence.l3_outcome.payload
    bindings: dict[str, Any] = {
        "provenance_raw_sha256": provenance.raw_sha256,
        "provenance_canonical_sha256": provenance.canonical_sha256,
        "provenance_signer_public_key_sha256": provenance.signer_public_key_sha256,
        "composition_attestation_raw_sha256": provenance.composition_raw_sha256,
        "composition_attestation_canonical_sha256": provenance.composition_canonical_sha256,
        "runtime_source_commit_sha": provenance.payload["runtime_source_commit_sha"],
        "runtime_image_reference": provenance.payload["image_reference"],
        "runtime_image_digest": provenance.payload["image_digest"],
        "runtime_image_id": provenance.payload["image_id"],
        "readiness_v4_raw_sha256": evidence.readiness.raw_sha256,
        "readiness_v4_canonical_sha256": evidence.readiness.canonical_sha256,
        "l3_outcome_raw_sha256": evidence.l3_outcome.raw_sha256,
        "l3_outcome_canonical_sha256": evidence.l3_outcome.canonical_sha256,
        "query_manifest_raw_sha256": evidence.query_manifest.raw_sha256,
        "query_manifest_canonical_sha256": evidence.query_manifest.canonical_sha256,
        "runtime_pin_generation_id": runtime_pin["generation_id"],
        "runtime_pin_manifest_sha256": evidence.runtime_pin_manifest.raw_sha256,
        "runtime_identity_sha256": evidence.runtime_pin_manifest.canonical_sha256,
        "custody_absolute_path": custody_path,
        "custody_path_sha256": sha256_bytes(custody_path.encode("utf-8")),
        "custody_id": readiness["packet_custody_id"],
        "custody_identity_sha256": readiness["packet_custody_identity_sha256"],
        "custody_directory_identity_sha256": readiness[
            "packet_custody_directory_identity_sha256"
        ],
        "dsn_file_identity_attestation_raw_sha256": (
            evidence.dsn_identity_attestation.raw_sha256
        ),
        "dsn_file_identity_attestation_canonical_sha256": (
            evidence.dsn_identity_attestation.canonical_sha256
        ),
        "dsn_file_identity_sha256": dsn["dsn_file_identity_sha256"],
        "expected_readonly_principal_sha256": dsn[
            "expected_readonly_principal_sha256"
        ],
        "expected_endpoint_identity_sha256": dsn[
            "expected_endpoint_identity_sha256"
        ],
        "provenance_keyring_sha256": provenance.payload["trusted_keyring_sha256"],
    }
    schema_paths = {
        "release_schema_sha256": RELEASE_SCHEMA_PATH,
        "trusted_keyring_schema_sha256": KEYRING_SCHEMA_PATH,
        "provenance_schema_sha256": query_v5.PROVENANCE_SCHEMA_PATH,
        "composition_attestation_schema_sha256": query_v5.COMPOSITION_SCHEMA_PATH,
        "readiness_v4_schema_sha256": READINESS_SCHEMA_PATH,
        "l3_outcome_schema_sha256": L3_OUTCOME_SCHEMA_PATH,
        "query_manifest_schema_sha256": QUERY_MANIFEST_SCHEMA_PATH,
        "runtime_pin_schema_sha256": RUNTIME_PIN_SCHEMA_PATH,
        "dsn_file_identity_attestation_schema_sha256": DSN_IDENTITY_SCHEMA_PATH,
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "child_started_schema_sha256": CHILD_STARTED_SCHEMA_PATH,
        "terminal_schema_sha256": TERMINAL_SCHEMA_PATH,
        "readonly_proof_schema_sha256": READONLY_PROOF_SCHEMA_PATH,
    }
    source_paths = {
        "offline_verifier_sha256": VERIFIER_PATH,
        "signer_source_sha256": SIGNER_PATH,
        "runtime_runner_sha256": RUNTIME_RUNNER_PATH,
        "query_child_sha256": QUERY_CHILD_PATH,
        "audit_script_sha256": AUDIT_SCRIPT_PATH,
    }
    bindings.update(
        {field: _schema_sha256(path, field) for field, path in schema_paths.items()}
    )
    bindings.update(
        {field: _source_sha256(path, field) for field, path in source_paths.items()}
    )
    _same(
        str(readiness["packet_custody_path_sha256"]),
        str(bindings["custody_path_sha256"]),
        "readiness/custody path",
    )
    _same(
        str(l3["questdb_target_identity_sha256"]),
        str(bindings["expected_endpoint_identity_sha256"]),
        "L3/expected endpoint",
    )
    _same(
        str(runtime_pin["runtime_image_digest"]),
        str(bindings["runtime_image_digest"]),
        "runtime pin/final image",
    )
    return bindings


def _validate_keyring(
    keyring: dict[str, Any], signer_key_id: str
) -> tuple[Ed25519PublicKey, str, frozenset[str]]:
    try:
        validate_json_schema(keyring, KEYRING_SCHEMA_PATH, "query-v6 keyring")
    except OneShotError as exc:
        raise QueryV6AuthorityError(str(exc)) from exc
    if keyring.get("schema_version") != KEYRING_VERSION:
        raise QueryV6AuthorityError("query-v6 keyring generation is invalid")
    matched: Ed25519PublicKey | None = None
    matched_hash = ""
    key_ids: set[str] = set()
    materials: set[str] = set()
    for entry in keyring["keys"]:
        key_id = str(entry["key_id"])
        if key_id in key_ids:
            raise QueryV6AuthorityError("query-v6 key_id is duplicated")
        key_ids.add(key_id)
        try:
            raw = base64.b64decode(entry["public_key_base64"], validate=True)
            if len(raw) != 32:
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(raw)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise QueryV6AuthorityError("query-v6 trusted key is invalid") from exc
        material_hash = sha256_bytes(raw)
        if material_hash in materials:
            raise QueryV6AuthorityError("query-v6 trusted key material is duplicated")
        materials.add(material_hash)
        if key_id == signer_key_id:
            matched = public_key
            matched_hash = material_hash
    if matched is None:
        raise QueryV6AuthorityError("query-v6 signer_key_id is not trusted")
    return matched, matched_hash, frozenset(materials)


def known_domain_public_key_hashes(
    provenance: query_v5.VerifiedProvenance,
    evidence: AuthorityEvidence,
) -> frozenset[str]:
    """Return only independently verified signer-domain key materials."""

    return frozenset(
        {provenance.signer_public_key_sha256}
        | set(evidence.verified_domain_public_key_hashes)
    )


def validate_release_semantics(
    payload: dict[str, Any],
    provenance: query_v5.VerifiedProvenance,
    evidence: AuthorityEvidence,
    *,
    now: datetime,
) -> None:
    try:
        validate_json_schema(payload, RELEASE_SCHEMA_PATH, "query-v6 foundation")
    except OneShotError as exc:
        raise QueryV6AuthorityError(str(exc)) from exc
    if _contains_pending(payload):
        raise QueryV6AuthorityError("query-v6 foundation contains PENDING_ placeholders")
    if (
        payload["schema_version"] != RELEASE_VERSION
        or payload["purpose"] != RELEASE_PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
        or payload["authority_state"] != AUTHORITY_STATE
    ):
        raise QueryV6AuthorityError("query-v6 foundation identity is invalid")
    if payload["attempt_id"] != release_attempt_id(payload["release_id"]):
        raise QueryV6AuthorityError("attempt_id does not match release_id")
    if not str(payload["human_signature"]).strip() or str(
        payload["human_signature"]
    ).startswith("PENDING_"):
        raise QueryV6AuthorityError("human_signature is not final")
    if not str(payload["reviewer_role"]).strip():
        raise QueryV6AuthorityError("reviewer_role is empty")
    expected = expected_runtime_bindings(
        provenance,
        evidence,
        custody_absolute_path=str(payload["custody_absolute_path"]),
    )
    for field, value in expected.items():
        if payload[field] != value:
            raise QueryV6AuthorityError(f"{field} binding mismatch")
    for field in FALSE_AUTHORITY_FIELDS + FALSE_FACT_FIELDS:
        if payload[field] is not False:
            raise QueryV6AuthorityError(f"forbidden query-v6 authority/fact: {field}")
    for field in ZERO_FACT_FIELDS:
        if type(payload[field]) is not int or payload[field] != 0:
            raise QueryV6AuthorityError(f"non-zero query-v6 fact: {field}")
    if (
        payload["offline_verification_only"] is not True
        or payload["one_shot"] is not True
        or payload["maximum_uses"] != 1
        or payload["replay_allowed"] is not False
        or payload["maximum_release_ttl_seconds"] != 600
        or payload["connect_timeout_seconds"] != 10
        or payload["statement_timeout_ms"] != 60_000
        or payload["maximum_runtime_seconds"] != 600
    ):
        raise QueryV6AuthorityError("query-v6 fixed safety policy is invalid")
    current = _utc(now, "verification time")
    try:
        issued = parse_datetime(payload["issued_at"], "issued_at")
        not_before = parse_datetime(payload["not_before"], "not_before")
        expires = parse_datetime(payload["expires_at"], "expires_at")
        readiness_generated = parse_datetime(
            evidence.readiness.payload["generated_at"], "readiness.generated_at"
        )
        readiness_expires = parse_datetime(
            evidence.readiness.payload["expires_at"], "readiness.expires_at"
        )
        provenance_issued = parse_datetime(
            provenance.payload["issued_at"], "provenance.issued_at"
        )
    except OneShotError as exc:
        raise QueryV6AuthorityError(str(exc)) from exc
    if not issued <= not_before <= current < expires:
        raise QueryV6AuthorityError("query-v6 release time window is inactive")
    if issued < max(readiness_generated, provenance_issued):
        raise QueryV6AuthorityError("query-v6 release predates bound evidence")
    if expires > readiness_expires:
        raise QueryV6AuthorityError("query-v6 release outlives readiness-v4")
    if expires - issued > MAX_RELEASE_TTL:
        raise QueryV6AuthorityError("query-v6 release TTL exceeds ten minutes")
    if current + timedelta(seconds=payload["minimum_verification_margin_seconds"]) >= expires:
        raise QueryV6AuthorityError("query-v6 verification margin is exhausted")


def verify_release(
    release_path: Path,
    release_keyring_path: Path,
    provenance: query_v5.VerifiedProvenance,
    provenance_key_materials: frozenset[str],
    evidence: AuthorityEvidence,
    *,
    expected_release_keyring_sha256: str,
    now: datetime,
) -> VerifiedAuthorityFoundation:
    release_raw = _read_bytes(release_path, "signed query-v6 foundation", private=True)
    try:
        payload = parse_json_bytes(release_raw, "signed query-v6 foundation")
    except OneShotError as exc:
        raise QueryV6AuthorityError(str(exc)) from exc
    keyring_raw = _read_bytes(release_keyring_path, "query-v6 keyring", private=True)
    try:
        keyring = parse_json_bytes(keyring_raw, "query-v6 keyring")
    except OneShotError as exc:
        raise QueryV6AuthorityError(str(exc)) from exc
    keyring_hash = sha256_bytes(canonical_json(keyring))
    _same(keyring_hash, expected_release_keyring_sha256, "pinned query-v6 keyring")
    _same(keyring_hash, str(payload.get("trusted_keyring_sha256") or ""), "signed query-v6 keyring")
    public_key, signer_hash, release_materials = _validate_keyring(
        keyring, str(payload.get("signer_key_id") or "")
    )
    if (
        provenance_key_materials & release_materials
        or known_domain_public_key_hashes(provenance, evidence) & release_materials
    ):
        raise QueryV6AuthorityError("provenance and query-v6 key domains overlap")
    try:
        signature = base64.b64decode(payload["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError
        public_key.verify(signature, canonical_json(unsigned_payload(payload)))
    except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise QueryV6AuthorityError("query-v6 signature is invalid") from exc
    validate_release_semantics(payload, provenance, evidence, now=now)
    return VerifiedAuthorityFoundation(
        payload=payload,
        raw_sha256=sha256_bytes(release_raw),
        canonical_sha256=sha256_bytes(canonical_json(payload)),
        signer_public_key_sha256=signer_hash,
        evidence=evidence,
        provenance=provenance,
    )


def verify_offline_foundation(
    paths: OfflineVerificationPaths,
    *,
    now: datetime,
) -> VerifiedAuthorityFoundation:
    try:
        provenance, provenance_materials = query_v5.verify_provenance(
            paths.provenance_path,
            paths.provenance_keyring_path,
            paths.composition_path,
            paths.final_oci_layout_path,
            paths.composition_replay,
            expected_provenance_keyring_sha256=paths.expected_provenance_keyring_sha256,
            expected_source_commit_sha=paths.expected_source_commit_sha,
            expected_image_digest=paths.expected_image_digest,
            now=now,
        )
    except query_v5.QueryV5ReleaseError as exc:
        raise QueryV6AuthorityError(f"query-v5 provenance closure failed: {exc}") from exc
    evidence = load_authority_evidence(
        paths.readiness_path,
        paths.l3_outcome_path,
        paths.query_manifest_path,
        paths.runtime_pin_manifest_path,
        paths.dsn_identity_attestation_path,
        readiness_inputs=paths.readiness_inputs,
        now=now,
    )
    return verify_release(
        paths.release_path,
        paths.release_keyring_path,
        provenance,
        provenance_materials,
        evidence,
        expected_release_keyring_sha256=paths.expected_release_keyring_sha256,
        now=now,
    )


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signed-release", type=Path, required=True)
    parser.add_argument("--release-keyring", type=Path, required=True)
    parser.add_argument("--expected-release-keyring-sha256", required=True)
    parser.add_argument("--signed-provenance", type=Path, required=True)
    parser.add_argument("--provenance-keyring", type=Path, required=True)
    parser.add_argument("--expected-provenance-keyring-sha256", required=True)
    parser.add_argument("--composition-attestation", type=Path, required=True)
    parser.add_argument("--final-oci-layout", type=Path, required=True)
    parser.add_argument("--query-v4-external-image-evidence", type=Path, required=True)
    parser.add_argument("--query-v4-source-bundle-archive", type=Path, required=True)
    parser.add_argument("--query-v4-oci-layout-archive", type=Path, required=True)
    parser.add_argument("--query-v4-content-attestation", type=Path, required=True)
    parser.add_argument("--expected-query-v4-source-commit-sha", required=True)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--source-bundle-archive", type=Path, required=True)
    parser.add_argument("--expected-source-commit-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--readiness-v4", type=Path, required=True)
    parser.add_argument("--l3-outcome", type=Path, required=True)
    parser.add_argument("--query-manifest", type=Path, required=True)
    parser.add_argument("--runtime-pin-manifest", type=Path, required=True)
    parser.add_argument("--dsn-file-identity-attestation", type=Path, required=True)
    _add_readiness_replay_arguments(parser)


def _add_readiness_replay_arguments(parser: argparse.ArgumentParser) -> None:
    path_fields = (
        "external_image_evidence",
        "source_bundle_archive",
        "oci_layout_archive",
        "content_attestation",
        "provenance",
        "provenance_keyring",
        "query_v5_keyring",
        "t1_keyring",
        "outcome_keyring",
    )
    for field in path_fields:
        parser.add_argument(
            "--readiness-" + field.replace("_", "-"),
            dest=f"readiness_{field}",
            type=Path,
            required=True,
        )
    for field in ("release", "release_keyring", "consume_marker", "receipt"):
        parser.add_argument(
            "--readiness-l3-" + field.replace("_", "-"),
            dest=f"readiness_l3_{field}",
            type=Path,
            required=True,
        )
    for field in DeploymentEvidencePaths.__dataclass_fields__:
        parser.add_argument(
            "--readiness-l3-pre-" + field.replace("_", "-"),
            dest=f"readiness_l3_pre_{field}",
            type=Path,
            required=True,
        )
    for field in PostEvidencePaths.__dataclass_fields__:
        parser.add_argument(
            "--readiness-l3-post-" + field.replace("_", "-"),
            dest=f"readiness_l3_post_{field}",
            type=Path,
            required=True,
        )
    for field in (
        "expected_t1_runtime_source_commit_sha",
        "expected_t1_runtime_image_digest",
        "expected_l3_contract_source_commit_sha",
        "expected_outcome_contract_source_commit_assertion",
        "expected_questdb_image_digest",
    ):
        parser.add_argument(
            "--readiness-" + field.replace("_", "-"),
            dest=f"readiness_{field}",
            required=True,
        )


def _readiness_inputs_from_args(
    args: argparse.Namespace,
) -> readiness_v4.ReadinessInputs:
    pre = DeploymentEvidencePaths(
        **{
            field: getattr(args, f"readiness_l3_pre_{field}")
            for field in DeploymentEvidencePaths.__dataclass_fields__
        }
    )
    post = PostEvidencePaths(
        **{
            field: getattr(args, f"readiness_l3_post_{field}")
            for field in PostEvidencePaths.__dataclass_fields__
        }
    )
    return readiness_v4.ReadinessInputs(
        external_image_evidence=args.readiness_external_image_evidence,
        source_bundle_archive=args.readiness_source_bundle_archive,
        oci_layout_archive=args.readiness_oci_layout_archive,
        content_attestation=args.readiness_content_attestation,
        provenance=args.readiness_provenance,
        provenance_keyring=args.readiness_provenance_keyring,
        query_v5_keyring=args.readiness_query_v5_keyring,
        t1_keyring=args.readiness_t1_keyring,
        outcome=args.l3_outcome,
        outcome_keyring=args.readiness_outcome_keyring,
        outcome_source=OutcomeSourcePaths(
            release=args.readiness_l3_release,
            release_keyring=args.readiness_l3_release_keyring,
            consume_marker=args.readiness_l3_consume_marker,
            receipt=args.readiness_l3_receipt,
            pre_evidence=pre,
        ),
        post_evidence=post,
        t1_runtime_source_commit_sha=(
            args.readiness_expected_t1_runtime_source_commit_sha
        ),
        t1_runtime_image_digest=(
            args.readiness_expected_t1_runtime_image_digest
        ),
        l3_contract_source_commit_sha=(
            args.readiness_expected_l3_contract_source_commit_sha
        ),
        outcome_contract_source_commit_assertion=(
            args.readiness_expected_outcome_contract_source_commit_assertion
        ),
        questdb_image_digest=args.readiness_expected_questdb_image_digest,
    )


def _paths(args: argparse.Namespace) -> OfflineVerificationPaths:
    replay = query_v5.CompositionReplayInputs(
        query_v4_external_image_evidence_path=args.query_v4_external_image_evidence,
        query_v4_source_bundle_path=args.query_v4_source_bundle_archive,
        query_v4_oci_layout_archive_path=args.query_v4_oci_layout_archive,
        query_v4_content_attestation_path=args.query_v4_content_attestation,
        expected_query_v4_source_commit_sha=args.expected_query_v4_source_commit_sha,
        external_image_evidence_path=args.external_image_evidence,
        source_bundle_path=args.source_bundle_archive,
        final_oci_layout_path=args.final_oci_layout,
    )
    return OfflineVerificationPaths(
        release_path=args.signed_release,
        release_keyring_path=args.release_keyring,
        provenance_path=args.signed_provenance,
        provenance_keyring_path=args.provenance_keyring,
        composition_path=args.composition_attestation,
        final_oci_layout_path=args.final_oci_layout,
        composition_replay=replay,
        readiness_path=args.readiness_v4,
        l3_outcome_path=args.l3_outcome,
        query_manifest_path=args.query_manifest,
        runtime_pin_manifest_path=args.runtime_pin_manifest,
        dsn_identity_attestation_path=args.dsn_file_identity_attestation,
        expected_release_keyring_sha256=args.expected_release_keyring_sha256,
        expected_provenance_keyring_sha256=args.expected_provenance_keyring_sha256,
        expected_source_commit_sha=args.expected_source_commit_sha,
        expected_image_digest=args.expected_image_digest,
        readiness_inputs=_readiness_inputs_from_args(args),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    _common_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        verified = verify_offline_foundation(
            _paths(args), now=datetime.now(timezone.utc)
        )
    except (OSError, QueryV6AuthorityError, ValueError) as exc:
        print(f"query-v6 offline verification failed: {exc}", file=sys.stderr)
        return 2
    print(f"status={AUTHORITY_STATE}")
    print(f"release_id={verified.payload['release_id']}")
    print(f"attempt_id={verified.payload['attempt_id']}")
    print("offline_verification_only=true")
    print("release_consumed=false")
    print("dsn_metadata_read=false")
    print("dsn_secret_read=false")
    print("network_attempted=false")
    print("production_query_attempted=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
