#!/usr/bin/env python3
"""Verify a distinct human-signed query-v6 executable one-shot release.

The query-v6 foundation remains non-authoritative.  This verifier first
replays that complete foundation, then verifies a separate executable signing
domain and active root-owned execution pin generation.  It performs no DSN
read, network access, consume, child launch, RPC, order, or position action.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import stat
import sys
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import commodity_c_fast_t1_query_v6_authority as foundation_v6
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
SIGNER_PATH = VERIFIER_PATH.with_name("commodity_c_fast_t1_query_v6_executable_sign.py")
RUNNER_PATH = VERIFIER_PATH.with_name("commodity_c_fast_t1_query_v6_runtime.py")
RELEASE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-one-shot-query-executable-release-v6.schema.json"
)
KEYRING_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-query-v6-executable-trusted-keys-v1.schema.json"
)
PIN_SET_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v6-executable-pin-set-v1.schema.json"
)
CONSUME_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-consume-v6.schema.json"
)
TERMINAL_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json"
)
CHILD_LAUNCH_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-child-launched-v6.schema.json"
)
ADAPTER_PACKAGE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v6-preconnect-package-v1.schema.json"
)
ADAPTER_PACKAGE_BUILDER_PATH = ROOT / "scripts/c_fast_t1/query_v6_preconnect_package.py"
AUDIT_EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
)
LEGACY_AUDIT_EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json"
)
READONLY_PROOF_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
)
ACTIVE_PIN_ROOT = Path("/run/c-fast-t1-query-v6-executable-pins")
ACTIVE_PIN_MANIFEST_PATH = ACTIVE_PIN_ROOT / "pin-set.manifest.json"

SCHEMA_VERSION = "commodity_c_fast_t1_one_shot_query_executable_release_v6"
PURPOSE = "c_fast_t1_query_v6_distinct_executable_one_shot"
KEYRING_VERSION = "commodity_c_fast_t1_query_v6_executable_trusted_keys_v1"
KEY_PURPOSE = "t1_query_v6_executable_release_signer"
PIN_SET_VERSION = "commodity_c_fast_t1_query_v6_executable_pin_set_v1"
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MAX_RELEASE_TTL = timedelta(minutes=5)
MAX_BYTES = 8 * 1024 * 1024

TRUE_AUTHORITY_FIELDS = (
    "authority_granted",
    "release_consumption_authorized",
    "t1_one_shot_child_launch_authorized",
    "network_authorized",
    "network_query_authorized",
    "readonly_production_query_authorized",
    "production_query_authorized",
    "readonly_query_authorized",
    "local_query_evidence_write_authorized",
)
FALSE_AUTHORITY_FIELDS = (
    "foundation_is_authority",
    "write_probe_authorized",
    "database_mutation_authorized",
    "collection_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "strategy_activation_authorized",
    "production_authorized",
    "p0_acceptance_authorized",
)


class QueryV6ExecutableError(RuntimeError):
    """Expected fail-closed executable authority error."""


@dataclass(frozen=True)
class ExecutablePins:
    payload: dict[str, Any]
    canonical_sha256: str

    def __getattr__(self, name: str) -> Any:
        try:
            return self.payload[name]
        except KeyError as exc:  # pragma: no cover - schema prevents this.
            raise AttributeError(name) from exc


@dataclass(frozen=True)
class VerifiedExecutableRelease:
    payload: dict[str, Any]
    raw_sha256: str
    canonical_sha256: str
    signer_public_key_sha256: str
    keyring_sha256: str
    foundation: foundation_v6.VerifiedAuthorityFoundation
    pins: ExecutablePins


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unsigned_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def _same(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise QueryV6ExecutableError(f"{label} binding mismatch")


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise QueryV6ExecutableError(f"{label} must include an explicit timezone")
    return value.astimezone(timezone.utc)


def _contains_pending(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("PENDING_")
    if isinstance(value, list):
        return any(_contains_pending(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_pending(item) for item in value.values())
    return False


def _read(path: Path, label: str, *, private: bool = False) -> bytes:
    try:
        return read_regular_file_strict(
            path,
            label,
            private=private,
            limit=MAX_BYTES,
        )
    except OneShotError as exc:
        raise QueryV6ExecutableError(str(exc)) from exc


def source_and_schema_hashes() -> dict[str, str]:
    paths = {
        "executable_signer_sha256": SIGNER_PATH,
        "executable_verifier_sha256": VERIFIER_PATH,
        "executable_runner_sha256": RUNNER_PATH,
        "executable_release_schema_sha256": RELEASE_SCHEMA_PATH,
        "executable_keyring_schema_sha256": KEYRING_SCHEMA_PATH,
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "terminal_schema_sha256": TERMINAL_SCHEMA_PATH,
        "audit_evidence_schema_sha256": AUDIT_EVIDENCE_SCHEMA_PATH,
        "legacy_audit_evidence_schema_sha256": (LEGACY_AUDIT_EVIDENCE_SCHEMA_PATH),
        "readonly_proof_schema_sha256": READONLY_PROOF_SCHEMA_PATH,
        "child_launch_schema_sha256": CHILD_LAUNCH_SCHEMA_PATH,
        "adapter_package_schema_sha256": ADAPTER_PACKAGE_SCHEMA_PATH,
        "adapter_package_builder_sha256": ADAPTER_PACKAGE_BUILDER_PATH,
    }
    return {field: sha256_bytes(_read(path, field)) for field, path in paths.items()}


def validate_pins(pins: ExecutablePins, *, verify_sources: bool = True) -> None:
    try:
        validate_json_schema(
            pins.payload,
            PIN_SET_SCHEMA_PATH,
            "query-v6 executable active pin set",
        )
    except OneShotError as exc:
        raise QueryV6ExecutableError(str(exc)) from exc
    if pins.payload["schema_version"] != PIN_SET_VERSION:
        raise QueryV6ExecutableError("executable pin generation is invalid")
    expected_hash = sha256_bytes(canonical_json(pins.payload))
    _same(pins.canonical_sha256, expected_hash, "executable pin manifest")
    if verify_sources:
        for field, actual in source_and_schema_hashes().items():
            _same(str(pins.payload[field]), actual, field)


def read_active_pins(
    path: Path = ACTIVE_PIN_MANIFEST_PATH,
    *,
    require_root_owned: bool = True,
) -> ExecutablePins:
    try:
        parent = path.parent.resolve(strict=True)
        parent_info = parent.lstat()
        path_info_before = path.lstat()
        if (
            stat.S_ISLNK(parent_info.st_mode)
            or not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(path_info_before.st_mode)
            or not stat.S_ISREG(path_info_before.st_mode)
            or (
                require_root_owned
                and (parent_info.st_uid != 0 or path_info_before.st_uid != 0)
            )
            or stat.S_IMODE(parent_info.st_mode) & 0o022
            or stat.S_IMODE(path_info_before.st_mode) & 0o022
        ):
            raise QueryV6ExecutableError("executable pin manifest custody is unsafe")
        raw_before = _read(path, "query-v6 executable active pin set")
        payload = parse_json_bytes(raw_before, "query-v6 executable active pin set")
        raw_after = _read(path, "query-v6 executable active pin set final re-read")
        path_info_after = path.lstat()
    except (OSError, OneShotError) as exc:
        raise QueryV6ExecutableError(str(exc)) from exc
    if raw_before != raw_after or (
        path_info_before.st_dev,
        path_info_before.st_ino,
        path_info_before.st_size,
    ) != (path_info_after.st_dev, path_info_after.st_ino, path_info_after.st_size):
        raise QueryV6ExecutableError("executable pin manifest changed while read")
    pins = ExecutablePins(
        payload=payload,
        canonical_sha256=sha256_bytes(canonical_json(payload)),
    )
    validate_pins(pins)
    return pins


def _validate_keyring(
    keyring: dict[str, Any],
    signer_key_id: str,
) -> tuple[Ed25519PublicKey, str, frozenset[str]]:
    try:
        validate_json_schema(
            keyring,
            KEYRING_SCHEMA_PATH,
            "query-v6 executable keyring",
        )
    except OneShotError as exc:
        raise QueryV6ExecutableError(str(exc)) from exc
    if keyring.get("schema_version") != KEYRING_VERSION:
        raise QueryV6ExecutableError("executable keyring generation is invalid")
    matched: Ed25519PublicKey | None = None
    matched_hash = ""
    key_ids: set[str] = set()
    materials: set[str] = set()
    for entry in keyring["keys"]:
        key_id = str(entry["key_id"])
        if key_id in key_ids:
            raise QueryV6ExecutableError("executable key_id is duplicated")
        key_ids.add(key_id)
        try:
            raw = base64.b64decode(entry["public_key_base64"], validate=True)
            if len(raw) != 32:
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(raw)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise QueryV6ExecutableError("executable trusted key is invalid") from exc
        material_hash = sha256_bytes(raw)
        if material_hash in materials:
            raise QueryV6ExecutableError("executable key material is duplicated")
        materials.add(material_hash)
        if key_id == signer_key_id:
            matched = public_key
            matched_hash = material_hash
    if matched is None:
        raise QueryV6ExecutableError("executable signer_key_id is not trusted")
    return matched, matched_hash, frozenset(materials)


def foundation_key_materials(
    foundation_keyring_path: Path,
    verified: foundation_v6.VerifiedAuthorityFoundation,
) -> frozenset[str]:
    raw = foundation_v6._read_bytes(
        foundation_keyring_path,
        "query-v6 foundation keyring",
        private=True,
    )
    keyring = foundation_v6.parse_json_bytes(raw, "query-v6 foundation keyring")
    keyring_hash = sha256_bytes(canonical_json(keyring))
    _same(
        keyring_hash,
        str(verified.payload["trusted_keyring_sha256"]),
        "foundation keyring",
    )
    _public, _signer_hash, materials = foundation_v6._validate_keyring(
        keyring,
        str(verified.payload["signer_key_id"]),
    )
    return materials


def expected_foundation_binding(
    verified: foundation_v6.VerifiedAuthorityFoundation,
) -> dict[str, Any]:
    return expected_foundation_binding_from_payload(
        verified.payload,
        verified.evidence.query_manifest.payload,
        raw_sha256=verified.raw_sha256,
        canonical_sha256=verified.canonical_sha256,
        signer_public_key_sha256=verified.signer_public_key_sha256,
    )


def expected_foundation_binding_from_payload(
    payload: dict[str, Any],
    manifest: dict[str, Any],
    *,
    raw_sha256: str,
    canonical_sha256: str,
    signer_public_key_sha256: str,
) -> dict[str, Any]:
    """Pure official projection used by offline and bundle verifiers."""

    fields = (
        "provenance_raw_sha256",
        "provenance_canonical_sha256",
        "composition_attestation_raw_sha256",
        "composition_attestation_canonical_sha256",
        "readiness_v4_raw_sha256",
        "readiness_v4_canonical_sha256",
        "l3_outcome_raw_sha256",
        "l3_outcome_canonical_sha256",
        "query_manifest_raw_sha256",
        "query_manifest_canonical_sha256",
        "runtime_source_commit_sha",
        "runtime_image_reference",
        "runtime_image_digest",
        "runtime_image_id",
        "runtime_pin_generation_id",
        "runtime_pin_manifest_sha256",
        "runtime_identity_sha256",
        "custody_absolute_path",
        "custody_path_sha256",
        "custody_id",
        "custody_identity_sha256",
        "custody_directory_identity_sha256",
        "dsn_file_identity_attestation_raw_sha256",
        "dsn_file_identity_attestation_canonical_sha256",
        "dsn_file_identity_sha256",
        "expected_readonly_principal_sha256",
        "expected_endpoint_identity_sha256",
        "query_child_sha256",
        "audit_script_sha256",
        "readonly_proof_schema_sha256",
    )
    return {
        "release_id": payload["release_id"],
        "attempt_id": payload["attempt_id"],
        "raw_sha256": raw_sha256,
        "canonical_sha256": canonical_sha256,
        "signer_public_key_sha256": signer_public_key_sha256,
        "trusted_keyring_sha256": payload["trusted_keyring_sha256"],
        "authority_state": payload["authority_state"],
        **{field: payload[field] for field in fields},
        "snapshot_id": manifest["snapshot_id"],
        "audit_window": manifest["audit_window"],
    }


def expected_execution_binding(pins: ExecutablePins) -> dict[str, Any]:
    return {
        "pin_set_generation_id": pins.generation_id,
        "pin_set_manifest_sha256": pins.canonical_sha256,
        **{
            field: pins.payload[field]
            for field in (
                "executable_signer_sha256",
                "executable_verifier_sha256",
                "executable_runner_sha256",
                "executable_release_schema_sha256",
                "executable_keyring_schema_sha256",
                "consume_schema_sha256",
                "terminal_schema_sha256",
                "audit_evidence_schema_sha256",
                "legacy_audit_evidence_schema_sha256",
                "readonly_proof_schema_sha256",
                "child_launch_schema_sha256",
                "adapter_package_schema_sha256",
                "adapter_package_builder_sha256",
                "execution_adapter_sha256",
                "execution_adapter_absolute_path",
                "adapter_package_manifest_absolute_path",
                "adapter_package_manifest_sha256",
                "adapter_package_root_identity_sha256",
                "python_executable_path",
                "python_executable_sha256",
                "python_dependency_closure_sha256",
                "questdb_build_sha256",
            )
        },
        "connect_timeout_seconds": 10,
        "statement_timeout_ms": 60_000,
        "maximum_runtime_seconds": 600,
        "minimum_launch_margin_seconds": 30,
    }


def validate_release_semantics(
    payload: dict[str, Any],
    foundation: foundation_v6.VerifiedAuthorityFoundation,
    pins: ExecutablePins,
    *,
    now: datetime,
) -> None:
    try:
        validate_json_schema(
            payload,
            RELEASE_SCHEMA_PATH,
            "query-v6 executable release",
        )
    except OneShotError as exc:
        raise QueryV6ExecutableError(str(exc)) from exc
    if _contains_pending(payload):
        raise QueryV6ExecutableError("executable release contains PENDING_ values")
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["purpose"] != PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
        or payload["attempt_id"]
        != foundation_v6.release_attempt_id(payload["release_id"])
    ):
        raise QueryV6ExecutableError("executable release identity is invalid")
    if payload["foundation"] != expected_foundation_binding(foundation):
        raise QueryV6ExecutableError("executable release foundation binding mismatch")
    if payload["execution"] != expected_execution_binding(pins):
        raise QueryV6ExecutableError("executable release execution binding mismatch")
    if any(payload[field] is not True for field in TRUE_AUTHORITY_FIELDS):
        raise QueryV6ExecutableError("executable release lacks narrow query authority")
    if any(payload[field] is not False for field in FALSE_AUTHORITY_FIELDS):
        raise QueryV6ExecutableError("executable release grants forbidden authority")
    for field in (
        "one_shot",
        "server_enforced_readonly_required",
        "consume_before_dsn_secret_read",
        "consume_before_network",
        "final_revalidation_before_network",
        "pre_and_post_readonly_proof_required",
    ):
        if payload[field] is not True:
            raise QueryV6ExecutableError(
                f"required executable safety fact is false: {field}"
            )
    if payload["maximum_uses"] != 1 or payload["replay_allowed"] is not False:
        raise QueryV6ExecutableError("executable release is not strict one-shot")
    current = _utc(now, "verification time")
    try:
        issued = parse_datetime(payload["issued_at"], "issued_at")
        not_before = parse_datetime(payload["not_before"], "not_before")
        expires = parse_datetime(payload["expires_at"], "expires_at")
        foundation_issued = parse_datetime(
            foundation.payload["issued_at"], "foundation issued_at"
        )
        foundation_expires = parse_datetime(
            foundation.payload["expires_at"], "foundation expires_at"
        )
    except OneShotError as exc:
        raise QueryV6ExecutableError(str(exc)) from exc
    if not foundation_issued <= issued <= not_before <= current < expires:
        raise QueryV6ExecutableError("executable release time window is inactive")
    if expires > foundation_expires or expires - issued > MAX_RELEASE_TTL:
        raise QueryV6ExecutableError("executable release outlives its authority window")
    margin = timedelta(seconds=payload["execution"]["minimum_launch_margin_seconds"])
    if current + margin >= expires:
        raise QueryV6ExecutableError("executable release launch margin is exhausted")


def verify_release(
    release_path: Path,
    keyring_path: Path,
    foundation_keyring_path: Path,
    foundation: foundation_v6.VerifiedAuthorityFoundation,
    pins: ExecutablePins,
    *,
    now: datetime,
) -> VerifiedExecutableRelease:
    validate_pins(pins)
    release_raw = _read(
        release_path, "signed query-v6 executable release", private=True
    )
    keyring_raw = _read(keyring_path, "query-v6 executable keyring", private=True)
    try:
        payload = parse_json_bytes(release_raw, "signed query-v6 executable release")
        keyring = parse_json_bytes(keyring_raw, "query-v6 executable keyring")
    except OneShotError as exc:
        raise QueryV6ExecutableError(str(exc)) from exc
    keyring_sha256 = sha256_bytes(canonical_json(keyring))
    _same(
        keyring_sha256, str(pins.executable_keyring_sha256), "active executable keyring"
    )
    _same(
        keyring_sha256,
        str(payload.get("trusted_keyring_sha256") or ""),
        "signed executable keyring",
    )
    public_key, signer_hash, executable_materials = _validate_keyring(
        keyring, str(payload.get("signer_key_id") or "")
    )
    prior_materials = set(foundation_key_materials(foundation_keyring_path, foundation))
    prior_materials.update(
        foundation_v6.known_domain_public_key_hashes(
            foundation.provenance,
            foundation.evidence,
        )
    )
    if prior_materials & set(executable_materials):
        raise QueryV6ExecutableError("foundation and executable key domains overlap")
    try:
        signature = base64.b64decode(payload["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError
        public_key.verify(signature, canonical_json(unsigned_payload(payload)))
    except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise QueryV6ExecutableError("executable release signature is invalid") from exc
    validate_release_semantics(payload, foundation, pins, now=now)
    return VerifiedExecutableRelease(
        payload=payload,
        raw_sha256=sha256_bytes(release_raw),
        canonical_sha256=sha256_bytes(canonical_json(payload)),
        signer_public_key_sha256=signer_hash,
        keyring_sha256=keyring_sha256,
        foundation=foundation,
        pins=pins,
    )


def verify_foundation_from_args(
    args: argparse.Namespace,
    *,
    now: datetime,
) -> foundation_v6.VerifiedAuthorityFoundation:
    return foundation_v6.verify_offline_foundation(
        foundation_v6._paths(args),
        now=now,
    )


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signed-executable-release", type=Path, required=True)
    parser.add_argument("--executable-keyring", type=Path, required=True)
    parser.add_argument(
        "--active-executable-pin-manifest",
        type=Path,
        default=ACTIVE_PIN_MANIFEST_PATH,
    )
    foundation_v6._common_arguments(parser)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    _common_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc)
    try:
        foundation = verify_foundation_from_args(args, now=now)
        pins = read_active_pins(args.active_executable_pin_manifest)
        verified = verify_release(
            args.signed_executable_release,
            args.executable_keyring,
            args.release_keyring,
            foundation,
            pins,
            now=now,
        )
    except (
        OSError,
        QueryV6ExecutableError,
        foundation_v6.QueryV6AuthorityError,
    ) as exc:
        print(f"query-v6 executable verification failed: {exc}", file=sys.stderr)
        return 2
    print("status=QUERY_V6_EXECUTABLE_AUTHORITY_VERIFIED_NO_CONSUME")
    print(f"release_id={verified.payload['release_id']}")
    print(f"attempt_id={verified.payload['attempt_id']}")
    print("release_consumed=false")
    print("dsn_secret_read=false")
    print("network_attempted=false")
    print("web_bridge_rpc_calls=0")
    print("orders_sent=0")
    print("positions_modified=0")
    print("production_authorized=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
