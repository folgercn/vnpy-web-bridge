#!/usr/bin/env python3
"""Verify or consume one C_FAST SimNow Research Acceptance v1."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import commodity_c_fast_simnow_research_bundle as research
from commodity_c_fast_t1_one_shot import (
    MAX_JSON_BYTES,
    OneShotError,
    canonical_json,
    parse_datetime,
    parse_json_bytes,
    read_regular_file_strict,
    validate_json_schema,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
ACCEPTANCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-simnow-research-acceptance-v1.schema.json"
)
KEYRING_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-simnow-research-acceptance-trusted-keys-v1.schema.json"
)
CONSUME_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-simnow-research-acceptance-consume-v1.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-simnow-research-acceptance-receipt-v1.schema.json"
)

SCHEMA_VERSION = "commodity_c_fast_simnow_research_acceptance_v1"
PURPOSE = "c_fast_simnow_research_control_acceptance"
KEYRING_VERSION = (
    "commodity_c_fast_simnow_research_acceptance_trusted_keys_v1"
)
KEY_PURPOSE = "c_fast_simnow_research_acceptance_signer"
CONSUME_VERSION = (
    "commodity_c_fast_simnow_research_acceptance_consume_v1"
)
RECEIPT_VERSION = (
    "commodity_c_fast_simnow_research_acceptance_receipt_v1"
)
ACCEPTANCE_STATE = "READY_FOR_HUMAN_SIMNOW_EXECUTION_PERMIT_ONLY"
CANDIDATE_ID = research.CANDIDATE_ID
MAX_ACCEPTANCE_TTL = timedelta(minutes=15)
MAX_ACCEPTANCE_BYTES = 2 * 1024 * 1024
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

FALSE_AUTHORITY_FIELDS = (
    "acceptance_is_deployment_authority",
    "acceptance_is_execution_authority",
    "countable_forward",
    "official_forward_claimed",
    "production_allowed",
    "deployment_authorized",
    "execution_permit_issued",
    "simnow_execution_authorized",
    "runtime_activation_authorized",
    "network_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_read_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "replacement_authorized",
    "production_authorized",
    "automatic_promotion_authorized",
    "dynamic_selection_allowed",
    "replay_allowed",
    "account_data_read",
    "execution_data_read",
)


class ResearchAcceptanceError(RuntimeError):
    """Expected fail-closed Research Acceptance error."""


@dataclass(frozen=True)
class InstalledResearchBundle:
    verified: research.VerifiedResearchBundle
    custody: research.CustodyFacts
    claim_path: Path
    bundle_path: Path
    receipt_path: Path
    claim: dict[str, Any]
    receipt: dict[str, Any]
    claim_raw: bytes
    receipt_raw: bytes
    claim_raw_sha256: str
    claim_canonical_sha256: str
    receipt_raw_sha256: str
    receipt_canonical_sha256: str
    install_files_identity_sha256: str
    research_keyring_raw: bytes
    research_key_materials: frozenset[bytes]


@dataclass(frozen=True)
class VerifiedResearchAcceptance:
    payload: dict[str, Any]
    raw: bytes
    raw_sha256: str
    canonical_sha256: str
    acceptance_keyring_raw: bytes
    acceptance_keyring_raw_sha256: str
    installed: InstalledResearchBundle


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _clock_now(clock: Callable[[], datetime]) -> datetime:
    current = clock()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ResearchAcceptanceError(
            "injected acceptance clock must include a UTC offset"
        )
    return current.astimezone(timezone.utc)


def _clock_now_not_before(
    clock: Callable[[], datetime],
    previous: datetime,
    *,
    stage: str,
) -> datetime:
    current = _clock_now(clock)
    if current < previous:
        raise ResearchAcceptanceError(
            f"acceptance clock regressed during {stage}"
        )
    return current


def _compare(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise ResearchAcceptanceError(f"{label} binding mismatch")


def _require_sha256(value: Any, label: str) -> str:
    text = str(value)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise ResearchAcceptanceError(
            f"{label} must be one lowercase SHA256"
        )
    return text


def _reject_pending(value: Any) -> None:
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise ResearchAcceptanceError(
            "PENDING values cannot be verified, signed or consumed"
        )
    if isinstance(value, dict):
        for child in value.values():
            _reject_pending(child)
    elif isinstance(value, list):
        for child in value:
            _reject_pending(child)


def unsigned_acceptance_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def acceptance_binding_payload(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in payload.items()
        if key not in {"acceptance_id", "signature"}
    }


def acceptance_binding_sha256(payload: dict[str, Any]) -> str:
    return _hash(canonical_json(acceptance_binding_payload(payload)))


def _tool_bindings() -> dict[str, str]:
    paths = {
        "acceptance_verifier_sha256": VERIFIER_PATH,
        "acceptance_schema_sha256": ACCEPTANCE_SCHEMA_PATH,
        "acceptance_keyring_schema_sha256": KEYRING_SCHEMA_PATH,
        "consume_schema_sha256": CONSUME_SCHEMA_PATH,
        "receipt_schema_sha256": RECEIPT_SCHEMA_PATH,
    }
    return {
        field: _hash(
            read_regular_file_strict(
                path,
                f"C_FAST Research Acceptance {field}",
                limit=MAX_JSON_BYTES,
            )
        )
        for field, path in paths.items()
    }


def _read_canonical_json(
    path: Path,
    label: str,
    *,
    limit: int = MAX_JSON_BYTES,
    private: bool = True,
) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_file_strict(
        path,
        label,
        limit=limit,
        private=private,
    )
    payload = parse_json_bytes(raw, label)
    if raw != canonical_json(payload) + b"\n":
        raise ResearchAcceptanceError(
            f"{label} must use exact canonical JSON bytes"
        )
    return payload, raw


def _public_key_material(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _load_keyring(
    path: Path,
    *,
    schema_path: Path,
    expected_raw_sha256: str,
    expected_version: str,
    expected_purpose: str,
    key_id: str | None,
    label: str,
) -> tuple[
    Ed25519PublicKey | None,
    frozenset[bytes],
    bytes,
    str,
]:
    expected = _require_sha256(
        expected_raw_sha256,
        f"independently pinned {label}",
    )
    raw = read_regular_file_strict(
        path,
        label,
        limit=MAX_JSON_BYTES,
        private=True,
    )
    raw_sha256 = _hash(raw)
    _compare(raw_sha256, expected, f"{label} raw pin")
    payload = parse_json_bytes(raw, label)
    validate_json_schema(payload, schema_path, label)
    if (
        payload["schema_version"] != expected_version
        or payload["purpose"] != expected_purpose
    ):
        raise ResearchAcceptanceError(f"{label} identity is invalid")
    keys = payload["keys"]
    seen_ids: set[str] = set()
    materials: set[bytes] = set()
    selected: Ed25519PublicKey | None = None
    for entry in keys:
        current_id = str(entry["key_id"])
        if current_id in seen_ids:
            raise ResearchAcceptanceError(
                f"{label} contains duplicate key IDs"
            )
        seen_ids.add(current_id)
        if entry["purpose"] != expected_purpose:
            raise ResearchAcceptanceError(f"{label} key purpose is invalid")
        try:
            material = base64.b64decode(
                str(entry["public_key_base64"]),
                validate=True,
            )
            if len(material) != 32:
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(material)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ResearchAcceptanceError(
                f"{label} public key is invalid"
            ) from exc
        if material in materials:
            raise ResearchAcceptanceError(
                f"{label} reuses public-key material"
            )
        materials.add(material)
        if current_id == key_id:
            selected = public_key
    if key_id is not None and selected is None:
        raise ResearchAcceptanceError(f"{label} signer key is not trusted")
    return selected, frozenset(materials), raw, raw_sha256


def _require_disjoint_key_material(
    research_materials: frozenset[bytes],
    acceptance_materials: frozenset[bytes],
) -> None:
    if research_materials & acceptance_materials:
        raise ResearchAcceptanceError(
            "Control acceptance keyring reuses Research key material"
        )


def _assert_distinct_paths(paths: dict[str, Path]) -> None:
    resolved_seen: dict[Path, str] = {}
    inode_seen: dict[tuple[int, int], str] = {}
    for label, path in paths.items():
        try:
            resolved = path.resolve(strict=True)
            info = path.lstat()
        except OSError as exc:
            raise ResearchAcceptanceError(
                f"{label} is unavailable"
            ) from exc
        if not stat.S_ISREG(info.st_mode):
            raise ResearchAcceptanceError(
                f"{label} must be a regular non-symlink file"
            )
        inode = (info.st_dev, info.st_ino)
        if resolved in resolved_seen:
            raise ResearchAcceptanceError(
                f"{label} aliases {resolved_seen[resolved]}"
            )
        if inode in inode_seen:
            raise ResearchAcceptanceError(
                f"{label} hardlinks {inode_seen[inode]}"
            )
        resolved_seen[resolved] = label
        inode_seen[inode] = label


def _custody_files_identity_sha256(
    custody: research.CustodyFacts,
    paths: dict[str, Path],
) -> str:
    entries: list[dict[str, Any]] = []
    for role in sorted(paths):
        path = paths[role]
        try:
            info = path.lstat()
        except OSError as exc:
            raise ResearchAcceptanceError(
                f"custody file {role} is unavailable"
            ) from exc
        if (
            path.parent != custody.root
            or not stat.S_ISREG(info.st_mode)
            or info.st_dev != custody.device
            or info.st_uid != custody.owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ResearchAcceptanceError(
                f"custody file {role} identity or mode is invalid"
            )
        entries.append(
            {
                "role": role,
                "filename": path.name,
                "device": info.st_dev,
                "inode": info.st_ino,
                "owner_uid": info.st_uid,
                "mode": stat.S_IMODE(info.st_mode),
                "size_bytes": info.st_size,
            }
        )
    return _hash(canonical_json(entries))


def _installed_paths(
    custody: research.CustodyFacts,
    bundle_id: str,
) -> tuple[Path, Path, Path]:
    try:
        claim_name, bundle_name, receipt_name = research._custody_filenames(
            bundle_id
        )
    except research.ResearchBundleError as exc:
        raise ResearchAcceptanceError(str(exc)) from exc
    return (
        custody.root / claim_name,
        custody.root / bundle_name,
        custody.root / receipt_name,
    )


def _verify_install_chain(
    *,
    bundle_id: str,
    custody_root: Path,
    research_keyring_path: Path,
    artifact_paths: dict[str, Path],
    expected_research_keyring_raw_sha256: str,
    expected_research_signer_sha256: str,
    now: datetime,
) -> InstalledResearchBundle:
    if set(artifact_paths) != set(research.ARTIFACT_ROLES):
        raise ResearchAcceptanceError(
            "research artifact role set is incomplete"
        )
    try:
        custody = research.custody_facts(custody_root)
    except research.ResearchBundleError as exc:
        raise ResearchAcceptanceError(str(exc)) from exc
    claim_path, bundle_path, receipt_path = _installed_paths(
        custody,
        bundle_id,
    )
    custody_paths = {
        "install_claim": claim_path,
        "installed_bundle": bundle_path,
        "install_receipt": receipt_path,
    }
    install_files_identity_sha256 = _custody_files_identity_sha256(
        custody,
        custody_paths,
    )
    _assert_distinct_paths(
        {
            "installed claim": claim_path,
            "installed bundle": bundle_path,
            "install receipt": receipt_path,
            "Research keyring": research_keyring_path,
            **{
                f"Research artifact {role}": path
                for role, path in artifact_paths.items()
            },
        }
    )
    try:
        verified = research.verify_signed_bundle(
            bundle_path,
            research_keyring_path,
            artifact_paths,
            expected_keyring_raw_sha256=(
                expected_research_keyring_raw_sha256
            ),
            expected_signer_sha256=expected_research_signer_sha256,
            now=now,
        )
    except (research.ResearchBundleError, OneShotError) as exc:
        raise ResearchAcceptanceError(
            f"installed Research bundle verification failed: {exc}"
        ) from exc
    if verified.payload["bundle_id"] != bundle_id:
        raise ResearchAcceptanceError(
            "installed Research bundle ID is not the requested bundle"
        )
    _compare(
        custody.root_path_sha256,
        str(verified.payload["custody_root_path_sha256"]),
        "installed Research custody root path",
    )
    _compare(
        custody.identity_sha256,
        str(verified.payload["custody_identity_sha256"]),
        "installed Research custody identity",
    )
    claim, claim_raw = _read_canonical_json(
        claim_path,
        "C_FAST Research install claim",
    )
    receipt, receipt_raw = _read_canonical_json(
        receipt_path,
        "C_FAST Research install receipt",
    )
    validate_json_schema(
        receipt,
        research.RECEIPT_SCHEMA_PATH,
        "C_FAST Research install receipt",
    )
    expected_claim = research._install_claim(
        verified,
        custody,
        installed_filename=bundle_path.name,
        receipt_filename=receipt_path.name,
    )
    if claim != expected_claim:
        raise ResearchAcceptanceError(
            "installed Research claim binding is invalid"
        )
    installed_at = parse_datetime(
        receipt["installed_at"],
        "Research install receipt installed_at",
    )
    bundle_not_before = parse_datetime(
        verified.payload["not_before"],
        "Research bundle not_before",
    )
    bundle_expires = parse_datetime(
        verified.payload["expires_at"],
        "Research bundle expires_at",
    )
    if not bundle_not_before <= installed_at <= bundle_expires:
        raise ResearchAcceptanceError(
            "Research install receipt is outside the bundle validity window"
        )
    expected_receipt = research._install_receipt(
        verified,
        bundle_path,
        install_claim_id=expected_claim["install_claim_id"],
        install_claim_raw_sha256=_hash(claim_raw),
        custody=custody,
        installed_at=installed_at,
    )
    if receipt != expected_receipt:
        raise ResearchAcceptanceError(
            "installed Research receipt binding is invalid"
        )
    _selected, research_materials, keyring_raw, keyring_raw_sha256 = (
        _load_keyring(
            research_keyring_path,
            schema_path=research.KEYRING_SCHEMA_PATH,
            expected_raw_sha256=expected_research_keyring_raw_sha256,
            expected_version=research.KEYRING_VERSION,
            expected_purpose=research.KEY_PURPOSE,
            key_id=str(verified.payload["signer_key_id"]),
            label="C_FAST Research trusted keyring",
        )
    )
    _compare(
        keyring_raw_sha256,
        verified.keyring_raw_sha256,
        "Research keyring",
    )
    if read_regular_file_strict(
        research_keyring_path,
        "C_FAST Research trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    ) != keyring_raw:
        raise ResearchAcceptanceError(
            "Research keyring changed during install-chain verification"
        )
    if read_regular_file_strict(
        claim_path,
        "C_FAST Research install claim",
        private=True,
    ) != claim_raw:
        raise ResearchAcceptanceError(
            "Research install claim changed during verification"
        )
    if read_regular_file_strict(
        receipt_path,
        "C_FAST Research install receipt",
        private=True,
    ) != receipt_raw:
        raise ResearchAcceptanceError(
            "Research install receipt changed during verification"
        )
    try:
        if research.custody_facts(custody.root) != custody:
            raise ResearchAcceptanceError(
                "Research custody changed during verification"
            )
    except research.ResearchBundleError as exc:
        raise ResearchAcceptanceError(str(exc)) from exc
    if (
        _custody_files_identity_sha256(custody, custody_paths)
        != install_files_identity_sha256
    ):
        raise ResearchAcceptanceError(
            "Research custody files changed during verification"
        )
    return InstalledResearchBundle(
        verified=verified,
        custody=custody,
        claim_path=claim_path,
        bundle_path=bundle_path,
        receipt_path=receipt_path,
        claim=claim,
        receipt=receipt,
        claim_raw=claim_raw,
        receipt_raw=receipt_raw,
        claim_raw_sha256=_hash(claim_raw),
        claim_canonical_sha256=_hash(canonical_json(claim)),
        receipt_raw_sha256=_hash(receipt_raw),
        receipt_canonical_sha256=_hash(canonical_json(receipt)),
        install_files_identity_sha256=install_files_identity_sha256,
        research_keyring_raw=keyring_raw,
        research_key_materials=research_materials,
    )


def _selected_target_bindings(
    payload: dict[str, Any],
    bundle: dict[str, Any],
) -> list[dict[str, Any]]:
    selected = payload.get("selected_products")
    if (
        not isinstance(selected, list)
        or not 1 <= len(selected) <= 2
        or any(not isinstance(value, str) for value in selected)
        or len(selected) != len(set(selected))
        or selected != sorted(selected)
    ):
        raise ResearchAcceptanceError(
            "selected products must be 1-2 unique products in sorted order"
        )
    rows = {
        str(row["product"]): row
        for row in bundle["targets"]
    }
    result: list[dict[str, Any]] = []
    for product in selected:
        if product not in research.PRODUCTS or product not in rows:
            raise ResearchAcceptanceError(
                "selected product is outside the frozen ten-product universe"
            )
        row = rows[product]
        target_delta = (
            int(row["target_quantity"])
            - int(row["previous_target_quantity"])
        )
        if target_delta == 0:
            raise ResearchAcceptanceError(
                "selected product must have a nonzero signed target delta"
            )
        result.append(
            {
                "product": product,
                "exact_contract": row["exact_contract"],
                "previous_target_quantity": row[
                    "previous_target_quantity"
                ],
                "signed_target_quantity": row["target_quantity"],
                "signed_target_delta": target_delta,
                "signed_target_row_sha256": _hash(canonical_json(row)),
            }
        )
    return result


def _verify_time_semantics(
    payload: dict[str, Any],
    installed: InstalledResearchBundle,
    *,
    now: datetime,
) -> None:
    current = now.astimezone(timezone.utc)
    accepted = parse_datetime(payload["accepted_at"], "accepted_at")
    not_before = parse_datetime(payload["not_before"], "not_before")
    expires = parse_datetime(payload["expires_at"], "expires_at")
    if not not_before <= accepted <= expires:
        raise ResearchAcceptanceError(
            "accepted_at must be inside the acceptance validity window"
        )
    if expires - not_before <= timedelta(0) or (
        expires - not_before > MAX_ACCEPTANCE_TTL
    ):
        raise ResearchAcceptanceError(
            "Research Acceptance validity must be positive and at most 15 minutes"
        )
    if current < not_before or current >= expires:
        raise ResearchAcceptanceError(
            "Research Acceptance is not currently valid"
        )
    if accepted > current:
        raise ResearchAcceptanceError(
            "Research Acceptance was accepted in the future"
        )
    bundle = installed.verified.payload
    bundle_not_before = parse_datetime(
        bundle["not_before"],
        "Research bundle not_before",
    )
    bundle_expires = parse_datetime(
        bundle["expires_at"],
        "Research bundle expires_at",
    )
    if not bundle_not_before <= not_before or expires > bundle_expires:
        raise ResearchAcceptanceError(
            "Research Acceptance window must be nested in bundle validity"
        )
    installed_at = parse_datetime(
        installed.receipt["installed_at"],
        "Research install receipt installed_at",
    )
    if installed_at > accepted:
        raise ResearchAcceptanceError(
            "Research Acceptance predates the verified install receipt"
        )
    if payload["execution_day"] != bundle["execution_day"]:
        raise ResearchAcceptanceError(
            "Research Acceptance execution day does not match bundle"
        )
    execution_day = str(payload["execution_day"])
    execution_date = date.fromisoformat(execution_day)
    if not research._timestamp_belongs_to_execution_day(
        accepted, execution_date
    ) or not research._timestamp_belongs_to_execution_day(expires, execution_date):
        raise ResearchAcceptanceError(
            "Research Acceptance must stay on the SimNow execution day"
        )


def _validate_acceptance_semantics(
    payload: dict[str, Any],
    installed: InstalledResearchBundle,
    *,
    expected_acceptance_keyring_raw_sha256: str,
    expected_acceptance_signer_sha256: str,
    expected_simnow_account_sha256: str,
    now: datetime,
) -> None:
    validate_json_schema(
        payload,
        ACCEPTANCE_SCHEMA_PATH,
        "C_FAST SimNow Research Acceptance",
    )
    _reject_pending(payload)
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["purpose"] != PURPOSE
        or payload["candidate_id"] != CANDIDATE_ID
        or payload["parent_issue_number"] != 114
        or payload["issue_number"] != 162
    ):
        raise ResearchAcceptanceError(
            "Research Acceptance identity is invalid"
        )
    if payload["acceptance_state"] != ACCEPTANCE_STATE:
        raise ResearchAcceptanceError(
            "Research Acceptance state is invalid"
        )
    if (
        payload["signer_type"] != "human"
        or not str(payload["reviewer_role"]).strip()
        or not str(payload["human_signature"]).strip()
    ):
        raise ResearchAcceptanceError(
            "Research Acceptance requires a real human reviewer assertion"
        )
    for field in FALSE_AUTHORITY_FIELDS:
        if payload[field] is not False:
            raise ResearchAcceptanceError(f"{field} must remain false")
    if (
        payload["orders_sent"] != 0
        or payload["positions_modified"] != 0
        or payload["web_bridge_rpc_calls"] != 0
    ):
        raise ResearchAcceptanceError(
            "Research Acceptance must have zero execution side effects"
        )
    account_pin = _require_sha256(
        expected_simnow_account_sha256,
        "independently pinned SimNow account",
    )
    _compare(
        str(payload["expected_simnow_account_sha256"]),
        account_pin,
        "SimNow account",
    )
    acceptance_keyring_pin = _require_sha256(
        expected_acceptance_keyring_raw_sha256,
        "independently pinned Control acceptance keyring",
    )
    _compare(
        str(payload["acceptance_keyring_raw_sha256"]),
        acceptance_keyring_pin,
        "Control acceptance keyring",
    )
    signer_pin = _require_sha256(
        expected_acceptance_signer_sha256,
        "independently pinned Control acceptance signer",
    )
    _compare(
        str(payload["acceptance_signer_sha256"]),
        signer_pin,
        "Control acceptance signer source",
    )
    bundle = installed.verified
    expected_bindings = {
        "research_bundle_id": bundle.payload["bundle_id"],
        "research_bundle_raw_sha256": bundle.raw_sha256,
        "research_bundle_canonical_sha256": bundle.canonical_sha256,
        "research_keyring_raw_sha256": bundle.keyring_raw_sha256,
        "research_install_claim_id": installed.claim["install_claim_id"],
        "research_install_claim_raw_sha256": (
            installed.claim_raw_sha256
        ),
        "research_install_claim_canonical_sha256": (
            installed.claim_canonical_sha256
        ),
        "research_install_receipt_raw_sha256": (
            installed.receipt_raw_sha256
        ),
        "research_install_receipt_canonical_sha256": (
            installed.receipt_canonical_sha256
        ),
        "research_artifact_bindings": bundle.payload["artifact_bindings"],
        "research_artifact_index_sha256": bundle.payload[
            "artifact_index_sha256"
        ],
        "formula_target_binding_sha256": bundle.payload[
            "formula_target_binding_sha256"
        ],
        "custody_root_path_sha256": installed.custody.root_path_sha256,
        "custody_identity_sha256": installed.custody.identity_sha256,
        "research_install_files_identity_sha256": (
            installed.install_files_identity_sha256
        ),
    }
    for field, expected in expected_bindings.items():
        if payload[field] != expected:
            raise ResearchAcceptanceError(f"{field} binding mismatch")
    expected_targets = _selected_target_bindings(payload, bundle.payload)
    if payload["selected_targets"] != expected_targets:
        raise ResearchAcceptanceError(
            "selected target rows do not match the signed Research bundle"
        )
    expected_target_index = _hash(canonical_json(expected_targets))
    _compare(
        str(payload["selected_target_index_sha256"]),
        expected_target_index,
        "selected target index",
    )
    for field, expected in _tool_bindings().items():
        _compare(str(payload[field]), expected, field)
    _verify_time_semantics(payload, installed, now=now)
    binding = acceptance_binding_sha256(payload)
    expected_id = f"cfast-simnow-research-accept-v1-{binding}"
    if payload["acceptance_id"] != expected_id:
        raise ResearchAcceptanceError(
            "Research Acceptance ID is not derived from exact bindings"
        )


def prepare_unsigned_acceptance(
    draft: dict[str, Any],
    *,
    custody_root: Path,
    research_keyring_path: Path,
    acceptance_keyring_path: Path,
    artifact_paths: dict[str, Path],
    expected_research_keyring_raw_sha256: str,
    expected_research_signer_sha256: str,
    expected_acceptance_keyring_raw_sha256: str,
    expected_acceptance_signer_sha256: str,
    expected_simnow_account_sha256: str,
    now: datetime,
) -> tuple[
    dict[str, Any],
    Ed25519PublicKey,
    InstalledResearchBundle,
]:
    """Complete every public/custody check before private-key access."""
    if "signature" in draft:
        raise ResearchAcceptanceError(
            "unsigned Research Acceptance must omit signature"
        )
    if "template_state" in draft:
        raise ResearchAcceptanceError(
            "INVALID/PENDING Research Acceptance template cannot be signed"
        )
    bundle_id = str(draft.get("research_bundle_id") or "")
    installed = _verify_install_chain(
        bundle_id=bundle_id,
        custody_root=custody_root,
        research_keyring_path=research_keyring_path,
        artifact_paths=artifact_paths,
        expected_research_keyring_raw_sha256=(
            expected_research_keyring_raw_sha256
        ),
        expected_research_signer_sha256=expected_research_signer_sha256,
        now=now,
    )
    public_key, acceptance_materials, _keyring_raw, keyring_raw_sha256 = (
        _load_keyring(
            acceptance_keyring_path,
            schema_path=KEYRING_SCHEMA_PATH,
            expected_raw_sha256=(
                expected_acceptance_keyring_raw_sha256
            ),
            expected_version=KEYRING_VERSION,
            expected_purpose=KEY_PURPOSE,
            key_id=str(draft.get("signer_key_id") or ""),
            label="C_FAST Control acceptance trusted keyring",
        )
    )
    if public_key is None:
        raise ResearchAcceptanceError(
            "Control acceptance signer key is unavailable"
        )
    _require_disjoint_key_material(
        installed.research_key_materials,
        acceptance_materials,
    )
    account_pin = _require_sha256(
        expected_simnow_account_sha256,
        "independently pinned SimNow account",
    )
    if draft.get("expected_simnow_account_sha256") != account_pin:
        raise ResearchAcceptanceError(
            "unsigned Research Acceptance SimNow account binding mismatch"
        )
    candidate = copy.deepcopy(draft)
    selected_targets = _selected_target_bindings(
        candidate,
        installed.verified.payload,
    )
    candidate.update(
        {
            "research_bundle_raw_sha256": installed.verified.raw_sha256,
            "research_bundle_canonical_sha256": (
                installed.verified.canonical_sha256
            ),
            "research_keyring_raw_sha256": (
                installed.verified.keyring_raw_sha256
            ),
            "research_install_claim_id": installed.claim[
                "install_claim_id"
            ],
            "research_install_claim_raw_sha256": (
                installed.claim_raw_sha256
            ),
            "research_install_claim_canonical_sha256": (
                installed.claim_canonical_sha256
            ),
            "research_install_receipt_raw_sha256": (
                installed.receipt_raw_sha256
            ),
            "research_install_receipt_canonical_sha256": (
                installed.receipt_canonical_sha256
            ),
            "research_artifact_bindings": installed.verified.payload[
                "artifact_bindings"
            ],
            "research_artifact_index_sha256": (
                installed.verified.payload["artifact_index_sha256"]
            ),
            "formula_target_binding_sha256": (
                installed.verified.payload[
                    "formula_target_binding_sha256"
                ]
            ),
            "custody_root_path_sha256": (
                installed.custody.root_path_sha256
            ),
            "custody_identity_sha256": installed.custody.identity_sha256,
            "research_install_files_identity_sha256": (
                installed.install_files_identity_sha256
            ),
            "acceptance_keyring_raw_sha256": keyring_raw_sha256,
            "acceptance_signer_sha256": _require_sha256(
                expected_acceptance_signer_sha256,
                "independently pinned Control acceptance signer",
            ),
            "expected_simnow_account_sha256": account_pin,
            "selected_targets": selected_targets,
            "selected_target_index_sha256": _hash(
                canonical_json(selected_targets)
            ),
            **_tool_bindings(),
        }
    )
    candidate["signature"] = PLACEHOLDER_SIGNATURE
    candidate["acceptance_id"] = (
        "cfast-simnow-research-accept-v1-"
        f"{acceptance_binding_sha256(candidate)}"
    )
    _validate_acceptance_semantics(
        candidate,
        installed,
        expected_acceptance_keyring_raw_sha256=(
            expected_acceptance_keyring_raw_sha256
        ),
        expected_acceptance_signer_sha256=(
            expected_acceptance_signer_sha256
        ),
        expected_simnow_account_sha256=expected_simnow_account_sha256,
        now=now,
    )
    return candidate, public_key, installed


def complete_signature(
    candidate: dict[str, Any],
    public_key: Ed25519PublicKey,
    private_key: Any,
) -> dict[str, Any]:
    expected_public = _public_key_material(public_key)
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise ResearchAcceptanceError(
            "private key does not match trusted Control acceptance signer"
        )
    signed = copy.deepcopy(candidate)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_json(unsigned_acceptance_payload(signed)))
    ).decode("ascii")
    validate_json_schema(
        signed,
        ACCEPTANCE_SCHEMA_PATH,
        "signed C_FAST SimNow Research Acceptance",
    )
    return signed


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
            canonical_json(unsigned_acceptance_payload(payload)),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise ResearchAcceptanceError(
            "Control acceptance signature is invalid"
        ) from exc


def verify_signed_acceptance(
    acceptance_path: Path,
    *,
    custody_root: Path,
    research_keyring_path: Path,
    acceptance_keyring_path: Path,
    artifact_paths: dict[str, Path],
    expected_research_keyring_raw_sha256: str,
    expected_research_signer_sha256: str,
    expected_acceptance_keyring_raw_sha256: str,
    expected_acceptance_signer_sha256: str,
    expected_simnow_account_sha256: str,
    now: datetime,
) -> VerifiedResearchAcceptance:
    payload, raw = _read_canonical_json(
        acceptance_path,
        "signed C_FAST SimNow Research Acceptance",
        limit=MAX_ACCEPTANCE_BYTES,
    )
    if "template_state" in payload:
        raise ResearchAcceptanceError(
            "INVALID/PENDING Research Acceptance template cannot be verified"
        )
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("purpose") != PURPOSE
        or payload.get("candidate_id") != CANDIDATE_ID
    ):
        raise ResearchAcceptanceError(
            "Research Acceptance identity is invalid"
        )
    installed = _verify_install_chain(
        bundle_id=str(payload.get("research_bundle_id") or ""),
        custody_root=custody_root,
        research_keyring_path=research_keyring_path,
        artifact_paths=artifact_paths,
        expected_research_keyring_raw_sha256=(
            expected_research_keyring_raw_sha256
        ),
        expected_research_signer_sha256=expected_research_signer_sha256,
        now=now,
    )
    public_key, acceptance_materials, keyring_raw, keyring_raw_sha256 = (
        _load_keyring(
            acceptance_keyring_path,
            schema_path=KEYRING_SCHEMA_PATH,
            expected_raw_sha256=(
                expected_acceptance_keyring_raw_sha256
            ),
            expected_version=KEYRING_VERSION,
            expected_purpose=KEY_PURPOSE,
            key_id=str(payload.get("signer_key_id") or ""),
            label="C_FAST Control acceptance trusted keyring",
        )
    )
    if public_key is None:
        raise ResearchAcceptanceError(
            "Control acceptance signer key is unavailable"
        )
    _require_disjoint_key_material(
        installed.research_key_materials,
        acceptance_materials,
    )
    _assert_distinct_paths(
        {
            "signed Research Acceptance": acceptance_path,
            "Research install claim": installed.claim_path,
            "installed Research bundle": installed.bundle_path,
            "Research install receipt": installed.receipt_path,
            "Research keyring": research_keyring_path,
            "Control acceptance keyring": acceptance_keyring_path,
            **{
                f"Research artifact {role}": path
                for role, path in artifact_paths.items()
            },
        }
    )
    _validate_acceptance_semantics(
        payload,
        installed,
        expected_acceptance_keyring_raw_sha256=(
            expected_acceptance_keyring_raw_sha256
        ),
        expected_acceptance_signer_sha256=(
            expected_acceptance_signer_sha256
        ),
        expected_simnow_account_sha256=expected_simnow_account_sha256,
        now=now,
    )
    _verify_signature(payload, public_key)
    if read_regular_file_strict(
        acceptance_path,
        "signed C_FAST SimNow Research Acceptance",
        limit=MAX_ACCEPTANCE_BYTES,
        private=True,
    ) != raw:
        raise ResearchAcceptanceError(
            "signed Research Acceptance changed during verification"
        )
    if read_regular_file_strict(
        acceptance_keyring_path,
        "C_FAST Control acceptance trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    ) != keyring_raw:
        raise ResearchAcceptanceError(
            "Control acceptance keyring changed during verification"
        )
    try:
        if research.custody_facts(installed.custody.root) != installed.custody:
            raise ResearchAcceptanceError(
                "Research custody changed during acceptance verification"
            )
    except research.ResearchBundleError as exc:
        raise ResearchAcceptanceError(str(exc)) from exc
    return VerifiedResearchAcceptance(
        payload=payload,
        raw=raw,
        raw_sha256=_hash(raw),
        canonical_sha256=_hash(canonical_json(payload)),
        acceptance_keyring_raw=keyring_raw,
        acceptance_keyring_raw_sha256=keyring_raw_sha256,
        installed=installed,
    )


def _consume_filenames(bundle_id: str) -> tuple[str, str]:
    if re.fullmatch(
        r"cfast-simnow-research-v1-[0-9a-f]{64}",
        bundle_id,
    ) is None:
        raise ResearchAcceptanceError(
            "Research bundle ID is unsafe for acceptance custody filenames"
        )
    return (
        f"{bundle_id}.acceptance-consume.json",
        f"{bundle_id}.acceptance-receipt.json",
    )


def _consume_marker(
    verified: VerifiedResearchAcceptance,
    *,
    consumed_at: datetime,
    receipt_filename: str,
) -> dict[str, Any]:
    payload = verified.payload
    installed = verified.installed
    marker = {
        "schema_version": CONSUME_VERSION,
        "purpose": "c_fast_simnow_research_acceptance_one_shot_consume",
        "candidate_id": CANDIDATE_ID,
        "acceptance_id": payload["acceptance_id"],
        "consume_id": "PENDING_DERIVED",
        "consumed_at": consumed_at.astimezone(timezone.utc).isoformat(),
        "execution_day": payload["execution_day"],
        "not_before": payload["not_before"],
        "expires_at": payload["expires_at"],
        "research_bundle_id": payload["research_bundle_id"],
        "acceptance_raw_sha256": verified.raw_sha256,
        "acceptance_canonical_sha256": verified.canonical_sha256,
        "research_bundle_raw_sha256": (
            installed.verified.raw_sha256
        ),
        "research_bundle_canonical_sha256": (
            installed.verified.canonical_sha256
        ),
        "research_install_claim_raw_sha256": (
            installed.claim_raw_sha256
        ),
        "research_install_receipt_raw_sha256": (
            installed.receipt_raw_sha256
        ),
        "research_artifact_index_sha256": payload[
            "research_artifact_index_sha256"
        ],
        "formula_target_binding_sha256": payload[
            "formula_target_binding_sha256"
        ],
        "research_keyring_raw_sha256": payload[
            "research_keyring_raw_sha256"
        ],
        "acceptance_keyring_raw_sha256": (
            verified.acceptance_keyring_raw_sha256
        ),
        "expected_simnow_account_sha256": payload[
            "expected_simnow_account_sha256"
        ],
        "selected_products": payload["selected_products"],
        "selected_target_index_sha256": payload[
            "selected_target_index_sha256"
        ],
        "custody_root_path_sha256": installed.custody.root_path_sha256,
        "custody_identity_sha256": installed.custody.identity_sha256,
        "receipt_filename": receipt_filename,
        "acceptance_state": ACCEPTANCE_STATE,
        "acceptance_is_deployment_authority": False,
        "acceptance_is_execution_authority": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "production_allowed": False,
        "deployment_authorized": False,
        "execution_permit_issued": False,
        "simnow_execution_authorized": False,
        "runtime_activation_authorized": False,
        "network_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_authorized": False,
        "order_submission_authorized": False,
        "position_read_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "replacement_authorized": False,
        "production_authorized": False,
        "automatic_promotion_authorized": False,
        "dynamic_selection_allowed": False,
        "replay_allowed": False,
        "account_data_read": False,
        "execution_data_read": False,
        "orders_sent": 0,
        "positions_modified": 0,
        "web_bridge_rpc_calls": 0,
    }
    binding = {
        key: value
        for key, value in marker.items()
        if key != "consume_id"
    }
    marker["consume_id"] = (
        "cfast-simnow-research-accept-consume-v1-"
        f"{_hash(canonical_json(binding))}"
    )
    return marker


def _acceptance_receipt(
    verified: VerifiedResearchAcceptance,
    marker: dict[str, Any],
    marker_raw: bytes,
    *,
    final_revalidated_at: datetime,
    ready_at: datetime,
    consume_filename: str,
) -> dict[str, Any]:
    payload = verified.payload
    installed = verified.installed
    return {
        "schema_version": RECEIPT_VERSION,
        "purpose": (
            "c_fast_simnow_research_acceptance_create_only_receipt"
        ),
        "candidate_id": CANDIDATE_ID,
        "acceptance_id": payload["acceptance_id"],
        "consume_id": marker["consume_id"],
        "consumed_at": marker["consumed_at"],
        "final_revalidated_at": (
            final_revalidated_at.astimezone(timezone.utc).isoformat()
        ),
        "ready_at": ready_at.astimezone(timezone.utc).isoformat(),
        "execution_day": payload["execution_day"],
        "research_bundle_id": payload["research_bundle_id"],
        "acceptance_raw_sha256": verified.raw_sha256,
        "acceptance_canonical_sha256": verified.canonical_sha256,
        "consume_raw_sha256": _hash(marker_raw),
        "consume_canonical_sha256": _hash(canonical_json(marker)),
        "consume_filename": consume_filename,
        "research_bundle_raw_sha256": (
            installed.verified.raw_sha256
        ),
        "research_install_claim_raw_sha256": (
            installed.claim_raw_sha256
        ),
        "research_install_receipt_raw_sha256": (
            installed.receipt_raw_sha256
        ),
        "research_artifact_index_sha256": payload[
            "research_artifact_index_sha256"
        ],
        "formula_target_binding_sha256": payload[
            "formula_target_binding_sha256"
        ],
        "expected_simnow_account_sha256": payload[
            "expected_simnow_account_sha256"
        ],
        "selected_products": payload["selected_products"],
        "selected_target_index_sha256": payload[
            "selected_target_index_sha256"
        ],
        "custody_root_path_sha256": installed.custody.root_path_sha256,
        "custody_identity_sha256": installed.custody.identity_sha256,
        "acceptance_state": ACCEPTANCE_STATE,
        "acceptance_is_deployment_authority": False,
        "acceptance_is_execution_authority": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "production_allowed": False,
        "deployment_authorized": False,
        "execution_permit_issued": False,
        "simnow_execution_authorized": False,
        "runtime_activation_authorized": False,
        "network_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_authorized": False,
        "order_submission_authorized": False,
        "position_read_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "replacement_authorized": False,
        "production_authorized": False,
        "automatic_promotion_authorized": False,
        "dynamic_selection_allowed": False,
        "replay_allowed": False,
        "account_data_read": False,
        "execution_data_read": False,
        "orders_sent": 0,
        "positions_modified": 0,
        "web_bridge_rpc_calls": 0,
    }


def _validate_receipt_chronology(
    receipt: dict[str, Any],
    acceptance_payload: dict[str, Any],
    marker: dict[str, Any],
) -> None:
    accepted_at = parse_datetime(
        acceptance_payload["accepted_at"],
        "accepted_at",
    )
    consumed_at = parse_datetime(receipt["consumed_at"], "consumed_at")
    final_revalidated_at = parse_datetime(
        receipt["final_revalidated_at"],
        "final_revalidated_at",
    )
    ready_at = parse_datetime(receipt["ready_at"], "ready_at")
    expires_at = parse_datetime(
        acceptance_payload["expires_at"],
        "expires_at",
    )
    if receipt["consumed_at"] != marker["consumed_at"] or not (
        accepted_at
        <= consumed_at
        <= final_revalidated_at
        <= ready_at
        < expires_at
    ):
        raise ResearchAcceptanceError(
            "Research Acceptance receipt chronology is invalid"
        )


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ResearchAcceptanceError(
            f"cannot inspect one-shot output {path.name}: {exc}"
        ) from exc
    return True


def _assert_exact_snapshot_current(
    verified: VerifiedResearchAcceptance,
    *,
    acceptance_path: Path,
    research_keyring_path: Path,
    acceptance_keyring_path: Path,
    artifact_paths: dict[str, Path],
) -> None:
    installed = verified.installed
    exact_files = (
        (
            acceptance_path,
            "signed C_FAST SimNow Research Acceptance",
            verified.raw,
            MAX_ACCEPTANCE_BYTES,
        ),
        (
            installed.bundle_path,
            "installed C_FAST Research bundle",
            installed.verified.raw,
            2 * 1024 * 1024,
        ),
        (
            installed.claim_path,
            "C_FAST Research install claim",
            installed.claim_raw,
            MAX_JSON_BYTES,
        ),
        (
            installed.receipt_path,
            "C_FAST Research install receipt",
            installed.receipt_raw,
            MAX_JSON_BYTES,
        ),
    )
    for path, label, expected, limit in exact_files:
        observed = read_regular_file_strict(
            path,
            label,
            limit=limit,
            private=True,
        )
        if observed != expected:
            raise ResearchAcceptanceError(
                f"{label} changed before acceptance receipt"
            )
    research_keyring_raw = read_regular_file_strict(
        research_keyring_path,
        "C_FAST Research trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    if research_keyring_raw != installed.research_keyring_raw:
        raise ResearchAcceptanceError(
            "Research keyring changed before acceptance receipt"
        )
    acceptance_keyring_raw = read_regular_file_strict(
        acceptance_keyring_path,
        "C_FAST Control acceptance trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    if acceptance_keyring_raw != verified.acceptance_keyring_raw:
        raise ResearchAcceptanceError(
            "Control acceptance keyring changed before acceptance receipt"
        )
    try:
        artifact_raw = research._read_artifacts(artifact_paths)
    except research.ResearchBundleError as exc:
        raise ResearchAcceptanceError(str(exc)) from exc
    if artifact_raw != installed.verified.artifact_raw:
        raise ResearchAcceptanceError(
            "Research artifacts changed before acceptance receipt"
        )
    try:
        current_custody = research.custody_facts(installed.custody.root)
    except research.ResearchBundleError as exc:
        raise ResearchAcceptanceError(str(exc)) from exc
    if current_custody != installed.custody:
        raise ResearchAcceptanceError(
            "Research custody changed before acceptance receipt"
        )
    current_file_identity = _custody_files_identity_sha256(
        current_custody,
        {
            "install_claim": installed.claim_path,
            "installed_bundle": installed.bundle_path,
            "install_receipt": installed.receipt_path,
        },
    )
    _compare(
        current_file_identity,
        installed.install_files_identity_sha256,
        "Research custody files final snapshot",
    )


def consume_signed_acceptance(
    acceptance_path: Path,
    *,
    custody_root: Path,
    research_keyring_path: Path,
    acceptance_keyring_path: Path,
    artifact_paths: dict[str, Path],
    expected_research_keyring_raw_sha256: str,
    expected_research_signer_sha256: str,
    expected_acceptance_keyring_raw_sha256: str,
    expected_acceptance_signer_sha256: str,
    expected_simnow_account_sha256: str,
    clock: Callable[[], datetime] = utc_now,
) -> tuple[Path, Path]:
    base_verify_kwargs = {
        "custody_root": custody_root,
        "research_keyring_path": research_keyring_path,
        "acceptance_keyring_path": acceptance_keyring_path,
        "artifact_paths": artifact_paths,
        "expected_research_keyring_raw_sha256": (
            expected_research_keyring_raw_sha256
        ),
        "expected_research_signer_sha256": (
            expected_research_signer_sha256
        ),
        "expected_acceptance_keyring_raw_sha256": (
            expected_acceptance_keyring_raw_sha256
        ),
        "expected_acceptance_signer_sha256": (
            expected_acceptance_signer_sha256
        ),
        "expected_simnow_account_sha256": (
            expected_simnow_account_sha256
        ),
    }
    initial_now = _clock_now(clock)
    verified = verify_signed_acceptance(
        acceptance_path,
        **base_verify_kwargs,
        now=initial_now,
    )
    marker_now = _clock_now_not_before(
        clock,
        initial_now,
        stage="consume marker preparation",
    )
    accepted_at = parse_datetime(
        verified.payload["accepted_at"],
        "accepted_at",
    )
    if marker_now < accepted_at:
        raise ResearchAcceptanceError(
            "consume marker cannot predate human acceptance"
        )
    marker_verified = verify_signed_acceptance(
        acceptance_path,
        **base_verify_kwargs,
        now=marker_now,
    )
    if marker_verified != verified:
        raise ResearchAcceptanceError(
            "Research Acceptance inputs changed before consume marker"
        )
    verified = marker_verified
    custody = verified.installed.custody
    consume_name, receipt_name = _consume_filenames(
        str(verified.payload["research_bundle_id"])
    )
    consume_path = custody.root / consume_name
    receipt_path = custody.root / receipt_name
    if _path_exists(receipt_path) and not _path_exists(consume_path):
        raise ResearchAcceptanceError(
            "acceptance receipt exists without a consume marker"
        )
    if _path_exists(consume_path):
        raise ResearchAcceptanceError(
            "acceptance consume marker already exists; replay is forbidden"
        )
    if _path_exists(receipt_path):
        raise ResearchAcceptanceError(
            "acceptance receipt already exists; replay is forbidden"
        )
    input_paths = {
        acceptance_path.resolve(),
        research_keyring_path.resolve(),
        acceptance_keyring_path.resolve(),
        *(path.resolve() for path in artifact_paths.values()),
        verified.installed.claim_path,
        verified.installed.bundle_path,
        verified.installed.receipt_path,
    }
    if consume_path in input_paths or receipt_path in input_paths:
        raise ResearchAcceptanceError(
            "one-shot outputs must not overlap verified inputs"
        )
    marker = _consume_marker(
        verified,
        consumed_at=marker_now,
        receipt_filename=receipt_name,
    )
    validate_json_schema(
        marker,
        CONSUME_SCHEMA_PATH,
        "C_FAST Research Acceptance consume marker",
    )
    marker_raw = canonical_json(marker) + b"\n"
    try:
        custody_fd = research._open_custody_root(custody)
    except research.ResearchBundleError as exc:
        raise ResearchAcceptanceError(str(exc)) from exc
    try:
        try:
            research._custody_write_create_only(
                custody_fd,
                custody,
                consume_name,
                marker_raw,
                label="C_FAST Research Acceptance consume marker",
            )
        except research.ResearchBundleError as exc:
            raise ResearchAcceptanceError(str(exc)) from exc
        # The consume marker is deliberately irreversible. Every public input
        # is re-verified before a receipt can be created.
        post_marker_now = _clock_now_not_before(
            clock,
            marker_now,
            stage="post-marker revalidation",
        )
        reverified = verify_signed_acceptance(
            acceptance_path,
            **base_verify_kwargs,
            now=post_marker_now,
        )
        if reverified != verified:
            raise ResearchAcceptanceError(
                "Research Acceptance inputs changed after consume marker"
            )
        observed_marker = read_regular_file_strict(
            consume_path,
            "C_FAST Research Acceptance consume marker",
            private=True,
        )
        if observed_marker != marker_raw:
            raise ResearchAcceptanceError(
                "Research Acceptance consume marker changed before receipt"
            )
        _assert_exact_snapshot_current(
            reverified,
            acceptance_path=acceptance_path,
            research_keyring_path=research_keyring_path,
            acceptance_keyring_path=acceptance_keyring_path,
            artifact_paths=artifact_paths,
        )
        final_revalidated_at = _clock_now_not_before(
            clock,
            post_marker_now,
            stage="final receipt revalidation",
        )
        _verify_time_semantics(
            reverified.payload,
            reverified.installed,
            now=final_revalidated_at,
        )
        observed_marker = read_regular_file_strict(
            consume_path,
            "C_FAST Research Acceptance consume marker",
            private=True,
        )
        if observed_marker != marker_raw:
            raise ResearchAcceptanceError(
                "Research Acceptance consume marker changed at receipt commit"
            )
        receipt_commit_started_at = _clock_now_not_before(
            clock,
            final_revalidated_at,
            stage="receipt commit",
        )
        _verify_time_semantics(
            reverified.payload,
            reverified.installed,
            now=receipt_commit_started_at,
        )
        receipt = _acceptance_receipt(
            reverified,
            marker,
            marker_raw,
            final_revalidated_at=final_revalidated_at,
            ready_at=receipt_commit_started_at,
            consume_filename=consume_name,
        )
        _validate_receipt_chronology(
            receipt,
            reverified.payload,
            marker,
        )
        validate_json_schema(
            receipt,
            RECEIPT_SCHEMA_PATH,
            "C_FAST Research Acceptance receipt",
        )
        receipt_created = False
        try:
            research._custody_write_create_only(
                custody_fd,
                custody,
                receipt_name,
                canonical_json(receipt) + b"\n",
                label="C_FAST Research Acceptance receipt",
            )
            receipt_created = True
            receipt_commit_completed_at = _clock_now_not_before(
                clock,
                receipt_commit_started_at,
                stage="receipt commit completion",
            )
            _verify_time_semantics(
                reverified.payload,
                reverified.installed,
                now=receipt_commit_completed_at,
            )
            if research.custody_facts(custody.root) != custody:
                raise ResearchAcceptanceError(
                    "Research custody changed during acceptance consumption"
                )
        except Exception as exc:
            if receipt_created:
                try:
                    os.unlink(receipt_name, dir_fd=custody_fd)
                    os.fsync(custody_fd)
                except OSError as cleanup_exc:
                    raise ResearchAcceptanceError(
                        "receipt commit validation failed and the "
                        "uncommitted receipt could not be removed"
                    ) from cleanup_exc
            if isinstance(exc, research.ResearchBundleError):
                raise ResearchAcceptanceError(str(exc)) from exc
            raise
    finally:
        os.close(custody_fd)
    return consume_path, receipt_path


def add_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    research.add_artifact_arguments(parser)


def artifact_paths_from_args(
    args: argparse.Namespace,
) -> dict[str, Path]:
    return research.artifact_paths_from_args(args)


def _add_common_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_acceptance: bool,
) -> None:
    if include_acceptance:
        parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--custody-root", type=Path, required=True)
    parser.add_argument(
        "--research-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-research-keyring-raw-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-research-signer-sha256",
        required=True,
    )
    parser.add_argument(
        "--acceptance-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-acceptance-keyring-raw-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-acceptance-signer-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-simnow-account-sha256",
        required=True,
    )
    add_artifact_arguments(parser)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    _add_common_arguments(verify, include_acceptance=True)
    consume = commands.add_parser("consume")
    _add_common_arguments(consume, include_acceptance=True)
    return parser.parse_args()


def _verification_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "custody_root": args.custody_root,
        "research_keyring_path": args.research_trusted_keyring,
        "acceptance_keyring_path": args.acceptance_trusted_keyring,
        "artifact_paths": artifact_paths_from_args(args),
        "expected_research_keyring_raw_sha256": (
            args.expected_research_keyring_raw_sha256
        ),
        "expected_research_signer_sha256": (
            args.expected_research_signer_sha256
        ),
        "expected_acceptance_keyring_raw_sha256": (
            args.expected_acceptance_keyring_raw_sha256
        ),
        "expected_acceptance_signer_sha256": (
            args.expected_acceptance_signer_sha256
        ),
        "expected_simnow_account_sha256": (
            args.expected_simnow_account_sha256
        ),
    }


def main() -> int:
    args = parse_args()
    try:
        kwargs = _verification_kwargs(args)
        if args.command == "consume":
            consume_path, receipt_path = consume_signed_acceptance(
                args.acceptance,
                **kwargs,
                clock=utc_now,
            )
            print(f"consume marker: {consume_path}")
            print(f"acceptance receipt: {receipt_path}")
        else:
            verified = verify_signed_acceptance(
                args.acceptance,
                **kwargs,
                now=utc_now(),
            )
            print(f"acceptance_id: {verified.payload['acceptance_id']}")
    except (
        ResearchAcceptanceError,
        research.ResearchBundleError,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"C_FAST Research Acceptance verification failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"acceptance_state: {ACCEPTANCE_STATE}")
    print("simnow_execution_authorized: false")
    print("trading_authorized: false")
    print("production_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
