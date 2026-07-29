#!/usr/bin/env python3
"""Verify or install one non-countable C_FAST SimNow research bundle."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any
from zoneinfo import ZoneInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
BUNDLE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-simnow-research-bundle-v1.schema.json"
)
KEYRING_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-simnow-research-bundle-trusted-keys-v1.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-simnow-research-bundle-install-receipt-v1.schema.json"
)

SCHEMA_VERSION = "commodity_c_fast_simnow_research_bundle_v1"
PURPOSE = "NON_COUNTABLE_SIMNOW_EXERCISE_ONLY"
KEYRING_VERSION = (
    "commodity_c_fast_simnow_research_bundle_trusted_keys_v1"
)
KEY_PURPOSE = "c_fast_simnow_research_bundle_signer"
RECEIPT_VERSION = (
    "commodity_c_fast_simnow_research_bundle_install_receipt_v1"
)
INSTALL_CLAIM_VERSION = (
    "commodity_c_fast_simnow_research_bundle_install_claim_v1"
)
CUSTODY_OWNER_UID = 0
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
FROZEN_RULE_SHA256 = (
    "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
)
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_TTL = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
CHINA_TZ = ZoneInfo("Asia/Shanghai")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

ARTIFACT_ROLES = (
    "freeze_contract",
    "research_manifest",
    "signal_evidence",
    "target_evidence",
    "allocation_evidence",
    "daily_roll_evidence",
    "reference_price_evidence",
    "calendar_authority",
    "contract_spec_evidence",
)

PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
SECTOR_MAP_ID = "COMMODITY_FROZEN_SECTOR_MAP_V1"
SECTOR_MAP = {
    "ag": "precious",
    "al": "nonferrous",
    "au": "precious",
    "bu": "energy_chemical",
    "cu": "nonferrous",
    "rb": "ferrous",
    "ru": "energy_chemical",
    "sc": "energy",
    "sp": "light_industry",
    "zn": "nonferrous",
}
PRODUCT_SPECS = {
    "ag": {"exchange": "SHFE", "multiplier": 15, "price_tick": 1.0},
    "al": {"exchange": "SHFE", "multiplier": 5, "price_tick": 5.0},
    "au": {"exchange": "SHFE", "multiplier": 1000, "price_tick": 0.02},
    "bu": {"exchange": "SHFE", "multiplier": 10, "price_tick": 1.0},
    "cu": {"exchange": "SHFE", "multiplier": 5, "price_tick": 10.0},
    "rb": {"exchange": "SHFE", "multiplier": 10, "price_tick": 1.0},
    "ru": {"exchange": "SHFE", "multiplier": 10, "price_tick": 5.0},
    "sc": {"exchange": "INE", "multiplier": 1000, "price_tick": 0.1},
    "sp": {"exchange": "SHFE", "multiplier": 10, "price_tick": 2.0},
    "zn": {"exchange": "SHFE", "multiplier": 5, "price_tick": 5.0},
}

FALSE_AUTHORITY_FIELDS = (
    "bundle_is_execution_authority",
    "countable_forward",
    "official_forward_claimed",
    "simnow_execution_authorized",
    "runtime_activation_authorized",
    "network_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
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


class ResearchBundleError(RuntimeError):
    """Expected fail-closed research-bundle error."""


@dataclass(frozen=True)
class VerifiedResearchBundle:
    payload: dict[str, Any]
    raw: bytes
    raw_sha256: str
    canonical_sha256: str
    keyring_raw_sha256: str
    artifact_raw: dict[str, bytes]


@dataclass(frozen=True)
class CustodyFacts:
    root: Path
    root_path_sha256: str
    identity_sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compare(actual: str, expected: str, label: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise ResearchBundleError(f"{label} binding mismatch")


def _require_sha256(value: Any, label: str) -> str:
    text = str(value)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise ResearchBundleError(f"{label} must be one lowercase SHA256")
    return text


def _close(left: Any, right: Any, *, tolerance: float = 1e-12) -> bool:
    try:
        left_value = float(left)
        right_value = float(right)
    except (TypeError, ValueError) as exc:
        raise ResearchBundleError("research bundle contains a non-number") from exc
    return (
        math.isfinite(left_value)
        and math.isfinite(right_value)
        and math.isclose(
            left_value,
            right_value,
            rel_tol=0,
            abs_tol=tolerance,
        )
    )


def unsigned_bundle_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def formula_target_binding_payload(
    payload: dict[str, Any],
) -> dict[str, Any]:
    excluded = {
        "bundle_id",
        "formula_target_binding_sha256",
        "signer_key_id",
        "signature",
    }
    return {
        key: copy.deepcopy(value)
        for key, value in payload.items()
        if key not in excluded
    }


def formula_target_binding_sha256(payload: dict[str, Any]) -> str:
    return _hash(canonical_json(formula_target_binding_payload(payload)))


def artifact_bindings(artifact_raw: dict[str, bytes]) -> dict[str, Any]:
    _validate_artifact_roles(artifact_raw)
    return {
        role: {
            "bytes": len(artifact_raw[role]),
            "raw_sha256": _hash(artifact_raw[role]),
        }
        for role in ARTIFACT_ROLES
    }


def artifact_index_sha256(bindings: dict[str, Any]) -> str:
    return _hash(canonical_json(bindings))


def _validate_artifact_roles(values: dict[str, Any]) -> None:
    if set(values) != set(ARTIFACT_ROLES):
        raise ResearchBundleError("research artifact role set is incomplete")


def _read_artifacts(paths: dict[str, Path]) -> dict[str, bytes]:
    _validate_artifact_roles(paths)
    identities: dict[str, tuple[Path, tuple[int, int], tuple[int, int, int, int]]] = {}
    resolved_seen: set[Path] = set()
    inode_seen: set[tuple[int, int]] = set()
    for role in ARTIFACT_ROLES:
        path = paths[role]
        try:
            resolved = path.resolve(strict=True)
            info = path.lstat()
        except OSError as exc:
            raise ResearchBundleError(
                f"C_FAST research artifact {role} is unavailable"
            ) from exc
        if not stat.S_ISREG(info.st_mode):
            raise ResearchBundleError(
                f"C_FAST research artifact {role} must be a regular non-symlink file"
            )
        inode = (info.st_dev, info.st_ino)
        if resolved in resolved_seen or inode in inode_seen:
            raise ResearchBundleError(
                "research artifact roles must use distinct paths and inodes"
            )
        resolved_seen.add(resolved)
        inode_seen.add(inode)
        identities[role] = (
            resolved,
            inode,
            (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode),
        )
    result: dict[str, bytes] = {}
    total = 0
    for role in ARTIFACT_ROLES:
        raw = read_regular_file_strict(
            paths[role],
            f"C_FAST research artifact {role}",
            limit=MAX_ARTIFACT_BYTES,
        )
        if not raw:
            raise ResearchBundleError(
                f"C_FAST research artifact {role} must not be empty"
            )
        total += len(raw)
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise ResearchBundleError(
                "C_FAST research artifacts exceed aggregate safety limit"
            )
        result[role] = raw
    for role in ARTIFACT_ROLES:
        try:
            final_resolved = paths[role].resolve(strict=True)
            final = paths[role].lstat()
        except OSError as exc:
            raise ResearchBundleError(
                f"C_FAST research artifact {role} changed while being read"
            ) from exc
        before_resolved, before_inode, before_metadata = identities[role]
        if (
            final_resolved != before_resolved
            or (final.st_dev, final.st_ino) != before_inode
            or (
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
                final.st_mode,
            )
            != before_metadata
        ):
            raise ResearchBundleError(
                f"C_FAST research artifact {role} changed while being read"
            )
    return result


def custody_facts(path: Path) -> CustodyFacts:
    expanded = path.expanduser()
    root = expanded if expanded.is_absolute() else Path.cwd() / expanded
    normalized = Path(os.path.normpath(str(root)))
    try:
        resolved = root.resolve(strict=True)
        info = root.lstat()
    except OSError as exc:
        raise ResearchBundleError("custody root is unavailable") from exc
    if normalized != root or resolved != root:
        raise ResearchBundleError(
            "custody root must be absolute, normalized and symlink-free"
        )
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != CUSTODY_OWNER_UID
        or mode & 0o022
    ):
        raise ResearchBundleError(
            "custody root must be root-owned and not group/world writable"
        )
    root_path_sha256 = _hash(str(root).encode("utf-8"))
    identity = {
        "root_path_sha256": root_path_sha256,
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "mode": mode,
    }
    return CustodyFacts(
        root=root,
        root_path_sha256=root_path_sha256,
        identity_sha256=_hash(canonical_json(identity)),
        device=info.st_dev,
        inode=info.st_ino,
        owner_uid=info.st_uid,
        mode=mode,
    )


def _tool_bindings() -> dict[str, str]:
    paths = {
        "verifier_sha256": VERIFIER_PATH,
        "bundle_schema_sha256": BUNDLE_SCHEMA_PATH,
        "trusted_keyring_schema_sha256": KEYRING_SCHEMA_PATH,
        "install_receipt_schema_sha256": RECEIPT_SCHEMA_PATH,
    }
    result: dict[str, str] = {}
    for field, path in paths.items():
        result[field] = _hash(
            read_regular_file_strict(
                path,
                f"C_FAST research bundle {field}",
                limit=MAX_JSON_BYTES,
            )
        )
    return result


def _load_keyring(
    path: Path,
    *,
    expected_raw_sha256: str,
    key_id: str,
) -> tuple[Ed25519PublicKey, bytes, str]:
    expected = _require_sha256(
        expected_raw_sha256,
        "independently pinned research-bundle keyring",
    )
    raw = read_regular_file_strict(
        path,
        "C_FAST research-bundle trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    )
    raw_sha256 = _hash(raw)
    _compare(
        raw_sha256,
        expected,
        "C_FAST research-bundle trusted keyring raw pin",
    )
    payload = parse_json_bytes(
        raw,
        "C_FAST research-bundle trusted keyring",
    )
    validate_json_schema(
        payload,
        KEYRING_SCHEMA_PATH,
        "C_FAST research-bundle trusted keyring",
    )
    keys = payload["keys"]
    if len({str(entry["key_id"]) for entry in keys}) != len(keys):
        raise ResearchBundleError("research-bundle key IDs must be unique")
    materials: set[bytes] = set()
    selected: Ed25519PublicKey | None = None
    for entry in keys:
        try:
            material = base64.b64decode(
                str(entry["public_key_base64"]),
                validate=True,
            )
            if len(material) != 32:
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(material)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ResearchBundleError(
                "research-bundle public key is invalid"
            ) from exc
        if material in materials:
            raise ResearchBundleError(
                "research-bundle keyring reuses public-key material"
            )
        materials.add(material)
        if entry["key_id"] == key_id:
            selected = public_key
    if selected is None:
        raise ResearchBundleError(
            "research-bundle signer key is not trusted"
        )
    return selected, raw, raw_sha256


def _reject_pending(value: Any) -> None:
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise ResearchBundleError("PENDING values cannot be verified or signed")
    if isinstance(value, dict):
        for child in value.values():
            _reject_pending(child)
    elif isinstance(value, list):
        for child in value:
            _reject_pending(child)


def _parse_date(value: Any, label: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ResearchBundleError(f"{label} must be an ISO date") from exc


def _verify_time_semantics(
    payload: dict[str, Any],
    *,
    now: datetime,
) -> None:
    current = now.astimezone(timezone.utc)
    generated = parse_datetime(payload["generated_at"], "generated_at")
    not_before = parse_datetime(payload["not_before"], "not_before")
    expires = parse_datetime(payload["expires_at"], "expires_at")
    if not not_before <= generated <= expires:
        raise ResearchBundleError(
            "generated_at must be inside the signed validity window"
        )
    if expires - not_before <= timedelta(0) or expires - not_before > MAX_BUNDLE_TTL:
        raise ResearchBundleError(
            "research-bundle validity must be positive and at most 24 hours"
        )
    if current < not_before or current > expires:
        raise ResearchBundleError("research bundle is not currently valid")
    if generated > current + MAX_CLOCK_SKEW:
        raise ResearchBundleError("research bundle was generated in the future")
    execution_day = _parse_date(payload["execution_day"], "execution_day")
    source_day = _parse_date(
        payload["research_as_of_official_day"],
        "research_as_of_official_day",
    )
    if source_day >= execution_day:
        raise ResearchBundleError(
            "research source day must precede the SimNow execution day"
        )
    if generated.astimezone(CHINA_TZ).date() != execution_day:
        raise ResearchBundleError(
            "research bundle must be generated on its execution day"
        )
    if expires.astimezone(CHINA_TZ).date() != execution_day:
        raise ResearchBundleError(
            "research bundle must expire on its execution day"
        )


def _verify_weight_caps(
    weights: dict[str, float],
    *,
    product_cap: float,
    sector_cap: float,
    gross_cap: float,
) -> None:
    values = list(weights.values())
    if any(not math.isfinite(value) for value in values):
        raise ResearchBundleError("target weight must be finite")
    if max(abs(value) for value in values) > product_cap + 1e-12:
        raise ResearchBundleError("target product cap is breached")
    if sum(abs(value) for value in values) > gross_cap + 1e-12:
        raise ResearchBundleError("target portfolio gross cap is breached")
    if abs(sum(values)) > 1e-10:
        raise ResearchBundleError("target portfolio must be dollar neutral")
    for sector in set(SECTOR_MAP.values()):
        gross = sum(
            abs(weights[product])
            for product in PRODUCTS
            if SECTOR_MAP[product] == sector
        )
        if gross > sector_cap + 1e-12:
            raise ResearchBundleError("target sector gross cap is breached")


def _verify_target_row(
    row: dict[str, Any],
    *,
    execution_day: date,
    generated_at: datetime,
) -> None:
    product = str(row["product"])
    spec = PRODUCT_SPECS[product]
    if row["sector"] != SECTOR_MAP[product]:
        raise ResearchBundleError("target sector does not match frozen map")
    pattern = rf"{spec['exchange']}\.{product}\d{{4}}"
    if re.fullmatch(pattern, str(row["exact_contract"])) is None:
        raise ResearchBundleError("target exact contract is invalid")
    if row["pit_main_exact_contract"] != row["exact_contract"]:
        raise ResearchBundleError("PIT-main exact contract binding mismatch")
    if row["previous_exact_contract"] is not None:
        raise ResearchBundleError(
            "v1 SimNow research bundle must use cold-start previous contracts"
        )
    if row["previous_target_quantity"] != 0 or row["pit_main_roll"]:
        raise ResearchBundleError(
            "v1 SimNow research bundle must use cold-start previous targets"
        )
    if row["multiplier"] != spec["multiplier"] or not _close(
        row["price_tick"],
        spec["price_tick"],
    ):
        raise ResearchBundleError("frozen contract spec mismatch")
    expected_score = (
        int(row["trend_21_sign"])
        + int(row["trend_63_sign"])
        + int(row["trend_126_sign"])
    ) / 3.0
    if not _close(row["source_score"], expected_score):
        raise ResearchBundleError("source score formula mismatch")
    expected_raw = expected_score / max(
        float(row["vol60_annualized"]),
        0.05,
    )
    if not _close(row["raw_risk_score"], expected_raw):
        raise ResearchBundleError("raw risk score formula mismatch")
    quantity = int(row["target_quantity"])
    buffered = float(row["buffered_target_weight"])
    if quantity and (
        buffered == 0
        or math.copysign(1, quantity) != math.copysign(1, buffered)
    ):
        raise ResearchBundleError("integer target direction mismatch")
    observed = parse_datetime(
        row["reference_price_observed_at"],
        f"{product}.reference_price_observed_at",
    )
    if observed.astimezone(CHINA_TZ).date() != execution_day:
        raise ResearchBundleError("reference open is not from execution day")
    if observed > generated_at:
        raise ResearchBundleError(
            "reference open was observed after bundle generation"
        )
    last_trading_day = _parse_date(
        row["pit_main_official_last_trading_day"],
        f"{product}.pit_main_official_last_trading_day",
    )
    following_day = _parse_date(
        row["pit_main_following_official_day"],
        f"{product}.pit_main_following_official_day",
    )
    if following_day <= execution_day:
        raise ResearchBundleError("PIT following official day is invalid")
    if row["pit_main_dte"] != (last_trading_day - execution_day).days:
        raise ResearchBundleError("PIT-main DTE arithmetic mismatch")
    if row["pit_main_following_dte"] != (
        last_trading_day - following_day
    ).days:
        raise ResearchBundleError("PIT-main following-DTE arithmetic mismatch")


def _verify_targets(payload: dict[str, Any]) -> None:
    rows = sorted(payload["targets"], key=lambda row: str(row["product"]))
    products = tuple(str(row["product"]) for row in rows)
    if products != PRODUCTS or len(products) != len(set(products)):
        raise ResearchBundleError("target universe must contain exact ten products")
    execution_day = _parse_date(payload["execution_day"], "execution_day")
    generated = parse_datetime(payload["generated_at"], "generated_at")
    for row in rows:
        _verify_target_row(
            row,
            execution_day=execution_day,
            generated_at=generated,
        )
    source_weights = {
        str(row["product"]): float(row["source_target_weight"])
        for row in rows
    }
    buffered_weights = {
        str(row["product"]): float(row["buffered_target_weight"])
        for row in rows
    }
    _verify_weight_caps(
        source_weights,
        product_cap=0.20,
        sector_cap=0.35,
        gross_cap=1.0,
    )
    _verify_weight_caps(
        buffered_weights,
        product_cap=0.12,
        sector_cap=0.27,
        gross_cap=0.80,
    )
    exposures = {
        str(row["product"]): (
            int(row["target_quantity"])
            * float(row["reference_open_price"])
            * int(row["multiplier"])
            / int(payload["virtual_nav_cny"])
        )
        for row in rows
    }
    if max(abs(value) for value in exposures.values()) >= 0.15 - 1e-12:
        raise ResearchBundleError("integer product hard cap is breached")
    if sum(abs(value) for value in exposures.values()) >= 1.0 - 1e-12:
        raise ResearchBundleError("integer portfolio gross cap is breached")
    if abs(sum(exposures.values())) >= 0.10 - 1e-12:
        raise ResearchBundleError("integer portfolio net cap is breached")
    for sector in set(SECTOR_MAP.values()):
        gross = sum(
            abs(exposures[product])
            for product in PRODUCTS
            if SECTOR_MAP[product] == sector
        )
        if gross >= 0.35 - 1e-12:
            raise ResearchBundleError("integer sector gross cap is breached")


def validate_bundle_semantics(
    payload: dict[str, Any],
    artifact_raw: dict[str, bytes],
    *,
    expected_signer_sha256: str,
    now: datetime,
) -> None:
    validate_json_schema(
        payload,
        BUNDLE_SCHEMA_PATH,
        "C_FAST SimNow research bundle",
    )
    _reject_pending(payload)
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ResearchBundleError("research-bundle schema version mismatch")
    if payload["purpose"] != PURPOSE or payload["candidate_id"] != CANDIDATE_ID:
        raise ResearchBundleError("research-bundle identity mismatch")
    if payload["frozen_rule_sha256"] != FROZEN_RULE_SHA256:
        raise ResearchBundleError("frozen-rule identity mismatch")
    for field in FALSE_AUTHORITY_FIELDS:
        if payload[field] is not False:
            raise ResearchBundleError(f"{field} must remain false")
    if payload["orders_sent"] != 0 or payload["positions_modified"] != 0:
        raise ResearchBundleError("research bundle must have zero side effects")
    signer_pin = _require_sha256(
        expected_signer_sha256,
        "independently pinned research-bundle signer",
    )
    _compare(
        str(payload["signer_sha256"]),
        signer_pin,
        "research-bundle signer source",
    )
    expected_bindings = artifact_bindings(artifact_raw)
    if payload["artifact_bindings"] != expected_bindings:
        raise ResearchBundleError("raw research artifact binding mismatch")
    expected_index = artifact_index_sha256(expected_bindings)
    _compare(
        str(payload["artifact_index_sha256"]),
        expected_index,
        "research artifact index",
    )
    tools = _tool_bindings()
    for field, expected in tools.items():
        _compare(str(payload[field]), expected, field)
    _verify_time_semantics(payload, now=now)
    _verify_targets(payload)
    binding = formula_target_binding_sha256(payload)
    _compare(
        str(payload["formula_target_binding_sha256"]),
        binding,
        "formula/target",
    )
    if payload["bundle_id"] != f"cfast-simnow-research-v1-{binding}":
        raise ResearchBundleError("bundle_id is not derived from exact binding")


def prepare_unsigned_bundle(
    draft: dict[str, Any],
    keyring_path: Path,
    artifact_paths: dict[str, Path],
    *,
    expected_keyring_raw_sha256: str,
    expected_signer_sha256: str,
    expected_custody_root_path_sha256: str,
    expected_custody_identity_sha256: str,
    now: datetime,
) -> tuple[dict[str, Any], Ed25519PublicKey, dict[str, bytes]]:
    """Finish all public checks before any private key is loaded."""
    if "signature" in draft:
        raise ResearchBundleError("unsigned research bundle must omit signature")
    if "template_state" in draft:
        raise ResearchBundleError("INVALID/PENDING template cannot be signed")
    artifact_raw = _read_artifacts(artifact_paths)
    candidate = copy.deepcopy(draft)
    candidate["artifact_bindings"] = artifact_bindings(artifact_raw)
    candidate["artifact_index_sha256"] = artifact_index_sha256(
        candidate["artifact_bindings"]
    )
    candidate.update(_tool_bindings())
    candidate["signer_sha256"] = _require_sha256(
        expected_signer_sha256,
        "independently pinned research-bundle signer",
    )
    candidate["custody_root_path_sha256"] = _require_sha256(
        expected_custody_root_path_sha256,
        "independently pinned custody root path",
    )
    candidate["custody_identity_sha256"] = _require_sha256(
        expected_custody_identity_sha256,
        "independently pinned custody identity",
    )
    public_key, _keyring_raw, keyring_raw_sha256 = _load_keyring(
        keyring_path,
        expected_raw_sha256=expected_keyring_raw_sha256,
        key_id=str(candidate.get("signer_key_id") or ""),
    )
    candidate["trusted_keyring_raw_sha256"] = keyring_raw_sha256
    candidate["formula_target_binding_sha256"] = (
        formula_target_binding_sha256(candidate)
    )
    candidate["bundle_id"] = (
        "cfast-simnow-research-v1-"
        f"{candidate['formula_target_binding_sha256']}"
    )
    candidate["signature"] = PLACEHOLDER_SIGNATURE
    validate_bundle_semantics(
        candidate,
        artifact_raw,
        expected_signer_sha256=expected_signer_sha256,
        now=now,
    )
    return candidate, public_key, artifact_raw


def complete_signature(
    candidate: dict[str, Any],
    public_key: Ed25519PublicKey,
    private_key: Any,
) -> dict[str, Any]:
    expected_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    actual_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public != expected_public:
        raise ResearchBundleError(
            "private key does not match trusted research-bundle signer"
        )
    signed = copy.deepcopy(candidate)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_json(unsigned_bundle_payload(signed)))
    ).decode("ascii")
    validate_json_schema(
        signed,
        BUNDLE_SCHEMA_PATH,
        "signed C_FAST SimNow research bundle",
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
            canonical_json(unsigned_bundle_payload(payload)),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        raise ResearchBundleError(
            "research-bundle signature is invalid"
        ) from exc


def verify_signed_bundle(
    bundle_path: Path,
    keyring_path: Path,
    artifact_paths: dict[str, Path],
    *,
    expected_keyring_raw_sha256: str,
    expected_signer_sha256: str,
    now: datetime,
) -> VerifiedResearchBundle:
    bundle_raw = read_regular_file_strict(
        bundle_path,
        "signed C_FAST SimNow research bundle",
        limit=2 * 1024 * 1024,
        private=True,
    )
    payload = parse_json_bytes(
        bundle_raw,
        "signed C_FAST SimNow research bundle",
    )
    if bundle_raw != canonical_json(payload) + b"\n":
        raise ResearchBundleError(
            "signed research bundle must use exact canonical JSON bytes"
        )
    artifact_raw = _read_artifacts(artifact_paths)
    public_key, keyring_raw, keyring_raw_sha256 = _load_keyring(
        keyring_path,
        expected_raw_sha256=expected_keyring_raw_sha256,
        key_id=str(payload.get("signer_key_id") or ""),
    )
    _compare(
        str(payload.get("trusted_keyring_raw_sha256")),
        keyring_raw_sha256,
        "research-bundle keyring",
    )
    validate_bundle_semantics(
        payload,
        artifact_raw,
        expected_signer_sha256=expected_signer_sha256,
        now=now,
    )
    _verify_signature(payload, public_key)
    if read_regular_file_strict(
        bundle_path,
        "signed C_FAST SimNow research bundle",
        limit=2 * 1024 * 1024,
        private=True,
    ) != bundle_raw:
        raise ResearchBundleError(
            "signed research bundle changed during verification"
        )
    if read_regular_file_strict(
        keyring_path,
        "C_FAST research-bundle trusted keyring",
        limit=MAX_JSON_BYTES,
        private=True,
    ) != keyring_raw:
        raise ResearchBundleError(
            "research-bundle keyring changed during verification"
        )
    final_artifacts = _read_artifacts(artifact_paths)
    if final_artifacts != artifact_raw:
        raise ResearchBundleError(
            "research artifact changed during bundle verification"
        )
    return VerifiedResearchBundle(
        payload=payload,
        raw=bundle_raw,
        raw_sha256=_hash(bundle_raw),
        canonical_sha256=_hash(canonical_json(payload)),
        keyring_raw_sha256=keyring_raw_sha256,
        artifact_raw=artifact_raw,
    )


def _normalized_private_output(path: Path, label: str) -> Path:
    expanded = path.expanduser()
    output = expanded if expanded.is_absolute() else Path.cwd() / expanded
    normalized = Path(os.path.normpath(str(output)))
    if normalized != output:
        raise ResearchBundleError(f"{label} path must already be normalized")
    parent = output.parent.resolve(strict=True)
    if output.parent != parent:
        raise ResearchBundleError(
            f"{label} parent must not traverse a symlink"
        )
    info = parent.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ResearchBundleError(
            f"{label} parent must be a pre-existing private owned directory"
        )
    target = parent / output.name
    try:
        target.lstat()
    except FileNotFoundError:
        return target
    except OSError as exc:
        raise ResearchBundleError(f"cannot inspect {label}: {exc}") from exc
    raise ResearchBundleError(f"{label} already exists")


def write_bytes_create_only_verified(
    path: Path,
    raw: bytes,
    *,
    label: str,
) -> Path:
    output = _normalized_private_output(path, label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory_fd = os.open(output.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    observed = read_regular_file_strict(
        output,
        label,
        limit=max(len(raw), MAX_JSON_BYTES),
        private=True,
    )
    if observed != raw:
        raise ResearchBundleError(f"{label} changed after create-only write")
    return output


def write_json_create_only_verified(
    path: Path,
    payload: dict[str, Any],
    *,
    label: str,
) -> Path:
    raw = canonical_json(payload) + b"\n"
    output = write_bytes_create_only_verified(path, raw, label=label)
    reparsed = parse_json_bytes(raw, label)
    if reparsed != payload:
        raise ResearchBundleError(f"{label} did not round-trip exactly")
    return output


def _install_receipt(
    verified: VerifiedResearchBundle,
    installed_path: Path,
    *,
    install_claim_id: str,
    install_claim_raw_sha256: str,
    custody: CustodyFacts,
    installed_at: datetime,
) -> dict[str, Any]:
    payload = verified.payload
    return {
        "schema_version": RECEIPT_VERSION,
        "purpose": (
            "c_fast_simnow_research_bundle_create_only_install_receipt"
        ),
        "candidate_id": CANDIDATE_ID,
        "bundle_id": payload["bundle_id"],
        "installed_at": installed_at.astimezone(timezone.utc).isoformat(),
        "installed_path_sha256": _hash(
            str(installed_path).encode("utf-8")
        ),
        "install_claim_id": install_claim_id,
        "install_claim_raw_sha256": install_claim_raw_sha256,
        "custody_root_path_sha256": custody.root_path_sha256,
        "custody_identity_sha256": custody.identity_sha256,
        "installed_bundle_bytes": len(verified.raw),
        "bundle_raw_sha256": verified.raw_sha256,
        "bundle_canonical_sha256": verified.canonical_sha256,
        "trusted_keyring_raw_sha256": verified.keyring_raw_sha256,
        "artifact_index_sha256": payload["artifact_index_sha256"],
        "formula_target_binding_sha256": (
            payload["formula_target_binding_sha256"]
        ),
        "signer_key_id": payload["signer_key_id"],
        "installer_verifier_sha256": payload["verifier_sha256"],
        "bundle_schema_sha256": payload["bundle_schema_sha256"],
        "trusted_keyring_schema_sha256": (
            payload["trusted_keyring_schema_sha256"]
        ),
        "install_receipt_schema_sha256": (
            payload["install_receipt_schema_sha256"]
        ),
        "installation_state": (
            "RESEARCH_BUNDLE_INSTALLED_NO_RUNTIME_AUTHORITY"
        ),
        "receipt_is_execution_authority": False,
        "countable_forward": False,
        "simnow_execution_authorized": False,
        "runtime_activation_authorized": False,
        "network_authorized": False,
        "web_bridge_rpc_authorized": False,
        "order_submission_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "replay_allowed": False,
    }


def _custody_filenames(bundle_id: str) -> tuple[str, str, str]:
    if re.fullmatch(r"cfast-simnow-research-v1-[0-9a-f]{64}", bundle_id) is None:
        raise ResearchBundleError("bundle_id is unsafe for custody filenames")
    return (
        f"{bundle_id}.install-claim.json",
        f"{bundle_id}.bundle.json",
        f"{bundle_id}.install-receipt.json",
    )


def _assert_custody_binding(
    expected: CustodyFacts,
    payload: dict[str, Any],
) -> CustodyFacts:
    current = custody_facts(expected.root)
    if current != expected:
        raise ResearchBundleError(
            "custody root path or identity changed during installation"
        )
    _compare(
        current.root_path_sha256,
        str(payload["custody_root_path_sha256"]),
        "signed custody root path",
    )
    _compare(
        current.identity_sha256,
        str(payload["custody_identity_sha256"]),
        "signed custody identity",
    )
    return current


def _open_custody_root(custody: CustodyFacts) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(custody.root, flags)
    info = os.fstat(descriptor)
    if (info.st_dev, info.st_ino) != (custody.device, custody.inode):
        os.close(descriptor)
        raise ResearchBundleError(
            "custody root identity changed before installation"
        )
    return descriptor


def _custody_write_create_only(
    custody_fd: int,
    custody: CustodyFacts,
    filename: str,
    raw: bytes,
    *,
    label: str,
) -> Path:
    if "/" in filename or filename in {"", ".", ".."}:
        raise ResearchBundleError(f"{label} filename is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            filename,
            flags,
            0o600,
            dir_fd=custody_fd,
        )
    except FileExistsError as exc:
        raise ResearchBundleError(
            f"{label} already exists; replay is forbidden"
        ) from exc
    except OSError as exc:
        raise ResearchBundleError(f"cannot create {label}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    os.fsync(custody_fd)
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    read_flags |= getattr(os, "O_NOFOLLOW", 0)
    observed_fd = os.open(filename, read_flags, dir_fd=custody_fd)
    try:
        info = os.fstat(observed_fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ResearchBundleError(
                f"{label} is not one private regular file"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(observed_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max(len(raw), MAX_JSON_BYTES):
                raise ResearchBundleError(f"{label} exceeds readback limit")
            chunks.append(chunk)
    finally:
        os.close(observed_fd)
    if b"".join(chunks) != raw:
        raise ResearchBundleError(f"{label} changed after create-only write")
    return custody.root / filename


def _install_claim(
    verified: VerifiedResearchBundle,
    custody: CustodyFacts,
    *,
    installed_filename: str,
    receipt_filename: str,
) -> dict[str, Any]:
    payload = {
        "schema_version": INSTALL_CLAIM_VERSION,
        "purpose": "c_fast_simnow_research_bundle_one_shot_install_claim",
        "bundle_id": verified.payload["bundle_id"],
        "bundle_raw_sha256": verified.raw_sha256,
        "bundle_canonical_sha256": verified.canonical_sha256,
        "artifact_index_sha256": verified.payload["artifact_index_sha256"],
        "custody_root_path_sha256": custody.root_path_sha256,
        "custody_identity_sha256": custody.identity_sha256,
        "installed_bundle_filename": installed_filename,
        "install_receipt_filename": receipt_filename,
    }
    payload["install_claim_id"] = (
        "cfast-simnow-install-claim-v1-"
        + _hash(canonical_json(payload))
    )
    return payload


def install_verified_bundle(
    verified: VerifiedResearchBundle,
    *,
    source_bundle_path: Path,
    keyring_path: Path,
    artifact_paths: dict[str, Path],
    custody_root: Path,
    expected_keyring_raw_sha256: str,
    expected_signer_sha256: str,
    now: datetime,
) -> tuple[Path, Path]:
    source_raw = read_regular_file_strict(
        source_bundle_path,
        "source signed C_FAST SimNow research bundle",
        limit=2 * 1024 * 1024,
        private=True,
    )
    if source_raw != verified.raw:
        raise ResearchBundleError(
            "source signed research bundle changed before installation"
        )
    custody = custody_facts(custody_root)
    _assert_custody_binding(custody, verified.payload)
    claim_filename, installed_filename, receipt_filename = _custody_filenames(
        str(verified.payload["bundle_id"])
    )
    claim_path = custody.root / claim_filename
    installed = custody.root / installed_filename
    receipt_output = custody.root / receipt_filename
    inputs = {
        source_bundle_path.resolve(),
        keyring_path.resolve(),
        *(path.resolve() for path in artifact_paths.values()),
        VERIFIER_PATH.resolve(),
        BUNDLE_SCHEMA_PATH.resolve(),
        KEYRING_SCHEMA_PATH.resolve(),
        RECEIPT_SCHEMA_PATH.resolve(),
    }
    if {claim_path, installed, receipt_output} & inputs:
        raise ResearchBundleError("install outputs must not overlap any input")
    custody_fd = _open_custody_root(custody)
    try:
        claim = _install_claim(
            verified,
            custody,
            installed_filename=installed_filename,
            receipt_filename=receipt_filename,
        )
        claim_raw = canonical_json(claim) + b"\n"
        _custody_write_create_only(
            custody_fd,
            custody,
            claim_filename,
            claim_raw,
            label="C_FAST research-bundle install claim",
        )
        _assert_custody_binding(custody, verified.payload)
        _custody_write_create_only(
            custody_fd,
            custody,
            installed_filename,
            verified.raw,
            label="installed C_FAST research bundle",
        )
        _assert_custody_binding(custody, verified.payload)
        installed_verified = verify_signed_bundle(
            installed,
            keyring_path,
            artifact_paths,
            expected_keyring_raw_sha256=expected_keyring_raw_sha256,
            expected_signer_sha256=expected_signer_sha256,
            now=now,
        )
        if (
            installed_verified.raw_sha256 != verified.raw_sha256
            or installed_verified.payload != verified.payload
        ):
            raise ResearchBundleError(
                "installed research bundle differs from verified source"
            )
        _assert_custody_binding(custody, verified.payload)
        receipt = _install_receipt(
            verified,
            installed,
            install_claim_id=claim["install_claim_id"],
            install_claim_raw_sha256=_hash(claim_raw),
            custody=custody,
            installed_at=now,
        )
        validate_json_schema(
            receipt,
            RECEIPT_SCHEMA_PATH,
            "C_FAST research-bundle install receipt",
        )
        _assert_custody_binding(custody, verified.payload)
        _custody_write_create_only(
            custody_fd,
            custody,
            receipt_filename,
            canonical_json(receipt) + b"\n",
            label="C_FAST research-bundle install receipt",
        )
        _assert_custody_binding(custody, verified.payload)
    finally:
        os.close(custody_fd)
    return installed, receipt_output


def add_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    for role in ARTIFACT_ROLES:
        parser.add_argument(
            f"--{role.replace('_', '-')}",
            dest=role,
            type=Path,
            required=True,
        )


def artifact_paths_from_args(args: argparse.Namespace) -> dict[str, Path]:
    return {role: getattr(args, role) for role in ARTIFACT_ROLES}


def _add_verification_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-trusted-keyring-raw-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-signer-sha256",
        required=True,
        help="independently pinned raw SHA256 of the offline signer source",
    )
    add_artifact_arguments(parser)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pins = commands.add_parser("custody-pins")
    pins.add_argument("--custody-root", type=Path, required=True)
    verify = commands.add_parser("verify")
    _add_verification_arguments(verify)
    install = commands.add_parser("install")
    _add_verification_arguments(install)
    install.add_argument("--custody-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "custody-pins":
        try:
            facts = custody_facts(args.custody_root)
        except (ResearchBundleError, OSError, ValueError) as exc:
            print(f"C_FAST custody pin derivation failed: {exc}", file=sys.stderr)
            return 2
        print(
            canonical_json(
                {
                    "custody_root": str(facts.root),
                    "custody_root_path_sha256": facts.root_path_sha256,
                    "custody_identity_sha256": facts.identity_sha256,
                    "owner_uid": facts.owner_uid,
                    "mode": f"{facts.mode:04o}",
                }
            ).decode("utf-8")
        )
        return 0
    now = datetime.now(timezone.utc)
    artifact_paths = artifact_paths_from_args(args)
    try:
        verified = verify_signed_bundle(
            args.bundle,
            args.trusted_keyring,
            artifact_paths,
            expected_keyring_raw_sha256=(
                args.expected_trusted_keyring_raw_sha256
            ),
            expected_signer_sha256=args.expected_signer_sha256,
            now=now,
        )
        if args.command == "install":
            installed, receipt = install_verified_bundle(
                verified,
                source_bundle_path=args.bundle,
                keyring_path=args.trusted_keyring,
                artifact_paths=artifact_paths,
                custody_root=args.custody_root,
                expected_keyring_raw_sha256=(
                    args.expected_trusted_keyring_raw_sha256
                ),
                expected_signer_sha256=args.expected_signer_sha256,
                now=now,
            )
            print(f"installed research bundle: {installed}")
            print(f"install receipt: {receipt}")
    except (
        ResearchBundleError,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"C_FAST research-bundle verification failed: {exc}", file=sys.stderr)
        return 2
    print(f"bundle_id: {verified.payload['bundle_id']}")
    print("countable_forward: false")
    print("simnow_execution_authorized: false")
    print("production_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
