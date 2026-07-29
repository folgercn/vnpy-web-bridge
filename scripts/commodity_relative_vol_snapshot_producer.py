#!/usr/bin/env python3
"""Pure Research producer for MONTHLY_RELATIVE_VOL_THERMOSTAT_V1.

The producer accepts one bounded PIT source view, independently recomputes the
frozen baseline guardband and 20m integer allocation, calculates strictly
lagged 21/126-day sample volatility, then emits:

* an unsigned ``commodity_relative_vol_position_manager_shadow_v2`` draft; and
* schema-distinct, non-authoritative producer evidence.

It owns no acquisition, signing, installation, Control Plane, network, RPC,
gateway, order, position mutation, or Execution Plane capability.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import calendar
from dataclasses import dataclass
from datetime import date, datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Mapping
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_pure_producer_kernel as frozen  # noqa: E402


SOURCE_SCHEMA_VERSION = "commodity_relative_vol_position_manager_source_view_v1"
SOURCE_PURPOSE = "VERIFIED_BOUNDED_PIT_BASELINE_INPUT_ONLY"
SOURCE_STATUS = "VERIFIED_BOUNDED_PIT_BASELINE_VIEW"
SNAPSHOT_SCHEMA_VERSION = "commodity_relative_vol_position_manager_shadow_v2"
EVIDENCE_SCHEMA_VERSION = (
    "commodity_relative_vol_position_manager_producer_evidence_v1"
)
PRODUCER_ID = "commodity_relative_vol_snapshot_producer_v1"
POSITION_MANAGER_ID = "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1"
BASELINE_SCHEDULER_ID = "STATIC_CORE_EQUAL"
SECTOR_MAP_ID = "POSITION_MANAGER_SECTOR_MAP_V1"
GENESIS_SOURCE_MONTH = "2026-08"

FAST_LOOKBACK_DAYS = 21
SLOW_LOOKBACK_DAYS = 126
ANNUALIZATION_DAYS = 252
SAMPLE_DDOF = 1
SCALE_MIN = 0.8
SCALE_MAX = 1.2
SMOOTHING_ALPHA = 0.5

MAX_SOURCE_VIEW_RAW_BYTES = 4 * 1024 * 1024
CHINA_TZ = ZoneInfo("Asia/Shanghai")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MONTH_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}$")
CONTRACT_PATTERN = re.compile(r"^(SHFE|INE)\.([a-z]{2})([0-9]{4})$")

FALSE_AUTHORITY_FIELDS = (
    "acceptance_authorized",
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "simnow_execution_authorized",
    "runtime_activation_authorized",
    "network_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "production_authorized",
    "automatic_promotion_authorized",
)

BASELINE_BATCH_FIELDS = {
    "schema_version",
    "batch_id",
    "scheduler_id",
    "source_combination_arm",
    "execution_lane",
    "source_month",
    "execution_day",
    "virtual_nav_cny",
    "candidate_weights",
    "guardband",
    "allocator",
    "previous_batch_hash",
    "targets",
    "signer_key_id",
    "signature",
}
BASELINE_TARGET_FIELDS = {
    "product",
    "previous_exact_contract",
    "previous_target_quantity",
    "exact_contract",
    "target_quantity",
    "source_target_weight",
    "buffered_target_weight",
    "reference_open_price",
    "multiplier",
    "price_tick",
}
PREVIOUS_SNAPSHOT_FIELDS = {
    "schema_version",
    "snapshot_id",
    "position_manager_id",
    "sector_map_id",
    "mode",
    "execution_lane",
    "countable_forward",
    "baseline_scheduler_id",
    "baseline_batch_hash",
    "source_month",
    "execution_day",
    "input_cutoff_day",
    "fast_lookback_days",
    "slow_lookback_days",
    "annualization_days",
    "fast_annual_vol",
    "slow_annual_vol",
    "scale_min",
    "scale_max",
    "raw_scale",
    "continuity_mode",
    "previous_snapshot_hash",
    "previous_smoothed_scale",
    "smoothing_alpha",
    "smoothed_scale",
    "daily_auto_reweight",
    "guardband_reapplied",
    "authority_granted",
    "dispatch_allowed",
    "targets",
    "signer_key_id",
    "signature",
}
PREVIOUS_TARGET_FIELDS = {
    "product",
    "exact_contract",
    "baseline_target_quantity",
    "shadow_target_quantity",
    "baseline_source_target_weight",
    "shadow_source_target_weight",
    "baseline_buffered_target_weight",
    "shadow_buffered_target_weight",
    "reference_open_price",
    "multiplier",
    "price_tick",
}


class SnapshotProducerError(ValueError):
    """Expected fail-closed source, continuity, or calculation failure."""


@dataclass(frozen=True)
class ProducerResult:
    source_view_canonical_sha256: str
    snapshot_draft_sha256: str
    snapshot_draft: bytes
    evidence: bytes


def canonical_json(payload: Any) -> bytes:
    """Return deterministic UTF-8 JSON while rejecting NaN and Infinity."""

    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SnapshotProducerError("payload is not canonical finite JSON") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise SnapshotProducerError(f"source JSON constant {value!r} is forbidden")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotProducerError(f"source JSON has duplicate key: {key}")
        result[key] = value
    return result


def _bounded_source_input(
    source_view: Mapping[str, Any] | bytes | bytearray,
) -> dict[str, Any]:
    if isinstance(source_view, (bytes, bytearray)):
        raw = bytes(source_view)
        if len(raw) > MAX_SOURCE_VIEW_RAW_BYTES:
            raise SnapshotProducerError("source-view raw bytes exceeds resource limit")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except SnapshotProducerError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SnapshotProducerError("source-view raw bytes are not strict JSON") from exc
        if not isinstance(value, dict):
            raise SnapshotProducerError("source-view JSON root must be one object")
        source = value
    elif isinstance(source_view, Mapping):
        source = dict(source_view)
    else:
        raise SnapshotProducerError(
            "source view must be one mapping or bounded JSON bytes"
        )
    if len(canonical_json(source)) > MAX_SOURCE_VIEW_RAW_BYTES:
        raise SnapshotProducerError("source-view canonical bytes exceeds resource limit")
    return source


def _exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotProducerError(f"{label} must be one object")
    if set(value) != fields:
        raise SnapshotProducerError(
            f"{label} field set mismatch: "
            f"missing={sorted(fields - set(value))}, "
            f"extra={sorted(set(value) - fields)}"
        )
    return value


def _stable_id(value: Any, label: str) -> str:
    text = str(value)
    if ID_PATTERN.fullmatch(text) is None:
        raise SnapshotProducerError(f"{label} must be one stable id")
    return text


def _sha256_text(value: Any, label: str) -> str:
    text = str(value)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise SnapshotProducerError(f"{label} must be one lowercase SHA256")
    return text


def _key_id(value: Any, label: str) -> str:
    text = str(value)
    if KEY_ID_PATTERN.fullmatch(text) is None:
        raise SnapshotProducerError(f"{label} must be one key id")
    return text


def _iso_date(value: Any, label: str) -> date:
    text = str(value)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise SnapshotProducerError(f"{label} must be an ISO date") from exc
    if parsed.isoformat() != text:
        raise SnapshotProducerError(f"{label} must use canonical ISO date form")
    return parsed


def _iso_datetime(value: Any, label: str) -> datetime:
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotProducerError(f"{label} must be an ISO datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SnapshotProducerError(f"{label} must be timezone-aware")
    return parsed


def _source_month(value: Any, label: str) -> str:
    text = str(value)
    if MONTH_PATTERN.fullmatch(text) is None:
        raise SnapshotProducerError(f"{label} must be YYYY-MM")
    try:
        year, month = (int(item) for item in text.split("-"))
        if not 1 <= month <= 12:
            raise ValueError("month outside range")
        date(year, month, 1)
    except ValueError as exc:
        raise SnapshotProducerError(f"{label} month is invalid") from exc
    return text


def _next_month(value: str) -> str:
    year, month = (int(item) for item in value.split("-"))
    return f"{year + (month == 12):04d}-{1 if month == 12 else month + 1:02d}"


def _finite(value: Any, label: str) -> float:
    if isinstance(value, bool):
        raise SnapshotProducerError(f"{label} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise SnapshotProducerError(f"{label} must be numeric") from exc
    if not math.isfinite(parsed):
        raise SnapshotProducerError(f"{label} must be finite")
    return parsed


def _finite_positive(value: Any, label: str) -> float:
    parsed = _finite(value, label)
    if parsed <= 0:
        raise SnapshotProducerError(f"{label} must be positive")
    return parsed


def _strict_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SnapshotProducerError(f"{label} must be one integer")
    return value


def _signature_shape(value: Any, label: str) -> str:
    text = str(value)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SnapshotProducerError(f"{label} must be canonical base64") from exc
    if len(raw) != 64:
        raise SnapshotProducerError(f"{label} must contain 64 bytes")
    return text


def _exact_contract(
    value: Any,
    *,
    product: str,
    exchange: str,
    label: str,
) -> str:
    text = str(value)
    match = CONTRACT_PATTERN.fullmatch(text)
    if match is None or match.group(1) != exchange or match.group(2) != product:
        raise SnapshotProducerError(f"{label} is outside the frozen product identity")
    return text


def _close(left: float, right: float, *, tolerance: float = 1e-12) -> bool:
    return math.isclose(left, right, rel_tol=0.0, abs_tol=tolerance)


def _sample_annual_vol(values: list[float], label: str) -> float:
    if len(values) < 2:
        raise SnapshotProducerError(f"{label} needs at least two observations")
    mean = math.fsum(values) / len(values)
    variance = math.fsum((value - mean) ** 2 for value in values) / (
        len(values) - SAMPLE_DDOF
    )
    annual_vol = math.sqrt(variance) * math.sqrt(ANNUALIZATION_DAYS)
    if not math.isfinite(annual_vol) or annual_vol <= 0:
        raise SnapshotProducerError(f"{label} volatility must be finite and positive")
    return annual_vol


def _validate_daily_returns(
    source: dict[str, Any],
    *,
    input_cutoff_day: date,
    execution_day: date,
) -> tuple[list[dict[str, Any]], list[float]]:
    raw_official_days = source["official_days"]
    raw_returns = source["baseline_daily_returns"]
    if not isinstance(raw_official_days, list) or not isinstance(raw_returns, list):
        raise SnapshotProducerError(
            "official_days and baseline_daily_returns must be arrays"
        )
    if (
        len(raw_official_days) != SLOW_LOOKBACK_DAYS
        or len(raw_returns) != SLOW_LOOKBACK_DAYS
    ):
        raise SnapshotProducerError(
            "exactly 126 official daily returns are required"
        )
    official_days = [
        _iso_date(value, f"official_days[{index}]")
        for index, value in enumerate(raw_official_days)
    ]
    if official_days != sorted(set(official_days)):
        raise SnapshotProducerError(
            "official_days must be strictly increasing and unique"
        )
    if official_days[-1] > input_cutoff_day or any(
        item >= execution_day for item in official_days
    ):
        raise SnapshotProducerError(
            "daily returns contain lookahead beyond the strict PIT cutoff"
        )

    normalized: list[dict[str, Any]] = []
    values: list[float] = []
    for index, raw in enumerate(raw_returns):
        row = _exact_object(
            raw,
            {"official_day", "daily_return"},
            f"baseline_daily_returns[{index}]",
        )
        observed_day = _iso_date(
            row["official_day"],
            f"baseline_daily_returns[{index}].official_day",
        )
        if observed_day != official_days[index]:
            raise SnapshotProducerError(
                "baseline daily returns are missing or not aligned to official_days"
            )
        value = _finite(
            row["daily_return"],
            f"baseline_daily_returns[{index}].daily_return",
        )
        normalized.append(
            {"official_day": observed_day.isoformat(), "daily_return": value}
        )
        values.append(value)
    return normalized, values


def _validate_baseline_batch(
    raw_batch: Any,
    *,
    claimed_hash: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], frozen.Allocation]:
    batch = _exact_object(raw_batch, BASELINE_BATCH_FIELDS, "baseline_batch")
    if batch["schema_version"] != "commodity_static_core_equal_target_batch_v2":
        raise SnapshotProducerError("baseline batch schema version mismatch")
    _stable_id(batch["batch_id"], "baseline_batch.batch_id")
    if (
        batch["scheduler_id"] != BASELINE_SCHEDULER_ID
        or batch["source_combination_arm"] != "CORE_EQUAL_TARGET"
    ):
        raise SnapshotProducerError("baseline strategy identity mismatch")
    if batch["execution_lane"] not in {"official_forward", "simnow_shakedown"}:
        raise SnapshotProducerError("baseline execution lane is invalid")
    source_month = _source_month(
        batch["source_month"], "baseline_batch.source_month"
    )
    execution_day = _iso_date(
        batch["execution_day"], "baseline_batch.execution_day"
    )
    if execution_day.strftime("%Y-%m") != _next_month(source_month):
        raise SnapshotProducerError(
            "baseline execution day must be in the next source month"
        )
    if batch["virtual_nav_cny"] != frozen.VIRTUAL_NAV_CNY:
        raise SnapshotProducerError("baseline virtual NAV is not frozen at 20m")
    if batch["candidate_weights"] != {"C": 0.5, "D": 0.5}:
        raise SnapshotProducerError("baseline candidate weights are not frozen")
    if batch["guardband"] != {
        "product": 0.12,
        "sector": 0.27,
        "gross": 0.8,
        "target_net": 0.0,
    }:
        raise SnapshotProducerError("baseline guardband identity mismatch")
    if batch["allocator"] != {
        "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
        "neighbourhood_radius_lots": 2,
        "beam_width": 2048,
        "net_error_penalty": 1.0,
        "monthly_target_dates_only": True,
        "daily_auto_reweight": False,
        "roll_preserves_integer_lots": True,
    }:
        raise SnapshotProducerError("baseline allocator identity mismatch")
    previous_batch_hash = batch["previous_batch_hash"]
    if previous_batch_hash is not None:
        _sha256_text(previous_batch_hash, "baseline_batch.previous_batch_hash")
    _key_id(batch["signer_key_id"], "baseline_batch.signer_key_id")
    _signature_shape(batch["signature"], "baseline_batch.signature")

    canonical_payload = canonical_json(
        {key: value for key, value in batch.items() if key != "signature"}
    )
    if _sha256(canonical_payload) != claimed_hash:
        raise SnapshotProducerError("baseline batch hash tamper detected")

    raw_targets = batch["targets"]
    if not isinstance(raw_targets, list) or len(raw_targets) != len(frozen.PRODUCTS):
        raise SnapshotProducerError("baseline must contain the frozen ten targets")
    by_product: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_targets):
        row = _exact_object(
            raw, BASELINE_TARGET_FIELDS, f"baseline_batch.targets[{index}]"
        )
        product = str(row["product"])
        if product not in frozen.PRODUCTS or product in by_product:
            raise SnapshotProducerError(
                "baseline targets must contain each frozen product exactly once"
            )
        spec = frozen.PRODUCT_SPECS[product]
        previous_exact = row["previous_exact_contract"]
        if previous_exact is not None:
            _exact_contract(
                previous_exact,
                product=product,
                exchange=spec["exchange"],
                label="baseline previous exact contract",
            )
        exact_contract = _exact_contract(
            row["exact_contract"],
            product=product,
            exchange=spec["exchange"],
            label="baseline exact contract",
        )
        previous_quantity = _strict_integer(
            row["previous_target_quantity"], "baseline previous target quantity"
        )
        target_quantity = _strict_integer(
            row["target_quantity"], "baseline target quantity"
        )
        if max(abs(previous_quantity), abs(target_quantity)) > frozen.MAX_ABS_TARGET_QUANTITY:
            raise SnapshotProducerError("baseline target quantity exceeds frozen lot cap")
        source_weight = _finite(
            row["source_target_weight"], "baseline source target weight"
        )
        buffered_weight = _finite(
            row["buffered_target_weight"], "baseline buffered target weight"
        )
        reference_price = _finite_positive(
            row["reference_open_price"], "baseline reference open price"
        )
        multiplier = _strict_integer(row["multiplier"], "baseline multiplier")
        price_tick = _finite_positive(row["price_tick"], "baseline price tick")
        if multiplier != spec["multiplier"] or not _close(
            price_tick, float(spec["price_tick"])
        ):
            raise SnapshotProducerError("baseline contract spec identity mismatch")
        by_product[product] = {
            "product": product,
            "previous_exact_contract": previous_exact,
            "previous_target_quantity": previous_quantity,
            "exact_contract": exact_contract,
            "target_quantity": target_quantity,
            "source_target_weight": source_weight,
            "buffered_target_weight": buffered_weight,
            "reference_open_price": reference_price,
            "multiplier": multiplier,
            "price_tick": price_tick,
        }
    if set(by_product) != set(frozen.PRODUCTS):
        raise SnapshotProducerError("baseline frozen product set is incomplete")

    source_weights = {
        product: by_product[product]["source_target_weight"]
        for product in frozen.PRODUCTS
    }
    try:
        frozen._verify_weight_limits(
            source_weights, frozen.SOURCE_LIMITS, "baseline source"
        )
        expected_buffered = frozen._buffer_weights(source_weights)
    except frozen.ProducerKernelError as exc:
        raise SnapshotProducerError(str(exc)) from exc
    for product in frozen.PRODUCTS:
        if not _close(
            by_product[product]["buffered_target_weight"],
            expected_buffered[product],
            tolerance=1e-10,
        ):
            raise SnapshotProducerError(
                f"baseline guardband tamper detected for {product}"
            )
    unit_weights = {
        product: (
            by_product[product]["reference_open_price"]
            * by_product[product]["multiplier"]
            / frozen.VIRTUAL_NAV_CNY
        )
        for product in frozen.PRODUCTS
    }
    try:
        baseline_allocation = frozen._joint_integer_allocate(
            expected_buffered, unit_weights
        )
    except frozen.ProducerKernelError as exc:
        raise SnapshotProducerError(str(exc)) from exc
    for product in frozen.PRODUCTS:
        if (
            by_product[product]["target_quantity"]
            != baseline_allocation.quantities[product]
        ):
            raise SnapshotProducerError(
                f"baseline frozen integer allocation mismatch for {product}"
            )
    return dict(batch), by_product, baseline_allocation


def _validate_previous_snapshot(
    raw_snapshot: Any,
    *,
    claimed_hash: str,
    current_source_month: str,
) -> tuple[str, float]:
    snapshot = _exact_object(
        raw_snapshot, PREVIOUS_SNAPSHOT_FIELDS, "continuity.previous_snapshot"
    )
    if (
        snapshot["schema_version"] != SNAPSHOT_SCHEMA_VERSION
        or snapshot["position_manager_id"] != POSITION_MANAGER_ID
        or snapshot["sector_map_id"] != SECTOR_MAP_ID
        or snapshot["mode"] != "shadow_only"
        or snapshot["execution_lane"] != "official_forward"
        or snapshot["countable_forward"] is not True
        or snapshot["baseline_scheduler_id"] != BASELINE_SCHEDULER_ID
        or snapshot["authority_granted"] is not False
        or snapshot["dispatch_allowed"] is not False
    ):
        raise SnapshotProducerError("previous snapshot identity or authority mismatch")
    _stable_id(snapshot["snapshot_id"], "previous_snapshot.snapshot_id")
    _sha256_text(
        snapshot["baseline_batch_hash"],
        "previous_snapshot.baseline_batch_hash",
    )
    previous_month = _source_month(
        snapshot["source_month"], "previous_snapshot.source_month"
    )
    if current_source_month != _next_month(previous_month):
        raise SnapshotProducerError("linked continuity source month chain break")
    previous_execution_day = _iso_date(
        snapshot["execution_day"], "previous_snapshot.execution_day"
    )
    previous_cutoff_day = _iso_date(
        snapshot["input_cutoff_day"], "previous_snapshot.input_cutoff_day"
    )
    previous_year, previous_month_number = (
        int(item) for item in previous_month.split("-")
    )
    expected_previous_cutoff = date(
        previous_year,
        previous_month_number,
        calendar.monthrange(previous_year, previous_month_number)[1],
    )
    if previous_cutoff_day != expected_previous_cutoff or (
        previous_execution_day.strftime("%Y-%m") != _next_month(previous_month)
    ):
        raise SnapshotProducerError("previous snapshot PIT month boundary mismatch")
    if (
        snapshot["fast_lookback_days"] != FAST_LOOKBACK_DAYS
        or snapshot["slow_lookback_days"] != SLOW_LOOKBACK_DAYS
        or snapshot["annualization_days"] != ANNUALIZATION_DAYS
        or snapshot["scale_min"] != SCALE_MIN
        or snapshot["scale_max"] != SCALE_MAX
        or snapshot["smoothing_alpha"] != SMOOTHING_ALPHA
        or snapshot["daily_auto_reweight"] is not False
        or snapshot["guardband_reapplied"] is not True
    ):
        raise SnapshotProducerError("previous snapshot frozen rule mismatch")
    fast_vol = _finite_positive(
        snapshot["fast_annual_vol"], "previous_snapshot.fast_annual_vol"
    )
    slow_vol = _finite_positive(
        snapshot["slow_annual_vol"], "previous_snapshot.slow_annual_vol"
    )
    raw_scale = _finite_positive(
        snapshot["raw_scale"], "previous_snapshot.raw_scale"
    )
    prior_scale = _finite_positive(
        snapshot["previous_smoothed_scale"],
        "previous_snapshot.previous_smoothed_scale",
    )
    smoothed_scale = _finite_positive(
        snapshot["smoothed_scale"], "previous_snapshot.smoothed_scale"
    )
    if not all(
        SCALE_MIN <= value <= SCALE_MAX
        for value in (raw_scale, prior_scale, smoothed_scale)
    ):
        raise SnapshotProducerError("previous snapshot scale is out of bounds")
    expected_raw = min(SCALE_MAX, max(SCALE_MIN, math.sqrt(slow_vol / fast_vol)))
    expected_smoothed = min(
        SCALE_MAX,
        max(
            SCALE_MIN,
            SMOOTHING_ALPHA * expected_raw
            + (1.0 - SMOOTHING_ALPHA) * prior_scale,
        ),
    )
    if not _close(raw_scale, expected_raw, tolerance=1e-10) or not _close(
        smoothed_scale, expected_smoothed, tolerance=1e-10
    ):
        raise SnapshotProducerError("previous snapshot frozen scale formula mismatch")
    if snapshot["continuity_mode"] not in {"genesis", "linked"}:
        raise SnapshotProducerError("previous snapshot continuity mode is invalid")
    if snapshot["continuity_mode"] == "genesis" and (
        previous_month != GENESIS_SOURCE_MONTH
        or snapshot["previous_snapshot_hash"] is not None
        or not _close(prior_scale, 1.0)
    ):
        raise SnapshotProducerError("previous snapshot genesis continuity is invalid")
    if snapshot["continuity_mode"] == "linked":
        _sha256_text(
            snapshot["previous_snapshot_hash"],
            "previous_snapshot.previous_snapshot_hash",
        )
    _key_id(snapshot["signer_key_id"], "previous_snapshot.signer_key_id")
    _signature_shape(snapshot["signature"], "previous_snapshot.signature")
    raw_targets = snapshot["targets"]
    if not isinstance(raw_targets, list) or len(raw_targets) != len(frozen.PRODUCTS):
        raise SnapshotProducerError("previous snapshot targets are incomplete")
    target_products: set[str] = set()
    for index, raw_target in enumerate(raw_targets):
        target = _exact_object(
            raw_target,
            PREVIOUS_TARGET_FIELDS,
            f"previous_snapshot.targets[{index}]",
        )
        product = str(target["product"])
        if product not in frozen.PRODUCTS or product in target_products:
            raise SnapshotProducerError(
                "previous snapshot target product set is invalid"
            )
        target_products.add(product)
        spec = frozen.PRODUCT_SPECS[product]
        _exact_contract(
            target["exact_contract"],
            product=product,
            exchange=spec["exchange"],
            label="previous snapshot exact contract",
        )
        _strict_integer(
            target["baseline_target_quantity"],
            "previous snapshot baseline target quantity",
        )
        _strict_integer(
            target["shadow_target_quantity"],
            "previous snapshot shadow target quantity",
        )
        for field in (
            "baseline_source_target_weight",
            "shadow_source_target_weight",
            "baseline_buffered_target_weight",
            "shadow_buffered_target_weight",
        ):
            _finite(target[field], f"previous snapshot {field}")
        _finite_positive(
            target["reference_open_price"],
            "previous snapshot reference open price",
        )
        if (
            _strict_integer(target["multiplier"], "previous snapshot multiplier")
            != spec["multiplier"]
            or not _close(
                _finite_positive(
                    target["price_tick"], "previous snapshot price tick"
                ),
                float(spec["price_tick"]),
            )
        ):
            raise SnapshotProducerError("previous snapshot contract spec mismatch")
    if target_products != set(frozen.PRODUCTS):
        raise SnapshotProducerError("previous snapshot target product set is invalid")

    canonical_payload = canonical_json(
        {key: value for key, value in snapshot.items() if key != "signature"}
    )
    if _sha256(canonical_payload) != claimed_hash:
        raise SnapshotProducerError("previous snapshot hash tamper detected")
    return previous_month, smoothed_scale


def _allocation_projection(allocation: frozen.Allocation) -> dict[str, Any]:
    return {
        "quantities": allocation.quantities,
        "raw_quantities": allocation.raw_quantities,
        "realized_weights": allocation.realized_weights,
        "squared_target_error": allocation.squared_target_error,
        "residual_net": allocation.residual_net,
        "objective": allocation.objective,
        "gross": allocation.gross,
        "sector_gross": allocation.sector_gross,
        "states_retained": allocation.states_retained,
    }


def produce_snapshot(
    source_view: Mapping[str, Any] | bytes | bytearray,
) -> ProducerResult:
    """Produce deterministic unsigned snapshot and non-authoritative evidence."""

    source = _bounded_source_input(source_view)
    source = _exact_object(
        source,
        {
            "schema_version",
            "purpose",
            "status",
            "source_view_id",
            "snapshot_id",
            "generated_at",
            "cutoff_at",
            "official_days",
            "baseline_daily_returns",
            "baseline_batch_hash",
            "baseline_batch",
            "continuity",
        },
        "source view",
    )
    if source["schema_version"] != SOURCE_SCHEMA_VERSION:
        raise SnapshotProducerError("source-view schema version mismatch")
    if source["purpose"] != SOURCE_PURPOSE or source["status"] != SOURCE_STATUS:
        raise SnapshotProducerError("source view is not the bounded PIT input class")
    source_view_id = _stable_id(source["source_view_id"], "source_view_id")
    snapshot_id = _stable_id(source["snapshot_id"], "snapshot_id")
    generated_at = _iso_datetime(source["generated_at"], "generated_at")
    cutoff_at = _iso_datetime(source["cutoff_at"], "cutoff_at")
    if cutoff_at > generated_at:
        raise SnapshotProducerError("source cutoff is after generation")
    baseline_batch_hash = _sha256_text(
        source["baseline_batch_hash"], "baseline_batch_hash"
    )
    batch, baseline_rows, baseline_allocation = _validate_baseline_batch(
        source["baseline_batch"], claimed_hash=baseline_batch_hash
    )
    source_month = str(batch["source_month"])
    execution_day = _iso_date(batch["execution_day"], "baseline execution_day")
    source_year, source_month_number = (
        int(item) for item in source_month.split("-")
    )
    input_cutoff_day = date(
        source_year,
        source_month_number,
        calendar.monthrange(source_year, source_month_number)[1],
    )
    if cutoff_at.astimezone(CHINA_TZ).date() != input_cutoff_day:
        raise SnapshotProducerError(
            "cutoff timestamp is not on the source-month PIT boundary"
        )
    if generated_at.astimezone(CHINA_TZ).date() != execution_day:
        raise SnapshotProducerError(
            "source view must be generated on the baseline execution day"
        )
    normalized_returns, daily_return_values = _validate_daily_returns(
        source,
        input_cutoff_day=input_cutoff_day,
        execution_day=execution_day,
    )

    continuity = _exact_object(
        source["continuity"],
        {"mode", "previous_snapshot_hash", "previous_snapshot"},
        "continuity",
    )
    mode = str(continuity["mode"])
    previous_snapshot_hash: str | None
    previous_smoothed_scale: float
    if batch["execution_lane"] == "simnow_shakedown":
        if (
            mode != "genesis"
            or continuity["previous_snapshot_hash"] is not None
            or continuity["previous_snapshot"] is not None
        ):
            raise SnapshotProducerError(
                "SimNow shakedown must use isolated genesis continuity"
            )
        previous_snapshot_hash = None
        previous_smoothed_scale = 1.0
    elif mode == "genesis":
        if (
            source_month != GENESIS_SOURCE_MONTH
            or continuity["previous_snapshot_hash"] is not None
            or continuity["previous_snapshot"] is not None
        ):
            raise SnapshotProducerError("formal genesis continuity declaration is invalid")
        previous_snapshot_hash = None
        previous_smoothed_scale = 1.0
    elif mode == "linked":
        previous_snapshot_hash = _sha256_text(
            continuity["previous_snapshot_hash"],
            "continuity.previous_snapshot_hash",
        )
        if continuity["previous_snapshot"] is None:
            raise SnapshotProducerError("linked continuity proof is missing")
        _, previous_smoothed_scale = _validate_previous_snapshot(
            continuity["previous_snapshot"],
            claimed_hash=previous_snapshot_hash,
            current_source_month=source_month,
        )
    else:
        raise SnapshotProducerError("continuity mode must be genesis or linked")

    fast_values = daily_return_values[-FAST_LOOKBACK_DAYS:]
    slow_values = daily_return_values[-SLOW_LOOKBACK_DAYS:]
    fast_annual_vol = _sample_annual_vol(fast_values, "fast 21-day sample")
    slow_annual_vol = _sample_annual_vol(slow_values, "slow 126-day sample")
    raw_scale = min(
        SCALE_MAX,
        max(SCALE_MIN, math.sqrt(slow_annual_vol / fast_annual_vol)),
    )
    smoothed_scale = min(
        SCALE_MAX,
        max(
            SCALE_MIN,
            SMOOTHING_ALPHA * raw_scale
            + (1.0 - SMOOTHING_ALPHA) * previous_smoothed_scale,
        ),
    )

    baseline_source = {
        product: baseline_rows[product]["source_target_weight"]
        for product in frozen.PRODUCTS
    }
    shadow_source = {
        product: baseline_source[product] * smoothed_scale
        for product in frozen.PRODUCTS
    }
    try:
        frozen._verify_weight_limits(
            shadow_source, frozen.SOURCE_LIMITS, "shadow source"
        )
        baseline_buffered = frozen._buffer_weights(baseline_source)
        shadow_buffered = frozen._buffer_weights(shadow_source)
        unit_weights = {
            product: (
                baseline_rows[product]["reference_open_price"]
                * baseline_rows[product]["multiplier"]
                / frozen.VIRTUAL_NAV_CNY
            )
            for product in frozen.PRODUCTS
        }
        shadow_allocation = frozen._joint_integer_allocate(
            shadow_buffered, unit_weights
        )
    except frozen.ProducerKernelError as exc:
        raise SnapshotProducerError(str(exc)) from exc

    targets: list[dict[str, Any]] = []
    for product in frozen.PRODUCTS:
        row = baseline_rows[product]
        targets.append(
            {
                "product": product,
                "exact_contract": row["exact_contract"],
                "baseline_target_quantity": baseline_allocation.quantities[product],
                "shadow_target_quantity": shadow_allocation.quantities[product],
                "baseline_source_target_weight": baseline_source[product],
                "shadow_source_target_weight": shadow_source[product],
                "baseline_buffered_target_weight": baseline_buffered[product],
                "shadow_buffered_target_weight": shadow_buffered[product],
                "reference_open_price": row["reference_open_price"],
                "multiplier": row["multiplier"],
                "price_tick": row["price_tick"],
            }
        )

    snapshot = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "position_manager_id": POSITION_MANAGER_ID,
        "sector_map_id": SECTOR_MAP_ID,
        "mode": "shadow_only",
        "execution_lane": batch["execution_lane"],
        "countable_forward": batch["execution_lane"] == "official_forward",
        "baseline_scheduler_id": BASELINE_SCHEDULER_ID,
        "baseline_batch_hash": baseline_batch_hash,
        "source_month": source_month,
        "execution_day": execution_day.isoformat(),
        "input_cutoff_day": input_cutoff_day.isoformat(),
        "fast_lookback_days": FAST_LOOKBACK_DAYS,
        "slow_lookback_days": SLOW_LOOKBACK_DAYS,
        "annualization_days": ANNUALIZATION_DAYS,
        "fast_annual_vol": fast_annual_vol,
        "slow_annual_vol": slow_annual_vol,
        "scale_min": SCALE_MIN,
        "scale_max": SCALE_MAX,
        "raw_scale": raw_scale,
        "continuity_mode": mode,
        "previous_snapshot_hash": previous_snapshot_hash,
        "previous_smoothed_scale": previous_smoothed_scale,
        "smoothing_alpha": SMOOTHING_ALPHA,
        "smoothed_scale": smoothed_scale,
        "daily_auto_reweight": False,
        "guardband_reapplied": True,
        "authority_granted": False,
        "dispatch_allowed": False,
        "targets": targets,
        "signer_key_id": batch["signer_key_id"],
    }
    snapshot_raw = canonical_json(snapshot)
    snapshot_hash = _sha256(snapshot_raw)
    source_raw = canonical_json(source)
    source_hash = _sha256(source_raw)
    evidence: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_id": f"evidence-{snapshot_id}",
        "producer_id": PRODUCER_ID,
        "position_manager_id": POSITION_MANAGER_ID,
        "source_view_id": source_view_id,
        "source_view_canonical_sha256": source_hash,
        "source_view_status_claim": SOURCE_STATUS,
        "sealed_source_view_verified_by_producer": False,
        "daily_return_source_authority_verified_by_producer": False,
        "baseline_batch_hash": baseline_batch_hash,
        "baseline_batch_hash_validation": (
            "CANONICAL_UNSIGNED_PAYLOAD_HASH_MATCH_ONLY"
        ),
        "baseline_batch_signature_verified_by_producer": False,
        "previous_snapshot_signature_verified_by_producer": False,
        "snapshot_draft_sha256": snapshot_hash,
        "snapshot_signed": False,
        "snapshot_installed": False,
        "research_evidence_only": True,
        "execution_lane": batch["execution_lane"],
        "countable_forward": batch["execution_lane"] == "official_forward",
        "input_cutoff_day": input_cutoff_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "daily_return_evidence_sha256": _sha256(
            canonical_json(normalized_returns)
        ),
        "daily_return_count": len(normalized_returns),
        "fast_lookback_days": FAST_LOOKBACK_DAYS,
        "slow_lookback_days": SLOW_LOOKBACK_DAYS,
        "sample_ddof": SAMPLE_DDOF,
        "annualization_days": ANNUALIZATION_DAYS,
        "fast_annual_vol": fast_annual_vol,
        "slow_annual_vol": slow_annual_vol,
        "raw_scale": raw_scale,
        "previous_smoothed_scale": previous_smoothed_scale,
        "smoothed_scale": smoothed_scale,
        "continuity_mode": mode,
        "previous_snapshot_hash": previous_snapshot_hash,
        "continuity_proof_present": mode == "genesis"
        or continuity["previous_snapshot"] is not None,
        "guardband": {
            "lineage_sha256": frozen.LINEAGE["guardband_v2_source_sha256"],
            "product": frozen.BUFFER_LIMITS["product"],
            "sector": frozen.BUFFER_LIMITS["sector"],
            "gross": frozen.BUFFER_LIMITS["gross"],
            "target_net": 0.0,
        },
        "allocator": {
            "lineage_sha256": frozen.LINEAGE[
                "integer_allocator_source_sha256"
            ],
            "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": frozen.NEIGHBOURHOOD_RADIUS_LOTS,
            "beam_width": frozen.BEAM_WIDTH,
            "net_error_penalty": frozen.NET_ERROR_PENALTY,
            "virtual_nav_cny": frozen.VIRTUAL_NAV_CNY,
            "integer_limits_strict": frozen.INTEGER_LIMITS,
        },
        "baseline_allocation": _allocation_projection(baseline_allocation),
        "shadow_allocation": _allocation_projection(shadow_allocation),
    }
    for field in FALSE_AUTHORITY_FIELDS:
        evidence[field] = False
    return ProducerResult(
        source_view_canonical_sha256=source_hash,
        snapshot_draft_sha256=snapshot_hash,
        snapshot_draft=snapshot_raw,
        evidence=canonical_json(evidence),
    )


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(raw)
            handle.write(b"\n")
            handle.flush()
    except FileExistsError as exc:
        raise SnapshotProducerError(f"refuse to overwrite existing artifact: {path}") from exc


def _write_outputs(
    snapshot_path: Path,
    snapshot_raw: bytes,
    evidence_path: Path,
    evidence_raw: bytes,
) -> None:
    if snapshot_path == evidence_path:
        raise SnapshotProducerError("snapshot and evidence outputs must be distinct")
    if snapshot_path.exists() or evidence_path.exists():
        existing = snapshot_path if snapshot_path.exists() else evidence_path
        raise SnapshotProducerError(f"refuse to overwrite existing artifact: {existing}")
    _write_new(snapshot_path, snapshot_raw)
    try:
        _write_new(evidence_path, evidence_raw)
    except Exception:
        snapshot_path.unlink(missing_ok=True)
        raise


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--snapshot-output", required=True, type=Path)
    parser.add_argument("--evidence-output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        raw = args.input.read_bytes()
        if len(raw) > MAX_SOURCE_VIEW_RAW_BYTES:
            raise SnapshotProducerError(
                "source-view raw bytes exceeds resource limit"
            )
        result = produce_snapshot(raw)
        _write_outputs(
            args.snapshot_output,
            result.snapshot_draft,
            args.evidence_output,
            result.evidence,
        )
    except (OSError, SnapshotProducerError) as exc:
        print(f"snapshot production failed: {exc}", file=sys.stderr)
        return 2
    print(f"unsigned snapshot draft written: {args.snapshot_output}")
    print(f"producer evidence written: {args.evidence_output}")
    print(f"snapshot_draft_sha256: {result.snapshot_draft_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
