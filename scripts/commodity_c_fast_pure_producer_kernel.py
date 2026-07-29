#!/usr/bin/env python3
"""Pure Research-Plane producer kernel for C_FAST research evidence.

The kernel accepts one unverified PIT-typed source view in memory or as bounded
JSON bytes.  It performs deterministic market-only calculations and returns
nine canonical JSON byte strings plus a schema-distinct producer summary.  A
later sealed-export verifier must independently verify the source receipt,
raw-byte and custody facts before producing any #160 signing input.

It deliberately owns no source acquisition, custody, signing, installation,
Control Plane or Execution Plane capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import hashlib
import json
import math
import re
from typing import Any, Mapping, TypedDict
from zoneinfo import ZoneInfo


STATUS = "PURE_PRODUCER_KERNEL_ONLY_NOT_REAL_ARTIFACT"
SOURCE_SCHEMA_VERSION = "commodity_c_fast_pit_frozen_source_view_v1"
SOURCE_PURPOSE = "UNVERIFIED_PIT_TYPED_VIEW_INPUT_ONLY"
SOURCE_STATUS = "UNVERIFIED_PIT_TYPED_VIEW"
RESEARCH_SOURCE_CLASS = "UNVERIFIED_PIT_TYPED_VIEW"
KERNEL_ID = "commodity_c_fast_pure_producer_kernel_v1"
ARTIFACT_SCHEMA_PREFIX = "commodity_c_fast_pure_producer"

CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
FROZEN_RULE_ID = "commodity_fast_tsmom_forward_freeze_v1"
FROZEN_RULE_SHA256 = (
    "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
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
FALSE_AUTHORITY_FIELDS = (
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
VIRTUAL_NAV_CNY = 20_000_000
VOLATILITY_FLOOR = 0.05
TREND_HORIZONS = (21, 63, 126)
VOLATILITY_LOOKBACK = 60
SOURCE_LIMITS = {"product": 0.20, "sector": 0.35, "gross": 1.00}
BUFFER_LIMITS = {"product": 0.12, "sector": 0.27, "gross": 0.80}
INTEGER_LIMITS = {
    "product": 0.15,
    "sector": 0.35,
    "gross": 1.00,
    "abs_net": 0.10,
}
NEIGHBOURHOOD_RADIUS_LOTS = 2
BEAM_WIDTH = 2048
NET_ERROR_PENALTY = 1.0
MAX_ABS_TARGET_QUANTITY = 500
MAX_SOURCE_VIEW_RAW_BYTES = 16 * 1024 * 1024
MAX_OFFICIAL_DAYS = 512
MAX_SOURCE_BINDINGS = 7
MAX_DAILY_ROWS_PER_PRODUCT = 512
MAX_CONTRACTS_PER_PRODUCT_DAY = 64
MAX_TOTAL_CONTRACT_ROWS = 40_000
STRICT_EPSILON = 1e-12
CHINA_TZ = ZoneInfo("Asia/Shanghai")

ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CONTRACT_PATTERN = re.compile(r"^(SHFE|INE)\.([a-z]{2})([0-9]{4})$")

LINEAGE = {
    "market_only_curve_panel_source_sha256": (
        "bd3d8f673bed08ea589aceafab2a9fceae2e658c4ae59266677000ae78d9ad2a"
    ),
    "fast_tsmom_signal_source_sha256": (
        "7ebe1529173b46cbae17680d872680c7bb7bae39863d09b2d9a37183828a43a9"
    ),
    "self_financing_target_source_sha256": (
        "40fd1a27bb1e6dedf483a4c7dcec6d181d325d9c9958d6620f79f04fbdb696db"
    ),
    "integer_allocator_source_sha256": (
        "66497283d1c35383d620ef3c92f2c23316046a9b4b0cbe6f1dcf3f361041f307"
    ),
    "guardband_v2_source_sha256": (
        "e9871b26af4f0ebebed6e697e8fa1c3064bc3d6557df739bcef9b80697eab353"
    ),
}


class SourceBinding(TypedDict):
    binding_id: str
    source_class: str
    scope: str
    source_identity: str
    query_start: str
    query_end: str
    cutoff_at: str
    generated_at: str
    raw_sha256: str
    lineage_sha256: str
    claimed_receipt_sha256: str


class ContractObservation(TypedDict):
    exact_contract: str
    delivery_yyyymm: int
    settlement: float
    open_interest: float


class DailyProductView(TypedDict):
    official_day: str
    source_binding_id: str
    contracts: list[ContractObservation]


class ExecutionReference(TypedDict):
    source_binding_id: str
    exact_contract: str
    official_open: float
    observed_at: str
    raw_sha256: str


class ContractSpecView(TypedDict):
    source_binding_id: str
    exact_contract: str
    official_last_trading_day: str
    multiplier: int
    price_tick: float
    raw_sha256: str


class ProductSourceView(TypedDict):
    product: str
    exchange: str
    daily: list[DailyProductView]
    execution_reference: ExecutionReference
    contract_spec: ContractSpecView


class PitFrozenSourceView(TypedDict):
    schema_version: str
    purpose: str
    status: str
    source_view_id: str
    claimed_receipt_sha256: str
    generated_at: str
    cutoff_at: str
    research_as_of_official_day: str
    execution_day: str
    official_days: list[str]
    source_bindings: list[SourceBinding]
    products: list[ProductSourceView]


class ProducerKernelError(ValueError):
    """Expected fail-closed pure-kernel input or calculation error."""


@dataclass(frozen=True)
class Allocation:
    quantities: dict[str, int]
    raw_quantities: dict[str, float]
    realized_weights: dict[str, float]
    squared_target_error: float
    residual_net: float
    objective: float
    gross: float
    sector_gross: dict[str, float]
    states_retained: int


@dataclass(frozen=True)
class ProducerResult:
    status: str
    source_view_canonical_sha256: str
    artifacts: Mapping[str, bytes]
    producer_projection: Mapping[str, Any]


def canonical_json(payload: Any) -> bytes:
    """Return deterministic UTF-8 JSON and reject NaN/Infinity."""
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProducerKernelError("payload is not canonical finite JSON") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ProducerKernelError(f"source JSON constant {value!r} is forbidden")


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProducerKernelError(f"source JSON has duplicate key: {key}")
        result[key] = value
    return result


def _enforce_source_shape_limits(source: dict[str, Any]) -> None:
    """Bound all collection sizes before semantic row loops or sorting."""
    raw_days = source.get("official_days")
    if isinstance(raw_days, list) and len(raw_days) > MAX_OFFICIAL_DAYS:
        raise ProducerKernelError("official_days exceeds the resource limit")

    raw_bindings = source.get("source_bindings")
    if isinstance(raw_bindings, list) and len(raw_bindings) > MAX_SOURCE_BINDINGS:
        raise ProducerKernelError("source_bindings exceeds the resource limit")

    raw_products = source.get("products")
    if not isinstance(raw_products, list):
        return
    if len(raw_products) > len(PRODUCTS):
        raise ProducerKernelError("products exceeds the frozen resource limit")

    total_contract_rows = 0
    for product_index, product in enumerate(raw_products):
        if not isinstance(product, dict):
            continue
        raw_daily = product.get("daily")
        if not isinstance(raw_daily, list):
            continue
        if len(raw_daily) > MAX_DAILY_ROWS_PER_PRODUCT:
            raise ProducerKernelError(
                f"products[{product_index}].daily exceeds the resource limit"
            )
        for day_index, daily in enumerate(raw_daily):
            if not isinstance(daily, dict):
                continue
            raw_contracts = daily.get("contracts")
            if not isinstance(raw_contracts, list):
                continue
            if len(raw_contracts) > MAX_CONTRACTS_PER_PRODUCT_DAY:
                raise ProducerKernelError(
                    "products"
                    f"[{product_index}].daily[{day_index}].contracts "
                    "exceeds the per-day resource limit"
                )
            total_contract_rows += len(raw_contracts)
            if total_contract_rows > MAX_TOTAL_CONTRACT_ROWS:
                raise ProducerKernelError(
                    "source view exceeds the total contract-row resource limit"
                )


def _bounded_source_view_input(
    source_view: Mapping[str, Any] | bytes | bytearray,
) -> dict[str, Any]:
    """Decode or copy one bounded JSON object before expensive normalization."""
    if isinstance(source_view, (bytes, bytearray)):
        raw = bytes(source_view)
        if len(raw) > MAX_SOURCE_VIEW_RAW_BYTES:
            raise ProducerKernelError("source-view raw bytes exceeds the resource limit")
        try:
            decoded = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except ProducerKernelError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProducerKernelError("source-view raw bytes are not strict JSON") from exc
        if not isinstance(decoded, dict):
            raise ProducerKernelError("source-view JSON root must be one object")
        source = decoded
    elif isinstance(source_view, Mapping):
        source = dict(source_view)
    else:
        raise ProducerKernelError("source view must be one mapping or bounded JSON bytes")

    _enforce_source_shape_limits(source)
    if len(canonical_json(source)) > MAX_SOURCE_VIEW_RAW_BYTES:
        raise ProducerKernelError("source-view canonical bytes exceeds the resource limit")
    return source


def _require_exact_keys(
    value: Any,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProducerKernelError(f"{label} must be one object")
    keys = set(value)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        raise ProducerKernelError(
            f"{label} field set mismatch: missing={missing}, extra={extra}"
        )
    return value


def _require_id(value: Any, label: str) -> str:
    text = str(value)
    if ID_PATTERN.fullmatch(text) is None:
        raise ProducerKernelError(f"{label} must be one stable id")
    return text


def _require_sha256(value: Any, label: str) -> str:
    text = str(value)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise ProducerKernelError(f"{label} must be one lowercase SHA256")
    return text


def _parse_date(value: Any, label: str) -> date:
    try:
        parsed = date.fromisoformat(str(value))
    except ValueError as exc:
        raise ProducerKernelError(f"{label} must be an ISO date") from exc
    if parsed.isoformat() != str(value):
        raise ProducerKernelError(f"{label} must use canonical ISO date form")
    return parsed


def _parse_datetime(value: Any, label: str) -> datetime:
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProducerKernelError(f"{label} must be an ISO datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProducerKernelError(f"{label} must be timezone-aware")
    return parsed


def _finite_positive(value: Any, label: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ProducerKernelError(f"{label} must be numeric") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ProducerKernelError(f"{label} must be finite and positive")
    return parsed


def _finite_nonnegative(value: Any, label: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ProducerKernelError(f"{label} must be numeric") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ProducerKernelError(f"{label} must be finite and non-negative")
    return parsed


def _strict_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProducerKernelError(f"{label} must be one integer")
    return value


def _exact_contract(value: Any, product: str, exchange: str, label: str) -> str:
    text = str(value)
    match = CONTRACT_PATTERN.fullmatch(text)
    if match is None or match.group(1) != exchange or match.group(2) != product:
        raise ProducerKernelError(f"{label} is outside the frozen exact contract")
    return text


def _delivery_yyyymm(exact_contract: str) -> int:
    match = CONTRACT_PATTERN.fullmatch(exact_contract)
    if match is None:
        raise ProducerKernelError("exact contract format is invalid")
    digits = match.group(3)
    year = 2000 + int(digits[:2])
    month = int(digits[2:])
    if not 1 <= month <= 12:
        raise ProducerKernelError("exact contract delivery month is invalid")
    return year * 100 + month


def _validate_source_binding(
    item: Any,
    *,
    index: int,
    generated_at: datetime,
) -> SourceBinding:
    row = _require_exact_keys(
        item,
        {
            "binding_id",
            "source_class",
            "scope",
            "source_identity",
            "query_start",
            "query_end",
            "cutoff_at",
            "generated_at",
            "raw_sha256",
            "lineage_sha256",
            "claimed_receipt_sha256",
        },
        f"source_bindings[{index}]",
    )
    binding_id = _require_id(row["binding_id"], f"source_bindings[{index}].binding_id")
    source_class = str(row["source_class"])
    if source_class not in {
        "MARKET_DAILY",
        "CALENDAR",
        "REFERENCE_OPEN",
        "CONTRACT_SPEC",
    }:
        raise ProducerKernelError("source binding class is outside the typed view")
    scope = str(row["scope"])
    if scope not in {"SHFE", "INE", "SHFE_INE"}:
        raise ProducerKernelError("source binding scope is outside the typed view")
    if source_class != "CALENDAR" and scope == "SHFE_INE":
        raise ProducerKernelError("non-calendar source binding must be exchange scoped")
    if source_class == "CALENDAR" and scope != "SHFE_INE":
        raise ProducerKernelError("calendar source binding must cover SHFE_INE")
    source_identity = _require_id(
        row["source_identity"],
        f"source_bindings[{index}].source_identity",
    )
    query_start = _parse_date(row["query_start"], "source query_start")
    query_end = _parse_date(row["query_end"], "source query_end")
    if query_start > query_end:
        raise ProducerKernelError("source query window is reversed")
    cutoff_at = _parse_datetime(row["cutoff_at"], "source cutoff_at")
    binding_generated = _parse_datetime(
        row["generated_at"],
        "source generated_at",
    )
    if cutoff_at > binding_generated or binding_generated > generated_at:
        raise ProducerKernelError("source binding time is not causally available")
    return {
        "binding_id": binding_id,
        "source_class": source_class,
        "scope": scope,
        "source_identity": source_identity,
        "query_start": query_start.isoformat(),
        "query_end": query_end.isoformat(),
        "cutoff_at": str(row["cutoff_at"]),
        "generated_at": str(row["generated_at"]),
        "raw_sha256": _require_sha256(row["raw_sha256"], "source raw"),
        "lineage_sha256": _require_sha256(row["lineage_sha256"], "source lineage"),
        "claimed_receipt_sha256": _require_sha256(
            row["claimed_receipt_sha256"],
            "claimed source receipt",
        ),
    }


def _binding_for(
    bindings: dict[str, SourceBinding],
    binding_id: Any,
    *,
    source_class: str,
    exchange: str | None,
    day: date,
) -> SourceBinding:
    key = str(binding_id)
    if key not in bindings:
        raise ProducerKernelError(f"unknown source binding: {key}")
    binding = bindings[key]
    if binding["source_class"] != source_class:
        raise ProducerKernelError(f"source binding class mismatch: {key}")
    if exchange is not None and binding["scope"] != exchange:
        raise ProducerKernelError(f"source binding scope mismatch: {key}")
    if not (
        _parse_date(binding["query_start"], "binding query_start")
        <= day
        <= _parse_date(binding["query_end"], "binding query_end")
    ):
        raise ProducerKernelError(f"source binding window does not cover {day}: {key}")
    return binding


def _validate_and_normalize_source_view(
    source_view: Mapping[str, Any],
) -> tuple[PitFrozenSourceView, dict[str, SourceBinding], list[date]]:
    source = _require_exact_keys(
        dict(source_view),
        {
            "schema_version",
            "purpose",
            "status",
            "source_view_id",
            "claimed_receipt_sha256",
            "generated_at",
            "cutoff_at",
            "research_as_of_official_day",
            "execution_day",
            "official_days",
            "source_bindings",
            "products",
        },
        "source view",
    )
    if source["schema_version"] != SOURCE_SCHEMA_VERSION:
        raise ProducerKernelError("source-view schema version mismatch")
    if source["purpose"] != SOURCE_PURPOSE or source["status"] != SOURCE_STATUS:
        raise ProducerKernelError("source view is not an unverified PIT typed input")
    source_view_id = _require_id(source["source_view_id"], "source_view_id")
    claimed_receipt = _require_sha256(
        source["claimed_receipt_sha256"],
        "claimed_receipt_sha256",
    )
    generated_at = _parse_datetime(source["generated_at"], "generated_at")
    cutoff_at = _parse_datetime(source["cutoff_at"], "cutoff_at")
    if cutoff_at > generated_at:
        raise ProducerKernelError("source-view cutoff is after generation")
    research_day = _parse_date(
        source["research_as_of_official_day"],
        "research_as_of_official_day",
    )
    execution_day = _parse_date(source["execution_day"], "execution_day")
    if research_day >= execution_day or (
        research_day.year,
        research_day.month,
    ) == (execution_day.year, execution_day.month):
        raise ProducerKernelError(
            "research day must be a completed prior source month"
        )
    if generated_at.astimezone(CHINA_TZ).date() != execution_day:
        raise ProducerKernelError("source view must be generated on execution day")

    raw_days = source["official_days"]
    if not isinstance(raw_days, list):
        raise ProducerKernelError("official_days must be one array")
    official_days = [
        _parse_date(item, f"official_days[{index}]")
        for index, item in enumerate(raw_days)
    ]
    if len(official_days) < 129 or official_days != sorted(set(official_days)):
        raise ProducerKernelError(
            "official calendar must be unique, sorted and contain warmup plus two future days"
        )
    if research_day not in official_days or execution_day not in official_days:
        raise ProducerKernelError("source/execution day is absent from official calendar")
    source_index = official_days.index(research_day)
    execution_index = official_days.index(execution_day)
    if execution_index != source_index + 1 or execution_index + 1 >= len(official_days):
        raise ProducerKernelError(
            "execution day must immediately follow source day with one following official day"
        )
    history_days = official_days[: source_index + 1]
    if len(history_days) < max(TREND_HORIZONS) + 1:
        raise ProducerKernelError("official calendar has insufficient trend warmup")

    raw_bindings = source["source_bindings"]
    if not isinstance(raw_bindings, list) or not raw_bindings:
        raise ProducerKernelError("source_bindings must be non-empty")
    binding_rows = [
        _validate_source_binding(item, index=index, generated_at=generated_at)
        for index, item in enumerate(raw_bindings)
    ]
    bindings = {row["binding_id"]: row for row in binding_rows}
    if len(bindings) != len(binding_rows):
        raise ProducerKernelError("source binding id is duplicated")
    binding_scopes = {
        (row["source_class"], row["scope"]) for row in binding_rows
    }
    if len(binding_scopes) != len(binding_rows):
        raise ProducerKernelError("source class/scope is spliced across bindings")
    if any(
        _parse_datetime(row["cutoff_at"], "source cutoff_at") > cutoff_at
        or _parse_datetime(row["generated_at"], "source generated_at") > cutoff_at
        for row in binding_rows
    ):
        raise ProducerKernelError("source binding was not available by source-view cutoff")
    calendar_bindings = [
        row for row in binding_rows if row["source_class"] == "CALENDAR"
    ]
    if len(calendar_bindings) != 1:
        raise ProducerKernelError("exactly one typed calendar binding is required")
    calendar_binding = calendar_bindings[0]
    if not (
        _parse_date(calendar_binding["query_start"], "calendar query_start")
        <= history_days[0]
        and _parse_date(calendar_binding["query_end"], "calendar query_end")
        >= official_days[execution_index + 1]
    ):
        raise ProducerKernelError("calendar binding does not cover the required window")

    raw_products = source["products"]
    if not isinstance(raw_products, list):
        raise ProducerKernelError("products must be one array")
    product_names = [str(item.get("product")) for item in raw_products if isinstance(item, dict)]
    if tuple(sorted(product_names)) != PRODUCTS or len(set(product_names)) != len(PRODUCTS):
        raise ProducerKernelError("source view must contain the exact frozen ten products")

    normalized_products: list[ProductSourceView] = []
    used_binding_ids = {calendar_binding["binding_id"]}
    expected_history = [item.isoformat() for item in history_days]
    for product_index, item in enumerate(
        sorted(raw_products, key=lambda row: str(row["product"]))
    ):
        row = _require_exact_keys(
            item,
            {
                "product",
                "exchange",
                "daily",
                "execution_reference",
                "contract_spec",
            },
            f"products[{product_index}]",
        )
        product = str(row["product"])
        spec = PRODUCT_SPECS[product]
        exchange = str(row["exchange"])
        if exchange != spec["exchange"]:
            raise ProducerKernelError(f"{product} exchange does not match frozen map")
        raw_daily = row["daily"]
        if not isinstance(raw_daily, list):
            raise ProducerKernelError(f"{product}.daily must be one array")
        daily_rows: list[DailyProductView] = []
        seen_days: set[str] = set()
        for day_index, day_item in enumerate(raw_daily):
            daily = _require_exact_keys(
                day_item,
                {"official_day", "source_binding_id", "contracts"},
                f"{product}.daily[{day_index}]",
            )
            official_day = _parse_date(
                daily["official_day"],
                f"{product}.daily[{day_index}].official_day",
            )
            if official_day > research_day:
                raise ProducerKernelError(f"{product} daily input contains future data")
            binding = _binding_for(
                bindings,
                daily["source_binding_id"],
                source_class="MARKET_DAILY",
                exchange=exchange,
                day=official_day,
            )
            used_binding_ids.add(binding["binding_id"])
            if _parse_date(binding["query_end"], "market query_end") > research_day:
                raise ProducerKernelError("market binding query window leaks future dates")
            if official_day.isoformat() in seen_days:
                raise ProducerKernelError(f"{product} daily official day is duplicated")
            seen_days.add(official_day.isoformat())
            raw_contracts = daily["contracts"]
            if not isinstance(raw_contracts, list) or len(raw_contracts) < 3:
                raise ProducerKernelError(
                    f"{product} {official_day} requires at least three full-curve rows"
                )
            contract_rows: list[ContractObservation] = []
            seen_contracts: set[str] = set()
            for contract_index, contract_item in enumerate(raw_contracts):
                contract = _require_exact_keys(
                    contract_item,
                    {
                        "exact_contract",
                        "delivery_yyyymm",
                        "settlement",
                        "open_interest",
                    },
                    f"{product}.daily[{day_index}].contracts[{contract_index}]",
                )
                exact = _exact_contract(
                    contract["exact_contract"],
                    product,
                    exchange,
                    "daily exact contract",
                )
                if exact in seen_contracts:
                    raise ProducerKernelError(
                        f"{product} {official_day} exact contract is duplicated"
                    )
                seen_contracts.add(exact)
                delivery = _strict_integer(
                    contract["delivery_yyyymm"],
                    "delivery_yyyymm",
                )
                if delivery != _delivery_yyyymm(exact):
                    raise ProducerKernelError("delivery_yyyymm does not match exact contract")
                contract_rows.append(
                    {
                        "exact_contract": exact,
                        "delivery_yyyymm": delivery,
                        "settlement": _finite_nonnegative(
                            contract["settlement"],
                            "settlement",
                        ),
                        "open_interest": _finite_nonnegative(
                            contract["open_interest"],
                            "open_interest",
                        ),
                    }
                )
            daily_rows.append(
                {
                    "official_day": official_day.isoformat(),
                    "source_binding_id": str(daily["source_binding_id"]),
                    "contracts": sorted(
                        contract_rows,
                        key=lambda contract: contract["exact_contract"],
                    ),
                }
            )
        daily_rows.sort(key=lambda daily: daily["official_day"])
        if [daily["official_day"] for daily in daily_rows] != expected_history:
            raise ProducerKernelError(
                f"{product} daily history must exactly cover the typed official days"
            )

        reference = _require_exact_keys(
            row["execution_reference"],
            {
                "source_binding_id",
                "exact_contract",
                "official_open",
                "observed_at",
                "raw_sha256",
            },
            f"{product}.execution_reference",
        )
        reference_binding = _binding_for(
            bindings,
            reference["source_binding_id"],
            source_class="REFERENCE_OPEN",
            exchange=exchange,
            day=execution_day,
        )
        used_binding_ids.add(reference_binding["binding_id"])
        observed_at = _parse_datetime(reference["observed_at"], "reference observed_at")
        if (
            observed_at.astimezone(CHINA_TZ).date() != execution_day
            or observed_at > generated_at
            or observed_at > cutoff_at
        ):
            raise ProducerKernelError(
                f"{product} official open is not causally observed on execution day"
            )
        normalized_reference: ExecutionReference = {
            "source_binding_id": str(reference["source_binding_id"]),
            "exact_contract": _exact_contract(
                reference["exact_contract"],
                product,
                exchange,
                "reference exact contract",
            ),
            "official_open": _finite_positive(
                reference["official_open"],
                "official_open",
            ),
            "observed_at": str(reference["observed_at"]),
            "raw_sha256": _require_sha256(
                reference["raw_sha256"],
                "reference raw",
            ),
        }

        raw_contract_spec = _require_exact_keys(
            row["contract_spec"],
            {
                "source_binding_id",
                "exact_contract",
                "official_last_trading_day",
                "multiplier",
                "price_tick",
                "raw_sha256",
            },
            f"{product}.contract_spec",
        )
        contract_spec_binding = _binding_for(
            bindings,
            raw_contract_spec["source_binding_id"],
            source_class="CONTRACT_SPEC",
            exchange=exchange,
            day=execution_day,
        )
        used_binding_ids.add(contract_spec_binding["binding_id"])
        multiplier = _strict_integer(
            raw_contract_spec["multiplier"],
            "multiplier",
        )
        price_tick = _finite_positive(raw_contract_spec["price_tick"], "price_tick")
        if multiplier != spec["multiplier"] or not math.isclose(
            price_tick,
            float(spec["price_tick"]),
            rel_tol=0,
            abs_tol=1e-12,
        ):
            raise ProducerKernelError(f"{product} contract spec conflicts with frozen spec")
        official_open_ticks = (
            normalized_reference["official_open"] / price_tick
        )
        if not math.isclose(
            official_open_ticks,
            round(official_open_ticks),
            rel_tol=0,
            abs_tol=1e-9,
        ):
            raise ProducerKernelError(
                f"{product} official open is not aligned to frozen price tick"
            )
        normalized_contract_spec: ContractSpecView = {
            "source_binding_id": str(raw_contract_spec["source_binding_id"]),
            "exact_contract": _exact_contract(
                raw_contract_spec["exact_contract"],
                product,
                exchange,
                "spec exact contract",
            ),
            "official_last_trading_day": _parse_date(
                raw_contract_spec["official_last_trading_day"],
                "official_last_trading_day",
            ).isoformat(),
            "multiplier": multiplier,
            "price_tick": price_tick,
            "raw_sha256": _require_sha256(
                raw_contract_spec["raw_sha256"],
                "contract spec raw",
            ),
        }
        normalized_products.append(
            {
                "product": product,
                "exchange": exchange,
                "daily": daily_rows,
                "execution_reference": normalized_reference,
                "contract_spec": normalized_contract_spec,
            }
        )
    if used_binding_ids != set(bindings):
        raise ProducerKernelError(
            "source view contains unused or unbound source binding"
        )

    normalized: PitFrozenSourceView = {
        "schema_version": SOURCE_SCHEMA_VERSION,
        "purpose": SOURCE_PURPOSE,
        "status": SOURCE_STATUS,
        "source_view_id": source_view_id,
        "claimed_receipt_sha256": claimed_receipt,
        "generated_at": str(source["generated_at"]),
        "cutoff_at": str(source["cutoff_at"]),
        "research_as_of_official_day": research_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "official_days": [item.isoformat() for item in official_days],
        "source_bindings": sorted(binding_rows, key=lambda row: row["binding_id"]),
        "products": normalized_products,
    }
    return normalized, bindings, official_days


def _pit_main(
    product: str,
    official_day: date,
    contracts: list[ContractObservation],
) -> tuple[ContractObservation, list[ContractObservation]]:
    source_yyyymm = official_day.year * 100 + official_day.month
    eligible = [
        row
        for row in contracts
        if int(row["delivery_yyyymm"]) > source_yyyymm
        and float(row["settlement"]) > 0
        and float(row["open_interest"]) > 0
    ]
    if len(eligible) < 3:
        raise ProducerKernelError(
            f"{product} {official_day} has fewer than three PIT-eligible contracts"
        )
    ranked = sorted(
        eligible,
        key=lambda row: (
            -float(row["open_interest"]),
            int(row["delivery_yyyymm"]),
            str(row["exact_contract"]),
        ),
    )
    return ranked[0], ranked


def _sign(value: float) -> int:
    if not math.isfinite(value):
        raise ProducerKernelError("trend value is not finite")
    if value > 0:
        return 1
    if value < 0:
        return -1
    return 0


def _sample_std(values: list[float]) -> float:
    if len(values) < 2:
        raise ProducerKernelError("sample standard deviation requires two values")
    mean = math.fsum(values) / len(values)
    variance = math.fsum((value - mean) ** 2 for value in values) / (
        len(values) - 1
    )
    return math.sqrt(max(variance, 0.0))


def _build_product_signal(
    product_view: ProductSourceView,
) -> tuple[dict[str, Any], dict[str, Any]]:
    product = product_view["product"]
    index_levels: list[float] = []
    returns: list[float] = []
    selected_rows: list[dict[str, Any]] = []
    previous: DailyProductView | None = None
    previous_main: ContractObservation | None = None
    index_level = 1.0
    for daily in product_view["daily"]:
        official_day = _parse_date(daily["official_day"], "daily official_day")
        main, ranked = _pit_main(product, official_day, daily["contracts"])
        daily_log_return: float | None = None
        if previous is not None and previous_main is not None:
            previous_settlement = float(previous_main["settlement"])
            comparable = {
                row["exact_contract"]: float(row["settlement"])
                for row in daily["contracts"]
            }.get(previous_main["exact_contract"])
            if comparable is None or comparable <= 0:
                raise ProducerKernelError(
                    f"{product} {official_day} lacks old-main comparable settlement"
                )
            daily_log_return = math.log(comparable / previous_settlement)
            if not math.isfinite(daily_log_return):
                raise ProducerKernelError("daily roll-safe return is not finite")
            returns.append(daily_log_return)
            index_level *= math.exp(daily_log_return)
        index_levels.append(index_level)
        selected_rows.append(
            {
                "official_day": official_day.isoformat(),
                "pit_main_exact_contract": main["exact_contract"],
                "pit_main_open_interest": main["open_interest"],
                "pit_main_settlement": main["settlement"],
                "eligible_contract_count": len(ranked),
                "daily_roll_safe_log_return": daily_log_return,
            }
        )
        previous = daily
        previous_main = main

    if len(index_levels) < max(TREND_HORIZONS) + 1:
        raise ProducerKernelError(f"{product} signal warmup is incomplete")
    trend_values = {
        horizon: math.log(index_levels[-1] / index_levels[-1 - horizon])
        for horizon in TREND_HORIZONS
    }
    trend_signs = {horizon: _sign(value) for horizon, value in trend_values.items()}
    if len(returns) < VOLATILITY_LOOKBACK:
        raise ProducerKernelError(f"{product} vol60 warmup is incomplete")
    vol60 = _sample_std(returns[-VOLATILITY_LOOKBACK:]) * math.sqrt(252.0)
    if not math.isfinite(vol60) or vol60 <= 0:
        raise ProducerKernelError(f"{product} vol60 must be positive before flooring")
    source_score = math.fsum(trend_signs.values()) / len(TREND_HORIZONS)
    raw_risk_score = source_score / max(vol60, VOLATILITY_FLOOR)
    signal = {
        "product": product,
        "trend_21_log_return": trend_values[21],
        "trend_63_log_return": trend_values[63],
        "trend_126_log_return": trend_values[126],
        "trend_21_sign": trend_signs[21],
        "trend_63_sign": trend_signs[63],
        "trend_126_sign": trend_signs[126],
        "source_score": source_score,
        "vol60_annualized": vol60,
        "vol60_return_count": VOLATILITY_LOOKBACK,
        "vol60_ddof": 1,
        "raw_risk_score": raw_risk_score,
        "trend_index_final": index_levels[-1],
        "history_official_day_count": len(index_levels),
        "pit_main_exact_contract": selected_rows[-1]["pit_main_exact_contract"],
    }
    roll = {
        "product": product,
        "selected_pit_main_history_sha256": _sha256(canonical_json(selected_rows)),
        "source_day_selection": selected_rows[-1],
        "source_day_eligible_contracts": [
            {
                "oi_rank": index + 1,
                "exact_contract": row["exact_contract"],
                "delivery_yyyymm": row["delivery_yyyymm"],
                "settlement": row["settlement"],
                "open_interest": row["open_interest"],
            }
            for index, row in enumerate(
                _pit_main(
                    product,
                    _parse_date(
                        product_view["daily"][-1]["official_day"],
                        "source official day",
                    ),
                    product_view["daily"][-1]["contracts"],
                )[1]
            )
        ],
    }
    return signal, roll


def _cap_source_weights(raw: dict[str, float]) -> dict[str, float]:
    mean = math.fsum(raw.values()) / len(PRODUCTS)
    centered = {product: raw[product] - mean for product in PRODUCTS}
    positive = math.fsum(max(value, 0.0) for value in centered.values())
    negative = math.fsum(max(-value, 0.0) for value in centered.values())
    if positive <= 1e-12 or negative <= 1e-12:
        return {product: 0.0 for product in PRODUCTS}
    weights = {
        product: (
            0.5 * centered[product] / positive
            if centered[product] > 0
            else 0.5 * centered[product] / negative
        )
        for product in PRODUCTS
    }
    weights = {
        product: max(
            -SOURCE_LIMITS["product"],
            min(SOURCE_LIMITS["product"], weights[product]),
        )
        for product in PRODUCTS
    }
    for sector in sorted(set(SECTOR_MAP.values())):
        members = [product for product in PRODUCTS if SECTOR_MAP[product] == sector]
        gross = math.fsum(abs(weights[product]) for product in members)
        if gross > SOURCE_LIMITS["sector"]:
            scale = SOURCE_LIMITS["sector"] / gross
            for product in members:
                weights[product] *= scale
    gross = math.fsum(abs(value) for value in weights.values())
    if gross > SOURCE_LIMITS["gross"]:
        weights = {
            product: value * SOURCE_LIMITS["gross"] / gross
            for product, value in weights.items()
        }
    positive_gross = math.fsum(max(value, 0.0) for value in weights.values())
    negative_gross = math.fsum(max(-value, 0.0) for value in weights.values())
    balanced = min(positive_gross, negative_gross)
    if balanced <= 0:
        raise ProducerKernelError("source caps removed one portfolio leg")
    for product, value in list(weights.items()):
        if value > 0:
            weights[product] = value * balanced / positive_gross
        elif value < 0:
            weights[product] = value * balanced / negative_gross
    _verify_weight_limits(weights, SOURCE_LIMITS, "source")
    return weights


def _buffer_weights(source: dict[str, float]) -> dict[str, float]:
    weights = {
        product: max(
            -BUFFER_LIMITS["product"],
            min(BUFFER_LIMITS["product"], source[product]),
        )
        for product in PRODUCTS
    }
    for sector in sorted(set(SECTOR_MAP.values())):
        members = [product for product in PRODUCTS if SECTOR_MAP[product] == sector]
        gross = math.fsum(abs(weights[product]) for product in members)
        if gross > BUFFER_LIMITS["sector"]:
            scale = BUFFER_LIMITS["sector"] / gross
            for product in members:
                weights[product] *= scale
    gross = math.fsum(abs(value) for value in weights.values())
    if gross > BUFFER_LIMITS["gross"]:
        scale = BUFFER_LIMITS["gross"] / gross
        weights = {product: value * scale for product, value in weights.items()}
    positive = math.fsum(max(value, 0.0) for value in weights.values())
    negative = math.fsum(max(-value, 0.0) for value in weights.values())
    if min(positive, negative) <= 1e-14:
        weights = {product: 0.0 for product in PRODUCTS}
    elif positive > negative:
        scale = negative / positive
        weights = {
            product: value * scale if value > 0 else value
            for product, value in weights.items()
        }
    elif negative > positive:
        scale = positive / negative
        weights = {
            product: value * scale if value < 0 else value
            for product, value in weights.items()
        }
    _verify_weight_limits(weights, BUFFER_LIMITS, "buffered")
    return weights


def _verify_weight_limits(
    weights: dict[str, float],
    limits: dict[str, float],
    label: str,
) -> None:
    if set(weights) != set(PRODUCTS) or any(
        not math.isfinite(value) for value in weights.values()
    ):
        raise ProducerKernelError(f"{label} weights are incomplete or non-finite")
    if max(abs(value) for value in weights.values()) > limits["product"] + 1e-12:
        raise ProducerKernelError(f"{label} product cap failed")
    if math.fsum(abs(value) for value in weights.values()) > limits["gross"] + 1e-12:
        raise ProducerKernelError(f"{label} gross cap failed")
    if abs(math.fsum(weights.values())) > 1e-10:
        raise ProducerKernelError(f"{label} net-zero check failed")
    for sector in set(SECTOR_MAP.values()):
        gross = math.fsum(
            abs(weights[product])
            for product in PRODUCTS
            if SECTOR_MAP[product] == sector
        )
        if gross > limits["sector"] + 1e-12:
            raise ProducerKernelError(f"{label} sector cap failed")


def _strictly_below(value: float, cap: float) -> bool:
    return (
        math.isfinite(value)
        and math.isfinite(cap)
        and cap > 0
        and value < cap - STRICT_EPSILON
    )


def _candidate_quantities(
    raw_quantity: float,
    target_weight: float,
    unit_weight: float,
) -> tuple[int, ...]:
    if not all(math.isfinite(value) for value in (raw_quantity, target_weight, unit_weight)):
        raise ProducerKernelError("integer allocator input is non-finite")
    if unit_weight <= 0:
        raise ProducerKernelError("integer allocator unit weight must be positive")
    if abs(target_weight) <= 1e-14:
        return (0,)
    if abs(raw_quantity) > MAX_ABS_TARGET_QUANTITY:
        raise ProducerKernelError(
            "raw target quantity exceeds the frozen absolute lot cap; "
            "refuse silent clipping/zeroing"
        )
    center = int(round(raw_quantity))
    values = set(
        range(
            center - NEIGHBOURHOOD_RADIUS_LOTS,
            center + NEIGHBOURHOOD_RADIUS_LOTS + 1,
        )
    )
    values.update(
        {
            0,
            math.trunc(raw_quantity),
            math.floor(raw_quantity),
            math.ceil(raw_quantity),
        }
    )
    if target_weight > 0:
        values = {quantity for quantity in values if quantity >= 0}
    else:
        values = {quantity for quantity in values if quantity <= 0}
    values = {
        int(quantity)
        for quantity in values
        if abs(int(quantity)) <= MAX_ABS_TARGET_QUANTITY
        and _strictly_below(
            abs(float(quantity) * unit_weight),
            INTEGER_LIMITS["product"],
        )
    }
    values.add(0)
    return tuple(sorted(values))


def _joint_integer_allocate(
    target: dict[str, float],
    unit_weights: dict[str, float],
) -> Allocation:
    if set(target) != set(PRODUCTS) or set(unit_weights) != set(PRODUCTS):
        raise ProducerKernelError("integer allocator input is incomplete")
    if any(
        not math.isfinite(value) or value <= 0 for value in unit_weights.values()
    ):
        raise ProducerKernelError("integer allocator unit weight is invalid")
    raw = {
        product: target[product] / unit_weights[product] for product in PRODUCTS
    }
    oversized = {
        product: raw[product]
        for product in PRODUCTS
        if abs(target[product]) > 1e-14
        and abs(raw[product]) > MAX_ABS_TARGET_QUANTITY
    }
    if oversized:
        details = ", ".join(
            f"{product}={oversized[product]:.12g}"
            for product in sorted(oversized)
        )
        raise ProducerKernelError(
            "raw target quantity exceeds the frozen absolute lot cap; "
            f"refuse silent clipping/zeroing: {details}"
        )
    candidates = {
        product: _candidate_quantities(
            raw[product],
            target[product],
            unit_weights[product],
        )
        for product in PRODUCTS
    }
    order = tuple(sorted(PRODUCTS, key=lambda product: (-unit_weights[product], product)))
    sectors = tuple(sorted(set(SECTOR_MAP.values())))
    sector_index = {sector: index for index, sector in enumerate(sectors)}
    option_weights = {
        product: tuple(
            quantity * unit_weights[product] for quantity in candidates[product]
        )
        for product in PRODUCTS
    }
    suffix_min_net = [0.0] * (len(order) + 1)
    suffix_max_net = [0.0] * (len(order) + 1)
    suffix_min_sse = [0.0] * (len(order) + 1)
    for index in range(len(order) - 1, -1, -1):
        product = order[index]
        options = option_weights[product]
        suffix_min_net[index] = suffix_min_net[index + 1] + min(options)
        suffix_max_net[index] = suffix_max_net[index + 1] + max(options)
        suffix_min_sse[index] = suffix_min_sse[index + 1] + min(
            (weight - target[product]) ** 2 for weight in options
        )

    State = tuple[float, float, float, tuple[float, ...], tuple[int, ...]]
    states: list[State] = [
        (0.0, 0.0, 0.0, tuple(0.0 for _ in sectors), tuple())
    ]
    for index, product in enumerate(order):
        expanded: list[tuple[float, State]] = []
        sidx = sector_index[SECTOR_MAP[product]]
        for sse, net, gross, sector_gross, quantities in states:
            for quantity in candidates[product]:
                weight = quantity * unit_weights[product]
                next_gross = gross + abs(weight)
                if not _strictly_below(next_gross, INTEGER_LIMITS["gross"]):
                    continue
                next_sector = list(sector_gross)
                next_sector[sidx] += abs(weight)
                if not _strictly_below(
                    next_sector[sidx],
                    INTEGER_LIMITS["sector"],
                ):
                    continue
                next_net = net + weight
                next_sse = sse + (weight - target[product]) ** 2
                low = next_net + suffix_min_net[index + 1]
                high = next_net + suffix_max_net[index + 1]
                if low > 0:
                    minimum_abs_net = low
                elif high < 0:
                    minimum_abs_net = -high
                else:
                    minimum_abs_net = 0.0
                lower_bound = (
                    next_sse
                    + suffix_min_sse[index + 1]
                    + NET_ERROR_PENALTY * minimum_abs_net**2
                )
                state: State = (
                    next_sse,
                    next_net,
                    next_gross,
                    tuple(next_sector),
                    quantities + (quantity,),
                )
                expanded.append((lower_bound, state))
        if not expanded:
            break
        expanded.sort(
            key=lambda item: (
                item[0],
                item[1][0],
                abs(item[1][1]),
                item[1][4],
            )
        )
        states = [item[1] for item in expanded[:BEAM_WIDTH]]

    feasible = [
        state
        for state in states
        if len(state[4]) == len(order)
        and _strictly_below(abs(state[1]), INTEGER_LIMITS["abs_net"])
    ]
    if not feasible:
        quantities = {product: 0 for product in PRODUCTS}
        squared_error = math.fsum(target[product] ** 2 for product in PRODUCTS)
        return Allocation(
            quantities=quantities,
            raw_quantities=raw,
            realized_weights={product: 0.0 for product in PRODUCTS},
            squared_target_error=squared_error,
            residual_net=0.0,
            objective=squared_error,
            gross=0.0,
            sector_gross={sector: 0.0 for sector in sectors},
            states_retained=len(states),
        )
    best = min(
        feasible,
        key=lambda state: (
            state[0] + NET_ERROR_PENALTY * state[1] ** 2,
            state[0],
            abs(state[1]),
            state[4],
        ),
    )
    sse, residual_net, gross, sector_tuple, quantity_tuple = best
    quantities = dict(zip(order, quantity_tuple))
    realized = {
        product: quantities[product] * unit_weights[product] for product in PRODUCTS
    }
    return Allocation(
        quantities=quantities,
        raw_quantities=raw,
        realized_weights=realized,
        squared_target_error=sse,
        residual_net=residual_net,
        objective=sse + NET_ERROR_PENALTY * residual_net**2,
        gross=gross,
        sector_gross=dict(zip(sectors, sector_tuple)),
        states_retained=len(states),
    )


def _artifact_base(
    role: str,
    source: PitFrozenSourceView,
    source_sha256: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": f"{ARTIFACT_SCHEMA_PREFIX}_{role}_v1",
        "purpose": STATUS,
        "status": STATUS,
        "artifact_role": role,
        "candidate_id": CANDIDATE_ID,
        "producer_kernel_id": KERNEL_ID,
        "source_view_id": source["source_view_id"],
        "source_view_canonical_sha256": source_sha256,
        "claimed_receipt_sha256": source["claimed_receipt_sha256"],
        "source_receipt_signature_verified": False,
        "source_receipt_keyring_verified": False,
        "source_custody_verified": False,
        "sealed_export_verified": False,
        "generated_at": source["generated_at"],
        "research_evidence_only": True,
    }
    for field in FALSE_AUTHORITY_FIELDS:
        payload[field] = False
    return payload


def produce_research_artifacts(
    source_view: Mapping[str, Any] | bytes | bytearray,
) -> ProducerResult:
    """Produce deterministic non-authoritative bytes from one bounded view."""
    bounded_source_view = _bounded_source_view_input(source_view)
    source, _bindings, official_days = _validate_and_normalize_source_view(
        bounded_source_view
    )
    source_raw = canonical_json(source)
    source_sha256 = _sha256(source_raw)
    research_day = _parse_date(
        source["research_as_of_official_day"],
        "research_as_of_official_day",
    )
    execution_day = _parse_date(source["execution_day"], "execution_day")
    execution_index = official_days.index(execution_day)
    following_day = official_days[execution_index + 1]

    signals: dict[str, dict[str, Any]] = {}
    roll_rows: dict[str, dict[str, Any]] = {}
    product_views = {row["product"]: row for row in source["products"]}
    for product in PRODUCTS:
        signal, roll = _build_product_signal(product_views[product])
        signals[product] = signal
        roll_rows[product] = roll

    raw_scores = {
        product: float(signals[product]["raw_risk_score"])
        for product in PRODUCTS
    }
    source_weights = _cap_source_weights(raw_scores)
    buffered_weights = _buffer_weights(source_weights)
    unit_weights = {
        product: (
            product_views[product]["execution_reference"]["official_open"]
            * product_views[product]["contract_spec"]["multiplier"]
            / VIRTUAL_NAV_CNY
        )
        for product in PRODUCTS
    }
    allocation = _joint_integer_allocate(buffered_weights, unit_weights)

    target_rows: list[dict[str, Any]] = []
    reference_rows: list[dict[str, Any]] = []
    spec_rows: list[dict[str, Any]] = []
    daily_roll_rows: list[dict[str, Any]] = []
    for product in PRODUCTS:
        product_view = product_views[product]
        signal = signals[product]
        reference = product_view["execution_reference"]
        spec = product_view["contract_spec"]
        exact_contract = str(signal["pit_main_exact_contract"])
        if (
            reference["exact_contract"] != exact_contract
            or spec["exact_contract"] != exact_contract
        ):
            raise ProducerKernelError(
                f"{product} PIT main/reference/spec exact contract splice"
            )
        last_trading_day = _parse_date(
            spec["official_last_trading_day"],
            "official_last_trading_day",
        )
        dte = (last_trading_day - execution_day).days
        following_dte = (last_trading_day - following_day).days
        if dte < 11 or following_dte < 11:
            raise ProducerKernelError(f"{product} PIT main is inside the DTE safety boundary")
        quantity = allocation.quantities[product]
        target_rows.append(
            {
                "product": product,
                "sector": SECTOR_MAP[product],
                "trend_21_sign": signal["trend_21_sign"],
                "trend_63_sign": signal["trend_63_sign"],
                "trend_126_sign": signal["trend_126_sign"],
                "source_score": signal["source_score"],
                "vol60_annualized": signal["vol60_annualized"],
                "raw_risk_score": signal["raw_risk_score"],
                "source_target_weight": source_weights[product],
                "buffered_target_weight": buffered_weights[product],
                "previous_exact_contract": None,
                "exact_contract": exact_contract,
                "previous_target_quantity": 0,
                "target_quantity": quantity,
                "reference_open_price": reference["official_open"],
                "reference_price_field": "official_open",
                "reference_price_observed_at": reference["observed_at"],
                "reference_price_source_sha256": reference["raw_sha256"],
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
                "pit_main_exact_contract": exact_contract,
                "pit_main_dte": dte,
                "pit_main_official_last_trading_day": last_trading_day.isoformat(),
                "pit_main_following_official_day": following_day.isoformat(),
                "pit_main_following_dte": following_dte,
                "pit_main_target_position_allowed": True,
                "pit_main_roll": False,
            }
        )
        reference_rows.append(
            {
                "product": product,
                "execution_day": execution_day.isoformat(),
                "exact_contract": exact_contract,
                "reference_price_field": "official_open",
                "reference_open_price": reference["official_open"],
                "observed_at": reference["observed_at"],
                "source_binding_id": reference["source_binding_id"],
                "source_raw_sha256": reference["raw_sha256"],
            }
        )
        spec_rows.append(
            {
                "product": product,
                "exchange": product_view["exchange"],
                "exact_contract": exact_contract,
                "official_last_trading_day": last_trading_day.isoformat(),
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
                "source_binding_id": spec["source_binding_id"],
                "source_raw_sha256": spec["raw_sha256"],
                "frozen_spec_match": True,
            }
        )
        daily_roll_rows.append(
            {
                **roll_rows[product],
                "research_as_of_official_day": research_day.isoformat(),
                "execution_day": execution_day.isoformat(),
                "pit_main_exact_contract": exact_contract,
                "pit_main_dte": dte,
                "pit_main_official_last_trading_day": last_trading_day.isoformat(),
                "pit_main_following_official_day": following_day.isoformat(),
                "pit_main_following_dte": following_dte,
                "pit_main_target_position_allowed": True,
                "pit_main_roll": False,
            }
        )

    artifact_payloads: dict[str, dict[str, Any]] = {}
    freeze = _artifact_base("freeze_contract", source, source_sha256)
    freeze.update(
        {
            "frozen_rule_id": FROZEN_RULE_ID,
            "frozen_rule_sha256": FROZEN_RULE_SHA256,
            "frozen_rule_hash_scope": (
                "external forward-freeze canonical FIXED_RULE; allocator lineage separate"
            ),
            "frozen_rule_projection": {
                "universe": list(PRODUCTS),
                "frequency": "MONTHLY",
                "pit_main_definition": "DAILY_PIT_OI_MAIN",
                "trend_horizons_official_days": list(TREND_HORIZONS),
                "volatility_lookback_official_days": VOLATILITY_LOOKBACK,
                "volatility_ddof": 1,
                "volatility_annualization": 252,
                "volatility_floor": VOLATILITY_FLOOR,
                "source_limits": SOURCE_LIMITS,
                "buffer_limits": BUFFER_LIMITS,
                "integer_limits_strict": INTEGER_LIMITS,
                "virtual_nav_cny": VIRTUAL_NAV_CNY,
                "neighbourhood_radius_lots": NEIGHBOURHOOD_RADIUS_LOTS,
                "beam_width": BEAM_WIDTH,
                "net_error_penalty": NET_ERROR_PENALTY,
                "absolute_lot_cap": MAX_ABS_TARGET_QUANTITY,
                "raw_lot_cap_policy": "REJECT_NOT_CLIP_OR_ZERO",
            },
            "source_resource_limits": {
                "max_raw_bytes": MAX_SOURCE_VIEW_RAW_BYTES,
                "max_official_days": MAX_OFFICIAL_DAYS,
                "max_source_bindings": MAX_SOURCE_BINDINGS,
                "max_daily_rows_per_product": MAX_DAILY_ROWS_PER_PRODUCT,
                "max_contracts_per_product_day": (
                    MAX_CONTRACTS_PER_PRODUCT_DAY
                ),
                "max_total_contract_rows": MAX_TOTAL_CONTRACT_ROWS,
            },
            "lineage": LINEAGE,
        }
    )
    artifact_payloads["freeze_contract"] = freeze

    manifest = _artifact_base("research_manifest", source, source_sha256)
    manifest.update(
        {
            "source_schema_version": SOURCE_SCHEMA_VERSION,
            "source_status": source["status"],
            "research_source_class": RESEARCH_SOURCE_CLASS,
            "source_cutoff_at": source["cutoff_at"],
            "research_as_of_official_day": source["research_as_of_official_day"],
            "execution_day": source["execution_day"],
            "source_bindings": source["source_bindings"],
            "source_artifact_roles": list(ARTIFACT_ROLES),
            "lineage": LINEAGE,
            "real_artifact_claimed": False,
            "sealed_export_receipt_verified": False,
            "sealed_export_upgrade_issue": 171,
        }
    )
    artifact_payloads["research_manifest"] = manifest

    signal_evidence = _artifact_base("signal_evidence", source, source_sha256)
    signal_evidence.update(
        {
            "research_as_of_official_day": source["research_as_of_official_day"],
            "trend_return_definition": (
                "old PIT-main exact-contract adjacent official-day settlement log return"
            ),
            "roll_rule": "new PIT main anchors same day; old exact contract closes interval",
            "signals": [signals[product] for product in PRODUCTS],
        }
    )
    artifact_payloads["signal_evidence"] = signal_evidence

    target_evidence = _artifact_base("target_evidence", source, source_sha256)
    target_evidence.update(
        {
            "execution_day": source["execution_day"],
            "source_target_formula": (
                "raw mean removal; positive/negative legs 50% gross; caps; shrink larger leg"
            ),
            "buffer_formula": "shrink-only product-sector-gross caps then exact zero-net",
            "targets": [
                {
                    "product": row["product"],
                    "source_target_weight": row["source_target_weight"],
                    "buffered_target_weight": row["buffered_target_weight"],
                    "target_quantity": row["target_quantity"],
                    "exact_contract": row["exact_contract"],
                }
                for row in target_rows
            ],
        }
    )
    artifact_payloads["target_evidence"] = target_evidence

    allocation_evidence = _artifact_base(
        "allocation_evidence",
        source,
        source_sha256,
    )
    allocation_evidence.update(
        {
            "virtual_nav_cny": VIRTUAL_NAV_CNY,
            "algorithm": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": NEIGHBOURHOOD_RADIUS_LOTS,
            "beam_width": BEAM_WIDTH,
            "net_error_penalty": NET_ERROR_PENALTY,
            "absolute_lot_cap": MAX_ABS_TARGET_QUANTITY,
            "raw_lot_cap_policy": "REJECT_NOT_CLIP_OR_ZERO",
            "integer_limits_strict": INTEGER_LIMITS,
            "raw_quantities": allocation.raw_quantities,
            "quantities": allocation.quantities,
            "realized_weights": allocation.realized_weights,
            "squared_target_error": allocation.squared_target_error,
            "residual_net": allocation.residual_net,
            "objective": allocation.objective,
            "gross": allocation.gross,
            "sector_gross": allocation.sector_gross,
            "states_retained": allocation.states_retained,
        }
    )
    artifact_payloads["allocation_evidence"] = allocation_evidence

    daily_roll = _artifact_base("daily_roll_evidence", source, source_sha256)
    daily_roll.update(
        {
            "pit_main_definition": "DAILY_PIT_OI_MAIN",
            "oi_rank_tie_break": [
                "open_interest_desc",
                "delivery_yyyymm_asc",
                "exact_contract_asc",
            ],
            "rows": daily_roll_rows,
        }
    )
    artifact_payloads["daily_roll_evidence"] = daily_roll

    reference_evidence = _artifact_base(
        "reference_price_evidence",
        source,
        source_sha256,
    )
    reference_evidence.update(
        {
            "execution_day": source["execution_day"],
            "reference_price_field": "official_open",
            "rows": reference_rows,
        }
    )
    artifact_payloads["reference_price_evidence"] = reference_evidence

    calendar = _artifact_base("calendar_authority", source, source_sha256)
    calendar_binding = next(
        row for row in source["source_bindings"] if row["source_class"] == "CALENDAR"
    )
    calendar.update(
        {
            "calendar_source_binding": calendar_binding,
            "official_days": source["official_days"],
            "research_as_of_official_day": source["research_as_of_official_day"],
            "execution_day": source["execution_day"],
            "following_official_day": following_day.isoformat(),
            "execution_is_immediate_next_official_day": True,
        }
    )
    artifact_payloads["calendar_authority"] = calendar

    contract_spec = _artifact_base(
        "contract_spec_evidence",
        source,
        source_sha256,
    )
    contract_spec.update({"rows": spec_rows})
    artifact_payloads["contract_spec_evidence"] = contract_spec

    artifacts = {
        role: canonical_json(artifact_payloads[role]) for role in ARTIFACT_ROLES
    }
    if (
        set(artifacts) != set(ARTIFACT_ROLES)
        or any(not raw for raw in artifacts.values())
        or len(set(artifacts.values())) != len(ARTIFACT_ROLES)
    ):
        raise ProducerKernelError("nine canonical artifacts are incomplete or duplicated")

    producer_projection: dict[str, Any] = {
        "projection_type": "producer_projection_v1",
        "status": STATUS,
        "candidate_id": CANDIDATE_ID,
        "producer_kernel_id": KERNEL_ID,
        "source_view_canonical_sha256": source_sha256,
        "artifact_roles": list(ARTIFACT_ROLES),
        "artifact_digests": [
            {"role": role, "sha256": _sha256(artifacts[role])}
            for role in ARTIFACT_ROLES
        ],
    }
    return ProducerResult(
        status=STATUS,
        source_view_canonical_sha256=source_sha256,
        artifacts=artifacts,
        producer_projection=producer_projection,
    )
