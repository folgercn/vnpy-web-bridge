"""Root-pinned Research Warehouse adapter for the frozen C_FAST producer.

The adapter is deliberately one way: verified Warehouse bytes become one
typed source view and nine deterministic Research artifacts.  It cannot sign,
install, dispatch, access an account, or trade.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import commodity_c_fast_pure_producer_kernel as producer

from .calendar_models import OfficialCalendar
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import false_authority
from .pit_source_view import (
    PitSourceViewError,
    _official_month_boundary,
    _pit_main,
    contract_rows_from_daily_raw,
)
from .pit_source_view_custody import (
    DIRECTORY_FLAGS,
    _create_at,
    _directory_identity,
    _open_bound_directory,
    _read_at,
    _require_private_directory,
)
from .sealed_export_contracts import validate_artifact_set, validate_lineage
from .static_core_baseline import (
    _aggregate_raw_identity,
    _binding,
    _last_trading_day,
    _registry,
)
from .timeutil import format_utc, parse_utc, require_utc
from .trade_day_mapping import map_exchange_timestamp

EVIDENCE_SCHEMA = "vnpy_research_c_fast_pit_source_evidence_v2"
DERIVATION_ID = "ROOT_PINNED_WAREHOUSE_C_FAST_PIT_SOURCE_V2"
SOURCE_VIEW_FILENAME = "source-view.json"
LINEAGE_FILENAME = "lineage.jsonl"
EVIDENCE_FILENAME = "source-evidence.jsonl"
IDENTITY_KEYS = {
    "history_receipt_raw_sha256",
    "history_receipt_completed_at",
    "calendar_raw_sha256",
    "calendar_anchor_raw_sha256",
    "warehouse_registry_raw_sha256",
    "contract_registry_raw_sha256",
    "operator_pins",
    "source_month",
    "execution_open_observed_at",
    "execution_open_receipt_raw_sha256",
    "execution_open_tick_export_raw_sha256",
    "derivation_id",
}
EVIDENCE_KEYS = {
    "schema_version",
    "derivation_id",
    "source_month",
    "research_as_of_official_day",
    "execution_day",
    "generated_at",
    "history_receipt_completed_at",
    "pins",
    "source_view_raw_sha256",
    "source_view_raw_bytes",
    "lineage_raw_sha256",
    "artifact_digests",
    "producer_replay",
    "authority",
}


@dataclass(frozen=True)
class VerifiedExecutionOpenObservation:
    official_day: str
    observed_at: datetime
    receipt_raw_sha256: str
    tick_export_raw_sha256: str
    rows: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class BuiltCFastSourceView:
    source_view_raw: bytes
    artifacts: dict[str, bytes]
    lineage_raw: bytes
    evidence_raw: bytes


def load_execution_open_observation(
    *,
    receipt_path: Path,
    capture_path: Path,
    tick_export_path: Path,
    official_day: date,
    calendar: OfficialCalendar | None = None,
) -> VerifiedExecutionOpenObservation:
    """Verify an immutable CTP exchange-feed open observation and exact tick export."""

    receipt_raw = read_regular_strict(
        receipt_path,
        "C_FAST execution-open observation receipt",
        limit=4 * 1024 * 1024,
    )
    receipt = parse_json_strict(
        receipt_raw, "C_FAST execution-open observation receipt"
    )
    expected_keys = {
        "schema_version",
        "purpose",
        "execution_day",
        "observed_at",
        "source",
        "capture_raw_sha256",
        "capture_raw_bytes",
        "tick_export_raw_sha256",
        "tick_export_raw_bytes",
        "rows",
        "authority",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) != expected_keys
        or receipt_raw != canonical_json_line(receipt)
        or receipt.get("schema_version")
        != "commodity_c_fast_execution_open_observation_v1"
        or receipt.get("purpose") != "c_fast_execution_open_observation"
        or receipt.get("source") != "SIMNOW_CTP_EXCHANGE_MARKET_DATA"
        or receipt.get("authority") != "RESEARCH_EVIDENCE_ONLY"
        or receipt.get("execution_day") != official_day.isoformat()
    ):
        raise PitSourceViewError("C_FAST execution-open receipt contract mismatch")
    capture_raw = read_regular_strict(
        capture_path, "C_FAST execution-open raw capture", limit=8 * 1024 * 1024
    )
    if receipt.get("capture_raw_bytes") != len(capture_raw) or receipt.get(
        "capture_raw_sha256"
    ) != sha256(capture_raw):
        raise PitSourceViewError("C_FAST execution-open raw capture binding mismatch")
    tick_raw = read_regular_strict(
        tick_export_path, "C_FAST execution-open tick export", limit=8 * 1024 * 1024
    )
    if receipt.get("tick_export_raw_bytes") != len(tick_raw) or receipt.get(
        "tick_export_raw_sha256"
    ) != sha256(tick_raw):
        raise PitSourceViewError("C_FAST execution-open tick export binding mismatch")
    ticks = parse_json_strict(tick_raw, "C_FAST execution-open tick export")
    if not isinstance(ticks, list) or receipt.get("rows") != ticks:
        raise PitSourceViewError("C_FAST execution-open receipt/tick rows mismatch")
    observed_at = parse_utc(receipt.get("observed_at"), "execution-open observed_at")
    if not _timestamp_belongs_to_execution_day(
        observed_at,
        official_day=official_day,
        calendar=calendar,
    ):
        raise PitSourceViewError(
            "C_FAST execution-open observation is not execution-day"
        )
    rows: dict[str, dict[str, Any]] = {}
    required_row_keys = {
        "exact_contract",
        "exchange",
        "open_price",
        "tick_datetime",
        "trading_day",
        "gateway_name",
    }
    for row in ticks:
        if not isinstance(row, dict) or set(row) != required_row_keys:
            raise PitSourceViewError("C_FAST execution-open tick row contract mismatch")
        contract = row.get("exact_contract")
        exchange = row.get("exchange")
        price = row.get("open_price")
        if (
            not isinstance(contract, str)
            or producer.CONTRACT_PATTERN.fullmatch(contract) is None
            or exchange not in {"SHFE", "INE"}
            or not isinstance(price, (int, float))
            or isinstance(price, bool)
            or not math.isfinite(float(price))
            or float(price) >= 1_000_000_000
            or float(price) <= 0
            or row.get("trading_day") != official_day.isoformat()
            or row.get("gateway_name") != "CTP"
            or contract in rows
        ):
            raise PitSourceViewError("C_FAST execution-open tick row is invalid")
        tick_at = parse_utc(row.get("tick_datetime"), "execution-open tick_datetime")
        if tick_at > observed_at:
            raise PitSourceViewError("C_FAST execution-open tick postdates observation")
        rows[contract] = row
    if not rows:
        raise PitSourceViewError("C_FAST execution-open observation is empty")
    return VerifiedExecutionOpenObservation(
        official_day=official_day.isoformat(),
        observed_at=observed_at,
        receipt_raw_sha256=sha256(receipt_raw),
        tick_export_raw_sha256=sha256(tick_raw),
        rows=rows,
    )


def _timestamp_belongs_to_execution_day(
    value: datetime,
    *,
    official_day: date,
    calendar: OfficialCalendar | None,
) -> bool:
    local = value.astimezone(producer.CHINA_TZ)
    if local.date() == official_day:
        return True
    if calendar is None or not (local.hour >= 20 or local.hour <= 3):
        return False
    try:
        mapped = map_exchange_timestamp(
            value,
            exchange="SHFE",
            session="NIGHT",
            calendar=calendar,
        )
    except RegistryError:
        return False
    return mapped.trade_day == official_day


def build_c_fast_source_view(
    *,
    calendar: OfficialCalendar,
    calendar_anchor_raw_sha256: str,
    warehouse_registry_raw_sha256: str,
    history_receipt: dict[str, Any],
    history_receipt_raw_sha256: str,
    operator_pins: dict[str, str],
    daily_source_raw: dict[str, dict[str, bytes]],
    execution_day_source: VerifiedExecutionOpenObservation,
    contract_registry_raw: bytes,
    expected_contract_registry_raw_sha256: str,
    source_month: str,
    observed_at_utc: datetime,
) -> BuiltCFastSourceView:
    """Build and replay exact C_FAST bytes from verified Warehouse custody."""

    history_official_days = history_receipt.get("official_days")
    history_daily_receipts = history_receipt.get("daily_receipts")
    if (
        history_receipt.get("required_official_days") != 186
        or not isinstance(history_official_days, list)
        or len(history_official_days) != 186
        or history_official_days != sorted(set(history_official_days))
        or not isinstance(history_daily_receipts, list)
        or [
            row.get("trade_day") if isinstance(row, dict) else None
            for row in history_daily_receipts
        ]
        != history_official_days
    ):
        raise PitSourceViewError("C_FAST history receipt is not the exact 186-day plan")
    if history_receipt.get("registry_raw_sha256") != warehouse_registry_raw_sha256:
        raise PitSourceViewError("C_FAST history receipt registry binding mismatch")
    required_operator_pins = {
        "operator_state_raw_sha256",
        "manifest_genesis_seal_sha256",
        "manifest_head_seal_sha256",
        "manifest_head_commit_seal_sha256",
        "commit_anchor_ledger_raw_sha256",
    }
    if set(operator_pins) != required_operator_pins or any(
        not isinstance(value, str) or producer.SHA256_PATTERN.fullmatch(value) is None
        for value in operator_pins.values()
    ):
        raise PitSourceViewError("C_FAST operator pin set is incomplete or invalid")
    registry, contract_registry_sha = _registry(contract_registry_raw)
    if contract_registry_sha != expected_contract_registry_raw_sha256:
        raise PitSourceViewError("C_FAST contract registry root pin mismatch")
    if (
        producer.SHA256_PATTERN.fullmatch(execution_day_source.receipt_raw_sha256)
        is None
        or producer.SHA256_PATTERN.fullmatch(
            execution_day_source.tick_export_raw_sha256
        )
        is None
    ):
        raise PitSourceViewError("C_FAST execution-day receipt SHA256 is invalid")
    research_day, first_execution_day, cutoff_day = _official_month_boundary(
        calendar,
        source_month=source_month,
    )
    try:
        execution_day = date.fromisoformat(execution_day_source.official_day)
    except ValueError as exc:
        raise PitSourceViewError("C_FAST execution-day source identity mismatch") from exc
    expected_execution_month = (
        (cutoff_day.year + 1, 1)
        if cutoff_day.month == 12
        else (cutoff_day.year, cutoff_day.month + 1)
    )
    calendar_row = calendar.days.get(execution_day)
    if (
        execution_day < first_execution_day
        or (execution_day.year, execution_day.month) != expected_execution_month
        or calendar_row is None
        or not calendar_row.is_official
    ):
        raise PitSourceViewError(
            "C_FAST execution day must be an official day in the month after source month"
        )
    if execution_day_source.official_day != execution_day.isoformat():
        raise PitSourceViewError("C_FAST execution-day source identity mismatch")
    source_completed_at = require_utc(
        execution_day_source.observed_at,
        "C_FAST execution-open observed_at",
    )
    generated_at = require_utc(observed_at_utc, "C_FAST source observed_at")
    history_completed_at = parse_utc(
        history_receipt.get("completed_at"),
        "C_FAST history receipt completed_at",
    )
    if (
        source_completed_at > generated_at
        or history_completed_at > generated_at
        or not _timestamp_belongs_to_execution_day(
            generated_at,
            official_day=execution_day,
            calendar=calendar,
        )
    ):
        raise PitSourceViewError(
            "C_FAST source must be built after history completion and open observation on execution day"
        )

    receipt_days = [
        day for day in history_official_days if day <= research_day.isoformat()
    ]
    receipt_last_day = date.fromisoformat(history_official_days[-1])
    supplemental_days = sorted(
        day.isoformat()
        for day, row in calendar.days.items()
        if row.is_official and receipt_last_day < day <= research_day
    )
    history_days = [*receipt_days, *supplemental_days]
    if (
        len(history_days) < max(producer.TREND_HORIZONS) + 1
        or history_days[-1] != research_day.isoformat()
    ):
        raise PitSourceViewError(
            "C_FAST Warehouse history lacks the research month-end or warmup"
        )
    if set(history_days) - set(daily_source_raw):
        raise PitSourceViewError("C_FAST Warehouse history exact days are incomplete")
    if any(set(daily_source_raw[day]) != {"SHFE", "INE"} for day in history_days):
        raise PitSourceViewError("C_FAST Warehouse history exchange set mismatch")
    following = sorted(
        day
        for day, row in calendar.days.items()
        if row.is_official and day > execution_day
    )
    if not following:
        raise PitSourceViewError("calendar lacks a following C_FAST official day")
    bridge_days = sorted(
        day.isoformat()
        for day, row in calendar.days.items()
        if row.is_official and research_day < day <= execution_day
    )
    official_days = [*history_days, *bridge_days, following[0].isoformat()]
    generated_text = format_utc(generated_at, "C_FAST source generated_at")

    market_bindings: dict[str, dict[str, Any]] = {}
    reference_bindings: dict[str, dict[str, Any]] = {}
    for exchange in ("SHFE", "INE"):
        market_sha = _aggregate_raw_identity(
            daily_source_raw,
            history_days,
            exchange,
        )
        market_bindings[exchange] = _binding(
            binding_id=f"market-{exchange.lower()}-{market_sha[:24]}",
            source_class="MARKET_DAILY",
            scope=exchange,
            source_identity=f"{exchange.lower()}-official-daily-custody-v1",
            query_start=history_days[0],
            query_end=history_days[-1],
            logical_at=generated_text,
            raw_sha256=market_sha,
            lineage={
                "history_receipt_raw_sha256": history_receipt_raw_sha256,
                "operator_pins": operator_pins,
                "exchange": exchange,
                "days": history_days,
            },
            history_receipt_sha256=history_receipt_raw_sha256,
        )
        exchange_rows = [
            row
            for row in execution_day_source.rows.values()
            if row["exchange"] == exchange
        ]
        reference_sha = sha256(canonical_json(exchange_rows))
        reference_bindings[exchange] = _binding(
            binding_id=f"open-{exchange.lower()}-{reference_sha[:24]}",
            source_class="REFERENCE_OPEN",
            scope=exchange,
            source_identity=f"{exchange.lower()}-official-daily-open-v1",
            query_start=execution_day.isoformat(),
            query_end=execution_day.isoformat(),
            logical_at=generated_text,
            raw_sha256=reference_sha,
            lineage={
                "operator_pins": operator_pins,
                "exchange": exchange,
                "execution_day": execution_day.isoformat(),
                "execution_open_observed_at": format_utc(
                    source_completed_at,
                    "C_FAST execution-open observed_at",
                ),
                "execution_open_receipt_raw_sha256": (
                    execution_day_source.receipt_raw_sha256
                ),
                "execution_open_tick_export_raw_sha256": (
                    execution_day_source.tick_export_raw_sha256
                ),
            },
            history_receipt_sha256=history_receipt_raw_sha256,
        )
    calendar_binding = _binding(
        binding_id=f"calendar-{calendar.raw_sha256[:24]}",
        source_class="CALENDAR",
        scope="SHFE_INE",
        source_identity=calendar.calendar_id,
        query_start=official_days[0],
        query_end=official_days[-1],
        logical_at=generated_text,
        raw_sha256=calendar.raw_sha256,
        lineage={
            "calendar_raw_sha256": calendar.raw_sha256,
            "calendar_anchor_raw_sha256": calendar_anchor_raw_sha256,
            "history_receipt_raw_sha256": history_receipt_raw_sha256,
        },
        history_receipt_sha256=history_receipt_raw_sha256,
    )
    spec_bindings = {
        exchange: _binding(
            binding_id=f"contract-spec-{exchange.lower()}-{contract_registry_sha[:20]}",
            source_class="CONTRACT_SPEC",
            scope=exchange,
            source_identity=f"c-fast-{exchange.lower()}-contract-registry-v1",
            query_start=execution_day.isoformat(),
            query_end=execution_day.isoformat(),
            logical_at=generated_text,
            raw_sha256=contract_registry_sha,
            lineage={
                "contract_registry_raw_sha256": contract_registry_sha,
                "calendar_raw_sha256": calendar.raw_sha256,
                "warehouse_registry_raw_sha256": warehouse_registry_raw_sha256,
                "exchange": exchange,
            },
            history_receipt_sha256=history_receipt_raw_sha256,
        )
        for exchange in ("SHFE", "INE")
    }

    daily_by_day: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for day in history_days:
        by_product = {product: [] for product in producer.PRODUCTS}
        for exchange in ("SHFE", "INE"):
            extracted = contract_rows_from_daily_raw(
                raw=daily_source_raw[day][exchange],
                exchange=exchange,
                official_day=day,
            )
            for product in producer.PRODUCTS:
                by_product[product].extend(extracted[product])
        daily_by_day[day] = by_product
    products: list[dict[str, Any]] = []
    for product in producer.PRODUCTS:
        frozen_spec = producer.PRODUCT_SPECS[product]
        main, _ranked = _pit_main(
            product,
            research_day,
            daily_by_day[history_days[-1]][product],
        )
        exact_contract = main["exact_contract"]
        execution_contract = execution_day_source.rows.get(exact_contract)
        if execution_contract is None:
            raise PitSourceViewError(
                f"{product} PIT main lacks execution-day official open"
            )
        if execution_contract["exchange"] != frozen_spec["exchange"]:
            raise PitSourceViewError(
                f"{product} execution-open exchange binding mismatch"
            )
        last_day = _last_trading_day(
            calendar,
            delivery_yyyymm=int(main["delivery_yyyymm"]),
            rule=registry[product]["last_trading_day_rule"],
        )
        exchange = frozen_spec["exchange"]
        products.append(
            {
                "product": product,
                "exchange": exchange,
                "daily": [
                    {
                        "official_day": day,
                        "source_binding_id": market_bindings[exchange]["binding_id"],
                        "contracts": daily_by_day[day][product],
                    }
                    for day in history_days
                ],
                "execution_reference": {
                    "source_binding_id": reference_bindings[exchange]["binding_id"],
                    "exact_contract": exact_contract,
                    "official_open": execution_contract["open_price"],
                    "observed_at": generated_text,
                    "raw_sha256": reference_bindings[exchange]["raw_sha256"],
                },
                "contract_spec": {
                    "source_binding_id": spec_bindings[exchange]["binding_id"],
                    "exact_contract": exact_contract,
                    "official_last_trading_day": last_day.isoformat(),
                    "multiplier": frozen_spec["multiplier"],
                    "price_tick": frozen_spec["price_tick"],
                    "raw_sha256": contract_registry_sha,
                },
            }
        )

    identity = {
        "history_receipt_raw_sha256": history_receipt_raw_sha256,
        "history_receipt_completed_at": format_utc(
            history_completed_at,
            "C_FAST history receipt completed_at",
        ),
        "calendar_raw_sha256": calendar.raw_sha256,
        "calendar_anchor_raw_sha256": calendar_anchor_raw_sha256,
        "warehouse_registry_raw_sha256": warehouse_registry_raw_sha256,
        "contract_registry_raw_sha256": contract_registry_sha,
        "operator_pins": operator_pins,
        "source_month": source_month,
        "execution_open_observed_at": format_utc(
            source_completed_at,
            "C_FAST execution-open observed_at",
        ),
        "execution_open_receipt_raw_sha256": (execution_day_source.receipt_raw_sha256),
        "execution_open_tick_export_raw_sha256": (
            execution_day_source.tick_export_raw_sha256
        ),
        "derivation_id": DERIVATION_ID,
    }
    source = {
        "schema_version": producer.SOURCE_SCHEMA_VERSION,
        "purpose": producer.SOURCE_PURPOSE,
        "status": producer.SOURCE_STATUS,
        "source_view_id": (
            f"warehouse-c-fast-{source_month.replace('-', '')}-"
            f"{sha256(canonical_json(identity))[:20]}"
        ),
        "claimed_receipt_sha256": history_receipt_raw_sha256,
        "generated_at": generated_text,
        "cutoff_at": generated_text,
        "research_as_of_official_day": research_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "official_days": official_days,
        "source_bindings": [
            calendar_binding,
            market_bindings["INE"],
            market_bindings["SHFE"],
            reference_bindings["INE"],
            reference_bindings["SHFE"],
            spec_bindings["INE"],
            spec_bindings["SHFE"],
        ],
        "products": products,
    }
    normalized_source, _bindings, _official_days = (
        producer._validate_and_normalize_source_view(source)
    )
    source_raw = producer.canonical_json(normalized_source)
    result = producer.produce_research_artifacts(source_raw)
    artifacts = dict(result.artifacts)
    lineage = validate_lineage(
        {
            "registry_raw_sha256": warehouse_registry_raw_sha256,
            "calendar_raw_sha256": calendar.raw_sha256,
            "calendar_anchor_sha256": calendar_anchor_raw_sha256,
            "commit_anchor_ledger_sha256": operator_pins[
                "commit_anchor_ledger_raw_sha256"
            ],
            "manifest_genesis_seal_sha256": operator_pins[
                "manifest_genesis_seal_sha256"
            ],
            "manifest_head_seal_sha256": operator_pins["manifest_head_seal_sha256"],
            "manifest_head_commit_seal_sha256": operator_pins[
                "manifest_head_commit_seal_sha256"
            ],
            "pit_cutoff_at": generated_text,
            "research_as_of_official_day": research_day.isoformat(),
            "execution_day": execution_day.isoformat(),
            "source_view_canonical_sha256": result.source_view_canonical_sha256,
        }
    )
    validate_artifact_set(artifacts, lineage=lineage)
    lineage_raw = canonical_json_line(lineage)
    evidence = {
        "schema_version": EVIDENCE_SCHEMA,
        "derivation_id": DERIVATION_ID,
        "source_month": source_month,
        "research_as_of_official_day": research_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "generated_at": generated_text,
        "history_receipt_completed_at": identity["history_receipt_completed_at"],
        "pins": identity,
        "source_view_raw_sha256": sha256(source_raw),
        "source_view_raw_bytes": len(source_raw),
        "lineage_raw_sha256": sha256(lineage_raw),
        "artifact_digests": [
            {"role": role, "raw_sha256": sha256(raw), "raw_bytes": len(raw)}
            for role, raw in artifacts.items()
        ],
        "producer_replay": "EXACT_NINE_ARTIFACT_BYTES_VERIFIED",
        "authority": false_authority(),
    }
    built = BuiltCFastSourceView(
        source_view_raw=source_raw,
        artifacts=artifacts,
        lineage_raw=lineage_raw,
        evidence_raw=canonical_json_line(evidence),
    )
    verify_built_c_fast_source_view(built)
    return built


def verify_built_c_fast_source_view(built: BuiltCFastSourceView) -> None:
    source = parse_json_strict(built.source_view_raw, "C_FAST source view")
    if (
        not isinstance(source, dict)
        or producer.canonical_json(source) != built.source_view_raw
    ):
        raise PitSourceViewError("C_FAST source view is not canonical")
    replay = producer.produce_research_artifacts(built.source_view_raw)
    if dict(replay.artifacts) != built.artifacts:
        raise PitSourceViewError("C_FAST nine-artifact replay diverged")
    lineage = parse_json_strict(built.lineage_raw, "C_FAST lineage")
    if (
        not isinstance(lineage, dict)
        or canonical_json_line(lineage) != built.lineage_raw
        or lineage.get("source_view_canonical_sha256")
        != replay.source_view_canonical_sha256
    ):
        raise PitSourceViewError("C_FAST lineage binding mismatch")
    validate_artifact_set(built.artifacts, lineage=validate_lineage(lineage))
    evidence = parse_json_strict(built.evidence_raw, "C_FAST source evidence")
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_KEYS:
        raise PitSourceViewError("C_FAST source evidence contract mismatch")
    identity = evidence["pins"]
    if not isinstance(identity, dict) or set(identity) != IDENTITY_KEYS:
        raise PitSourceViewError("C_FAST source evidence pin set mismatch")
    operator_pins = identity["operator_pins"]
    required_operator_pins = {
        "operator_state_raw_sha256",
        "manifest_genesis_seal_sha256",
        "manifest_head_seal_sha256",
        "manifest_head_commit_seal_sha256",
        "commit_anchor_ledger_raw_sha256",
    }
    digest_values = [
        identity["history_receipt_raw_sha256"],
        identity["calendar_raw_sha256"],
        identity["calendar_anchor_raw_sha256"],
        identity["warehouse_registry_raw_sha256"],
        identity["contract_registry_raw_sha256"],
        identity["execution_open_receipt_raw_sha256"],
        identity["execution_open_tick_export_raw_sha256"],
    ]
    if (
        not isinstance(operator_pins, dict)
        or set(operator_pins) != required_operator_pins
        or any(
            not isinstance(value, str)
            or producer.SHA256_PATTERN.fullmatch(value) is None
            for value in [*digest_values, *operator_pins.values()]
        )
        or identity["derivation_id"] != DERIVATION_ID
    ):
        raise PitSourceViewError("C_FAST source evidence root pins are invalid")
    expected_source_id = (
        f"warehouse-c-fast-{str(identity['source_month']).replace('-', '')}-"
        f"{sha256(canonical_json(identity))[:20]}"
    )
    artifact_digests = [
        {"role": role, "raw_sha256": sha256(raw), "raw_bytes": len(raw)}
        for role, raw in built.artifacts.items()
    ]
    expected_lineage_pins = {
        "registry_raw_sha256": identity["warehouse_registry_raw_sha256"],
        "calendar_raw_sha256": identity["calendar_raw_sha256"],
        "calendar_anchor_sha256": identity["calendar_anchor_raw_sha256"],
        "commit_anchor_ledger_sha256": operator_pins["commit_anchor_ledger_raw_sha256"],
        "manifest_genesis_seal_sha256": operator_pins["manifest_genesis_seal_sha256"],
        "manifest_head_seal_sha256": operator_pins["manifest_head_seal_sha256"],
        "manifest_head_commit_seal_sha256": operator_pins[
            "manifest_head_commit_seal_sha256"
        ],
    }
    if any(lineage[field] != value for field, value in expected_lineage_pins.items()):
        raise PitSourceViewError("C_FAST source evidence/lineage root pin mismatch")
    expected_evidence = {
        "schema_version": EVIDENCE_SCHEMA,
        "derivation_id": DERIVATION_ID,
        "source_month": identity["source_month"],
        "research_as_of_official_day": source["research_as_of_official_day"],
        "execution_day": source["execution_day"],
        "generated_at": source["generated_at"],
        "history_receipt_completed_at": identity["history_receipt_completed_at"],
        "pins": identity,
        "source_view_raw_sha256": sha256(built.source_view_raw),
        "source_view_raw_bytes": len(built.source_view_raw),
        "lineage_raw_sha256": sha256(built.lineage_raw),
        "artifact_digests": artifact_digests,
        "producer_replay": "EXACT_NINE_ARTIFACT_BYTES_VERIFIED",
        "authority": false_authority(),
    }
    if (
        source["source_view_id"] != expected_source_id
        or identity["source_month"] != str(source["research_as_of_official_day"])[:7]
    ):
        raise PitSourceViewError("C_FAST source evidence identity mismatch")
    if (
        lineage["pit_cutoff_at"] != source["cutoff_at"]
        or lineage["research_as_of_official_day"]
        != source["research_as_of_official_day"]
        or lineage["execution_day"] != source["execution_day"]
    ):
        raise PitSourceViewError("C_FAST source evidence date lineage mismatch")
    history_completed_at = parse_utc(
        identity["history_receipt_completed_at"],
        "C_FAST history receipt completed_at",
    )
    receipt_completed_at = parse_utc(
        identity["execution_open_observed_at"],
        "C_FAST execution-open observed_at",
    )
    source_generated_at = parse_utc(source["generated_at"], "C_FAST generated_at")
    execution_day = date.fromisoformat(source["execution_day"])
    source_official_days = [
        date.fromisoformat(day) for day in source["official_days"]
    ]
    if (
        history_completed_at > source_generated_at
        or receipt_completed_at > source_generated_at
        or not producer._timestamp_belongs_to_execution_day(
            receipt_completed_at,
            execution_day=execution_day,
            official_days=source_official_days,
        )
        or not producer._timestamp_belongs_to_execution_day(
            source_generated_at,
            execution_day=execution_day,
            official_days=source_official_days,
        )
    ):
        raise PitSourceViewError(
            "C_FAST source predates its execution-open observation"
        )
    bindings = {
        (row["source_class"], row["scope"]): row for row in source["source_bindings"]
    }
    history_days = [
        day
        for day in source["official_days"]
        if day <= source["research_as_of_official_day"]
    ]
    expected_binding_lineages = {
        ("CALENDAR", "SHFE_INE"): {
            "calendar_raw_sha256": identity["calendar_raw_sha256"],
            "calendar_anchor_raw_sha256": identity["calendar_anchor_raw_sha256"],
            "history_receipt_raw_sha256": identity["history_receipt_raw_sha256"],
        },
        **{
            ("MARKET_DAILY", exchange): {
                "history_receipt_raw_sha256": identity["history_receipt_raw_sha256"],
                "operator_pins": operator_pins,
                "exchange": exchange,
                "days": history_days,
            }
            for exchange in ("SHFE", "INE")
        },
        **{
            ("REFERENCE_OPEN", exchange): {
                "operator_pins": operator_pins,
                "exchange": exchange,
                "execution_day": source["execution_day"],
                "execution_open_observed_at": identity["execution_open_observed_at"],
                "execution_open_receipt_raw_sha256": identity[
                    "execution_open_receipt_raw_sha256"
                ],
                "execution_open_tick_export_raw_sha256": identity[
                    "execution_open_tick_export_raw_sha256"
                ],
            }
            for exchange in ("SHFE", "INE")
        },
        **{
            ("CONTRACT_SPEC", exchange): {
                "contract_registry_raw_sha256": identity[
                    "contract_registry_raw_sha256"
                ],
                "calendar_raw_sha256": identity["calendar_raw_sha256"],
                "warehouse_registry_raw_sha256": identity[
                    "warehouse_registry_raw_sha256"
                ],
                "exchange": exchange,
            }
            for exchange in ("SHFE", "INE")
        },
    }
    if set(bindings) != set(expected_binding_lineages) or any(
        bindings[key]["lineage_sha256"] != sha256(canonical_json(lineage_preimage))
        for key, lineage_preimage in expected_binding_lineages.items()
    ):
        raise PitSourceViewError("C_FAST source binding provenance mismatch")
    if (
        evidence != expected_evidence
        or canonical_json_line(evidence) != built.evidence_raw
    ):
        raise PitSourceViewError("C_FAST source evidence binding mismatch")


def publish_built_c_fast_source_view(
    output: Path,
    built: BuiltCFastSourceView,
) -> None:
    if output.name in {"", ".", ".."} or "/" in output.name:
        raise PitSourceViewError("C_FAST output directory name is unsafe")
    files = {
        SOURCE_VIEW_FILENAME: built.source_view_raw,
        LINEAGE_FILENAME: built.lineage_raw,
        EVIDENCE_FILENAME: built.evidence_raw,
        **{f"{role}.json": raw for role, raw in built.artifacts.items()},
    }
    root_fd, root_identity = _open_bound_directory(
        output.parent,
        "C_FAST output root",
    )
    output_fd: int | None = None
    try:
        try:
            os.mkdir(output.name, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError as exc:
            raise PitSourceViewError(
                "C_FAST output already exists; overwrite forbidden"
            ) from exc
        expected_output = _directory_identity(
            os.stat(output.name, dir_fd=root_fd, follow_symlinks=False)
        )
        output_fd = os.open(output.name, DIRECTORY_FLAGS, dir_fd=root_fd)
        output_info = os.fstat(output_fd)
        _require_private_directory(output_info, "C_FAST output directory")
        output_identity = _directory_identity(output_info)
        if output_identity != expected_output:
            raise PitSourceViewError("C_FAST output directory changed while opening")
        for name, raw in files.items():
            _create_at(output_fd, name, raw)
        if set(os.listdir(output_fd)) != set(files):
            raise PitSourceViewError("C_FAST published file set mismatch")
        for name, raw in files.items():
            if _read_at(output_fd, name, limit=max(1, len(raw))) != raw:
                raise PitSourceViewError("C_FAST published readback mismatch")
        if (
            _directory_identity(output.parent.lstat()) != root_identity
            or _directory_identity(
                os.stat(output.name, dir_fd=root_fd, follow_symlinks=False)
            )
            != output_identity
        ):
            raise PitSourceViewError("C_FAST output custody changed")
        os.fsync(output_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise PitSourceViewError("C_FAST publication failed closed") from exc
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(root_fd)


def read_built_c_fast_source_view(output: Path) -> BuiltCFastSourceView:
    descriptor, identity = _open_bound_directory(output, "C_FAST output directory")
    try:
        expected = {
            SOURCE_VIEW_FILENAME,
            LINEAGE_FILENAME,
            EVIDENCE_FILENAME,
            *(f"{role}.json" for role in producer.ARTIFACT_ROLES),
        }
        if set(os.listdir(descriptor)) != expected:
            raise PitSourceViewError("C_FAST output file set mismatch")
        built = BuiltCFastSourceView(
            source_view_raw=_read_at(
                descriptor,
                SOURCE_VIEW_FILENAME,
                limit=producer.MAX_SOURCE_VIEW_RAW_BYTES,
            ),
            artifacts={
                role: _read_at(
                    descriptor,
                    f"{role}.json",
                    limit=16 * 1024 * 1024,
                )
                for role in producer.ARTIFACT_ROLES
            },
            lineage_raw=_read_at(
                descriptor,
                LINEAGE_FILENAME,
                limit=1024 * 1024,
            ),
            evidence_raw=_read_at(
                descriptor,
                EVIDENCE_FILENAME,
                limit=4 * 1024 * 1024,
            ),
        )
        if _directory_identity(output.lstat()) != identity:
            raise PitSourceViewError("C_FAST output directory changed while read")
        return built
    finally:
        os.close(descriptor)
