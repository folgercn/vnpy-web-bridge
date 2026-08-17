"""Root-pinned historical Warehouse replay for a signed STATIC_CORE_EQUAL baseline.

This adapter verifies exact daily bytes outside the pure producer, constructs a
logical execution-day PIT view, freshly replays the frozen C/D producer, and
emits an unsigned target batch plus evidence.  It cannot sign, install, deploy,
dispatch, access accounts, or trade.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date, datetime, time
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import commodity_c_fast_pure_producer_kernel as frozen
import commodity_static_core_equal_pure_producer as baseline_producer

from .calendar_models import OfficialCalendar
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import false_authority
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_receipts import validate_run_receipt
from .m2_runtime_input import require_sha
from .m2_runtime_loader import RuntimeContext
from .pit_source_view import (
    PitSourceViewError,
    _official_month_boundary,
    _pit_main,
    _safe_relative_path,
    contract_rows_from_daily_raw,
    verified_daily_raw,
)
from .timeutil import parse_utc

REGISTRY_SCHEMA = "vnpy_research_static_core_contract_registry_v1"
RECEIPT_SCHEMA = "vnpy_research_static_core_baseline_evidence_v1"
DERIVATION_ID = "ROOT_PINNED_HISTORICAL_STATIC_CORE_EQUAL_REPLAY_V1"
SHFE_LAST_DAY_RULE = "SHFE_DELIVERY_MONTH_15TH_NEXT_OFFICIAL_V1"
INE_SC_LAST_DAY_RULE = "INE_SC_PREVIOUS_MONTH_LAST_OFFICIAL_V1"
CHINA_TZ = ZoneInfo("Asia/Shanghai")
PLACEHOLDER_SIGNATURE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
MAX_SOURCE_RAW_BYTES = 16 * 1024 * 1024
MAX_AGGREGATE_RAW_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class BuiltBaseline:
    source_view_raw: bytes
    artifacts: dict[str, bytes]
    unsigned_batch_raw: bytes
    evidence_raw: bytes


@dataclass(frozen=True)
class VerifiedStaticBaselineDailySources:
    """Exact historical and normal-run bytes, including supplemental lineage."""

    daily_raw: dict[str, dict[str, bytes]]
    supplemental_daily_receipts: tuple[dict[str, Any], ...]


def _logical_instant(day: date, value: time) -> str:
    return datetime.combine(day, value, tzinfo=CHINA_TZ).isoformat()


def _aggregate_raw_identity(
    daily_source_raw: dict[str, dict[str, bytes]],
    days: list[str],
    exchange: str,
) -> str:
    return sha256(
        canonical_json(
            [
                {
                    "official_day": day,
                    "raw_sha256": sha256(daily_source_raw[day][exchange]),
                    "raw_bytes": len(daily_source_raw[day][exchange]),
                }
                for day in days
            ]
        )
    )


def verified_static_baseline_daily_sources(
    *,
    context: RuntimeContext,
    history: dict[str, Any],
    chain: list[dict[str, Any]],
    source_month: str,
) -> VerifiedStaticBaselineDailySources:
    """Load a baseline's exact bytes without applying the PIT month-end cutoff.

    The fixed history receipt remains the authority for its own days.  Every
    later official day needed through the baseline execution day must instead
    have an independently verified *normal* run receipt and a committed,
    root-pinned manifest revision.  The resulting receipt/manifest pins are
    carried into the baseline evidence so an execution-day reference cannot be
    misrepresented as history-receipt-only provenance.
    """

    _research_day, execution_day, _cutoff_day = _official_month_boundary(
        context.calendar,
        source_month=source_month,
    )
    history_days = sorted(
        day
        for day in history.get("official_days", [])
        if day <= execution_day.isoformat()
    )
    if not history_days or history_days != sorted(set(history_days)):
        raise PitSourceViewError("static baseline history days are invalid")
    history_raw = verified_daily_raw(
        context=context,
        history=history,
        chain=chain,
        through_day=execution_day,
    )
    if set(history_raw) != set(history_days):
        raise PitSourceViewError("static baseline history daily evidence is incomplete")

    last_history_day = date.fromisoformat(history_days[-1])
    supplemental_days = [
        day
        for day, row in context.calendar.days.items()
        if row.is_official and last_history_day < day <= execution_day
    ]
    if supplemental_days and supplemental_days[-1] != execution_day:
        raise PitSourceViewError("static baseline supplemental official days are incomplete")

    manifests = {item["trade_day"]: item for item in chain}
    result = dict(history_raw)
    pins: list[dict[str, Any]] = []
    aggregate = sum(len(raw) for sources in result.values() for raw in sources.values())
    for day in supplemental_days:
        raw_day = day.isoformat()
        receipt_path = context.runtime.run_receipts / f"{raw_day}.json"
        receipt_raw = read_regular_strict(
            receipt_path,
            "static baseline supplemental daily run receipt",
        )
        receipt = validate_run_receipt(
            parse_json_strict(receipt_raw, "static baseline supplemental daily run receipt")
        )
        if (
            receipt_raw != canonical_json_line(receipt)
            or receipt_path.name != f"{receipt['trade_day']}.json"
        ):
            raise PitSourceViewError(
                "static baseline supplemental receipt raw/path binding mismatch"
            )
        verify_daily_run_receipt(
            receipt,
            paths=context.paths,
            registry=context.registry,
            calendar=context.calendar,
            calendar_availability_raw_sha256=context.availability.raw_sha256,
        )
        manifest = manifests.get(raw_day)
        if manifest is None or manifest["commit_receipt"] is None:
            raise PitSourceViewError(
                "static baseline supplemental daily manifest is uncommitted"
            )
        revisions = {item["revision_id"]: item for item in manifest["revisions"]}
        sources: dict[str, bytes] = {}
        source_pins: list[dict[str, Any]] = []
        for source in receipt["sources"]:
            revision = revisions.get(source["revision_id"])
            if revision is None or any(
                revision[field] != source[field]
                for field in ("raw_sha256", "raw_bytes", "raw_relative_path")
            ):
                raise PitSourceViewError(
                    "static baseline supplemental manifest/receipt revision mismatch"
                )
            raw_path = _safe_relative_path(
                context.paths.root,
                source["raw_relative_path"],
                "static baseline supplemental raw",
            )
            raw = read_regular_strict(
                raw_path,
                "static baseline supplemental exact raw",
                limit=MAX_SOURCE_RAW_BYTES,
            )
            if len(raw) != source["raw_bytes"] or sha256(raw) != source["raw_sha256"]:
                raise PitSourceViewError("static baseline supplemental raw bytes drifted")
            aggregate += len(raw)
            if aggregate > MAX_AGGREGATE_RAW_BYTES:
                raise PitSourceViewError(
                    "static baseline supplemental aggregate raw resource limit exceeded"
                )
            sources[source["exchange"]] = raw
            source_pins.append(
                {
                    "exchange": source["exchange"],
                    "raw_sha256": source["raw_sha256"],
                    "raw_bytes": source["raw_bytes"],
                    "revision_id": source["revision_id"],
                }
            )
        if set(sources) != {"SHFE", "INE"}:
            raise PitSourceViewError(
                "static baseline supplemental exact source set mismatch"
            )
        result[raw_day] = sources
        pins.append(
            {
                "trade_day": raw_day,
                "run_receipt_raw_sha256": sha256(receipt_raw),
                "completed_at": receipt["completed_at"],
                "manifest_batch_id": manifest["batch_id"],
                "manifest_batch_seal_sha256": manifest["batch_seal_sha256"],
                "manifest_commit_seal_sha256": manifest["commit_seal_sha256"],
                "sources": source_pins,
            }
        )
    return VerifiedStaticBaselineDailySources(
        daily_raw=result,
        supplemental_daily_receipts=tuple(pins),
    )


def _registry(raw: bytes) -> tuple[dict[str, dict[str, Any]], str]:
    payload = parse_json_strict(raw, "static-core contract registry")
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "registry_id",
        "generated_at",
        "sources",
        "products",
        "authority",
    }:
        raise PitSourceViewError("contract registry shape mismatch")
    if (
        payload["schema_version"] != REGISTRY_SCHEMA
        or not isinstance(payload["registry_id"], str)
        or len(payload["registry_id"]) < 8
        or not isinstance(payload["generated_at"], str)
        or not isinstance(payload["sources"], list)
        or not payload["sources"]
        or payload["authority"] != false_authority()
    ):
        raise PitSourceViewError("contract registry identity mismatch")
    rows = payload["products"]
    if not isinstance(rows, list) or len(rows) != len(frozen.PRODUCTS):
        raise PitSourceViewError("contract registry product count mismatch")
    by_product: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "product",
            "exchange",
            "multiplier",
            "price_tick",
            "last_trading_day_rule",
            "source_id",
        }:
            raise PitSourceViewError(f"contract registry row {index} shape mismatch")
        product = row["product"]
        if product not in frozen.PRODUCTS or product in by_product:
            raise PitSourceViewError("contract registry product set mismatch")
        expected = frozen.PRODUCT_SPECS[product]
        expected_rule = (
            INE_SC_LAST_DAY_RULE if product == "sc" else SHFE_LAST_DAY_RULE
        )
        if (
            row["exchange"] != expected["exchange"]
            or row["multiplier"] != expected["multiplier"]
            or float(row["price_tick"]) != float(expected["price_tick"])
            or row["last_trading_day_rule"] != expected_rule
            or not isinstance(row["source_id"], str)
            or not row["source_id"]
        ):
            raise PitSourceViewError(f"{product} contract registry conflicts with freeze")
        by_product[product] = row
    if tuple(sorted(by_product)) != frozen.PRODUCTS:
        raise PitSourceViewError("contract registry frozen universe mismatch")
    return by_product, sha256(raw)


def _last_trading_day(
    calendar: OfficialCalendar,
    *,
    delivery_yyyymm: int,
    rule: str,
) -> date:
    year, month = divmod(delivery_yyyymm, 100)
    if rule == SHFE_LAST_DAY_RULE:
        threshold = date(year, month, 15)
        candidates = sorted(
            day
            for day, row in calendar.days.items()
            if (
                row.is_official
                and day.year == year
                and day.month == month
                and day >= threshold
            )
        )
    elif rule == INE_SC_LAST_DAY_RULE:
        delivery_start = date(year, month, 1)
        previous_month_last = date.fromordinal(
            delivery_start.toordinal() - 1
        )
        candidates = sorted(
            (
                day
                for day, row in calendar.days.items()
                if (
                    row.is_official
                    and day.year == previous_month_last.year
                    and day.month == previous_month_last.month
                )
            ),
            reverse=True,
        )
    else:
        raise PitSourceViewError("unsupported last-trading-day rule")
    if not candidates:
        raise PitSourceViewError("calendar cannot resolve last trading day")
    return candidates[0]


def _binding(
    *,
    binding_id: str,
    source_class: str,
    scope: str,
    source_identity: str,
    query_start: str,
    query_end: str,
    logical_at: str,
    raw_sha256: str,
    lineage: dict[str, Any],
    history_receipt_sha256: str,
) -> dict[str, Any]:
    return {
        "binding_id": binding_id,
        "source_class": source_class,
        "scope": scope,
        "source_identity": source_identity,
        "query_start": query_start,
        "query_end": query_end,
        "cutoff_at": logical_at,
        "generated_at": logical_at,
        "raw_sha256": raw_sha256,
        "lineage_sha256": sha256(canonical_json(lineage)),
        "claimed_receipt_sha256": history_receipt_sha256,
    }


def _unsigned_batch(
    target_evidence: dict[str, Any],
    *,
    source_month: str,
    execution_day: date,
    signer_key_id: str,
    execution_lane: str,
) -> dict[str, Any]:
    targets = []
    for row in target_evidence["targets"]:
        targets.append(
            {
                "product": row["product"],
                "previous_exact_contract": None,
                "previous_target_quantity": 0,
                "exact_contract": row["exact_contract"],
                "target_quantity": row["target_quantity"],
                "source_target_weight": row["source_target_weight"],
                "buffered_target_weight": row["buffered_target_weight"],
                "reference_open_price": row["reference_open_price"],
                "multiplier": row["multiplier"],
                "price_tick": row["price_tick"],
            }
        )
    return {
        "schema_version": "commodity_static_core_equal_target_batch_v2",
        "batch_id": f"static-core-{source_month.replace('-', '')}-warehouse-v1",
        "scheduler_id": "STATIC_CORE_EQUAL",
        "source_combination_arm": "CORE_EQUAL_TARGET",
        "execution_lane": execution_lane,
        "source_month": source_month,
        "execution_day": execution_day.isoformat(),
        "virtual_nav_cny": frozen.VIRTUAL_NAV_CNY,
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "guardband": {
            "product": 0.12,
            "sector": 0.27,
            "gross": 0.8,
            "target_net": 0.0,
        },
        "allocator": {
            "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": 2,
            "beam_width": 2048,
            "net_error_penalty": 1.0,
            "monthly_target_dates_only": True,
            "daily_auto_reweight": False,
            "roll_preserves_integer_lots": True,
        },
        "previous_batch_hash": None,
        "targets": targets,
        "signer_key_id": signer_key_id,
        "signature": PLACEHOLDER_SIGNATURE,
    }


def build_historical_baseline(
    *,
    calendar: OfficialCalendar,
    calendar_anchor_raw_sha256: str,
    warehouse_registry_raw_sha256: str,
    history_receipt: dict[str, Any],
    history_receipt_raw_sha256: str,
    operator_pins: dict[str, str],
    daily_source_raw: dict[str, dict[str, bytes]],
    contract_registry_raw: bytes,
    source_month: str,
    signer_key_id: str,
    execution_lane: str,
    supplemental_daily_receipts: tuple[dict[str, Any], ...] | list[dict[str, Any]] = (),
) -> BuiltBaseline:
    if execution_lane not in {"official_forward", "simnow_shakedown"}:
        raise PitSourceViewError("historical baseline execution lane is invalid")
    registry, contract_registry_sha = _registry(contract_registry_raw)
    research_day, execution_day, _cutoff_day = _official_month_boundary(
        calendar,
        source_month=source_month,
    )
    history_receipt_days = [
        day
        for day in history_receipt.get("official_days", [])
        if day <= research_day.isoformat()
    ]
    if (
        len(history_receipt_days) < 127
        or history_receipt_days != sorted(set(history_receipt_days))
    ):
        raise PitSourceViewError("historical baseline lacks 127 official days")
    fixed_history_through_execution = [
        day
        for day in history_receipt.get("official_days", [])
        if day <= execution_day.isoformat()
    ]
    if (
        not fixed_history_through_execution
        or fixed_history_through_execution != sorted(set(fixed_history_through_execution))
    ):
        raise PitSourceViewError("historical baseline execution history is invalid")
    following = sorted(
        day
        for day, row in calendar.days.items()
        if row.is_official and day > execution_day
    )
    if not following:
        raise PitSourceViewError("calendar lacks following execution day")
    last_history_day = date.fromisoformat(fixed_history_through_execution[-1])
    required_supplemental_days = [
        day.isoformat()
        for day, row in calendar.days.items()
        if row.is_official and last_history_day < day <= execution_day
    ]
    if required_supplemental_days and required_supplemental_days[-1] != (
        execution_day.isoformat()
    ):
        raise PitSourceViewError("historical baseline supplemental days are incomplete")
    supplied_supplemental = list(supplemental_daily_receipts)
    if [item.get("trade_day") if isinstance(item, dict) else None for item in supplied_supplemental] != required_supplemental_days:
        raise PitSourceViewError("historical baseline supplemental receipt days mismatch")
    for receipt_pin in supplied_supplemental:
        if not isinstance(receipt_pin, dict) or set(receipt_pin) != {
            "trade_day",
            "run_receipt_raw_sha256",
            "completed_at",
            "manifest_batch_id",
            "manifest_batch_seal_sha256",
            "manifest_commit_seal_sha256",
            "sources",
        }:
            raise PitSourceViewError("historical baseline supplemental receipt shape mismatch")
        require_sha(
            receipt_pin["run_receipt_raw_sha256"],
            "historical baseline supplemental receipt",
        )
        parse_utc(
            receipt_pin["completed_at"],
            "historical baseline supplemental receipt completion",
        )
        require_sha(
            receipt_pin["manifest_batch_seal_sha256"],
            "historical baseline supplemental manifest",
        )
        require_sha(
            receipt_pin["manifest_commit_seal_sha256"],
            "historical baseline supplemental commit",
        )
        if (
            not isinstance(receipt_pin["manifest_batch_id"], str)
            or not receipt_pin["manifest_batch_id"]
            or not isinstance(receipt_pin["sources"], list)
            or [item.get("exchange") if isinstance(item, dict) else None for item in receipt_pin["sources"]]
            != ["SHFE", "INE"]
        ):
            raise PitSourceViewError("historical baseline supplemental source shape mismatch")
        for source_pin in receipt_pin["sources"]:
            if not isinstance(source_pin, dict) or set(source_pin) != {
                "exchange",
                "raw_sha256",
                "raw_bytes",
                "revision_id",
            }:
                raise PitSourceViewError(
                    "historical baseline supplemental source pin shape mismatch"
                )
            if (
                not isinstance(source_pin["revision_id"], str)
                or not source_pin["revision_id"]
                or not isinstance(source_pin["raw_bytes"], int)
                or isinstance(source_pin["raw_bytes"], bool)
                or source_pin["raw_bytes"] < 1
            ):
                raise PitSourceViewError(
                    "historical baseline supplemental source pin is invalid"
                )
            require_sha(
                source_pin["raw_sha256"],
                "historical baseline supplemental source",
            )
            sources = daily_source_raw.get(receipt_pin["trade_day"])
            if not isinstance(sources, dict) or source_pin["exchange"] not in sources:
                raise PitSourceViewError("historical baseline raw days are incomplete")
            raw = sources[source_pin["exchange"]]
            if (
                sha256(raw) != source_pin["raw_sha256"]
                or len(raw) != source_pin["raw_bytes"]
            ):
                raise PitSourceViewError(
                    "historical baseline supplemental source bytes mismatch"
                )

    research_supplemental_days = [
        day for day in required_supplemental_days if day <= research_day.isoformat()
    ]
    history_days = [*history_receipt_days, *research_supplemental_days]
    if history_days != sorted(set(history_days)):
        raise PitSourceViewError("historical baseline calculation days are invalid")
    official_days = [*history_days, execution_day.isoformat(), following[0].isoformat()]
    required = set(history_days) | {execution_day.isoformat()}
    if required - set(daily_source_raw):
        raise PitSourceViewError("historical baseline raw days are incomplete")
    if any(
        set(daily_source_raw[day]) != {"SHFE", "INE"}
        for day in required
    ):
        raise PitSourceViewError("historical baseline exchange set mismatch")

    logical_at = _logical_instant(execution_day, time(18, 30))
    market_bindings: dict[str, dict[str, Any]] = {}
    reference_bindings: dict[str, dict[str, Any]] = {}
    execution_day_receipt = next(
        (
            item
            for item in supplied_supplemental
            if item["trade_day"] == execution_day.isoformat()
        ),
        None,
    )
    execution_day_evidence = (
        {
            "evidence_kind": "NORMAL_RUN_RECEIPT",
            "normal_run_receipt": execution_day_receipt,
        }
        if execution_day_receipt is not None
        else {
            "evidence_kind": "FIXED_HISTORY_RECEIPT",
            "history_receipt_raw_sha256": history_receipt_raw_sha256,
            "trade_day": execution_day.isoformat(),
        }
    )
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
            source_identity=f"{exchange.lower()}-daily-market-data-v1",
            query_start=history_days[0],
            query_end=history_days[-1],
            logical_at=logical_at,
            raw_sha256=market_sha,
            lineage={
                "history_receipt_raw_sha256": history_receipt_raw_sha256,
                "operator_pins": operator_pins,
                "exchange": exchange,
                "days": history_days,
                "supplemental_daily_receipts": supplied_supplemental,
            },
            history_receipt_sha256=history_receipt_raw_sha256,
        )
        reference_sha = sha256(daily_source_raw[execution_day.isoformat()][exchange])
        reference_bindings[exchange] = _binding(
            binding_id=f"open-{exchange.lower()}-{reference_sha[:24]}",
            source_class="REFERENCE_OPEN",
            scope=exchange,
            source_identity=f"{exchange.lower()}-official-open-v1",
            query_start=execution_day.isoformat(),
            query_end=execution_day.isoformat(),
            logical_at=logical_at,
            raw_sha256=reference_sha,
            lineage={
                "history_receipt_raw_sha256": history_receipt_raw_sha256,
                "operator_pins": operator_pins,
                "exchange": exchange,
                "execution_day": execution_day.isoformat(),
                "execution_day_evidence": execution_day_evidence,
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
        logical_at=logical_at,
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
            binding_id=(
                f"contract-spec-{exchange.lower()}-{contract_registry_sha[:20]}"
            ),
            source_class="CONTRACT_SPEC",
            scope=exchange,
            source_identity=f"static-core-{exchange.lower()}-contract-registry-v1",
            query_start=execution_day.isoformat(),
            query_end=execution_day.isoformat(),
            logical_at=logical_at,
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
        by_product = {product: [] for product in frozen.PRODUCTS}
        for exchange in ("SHFE", "INE"):
            extracted = contract_rows_from_daily_raw(
                raw=daily_source_raw[day][exchange],
                exchange=exchange,
                official_day=day,
                include_ohlc=True,
            )
            for product in frozen.PRODUCTS:
                by_product[product].extend(extracted[product])
        daily_by_day[day] = by_product
    execution_rows: dict[str, list[dict[str, Any]]] = {
        product: [] for product in frozen.PRODUCTS
    }
    for exchange in ("SHFE", "INE"):
        extracted = contract_rows_from_daily_raw(
            raw=daily_source_raw[execution_day.isoformat()][exchange],
            exchange=exchange,
            official_day=execution_day.isoformat(),
            include_ohlc=True,
        )
        for product in frozen.PRODUCTS:
            execution_rows[product].extend(extracted[product])

    products: list[dict[str, Any]] = []
    for product in frozen.PRODUCTS:
        spec = frozen.PRODUCT_SPECS[product]
        main, _ = _pit_main(product, research_day, daily_by_day[history_days[-1]][product])
        exact_contract = main["exact_contract"]
        execution_contract = {
            row["exact_contract"]: row for row in execution_rows[product]
        }.get(exact_contract)
        if execution_contract is None:
            raise PitSourceViewError(
                f"{product} PIT main lacks execution-day official open"
            )
        delivery = int(main["delivery_yyyymm"])
        last_day = _last_trading_day(
            calendar,
            delivery_yyyymm=delivery,
            rule=registry[product]["last_trading_day_rule"],
        )
        products.append(
            {
                "product": product,
                "exchange": spec["exchange"],
                "daily": [
                    {
                        "official_day": day,
                        "source_binding_id": market_bindings[spec["exchange"]][
                            "binding_id"
                        ],
                        "contracts": daily_by_day[day][product],
                    }
                    for day in history_days
                ],
                "execution_reference": {
                    "source_binding_id": reference_bindings[spec["exchange"]][
                        "binding_id"
                    ],
                    "exact_contract": exact_contract,
                    "official_open": execution_contract["open"],
                    "observed_at": _logical_instant(execution_day, time(15, 30)),
                    "raw_sha256": sha256(
                        daily_source_raw[execution_day.isoformat()][spec["exchange"]]
                    ),
                },
                "contract_spec": {
                    "source_binding_id": spec_bindings[spec["exchange"]][
                        "binding_id"
                    ],
                    "exact_contract": exact_contract,
                    "official_last_trading_day": last_day.isoformat(),
                    "multiplier": spec["multiplier"],
                    "price_tick": spec["price_tick"],
                    "raw_sha256": contract_registry_sha,
                },
            }
        )
    identity = {
        "history_receipt_raw_sha256": history_receipt_raw_sha256,
        "calendar_raw_sha256": calendar.raw_sha256,
        "calendar_anchor_raw_sha256": calendar_anchor_raw_sha256,
        "warehouse_registry_raw_sha256": warehouse_registry_raw_sha256,
        "contract_registry_raw_sha256": contract_registry_sha,
        "operator_pins": operator_pins,
        "supplemental_daily_receipts": supplied_supplemental,
        "source_month": source_month,
        "derivation_id": DERIVATION_ID,
    }
    source = {
        "schema_version": baseline_producer.SOURCE_SCHEMA_VERSION,
        "purpose": baseline_producer.SOURCE_PURPOSE,
        "status": baseline_producer.SOURCE_STATUS,
        "source_view_id": (
            f"warehouse-static-core-{source_month.replace('-', '')}-"
            f"{sha256(canonical_json(identity))[:20]}"
        ),
        "claimed_receipt_sha256": history_receipt_raw_sha256,
        "generated_at": logical_at,
        "cutoff_at": logical_at,
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
    result = baseline_producer.produce_research_artifacts(source)
    target = json.loads(result.artifacts["target_evidence"])
    unsigned = _unsigned_batch(
        target,
        source_month=source_month,
        execution_day=execution_day,
        signer_key_id=signer_key_id,
        execution_lane=execution_lane,
    )
    unsigned_raw = canonical_json(unsigned)
    evidence = {
        "schema_version": RECEIPT_SCHEMA,
        "derivation_id": DERIVATION_ID,
        "source_month": source_month,
        "research_as_of_official_day": research_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "execution_lane": execution_lane,
        "historical_backfill_completed_at": history_receipt["completed_at"],
        "logical_replay_generated_at": logical_at,
        "logical_replay_is_not_acquisition_time": True,
        "pins": identity,
        "source_view_raw_sha256": result.source_view_canonical_sha256,
        "source_view_raw_bytes": len(result.source_view_canonical),
        "artifact_digests": [
            {"role": role, "raw_sha256": sha256(raw), "raw_bytes": len(raw)}
            for role, raw in result.artifacts.items()
        ],
        "unsigned_batch_raw_sha256": sha256(unsigned_raw),
        "unsigned_batch_raw_bytes": len(unsigned_raw),
        "producer_replay": "EXACT_BYTES_VERIFIED",
        "authority": false_authority(),
    }
    built = BuiltBaseline(
        source_view_raw=result.source_view_canonical,
        artifacts=dict(result.artifacts),
        unsigned_batch_raw=unsigned_raw,
        evidence_raw=canonical_json_line(evidence),
    )
    verify_built_baseline(built)
    return built


def verify_built_baseline(built: BuiltBaseline) -> None:
    result = baseline_producer.ProducerResult(
        status=baseline_producer.STATUS,
        source_view_canonical_sha256=sha256(built.source_view_raw),
        source_view_canonical=built.source_view_raw,
        artifacts=built.artifacts,
        producer_projection={
            "projection_type": "research_evidence_projection_v1",
            "status": baseline_producer.STATUS,
            "scheduler_id": baseline_producer.SCHEDULER_ID,
            "producer_kernel_id": baseline_producer.KERNEL_ID,
            "source_view_canonical_sha256": sha256(built.source_view_raw),
            "artifact_roles": list(baseline_producer.ARTIFACT_ROLES),
            "artifact_digests": [
                {"role": role, "sha256": sha256(built.artifacts[role])}
                for role in baseline_producer.ARTIFACT_ROLES
            ],
        },
    )
    baseline_producer.verify_research_artifacts(result)
    replay = baseline_producer.produce_research_artifacts(built.source_view_raw)
    if replay.artifacts != built.artifacts:
        raise PitSourceViewError("historical baseline artifact replay diverged")
    evidence = parse_json_strict(built.evidence_raw, "baseline evidence")
    if (
        not isinstance(evidence, dict)
        or canonical_json_line(evidence) != built.evidence_raw
        or evidence.get("source_view_raw_sha256") != sha256(built.source_view_raw)
        or evidence.get("unsigned_batch_raw_sha256")
        != sha256(built.unsigned_batch_raw)
        or evidence.get("authority") != false_authority()
    ):
        raise PitSourceViewError("historical baseline evidence binding mismatch")


def publish_built_baseline(output: Path, built: BuiltBaseline) -> None:
    output.mkdir(mode=0o700)
    try:
        files = {
            "source-view.json": built.source_view_raw,
            "unsigned-target-batch.json": built.unsigned_batch_raw,
            "baseline-evidence.json": built.evidence_raw,
            **{
                f"{role}.json": raw for role, raw in built.artifacts.items()
            },
        }
        for name, raw in files.items():
            path = output / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
    except Exception:
        for child in output.iterdir():
            child.unlink(missing_ok=True)
        output.rmdir()
        raise
