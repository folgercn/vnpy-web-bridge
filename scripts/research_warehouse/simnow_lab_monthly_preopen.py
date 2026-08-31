"""Bounded, no-authority month-end inputs awaiting real CTP execution opens."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, time
from typing import Any

import commodity_c_fast_pure_producer_kernel as frozen

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .m2_isolation_contracts import false_authority
from .pit_source_view import (
    PitSourceViewError,
    _calendar_binding,
    _official_month_boundary,
    contract_rows_from_daily_raw,
)
from .shfe_contract_parameters import (
    ShfeContractParameterError,
    ShfeContractParameterEvidence,
)
from .shfe_contract_parameters import (
    lineage_for_exact_contract as shfe_contract_parameters_lineage,
)
from .static_core_baseline import (
    SHFE_LAST_DAY_RULE,
    _aggregate_raw_identity,
    _binding,
    _last_trading_day,
    _logical_instant,
    _registry,
)

STATIC_SCHEMA = "simnow_lab_static_core_monthly_preopen_v1"
THERMOSTAT_SCHEMA = "simnow_lab_relative_vol_monthly_preopen_v1"
STATUS = "PREOPEN_REQUIRES_LIVE_CTP_OPEN"
MAX_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class BuiltMonthlyPreopen:
    static_raw: bytes
    thermostat_raw: bytes


def _require_source_month(value: str) -> None:
    try:
        year, month = (int(item) for item in value.split("-"))
        date(year, month, 1)
    except (TypeError, ValueError) as exc:
        raise PitSourceViewError("SIMNOW preopen source month is invalid") from exc
    if value != f"{year:04d}-{month:02d}":
        raise PitSourceViewError("SIMNOW preopen source month is invalid")


def _history_days(history_receipt: dict[str, Any], research_day: date) -> list[str]:
    days = [
        item
        for item in history_receipt.get("official_days", [])
        if isinstance(item, str) and item <= research_day.isoformat()
    ]
    if len(days) < 127 or days != sorted(set(days)):
        raise PitSourceViewError("SIMNOW preopen lacks 127 completed official days")
    return days


def _product_daily(
    *,
    daily_source_raw: dict[str, dict[str, bytes]],
    history_days: list[str],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    result: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for raw_day in history_days:
        sources = daily_source_raw.get(raw_day)
        if not isinstance(sources, dict) or set(sources) != {"SHFE", "INE"}:
            raise PitSourceViewError("SIMNOW preopen daily source set is incomplete")
        by_product = {product: [] for product in frozen.PRODUCTS}
        for exchange in ("SHFE", "INE"):
            extracted = contract_rows_from_daily_raw(
                raw=sources[exchange],
                exchange=exchange,
                official_day=raw_day,
                include_ohlc=True,
            )
            for product in frozen.PRODUCTS:
                by_product[product].extend(extracted[product])
        result[raw_day] = by_product
    return result


def _history_receipt_projection(history_receipt: dict[str, Any], raw_sha256: str) -> dict[str, Any]:
    """Carry all custody pins needed by the later readonly completion step."""

    required = {"required_official_days", "official_days", "daily_receipts"}
    if not required.issubset(history_receipt):
        raise PitSourceViewError("SIMNOW preopen history receipt is incomplete")
    return {
        "raw_sha256": raw_sha256,
        "payload": history_receipt,
    }


def _official_last_trading_day(
    *,
    calendar,
    delivery_yyyymm: int,
    rule: str,
    exact_contract: str,
    shfe_contract_parameters: ShfeContractParameterEvidence | None,
) -> tuple[date, dict[str, object] | None]:
    """Resolve SHFE delivery dates across the signed calendar horizon.

    The exchange-published exact-contract evidence is already admitted by the
    daily PIT route for this same purpose.  It may bridge a partial or future
    SHFE delivery month, but it never replaces a calendar value that can be
    resolved: those two facts must agree.
    """

    if rule != SHFE_LAST_DAY_RULE:
        return (
            _last_trading_day(
                calendar,
                delivery_yyyymm=delivery_yyyymm,
                rule=rule,
            ),
            None,
        )
    delivery_year, delivery_month = divmod(delivery_yyyymm, 100)
    threshold = date(delivery_year, delivery_month, 15)
    calendar_last_day = None
    if threshold <= calendar.valid_to:
        try:
            calendar_last_day = _last_trading_day(
                calendar,
                delivery_yyyymm=delivery_yyyymm,
                rule=rule,
            )
        except PitSourceViewError:
            # A partial delivery month cannot prove a post-15th official day.
            calendar_last_day = None
    if shfe_contract_parameters is None:
        if calendar_last_day is None:
            raise PitSourceViewError(
                "SIMNOW preopen SHFE expiry evidence is required outside "
                "calendar coverage"
            )
        return calendar_last_day, None
    try:
        expiry = shfe_contract_parameters_lineage(
            shfe_contract_parameters,
            exact_contract=exact_contract,
        )
    except ShfeContractParameterError as exc:
        raise PitSourceViewError(str(exc)) from exc
    parameter_last_day = date.fromisoformat(str(expiry["expire_date"]))
    if (
        calendar_last_day is not None
        and parameter_last_day != calendar_last_day
    ):
        raise PitSourceViewError(
            "SIMNOW preopen SHFE calendar/EXPIREDATE disagreement"
        )
    return calendar_last_day or parameter_last_day, expiry


def build_monthly_preopen(
    *,
    calendar,
    calendar_anchor_raw_sha256: str,
    warehouse_registry_raw_sha256: str,
    history_receipt: dict[str, Any],
    history_receipt_raw_sha256: str,
    operator_pins: dict[str, str],
    daily_source_raw: dict[str, dict[str, bytes]],
    contract_registry_raw: bytes,
    source_month: str,
    shfe_contract_parameters: ShfeContractParameterEvidence | None = None,
) -> BuiltMonthlyPreopen:
    """Build the two M2-only month-end halves before the execution open exists.

    These are deliberately not producer source views: no execution reference,
    official open, integer quantity, baseline batch, or target is present.
    """

    _require_source_month(source_month)
    research_day, execution_day, cutoff_day = _official_month_boundary(
        calendar, source_month=source_month
    )
    following = sorted(
        day
        for day, row in calendar.days.items()
        if row.is_official and day > execution_day
    )
    if not following:
        raise PitSourceViewError("SIMNOW preopen calendar lacks following official day")
    history_days = _history_days(history_receipt, research_day)
    daily_by_day = _product_daily(
        daily_source_raw=daily_source_raw, history_days=history_days
    )
    registry, registry_sha = _registry(contract_registry_raw)
    logical_at = _logical_instant(research_day, time(18, 30))
    history_projection = _history_receipt_projection(
        history_receipt, history_receipt_raw_sha256
    )

    market_bindings = {}
    for exchange in ("SHFE", "INE"):
        market_sha = _aggregate_raw_identity(daily_source_raw, history_days, exchange)
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
            },
            history_receipt_sha256=history_receipt_raw_sha256,
        )
    calendar_binding = _binding(
        binding_id=f"calendar-{calendar.raw_sha256[:24]}",
        source_class="CALENDAR",
        scope="SHFE_INE",
        source_identity=calendar.calendar_id,
        query_start=history_days[0],
        query_end=execution_day.isoformat(),
        logical_at=logical_at,
        raw_sha256=calendar.raw_sha256,
        lineage={
            "calendar_raw_sha256": calendar.raw_sha256,
            "calendar_anchor_raw_sha256": calendar_anchor_raw_sha256,
            "history_receipt_raw_sha256": history_receipt_raw_sha256,
        },
        history_receipt_sha256=history_receipt_raw_sha256,
    )
    spec_binding_ids = {
        exchange: f"contract-spec-{exchange.lower()}-{registry_sha[:20]}"
        for exchange in ("SHFE", "INE")
    }
    products: list[dict[str, Any]] = []
    shfe_expiry_lineage: list[dict[str, object]] = []
    for product in frozen.PRODUCTS:
        spec = frozen.PRODUCT_SPECS[product]
        daily = daily_by_day[history_days[-1]][product]
        try:
            main, _ranked = frozen._pit_main(product, research_day, daily)
        except frozen.ProducerKernelError as exc:
            raise PitSourceViewError(str(exc)) from exc
        delivery = int(main["delivery_yyyymm"])
        last_trading_day, expiry = _official_last_trading_day(
            calendar=calendar,
            delivery_yyyymm=delivery,
            rule=registry[product]["last_trading_day_rule"],
            exact_contract=main["exact_contract"],
            shfe_contract_parameters=shfe_contract_parameters,
        )
        if expiry is not None:
            shfe_expiry_lineage.append(expiry)
        products.append(
            {
                "product": product,
                "exchange": spec["exchange"],
                "daily": [
                    {
                        "official_day": raw_day,
                        "source_binding_id": market_bindings[spec["exchange"]]["binding_id"],
                        "contracts": daily_by_day[raw_day][product],
                    }
                    for raw_day in history_days
                ],
                "pit_main": {
                    "exact_contract": main["exact_contract"],
                    "delivery_yyyymm": delivery,
                },
                "contract_spec": {
                    "source_binding_id": spec_binding_ids[spec["exchange"]],
                    "exact_contract": main["exact_contract"],
                    "official_last_trading_day": last_trading_day.isoformat(),
                    "multiplier": spec["multiplier"],
                    "price_tick": spec["price_tick"],
                    "raw_sha256": registry_sha,
                },
            }
        )

    shfe_expiry_lineage.sort(key=lambda item: str(item["exact_contract"]))
    spec_bindings = {}
    for exchange in ("SHFE", "INE"):
        spec_lineage: dict[str, Any] = {
            "contract_registry_raw_sha256": registry_sha,
            "calendar_raw_sha256": calendar.raw_sha256,
            "warehouse_registry_raw_sha256": warehouse_registry_raw_sha256,
            "exchange": exchange,
        }
        if exchange == "SHFE" and shfe_expiry_lineage:
            spec_lineage["contract_parameter_expiries"] = shfe_expiry_lineage
        spec_bindings[exchange] = _binding(
            binding_id=spec_binding_ids[exchange],
            source_class="CONTRACT_SPEC",
            scope=exchange,
            source_identity=f"static-core-{exchange.lower()}-contract-registry-v1",
            query_start=research_day.isoformat(),
            query_end=research_day.isoformat(),
            logical_at=logical_at,
            raw_sha256=registry_sha,
            lineage=spec_lineage,
            history_receipt_sha256=history_receipt_raw_sha256,
        )

    calendar_context, selected_days = _calendar_binding(
        calendar,
        history_receipt_sha256=history_receipt_raw_sha256,
        calendar_anchor_sha256=calendar_anchor_raw_sha256,
        source_month=source_month,
        research_as_of=research_day,
        cutoff_day=cutoff_day,
    )
    lineage = {
        "history_receipt_raw_sha256": history_receipt_raw_sha256,
        "calendar_raw_sha256": calendar.raw_sha256,
        "calendar_anchor_raw_sha256": calendar_anchor_raw_sha256,
        "warehouse_registry_raw_sha256": warehouse_registry_raw_sha256,
        "contract_registry_raw_sha256": registry_sha,
        "operator_pins": operator_pins,
        "history_days": history_days,
    }
    if shfe_expiry_lineage:
        lineage["shfe_contract_parameter_expiries"] = shfe_expiry_lineage
    pair_identity = {
        "source_month": source_month,
        "research_as_of_official_day": research_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "following_official_day": following[0].isoformat(),
        "history_receipt_raw_sha256": history_receipt_raw_sha256,
        "calendar_raw_sha256": calendar.raw_sha256,
        "calendar_anchor_raw_sha256": calendar_anchor_raw_sha256,
        "warehouse_registry_raw_sha256": warehouse_registry_raw_sha256,
        "contract_registry_raw_sha256": registry_sha,
        "operator_pins": operator_pins,
    }
    if shfe_expiry_lineage:
        pair_identity["shfe_contract_parameter_expiries"] = shfe_expiry_lineage
    pair_id = "simnow-monthly-preopen-" + sha256(
        canonical_json(pair_identity)
    )[:32]
    static = {
        "schema_version": STATIC_SCHEMA,
        "status": STATUS,
        "source_month": source_month,
        "research_as_of_official_day": research_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "history_receipt": history_projection,
        "operator_pins": operator_pins,
        "calendar": {
            "calendar_id": calendar.calendar_id,
            "raw_sha256": calendar.raw_sha256,
            "availability_anchor_raw_sha256": calendar_anchor_raw_sha256,
            "following_official_day": following[0].isoformat(),
            "static_core_binding": calendar_binding,
        },
        "contract_registry": {
            "raw_sha256": registry_sha,
            "products": [registry[product] for product in frozen.PRODUCTS],
        },
        "source_bindings": [
            calendar_binding,
            market_bindings["INE"],
            market_bindings["SHFE"],
            spec_bindings["INE"],
            spec_bindings["SHFE"],
        ],
        "products": products,
        "lineage": lineage,
        "pair_id": pair_id,
        "authority": false_authority(),
    }
    thermostat = {
        "schema_version": THERMOSTAT_SCHEMA,
        "status": STATUS,
        "source_month": source_month,
        "research_as_of_official_day": research_day.isoformat(),
        "execution_day": execution_day.isoformat(),
        "history_receipt": history_projection,
        "operator_pins": operator_pins,
        "calendar": calendar_context,
        "selected_official_days": selected_days,
        "continuity": {
            "mode": "genesis",
            "previous_snapshot_hash": None,
            "previous_snapshot": None,
        },
        "lineage": lineage,
        "pair_id": pair_id,
        "static_preopen_sha256": sha256(canonical_json_line(static)),
        "authority": false_authority(),
    }
    static_raw = canonical_json_line(static)
    thermostat_raw = canonical_json_line(thermostat)
    validate_preopen_pair(static_raw, thermostat_raw)
    if len(static_raw) > MAX_BYTES or len(thermostat_raw) > MAX_BYTES:
        raise PitSourceViewError("SIMNOW monthly preopen exceeds 4 MiB export limit")
    return BuiltMonthlyPreopen(static_raw=static_raw, thermostat_raw=thermostat_raw)


def _load_preopen(raw: bytes, *, schema: str, label: str) -> dict[str, Any]:
    payload = parse_json_strict(raw, label)
    if not isinstance(payload, dict) or canonical_json_line(payload) != raw:
        raise PitSourceViewError(f"{label} must be canonical object bytes")
    if payload.get("schema_version") != schema or payload.get("status") != STATUS:
        raise PitSourceViewError(f"{label} schema/status is invalid")
    if payload.get("authority") != false_authority():
        raise PitSourceViewError(f"{label} has authority")
    for field in ("source_month", "research_as_of_official_day", "execution_day"):
        if not isinstance(payload.get(field), str):
            raise PitSourceViewError(f"{label} {field} is invalid")
    _require_source_month(payload["source_month"])
    return payload


def validate_preopen_pair(
    static_raw: bytes, thermostat_raw: bytes
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Strictly identify the two non-executable counterparts before live binding."""

    if len(static_raw) > MAX_BYTES or len(thermostat_raw) > MAX_BYTES:
        raise PitSourceViewError("SIMNOW monthly preopen exceeds 4 MiB export limit")
    static = _load_preopen(static_raw, schema=STATIC_SCHEMA, label="static preopen")
    thermostat = _load_preopen(
        thermostat_raw, schema=THERMOSTAT_SCHEMA, label="thermostat preopen"
    )
    static_fields = {
        "schema_version", "status", "source_month", "research_as_of_official_day",
        "execution_day", "history_receipt", "operator_pins", "calendar",
        "contract_registry", "source_bindings", "products", "lineage",
        "pair_id", "authority",
    }
    thermostat_fields = {
        "schema_version", "status", "source_month", "research_as_of_official_day",
        "execution_day", "history_receipt", "operator_pins", "calendar",
        "selected_official_days", "continuity", "lineage",
        "pair_id", "static_preopen_sha256", "authority",
    }
    if set(static) != static_fields or set(thermostat) != thermostat_fields:
        raise PitSourceViewError("SIMNOW monthly preopen fields are invalid")
    if not isinstance(static["pair_id"], str) or not static["pair_id"]:
        raise PitSourceViewError("SIMNOW monthly preopen pair ID is invalid")
    shared = (
        "source_month", "research_as_of_official_day", "execution_day",
        "history_receipt", "operator_pins", "lineage", "pair_id",
    )
    if any(static[field] != thermostat[field] for field in shared):
        raise PitSourceViewError("SIMNOW monthly preopen pair metadata differs")
    try:
        research_day = date.fromisoformat(static["research_as_of_official_day"])
        execution_day = date.fromisoformat(static["execution_day"])
    except ValueError as exc:
        raise PitSourceViewError("SIMNOW monthly preopen dates are invalid") from exc
    if research_day >= execution_day:
        raise PitSourceViewError("SIMNOW monthly preopen date order is invalid")
    calendar = static["calendar"]
    if not isinstance(calendar, dict) or not isinstance(
        calendar.get("following_official_day"), str
    ):
        raise PitSourceViewError("SIMNOW monthly preopen following official day is invalid")
    try:
        following_day = date.fromisoformat(calendar["following_official_day"])
    except ValueError as exc:
        raise PitSourceViewError(
            "SIMNOW monthly preopen following official day is invalid"
        ) from exc
    if following_day <= execution_day:
        raise PitSourceViewError("SIMNOW monthly preopen following official day is invalid")
    if thermostat["static_preopen_sha256"] != sha256(static_raw):
        raise PitSourceViewError("SIMNOW monthly preopen pair hash binding differs")
    forbidden = {
        "execution_reference",
        "official_open",
        "target_quantity",
        "targets",
        "baseline_batch",
    }
    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if forbidden.intersection(value):
                raise PitSourceViewError("SIMNOW monthly preopen contains executable data")
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(static)
    walk(thermostat)
    return static, thermostat


# Compatibility alias for callers written before the stable interface name.
verify_monthly_preopen_pair = validate_preopen_pair
