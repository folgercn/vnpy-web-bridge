"""Complete a verified M2 monthly pre-open pair with one live CTP snapshot.

This is deliberately an M5-only content join.  It creates no new shared
artifact: the completed producer inputs live only in memory until the existing
create-only monthly-bundle adapter has accepted both pure-producer replays.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import commodity_c_fast_pure_producer_kernel as cfast
import commodity_relative_vol_snapshot_producer as thermostat_producer
import commodity_static_core_equal_pure_producer as static_producer
from research_warehouse.canonical import canonical_json, sha256
from research_warehouse.pit_source_view import PitSourceViewError, _roll_safe_returns
from research_warehouse.simnow_lab_monthly_preopen import validate_preopen_pair
from research_warehouse.static_core_baseline import _unsigned_batch

from scripts import simnow_experimental_materialize_target as materializer
from scripts import simnow_experimental_monthly_once as monthly_once

MARKET_SCHEMA = "simnow_lab_market_snapshot_v1"
MAX_MARKET_AGE_SECONDS = 300
SHANGHAI = ZoneInfo("Asia/Shanghai")


class MonthlyPreopenJoinError(ValueError):
    """Any join error must stop before a target/RPC mutation."""


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_time(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise MonthlyPreopenJoinError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonthlyPreopenJoinError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonthlyPreopenJoinError(f"{label} is invalid")
    return parsed.astimezone(timezone.utc)


def _market_rows(
    snapshot: Any,
    *,
    expected: Mapping[str, tuple[str, str]],
    execution_day: str,
    now: datetime | None = None,
) -> tuple[dict[str, dict[str, Any]], datetime]:
    """Validate the one readonly RPC response before producer work begins."""

    fields = {"schema_version", "status", "observed_at", "rows", "snapshot_sha256"}
    if not isinstance(snapshot, Mapping) or set(snapshot) != fields:
        raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_INVALID")
    if snapshot.get("schema_version") != MARKET_SCHEMA or snapshot.get("status") != "MARKET":
        raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_INVALID")
    claimed = snapshot.get("snapshot_sha256")
    if not isinstance(claimed, str) or claimed != sha256(
        canonical_json({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
    ):
        raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_HASH_INVALID")
    observed_at = _parse_time(snapshot.get("observed_at"), label="MARKET observed_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if observed_at > current or (current - observed_at).total_seconds() > MAX_MARKET_AGE_SECONDS:
        raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_STALE")
    rows = snapshot.get("rows")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
    result: dict[str, dict[str, Any]] = {}
    required = {
        "vt_symbol", "exact_contract", "exchange", "open_price", "tick_datetime",
        "trading_day", "gateway_name",
    }
    expected_contracts = {contract for contract, _exchange in expected.values()}
    for row in rows:
        if not isinstance(row, dict) or set(row) != required:
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
        contract = row.get("exact_contract")
        exchange = row.get("exchange")
        if not isinstance(contract, str) or not isinstance(exchange, str):
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
        if contract not in expected_contracts:
            continue
        if (
            exchange not in {"SHFE", "INE"}
            or row.get("trading_day") != execution_day
            or row.get("gateway_name") != "CTP"
        ):
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
        price = row.get("open_price")
        if isinstance(price, bool) or not isinstance(price, (int, float)) or not math.isfinite(float(price)) or price <= 0:
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
        tick_at = _parse_time(row.get("tick_datetime"), label="MARKET tick_datetime")
        if tick_at > observed_at or (observed_at - tick_at).total_seconds() > MAX_MARKET_AGE_SECONDS:
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_STALE")
        if contract in result:
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
        product = next(product for product, pair in expected.items() if pair[0] == contract)
        if exchange != expected[product][1]:
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
        symbol = contract.split(".", 1)[1]
        if row.get("vt_symbol") != f"{symbol}.{exchange}":
            raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
        result[contract] = dict(row)
    if set(result) != expected_contracts:
        raise MonthlyPreopenJoinError("MARKET_SNAPSHOT_ROWS_INVALID")
    return result, observed_at


def _source_products(static: Mapping[str, Any], market: Mapping[str, Mapping[str, Any]], generated_at: str) -> list[dict[str, Any]]:
    products = static.get("products")
    if not isinstance(products, list) or len(products) != len(cfast.PRODUCTS):
        raise MonthlyPreopenJoinError("PREOPEN_PRODUCTS_INVALID")
    result: list[dict[str, Any]] = []
    exchange_rows = {
        exchange: sorted(
            (dict(item) for item in market.values() if item["exchange"] == exchange),
            key=lambda item: str(item["exact_contract"]),
        )
        for exchange in ("INE", "SHFE")
    }
    for row in products:
        if not isinstance(row, dict):
            raise MonthlyPreopenJoinError("PREOPEN_PRODUCTS_INVALID")
        product, exchange = row.get("product"), row.get("exchange")
        pit_main = row.get("pit_main")
        if (
            not isinstance(product, str)
            or product not in cfast.PRODUCTS
            or exchange != cfast.PRODUCT_SPECS[product]["exchange"]
            or not isinstance(pit_main, dict)
        ):
            raise MonthlyPreopenJoinError("PREOPEN_PRODUCTS_INVALID")
        exact = pit_main.get("exact_contract")
        tick = market.get(exact) if isinstance(exact, str) else None
        spec = row.get("contract_spec")
        if not isinstance(tick, Mapping) or not isinstance(spec, dict):
            raise MonthlyPreopenJoinError("PREOPEN_CONTRACT_MISMATCH")
        result.append(
            {
                "product": product,
                "exchange": exchange,
                "daily": row.get("daily"),
                "execution_reference": {
                    "source_binding_id": f"open-{exchange.lower()}-{sha256(canonical_json(exchange_rows[exchange]))[:24]}",
                    "exact_contract": exact,
                    "official_open": tick["open_price"],
                    "observed_at": generated_at,
                    "raw_sha256": sha256(canonical_json(exchange_rows[exchange])),
                },
                "contract_spec": spec,
            }
        )
    if tuple(sorted(item["product"] for item in result)) != cfast.PRODUCTS:
        raise MonthlyPreopenJoinError("PREOPEN_PRODUCTS_INVALID")
    return result


def _static_source(
    static: Mapping[str, Any], market: Mapping[str, Mapping[str, Any]], observed_at: datetime
) -> bytes:
    generated_at = _utc_text(observed_at)
    calendar = static.get("calendar")
    history = static.get("history_receipt")
    if not isinstance(calendar, dict) or not isinstance(history, dict):
        raise MonthlyPreopenJoinError("PREOPEN_STATIC_INVALID")
    following = calendar.get("following_official_day")
    history_days = static.get("lineage", {}).get("history_days") if isinstance(static.get("lineage"), dict) else None
    if not isinstance(following, str) or not isinstance(history_days, list) or not history_days:
        raise MonthlyPreopenJoinError("PREOPEN_CALENDAR_INVALID")
    bindings = static.get("source_bindings")
    if not isinstance(bindings, list):
        raise MonthlyPreopenJoinError("PREOPEN_STATIC_INVALID")
    ref_bindings: list[dict[str, Any]] = []
    for exchange in ("INE", "SHFE"):
        exchange_rows = sorted(
            (dict(item) for item in market.values() if item["exchange"] == exchange),
            key=lambda item: str(item["exact_contract"]),
        )
        raw_sha = sha256(canonical_json(exchange_rows))
        ref_bindings.append(
            {
                "binding_id": f"open-{exchange.lower()}-{raw_sha[:24]}",
                "source_class": "REFERENCE_OPEN",
                "scope": exchange,
                "source_identity": f"{exchange.lower()}-ctp-execution-open-v1",
                "query_start": static["execution_day"],
                "query_end": static["execution_day"],
                "cutoff_at": generated_at,
                "generated_at": generated_at,
                "raw_sha256": raw_sha,
                "lineage_sha256": sha256(canonical_json({"pair_id": static["pair_id"], "exchange": exchange, "market_snapshot": raw_sha})),
                "claimed_receipt_sha256": history["raw_sha256"],
            }
        )
    copied_bindings = [dict(item) for item in bindings if isinstance(item, dict)]
    calendar_bindings = [item for item in copied_bindings if item.get("source_class") == "CALENDAR"]
    if len(calendar_bindings) != 1:
        raise MonthlyPreopenJoinError("PREOPEN_CALENDAR_INVALID")
    calendar_bindings[0]["query_end"] = following
    for binding in copied_bindings:
        if binding.get("source_class") == "CONTRACT_SPEC":
            binding["query_start"] = static["execution_day"]
            binding["query_end"] = static["execution_day"]
    source = {
        "schema_version": static_producer.SOURCE_SCHEMA_VERSION,
        "purpose": static_producer.SOURCE_PURPOSE,
        "status": static_producer.SOURCE_STATUS,
        "source_view_id": f"simnow-preopen-{static['pair_id']}",
        "claimed_receipt_sha256": history["raw_sha256"],
        "generated_at": generated_at,
        "cutoff_at": generated_at,
        "research_as_of_official_day": static["research_as_of_official_day"],
        "execution_day": static["execution_day"],
        "official_days": [*history_days, static["execution_day"], following],
        "source_bindings": [
            *calendar_bindings,
            *[item for item in copied_bindings if item.get("source_class") != "CALENDAR"],
            *ref_bindings,
        ],
        "products": _source_products(static, market, generated_at),
    }
    try:
        return static_producer.canonical_json(source)
    except static_producer.StaticCoreEqualProducerError as exc:
        raise MonthlyPreopenJoinError("STATIC_PREOPEN_REPLAY_INVALID") from exc


def _baseline(static_result: Any, *, source_month: str, execution_day: str) -> dict[str, Any]:
    try:
        evidence = json.loads(static_result.artifacts["target_evidence"])
        return _unsigned_batch(
            evidence,
            source_month=source_month,
            execution_day=date.fromisoformat(execution_day),
            signer_key_id="simnow-lab-placeholder",
            execution_lane="simnow_shakedown",
        )
    except (KeyError, TypeError, ValueError, PitSourceViewError) as exc:
        raise MonthlyPreopenJoinError("STATIC_PREOPEN_RESULT_INVALID") from exc


def _thermostat_source(
    static: Mapping[str, Any], thermostat: Mapping[str, Any], baseline: dict[str, Any], observed_at: datetime
) -> bytes:
    products = static.get("products")
    selected = thermostat.get("selected_official_days")
    if not isinstance(products, list) or not isinstance(selected, list) or len(selected) != thermostat_producer.SLOW_LOOKBACK_DAYS:
        raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID")
    daily: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for product_row in products:
        if not isinstance(product_row, dict) or not isinstance(product_row.get("daily"), list):
            raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID")
        product = product_row.get("product")
        if product not in cfast.PRODUCTS:
            raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID")
        for row in product_row["daily"]:
            if not isinstance(row, dict) or not isinstance(row.get("official_day"), str) or not isinstance(row.get("contracts"), list):
                raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID")
            daily.setdefault(row["official_day"], {item: [] for item in cfast.PRODUCTS})[product] = row["contracts"]
    if any(set(values) != set(cfast.PRODUCTS) for values in daily.values()):
        raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID")
    try:
        first = selected[0]
        predecessor = max(day for day in daily if day < first)
        returns = _roll_safe_returns(daily, [predecessor, *selected])
    except (TypeError, ValueError, PitSourceViewError) as exc:
        raise MonthlyPreopenJoinError("THERMOSTAT_RETURNS_INVALID") from exc
    weights = {row["product"]: row["buffered_target_weight"] for row in baseline["targets"]}
    try:
        daily_returns = [
            {
                "official_day": raw_day,
                "daily_return": math.fsum(weights[product] * returns[product][raw_day] for product in cfast.PRODUCTS),
            }
            for raw_day in selected
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise MonthlyPreopenJoinError("THERMOSTAT_RETURNS_INVALID") from exc
    source_bindings = static.get("source_bindings")
    if not isinstance(source_bindings, list) or not source_bindings:
        raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID")
    try:
        cutoff_candidates = [
            _parse_time(binding["generated_at"], label="preopen source generated_at")
            for binding in source_bindings
            if isinstance(binding, dict)
        ]
        cutoff_at = max(cutoff_candidates)
    except (KeyError, ValueError) as exc:
        raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID") from exc
    source_month = str(static["source_month"])
    if (
        len(cutoff_candidates) != len(source_bindings)
        or cutoff_at > observed_at
        or cutoff_at.astimezone(SHANGHAI).strftime("%Y-%m") != source_month
    ):
        raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_INVALID")
    source = {
        "schema_version": thermostat_producer.SOURCE_SCHEMA_VERSION,
        "purpose": thermostat_producer.SOURCE_PURPOSE,
        "status": thermostat_producer.SOURCE_STATUS,
        "source_view_id": f"simnow-preopen-thermostat-{static['pair_id']}",
        "snapshot_id": f"simnow-preopen-relative-vol-{static['pair_id']}",
        "generated_at": _utc_text(observed_at),
        "cutoff_at": _utc_text(cutoff_at),
        "official_calendar": thermostat["calendar"],
        "official_days": selected,
        "baseline_daily_returns": daily_returns,
        "baseline_batch_hash": sha256(thermostat_producer.canonical_json({key: value for key, value in baseline.items() if key != "signature"})),
        "baseline_batch": baseline,
        "continuity": thermostat["continuity"],
    }
    try:
        thermostat_producer.produce_snapshot(thermostat_producer.canonical_json(source))
        return thermostat_producer.canonical_json(source)
    except thermostat_producer.SnapshotProducerError as exc:
        raise MonthlyPreopenJoinError("THERMOSTAT_PREOPEN_REPLAY_INVALID") from exc


def complete_and_materialize(
    *,
    static_preopen_raw: bytes,
    thermostat_preopen_raw: bytes,
    daily_route_path: Path,
    market_snapshot: Any,
    monthly_bundle_directory,
    target_path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify, join, replay both producers, then use the existing materializer."""

    try:
        static, thermostat = validate_preopen_pair(static_preopen_raw, thermostat_preopen_raw)
    except PitSourceViewError as exc:
        raise MonthlyPreopenJoinError("PREOPEN_PAIR_INVALID") from exc
    try:
        daily_route, daily_route_raw = materializer.read_json_stable(
            daily_route_path, label="daily PIT route"
        )
        route = materializer._daily_routes(daily_route)
        route_execution = daily_route["metadata"]["execution_day"]
    except (KeyError, TypeError, materializer.ExperimentalTargetError) as exc:
        raise MonthlyPreopenJoinError("DAILY_ROUTE_INVALID") from exc
    try:
        expected = {
            row["product"]: (row["pit_main"]["exact_contract"], row["exchange"])
            for row in static["products"]
        }
    except (KeyError, TypeError) as exc:
        raise MonthlyPreopenJoinError("PREOPEN_ROUTE_MISMATCH") from exc
    if (
        route_execution != static["execution_day"]
        or set(expected) != set(cfast.PRODUCTS)
        or any(route[product] != expected[product][0] for product in expected)
    ):
        raise MonthlyPreopenJoinError("PREOPEN_ROUTE_MISMATCH")
    market, observed_at = _market_rows(
        market_snapshot, expected=expected, execution_day=static["execution_day"], now=now
    )
    static_raw = _static_source(static, market, observed_at)
    try:
        static_result = static_producer.produce_research_artifacts(static_raw)
    except static_producer.StaticCoreEqualProducerError as exc:
        raise MonthlyPreopenJoinError("STATIC_PREOPEN_REPLAY_INVALID") from exc
    baseline = _baseline(static_result, source_month=static["source_month"], execution_day=static["execution_day"])
    thermostat_raw = _thermostat_source(static, thermostat, baseline, observed_at)
    try:
        return monthly_once.materialize_monthly_once(
            source_month=static["source_month"],
            static_source_raw=static_raw,
            thermostat_source_raw=thermostat_raw,
            monthly_bundle_directory=monthly_bundle_directory,
            daily_pit_route_raw=daily_route_raw,
            target_path=target_path,
            generated_at=_utc_text(observed_at),
        )
    except monthly_once.ExperimentalMonthlyError as exc:
        raise MonthlyPreopenJoinError("MONTHLY_MATERIALIZE_FAILED") from exc
