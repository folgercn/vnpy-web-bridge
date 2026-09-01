#!/usr/bin/env python3
"""Offline, diagnostic-only PnL screen for the #488 frozen BBO feature.

This deliberately accepts only already collected, event-window CSVs.  It is not
a collector or an execution simulator and its output must never be treated as a
countable holdout result.
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Iterable

from collector_ordered_l1_bbo_change_v1 import (
    BBOChangeContractError,
    BBOChangeEngine,
    ObservedBBO,
    freeze_feature_only_thresholds,
    signal_from_threshold,
)


NS = 1_000_000_000
FEATURE_SECONDS = 10
HOLD_SECONDS = 30
MIN_CALIBRATION_DAYS = 5
WARNINGS = [
    "EVENT_WINDOW_SELECTED",
    "NO_RECEIVE_CLOCK",
    "NO_LOCAL_MONOTONIC_CLOCK",
    "NO_COLLECTOR_SEQUENCE",
    "NO_PROVIDER_UPDATE_ID",
    "BROKER_MARKUP_UNBOUND",
    "NOT_COUNTABLE_HOLDOUT",
    "NON_CONTINUOUS_MARKET_COVERAGE",
    "SOURCE_TIME_USED_AS_RECEIVE_CLOCK",
    "EXCHANGE_FEE_FLOOR_ONLY",
    "SESSION_OCCURRENCE_DATE_PROXY_NOT_OFFICIAL_TRADING_DAY",
]
REQUIRED_TICK = {
    "segment_id",
    "instrument",
    "exchange",
    "exact_contract_symbol",
    "segment_start_utc",
    "segment_end_utc",
    "tick_timestamp_utc",
    "bid_price1",
    "bid_volume1",
    "ask_price1",
    "ask_volume1",
}


class ScreenInputError(ValueError):
    pass


def _dec(value: str, field: str) -> Decimal:
    try:
        result = Decimal(value)
    except Exception as exc:  # csv boundary
        raise ScreenInputError(f"invalid {field}") from exc
    if not result.is_finite():
        raise ScreenInputError(f"invalid {field}")
    return result


def _ns(text: str) -> int:
    try:
        # The historical TQSDK exports retain nine fractional digits, while
        # ``datetime.fromisoformat`` only accepts microseconds.  Parse the
        # integer nanosecond tail explicitly instead of silently rounding it.
        normalized = text.strip().replace("Z", "+00:00")
        if not normalized.endswith("+00:00"):
            raise ValueError("timestamp must use an explicit UTC offset")
        base = normalized[:-6]
        if "T" not in base and " " not in base:
            raise ValueError("timestamp must contain a date and time")
        fraction = ""
        if "." in base:
            base, fraction = base.split(".", 1)
        if fraction and (not fraction.isdigit() or len(fraction) > 9):
            raise ValueError("timestamp fraction must contain at most 9 digits")
        fraction = (fraction + "000000000")[:9]
        seconds = datetime.fromisoformat(base).replace(tzinfo=timezone.utc).timestamp()
        return int(seconds) * NS + int(fraction)
    except ValueError as exc:
        raise ScreenInputError(f"invalid timestamp {text!r}") from exc


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _input_meta(path: Path) -> dict[str, object]:
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": _sha(path)}


def _csv_rows(path: Path) -> Iterable[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        yield from csv.DictReader(fh)


def _require_columns(path: Path, required: set[str]) -> None:
    with path.open(newline="", encoding="utf-8") as fh:
        names = set(csv.DictReader(fh).fieldnames or [])
    missing = sorted(required - names)
    if missing:
        raise ScreenInputError(f"{path}: missing columns {','.join(missing)}")


@dataclass(frozen=True)
class Segment:
    segment_id: str
    product: str
    exact: str
    official_day: str
    family: str
    rows: tuple[ObservedBBO, ...]


def _session_map(window_plan: Path, registry: Path) -> dict[str, tuple[str, str]]:
    """Attach one local session-occurrence date/family by exact/time overlap."""
    _require_columns(
        registry,
        {
            "segment_id",
            "exact_contract_symbol",
            "segment_start_utc",
            "segment_end_utc",
            "top1_download_complete",
        },
    )
    _require_columns(
        window_plan,
        {
            "exact_contract_symbol",
            "session_id",
            "session_name",
            "window_start_utc",
            "window_end_utc",
        },
    )
    windows: list[tuple[str, int, int, str, str]] = []
    for row in _csv_rows(window_plan):
        session = row["session_id"].split(":")
        if len(session) < 3 or not session[-2]:
            raise ScreenInputError("window plan has non-canonical session_id")
        try:
            date.fromisoformat(session[-2])
        except ValueError as exc:
            raise ScreenInputError(
                "window plan has invalid session occurrence date"
            ) from exc
        # Preserve the producer's sub-session identity.  Merging day_1/day_2/
        # day_3 would change the frozen (contract, session_family) Q95 cell.
        family = row["session_name"].upper()
        if family not in {"DAY_1", "DAY_2", "DAY_3", "NIGHT"}:
            raise ScreenInputError("window plan has unsupported session family")
        windows.append(
            (
                row["exact_contract_symbol"],
                _ns(row["window_start_utc"]),
                _ns(row["window_end_utc"]),
                session[-2],
                family,
            )
        )
    result: dict[str, tuple[str, str]] = {}
    for row in _csv_rows(registry):
        if row["top1_download_complete"] != "True":
            continue
        start, end = _ns(row["segment_start_utc"]), _ns(row["segment_end_utc"])
        candidates = {
            (day, family)
            for exact, left, right, day, family in windows
            if exact == row["exact_contract_symbol"]
            and max(left, start) <= min(right, end)
        }
        if len(candidates) != 1:
            raise ScreenInputError(
                f"segment {row['segment_id']} has {len(candidates)} session-date mappings"
            )
        result[row["segment_id"]] = next(iter(candidates))
    return result


def _load_segments(
    tick_glob: str, sessions: dict[str, tuple[str, str]], products: set[str]
) -> tuple[list[Segment], list[dict[str, object]]]:
    paths = [Path(p) for p in sorted(glob.glob(tick_glob))]
    if not paths:
        raise ScreenInputError("tick glob matched no files")
    by_segment: dict[str, list[tuple[dict[str, str], Path]]] = defaultdict(list)
    inputs: list[dict[str, object]] = []
    for path in paths:
        _require_columns(path, REQUIRED_TICK)
        inputs.append(_input_meta(path))
        for row in _csv_rows(path):
            if row["instrument"].upper() in products:
                by_segment[row["segment_id"]].append((row, path))
    result: list[Segment] = []
    for segment_id, raw in sorted(by_segment.items()):
        if segment_id not in sessions:
            raise ScreenInputError(
                f"tick segment missing completed official-session mapping: {segment_id}"
            )
        first = raw[0][0]
        product, exact = first["instrument"].upper(), first["exact_contract_symbol"]
        start_ns = _ns(first["segment_start_utc"])
        observed: list[ObservedBBO] = []
        previous: int | None = None
        seen: set[int] = set()
        for index, (row, _) in enumerate(raw, 1):
            if (
                row["instrument"].upper() != product
                or row["exact_contract_symbol"] != exact
            ):
                raise ScreenInputError(f"mixed identity in segment {segment_id}")
            stamp = _ns(row["tick_timestamp_utc"])
            if stamp in seen or (previous is not None and stamp <= previous):
                raise ScreenInputError(
                    f"non-monotonic/duplicate tick time in {segment_id}"
                )
            seen.add(stamp)
            previous = stamp
            bid, ask = (
                _dec(row["bid_price1"], "bid_price1"),
                _dec(row["ask_price1"], "ask_price1"),
            )
            bid_size, ask_size = (
                _dec(row["bid_volume1"], "bid_volume1"),
                _dec(row["ask_volume1"], "ask_volume1"),
            )
            if bid <= 0 or ask <= 0 or bid >= ask or bid_size <= 0 or ask_size <= 0:
                raise ScreenInputError(f"invalid BBO in {segment_id}")
            active = stamp - start_ns
            end_ns = _ns(row["segment_end_utc"])
            if stamp < start_ns or stamp > end_ns:
                raise ScreenInputError(
                    f"tick outside declared segment bounds in {segment_id}"
                )
            observed.append(
                ObservedBBO(
                    "CSV_DIAGNOSTIC",
                    "CSV_CLOCK",
                    exact,
                    sessions[segment_id][1],
                    segment_id,
                    index,
                    stamp,
                    stamp,
                    active,
                    active,
                    bid,
                    bid_size,
                    ask,
                    ask_size,
                )
            )
        if observed:
            day, family = sessions[segment_id]
            result.append(
                Segment(segment_id, product, exact, day, family, tuple(observed))
            )
    return result, inputs


def _require_nonoverlapping_segments(segments: Iterable[Segment]) -> None:
    """Prove that resetting admission state at each CSV segment is safe."""
    grouped: dict[str, list[Segment]] = defaultdict(list)
    for segment in segments:
        grouped[segment.exact].append(segment)
    for exact, rows in grouped.items():
        prior: Segment | None = None
        for segment in sorted(rows, key=lambda item: item.rows[0].source_event_ns):
            if (
                prior is not None
                and segment.rows[0].source_event_ns <= prior.rows[-1].source_event_ns
            ):
                raise ScreenInputError(
                    f"overlapping tick segments for {exact}: "
                    f"{prior.segment_id}/{segment.segment_id}"
                )
            prior = segment


def _specs(path: Path) -> dict[str, tuple[Decimal, Decimal]]:
    _require_columns(
        path, {"code", "multiplier", "tick_size", "research_cash_pnl_authorized"}
    )
    result = {}
    for row in _csv_rows(path):
        if row["research_cash_pnl_authorized"].lower() == "true":
            product = row["code"].upper()
            if product in result:
                raise ScreenInputError(f"duplicate authorized spec for {product}")
            multiplier = _dec(row["multiplier"], "multiplier")
            tick_size = _dec(row["tick_size"], "tick_size")
            if multiplier <= 0 or tick_size <= 0:
                raise ScreenInputError(f"non-positive authorized spec for {product}")
            result[product] = (multiplier, tick_size)
    return result


def _fees(
    path: Path,
) -> dict[tuple[str, str], tuple[Decimal, Decimal, Decimal, Decimal]]:
    required = {
        "official_day",
        "product",
        "exact_contract",
        "open_fee_ratio_per_mille",
        "open_fee_cny_per_lot",
        "close_today_fee_ratio_per_mille",
        "close_today_fee_cny_per_lot",
    }
    _require_columns(path, required)
    result = {}
    for row in _csv_rows(path):
        # Empty fee fields are intentionally not converted to zero: caller fails closed.
        if all(
            row[k] != ""
            for k in required - {"official_day", "product", "exact_contract"}
        ):
            key = (row["official_day"], row["exact_contract"])
            if key in result:
                raise ScreenInputError(f"duplicate fee schedule for {key}")
            values = (
                _dec(row["open_fee_ratio_per_mille"], "open ratio") / Decimal(1000),
                _dec(row["open_fee_cny_per_lot"], "open cny"),
                _dec(row["close_today_fee_ratio_per_mille"], "close ratio")
                / Decimal(1000),
                _dec(row["close_today_fee_cny_per_lot"], "close cny"),
            )
            if any(value < 0 for value in values):
                raise ScreenInputError(f"negative fee schedule for {key}")
            result[key] = values
    return result


def _leg_fee(
    price: Decimal,
    multiplier: Decimal,
    ratio: Decimal,
    fixed_cny: Decimal,
) -> Decimal:
    return (price * multiplier * ratio + fixed_cny).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )


def _points(segment: Segment):
    engine = BBOChangeEngine()
    return [(obs, engine.process(obs)) for obs in segment.rows]


def _round_trip(
    signal,
    rows: tuple[ObservedBBO, ...],
    latency_ns: int,
    adverse_ticks: int,
    tick: Decimal,
):
    """A lane-local replay; CSV clocks are marked assumed in the output."""
    start = next(
        (i + 1 for i, x in enumerate(rows) if x.collector_seq == signal.collector_seq),
        len(rows),
    )
    entry = None
    entry_side = "BUY" if signal.direction == "LONG" else "SELL"
    exit_side = "SELL" if entry_side == "BUY" else "BUY"
    for obs in rows[start:]:
        if obs.receive_monotonic_ns >= signal.receive_monotonic_ns + latency_ns:
            entry = obs
            break
    if entry is None:
        return None
    horizon = entry.active_time_ns + HOLD_SECONDS * NS
    exit_cutoff = None
    timed_out = False
    for obs in rows[start:]:
        if obs.collector_seq <= entry.collector_seq:
            continue
        if exit_cutoff is None:
            if obs.active_time_ns < horizon:
                continue
            if obs.active_time_ns > horizon + 5 * NS:
                timed_out = True
            else:
                # The first horizon observation recognizes the exit decision;
                # it cannot also satisfy the subsequent latency cutoff.
                exit_cutoff = obs.receive_monotonic_ns + latency_ns
                continue
        elif obs.active_time_ns > horizon + 5 * NS:
            timed_out = True
        elif obs.receive_monotonic_ns < exit_cutoff:
            continue
        if timed_out or obs.receive_monotonic_ns >= exit_cutoff:
            ep = _dec(
                str(entry.ask_price if entry_side == "BUY" else entry.bid_price),
                "entry price",
            )
            xp = _dec(
                str(obs.bid_price if exit_side == "SELL" else obs.ask_price),
                "exit price",
            )
            if entry_side == "BUY":
                ep += adverse_ticks * tick
                xp -= adverse_ticks * tick
            else:
                ep -= adverse_ticks * tick
                xp += adverse_ticks * tick
            return (
                entry_side,
                ep,
                xp,
                obs.collector_seq,
                obs.source_event_ns,
                timed_out,
            )
    return None


def _maximum_drawdown(values: list[Decimal]) -> Decimal:
    peak = Decimal(0)
    worst = Decimal(0)
    total = Decimal(0)
    for value in values:
        total += value
        peak = max(peak, total)
        worst = min(worst, total - peak)
    return worst


def _remove_best_three_session_dates(
    items: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[str]]:
    day_net: dict[str, Decimal] = defaultdict(lambda: Decimal(0))
    for item in items:
        day_net[str(item["official_day"])] += item["net"]  # type: ignore[operator]
    removed = sorted(day_net, key=lambda day: (-day_net[day], day))[:3]
    return (
        [item for item in items if item["official_day"] not in removed],
        removed,
    )


def _session_date_split(days: Iterable[str]) -> tuple[set[str], set[str]]:
    """The earliest five local session dates are feature-only calibration."""
    ordered = sorted(set(days))
    return set(ordered[:MIN_CALIBRATION_DAYS]), set(ordered[MIN_CALIBRATION_DAYS:])


def run_screen(
    *,
    tick_glob: str,
    segment_registry: str,
    window_plan: str,
    fee_history: str,
    specs: str,
    products: str,
) -> dict[str, object]:
    wanted = {x.strip().upper() for x in products.split(",") if x.strip()}
    if not wanted:
        raise ScreenInputError("products required")
    sessions = _session_map(Path(window_plan), Path(segment_registry))
    segments, inputs = _load_segments(tick_glob, sessions, wanted)
    _require_nonoverlapping_segments(segments)
    specs_by_product, fees = _specs(Path(specs)), _fees(Path(fee_history))
    cells: dict[tuple[str, str, str], list[Segment]] = defaultdict(list)
    for segment in segments:
        cells[(segment.product, segment.exact, segment.family)].append(segment)
    all_trades: dict[str, list[dict[str, object]]] = {"PRIMARY": [], "STRESS": []}
    excluded = []
    thresholds = []
    failures = defaultdict(int)
    binding_blocked = False
    for key, cell_segments in sorted(cells.items()):
        product, exact, family = key
        days = sorted({x.official_day for x in cell_segments})
        calibration, evaluation = _session_date_split(days)
        if not evaluation:
            excluded.append({"cell": list(key), "reason": "NO_EVALUATION_OFFICIAL_DAY"})
            continue
        calibration_points = []
        for segment in cell_segments:
            if segment.official_day in calibration:
                calibration_points.extend(point for _, point in _points(segment))
        try:
            frozen = freeze_feature_only_thresholds(calibration_points)[(exact, family)]
        except (BBOChangeContractError, KeyError) as exc:
            excluded.append({"cell": list(key), "reason": str(exc)})
            continue
        thresholds.append(
            {
                "cell": list(key),
                "sample_count": frozen.sample_count,
                "threshold": str(frozen.threshold),
                "calibration_session_dates": sorted(calibration),
                "evaluation_session_dates": sorted(evaluation),
            }
        )
        if product not in specs_by_product:
            excluded.append({"cell": list(key), "reason": "NO_AUTHORIZED_SPEC"})
            binding_blocked = True
            continue
        missing_fee_days = [
            day for day in sorted(evaluation) if (day, exact) not in fees
        ]
        if missing_fee_days:
            excluded.append(
                {
                    "cell": list(key),
                    "reason": "MISSING_OPEN_OR_CLOSE_TODAY_FEE",
                    "session_date_proxies": missing_fee_days,
                }
            )
            binding_blocked = True
            continue
        multiplier, tick = specs_by_product[product]
        for segment in cell_segments:
            for observation in segment.rows:
                if observation.bid_price % tick or observation.ask_price % tick:
                    raise ScreenInputError(f"off-grid BBO in {segment.segment_id}")
        for segment in sorted(
            cell_segments, key=lambda x: (x.official_day, x.rows[0].source_event_ns)
        ):
            if segment.official_day not in evaluation:
                continue
            if (
                segment.rows[-1].active_time_ns - segment.rows[0].active_time_ns
                < 60 * NS
            ):
                failures["SHORT_SEGMENT"] += 1
                continue
            last_exit_seq = {"PRIMARY": 0, "STRESS": 0}
            for _, point in _points(segment):
                signal = signal_from_threshold(point, {(exact, family): frozen})
                if signal is None:
                    continue
                if segment.rows[-1].active_time_ns - signal.active_time_ns < 60 * NS:
                    failures["INSUFFICIENT_SIGNAL_REMAINING"] += 1
                    continue
                for scenario, latency, adverse in (
                    ("PRIMARY", 500_000_000, 0),
                    ("STRESS", NS, 1),
                ):
                    # The frozen event order releases an exited slot before a
                    # signal produced by that same callback is considered.
                    if signal.collector_seq < last_exit_seq[scenario]:
                        failures[f"{scenario}_OVERLAP_SUPPRESSED"] += 1
                        continue
                    replay = _round_trip(signal, segment.rows, latency, adverse, tick)
                    if replay is None:
                        failures[f"{scenario}_NO_COMPLETE"] += 1
                        continue
                    side, entry, exit, exit_seq, exit_time_ns, timed_out = replay
                    last_exit_seq[scenario] = exit_seq
                    if timed_out:
                        failures[f"{scenario}_EXIT_GRACE_EXCEEDED"] += 1
                    fee = fees[(segment.official_day, exact)]
                    open_ratio, open_cny, close_ratio, close_cny = fee
                    open_fee = _leg_fee(entry, multiplier, open_ratio, open_cny)
                    close_fee = _leg_fee(exit, multiplier, close_ratio, close_cny)
                    fee_value = open_fee + close_fee
                    gross = (
                        (exit - entry) if side == "BUY" else (entry - exit)
                    ) * multiplier
                    all_trades[scenario].append(
                        {
                            "product": product,
                            "official_day": segment.official_day,
                            "gross": gross,
                            "fees": fee_value,
                            "net": gross - fee_value,
                            "exit_time_ns": exit_time_ns,
                        }
                    )

    def metrics(items):
        grouped = defaultdict(list)
        for x in items:
            grouped[x["product"]].append(x)

        def one(rows):
            ordered = sorted(rows, key=lambda x: x["exit_time_ns"])
            nets = [x["net"] for x in ordered]
            days = defaultdict(lambda: Decimal(0))
            for x in rows:
                days[x["official_day"]] += x["net"]
            return {
                "trades": len(rows),
                "wins": sum(x > 0 for x in nets),
                "gross": str(sum((x["gross"] for x in rows), Decimal(0))),
                "exchange_fees": str(sum((x["fees"] for x in rows), Decimal(0))),
                "exchange_fee_net": str(sum(nets, Decimal(0))),
                "max_drawdown": str(_maximum_drawdown(nets)),
                "positive_days": sum(x > 0 for x in days.values()),
            }

        result = {p: one(rows) for p, rows in sorted(grouped.items())}
        result["SESSION_DATE_PROXY"] = {
            day: one([x for x in items if x["official_day"] == day])
            for day in sorted({x["official_day"] for x in items})
        }
        result["POOLED"] = one(items)
        if items:
            retained, removed_days = _remove_best_three_session_dates(items)
            result["POOLED_BEST3_SESSION_DATE_PROXY_REMOVED"] = one(retained)
            result["POOLED_BEST3_SESSION_DATE_PROXY_REMOVED"][
                "removed_session_dates"
            ] = removed_days
            result["PRODUCTS_AFTER_POOLED_BEST3_SESSION_DATE_PROXY_REMOVAL"] = {
                product: one(
                    [item for item in rows if item["official_day"] not in removed_days]
                )
                for product, rows in sorted(grouped.items())
            }
        return result

    out = {
        "schema_version": "issue488_csv_pnl_screen_v1",
        "classification": "DIAGNOSTIC_SCREEN",
        "products": sorted(wanted),
        "method": {
            "feature_window_seconds": FEATURE_SECONDS,
            "feature_only_calibration_session_dates": MIN_CALIBRATION_DAYS,
            "threshold": "nearest_rank_Q95_abs_score_per_exact_contract_session_family",
            "direction": "positive_LONG_negative_SHORT",
            "quantity_lots": 1,
            "holding_horizon_seconds": HOLD_SECONDS,
            "primary_latency_ms_each_decision": 500,
            "primary_adverse_ticks_each_leg": 0,
            "stress_latency_ms_each_decision": 1000,
            "stress_adverse_ticks_each_leg": 1,
            "fills": "aggressive_observed_ask_bid",
            "fee_rounding": "each_leg_0.01_ROUND_HALF_UP",
        },
        "warnings": WARNINGS,
        "date_axis": {
            "source": "phase120_session_id_middle_component",
            "semantics": "LOCAL_SESSION_OCCURRENCE_DATE_PROXY",
            "official_trading_day_verified": False,
        },
        "exchange_fee_binding": "HISTORICAL_SCHEDULE_LOOKUP_BY_SESSION_DATE_PROXY",
        "broker_markup": "UNBOUND",
        "segment_overlap_preflight": "PASS",
        "code_inputs": [
            _input_meta(Path(__file__).resolve()),
            _input_meta(
                Path(__file__)
                .with_name("collector_ordered_l1_bbo_change_v1.py")
                .resolve()
            ),
        ],
        "inputs": inputs
        + [
            _input_meta(x)
            for x in (
                Path(segment_registry),
                Path(window_plan),
                Path(fee_history),
                Path(specs),
            )
        ],
        "rows": sum(len(s.rows) for s in segments),
        "segments": len(segments),
        "cells": len(cells),
        "thresholds": thresholds,
        "excluded_cells": excluded,
        "fail_counts": dict(sorted(failures.items())),
        "scenarios": {name: metrics(items) for name, items in all_trades.items()},
    }
    primary, stress = out["scenarios"]["PRIMARY"], out["scenarios"]["STRESS"]
    pn = Decimal(primary["POOLED"]["exchange_fee_net"])
    sn = Decimal(stress["POOLED"]["exchange_fee_net"])
    product_nets = [
        Decimal(primary.get(p, {"exchange_fee_net": "0"})["exchange_fee_net"])
        for p in wanted
    ]
    removed = Decimal(
        primary.get(
            "POOLED_BEST3_SESSION_DATE_PROXY_REMOVED", {"exchange_fee_net": "0"}
        )["exchange_fee_net"]
    )
    retained_product_nets = [
        Decimal(
            primary.get(
                "PRODUCTS_AFTER_POOLED_BEST3_SESSION_DATE_PROXY_REMOVAL", {}
            ).get(product, {"exchange_fee_net": "0"})["exchange_fee_net"]
        )
        for product in wanted
    ]
    product_trade_counts = [primary.get(p, {"trades": 0})["trades"] for p in wanted]
    if binding_blocked or not thresholds or not all(product_trade_counts):
        out["decision"] = "INSUFFICIENT_DATA_FOR_FAST_SCREEN"
    else:
        out["decision"] = (
            "PROMISING_NOT_VALIDATED"
            if pn > 0
            and sn > 0
            and removed > 0
            and all(x > 0 for x in product_nets)
            and all(x > 0 for x in retained_product_nets)
            else "NO_EDGE_IN_FAST_SCREEN"
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tick-glob", required=True)
    parser.add_argument("--segment-registry", required=True)
    parser.add_argument("--window-plan", required=True)
    parser.add_argument("--fee-history", required=True)
    parser.add_argument("--specs", required=True)
    parser.add_argument("--products", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        report = run_screen(
            **{
                k: getattr(args, k)
                for k in (
                    "tick_glob",
                    "segment_registry",
                    "window_plan",
                    "fee_history",
                    "specs",
                    "products",
                )
            }
        )
    except (ScreenInputError, BBOChangeContractError) as exc:
        parser.error(str(exc))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", delete=False, dir=target.parent, encoding="utf-8"
    ) as fh:
        fh.write(payload)
        temporary = fh.name
    os.replace(temporary, target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
