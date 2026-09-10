#!/usr/bin/env python3
"""Issue #481's deliberately small, target-only causal replay feasibility check.

The input directory is an extracted, immutable custody export.  This runner does
not build bars, query a database, or place orders.  It consumes the frozen target
event path plus the already-qualified BBO/fee/spec projections and writes exactly
three small evidence files.  It fails closed if an event cannot be applied to the
position state that precedes it.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


CANDIDATE_ID = "INTRADAY_SWING_TREND_EXACT_V1"
PRIMARY = "PRIMARY_2S"
STRESS = "STRESS_5S"
SCENARIOS = (PRIMARY, STRESS)

EVENT_FILE = "bbo_event_path_assumed_fill.csv"
BBO_FILE = "event_bbo_first_qualified.csv"
FEE_FILE = "official_pit_mapping_with_modeled_close_today_fee.csv"
FEE_HISTORY_FILE = "official_fee_margin_history_6products_with_modeled_close_today.csv"
SPEC_FILE = "contract_specs.csv"
CURVE_FILE = "curve_contract_daily.csv"
INITIAL_CASH_CNY = 1_000_000.0
DEV_START = "2023-01-03"
DEV_END = "2024-12-31"
EXPECTED_CORRECTED_EVENT_SHA256 = "74915208177e188f65074290d68590eec7b4c4d811a8648c1d92a331d2cbd71c"
FOLDS = {"DEV_2023": ("2023-01-01", "2023-12-31"), "DEV_2024": ("2024-01-01", "2024-12-31")}


class ReplayError(ValueError):
    """A frozen input or causal state transition is not usable."""


@dataclass(frozen=True)
class Position:
    contract: str
    direction: int
    opened_day: str


@dataclass
class AccountPosition:
    contract: str
    direction: int
    opened_day: str
    entry_price: float
    multiplier: float


@dataclass
class Account:
    cash: float = INITIAL_CASH_CNY
    realized_pnl: float = 0.0
    fees_cny: float = 0.0
    position: AccountPosition | None = None
    daily: dict[str, dict[str, float | str | None]] | None = None

    def __post_init__(self) -> None:
        if self.daily is None:
            self.daily = {}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path, required: set[str]) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        actual = set(reader.fieldnames or ())
        missing = required - actual
        if missing:
            raise ReplayError(f"{path.name} missing columns: {sorted(missing)}")
        return list(reader)


def read_dev_curve(path: Path) -> tuple[list[str], dict[str, dict[str, float]]]:
    """Read only the chronological DEV source rows; never parse 2025+ marks."""
    required = {"source_official_day", "available_official_day", "exact_contract", "settlement"}
    marks: dict[str, dict[str, float]] = defaultdict(dict)
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ReplayError(f"{path.name} missing columns: {sorted(missing)}")
        for row in reader:
            day = row["source_official_day"]
            if day > DEV_END:
                break
            if day < DEV_START:
                continue
            if row["available_official_day"] <= day:
                raise ReplayError(f"non-causal curve availability for {row['exact_contract']} {day}")
            settlement = parse_float(row["settlement"], "settlement")
            if settlement <= 0:
                continue
            existing = marks[day].get(row["exact_contract"])
            if existing is not None and existing != settlement:
                raise ReplayError(f"conflicting settlement for {row['exact_contract']} {day}")
            marks[day][row["exact_contract"]] = settlement
    if not marks:
        raise ReplayError("no DEV curve settlements")
    return sorted(marks), marks


def one_named_file(input_root: Path, name: str) -> Path:
    matches = sorted(input_root.rglob(name))
    if len(matches) != 1:
        raise ReplayError(f"expected exactly one {name}, found {len(matches)}")
    return matches[0]


def parse_time(value: str, field: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    timezone_start = max(normalized.rfind("+"), normalized.rfind("-"))
    fraction_start = normalized.rfind(".", 0, timezone_start)
    if fraction_start != -1 and timezone_start > fraction_start:
        fraction = normalized[fraction_start + 1 : timezone_start]
        if len(fraction) > 6:
            normalized = normalized[: fraction_start + 1] + fraction[:6] + normalized[timezone_start:]
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ReplayError(f"invalid {field}: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ReplayError(f"{field} lacks timezone: {value!r}")
    return parsed


def parse_float(value: str, field: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ReplayError(f"invalid {field}: {value!r}") from exc
    if not math.isfinite(result):
        raise ReplayError(f"non-finite {field}: {value!r}")
    return result


def is_open(event_type: str) -> bool:
    return "_ENTRY" in event_type or event_type.endswith("ROLL_OPEN")


def priority(event_type: str) -> int:
    # On one legal open a slow/target exit must settle the held contract before
    # a mapping-roll close is considered. Both close classes precede all opens.
    # Do not let opaque event ids decide this economic ordering.
    if event_type.endswith("ROLL_CLOSE"):
        return 1
    return 2 if is_open(event_type) else 0


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def event_sort_key(row: dict[str, str]) -> tuple[datetime, int, str]:
    return parse_time(row["eligibility_time"], "eligibility_time"), priority(row["event_type"]), row["event_id"]


def corrected_event_path(events: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Resolve the only permitted same-open slow-exit/roll collision.

    The source path was an assumed-fill BBO acquisition path. A slow target exit
    on the same open as a mapping change named the new map contract, although
    the held position was still in the old contract. The causal action is one
    close of that old contract and no roll-open. Every source event and BBO
    source remains in the derived evidence; nothing edits the custody CSV.
    """
    ordered = sorted(events, key=event_sort_key)
    groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in ordered:
        groups[(row["path_id"], row["product"], row["eligibility_time"])].append(row)
    states: dict[tuple[str, str], Position] = {}
    corrected: list[dict[str, str]] = []
    audits: list[dict[str, str]] = []
    skipped: set[str] = set()

    for event in ordered:
        if event["event_id"] in skipped:
            continue
        key = (event["path_id"], event["product"])
        previous = states.get(key)
        opening = is_open(event["event_type"])
        if opening:
            if previous is not None:
                raise ReplayError(f"event path opens while holding {previous.contract}: {event['event_id']}")
            states[key] = Position(event["exact_contract"], 1 if event["side"] == "BUY" else -1, event["official_trading_day"])
            corrected.append(event)
            continue
        if previous is None:
            raise ReplayError(f"event path closes while flat: {event['event_id']}")
        expected_side = "SELL" if previous.direction > 0 else "BUY"
        if event["side"] != expected_side:
            raise ReplayError(f"event path close side does not reduce held position: {event['event_id']}")
        if event["exact_contract"] == previous.contract:
            states.pop(key)
            corrected.append(event)
            continue

        same_open = groups[(event["path_id"], event["product"], event["eligibility_time"])]
        old_close = [
            row for row in same_open
            if not is_open(row["event_type"])
            and row["exact_contract"] == previous.contract
            and row["side"] == expected_side
        ]
        redundant_open = [
            row for row in same_open
            if is_open(row["event_type"])
            and row["exact_contract"] == event["exact_contract"]
            and row["side"] == ("BUY" if previous.direction > 0 else "SELL")
        ]
        if len(old_close) != 1 or len(redundant_open) != 1:
            raise ReplayError(
                "close contract differs from held contract without the exact "
                f"same-open exit/roll correction pattern: {event['event_id']}"
            )
        source_close = old_close[0]
        source_open = redundant_open[0]
        corrected_id = canonical_sha256(
            {
                "schema_version": "issue481_same_open_exit_roll_correction_v1",
                "exit_event_id": event["event_id"],
                "roll_close_event_id": source_close["event_id"],
                "roll_open_event_id": source_open["event_id"],
                "held_contract": previous.contract,
            }
        )
        replacement = dict(event)
        replacement.update(
            {
                "event_id": corrected_id,
                "exact_contract": previous.contract,
                "bbo_source_event_id": source_close["event_id"],
                "correction_type": "SAME_OPEN_SLOW_EXIT_PRECEDES_ROLL",
                "source_event_id": event["event_id"],
                "dropped_roll_close_event_id": source_close["event_id"],
                "dropped_roll_open_event_id": source_open["event_id"],
            }
        )
        corrected.append(replacement)
        audits.append(
            {
                "correction_type": replacement["correction_type"],
                "corrected_event_id": corrected_id,
                "source_exit_event_id": event["event_id"],
                "bbo_source_event_id": source_close["event_id"],
                "dropped_roll_close_event_id": source_close["event_id"],
                "dropped_roll_open_event_id": source_open["event_id"],
                "held_contract": previous.contract,
                "incorrect_mapped_exit_contract": event["exact_contract"],
                "eligibility_time": event["eligibility_time"],
            }
        )
        skipped.update({source_close["event_id"], source_open["event_id"]})
        states.pop(key)
    return corrected, audits


def load_inputs(input_root: Path) -> tuple[
    list[dict[str, str]],
    dict[tuple[str, str], dict[str, str]],
    dict[str, list[dict[str, str]]],
    dict[str, dict[str, str]],
    list[str],
    dict[str, dict[str, float]],
    dict[str, str],
]:
    paths = {name: one_named_file(input_root, name) for name in (EVENT_FILE, BBO_FILE, FEE_FILE, FEE_HISTORY_FILE, SPEC_FILE, CURVE_FILE)}
    events = read_csv(
        paths[EVENT_FILE],
        {"event_id", "path_id", "candidate_id", "product", "exact_contract", "event_type", "side", "official_trading_day", "eligibility_time"},
    )
    bbo_rows = read_csv(
        paths[BBO_FILE],
        {"event_id", "scenario", "threshold_time", "qualified", "event_time", "received_time_simulated", "bid_price_1", "bid_volume_1", "ask_price_1", "ask_volume_1", "limit_down_simulated", "limit_up_simulated", "received_time_model"},
    )
    fee_rows = read_csv(
        paths[FEE_FILE],
        {"official_trading_day", "exact_contract", "ordinary_fee_ratio_per_mille", "ordinary_fee_cny_per_lot", "modeled_close_today_fee_ratio_per_mille", "modeled_close_today_fee_cny_per_lot", "close_today_fee_provenance"},
    )
    fee_history_rows = read_csv(
        paths[FEE_HISTORY_FILE],
        {"official_day", "exact_contract", "ordinary_fee_ratio_per_mille", "ordinary_fee_cny_per_lot", "modeled_close_today_fee_ratio_per_mille", "modeled_close_today_fee_cny_per_lot", "close_today_fee_provenance"},
    )
    spec_rows = read_csv(paths[SPEC_FILE], {"exact_contract", "price_tick", "volume_multiple"})
    curve_days, curve_marks = read_dev_curve(paths[CURVE_FILE])

    event_ids: set[str] = set()
    for event in events:
        if event["candidate_id"] != CANDIDATE_ID:
            raise ReplayError(f"unexpected candidate_id: {event['candidate_id']!r}")
        if event["event_id"] in event_ids:
            raise ReplayError(f"duplicate event_id: {event['event_id']}")
        if event["side"] not in {"BUY", "SELL"}:
            raise ReplayError(f"invalid side for {event['event_id']}: {event['side']!r}")
        event_ids.add(event["event_id"])

    quotes: dict[tuple[str, str], dict[str, str]] = {}
    for quote in bbo_rows:
        key = (quote["event_id"], quote["scenario"])
        if key in quotes:
            raise ReplayError(f"duplicate BBO row: {key}")
        quotes[key] = quote
    for event_id in event_ids:
        for scenario in SCENARIOS:
            if (event_id, scenario) not in quotes:
                raise ReplayError(f"missing {scenario} BBO for event {event_id}")

    fees: dict[tuple[str, str], dict[str, str]] = {}
    for fee in fee_rows:
        key = (fee["official_trading_day"], fee["exact_contract"])
        if key in fees:
            raise ReplayError(f"duplicate fee row: {key}")
        fees[key] = fee
    fee_history: dict[str, list[dict[str, str]]] = defaultdict(list)
    for fee in fee_history_rows:
        fee_history[fee["exact_contract"]].append(fee)
    for rows in fee_history.values():
        rows.sort(key=lambda row: row["official_day"])
    specs: dict[str, dict[str, str]] = {}
    for spec in spec_rows:
        contract = spec["exact_contract"]
        if contract in specs:
            raise ReplayError(f"duplicate spec: {contract}")
        specs[contract] = spec
    return events, quotes, fee_history, specs, curve_days, curve_marks, {name: sha256_file(path) for name, path in paths.items()}


def effective_fee(fee_history: dict[str, list[dict[str, str]]], event: dict[str, str]) -> dict[str, str]:
    rows = fee_history.get(event["exact_contract"], [])
    eligible = [row for row in rows if row["official_day"] < event["official_trading_day"]]
    if not eligible:
        raise ReplayError(f"no prior official fee for {event['exact_contract']} on {event['official_trading_day']}")
    return eligible[-1]


def quote_fill(event: dict[str, str], quote: dict[str, str], spec: dict[str, str], scenario: str) -> dict[str, Any]:
    if quote["qualified"].lower() != "true":
        return {"status": "UNFILLED", "reason": quote.get("reason", "BBO_NOT_QUALIFIED")}
    eligibility = parse_time(event["eligibility_time"], "eligibility_time")
    threshold = parse_time(quote["threshold_time"], "threshold_time")
    event_time = parse_time(quote["event_time"], "event_time")
    received_time = parse_time(quote["received_time_simulated"], "received_time_simulated")
    if threshold < eligibility or event_time < threshold or received_time < event_time:
        raise ReplayError(f"non-causal quote timing for {event['event_id']} {scenario}")
    bid = parse_float(quote["bid_price_1"], "bid_price_1")
    ask = parse_float(quote["ask_price_1"], "ask_price_1")
    bid_volume = parse_float(quote["bid_volume_1"], "bid_volume_1")
    ask_volume = parse_float(quote["ask_volume_1"], "ask_volume_1")
    limit_down = parse_float(quote["limit_down_simulated"], "limit_down_simulated")
    limit_up = parse_float(quote["limit_up_simulated"], "limit_up_simulated")
    tick = parse_float(spec["price_tick"], "price_tick")
    if bid <= 0 or ask <= 0 or bid >= ask or limit_down >= limit_up:
        raise ReplayError(f"invalid BBO/limit envelope for {event['event_id']} {scenario}")
    if event["side"] == "BUY":
        if ask_volume < 1:
            return {"status": "UNFILLED", "reason": "INSUFFICIENT_ASK_DEPTH"}
        fill_price = ask + (1 if scenario == PRIMARY else 3) * tick
    else:
        if bid_volume < 1:
            return {"status": "UNFILLED", "reason": "INSUFFICIENT_BID_DEPTH"}
        fill_price = bid - (1 if scenario == PRIMARY else 3) * tick
    if not limit_down <= fill_price <= limit_up:
        return {"status": "UNFILLED", "reason": "IMPACTED_PRICE_OUTSIDE_MODELED_LIMIT"}
    return {
        "status": "FILLED",
        "fill_price": fill_price,
        "event_time": quote["event_time"],
        "received_time_simulated": quote["received_time_simulated"],
        "received_time_model": quote["received_time_model"],
        "limit_model": quote.get("limit_model", "SIMULATED_PREVIOUS_OFFICIAL_SETTLEMENT_20PCT_ENVELOPE"),
    }


def fee_cny(event: dict[str, str], position: Position | None, fee: dict[str, str], spec: dict[str, str], fill_price: float, scenario: str) -> tuple[str, str, float]:
    opening = is_open(event["event_type"])
    if opening:
        offset = "OPEN"
        ratio = parse_float(fee["ordinary_fee_ratio_per_mille"], "ordinary_fee_ratio_per_mille")
        fixed = parse_float(fee["ordinary_fee_cny_per_lot"], "ordinary_fee_cny_per_lot")
        provenance = "OFFICIAL_ORDINARY"
    elif position is not None and position.opened_day == event["official_trading_day"]:
        offset = "CLOSE_TODAY"
        ratio = parse_float(fee["modeled_close_today_fee_ratio_per_mille"], "modeled_close_today_fee_ratio_per_mille")
        fixed = parse_float(fee["modeled_close_today_fee_cny_per_lot"], "modeled_close_today_fee_cny_per_lot")
        provenance = fee["close_today_fee_provenance"]
    else:
        offset = "CLOSE"
        ratio = parse_float(fee["ordinary_fee_ratio_per_mille"], "ordinary_fee_ratio_per_mille")
        fixed = parse_float(fee["ordinary_fee_cny_per_lot"], "ordinary_fee_cny_per_lot")
        provenance = "OFFICIAL_ORDINARY"
    multiplier = parse_float(spec["volume_multiple"], "volume_multiple")
    multiplier_cost = 1.0 if scenario == PRIMARY else 1.25
    return offset, provenance, (fill_price * multiplier * ratio / 1000.0 + fixed) * multiplier_cost


def max_drawdown(equity: list[float]) -> float:
    peak = equity[0]
    drawdown = 0.0
    for value in equity:
        peak = max(peak, value)
        drawdown = max(drawdown, peak - value)
    return drawdown


def directional_unrealized(snapshot: dict[str, float | str | None], direction: int) -> float:
    """Return the snapshot unrealized PnL only when that direction is held."""
    return float(snapshot["unrealized_pnl_cny"]) if snapshot["position_direction"] == direction else 0.0


def account_metrics(account: Account, rows: list[dict[str, Any]], days: list[str], start_index: int, end_index: int) -> dict[str, Any]:
    assert account.daily is not None
    selected_days = days[start_index : end_index + 1]
    before = INITIAL_CASH_CNY if start_index == 0 else float(account.daily[days[start_index - 1]]["equity_cny"])
    before_fees = 0.0 if start_index == 0 else float(account.daily[days[start_index - 1]]["fees_cny"])
    before_realized = 0.0 if start_index == 0 else float(account.daily[days[start_index - 1]]["realized_pnl_cny"])
    before_snapshot: dict[str, float | str | None] = {
        "unrealized_pnl_cny": 0.0,
        "position_direction": None,
    } if start_index == 0 else account.daily[days[start_index - 1]]
    equity = [before] + [float(account.daily[day]["equity_cny"]) for day in selected_days]
    deltas = [equity[index] - equity[index - 1] for index in range(1, len(equity))]
    top_index = max(range(len(deltas)), key=deltas.__getitem__) if deltas else None
    reduced = [before]
    for index, delta in enumerate(deltas):
        reduced.append(reduced[-1] + (0.0 if index == top_index else delta))
    last = account.daily[selected_days[-1]]
    net_pnl = equity[-1] - before
    max_dd = max_drawdown(equity)
    filled = [row for row in rows if row["status"] == "FILLED" and selected_days[0] <= row["official_trading_day"] <= selected_days[-1]]
    opened = [row for row in filled if is_open(str(row["event_type"]))]

    def direction_net(direction: int) -> float:
        attributed = [row for row in filled if int(row["pnl_direction"]) == direction]
        realized_after_fees = sum(float(row["realized_pnl_cny"]) - float(row["fee_cny"]) for row in attributed)
        unrealized_change = directional_unrealized(last, direction) - directional_unrealized(before_snapshot, direction)
        return realized_after_fees + unrealized_change

    long_net = direction_net(1)
    short_net = direction_net(-1)
    roll_rows = [row for row in filled if "ROLL" in str(row["event_type"])]
    roll_fees = sum(float(row["fee_cny"]) for row in roll_rows)
    roll_realized_net = sum(float(row["realized_pnl_cny"]) - float(row["fee_cny"]) for row in roll_rows)
    return {
        "start_equity_cny": round(before, 10),
        "end_equity_cny": round(equity[-1], 10),
        "net_pnl_cny": round(net_pnl, 10),
        "net_return": round(net_pnl / INITIAL_CASH_CNY, 12),
        "realized_pnl_cny": round(float(last["realized_pnl_cny"]) - before_realized, 10),
        "unrealized_pnl_cny": round(float(last["unrealized_pnl_cny"]), 10),
        "fees_cny": round(float(last["fees_cny"]) - before_fees, 10),
        "max_drawdown_cny": round(max_dd, 10),
        "profit_to_max_drawdown": None if max_dd == 0 else round(net_pnl / max_dd, 12),
        "top_day": None if top_index is None else selected_days[top_index],
        "top_day_pnl_cny": None if top_index is None else round(deltas[top_index], 10),
        "net_pnl_after_top_day_removal_cny": round(reduced[-1] - before, 10),
        "max_drawdown_after_top_day_removal_cny": round(max_drawdown(reduced), 10),
        "filled_events": len(filled),
        "long_open_events": sum(1 for row in opened if row["side"] == "BUY"),
        "short_open_events": sum(1 for row in opened if row["side"] == "SELL"),
        "long_net_pnl_cny": round(long_net, 10),
        "short_net_pnl_cny": round(short_net, 10),
        "roll_events": len(roll_rows),
        "roll_realized_net_pnl_cny": round(roll_realized_net, 10),
        "roll_fees_cny": round(roll_fees, 10),
        "terminal_contract": last["position_contract"],
        "terminal_direction": last["position_direction"],
        "directional_pnl_identity_error_cny": round(net_pnl - long_net - short_net, 10),
        "accounting_identity_error_cny": round(
            float(last["equity_cny"]) - INITIAL_CASH_CNY - (float(last["realized_pnl_cny"]) - float(last["fees_cny"]) + float(last["unrealized_pnl_cny"])),
            10,
        ) if start_index == 0 else None,
    }


def apply_fill(account: Account, event: dict[str, str], fill: dict[str, Any], fee: dict[str, str], spec: dict[str, str], scenario: str) -> dict[str, Any]:
    opening = is_open(event["event_type"])
    previous = account.position
    if fill["status"] != "FILLED":
        return {"position_before": 0 if previous is None else previous.direction, "position_after": 0 if previous is None else previous.direction, "pnl_direction": 0 if previous is None else previous.direction, "realized_pnl_cny": 0.0, "fee_cny": 0.0}
    if opening:
        if previous is not None:
            raise ReplayError(f"open while holding {previous.contract}")
        direction = 1 if event["side"] == "BUY" else -1
        offset, provenance, cost = fee_cny(event, None, fee, spec, float(fill["fill_price"]), scenario)
        account.cash -= cost
        account.fees_cny += cost
        account.position = AccountPosition(event["exact_contract"], direction, event["official_trading_day"], float(fill["fill_price"]), parse_float(spec["volume_multiple"], "volume_multiple"))
        return {"position_before": 0, "position_after": direction, "pnl_direction": direction, "realized_pnl_cny": 0.0, "fee_cny": cost, "offset": offset, "fee_provenance": provenance}
    if previous is None:
        raise ReplayError("close while flat")
    if event["exact_contract"] != previous.contract:
        raise ReplayError(f"close contract {event['exact_contract']} differs from held {previous.contract}")
    if event["side"] != ("SELL" if previous.direction > 0 else "BUY"):
        raise ReplayError("close side does not reduce held position")
    offset, provenance, cost = fee_cny(event, previous, fee, spec, float(fill["fill_price"]), scenario)
    realized = previous.direction * (float(fill["fill_price"]) - previous.entry_price) * previous.multiplier
    account.cash += realized - cost
    account.realized_pnl += realized
    account.fees_cny += cost
    account.position = None
    return {"position_before": previous.direction, "position_after": 0, "pnl_direction": previous.direction, "realized_pnl_cny": realized, "fee_cny": cost, "offset": offset, "fee_provenance": provenance}


def mark_account(account: Account, day: str, marks: dict[str, float]) -> None:
    position = account.position
    unrealized = 0.0
    if position is not None:
        settlement = marks.get(position.contract)
        if settlement is None:
            raise ReplayError(f"missing official settlement for held {position.contract} on {day}")
        unrealized = position.direction * (settlement - position.entry_price) * position.multiplier
    assert account.daily is not None
    account.daily[day] = {
        "cash_cny": account.cash,
        "realized_pnl_cny": account.realized_pnl,
        "unrealized_pnl_cny": unrealized,
        "fees_cny": account.fees_cny,
        "equity_cny": account.cash + unrealized,
        "position_contract": None if position is None else position.contract,
        "position_direction": None if position is None else position.direction,
    }


def replay(input_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    events, quotes, fee_history, specs, curve_days, curve_marks, source_hashes = load_inputs(input_root)
    input_event_sha256 = canonical_sha256(events)
    try:
        ordered, corrections = corrected_event_path(events)
    except ReplayError as exc:
        summary = {
            "schema_version": "issue481_minimal_causal_replay_v1",
            "candidate_id": CANDIDATE_ID,
            "status": "STOP_EVENT_PATH_INCONSISTENT",
            "economic_pnl_evaluated": False,
            "source_files_sha256": source_hashes,
            "events_input": len(events),
            "events_applied_before_stop": 0,
            "failures": [{"reason": str(exc)}],
            "event_path": {"input_canonical_sha256": input_event_sha256},
        }
        comparison = {"schema_version": "issue481_paired_baseline_feasibility_comparison_v1", "candidate_id": CANDIDATE_ID, "status": summary["status"], "economic_pnl_evaluated": False, "paths": {}}
        return summary, [], comparison
    corrected_event_sha256 = canonical_sha256(ordered)
    if len(events) == 607 and corrected_event_sha256 != EXPECTED_CORRECTED_EVENT_SHA256:
        raise ReplayError("corrected event path SHA256 differs from the frozen 603-event binding")
    if any(not DEV_START <= event["official_trading_day"] <= DEV_END for event in ordered):
        raise ReplayError("non-DEV target event is forbidden")
    evidence: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    events_by_day: dict[str, list[dict[str, str]]] = defaultdict(list)
    for event in ordered:
        events_by_day[event["official_trading_day"]].append(event)
    products = sorted({event["product"] for event in ordered})
    accounts = {(path, scenario, product): Account() for path in ("CANDIDATE", "PAIRED") for scenario in SCENARIOS for product in products}

    for day in curve_days:
        for event in events_by_day.get(day, []):
            spec = specs.get(event["exact_contract"])
            if spec is None:
                failures.append({"event_id": event["event_id"], "reason": "missing exact-contract spec"})
                break
            fee = effective_fee(fee_history, event)
            bbo_source_event_id = event.get("bbo_source_event_id", event["event_id"])
            for scenario in SCENARIOS:
                account = accounts[(event["path_id"], scenario, event["product"])]
                try:
                    fill = quote_fill(event, quotes[(bbo_source_event_id, scenario)], spec, scenario)
                    accounting = apply_fill(account, event, fill, fee, spec, scenario)
                except ReplayError as exc:
                    failures.append({"event_id": event["event_id"], "path_id": event["path_id"], "product": event["product"], "scenario": scenario, "reason": str(exc)})
                    break
                record: dict[str, Any] = {**event, "source_event_id": event.get("source_event_id", event["event_id"]), "bbo_source_event_id": bbo_source_event_id, "scenario": scenario, "status": fill["status"]}
                record.update(fill)
                record.update({key: round(value, 10) if isinstance(value, float) else value for key, value in accounting.items()})
                record.update({"cash_after_cny": round(account.cash, 10), "realized_pnl_after_cny": round(account.realized_pnl, 10), "fees_after_cny": round(account.fees_cny, 10)})
                if "correction_type" in event:
                    record["correction"] = {"type": event["correction_type"], "dropped_roll_close_event_id": event["dropped_roll_close_event_id"], "dropped_roll_open_event_id": event["dropped_roll_open_event_id"]}
                evidence.append(record)
            if failures:
                break
        if failures:
            break
        try:
            for account in accounts.values():
                mark_account(account, day, curve_marks[day])
        except ReplayError as exc:
            failures.append({"official_trading_day": day, "reason": str(exc)})
            break

    status = "MODELED_PASS_RESEARCH_ONLY" if not failures else "STOP_REPLAY_INCONSISTENT"
    summary = {
        "schema_version": "issue481_minimal_causal_replay_v1",
        "candidate_id": CANDIDATE_ID,
        "status": status,
        "economic_pnl_evaluated": not failures,
        "replay_scope": "DEV_2023/DEV_2024 only; side-aware fills, historical fee model, official daily settlement MTM, no holdout or 2025+ economic data",
        "source_files_sha256": source_hashes,
        "events_input": len(events),
        "events_after_causal_correction": len(ordered),
        "event_path": {
            "input_canonical_sha256": input_event_sha256,
            "corrected_canonical_sha256": corrected_event_sha256,
            "correction_schema_version": "issue481_same_open_exit_roll_correction_v1",
            "corrections": corrections,
        },
        "events_applied_before_stop": len(evidence) // len(SCENARIOS),
        "failures": failures,
        "modeled_assumptions": {
            "received_time": "received_time_simulated from frozen BBO audit; not observed collector receipt time",
            "limit_envelope": "SIMULATED_PREVIOUS_OFFICIAL_SETTLEMENT_20PCT_ENVELOPE; not observed exchange limit fields",
            "close_today_fee": "official explicit value when present; otherwise ordinary fee * 0.5",
        },
    }
    comparisons: dict[str, Any] = {
        "schema_version": "issue481_paired_baseline_economic_comparison_v1",
        "candidate_id": CANDIDATE_ID,
        "status": status,
        "economic_pnl_evaluated": not failures,
        "pnl_attribution_definition": {
            "long_net_pnl_cny": "long realized pnl less long-attributed fees plus long unrealized change within the fold",
            "short_net_pnl_cny": "short realized pnl less short-attributed fees plus short unrealized change within the fold",
            "roll_realized_net_pnl_cny": "ROLL event realized pnl less ROLL event fees; roll_fees_cny is reported separately",
            "directional_pnl_identity_error_cny": "net_pnl_cny - long_net_pnl_cny - short_net_pnl_cny",
        },
        "by_product": {},
    }
    if not failures:
        all_ranges = {"FULL_DEV": (0, len(curve_days) - 1)}
        for fold, (start, end) in FOLDS.items():
            indexes = [index for index, day in enumerate(curve_days) if start <= day <= end]
            if not indexes:
                raise ReplayError(f"no curve days for {fold}")
            all_ranges[fold] = (indexes[0], indexes[-1])
        gate_cells: list[bool] = []
        for product in products:
            comparisons["by_product"][product] = {}
            for scenario in SCENARIOS:
                path_metrics: dict[str, dict[str, Any]] = {}
                for path in ("CANDIDATE", "PAIRED"):
                    rows = [row for row in evidence if row["product"] == product and row["scenario"] == scenario and row["path_id"] == path]
                    path_metrics[path] = {name: account_metrics(accounts[(path, scenario, product)], rows, curve_days, start, end) for name, (start, end) in all_ranges.items()}
                comparisons["by_product"][product][scenario] = path_metrics
                candidate = path_metrics["CANDIDATE"]["FULL_DEV"]
                paired = path_metrics["PAIRED"]["FULL_DEV"]
                ratio = candidate["profit_to_max_drawdown"]
                paired_ratio = paired["profit_to_max_drawdown"]
                net_gate = candidate["net_pnl_cny"] > 0 if scenario == PRIMARY else candidate["net_pnl_cny"] >= 0
                paired_increment = ratio is not None and paired_ratio is not None and ratio > paired_ratio
                ratio_gate = ratio is not None and ratio > 1
                gates = {"net": net_gate}
                if scenario == PRIMARY:
                    gates.update({"profit_to_max_drawdown": ratio_gate, "paired_increment": paired_increment})
                comparisons["by_product"][product][scenario]["gates"] = gates
                comparisons["by_product"][product][scenario]["reported_comparisons"] = {
                    "candidate_profit_to_max_drawdown": ratio,
                    "paired_profit_to_max_drawdown": paired_ratio,
                    "paired_increment": paired_increment,
                }
                gate_cells.append(all(gates.values()))
        go_stop = "GO_RESEARCH_ONLY" if all(gate_cells) else "STOP_ECONOMIC_GATE"
        summary["go_stop"] = go_stop
        comparisons["go_stop"] = go_stop
        summary["status"] = go_stop
        comparisons["status"] = go_stop
        summary["standalone_accounts"] = comparisons["by_product"]
    return summary, evidence, comparisons


def write_evidence(output_dir: Path, summary: dict[str, Any], evidence: Iterable[dict[str, Any]], comparison: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = (output_dir / "replay-summary.json", output_dir / "target-changes.jsonl", output_dir / "paired-baseline-comparison.json")
    if any(path.exists() for path in outputs):
        raise ReplayError(f"evidence output already exists under {output_dir}")
    outputs[0].write_text(canonical_json(summary) + "\n", encoding="utf-8")
    with outputs[1].open("w", encoding="utf-8") as handle:
        for row in evidence:
            handle.write(canonical_json(row) + "\n")
    outputs[2].write_text(canonical_json(comparison) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, required=True, help="extracted Issue #481 immutable custody input")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for exactly three lightweight evidence files")
    args = parser.parse_args(argv)
    try:
        summary, evidence, comparison = replay(args.input_root)
        write_evidence(args.output_dir, summary, evidence, comparison)
    except ReplayError as exc:
        print(f"issue481 replay error: {exc}", file=sys.stderr)
        return 2
    print(canonical_json({"status": summary["status"], "output_dir": str(args.output_dir), "events_applied_before_stop": summary["events_applied_before_stop"]}))
    return 0 if summary["status"] == "GO_RESEARCH_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
