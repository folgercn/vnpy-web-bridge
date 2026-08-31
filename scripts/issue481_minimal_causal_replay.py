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


class ReplayError(ValueError):
    """A frozen input or causal state transition is not usable."""


@dataclass(frozen=True)
class Position:
    contract: str
    direction: int
    opened_day: str


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
    dict[str, str],
]:
    paths = {name: one_named_file(input_root, name) for name in (EVENT_FILE, BBO_FILE, FEE_FILE, FEE_HISTORY_FILE, SPEC_FILE)}
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
    return events, quotes, fee_history, specs, {name: sha256_file(path) for name, path in paths.items()}


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


def replay(input_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    events, quotes, fee_history, specs, source_hashes = load_inputs(input_root)
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
    states: dict[tuple[str, str, str], Position] = {}
    evidence: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"filled": 0, "unfilled": 0, "events": 0})

    for event in ordered:
        key = (event["path_id"], event["product"], "shared_target")
        previous = states.get(key)
        opening = is_open(event["event_type"])
        try:
            if opening:
                if previous is not None:
                    raise ReplayError(f"open while already holding {previous.contract}")
                next_position = Position(event["exact_contract"], 1 if event["side"] == "BUY" else -1, event["official_trading_day"])
            else:
                if previous is None:
                    raise ReplayError("close while flat")
                expected_side = "SELL" if previous.direction > 0 else "BUY"
                if event["side"] != expected_side:
                    raise ReplayError(f"close side {event['side']} does not reduce {previous.direction:+d} position")
                if event["exact_contract"] != previous.contract:
                    raise ReplayError(f"close contract {event['exact_contract']} differs from held {previous.contract}")
                next_position = None
            spec = specs.get(event["exact_contract"])
            if spec is None:
                raise ReplayError("missing exact-contract spec")
            fee = effective_fee(fee_history, event)
        except ReplayError as exc:
            failures.append({"event_id": event["event_id"], "path_id": event["path_id"], "product": event["product"], "event_type": event["event_type"], "reason": str(exc)})
            break

        scenario_records: list[dict[str, Any]] = []
        bbo_source_event_id = event.get("bbo_source_event_id", event["event_id"])
        for scenario in SCENARIOS:
            fill = quote_fill(event, quotes[(bbo_source_event_id, scenario)], spec, scenario)
            record: dict[str, Any] = {
                "event_id": event["event_id"],
                "source_event_id": event.get("source_event_id", event["event_id"]),
                "bbo_source_event_id": bbo_source_event_id,
                "path_id": event["path_id"],
                "product": event["product"],
                "exact_contract": event["exact_contract"],
                "event_type": event["event_type"],
                "side": event["side"],
                "official_trading_day": event["official_trading_day"],
                "scenario": scenario,
                "target_before": 0 if previous is None else previous.direction,
                "target_after": 0 if next_position is None else next_position.direction,
                "status": fill["status"],
            }
            if "correction_type" in event:
                record["correction"] = {
                    "type": event["correction_type"],
                    "dropped_roll_close_event_id": event["dropped_roll_close_event_id"],
                    "dropped_roll_open_event_id": event["dropped_roll_open_event_id"],
                }
            record.update(fill)
            if fill["status"] == "FILLED":
                offset, provenance, cost = fee_cny(event, previous, fee, spec, fill["fill_price"], scenario)
                record.update({"offset": offset, "fee_provenance": provenance, "fee_cny": round(cost, 10)})
                counts[(event["path_id"], scenario)]["filled"] += 1
            else:
                counts[(event["path_id"], scenario)]["unfilled"] += 1
            counts[(event["path_id"], scenario)]["events"] += 1
            scenario_records.append(record)
        evidence.extend(scenario_records)
        if all(record["status"] == "FILLED" for record in scenario_records):
            if next_position is None:
                states.pop(key, None)
            else:
                states[key] = next_position

    status = "MODELED_PASS_RESEARCH_ONLY" if not failures else "STOP_EVENT_PATH_INCONSISTENT"
    summary = {
        "schema_version": "issue481_minimal_causal_replay_v1",
        "candidate_id": CANDIDATE_ID,
        "status": status,
        "economic_pnl_evaluated": False,
        "replay_scope": "target-only causal transition and quote/fee feasibility; no terminal MTM or economic gate evaluation",
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
    comparisons: dict[str, Any] = {"schema_version": "issue481_paired_baseline_feasibility_comparison_v1", "candidate_id": CANDIDATE_ID, "status": status, "economic_pnl_evaluated": False, "paths": {}}
    for (path_id, scenario), total in sorted(counts.items()):
        selected = [row for row in evidence if row["path_id"] == path_id and row["scenario"] == scenario]
        comparisons["paths"].setdefault(path_id, {})[scenario] = {
            **total,
            "total_modeled_fee_cny": round(sum(float(row.get("fee_cny", 0.0)) for row in selected), 10),
            "unfilled_retained": total["unfilled"],
        }
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
    return 0 if summary["status"] == "MODELED_PASS_RESEARCH_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
