import csv
import importlib.util
import json
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[3] / "scripts" / "issue481_minimal_causal_replay.py"
SPEC = importlib.util.spec_from_file_location("issue481_minimal_causal_replay", MODULE_PATH)
assert SPEC and SPEC.loader
replay_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = replay_module
SPEC.loader.exec_module(replay_module)


def write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def fixture_root(tmp_path: Path, bad_close_contract: bool = False) -> Path:
    root = tmp_path / "custody"
    root.mkdir()
    events = [
        {"event_id": "open", "path_id": "CANDIDATE", "candidate_id": replay_module.CANDIDATE_ID, "product": "ag", "exact_contract": "SHFE.ag2306", "event_type": "CANDIDATE_ENTRY_BREAKOUT", "side": "BUY", "official_trading_day": "2023-01-03", "eligibility_time": "2023-01-03T01:15:00+00:00"},
        {"event_id": "close", "path_id": "CANDIDATE", "candidate_id": replay_module.CANDIDATE_ID, "product": "ag", "exact_contract": "SHFE.ag2308" if bad_close_contract else "SHFE.ag2306", "event_type": "CANDIDATE_CHANNEL_EXIT", "side": "SELL", "official_trading_day": "2023-01-04", "eligibility_time": "2023-01-04T01:15:00+00:00"},
    ]
    write_csv(root / replay_module.EVENT_FILE, list(events[0]), events)
    quote_rows = []
    for event in events:
        for scenario, stamp in ((replay_module.PRIMARY, "01:15:02"), (replay_module.STRESS, "01:15:05")):
            quote_rows.append({"event_id": event["event_id"], "scenario": scenario, "threshold_time": f"{event['official_trading_day']}T{stamp}+00:00", "qualified": "True", "event_time": f"{event['official_trading_day']}T{stamp}+00:00", "received_time_simulated": f"{event['official_trading_day']}T{stamp}.050000+00:00", "bid_price_1": "100", "bid_volume_1": "1", "ask_price_1": "101", "ask_volume_1": "1", "limit_down_simulated": "80", "limit_up_simulated": "120", "received_time_model": "fixed-test"})
    write_csv(root / replay_module.BBO_FILE, list(quote_rows[0]), quote_rows)
    fee_rows = []
    for event in events:
        fee_rows.append({"official_trading_day": event["official_trading_day"], "exact_contract": event["exact_contract"], "ordinary_fee_ratio_per_mille": "0.05", "ordinary_fee_cny_per_lot": "0", "modeled_close_today_fee_ratio_per_mille": "0.025", "modeled_close_today_fee_cny_per_lot": "0", "close_today_fee_provenance": "SIMULATED_ORDINARY_X_0_5"})
    write_csv(root / replay_module.FEE_FILE, list(fee_rows[0]), fee_rows)
    history_rows = []
    for event in events:
        history_rows.append({"official_day": "2023-01-02", "exact_contract": event["exact_contract"], "ordinary_fee_ratio_per_mille": "0.05", "ordinary_fee_cny_per_lot": "0", "modeled_close_today_fee_ratio_per_mille": "0.025", "modeled_close_today_fee_cny_per_lot": "0", "close_today_fee_provenance": "SIMULATED_ORDINARY_X_0_5"})
    write_csv(root / replay_module.FEE_HISTORY_FILE, list(history_rows[0]), history_rows)
    specs = [{"exact_contract": "SHFE.ag2306", "price_tick": "1", "volume_multiple": "15"}]
    if bad_close_contract:
        specs.append({"exact_contract": "SHFE.ag2308", "price_tick": "1", "volume_multiple": "15"})
    write_csv(root / replay_module.SPEC_FILE, list(specs[0]), specs)
    curve = [
        {"source_official_day": "2023-01-03", "available_official_day": "2023-01-04", "exact_contract": "SHFE.ag2306", "settlement": "102"},
        {"source_official_day": "2023-01-04", "available_official_day": "2023-01-05", "exact_contract": "SHFE.ag2306", "settlement": "103"},
        {"source_official_day": "2024-01-02", "available_official_day": "2024-01-03", "exact_contract": "SHFE.ag2306", "settlement": "103"},
    ]
    if bad_close_contract:
        curve.extend(
            [
                {"source_official_day": "2023-01-03", "available_official_day": "2023-01-04", "exact_contract": "SHFE.ag2308", "settlement": "102"},
                {"source_official_day": "2023-01-04", "available_official_day": "2023-01-05", "exact_contract": "SHFE.ag2308", "settlement": "103"},
                {"source_official_day": "2024-01-02", "available_official_day": "2024-01-03", "exact_contract": "SHFE.ag2308", "settlement": "103"},
            ]
        )
    write_csv(root / replay_module.CURVE_FILE, list(curve[0]), curve)
    return root


def add_same_open_exit_roll_collision(root: Path) -> None:
    event_path = root / replay_module.EVENT_FILE
    events = list(csv.DictReader(event_path.open()))
    events.extend(
        [
            {"event_id": "zzz-new-exit", "path_id": "CANDIDATE", "candidate_id": replay_module.CANDIDATE_ID, "product": "ag", "exact_contract": "SHFE.ag2308", "event_type": "CANDIDATE_CHANNEL_EXIT", "side": "SELL", "official_trading_day": "2023-01-04", "eligibility_time": "2023-01-04T01:15:00+00:00"},
            {"event_id": "aaa-roll-close", "path_id": "CANDIDATE", "candidate_id": replay_module.CANDIDATE_ID, "product": "ag", "exact_contract": "SHFE.ag2306", "event_type": "ROLL_CLOSE", "side": "SELL", "official_trading_day": "2023-01-04", "eligibility_time": "2023-01-04T01:15:00+00:00"},
            {"event_id": "bbb-roll-open", "path_id": "CANDIDATE", "candidate_id": replay_module.CANDIDATE_ID, "product": "ag", "exact_contract": "SHFE.ag2308", "event_type": "ROLL_OPEN", "side": "BUY", "official_trading_day": "2023-01-04", "eligibility_time": "2023-01-04T01:15:00+00:00"},
        ]
    )
    events = [event for event in events if event["event_id"] != "close"]
    write_csv(event_path, list(events[0]), events)
    quote_path = root / replay_module.BBO_FILE
    quotes = list(csv.DictReader(quote_path.open()))
    for event_id in ("zzz-new-exit", "aaa-roll-close", "bbb-roll-open"):
        for scenario, stamp in ((replay_module.PRIMARY, "01:15:02"), (replay_module.STRESS, "01:15:05")):
            quotes.append({"event_id": event_id, "scenario": scenario, "threshold_time": f"2023-01-04T{stamp}+00:00", "qualified": "True", "event_time": f"2023-01-04T{stamp}+00:00", "received_time_simulated": f"2023-01-04T{stamp}.050000+00:00", "bid_price_1": "100", "bid_volume_1": "1", "ask_price_1": "101", "ask_volume_1": "1", "limit_down_simulated": "80", "limit_up_simulated": "120", "received_time_model": "fixed-test"})
    write_csv(quote_path, list(quotes[0]), quotes)
    fee_path = root / replay_module.FEE_FILE
    fees = list(csv.DictReader(fee_path.open()))
    fees.append({"official_trading_day": "2023-01-04", "exact_contract": "SHFE.ag2308", "ordinary_fee_ratio_per_mille": "0.05", "ordinary_fee_cny_per_lot": "0", "modeled_close_today_fee_ratio_per_mille": "0.025", "modeled_close_today_fee_cny_per_lot": "0", "close_today_fee_provenance": "SIMULATED_ORDINARY_X_0_5"})
    write_csv(fee_path, list(fees[0]), fees)
    history_path = root / replay_module.FEE_HISTORY_FILE
    history = list(csv.DictReader(history_path.open()))
    history.append({"official_day": "2023-01-03", "exact_contract": "SHFE.ag2306", "ordinary_fee_ratio_per_mille": "0.05", "ordinary_fee_cny_per_lot": "0", "modeled_close_today_fee_ratio_per_mille": "0.025", "modeled_close_today_fee_cny_per_lot": "0", "close_today_fee_provenance": "SIMULATED_ORDINARY_X_0_5"})
    history.append({"official_day": "2023-01-03", "exact_contract": "SHFE.ag2308", "ordinary_fee_ratio_per_mille": "0.05", "ordinary_fee_cny_per_lot": "0", "modeled_close_today_fee_ratio_per_mille": "0.025", "modeled_close_today_fee_cny_per_lot": "0", "close_today_fee_provenance": "SIMULATED_ORDINARY_X_0_5"})
    write_csv(history_path, list(history[0]), history)
    spec_path = root / replay_module.SPEC_FILE
    specs = list(csv.DictReader(spec_path.open()))
    specs.append({"exact_contract": "SHFE.ag2308", "price_tick": "1", "volume_multiple": "15"})
    write_csv(spec_path, list(specs[0]), specs)


def test_replay_writes_exactly_three_evidence_files_for_valid_path(tmp_path: Path) -> None:
    summary, rows, comparison = replay_module.replay(fixture_root(tmp_path))
    output = tmp_path / "evidence"
    replay_module.write_evidence(output, summary, rows, comparison)
    assert summary["status"] == "STOP_ECONOMIC_GATE"
    assert summary["economic_pnl_evaluated"] is True
    assert summary["events_applied_before_stop"] == 2
    assert len(rows) == 4
    assert {path.name for path in output.iterdir()} == {"replay-summary.json", "target-changes.jsonl", "paired-baseline-comparison.json"}
    assert all(json.loads(line)["status"] == "FILLED" for line in (output / "target-changes.jsonl").read_text().splitlines())


def test_replay_fails_closed_when_close_event_does_not_match_held_contract(tmp_path: Path) -> None:
    summary, rows, comparison = replay_module.replay(fixture_root(tmp_path, bad_close_contract=True))
    assert summary["status"] == "STOP_EVENT_PATH_INCONSISTENT"
    assert summary["events_applied_before_stop"] == 0
    assert "without the exact same-open exit/roll correction pattern" in summary["failures"][0]["reason"]
    assert comparison["status"] == "STOP_EVENT_PATH_INCONSISTENT"
    assert len(rows) == 0


def test_same_open_exit_roll_collision_uses_held_contract_bbo_and_drops_roll_open(tmp_path: Path) -> None:
    root = fixture_root(tmp_path)
    add_same_open_exit_roll_collision(root)
    summary, rows, _ = replay_module.replay(root)
    assert summary["status"] == "STOP_ECONOMIC_GATE"
    assert summary["events_input"] == 4
    assert summary["events_after_causal_correction"] == 2
    correction = summary["event_path"]["corrections"][0]
    assert correction["bbo_source_event_id"] == "aaa-roll-close"
    assert correction["dropped_roll_open_event_id"] == "bbb-roll-open"
    corrected_rows = [row for row in rows if row["event_id"] == correction["corrected_event_id"]]
    assert len(corrected_rows) == 2
    assert {row["exact_contract"] for row in corrected_rows} == {"SHFE.ag2306"}
    assert {row["bbo_source_event_id"] for row in corrected_rows} == {"aaa-roll-close"}


def test_economic_replay_covers_fees_roll_terminal_mtm_cross_fold_and_paired_gate(tmp_path: Path) -> None:
    root = tmp_path / "economic-custody"
    root.mkdir()
    candidate = replay_module.CANDIDATE_ID
    events = [
        {"event_id": "c-long", "path_id": "CANDIDATE", "candidate_id": candidate, "product": "ag", "exact_contract": "SHFE.ag2306", "event_type": "CANDIDATE_ENTRY_BREAKOUT", "side": "BUY", "official_trading_day": "2023-12-29", "eligibility_time": "2023-12-29T01:00:00+00:00"},
        {"event_id": "c-roll-close", "path_id": "CANDIDATE", "candidate_id": candidate, "product": "ag", "exact_contract": "SHFE.ag2306", "event_type": "ROLL_CLOSE", "side": "SELL", "official_trading_day": "2024-01-02", "eligibility_time": "2024-01-02T01:00:00+00:00"},
        {"event_id": "c-roll-open", "path_id": "CANDIDATE", "candidate_id": candidate, "product": "ag", "exact_contract": "SHFE.ag2308", "event_type": "ROLL_OPEN", "side": "BUY", "official_trading_day": "2024-01-02", "eligibility_time": "2024-01-02T01:00:00+00:00"},
        {"event_id": "c-au-open", "path_id": "CANDIDATE", "candidate_id": candidate, "product": "au", "exact_contract": "SHFE.au2306", "event_type": "CANDIDATE_ENTRY_BREAKOUT", "side": "BUY", "official_trading_day": "2023-12-29", "eligibility_time": "2023-12-29T01:00:00+00:00"},
        {"event_id": "c-au-close", "path_id": "CANDIDATE", "candidate_id": candidate, "product": "au", "exact_contract": "SHFE.au2306", "event_type": "CANDIDATE_CHANNEL_EXIT", "side": "SELL", "official_trading_day": "2023-12-29", "eligibility_time": "2023-12-29T01:15:00+00:00"},
        {"event_id": "p-short", "path_id": "PAIRED", "candidate_id": candidate, "product": "ag", "exact_contract": "SHFE.ag2306", "event_type": "PAIRED_NEXT_OPEN_ENTRY", "side": "SELL", "official_trading_day": "2023-12-29", "eligibility_time": "2023-12-29T01:00:00+00:00"},
        {"event_id": "p-cover", "path_id": "PAIRED", "candidate_id": candidate, "product": "ag", "exact_contract": "SHFE.ag2306", "event_type": "PAIRED_NEXT_OPEN_EXIT", "side": "BUY", "official_trading_day": "2024-01-02", "eligibility_time": "2024-01-02T01:00:00+00:00"},
    ]
    write_csv(root / replay_module.EVENT_FILE, list(events[0]), events)
    quotes = []
    for event in events:
        stamp = event["eligibility_time"].replace("+00:00", "")
        for scenario, seconds in ((replay_module.PRIMARY, 2), (replay_module.STRESS, 5)):
            quote_time = f"{stamp[:-2]}{seconds:02d}+00:00"
            quotes.append({"event_id": event["event_id"], "scenario": scenario, "threshold_time": quote_time, "qualified": "True", "event_time": quote_time, "received_time_simulated": quote_time.replace("+00:00", ".050000+00:00"), "bid_price_1": "100", "bid_volume_1": "1", "ask_price_1": "101", "ask_volume_1": "1", "limit_down_simulated": "50", "limit_up_simulated": "300", "received_time_model": "fixed-test"})
    write_csv(root / replay_module.BBO_FILE, list(quotes[0]), quotes)
    fee_headers = ["official_trading_day", "exact_contract", "ordinary_fee_ratio_per_mille", "ordinary_fee_cny_per_lot", "modeled_close_today_fee_ratio_per_mille", "modeled_close_today_fee_cny_per_lot", "close_today_fee_provenance"]
    mapping = [{**{key: event[key] for key in ("official_trading_day", "exact_contract")}, "ordinary_fee_ratio_per_mille": "0.05", "ordinary_fee_cny_per_lot": "0", "modeled_close_today_fee_ratio_per_mille": "0.025", "modeled_close_today_fee_cny_per_lot": "0", "close_today_fee_provenance": "SIMULATED_ORDINARY_X_0_5"} for event in events]
    unique_mapping = {(row["official_trading_day"], row["exact_contract"]): row for row in mapping}
    write_csv(root / replay_module.FEE_FILE, fee_headers, list(unique_mapping.values()))
    history_headers = ["official_day", *fee_headers[1:]]
    history = [{"official_day": "2023-12-28", **{key: row[key] for key in fee_headers[1:]}} for row in unique_mapping.values()]
    write_csv(root / replay_module.FEE_HISTORY_FILE, history_headers, history)
    specs = [{"exact_contract": contract, "price_tick": "1", "volume_multiple": "10"} for contract in ("SHFE.ag2306", "SHFE.ag2308", "SHFE.au2306")]
    write_csv(root / replay_module.SPEC_FILE, list(specs[0]), specs)
    curve = [
        {"source_official_day": "2023-12-29", "available_official_day": "2024-01-02", "exact_contract": "SHFE.ag2306", "settlement": "102"},
        {"source_official_day": "2023-12-29", "available_official_day": "2024-01-02", "exact_contract": "SHFE.au2306", "settlement": "102"},
        {"source_official_day": "2024-01-02", "available_official_day": "2024-01-03", "exact_contract": "SHFE.ag2306", "settlement": "103"},
        {"source_official_day": "2024-01-02", "available_official_day": "2024-01-03", "exact_contract": "SHFE.ag2308", "settlement": "201"},
        {"source_official_day": "2024-01-03", "available_official_day": "2024-01-04", "exact_contract": "SHFE.ag2308", "settlement": "203"},
        {"source_official_day": "2025-01-02", "available_official_day": "2025-01-03", "exact_contract": "SHFE.ag2308", "settlement": "holdout-must-not-be-read"},
    ]
    write_csv(root / replay_module.CURVE_FILE, list(curve[0]), curve)
    summary, rows, comparison = replay_module.replay(root)
    assert summary["economic_pnl_evaluated"] is True
    ag = comparison["by_product"]["ag"][replay_module.PRIMARY]["CANDIDATE"]
    assert ag["DEV_2024"]["start_equity_cny"] == ag["DEV_2023"]["end_equity_cny"]
    assert ag["FULL_DEV"]["terminal_contract"] == "SHFE.ag2308"
    assert ag["FULL_DEV"]["terminal_direction"] == 1
    assert ag["FULL_DEV"]["roll_events"] == 2
    assert abs(ag["FULL_DEV"]["accounting_identity_error_cny"]) < 1e-6
    assert any(row["event_id"] == "c-au-close" and row["scenario"] == replay_module.PRIMARY and row["offset"] == "CLOSE_TODAY" for row in rows)
    assert any(row["event_id"] == "p-short" and row["scenario"] == replay_module.PRIMARY and row["position_after"] == -1 for row in rows)
    assert set(comparison["by_product"]["ag"][replay_module.PRIMARY]["gates"]) == {"net", "profit_to_max_drawdown", "paired_increment"}
