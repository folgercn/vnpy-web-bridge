from __future__ import annotations

import ast
import json
import os
import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import collector_ordered_l1_bbo_change_v1 as bbo_change_module  # noqa: E402
import collector_ordered_l1_bbo_change_csv_pnl_screen_v1 as pnl_screen_module  # noqa: E402

from collector_ordered_l1_bbo_change_v1 import (  # noqa: E402
    BBOChangeContractError,
    BBOChangeEngine,
    CollectorControl,
    CustodyJournal,
    FeaturePoint,
    FrozenThreshold,
    ObservedBBO,
    SignalDecision,
    VerifiedCustodyStream,
    bbo_change_contribution,
    evaluate_clock_gate,
    freeze_feature_only_thresholds,
    read_verified_custody_stream_v1,
    replay_multi_signal_raw_v1,
    replay_primary_round_trip,
    pin_custody_root,
    signal_from_threshold,
)


SECOND = 1_000_000_000
BASE_UTC_NS = 1_800_000_000 * SECOND
CODE_SHA = "a" * 40


def observation(
    seq: int,
    *,
    active_ns: int = 0,
    source_event_ns: int | None = None,
    receive_utc_ns: int | None = None,
    receive_monotonic_ns: int | None = None,
    bid_price: object = "100",
    bid_size: object = "10",
    ask_price: object = "102",
    ask_size: object = "12",
    provider_update_id: str | None = None,
    collector_generation: str = "generation-1",
    clock_epoch: str = "clock-1",
    session_family: str = "DAY",
    segment_id: str = "day-am-1",
    reset_reason: str | None = None,
    explicit_duplicate: bool = False,
    clock_sync_state: str = "SYNCED",
    clock_offset_ns: int = 0,
    clock_uncertainty_ns: int = 1_000_000,
    source_time_precision_ns: int = 1_000_000,
) -> ObservedBBO:
    source = BASE_UTC_NS + active_ns if source_event_ns is None else source_event_ns
    receive_utc = (
        source + 100_000_000 if receive_utc_ns is None else receive_utc_ns
    )
    receive_monotonic = (
        active_ns
        if receive_monotonic_ns is None
        else receive_monotonic_ns
    )
    return ObservedBBO(
        collector_generation=collector_generation,
        clock_epoch=clock_epoch,
        exact_contract="SHFE.rb2701",
        session_family=session_family,
        segment_id=segment_id,
        collector_seq=seq,
        source_event_ns=source,
        receive_utc_ns=receive_utc,
        receive_monotonic_ns=receive_monotonic,
        active_time_ns=active_ns,
        bid_price=bid_price,
        bid_size=bid_size,
        ask_price=ask_price,
        ask_size=ask_size,
        provider_update_id=provider_update_id or f"provider-{seq}",
        explicit_duplicate=explicit_duplicate,
        reset_reason=reset_reason,
        clock_sync_state=clock_sync_state,
        clock_offset_ns=clock_offset_ns,
        clock_uncertainty_ns=clock_uncertainty_ns,
        source_time_precision_ns=source_time_precision_ns,
    )


def control(
    seq: int,
    event_type: str,
    *,
    receive_monotonic_ns: int,
    collector_generation: str = "generation-1",
    clock_epoch: str = "clock-1",
) -> CollectorControl:
    return CollectorControl(
        collector_generation=collector_generation,
        clock_epoch=clock_epoch,
        collector_seq=seq,
        receive_utc_ns=BASE_UTC_NS + receive_monotonic_ns,
        receive_monotonic_ns=receive_monotonic_ns,
        event_type=event_type,
        reason=f"fixture-{event_type.lower()}",
    )


def test_csv_pnl_screen_requires_unique_session_date_mapping(tmp_path: Path) -> None:
    """The quick screen must not invent a date when no session overlaps."""
    registry = tmp_path / "registry.csv"
    registry.write_text(
        "segment_id,exact_contract_symbol,segment_start_utc,segment_end_utc,top1_download_complete\n"
        "s1,SHFE.cu2601,2026-01-01T01:00:00+00:00,2026-01-01T01:02:00+00:00,True\n"
    )
    plan = tmp_path / "plan.csv"
    plan.write_text(
        "exact_contract_symbol,session_id,session_name,window_start_utc,window_end_utc\n"
        "SHFE.cu2601,SHFE.cu:2026-01-01:day_1,day_1,2026-01-01T03:00:00+00:00,2026-01-01T03:01:00+00:00\n"
    )
    with pytest.raises(pnl_screen_module.ScreenInputError, match="0 session-date"):
        pnl_screen_module._session_map(plan, registry)


@pytest.mark.parametrize(("bid", "ask"), [("101", "100"), ("100", "100")])
def test_csv_pnl_screen_fail_closed_bbo_and_deterministic_json(
    tmp_path: Path, bid: str, ask: str
) -> None:
    """Invalid BBO is never repaired and canonical serialization is stable."""
    rows = tmp_path / "ticks.csv"
    rows.write_text(
        "segment_id,instrument,exchange,exact_contract_symbol,segment_start_utc,segment_end_utc,tick_timestamp_utc,bid_price1,bid_volume1,ask_price1,ask_volume1\n"
        f"s1,CU,SHFE,SHFE.cu2601,2026-01-01T01:00:00+00:00,2026-01-01T01:02:00+00:00,2026-01-01T01:00:00+00:00,{bid},1,{ask},1\n"
    )
    with pytest.raises(pnl_screen_module.ScreenInputError, match="invalid BBO"):
        pnl_screen_module._load_segments(
            str(rows), {"s1": ("2026-01-01", "DAY")}, {"CU"}
        )
    payload = {"b": ["x"], "a": {"z": 1}}
    first = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
    second = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
    assert first == second


def test_csv_pnl_screen_uses_first_five_session_dates_without_lookahead() -> None:
    calibration, evaluation = pnl_screen_module._session_date_split(
        [
            "2026-01-06",
            "2026-01-02",
            "2026-01-05",
            "2026-01-01",
            "2026-01-04",
            "2026-01-03",
            "2026-01-07",
        ]
    )
    assert calibration == {
        "2026-01-01",
        "2026-01-02",
        "2026-01-03",
        "2026-01-04",
        "2026-01-05",
    }
    assert evaluation == {"2026-01-06", "2026-01-07"}


def test_csv_pnl_screen_primary_and_stress_fill_are_adverse() -> None:
    signal = SignalDecision(
        exact_contract="SHFE.rb2701",
        session_family="DAY_1",
        segment_id="s",
        collector_generation="CSV_DIAGNOSTIC",
        clock_epoch="CSV_CLOCK",
        collector_seq=1,
        source_event_ns=BASE_UTC_NS,
        receive_monotonic_ns=0,
        active_time_ns=0,
        direction="LONG",
        score=Decimal("2"),
        threshold=Decimal("1"),
    )
    rows = (
        replace(
            observation(
                1,
                active_ns=0,
                collector_generation="CSV_DIAGNOSTIC",
                clock_epoch="CSV_CLOCK",
                session_family="DAY_1",
                segment_id="s",
            ),
            exact_contract="SHFE.rb2701",
        ),
        replace(
            observation(
                2,
                active_ns=SECOND,
                bid_price="100",
                ask_price="101",
                collector_generation="CSV_DIAGNOSTIC",
                clock_epoch="CSV_CLOCK",
                session_family="DAY_1",
                segment_id="s",
            ),
            exact_contract="SHFE.rb2701",
        ),
        replace(
            observation(
                3,
                active_ns=31 * SECOND,
                bid_price="103",
                ask_price="104",
                collector_generation="CSV_DIAGNOSTIC",
                clock_epoch="CSV_CLOCK",
                session_family="DAY_1",
                segment_id="s",
            ),
            exact_contract="SHFE.rb2701",
        ),
        replace(
            observation(
                4,
                active_ns=32 * SECOND,
                bid_price="103",
                ask_price="104",
                collector_generation="CSV_DIAGNOSTIC",
                clock_epoch="CSV_CLOCK",
                session_family="DAY_1",
                segment_id="s",
            ),
            exact_contract="SHFE.rb2701",
        ),
    )
    primary = pnl_screen_module._round_trip(signal, rows, 500_000_000, 0, Decimal("1"))
    stress = pnl_screen_module._round_trip(signal, rows, SECOND, 1, Decimal("1"))
    assert primary[:3] == ("BUY", Decimal("101"), Decimal("103"))
    assert stress[:3] == ("BUY", Decimal("102"), Decimal("102"))

    late_entry_rows = (
        rows[0],
        replace(rows[1], active_time_ns=7 * SECOND, receive_monotonic_ns=7 * SECOND),
        replace(rows[2], active_time_ns=37 * SECOND, receive_monotonic_ns=37 * SECOND),
        replace(rows[3], active_time_ns=38 * SECOND, receive_monotonic_ns=38 * SECOND),
    )
    late_entry = pnl_screen_module._round_trip(
        signal, late_entry_rows, 500_000_000, 0, Decimal("1")
    )
    assert late_entry is not None
    assert late_entry[-1] is False

    timeout_rows = (
        rows[0],
        rows[1],
        replace(rows[2], active_time_ns=37 * SECOND, receive_monotonic_ns=37 * SECOND),
    )
    timed_out = pnl_screen_module._round_trip(
        signal, timeout_rows, 500_000_000, 0, Decimal("1")
    )
    assert timed_out is not None
    assert timed_out[-1] is True


def test_csv_pnl_screen_rounds_each_fee_leg_and_removes_whole_session_dates() -> None:
    entry_fee = pnl_screen_module._leg_fee(
        Decimal("100"), Decimal("1"), Decimal("0.00005"), Decimal(0)
    )
    exit_fee = pnl_screen_module._leg_fee(
        Decimal("100"), Decimal("1"), Decimal("0.00005"), Decimal(0)
    )
    assert entry_fee + exit_fee == Decimal("0.02")

    rows = [
        {"official_day": "2026-01-01", "net": Decimal("5")},
        {"official_day": "2026-01-01", "net": Decimal("5")},
        {"official_day": "2026-01-02", "net": Decimal("9")},
        {"official_day": "2026-01-03", "net": Decimal("8")},
        {"official_day": "2026-01-04", "net": Decimal("7")},
    ]
    retained, removed = pnl_screen_module._remove_best_three_session_dates(rows)
    assert removed == ["2026-01-01", "2026-01-02", "2026-01-03"]
    assert retained == [{"official_day": "2026-01-04", "net": Decimal("7")}]


def test_csv_pnl_screen_rejects_overlapping_exact_contract_segments() -> None:
    first_rows = (
        replace(observation(1, active_ns=0), exact_contract="SHFE.cu2601"),
        replace(observation(2, active_ns=2 * SECOND), exact_contract="SHFE.cu2601"),
    )
    second_rows = (
        replace(observation(1, active_ns=SECOND), exact_contract="SHFE.cu2601"),
        replace(observation(2, active_ns=3 * SECOND), exact_contract="SHFE.cu2601"),
    )
    segments = (
        pnl_screen_module.Segment(
            "s1", "CU", "SHFE.cu2601", "2026-01-01", "DAY_1", first_rows
        ),
        pnl_screen_module.Segment(
            "s2", "CU", "SHFE.cu2601", "2026-01-01", "DAY_1", second_rows
        ),
    )
    with pytest.raises(pnl_screen_module.ScreenInputError, match="overlapping"):
        pnl_screen_module._require_nonoverlapping_segments(segments)



def custody_record(
    record_type: str = "QUOTE", *, seq: int = 1, generation: str = "generation-1"
) -> dict[str, object]:
    row: dict[str, object] = {
        "record_type": record_type,
        "collector_generation": generation,
        "collector_seq": seq,
        "clock_epoch": "clock-1",
        "segment_id": "day-am-1",
        "provider_delivery_semantics": "CALLBACK",
        "provider_batch_id": None,
        "within_batch_rank": 1,
        "provider_update_id": None,
        "provider_update_id_semantics": "UNVERIFIED",
        "source_event_time_raw": "2030-01-01T00:00:00.000000000Z",
        "source_event_utc_ns": BASE_UTC_NS,
        "source_time_precision_ns": 1_000_000,
        "callback_entry_receive_utc_ns": BASE_UTC_NS + 100_000_000,
        "callback_entry_receive_monotonic_ns": 1,
        "clock_sample_id": "clock-sample-1",
        "clock_sync_state": "SYNCED",
        "clock_offset_ns": 0,
        "clock_uncertainty_ns": 1_000_000,
        "product": "rb",
        "exact_contract": "SHFE.rb2701",
        "exchange": "SHFE",
        "official_trading_day": "2030-01-01",
        "session_family": "DAY",
    }
    if record_type == "QUOTE":
        row.update(
            bid_price1_raw="100", bid_size1_raw="10", ask_price1_raw="102",
            ask_size1_raw="12", last_price_raw="101", cumulative_volume_raw="1",
            cumulative_amount_raw="101", open_interest_raw="1000",
            parse_status="RAW_RETAINED", duplicate_status="NOT_CLASSIFIED",
            source_status="OBSERVED",
        )
    else:
        row.update(
            event_type="COLLECTOR_START",
            reason="fixture",
            scope="GENERATION_GLOBAL",
        )
    return row


def custody_journal(root: Path, **kwargs: object) -> CustodyJournal:
    return CustodyJournal(root, code_sha=CODE_SHA, **kwargs)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"bid_size": "13"}, "3"),
        ({"bid_size": "7"}, "-3"),
        ({"bid_price": "101", "bid_size": "8"}, "8"),
        ({"bid_price": "99", "bid_size": "8"}, "-10"),
        ({"ask_size": "15"}, "-3"),
        ({"ask_size": "9"}, "3"),
        ({"ask_price": "101", "ask_size": "8"}, "-8"),
        ({"ask_price": "103", "ask_size": "8"}, "12"),
    ],
)
def test_frozen_bbo_change_formula_covers_price_and_size_cases(
    changes: dict[str, str], expected: str
) -> None:
    previous = observation(1)
    current = observation(2, active_ns=SECOND, **changes)

    assert bbo_change_contribution(previous, current) == Decimal(expected)


def test_formula_adds_simultaneous_bid_up_and_ask_down() -> None:
    previous = observation(1)
    current = observation(
        2,
        active_ns=SECOND,
        bid_price="101",
        bid_size="8",
        ask_price="101.5",
        ask_size="7",
    )

    assert bbo_change_contribution(previous, current) == Decimal("1")


def test_same_source_timestamp_callbacks_are_not_timestamp_deduped() -> None:
    engine = BBOChangeEngine()
    baseline = observation(1, source_event_ns=BASE_UTC_NS)
    changed = observation(
        2,
        active_ns=SECOND,
        source_event_ns=BASE_UTC_NS,
        bid_size="11",
    )
    same_bbo_new_callback = observation(
        3,
        active_ns=SECOND,
        source_event_ns=BASE_UTC_NS,
        bid_size="11",
    )

    assert engine.process(baseline).status == "BASELINE_RESET"
    first = engine.process(changed)
    second = engine.process(same_bbo_new_callback)

    assert first.contribution == Decimal("1")
    assert second.contribution == Decimal("0")
    assert second.window_terms == 2


def test_only_explicit_adjacent_provider_duplicate_is_skipped() -> None:
    engine = BBOChangeEngine()
    baseline = observation(1)
    changed = observation(2, active_ns=SECOND, bid_size="11")
    duplicate = replace(
        changed,
        collector_seq=3,
        receive_utc_ns=changed.receive_utc_ns + 1,
        receive_monotonic_ns=changed.receive_monotonic_ns + 1,
        explicit_duplicate=True,
    )

    engine.process(baseline)
    changed_result = engine.process(changed)
    duplicate_result = engine.process(duplicate)

    assert changed_result.window_terms == 1
    assert duplicate_result.status == "EXPLICIT_DUPLICATE_SKIPPED"

    with pytest.raises(BBOChangeContractError, match="explicit duplicate"):
        engine.process(
            replace(
                duplicate,
                collector_seq=4,
                bid_size="12",
            )
        )


def test_collector_sequence_gap_fails_closed() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))

    with pytest.raises(BBOChangeContractError, match="expected 2"):
        engine.process(observation(3, active_ns=SECOND))

    with pytest.raises(BBOChangeContractError, match="generation is aborted"):
        engine.process(observation(2, active_ns=SECOND))


def test_control_records_share_global_sequence_and_reset_feature_state() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))
    engine.process(observation(2, active_ns=SECOND, bid_size="11"))

    lifecycle = engine.process_control(
        control(3, "DISCONNECT", receive_monotonic_ns=2 * SECOND)
    )
    after = engine.process(observation(4, active_ns=3 * SECOND))

    assert lifecycle.status == "STATE_RESET"
    assert after.status == "BASELINE_ONLY"
    assert after.score is None


def test_backpressure_control_aborts_until_a_new_generation_starts() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))
    aborted = engine.process_control(
        control(2, "BACKPRESSURE_ABORT", receive_monotonic_ns=SECOND)
    )

    assert aborted.status == "GENERATION_ABORTED"
    with pytest.raises(BBOChangeContractError, match="generation is aborted"):
        engine.process(observation(3, active_ns=2 * SECOND))

    started = engine.process_control(
        control(
            1,
            "COLLECTOR_START",
            receive_monotonic_ns=0,
            collector_generation="generation-2",
            clock_epoch="clock-2",
        )
    )
    assert started.status == "STATE_RESET"


def test_clock_epoch_control_keeps_sequence_but_resets_state() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))
    epoch = engine.process_control(
        control(
            2,
            "CLOCK_EPOCH_CHANGE",
            receive_monotonic_ns=0,
            clock_epoch="clock-2",
        )
    )
    after = engine.process(
        observation(
            3,
            active_ns=0,
            receive_monotonic_ns=0,
            clock_epoch="clock-2",
        )
    )

    assert epoch.status == "STATE_RESET"
    assert after.status == "BASELINE_ONLY"


def test_invalid_raw_bbo_is_retained_as_a_reset_result() -> None:
    engine = BBOChangeEngine()

    result = engine.process(observation(1, bid_price="nan"))

    assert result.status == "INVALID_BBO_RESET"
    assert result.reset_reason == "INVALID_BBO"


def test_reconnect_resets_baseline_and_window() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))
    engine.process(observation(2, active_ns=SECOND, bid_size="11"))

    reset = engine.process(
        observation(
            3,
            active_ns=2 * SECOND,
            bid_size="12",
            reset_reason="RECONNECT",
        )
    )
    after = engine.process(
        observation(4, active_ns=3 * SECOND, bid_size="13")
    )

    assert reset.status == "BASELINE_RESET"
    assert reset.reset_reason == "RECONNECT"
    assert after.contribution == Decimal("1")
    assert after.window_terms == 1
    assert after.score is None


def test_new_generation_and_clock_epoch_cannot_carry_feature_state() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))
    engine.process(observation(2, active_ns=SECOND, bid_size="11"))

    with pytest.raises(BBOChangeContractError, match="must begin"):
        engine.process(
            observation(
                2,
                collector_generation="generation-2",
                clock_epoch="clock-2",
            )
        )

    generation_reset = engine.process(
        observation(
            1,
            collector_generation="generation-2",
            clock_epoch="clock-2",
        )
    )
    epoch_reset = engine.process(
        observation(
            2,
            active_ns=SECOND,
            collector_generation="generation-2",
            clock_epoch="clock-3",
            bid_size="11",
        )
    )

    assert generation_reset.reset_reason == "COLLECTOR_GENERATION"
    assert epoch_reset.reset_reason == "CLOCK_EPOCH"
    assert epoch_reset.score is None


def test_source_time_regression_resets_instead_of_reordering() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1, source_event_ns=BASE_UTC_NS + SECOND))

    result = engine.process(
        observation(
            2,
            active_ns=SECOND,
            source_event_ns=BASE_UTC_NS,
        )
    )

    assert result.status == "SOURCE_TIME_REGRESSION_RESET"
    assert result.score is None


def test_window_is_open_left_closed_right_and_keeps_zero_terms() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))
    at_ten = None
    at_eleven = None
    for second in range(1, 12):
        result = engine.process(
            observation(
                second + 1,
                active_ns=second * SECOND,
                bid_size="11",
            )
        )
        if second == 10:
            at_ten = result
        if second == 11:
            at_eleven = result

    assert at_ten is not None and at_ten.status == "SCORE_READY"
    assert at_ten.raw_imbalance == Decimal("1")
    assert at_ten.window_terms == 10
    assert at_eleven is not None and at_eleven.status == "SCORE_READY"
    assert at_eleven.raw_imbalance == Decimal("0")
    assert at_eleven.window_terms == 10


def test_window_drops_before_and_at_left_edge_but_keeps_one_ns_after() -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1, active_ns=100, receive_monotonic_ns=100))
    engine.process(
        observation(
            2,
            active_ns=101,
            receive_monotonic_ns=101,
            bid_size="11",
        )
    )
    engine.process(
        observation(
            3,
            active_ns=102,
            receive_monotonic_ns=102,
            bid_size="12",
        )
    )
    engine.process(
        observation(
            4,
            active_ns=103,
            receive_monotonic_ns=103,
            bid_size="13",
        )
    )

    result = engine.process(
        observation(
            5,
            active_ns=10 * SECOND + 102,
            receive_monotonic_ns=10 * SECOND + 102,
            bid_size="13",
        )
    )

    assert result.status == "SCORE_READY"
    assert result.raw_imbalance == Decimal("1")
    assert result.window_terms == 2


@pytest.mark.parametrize(
    ("gap_ns", "expected"),
    [
        (10 * SECOND - 1, "WARMING_UP"),
        (10 * SECOND, "LONG_GAP_RESET"),
        (10 * SECOND + 1, "LONG_GAP_RESET"),
    ],
)
def test_long_gap_boundary_is_frozen(gap_ns: int, expected: str) -> None:
    engine = BBOChangeEngine()
    engine.process(observation(1))

    result = engine.process(
        observation(2, active_ns=gap_ns, receive_monotonic_ns=gap_ns)
    )

    assert result.status == expected


def feature_point(seq: int, score: int) -> FeaturePoint:
    return FeaturePoint(
        exact_contract="SHFE.rb2701",
        session_family="DAY",
        segment_id="day-am-1",
        collector_generation="generation-1",
        clock_epoch="clock-1",
        collector_seq=seq,
        source_event_ns=BASE_UTC_NS + seq,
        receive_monotonic_ns=seq,
        active_time_ns=seq,
        status="SCORE_READY",
        score=Decimal(score),
    )


def test_feature_only_q95_is_nearest_rank_and_trigger_is_inclusive() -> None:
    points = [feature_point(index, index) for index in range(1, 1001)]

    thresholds = freeze_feature_only_thresholds(points)
    frozen = thresholds[("SHFE.rb2701", "DAY")]

    assert frozen.sample_count == 1000
    assert frozen.threshold == Decimal("950")
    assert signal_from_threshold(feature_point(1001, 949), thresholds) is None
    inclusive = signal_from_threshold(feature_point(1002, -950), thresholds)
    assert inclusive is not None
    assert inclusive.direction == "SHORT"


def test_feature_only_q95_rejects_underfilled_cell() -> None:
    with pytest.raises(BBOChangeContractError, match="insufficient"):
        freeze_feature_only_thresholds([feature_point(1, 1)])


def test_feature_only_q95_rejects_degenerate_zero_threshold() -> None:
    points = [feature_point(index, 0) for index in range(1, 1001)]

    with pytest.raises(BBOChangeContractError, match="degenerate"):
        freeze_feature_only_thresholds(points)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("quantile", "0.90"),
        ("sample_count", 999),
        ("threshold", "0"),
        ("threshold", "-0.1"),
    ],
)
def test_replay_freeze_rejects_non_candidate_thresholds_eagerly(
    field: str,
    value: object,
) -> None:
    row: dict[str, object] = {
        "exact_contract": "SHFE.rb2701",
        "session_family": "DAY",
        "quantile": "0.95",
        "sample_count": 1000,
        "threshold": "0.1",
    }
    row[field] = value

    with pytest.raises(
        BBOChangeContractError,
        match="threshold is not a frozen candidate Q95",
    ):
        bbo_change_module._freeze_thresholds({"thresholds": [row]})


def clock_observations(lag_ns: int) -> list[ObservedBBO]:
    values = []
    for index in range(1000):
        source = BASE_UTC_NS + index
        values.append(
            observation(
                index + 1,
                active_ns=index,
                source_event_ns=source,
                receive_utc_ns=source + lag_ns,
                receive_monotonic_ns=index,
            )
        )
    return values


def test_clock_gate_requires_measurement_quality_before_250ms_p99() -> None:
    passed = evaluate_clock_gate(clock_observations(200_000_000))
    failed_lag = evaluate_clock_gate(clock_observations(300_000_000))
    coarse = clock_observations(100_000_000)
    coarse[0] = replace(coarse[0], source_time_precision_ns=2_000_000)

    assert passed.passed is True
    assert passed.p99_lag_ns == 200_000_000
    assert failed_lag.passed is False
    assert failed_lag.reason == "P99_LAG_TOO_LARGE"
    assert evaluate_clock_gate(coarse).reason == "SOURCE_TIME_TOO_COARSE"


def signal() -> SignalDecision:
    return SignalDecision(
        exact_contract="SHFE.rb2701",
        session_family="DAY",
        segment_id="day-am-1",
        collector_generation="generation-1",
        clock_epoch="clock-1",
        collector_seq=100,
        source_event_ns=BASE_UTC_NS + 10 * SECOND,
        receive_monotonic_ns=10 * SECOND,
        active_time_ns=10 * SECOND,
        direction="LONG",
        score=Decimal("3"),
        threshold=Decimal("2"),
    )


def test_primary_replay_uses_first_quote_after_each_latency_cutoff() -> None:
    future = [
        observation(
            101,
            active_ns=10 * SECOND + 499_000_000,
            receive_monotonic_ns=10 * SECOND + 499_000_000,
            ask_price="101",
        ),
        observation(
            102,
            active_ns=10 * SECOND + 500_000_000,
            receive_monotonic_ns=10 * SECOND + 500_000_000,
            ask_price="102",
        ),
        observation(
            103,
            active_ns=19 * SECOND,
            receive_monotonic_ns=19 * SECOND,
        ),
        observation(
            104,
            active_ns=28 * SECOND,
            receive_monotonic_ns=28 * SECOND,
        ),
        observation(
            105,
            active_ns=37 * SECOND,
            receive_monotonic_ns=37 * SECOND,
        ),
        observation(
            106,
            active_ns=40 * SECOND + 500_000_000,
            receive_monotonic_ns=40 * SECOND + 500_000_000,
            bid_price="108",
            ask_price="110",
        ),
        observation(
            107,
            active_ns=40 * SECOND + 999_000_000,
            receive_monotonic_ns=40 * SECOND + 999_000_000,
            bid_price="110",
            ask_price="112",
        ),
        observation(
            108,
            active_ns=41 * SECOND,
            receive_monotonic_ns=41 * SECOND,
            bid_price="109",
            ask_price="111",
        ),
    ]

    replay = replay_primary_round_trip(signal(), future)

    assert replay.status == "COMPLETE"
    assert replay.entry is not None and replay.entry.price == Decimal("102")
    assert replay.exit is not None and replay.exit.price == Decimal("109")


def test_replay_fails_first_quote_with_insufficient_size_and_stops_at_epoch() -> None:
    below_one_lot = observation(
        101,
        active_ns=11 * SECOND,
        receive_monotonic_ns=11 * SECOND,
        ask_size="0.5",
    )
    restarted = observation(
        1,
        collector_generation="generation-2",
        clock_epoch="clock-2",
        active_ns=0,
        receive_monotonic_ns=0,
    )

    replay = replay_primary_round_trip(signal(), [below_one_lot])
    stopped = replay_primary_round_trip(signal(), [restarted])

    assert replay.status == "NO_ENTRY"
    assert replay.entry is None
    assert stopped.status == "NO_ENTRY"


def test_replay_does_not_cross_a_lifecycle_reset() -> None:
    reset = observation(
        101,
        active_ns=11 * SECOND,
        receive_monotonic_ns=11 * SECOND,
        reset_reason="RECONNECT",
    )
    later = observation(
        102,
        active_ns=12 * SECOND,
        receive_monotonic_ns=12 * SECOND,
    )

    replay = replay_primary_round_trip(signal(), [reset, later])

    assert replay.status == "NO_ENTRY"


@pytest.mark.parametrize(
    ("changes", "expected_status"),
    [
        ({"bid_price": "102"}, "NO_ENTRY"),
        ({"bid_size": "0"}, "NO_ENTRY"),
        ({"clock_sync_state": "UNSYNCED"}, "NO_ENTRY"),
    ],
)
def test_replay_never_crosses_invalid_or_untrusted_bbo(
    changes: dict[str, object], expected_status: str
) -> None:
    broken = observation(
        101,
        active_ns=10 * SECOND + 100_000_000,
        receive_monotonic_ns=10 * SECOND + 100_000_000,
        **changes,
    )
    later = observation(
        102,
        active_ns=11 * SECOND,
        receive_monotonic_ns=11 * SECOND,
    )

    replay = replay_primary_round_trip(signal(), [broken, later])

    assert replay.status == expected_status


def test_replay_requires_gapless_run_global_future_records() -> None:
    with pytest.raises(BBOChangeContractError, match="expected 101"):
        replay_primary_round_trip(
            signal(),
            [
                observation(
                    102,
                    active_ns=10 * SECOND + 500_000_000,
                    receive_monotonic_ns=10 * SECOND + 500_000_000,
                )
            ],
        )


def test_replay_long_gap_resets_before_entry_and_after_fill() -> None:
    before_entry = observation(
        101,
        active_ns=20 * SECOND,
        receive_monotonic_ns=20 * SECOND,
    )
    entry = observation(
        101,
        active_ns=10 * SECOND + 500_000_000,
        receive_monotonic_ns=10 * SECOND + 500_000_000,
    )
    after_entry_gap = observation(
        102,
        active_ns=20 * SECOND + 500_000_000,
        receive_monotonic_ns=20 * SECOND + 500_000_000,
    )

    no_entry = replay_primary_round_trip(signal(), [before_entry])
    no_exit = replay_primary_round_trip(signal(), [entry, after_entry_gap])

    assert no_entry.status == "NO_ENTRY"
    assert no_exit.status == "NO_EXIT"
    assert no_exit.entry is not None


def test_replay_source_time_regression_and_control_record_reset_lane() -> None:
    regressed = observation(
        101,
        active_ns=10 * SECOND + 100_000_000,
        receive_monotonic_ns=10 * SECOND + 100_000_000,
        source_event_ns=BASE_UTC_NS + 9 * SECOND,
    )
    disconnected = control(
        101,
        "DISCONNECT",
        receive_monotonic_ns=10 * SECOND + 100_000_000,
    )

    source_reset = replay_primary_round_trip(signal(), [regressed])
    control_reset = replay_primary_round_trip(signal(), [disconnected])

    assert source_reset.status == "NO_ENTRY"
    assert control_reset.status == "NO_ENTRY"


def test_signal_requires_the_frozen_contract_session_threshold() -> None:
    point = feature_point(1, 10)
    thresholds = {
        ("OTHER.contract", "DAY"): FrozenThreshold(
            exact_contract="OTHER.contract",
            session_family="DAY",
            quantile=Decimal("0.95"),
            sample_count=1000,
            threshold=Decimal("1"),
        )
    }

    assert signal_from_threshold(point, thresholds) is None


def test_custody_journal_is_canonical_durable_and_sealed(tmp_path: Path) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        quote = journal.append(custody_record(seq=1))
        lifecycle = journal.append(custody_record("CONTROL", seq=2))
        manifest = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
        assert quote["collector_seq"] == 1
        assert lifecycle["collector_seq"] == 2
        assert lifecycle["prev_record_hash"] == quote["record_hash"]
        assert manifest.exact_bytes == len((root / "p-1.jsonl").read_bytes())
        assert manifest.partition_hash
        with pytest.raises(BBOChangeContractError, match="sealed"):
            journal.append(custody_record(seq=3))

    root_pins = pin_custody_root(root)
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-2",
        collector_generation="generation-1",
        expected_root_pins=root_pins,
        expected_head_partition_hash=manifest.partition_hash,
        expected_head_seal_id=manifest.seal_id,
    ) as next_partition:
        row = next_partition.append(custody_record(seq=3))
        assert row["collector_seq"] == 3
        assert row["prev_record_hash"] == lifecycle["record_hash"]
        next_manifest = next_partition.seal(closed_at_utc="2030-01-01T00:00:02Z")
    assert next_manifest.previous_partition_hash == manifest.partition_hash


def test_custody_resume_rejects_tamper_and_partial_tail_by_quarantining(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as journal:
        journal.append(custody_record(seq=1))
    journal_path = root / "p-1.jsonl"
    root_pins = pin_custody_root(root)
    journal_path.write_bytes(journal_path.read_bytes() + b"{")

    with pytest.raises(BBOChangeContractError, match="partial trailing"):
        custody_journal(
            root, run_id="run-1", partition_id="p-1", collector_generation="generation-1",
            mode="resume", expected_root_pins=root_pins,
            expected_head_partition_hash=None, expected_head_seal_id=None,
        )
    assert (root / ".quarantine-generation-1.json").exists()
    with pytest.raises(BBOChangeContractError, match="quarantined"):
        custody_journal(
            root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
            expected_root_pins=root_pins,
            expected_head_partition_hash=None, expected_head_seal_id=None,
        )


def test_custody_requires_callback_sequence_locks_and_trusted_head(tmp_path: Path) -> None:
    root = tmp_path / "custody"
    journal = custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    )
    root_pins = pin_custody_root(root)
    try:
        with pytest.raises(BBOChangeContractError, match="callback-entry collector_seq"):
            journal.append(
                {
                    key: value
                    for key, value in custody_record(seq=1).items()
                    if key != "collector_seq"
                }
            )
        with pytest.raises(BBOChangeContractError, match="collector_seq must be an integer"):
            journal.append(custody_record(seq=True))
        with pytest.raises(BBOChangeContractError, match="inconsistent collector_seq"):
            journal.append(custody_record(seq=2))
        with pytest.raises(BBOChangeContractError, match="writer-owned"):
            journal.append(custody_record(seq=1) | {"run_id": "forbidden"})
        with pytest.raises(BBOChangeContractError, match="final partition fields"):
            journal.append(custody_record(seq=1) | {"seal_id": "forbidden"})
        with pytest.raises(BBOChangeContractError, match="already locked"):
            custody_journal(
                root, run_id="run-1", partition_id="p-1", collector_generation="generation-1",
                expected_root_pins=root_pins,
                expected_head_partition_hash=None, expected_head_seal_id=None,
            )
        journal.append(custody_record(seq=1))
        manifest = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    finally:
        journal.close()
    with pytest.raises(BBOChangeContractError, match="existing custody root requires"):
        custody_journal(
            root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
            expected_head_partition_hash=manifest.partition_hash,
            expected_head_seal_id=manifest.seal_id,
        )
    with pytest.raises(BBOChangeContractError, match="requires both trusted head anchors"):
        custody_journal(
            root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
            expected_root_pins=root_pins,
        )
    with pytest.raises(BBOChangeContractError, match="trusted custody head"):
        custody_journal(
            root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
            expected_root_pins=root_pins, expected_head_hash="0" * 64,
            expected_head_seal_id=manifest.seal_id,
        )
    with custody_journal(
        root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
        expected_root_pins=root_pins,
        expected_previous_partition_hash=manifest.partition_hash,
        expected_head_partition_hash=manifest.partition_hash,
        expected_head_seal_id=manifest.seal_id,
    ) as next_partition:
        assert next_partition.append(custody_record(seq=2))["collector_seq"] == 2

    tamper_root = tmp_path / "tamper"
    with custody_journal(
        tamper_root, run_id="run-2", partition_id="p-1", collector_generation="generation-1"
    ) as journal:
        journal.append(custody_record(seq=1))
        journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    payload = tamper_root / "p-1.jsonl"
    payload.write_bytes(payload.read_bytes().replace(b'"100"', b'"101"', 1))
    with pytest.raises(BBOChangeContractError, match="closed partition custody"):
        custody_journal(
            tamper_root, run_id="run-2", partition_id="p-2", collector_generation="generation-1",
            expected_root_pins=pin_custody_root(tamper_root),
            expected_head_partition_hash="0" * 64, expected_head_seal_id="0" * 64,
        )


def test_custody_rejects_symlink_and_root_replacement(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "symlink-root"
    os.symlink(target, link)
    with pytest.raises(BBOChangeContractError, match="real directory"):
        custody_journal(
            link,
            run_id="run-1",
            partition_id="p-1",
            collector_generation="generation-1",
        )

    root = tmp_path / "replacement"
    journal = custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    )
    moved = tmp_path / "replacement-old"
    root.rename(moved)
    root.mkdir()
    try:
        with pytest.raises(BBOChangeContractError, match="replaced"):
            journal.append(custody_record(seq=1))
    finally:
        journal.close()


def test_custody_external_head_anchor_detects_tail_manifest_deletion(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as first:
        first.append(custody_record(seq=1))
        first_manifest = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=first_manifest.partition_hash,
        expected_head_seal_id=first_manifest.seal_id,
    ) as second:
        second.append(custody_record(seq=2))
        second_manifest = second.seal(closed_at_utc="2030-01-01T00:00:02Z")
    (root / "p-2.closed.json").unlink()
    with pytest.raises(BBOChangeContractError, match="trusted custody head anchor"):
        custody_journal(
            root, run_id="run-1", partition_id="p-3", collector_generation="generation-1",
            expected_root_pins=pins,
            expected_head_partition_hash=second_manifest.partition_hash,
            expected_head_seal_id=second_manifest.seal_id,
        )


def test_custody_rejects_resealed_manifest_path_escape_and_filename_tamper(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as journal:
        journal.append(custody_record(seq=1))
        manifest = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    manifest_path = root / "p-1.closed.json"
    decoded = json.loads(manifest_path.read_text(encoding="utf-8"))
    decoded["path"] = "../escape.jsonl"
    core = dict(decoded)
    core.pop("seal_id")
    decoded["seal_id"] = bbo_change_module._sha256(
        bbo_change_module._canonical_json_bytes(core)
    )
    manifest_path.write_bytes(bbo_change_module._canonical_json_bytes(decoded) + b"\n")
    with pytest.raises(BBOChangeContractError, match="closed partition custody"):
        custody_journal(
            root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
            expected_root_pins=pin_custody_root(root),
            expected_head_partition_hash=manifest.partition_hash,
            expected_head_seal_id=manifest.seal_id,
        )


def test_custody_resumes_complete_tail_and_detects_current_partition_deletion(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        first = journal.append(custody_record(seq=1))
    pins = pin_custody_root(root)
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
        mode="resume",
        expected_root_pins=pins,
        expected_head_partition_hash=None,
        expected_head_seal_id=None,
    ) as resumed:
        second = resumed.append(custody_record(seq=2))
        assert second["prev_record_hash"] == first["record_hash"]
        (root / "p-1.jsonl").unlink()
        with pytest.raises(BBOChangeContractError, match="changed externally"):
            resumed.verify()
    assert (root / ".quarantine-generation-1.json").exists()


def test_custody_refuses_append_after_open_current_data_is_unlinked(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as journal:
        journal.append(custody_record(seq=1))
        (root / "p-1.jsonl").unlink()
        with pytest.raises(BBOChangeContractError, match="changed externally"):
            journal.append(custody_record(seq=2))
    assert (root / ".quarantine-generation-1.json").exists()


def test_custody_refuses_append_after_open_terminal_manifest_is_deleted(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as first:
        first.append(custody_record(seq=1))
        terminal = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-2",
        collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=terminal.partition_hash,
        expected_head_seal_id=terminal.seal_id,
    ) as next_partition:
        (root / "p-1.closed.json").unlink()
        with pytest.raises(BBOChangeContractError, match="changed externally"):
            next_partition.append(custody_record(seq=2))
    assert (root / ".quarantine-generation-1.json").exists()


def test_custody_rechecks_replaced_lock_immediately_before_append_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as journal:
        original_assert = journal._assert_append_state
        calls = 0

        def replace_lock_before_final_check() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                (root / ".custody.lock").unlink()
                (root / ".custody.lock").write_bytes(b"")
            original_assert()

        monkeypatch.setattr(journal, "_assert_append_state", replace_lock_before_final_check)
        with pytest.raises(BBOChangeContractError, match="writer lock was replaced"):
            journal.append(custody_record(seq=1))
    assert (root / ".quarantine-generation-1.json").exists()


def test_custody_rejects_unexpected_extra_append_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "custody"
    original_write_all = bbo_change_module._write_all
    injected = False

    def write_then_inject_extra_byte(fd: int, data: bytes) -> None:
        nonlocal injected
        original_write_all(fd, data)
        if not injected:
            injected = True
            os.write(fd, b"X")

    monkeypatch.setattr(bbo_change_module, "_write_all", write_then_inject_extra_byte)
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as journal:
        with pytest.raises(BBOChangeContractError, match="append size changed unexpectedly"):
            journal.append(custody_record(seq=1))
    assert (root / ".quarantine-generation-1.json").exists()


@pytest.mark.parametrize("target", ["p-1.jsonl", "p-1.closed.json"])
def test_custody_rejects_nonterminal_closed_chain_tamper_before_append(
    tmp_path: Path, target: str
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as first:
        first.append(custody_record(seq=1))
        first_manifest = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-2",
        collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=first_manifest.partition_hash,
        expected_head_seal_id=first_manifest.seal_id,
    ) as second:
        second.append(custody_record(seq=2))
        second_manifest = second.seal(closed_at_utc="2030-01-01T00:00:02Z")
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-3",
        collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=second_manifest.partition_hash,
        expected_head_seal_id=second_manifest.seal_id,
    ) as third:
        victim = root / target
        if target.endswith(".jsonl"):
            victim.write_bytes(victim.read_bytes().replace(b'"100"', b'"101"', 1))
        else:
            victim.unlink()
        with pytest.raises(BBOChangeContractError, match="changed externally"):
            third.append(custody_record(seq=3))
        assert not (root / "p-3.jsonl").exists()
    assert (root / ".quarantine-generation-1.json").exists()


def test_custody_generation_identity_cannot_reappear_after_transition(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as first:
        first.append(custody_record(seq=1))
        first_manifest = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-2",
        collector_generation="generation-2",
        expected_root_pins=pins,
        expected_head_partition_hash=first_manifest.partition_hash,
        expected_head_seal_id=first_manifest.seal_id,
    ) as second:
        second.append(custody_record(seq=1, generation="generation-2"))
        second_manifest = second.seal(closed_at_utc="2030-01-01T00:00:02Z")
    with pytest.raises(BBOChangeContractError, match="cannot reappear"):
        custody_journal(
            root,
            run_id="run-1",
            partition_id="p-3",
            collector_generation="generation-1",
            expected_root_pins=pins,
            expected_head_partition_hash=second_manifest.partition_hash,
            expected_head_seal_id=second_manifest.seal_id,
        )


def test_custody_requires_normalized_root_and_real_code_sha(tmp_path: Path) -> None:
    with pytest.raises(BBOChangeContractError, match="absolute and normalized"):
        CustodyJournal(
            Path("relative-custody"),
            run_id="run-1",
            partition_id="p-1",
            collector_generation="generation-1",
            code_sha=CODE_SHA,
        )
    with pytest.raises(BBOChangeContractError, match="code_sha"):
        CustodyJournal(
            tmp_path / "custody",
            run_id="run-1",
            partition_id="p-1",
            collector_generation="generation-1",
            code_sha="UNSPECIFIED",
        )


def test_custody_durable_io_failure_poisons_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    journal = custody_journal(
        tmp_path / "custody",
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    )

    def fail_fsync(_: int) -> None:
        raise OSError("fixture fsync failure")

    monkeypatch.setattr(bbo_change_module.os, "fsync", fail_fsync)
    try:
        with pytest.raises(OSError, match="fixture fsync failure"):
            journal.append(custody_record(seq=1))
        with pytest.raises(BBOChangeContractError, match="poisoned"):
            journal.append(custody_record(seq=1))
    finally:
        journal.close()


def test_custody_rejects_skipping_unsealed_partition_but_allows_its_resume(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as first:
        first.append(custody_record(seq=1))
        head = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=head.partition_hash,
        expected_head_seal_id=head.seal_id,
    ) as interrupted:
        interrupted.append(custody_record(seq=2))
    with pytest.raises(BBOChangeContractError, match="must be explicitly resumed"):
        custody_journal(
            root, run_id="run-1", partition_id="p-3", collector_generation="generation-2",
            expected_root_pins=pins,
            expected_head_partition_hash=head.partition_hash,
            expected_head_seal_id=head.seal_id,
        )
    with custody_journal(
        root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
        mode="resume", expected_root_pins=pins,
        expected_head_partition_hash=head.partition_hash,
        expected_head_seal_id=head.seal_id,
    ) as resumed:
        assert resumed.append(custody_record(seq=3))["collector_seq"] == 3


def test_custody_rechecks_closed_chain_after_write_before_returning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as first:
        first.append(custody_record(seq=1))
        first_head = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=first_head.partition_hash,
        expected_head_seal_id=first_head.seal_id,
    ) as second:
        second.append(custody_record(seq=2))
        second_head = second.seal(closed_at_utc="2030-01-01T00:00:02Z")
    original_write_all = bbo_change_module._write_all
    mutated = False

    def write_then_tamper_nonterminal(fd: int, data: bytes) -> None:
        nonlocal mutated
        original_write_all(fd, data)
        if not mutated:
            mutated = True
            p1_data = root / "p-1.jsonl"
            p1_data.write_bytes(p1_data.read_bytes().replace(b'"100"', b'"101"', 1))

    monkeypatch.setattr(bbo_change_module, "_write_all", write_then_tamper_nonterminal)
    with custody_journal(
        root, run_id="run-1", partition_id="p-3", collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=second_head.partition_hash,
        expected_head_seal_id=second_head.seal_id,
    ) as third:
        with pytest.raises(BBOChangeContractError, match="changed externally"):
            third.append(custody_record(seq=3))
    assert (root / ".quarantine-generation-1.json").exists()


def test_custody_rechecks_old_chain_after_manifest_publish_before_repinning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root, run_id="run-1", partition_id="p-1", collector_generation="generation-1"
    ) as first:
        first.append(custody_record(seq=1))
        head = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root, run_id="run-1", partition_id="p-2", collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=head.partition_hash,
        expected_head_seal_id=head.seal_id,
    ) as second:
        second.append(custody_record(seq=2))
        original_write_exclusive = second._write_exclusive
        mutated = False

        def publish_then_tamper_old_partition(name: str, data: bytes) -> None:
            nonlocal mutated
            original_write_exclusive(name, data)
            if name.endswith(".closed.json") and not mutated:
                mutated = True
                p1_data = root / "p-1.jsonl"
                p1_data.write_bytes(p1_data.read_bytes().replace(b'"100"', b'"101"', 1))

        monkeypatch.setattr(second, "_write_exclusive", publish_then_tamper_old_partition)
        with pytest.raises(BBOChangeContractError, match="changed externally"):
            second.seal(closed_at_utc="2030-01-01T00:00:02Z")
    assert (root / ".quarantine-generation-1.json").exists()


def test_offline_kernel_has_no_runtime_network_or_broker_imports() -> None:
    module_path = ROOT / "scripts/collector_ordered_l1_bbo_change_v1.py"
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    forbidden = {
        "asyncio",
        "http",
        "requests",
        "socket",
        "urllib",
        "vnpy",
        "websocket",
        "zmq",
    }
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(
                alias.name.split(".", 1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint(forbidden)


def test_custody_imports_but_fails_closed_without_posix_capabilities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(bbo_change_module.os, "name", "nt")
    with pytest.raises(BBOChangeContractError, match="explicit POSIX"):
        bbo_change_module.CustodyJournal(
            tmp_path / "custody",
            run_id="run-1",
            partition_id="p-1",
            collector_generation="generation-1",
            code_sha=CODE_SHA,
        )


def test_exact_contract_segment_control_resets_only_its_lane() -> None:
    engine = BBOChangeEngine()
    rb = observation(1, receive_monotonic_ns=1)
    iron = replace(
        observation(2, active_ns=2, receive_monotonic_ns=2),
        exact_contract="DCE.i2701",
        bid_price="700",
        ask_price="701",
    )
    engine.process(rb)
    assert engine.process(iron).status == "BASELINE_ONLY"

    point = engine.process_control(
        CollectorControl(
            collector_generation="generation-1",
            clock_epoch="clock-1",
            collector_seq=3,
            receive_utc_ns=BASE_UTC_NS + 3,
            receive_monotonic_ns=3,
            event_type="SESSION_SEGMENT_END",
            reason="scheduled-boundary",
            scope="EXACT_CONTRACT_SEGMENT",
            exact_contract="SHFE.rb2701",
            session_family="DAY",
            segment_id="day-am-1",
            official_trading_day="2030-01-01",
        )
    )
    retained = engine.process(
        replace(
            iron,
            collector_seq=4,
            source_event_ns=iron.source_event_ns + 2,
            receive_utc_ns=iron.receive_utc_ns + 2,
            receive_monotonic_ns=4,
            active_time_ns=4,
            bid_size="11",
            provider_update_id="provider-4",
        )
    )

    assert point.status == "LANE_RESET"
    assert retained.status == "WARMING_UP"


def test_read_only_custody_reader_requires_external_terminal_anchors(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        written = journal.append(custody_record(seq=1))
        head = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    before = {
        path.name: path.read_bytes()
        for path in root.iterdir()
        if path.is_file()
    }

    stream = read_verified_custody_stream_v1(
        root,
        expected_root_pins=pins,
        trusted_head_partition_hash=head.partition_hash,
        trusted_head_seal_id=head.seal_id,
    )

    assert stream.terminal_partition_hash == head.partition_hash
    assert stream.terminal_seal_id == head.seal_id
    assert stream.rows == (written,)
    assert {
        path.name: path.read_bytes()
        for path in root.iterdir()
        if path.is_file()
    } == before
    with pytest.raises(BBOChangeContractError, match="terminal anchor"):
        read_verified_custody_stream_v1(
            root,
            expected_root_pins=pins,
            trusted_head_partition_hash="0" * 64,
            trusted_head_seal_id=head.seal_id,
        )


def test_read_only_custody_reader_rejects_an_unsealed_orphan_tail(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        journal.append(custody_record(seq=1))
        head = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    (root / "p-orphan.jsonl").write_text("{}\n", encoding="utf-8")
    os.chmod(root / "p-orphan.jsonl", 0o600)

    with pytest.raises(BBOChangeContractError, match="orphan or unsealed"):
        read_verified_custody_stream_v1(
            root,
            expected_root_pins=pins,
            trusted_head_partition_hash=head.partition_hash,
            trusted_head_seal_id=head.seal_id,
        )


def test_read_only_manifest_identity_names_must_be_canonical(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        journal.append(custody_record(seq=1))
        head = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")

    with pytest.raises(BBOChangeContractError, match="not canonical"):
        bbo_change_module._validate_sealed_manifest_v1(
            replace(head, run_id=" run-1")
        )


def test_read_only_custody_reader_requires_empty_writer_lock(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        journal.append(custody_record(seq=1))
        head = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    (root / ".custody.lock").write_bytes(b"unexpected")

    with pytest.raises(BBOChangeContractError, match="size is invalid"):
        read_verified_custody_stream_v1(
            root,
            expected_root_pins=pins,
            trusted_head_partition_hash=head.partition_hash,
            trusted_head_seal_id=head.seal_id,
        )


def test_read_only_custody_reader_bounds_data_before_reading(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        journal.append(custody_record(seq=1))
        head = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    partition = root / "p-1.jsonl"
    partition.write_bytes(partition.read_bytes() + b"x")

    with pytest.raises(BBOChangeContractError, match="size is invalid"):
        read_verified_custody_stream_v1(
            root,
            expected_root_pins=pins,
            trusted_head_partition_hash=head.partition_hash,
            trusted_head_seal_id=head.seal_id,
        )


def test_read_only_custody_reader_caps_manifest_before_reading(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        journal.append(custody_record(seq=1))
        head = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    manifest = root / "p-1.closed.json"
    with manifest.open("r+b") as handle:
        handle.truncate(bbo_change_module._MAX_CUSTODY_MANIFEST_BYTES + 1)

    with pytest.raises(BBOChangeContractError, match="exceeds its read bound"):
        read_verified_custody_stream_v1(
            root,
            expected_root_pins=pins,
            trusted_head_partition_hash=head.partition_hash,
            trusted_head_seal_id=head.seal_id,
        )


def test_replay_reverifies_public_stream_bytes_and_rows_before_freeze(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as journal:
        journal.append(custody_record(seq=1))
        head = journal.seal(closed_at_utc="2030-01-01T00:00:01Z")
    stream = read_verified_custody_stream_v1(
        root,
        expected_root_pins=pin_custody_root(root),
        trusted_head_partition_hash=head.partition_hash,
        trusted_head_seal_id=head.seal_id,
    )
    with pytest.raises(TypeError):
        stream.rows[0]["bid_price1_raw"] = "999"  # type: ignore[index]
    forged_rows = [dict(stream.rows[0])]
    forged_rows[0]["bid_price1_raw"] = "999"
    forged = VerifiedCustodyStream(
        stream.root_pins,
        stream.terminal_partition_hash,
        stream.terminal_seal_id,
        stream.partitions,
        tuple(forged_rows),
    )

    with pytest.raises(BBOChangeContractError, match="forged"):
        replay_multi_signal_raw_v1(
            forged,
            {},
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256="0" * 64,
        )


def test_terminal_seal_recursively_binds_prior_manifest_metadata(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
    ) as first:
        first.append(custody_record(seq=1))
        first_head = first.seal(closed_at_utc="2030-01-01T00:00:01Z")
    pins = pin_custody_root(root)
    with custody_journal(
        root,
        run_id="run-1",
        partition_id="p-2",
        collector_generation="generation-1",
        expected_root_pins=pins,
        expected_head_partition_hash=first_head.partition_hash,
        expected_head_seal_id=first_head.seal_id,
    ) as second:
        second.append(custody_record(seq=2))
        terminal = second.seal(closed_at_utc="2030-01-01T00:00:02Z")
    prior_manifest = root / "p-1.closed.json"
    decoded = json.loads(prior_manifest.read_text(encoding="utf-8"))
    decoded["closed_at_utc"] = "2030-01-01T00:00:09Z"
    core = dict(decoded)
    core.pop("seal_id")
    decoded["seal_id"] = bbo_change_module._sha256(
        bbo_change_module._canonical_json_bytes(core)
    )
    prior_manifest.write_bytes(
        bbo_change_module._canonical_json_bytes(decoded) + b"\n"
    )

    with pytest.raises(BBOChangeContractError, match="partition commitment"):
        read_verified_custody_stream_v1(
            root,
            expected_root_pins=pins,
            trusted_head_partition_hash=terminal.partition_hash,
            trusted_head_seal_id=terminal.seal_id,
        )
