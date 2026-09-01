from __future__ import annotations

import ast
import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from collector_ordered_l1_bbo_change_v1 import (  # noqa: E402
    BBOChangeContractError,
    BBOChangeEngine,
    CollectorControl,
    FeaturePoint,
    FrozenThreshold,
    ObservedBBO,
    SignalDecision,
    bbo_change_contribution,
    evaluate_clock_gate,
    freeze_feature_only_thresholds,
    replay_primary_round_trip,
    signal_from_threshold,
)


SECOND = 1_000_000_000
BASE_UTC_NS = 1_800_000_000 * SECOND


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
