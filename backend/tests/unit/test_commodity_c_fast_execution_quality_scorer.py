from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityContractSpecDTO,
    CFastExecutionQualityScoreDTO,
    CFastL1L5BookSnapshotDTO,
)
from app.services.commodity_c_fast_execution_quality_scorer import (
    CFastExecutionQualityScorerError,
    execution_quality_score_hash,
    reload_and_verify_execution_quality_score,
    score_execution_quality,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


ROOT = Path(__file__).resolve().parents[3]
POLICY_TEST_PATH = (
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py"
)
SPEC = importlib.util.spec_from_file_location(
    "execution_quality_scorer_policy_helpers",
    POLICY_TEST_PATH,
)
assert SPEC is not None and SPEC.loader is not None
POLICY_HELPERS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = POLICY_HELPERS
SPEC.loader.exec_module(POLICY_HELPERS)

ANCHOR = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)


def policy():
    return POLICY_HELPERS._signed_chain()[2].policy


def intent(*, lots: int = 5, direction: str = "buy") -> CFastVirtualIntentDTO:
    signed_delta = lots if direction == "buy" else -lots
    policy_hash = policy().foundation_policy_hash
    leg_core = {
        "schema_version": "commodity_c_fast_virtual_leg_v1",
        "snapshot_id": "c-fast-score-snapshot-v1",
        "snapshot_hash": "b" * 64,
        "formula_target_binding_sha256": "c" * 64,
        "policy_hash": policy_hash,
        "product": "cu",
        "phase": "virtual_open",
        "position_effect": "establish_target",
        "exact_contract": "SHFE.cu2612",
        "signed_quantity_delta": signed_delta,
        "leg_sequence": 1,
    }
    core = {
        "schema_version": "commodity_c_fast_virtual_intent_v1",
        "leg_id": f"cfast-virtual-leg-v1-{sha256_json(leg_core)}",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_id": "c-fast-score-snapshot-v1",
        "snapshot_hash": "b" * 64,
        "formula_target_binding_sha256": "c" * 64,
        "policy_hash": policy_hash,
        "product": "cu",
        "phase": "virtual_open",
        "position_effect": "establish_target",
        "exact_contract": "SHFE.cu2612",
        "direction": direction,
        "leg_sequence": 1,
        "intent_sequence": 1,
        "child_index": 1,
        "child_count": 1,
        "leg_signed_quantity_delta": signed_delta,
        "signed_quantity_delta": signed_delta,
        "lots": lots,
        "decision_timestamp_state": "NOT_CAPTURED_FOUNDATION_ONLY",
        "quote_snapshot_state": "NOT_CAPTURED_FOUNDATION_ONLY",
        "virtual_only": True,
        "collection_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }
    return CFastVirtualIntentDTO.model_validate(
        {
            **core,
            "intent_id": (
                f"cfast-virtual-intent-v1-{sha256_json(core)}"
            ),
        }
    )


def contract_spec(
    *,
    volume_lots_per_raw_unit: str | None = "1",
) -> CFastExecutionQualityContractSpecDTO:
    core = {
        "schema_version": (
            "commodity_c_fast_execution_quality_contract_spec_v1"
        ),
        "exact_contract": "SHFE.cu2612",
        "price_tick": "1",
        "multiplier": 10,
        "volume_lots_per_raw_unit": volume_lots_per_raw_unit,
        "binding_state": (
            "CALLER_MUST_BIND_TO_ACCEPTED_SIGNED_SNAPSHOT_CONTRACT_SPEC"
        ),
    }
    return CFastExecutionQualityContractSpecDTO.model_validate(
        {**core, "contract_spec_hash": sha256_json(core)}
    )


def book(
    offset_ms: int,
    *,
    ingest_seq: int | None = None,
    ingest_id: str | None = None,
    exchange_offset_ms: int = -100,
    bid_prices: list[str | None] | None = None,
    ask_prices: list[str | None] | None = None,
    bid_sizes: list[int | None] | None = None,
    ask_sizes: list[int | None] | None = None,
    cumulative_volume: str | None = "100",
    shift_ticks: int = 0,
) -> CFastL1L5BookSnapshotDTO:
    received = ANCHOR + timedelta(milliseconds=offset_ms)
    exchange = received + timedelta(milliseconds=exchange_offset_ms)
    sequence = ingest_seq if ingest_seq is not None else offset_ms + 1
    core = {
        "schema_version": "commodity_c_fast_l1_l5_book_snapshot_v1",
        "exact_contract": "SHFE.cu2612",
        "exchange_timestamp": exchange.isoformat().replace("+00:00", "Z"),
        "received_at_utc": received.isoformat().replace("+00:00", "Z"),
        "ingest_seq": sequence,
        "ingest_id": ingest_id or f"tick-{offset_ms}-{sequence}",
        "cumulative_volume": cumulative_volume,
        "bid_prices": bid_prices
        or [str(value + shift_ticks) for value in (1_000, 999, 998, 997, 996)],
        "ask_prices": ask_prices
        or [str(value + shift_ticks) for value in (1_002, 1_003, 1_004, 1_005, 1_006)],
        "bid_sizes": bid_sizes or [2, 2, 2, 2, 2],
        "ask_sizes": ask_sizes or [2, 2, 2, 2, 2],
    }
    return CFastL1L5BookSnapshotDTO.model_validate(
        {**core, "book_snapshot_hash": sha256_json(core)}
    )


def score(
    snapshots: list[CFastL1L5BookSnapshotDTO],
    *,
    virtual_intent: CFastVirtualIntentDTO | None = None,
    spec: CFastExecutionQualityContractSpecDTO | None = None,
):
    frozen_policy = policy()
    return score_execution_quality(
        intent=virtual_intent or intent(),
        durably_created_at_utc=ANCHOR,
        policy=frozen_policy,
        policy_hash=sha256_json(frozen_policy.model_dump(mode="json")),
        contract_spec=spec or contract_spec(),
        snapshots=snapshots,
    )


def full_horizon_books() -> list[CFastL1L5BookSnapshotDTO]:
    return [
        book(0, cumulative_volume="100"),
        book(250, cumulative_volume="101", shift_ticks=1),
        book(1_000, cumulative_volume="103", shift_ticks=2),
        book(5_000, cumulative_volume="106", shift_ticks=3),
        book(30_000, cumulative_volume="110", shift_ticks=4),
        book(60_000, cumulative_volume="115", shift_ticks=5),
    ]


def test_happy_path_scores_market_book_walk_markout_and_bounds() -> None:
    result = score(full_horizon_books())

    assert result.decision_tick is not None
    assert result.decision_tick.quality_state == "L5_USABLE"
    assert result.decision_metrics is not None
    assert result.decision_metrics.metric_mask_state == "L5_METRICS"
    assert result.decision_metrics.spread_ticks == "2"
    assert result.decision_metrics.spread_cny_per_lot == "20"
    assert result.decision_metrics.microprice_ticks == "1001"
    assert result.decision_metrics.depth_imbalance == "0"
    assert result.decision_metrics.protected_price == "1003"
    assert result.decision_metrics.l1_coverage_ratio == "0.4"
    assert result.decision_metrics.l5_coverage_ratio == "1"
    assert result.decision_metrics.l5_vwap_price == "1002.8"
    assert result.decision_metrics.l5_adverse_ticks == "0.8"
    assert result.decision_metrics.l5_adverse_cny == "40"
    assert result.horizons[0].midpoint_markout_ticks == "1"
    assert result.horizons[0].midpoint_markout_cny == "50"
    assert result.horizons[0].passive_fill_bounds.lower_bound == "0"
    assert result.horizons[0].passive_fill_bounds.upper_bound == "0.2"
    assert result.horizons[-1].passive_fill_bounds.upper_bound == "1"
    assert result.horizons[-1].passive_fill_bounds.point_probability_output == (
        "FORBIDDEN"
    )
    assert result.collection_authorized is False
    assert result.runtime_activation_authorized is False
    assert result.authority_granted is False
    assert result.dispatch_allowed is False
    assert result.order_authorized is False
    assert result.position_mutation_authorized is False
    assert result.database_mutation_authorized is False
    assert result.deployment_mutation_authorized is False
    assert result.replacement_allowed is False
    assert result.production_allowed is False
    assert result.score_hash == execution_quality_score_hash(result)


def test_l1_only_never_synthesizes_l5_metrics_or_fill_bounds() -> None:
    rows = full_horizon_books()
    rows[0] = book(
        0,
        bid_prices=["1000", None, None, None, None],
        ask_prices=["1002", None, None, None, None],
        bid_sizes=[2, None, None, None, None],
        ask_sizes=[2, None, None, None, None],
    )

    result = score(rows)

    assert result.decision_tick is not None
    assert result.decision_tick.quality_state == (
        "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO"
    )
    assert result.decision_metrics is not None
    assert result.decision_metrics.metric_mask_state == "L1_METRICS_ONLY"
    assert result.decision_metrics.microprice_ticks is None
    assert result.decision_metrics.depth_imbalance is None
    assert result.decision_metrics.l1_coverage_ratio == "0.4"
    assert result.decision_metrics.l5_coverage_ratio is None
    assert result.decision_metrics.l5_vwap_price is None
    assert result.horizons[0].passive_fill_bounds.state == (
        "UNIDENTIFIED_NO_PASSIVE_FILL_BOUNDS"
    )


def test_sell_direction_walk_uses_bids_and_directional_adverse_cost() -> None:
    result = score(
        full_horizon_books(),
        virtual_intent=intent(direction="sell"),
    )

    assert result.decision_metrics is not None
    assert result.decision_metrics.protected_price == "999"
    assert result.decision_metrics.l5_vwap_price == "999.2"
    assert result.decision_metrics.l5_adverse_ticks == "0.8"
    assert result.decision_metrics.l5_adverse_cny == "40"
    assert result.horizons[0].midpoint_markout_ticks == "-1"


def test_quality_precedence_skips_clock_stale_crossed_and_missing_l1() -> None:
    clock_invalid = book(0, exchange_offset_ms=1)
    stale_crossed = book(
        10,
        exchange_offset_ms=-2_000,
        bid_prices=["1005", "999", "998", "997", "996"],
        ask_prices=["1002", "1003", "1004", "1005", "1006"],
    )
    crossed = book(
        20,
        bid_prices=["1005", "999", "998", "997", "996"],
        ask_prices=["1002", "1003", "1004", "1005", "1006"],
    )
    missing = book(
        25,
        bid_prices=[None, None, None, None, None],
        bid_sizes=[None, None, None, None, None],
    )
    locked = book(
        30,
        bid_prices=["1002", "1001", "1000", "999", "998"],
        ask_prices=["1002", "1003", "1004", "1005", "1006"],
    )

    result = score(
        [
            clock_invalid,
            stale_crossed,
            crossed,
            missing,
            locked,
            book(250, shift_ticks=1),
            book(1_000, shift_ticks=1),
            book(5_000, shift_ticks=1),
            book(30_000, shift_ticks=1),
            book(60_000, shift_ticks=1),
        ]
    )

    assert result.rejection_quality_counts["UNUSABLE_CLOCK_ORDER_INVALID"] == 1
    assert (
        result.rejection_quality_counts[
            "UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS"
        ]
        == 1
    )
    assert result.rejection_quality_counts["UNUSABLE_CROSSED_BOOK"] == 1
    assert (
        result.rejection_quality_counts["UNUSABLE_NO_EXECUTION_METRICS"]
        == 1
    )
    assert result.decision_tick is not None
    assert result.decision_tick.ingest_id == locked.ingest_id
    assert result.decision_metrics is not None
    assert result.decision_metrics.metric_mask_state == (
        "MARKOUT_ONLY_NO_DECISION_EXECUTION_METRICS"
    )
    assert result.decision_metrics.spread_ticks is None
    assert result.horizons[0].passive_fill_bounds.state == (
        "UNIDENTIFIED_NO_PASSIVE_FILL_BOUNDS"
    )


def test_insufficient_l5_depth_reports_partial_observed_walk() -> None:
    result = score(
        full_horizon_books(),
        virtual_intent=intent(lots=12),
    )

    assert result.decision_metrics is not None
    assert result.decision_metrics.l5_book_walk_state == (
        "PARTIAL_L5_DEPTH_INSUFFICIENT"
    )
    assert result.decision_metrics.l5_covered_lots == 10
    assert result.decision_metrics.l5_coverage_ratio == (
        "0.8333333333333333333333333333"
    )


def test_missing_horizons_are_not_imputed() -> None:
    result = score([book(0)])

    assert result.decision_selection_state == "SELECTED_EARLIEST_ELIGIBLE"
    assert all(
        row.selection_state == "MISSING_HORIZON_NOT_IMPUTED"
        for row in result.horizons
    )
    assert all(row.selected_tick is None for row in result.horizons)
    assert all(
        row.passive_fill_bounds.state == "UNIDENTIFIED_MISSING_HORIZON"
        for row in result.horizons
    )


def test_out_of_order_input_is_deterministic_and_duplicates_drop_once() -> None:
    ordered = full_horizon_books()
    reversed_result = score(list(reversed(ordered)))
    ordered_result = score(ordered)

    assert reversed_result == ordered_result

    duplicate_result = score([ordered[1], *reversed(ordered)])

    assert duplicate_result.duplicate_snapshot_count == 1
    assert duplicate_result.canonical_snapshot_count == len(ordered)
    assert duplicate_result.horizons[0].selected_tick is not None
    assert duplicate_result.horizons[0].selected_tick.book_snapshot_hash == (
        ordered[1].book_snapshot_hash
    )


def test_conflicting_duplicate_ingest_identity_fails_closed() -> None:
    rows = full_horizon_books()
    conflicting = book(
        251,
        ingest_seq=rows[1].ingest_seq,
        ingest_id=rows[1].ingest_id,
        cumulative_volume="999",
    )

    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="BOOK_DUPLICATE_IDENTITY_CONFLICT",
    ):
        score([*rows, conflicting])


def test_event_duplicate_registers_skipped_ingest_identity_before_skip() -> None:
    first = book(250)
    duplicate_core = first.model_dump(
        mode="json",
        exclude={"book_snapshot_hash"},
    )
    duplicate_core["ingest_id"] = "zz-skipped-ingest-id"
    skipped_duplicate = CFastL1L5BookSnapshotDTO.model_validate(
        {
            **duplicate_core,
            "book_snapshot_hash": sha256_json(duplicate_core),
        }
    )
    conflicting_reuse = book(
        500,
        ingest_id="zz-skipped-ingest-id",
        cumulative_volume="999",
    )

    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="BOOK_DUPLICATE_IDENTITY_CONFLICT",
    ):
        score([first, skipped_duplicate, conflicting_reuse])


def test_same_event_key_with_different_content_fails_closed() -> None:
    first = book(250)
    conflicting_core = first.model_dump(
        mode="json",
        exclude={"book_snapshot_hash"},
    )
    conflicting_core["ingest_id"] = "zz-conflicting-event"
    conflicting_core["cumulative_volume"] = "999"
    conflicting = CFastL1L5BookSnapshotDTO.model_validate(
        {
            **conflicting_core,
            "book_snapshot_hash": sha256_json(conflicting_core),
        }
    )

    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="BOOK_DUPLICATE_EVENT_CONFLICT",
    ):
        score([first, conflicting])


def test_same_contract_timestamp_and_sequence_is_duplicate_event() -> None:
    rows = full_horizon_books()
    first = rows[1]
    duplicate_core = first.model_dump(
        mode="json",
        exclude={"book_snapshot_hash"},
    )
    duplicate_core["ingest_id"] = "different-ingest-id"
    duplicate = CFastL1L5BookSnapshotDTO.model_validate(
        {
            **duplicate_core,
            "book_snapshot_hash": sha256_json(duplicate_core),
        }
    )

    result = score([*rows, duplicate])

    assert result.duplicate_snapshot_count == 1
    assert result.horizons[0].selected_tick is not None
    assert result.horizons[0].selected_tick.ingest_id == (
        "different-ingest-id"
    )


def test_passive_bounds_never_emit_point_probability_and_degrade_safely() -> None:
    unidentified = score(
        full_horizon_books(),
        spec=contract_spec(volume_lots_per_raw_unit=None),
    )
    first_bound = unidentified.horizons[0].passive_fill_bounds

    assert first_bound.state == "UNIDENTIFIED_VOLUME_UNIT_BINDING"
    assert first_bound.lower_bound is None
    assert first_bound.upper_bound is None
    assert "fill_probability" not in first_bound.model_dump(mode="json")

    reset_rows = full_horizon_books()
    reset_rows[1] = book(250, cumulative_volume="99")
    reset = score(reset_rows)
    assert reset.horizons[0].passive_fill_bounds.state == (
        "UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL"
    )
    assert reset.horizons[0].passive_fill_bounds.lower_bound is None
    assert reset.horizons[0].passive_fill_bounds.upper_bound is None


def test_passive_interval_stops_at_selected_horizon_total_order_position() -> None:
    rows = full_horizon_books()
    after_selected_same_time = book(
        250,
        exchange_offset_ms=-50,
        ingest_seq=999,
        ingest_id="zz-after-selected-horizon",
        cumulative_volume="105",
        shift_ticks=1,
    )

    result = score([*rows, after_selected_same_time])

    assert result.horizons[0].selected_tick is not None
    assert result.horizons[0].selected_tick.book_snapshot_hash == (
        rows[1].book_snapshot_hash
    )
    assert result.horizons[0].passive_fill_bounds.state == (
        "IDENTIFIED_CONSERVATIVE_BOUNDS"
    )
    assert result.horizons[0].passive_fill_bounds.upper_bound == "0.2"


def test_score_hash_and_fresh_derivation_reject_tamper() -> None:
    rows = full_horizon_books()
    frozen_policy = policy()
    frozen_policy_hash = sha256_json(frozen_policy.model_dump(mode="json"))
    original = score_execution_quality(
        intent=intent(),
        durably_created_at_utc=ANCHOR,
        policy=frozen_policy,
        policy_hash=frozen_policy_hash,
        contract_spec=contract_spec(),
        snapshots=rows,
    )
    payload = original.model_dump(mode="json")
    payload["input_snapshot_set_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="score_hash mismatch"):
        CFastExecutionQualityScoreDTO.model_validate(payload)

    coherent = copy.deepcopy(payload)
    coherent["score_hash"] = sha256_json(
        {key: value for key, value in coherent.items() if key != "score_hash"}
    )
    rewritten = CFastExecutionQualityScoreDTO.model_validate(coherent)
    assert rewritten.input_snapshot_set_sha256 == "0" * 64

    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="SCORE_DERIVATION_MISMATCH",
    ):
        reload_and_verify_execution_quality_score(
            rewritten.model_dump(mode="json"),
            intent=intent(),
            durably_created_at_utc=ANCHOR,
            policy=frozen_policy,
            policy_hash=frozen_policy_hash,
            contract_spec=contract_spec(),
            snapshots=rows,
        )


def test_book_and_contract_spec_checksums_reject_unsynchronised_tamper() -> None:
    book_payload = book(0).model_dump(mode="json")
    book_payload["bid_prices"][0] = "999"
    with pytest.raises(ValidationError, match="book_snapshot_hash mismatch"):
        CFastL1L5BookSnapshotDTO.model_validate(book_payload)

    spec_payload = contract_spec().model_dump(mode="json")
    spec_payload["multiplier"] = 11
    with pytest.raises(ValidationError, match="contract_spec_hash mismatch"):
        CFastExecutionQualityContractSpecDTO.model_validate(spec_payload)


def test_score_rejects_coercive_authority_boolean() -> None:
    payload = score(full_horizon_books()).model_dump(mode="json")
    payload["dispatch_allowed"] = 0
    payload["score_hash"] = sha256_json(
        {key: value for key, value in payload.items() if key != "score_hash"}
    )

    with pytest.raises(ValidationError, match="JSON boolean literal"):
        CFastExecutionQualityScoreDTO.model_validate(payload)


@pytest.mark.parametrize(
    "replacement",
    [float("nan"), float("inf"), "NaN", "Infinity", "1e3"],
)
def test_snapshot_rejects_nan_infinity_float_and_non_plain_decimal(
    replacement,
) -> None:
    core = book(0).model_dump(
        mode="json",
        exclude={"book_snapshot_hash"},
    )
    core["bid_prices"][0] = replacement
    core["book_snapshot_hash"] = sha256_json(core)

    with pytest.raises((ValidationError, ValueError)):
        CFastL1L5BookSnapshotDTO.model_validate(core)


def test_off_grid_l1_is_unusable_and_not_selected() -> None:
    spec_core = contract_spec().model_dump(
        mode="json",
        exclude={"contract_spec_hash"},
    )
    spec_core["price_tick"] = "2"
    spec = CFastExecutionQualityContractSpecDTO.model_validate(
        {**spec_core, "contract_spec_hash": sha256_json(spec_core)}
    )

    result = score(
        [
            book(
                0,
                bid_prices=["1001", "999", "997", "995", "993"],
                ask_prices=["1002", "1004", "1006", "1008", "1010"],
            )
        ],
        spec=spec,
    )

    assert result.decision_selection_state == (
        "MISSING_DECISION_TICK_NOT_IMPUTED"
    )
    assert (
        result.rejection_quality_counts["UNUSABLE_NO_EXECUTION_METRICS"]
        == 1
    )
    assert all(
        row.selection_state == "DECISION_TICK_MISSING"
        for row in result.horizons
    )


def test_64_character_off_grid_locked_book_cannot_round_to_integer_ticks() -> None:
    off_grid_price = "1." + ("0" * 61) + "1"
    price_tick = "0." + ("0" * 61) + "3"
    assert len(off_grid_price) == 64
    assert len(price_tick) == 64

    spec_core = contract_spec().model_dump(
        mode="json",
        exclude={"contract_spec_hash"},
    )
    spec_core["price_tick"] = price_tick
    spec = CFastExecutionQualityContractSpecDTO.model_validate(
        {**spec_core, "contract_spec_hash": sha256_json(spec_core)}
    )
    locked_off_grid = book(
        0,
        bid_prices=[off_grid_price, None, None, None, None],
        ask_prices=[off_grid_price, None, None, None, None],
        bid_sizes=[2, None, None, None, None],
        ask_sizes=[2, None, None, None, None],
    )

    result = score([locked_off_grid], spec=spec)

    assert result.rejection_quality_counts[
        "DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS"
    ] == 1
    assert result.decision_selection_state == (
        "MISSING_DECISION_TICK_NOT_IMPUTED"
    )
    assert result.decision_tick is None


def test_zero_l1_and_zero_l2_depth_follow_quality_degradation() -> None:
    missing_l1 = score(
        [
            book(
                0,
                bid_prices=["0", None, None, None, None],
                bid_sizes=[0, None, None, None, None],
            )
        ]
    )
    assert (
        missing_l1.rejection_quality_counts[
            "UNUSABLE_NO_EXECUTION_METRICS"
        ]
        == 1
    )

    l1_only = score(
        [
            book(
                0,
                bid_prices=["1000", "0", None, None, None],
                ask_prices=["1002", "0", None, None, None],
                bid_sizes=[2, 0, None, None, None],
                ask_sizes=[2, 0, None, None, None],
            )
        ]
    )
    assert l1_only.decision_tick is not None
    assert l1_only.decision_tick.quality_state == (
        "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO"
    )


def test_policy_contract_and_resource_limits_fail_closed() -> None:
    frozen_policy = policy()
    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="POLICY_HASH_MISMATCH",
    ):
        score_execution_quality(
            intent=intent(),
            durably_created_at_utc=ANCHOR,
            policy=frozen_policy,
            policy_hash="0" * 64,
            contract_spec=contract_spec(),
            snapshots=[],
        )

    wrong_contract = contract_spec().model_dump(
        mode="json",
        exclude={"contract_spec_hash"},
    )
    wrong_contract["exact_contract"] = "SHFE.cu2712"
    wrong_spec = CFastExecutionQualityContractSpecDTO.model_validate(
        {
            **wrong_contract,
            "contract_spec_hash": sha256_json(wrong_contract),
        }
    )
    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="CONTRACT_SPEC_MISMATCH",
    ):
        score(
            [],
            spec=wrong_spec,
        )

    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="BOOK_SNAPSHOT_RESOURCE_LIMIT",
    ):
        score([book(0)] * 10_001)

    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="VIRTUAL_INTENT_LOT_LIMIT",
    ):
        score([], virtual_intent=intent(lots=101))


def test_intent_must_bind_policy_v2_foundation_hash() -> None:
    mismatched = intent().model_dump(mode="json")
    mismatched["policy_hash"] = "0" * 64
    leg_core = {
        "schema_version": "commodity_c_fast_virtual_leg_v1",
        "snapshot_id": mismatched["snapshot_id"],
        "snapshot_hash": mismatched["snapshot_hash"],
        "formula_target_binding_sha256": (
            mismatched["formula_target_binding_sha256"]
        ),
        "policy_hash": mismatched["policy_hash"],
        "product": mismatched["product"],
        "phase": mismatched["phase"],
        "position_effect": mismatched["position_effect"],
        "exact_contract": mismatched["exact_contract"],
        "signed_quantity_delta": mismatched["leg_signed_quantity_delta"],
        "leg_sequence": mismatched["leg_sequence"],
    }
    mismatched["leg_id"] = (
        f"cfast-virtual-leg-v1-{sha256_json(leg_core)}"
    )
    intent_core = {
        key: value for key, value in mismatched.items() if key != "intent_id"
    }
    mismatched["intent_id"] = (
        f"cfast-virtual-intent-v1-{sha256_json(intent_core)}"
    )
    rewritten = CFastVirtualIntentDTO.model_validate(mismatched)

    with pytest.raises(
        CFastExecutionQualityScorerError,
        match="INTENT_FOUNDATION_POLICY_MISMATCH",
    ):
        score([], virtual_intent=rewritten)
