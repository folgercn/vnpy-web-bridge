from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from app.schemas.commodity_c_fast_pnl_ledger import (
    CommodityCFastFourLayerPnlLedgerEntryDTO,
)
from app.services.commodity_c_fast_pnl_ledger import (
    CFastPnlLedgerError,
    build_four_layer_pnl_entry,
    verify_four_layer_pnl_chain,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


SNAPSHOT_HASH = "a" * 64
FORMULA_HASH = "b" * 64
LEDGER_ID = "cfast-four-layer-ledger-2026-09"


def lineage(kind: str, marker: str) -> dict[str, Any]:
    return {
        "schema_version": "commodity_c_fast_pnl_source_lineage_v1",
        "source_kind": kind,
        "source_artifact_id": f"source-artifact-{marker * 8}",
        "source_artifact_sha256": marker * 64,
        "source_payload_sha256": chr(ord(marker) + 1) * 64,
        "derivation_rule_id": f"derivation-rule-{marker * 8}",
        "derivation_code_sha256": chr(ord(marker) + 2) * 64,
        "input_cutoff_at_utc": "2026-09-02T08:00:00Z",
    }


def inputs(
    *,
    fee_bound: bool = False,
    fill_state: str = "PARTIAL",
    actual: str = "none",
) -> dict[str, dict[str, Any]]:
    theoretical = {
        "lineage": lineage("SIGNED_EXACT_TARGET_MARKS", "1"),
        "valuation_day": "2026-09-02",
        "position_basis": (
            "OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET"
        ),
        "held_lots": 7,
        "pending_virtual_lots": 3,
        "realized_pnl_cny": 1_000.0,
        "unrealized_pnl_cny": -120.0,
        "roll_pnl_cny": -30.0,
        "total_pnl_cny": 850.0,
    }
    if fee_bound:
        fee = {
            "lineage": lineage(
                "FEE_AND_STRESS_ASSUMPTIONS",
                "4",
            ),
            "fee_binding_state": "BOUND",
            "official_exchange_fee_cny": 10.0,
            "preregistered_tick_stress_cny": 20.0,
            "roll_round_trip_cost_cny": 30.0,
            "broker_customer_fee_cny": 5.0,
            "all_in_cost_cny": 65.0,
            "fee_adjusted_total_pnl_cny": 785.0,
            "fee_schedule_sha256": "8" * 64,
            "unbound_components": (),
        }
    else:
        fee = {
            "lineage": lineage(
                "FEE_AND_STRESS_ASSUMPTIONS",
                "4",
            ),
            "fee_binding_state": "UNBOUND_NOT_ASSUMED_ZERO",
            "official_exchange_fee_cny": 10.0,
            "preregistered_tick_stress_cny": 20.0,
            "roll_round_trip_cost_cny": 30.0,
            "broker_customer_fee_cny": None,
            "all_in_cost_cny": None,
            "fee_adjusted_total_pnl_cny": None,
            "fee_schedule_sha256": None,
            "unbound_components": ("broker_customer_fee_rate",),
        }
    execution = {
        "lineage": lineage(
            "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS",
            "7",
        ),
        "fill_evidence_state": fill_state,
        "point_fill_probability_state": (
            "FORBIDDEN_UNCALIBRATED_BOUNDS_ONLY"
        ),
        "planned_lots": 10,
        "filled_lots_lower": 4,
        "filled_lots_upper": 7,
        "unfilled_lots_lower": 3,
        "unfilled_lots_upper": 6,
        "marketable_book_walk_pnl_cny": 700.0,
        "conservative_fill_lower_bound_pnl_cny": 300.0,
        "optimistic_fill_upper_bound_pnl_cny": 720.0,
        "opportunity_cost_lower_bound_cny": -250.0,
        "opportunity_cost_upper_bound_cny": 80.0,
    }
    if fill_state == "UNFILLED":
        execution.update(
            {
                "filled_lots_lower": 0,
                "filled_lots_upper": 0,
                "unfilled_lots_lower": 10,
                "unfilled_lots_upper": 10,
                "marketable_book_walk_pnl_cny": None,
                "conservative_fill_lower_bound_pnl_cny": 0.0,
                "optimistic_fill_upper_bound_pnl_cny": 0.0,
            }
        )
    elif fill_state == "UNIDENTIFIED_BOUNDS_ONLY":
        execution.update(
            {
                "filled_lots_lower": 0,
                "filled_lots_upper": 10,
                "unfilled_lots_lower": 0,
                "unfilled_lots_upper": 10,
                "marketable_book_walk_pnl_cny": None,
            }
        )
    elif fill_state == "FULL":
        execution.update(
            {
                "filled_lots_lower": 10,
                "filled_lots_upper": 10,
                "unfilled_lots_lower": 0,
                "unfilled_lots_upper": 0,
                "opportunity_cost_lower_bound_cny": 0.0,
                "opportunity_cost_upper_bound_cny": 0.0,
            }
        )
    if actual == "none":
        actual_payload = {
            "actual_state": "NOT_PROVIDED",
            "lineage": None,
            "facts": None,
            "gross_execution_pnl_cny": None,
            "adverse_slippage_cny": None,
            "fees_state": "NOT_AVAILABLE",
            "actual_fees_cny": None,
            "net_pnl_state": "NOT_AVAILABLE",
            "actual_net_pnl_cny": None,
            "countable_forward": False,
        }
    else:
        complete = actual != "incomplete"
        actual_payload = {
            "actual_state": "FACTS_BOUND",
            "lineage": lineage(
                (
                    "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_"
                    "RECONCILIATION"
                ),
                "a",
            ),
            "facts": {
                "schema_version": (
                    "commodity_c_fast_actual_simnow_facts_v1"
                ),
                "fact_source": (
                    "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_"
                    "RECONCILIATION"
                ),
                "execution_lane": "simnow_shakedown",
                "session_id": "cfast-simnow-session-20260902",
                "account_sha256": "c" * 64,
                "orders_sha256": "d" * 64,
                "trades_sha256": "e" * 64,
                "positions_sha256": "f" * 64,
                "reconciliation_sha256": "0" * 64,
                "execution_captured_at_utc": "2026-09-02T08:01:00Z",
                "expected_lots": 10,
                "filled_lots": 3,
                "order_outcome": "PARTIAL_FILL",
                "trade_evidence_state": (
                    "COMPLETE" if complete else "INCOMPLETE"
                ),
                "reconciliation_complete": complete,
                "countable_forward": False,
                "production_allowed": False,
            },
            "gross_execution_pnl_cny": 90.0 if complete else None,
            "adverse_slippage_cny": 12.0 if complete else None,
            "fees_state": "BOUND" if complete else "NOT_AVAILABLE",
            "actual_fees_cny": 5.0 if complete else None,
            "net_pnl_state": (
                "AVAILABLE_FOR_OBSERVED_FILLS"
                if complete
                else "NOT_AVAILABLE"
            ),
            "actual_net_pnl_cny": 85.0 if complete else None,
            "countable_forward": False,
        }
        actual_payload["lineage"]["input_cutoff_at_utc"] = (
            "2026-09-02T08:02:00Z"
        )
        actual_payload["lineage"]["source_payload_sha256"] = sha256_json(
            actual_payload["facts"]
        )
    return {
        "theoretical": theoretical,
        "fee": fee,
        "execution": execution,
        "actual": actual_payload,
    }


def build(
    *,
    ledger_id: str = LEDGER_ID,
    sequence: int = 1,
    previous: str | None = None,
    valuation_day: str = "2026-09-02",
    created_at: str = "2026-09-02T08:02:00Z",
    payloads: dict[str, dict[str, Any]] | None = None,
):
    source = payloads or inputs()
    source["theoretical"]["valuation_day"] = valuation_day
    return build_four_layer_pnl_entry(
        ledger_id=ledger_id,
        entry_sequence=sequence,
        previous_entry_hash=previous,
        snapshot_hash=SNAPSHOT_HASH,
        formula_target_binding_sha256=FORMULA_HASH,
        valuation_day=valuation_day,
        created_at_utc=created_at,
        theoretical_target_pnl=source["theoretical"],
        fee_adjusted_pnl=source["fee"],
        execution_quality_interval_pnl=source["execution"],
        actual_simnow_calibration_pnl=source["actual"],
    )


def assert_error(code: str, function, *args, **kwargs) -> None:
    with pytest.raises(CFastPnlLedgerError) as exc_info:
        function(*args, **kwargs)
    assert exc_info.value.code == code


def test_happy_path_is_deterministic_and_layers_are_independently_bound() -> None:
    first = build()
    second = build()

    assert first == second
    hashes = first.layer_hashes.model_dump(mode="json")
    assert len(set(hashes.values())) == 4
    assert first.countable_forward is False
    assert first.dispatch_allowed is False
    assert first.theoretical_target_pnl.pending_virtual_lots == 3
    assert (
        first.fee_adjusted_pnl.fee_binding_state
        == "UNBOUND_NOT_ASSUMED_ZERO"
    )
    assert first.fee_adjusted_pnl.fee_adjusted_total_pnl_cny is None
    assert first.actual_simnow_calibration_pnl.actual_state == "NOT_PROVIDED"


def test_changing_execution_interval_does_not_overwrite_other_layer_hashes() -> None:
    first = build()
    changed_inputs = inputs()
    changed_inputs["execution"][
        "optimistic_fill_upper_bound_pnl_cny"
    ] = 710.0
    changed = build(payloads=changed_inputs)

    assert (
        first.theoretical_target_pnl.layer_hash
        == changed.theoretical_target_pnl.layer_hash
    )
    assert (
        first.fee_adjusted_pnl.layer_hash
        == changed.fee_adjusted_pnl.layer_hash
    )
    assert (
        first.actual_simnow_calibration_pnl.layer_hash
        == changed.actual_simnow_calibration_pnl.layer_hash
    )
    assert (
        first.execution_quality_interval_pnl.layer_hash
        != changed.execution_quality_interval_pnl.layer_hash
    )
    assert first.entry_hash != changed.entry_hash


def test_fee_bound_computes_net_and_unbound_cannot_assume_zero() -> None:
    bound = build(payloads=inputs(fee_bound=True))
    assert bound.fee_adjusted_pnl.all_in_cost_cny == 65.0
    assert bound.fee_adjusted_pnl.fee_adjusted_total_pnl_cny == 785.0

    invalid = inputs()
    invalid["fee"]["broker_customer_fee_cny"] = 0.0
    invalid["fee"]["all_in_cost_cny"] = 60.0
    invalid["fee"]["fee_adjusted_total_pnl_cny"] = 790.0
    assert_error("INVALID_FEE_ADJUSTED_PNL", build, payloads=invalid)


@pytest.mark.parametrize(
    ("state", "lower", "upper", "unfilled_lower", "unfilled_upper"),
    [
        ("PARTIAL", 4, 7, 3, 6),
        ("UNFILLED", 0, 0, 10, 10),
        ("UNIDENTIFIED_BOUNDS_ONLY", 0, 10, 0, 10),
        ("FULL", 10, 10, 0, 0),
    ],
)
def test_fill_states_preserve_filled_and_unfilled_facts(
    state: str,
    lower: int,
    upper: int,
    unfilled_lower: int,
    unfilled_upper: int,
) -> None:
    entry = build(payloads=inputs(fill_state=state))
    layer = entry.execution_quality_interval_pnl
    assert layer.filled_lots_lower == lower
    assert layer.filled_lots_upper == upper
    assert layer.unfilled_lots_lower == unfilled_lower
    assert layer.unfilled_lots_upper == unfilled_upper
    assert (
        layer.point_fill_probability_state
        == "FORBIDDEN_UNCALIBRATED_BOUNDS_ONLY"
    )


def test_interval_rejects_lower_above_upper_and_fake_unfilled_quantity() -> None:
    lower_above = inputs()
    lower_above["execution"][
        "conservative_fill_lower_bound_pnl_cny"
    ] = 800.0
    assert_error(
        "INVALID_EXECUTION_QUALITY_INTERVAL_PNL",
        build,
        payloads=lower_above,
    )

    fake_unfilled = inputs()
    fake_unfilled["execution"]["unfilled_lots_upper"] = 0
    assert_error(
        "INVALID_EXECUTION_QUALITY_INTERVAL_PNL",
        build,
        payloads=fake_unfilled,
    )


def test_actual_accepts_only_explicit_non_countable_simnow_facts() -> None:
    entry = build(payloads=inputs(actual="complete"))
    actual = entry.actual_simnow_calibration_pnl

    assert actual.actual_state == "FACTS_BOUND"
    assert actual.facts is not None
    assert actual.facts.order_outcome == "PARTIAL_FILL"
    assert actual.facts.filled_lots == 3
    assert actual.actual_net_pnl_cny == 85.0
    assert actual.countable_forward is False

    fake = inputs(actual="complete")
    fake["actual"]["facts"]["fact_source"] = "SHADOW_OR_SYNTHETIC"
    fake["actual"]["lineage"]["source_payload_sha256"] = sha256_json(
        fake["actual"]["facts"]
    )
    assert_error(
        "INVALID_ACTUAL_SIMNOW_CALIBRATION_PNL",
        build,
        payloads=fake,
    )

    countable = inputs(actual="complete")
    countable["actual"]["facts"]["countable_forward"] = True
    countable["actual"]["lineage"]["source_payload_sha256"] = sha256_json(
        countable["actual"]["facts"]
    )
    assert_error(
        "INVALID_ACTUAL_SIMNOW_CALIBRATION_PNL",
        build,
        payloads=countable,
    )


def test_incomplete_actual_facts_cannot_publish_amounts() -> None:
    incomplete = build(payloads=inputs(actual="incomplete"))
    actual = incomplete.actual_simnow_calibration_pnl
    assert actual.facts is not None
    assert actual.facts.trade_evidence_state == "INCOMPLETE"
    assert actual.actual_net_pnl_cny is None

    fake_amount = inputs(actual="incomplete")
    fake_amount["actual"]["gross_execution_pnl_cny"] = 0.0
    assert_error(
        "INVALID_ACTUAL_SIMNOW_CALIBRATION_PNL",
        build,
        payloads=fake_amount,
    )


def test_complete_actual_facts_keep_net_unavailable_when_fees_unbound() -> None:
    unbound = inputs(actual="complete")
    unbound["actual"].update(
        {
            "fees_state": "UNBOUND_NOT_ASSUMED_ZERO",
            "actual_fees_cny": None,
            "net_pnl_state": "UNAVAILABLE_UNTIL_FEES_BOUND",
            "actual_net_pnl_cny": None,
        }
    )

    actual = build(
        payloads=unbound
    ).actual_simnow_calibration_pnl
    assert actual.gross_execution_pnl_cny == 90.0
    assert actual.actual_net_pnl_cny is None
    assert actual.net_pnl_state == "UNAVAILABLE_UNTIL_FEES_BOUND"


def test_layer_kind_confusion_and_builder_owned_hashes_fail_closed() -> None:
    confused = inputs()
    confused["theoretical"]["lineage"]["source_kind"] = (
        "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS"
    )
    assert_error("INVALID_THEORETICAL_TARGET_PNL", build, payloads=confused)

    injected = inputs()
    injected["execution"]["layer_hash"] = "0" * 64
    assert_error(
        "CALLER_SUPPLIED_BUILDER_OWNED_FIELD",
        build,
        payloads=injected,
    )

    cross_layer = inputs()
    cross_layer["fee"]["source_theoretical_layer_hash"] = "0" * 64
    assert_error(
        "CALLER_SUPPLIED_BUILDER_OWNED_FIELD",
        build,
        payloads=cross_layer,
    )


def test_temporal_lineage_binding_fails_closed() -> None:
    future_cutoff = inputs()
    future_cutoff["theoretical"]["lineage"]["input_cutoff_at_utc"] = (
        "2026-09-02T08:03:00Z"
    )
    assert_error("INVALID_LEDGER_ENTRY", build, payloads=future_cutoff)

    before_capture = inputs(actual="complete")
    before_capture["actual"]["lineage"]["input_cutoff_at_utc"] = (
        "2026-09-02T08:00:00Z"
    )
    assert_error(
        "INVALID_ACTUAL_SIMNOW_CALIBRATION_PNL",
        build,
        payloads=before_capture,
    )


def test_chain_verifier_accepts_valid_chain_and_rejects_tamper() -> None:
    first = build()
    second_payloads = inputs(actual="complete")
    second_payloads["theoretical"]["total_pnl_cny"] = 900.0
    second_payloads["theoretical"]["realized_pnl_cny"] = 1_050.0
    second = build(
        sequence=2,
        previous=first.entry_hash,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:02:00Z",
        payloads=second_payloads,
    )

    audit = verify_four_layer_pnl_chain(
        [
            first.model_dump(mode="json"),
            second.model_dump(mode="json"),
        ]
    )
    assert audit.entry_count == 2
    assert audit.chain_tip_entry_hash == second.entry_hash
    assert audit.actual_fact_entry_count == 1
    assert audit.countable_forward is False

    tampered = second.model_dump(mode="json")
    tampered["theoretical_target_pnl"]["total_pnl_cny"] = 999.0
    assert_error(
        "LEDGER_ENTRY_VERIFICATION_FAILED",
        verify_four_layer_pnl_chain,
        [first.model_dump(mode="json"), tampered],
    )

    broken = build(
        sequence=2,
        previous="0" * 64,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:02:00Z",
    )
    assert_error(
        "LEDGER_PREDECESSOR_MISMATCH",
        verify_four_layer_pnl_chain,
        [
            first.model_dump(mode="json"),
            broken.model_dump(mode="json"),
        ],
    )


def test_duplicate_replay_and_mixed_ledger_fail_closed() -> None:
    first = build()
    assert_error(
        "LEDGER_DUPLICATE_ENTRY",
        verify_four_layer_pnl_chain,
        [
            first.model_dump(mode="json"),
            first.model_dump(mode="json"),
        ],
    )

    mixed = build(
        ledger_id="another-ledger-id",
        sequence=2,
        previous=first.entry_hash,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:02:00Z",
    )
    assert_error(
        "LEDGER_ID_MIXED",
        verify_four_layer_pnl_chain,
        [
            first.model_dump(mode="json"),
            mixed.model_dump(mode="json"),
        ],
    )


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -float("inf")])
def test_nan_and_inf_fail_closed(bad: float) -> None:
    invalid = inputs()
    invalid["theoretical"]["realized_pnl_cny"] = bad
    assert_error("INVALID_THEORETICAL_TARGET_PNL", build, payloads=invalid)


def test_money_and_lot_resource_limits_fail_closed() -> None:
    money = inputs()
    money["theoretical"]["realized_pnl_cny"] = 1_000_000_000_001.0
    assert_error("INVALID_THEORETICAL_TARGET_PNL", build, payloads=money)

    lots = inputs()
    lots["execution"]["planned_lots"] = 100_001
    assert_error(
        "INVALID_EXECUTION_QUALITY_INTERVAL_PNL",
        build,
        payloads=lots,
    )


def test_dto_json_schema_is_strict_and_has_four_separate_layers() -> None:
    schema = CommodityCFastFourLayerPnlLedgerEntryDTO.model_json_schema()
    assert schema["additionalProperties"] is False
    required = set(schema["required"])
    assert {
        "theoretical_target_pnl",
        "fee_adjusted_pnl",
        "execution_quality_interval_pnl",
        "actual_simnow_calibration_pnl",
        "layer_hashes",
    } <= required


def test_pure_module_import_boundary_has_no_runtime_or_execution_capability() -> None:
    root = Path(__file__).resolve().parents[2]
    paths = (
        root / "app/schemas/commodity_c_fast_pnl_ledger.py",
        root / "app/services/commodity_c_fast_pnl_ledger.py",
    )
    forbidden_modules = {
        "app.api",
        "app.core.config",
        "app.services.commodity_simnow",
        "app.services.trade_service",
        "app.services.vnpy_rpc_service",
        "app.services.tick_persistence",
        "app.stores",
        "questdb",
        "vnpy",
        "zmq",
    }
    forbidden_names = {
        "Settings",
        "TradeService",
        "VnpyRpcService",
        "send_order",
        "cancel_order",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: set[str] = set()
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                names.update(alias.name for alias in node.names)
        assert not any(
            module == forbidden
            or module.startswith(f"{forbidden}.")
            for module in imported
            for forbidden in forbidden_modules
        )
        assert not (names & forbidden_names)
