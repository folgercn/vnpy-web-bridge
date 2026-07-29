from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest

from app.schemas.commodity_c_fast_pnl_ledger import (
    CommodityCFastFourLayerPnlLedgerEntryDTO,
    sha256_json,
)
from app.services.commodity_c_fast_pnl_ledger import (
    CFastPnlLedgerError,
    build_four_layer_pnl_entry,
    reload_and_verify_four_layer_pnl_entry,
    verify_four_layer_pnl_chain,
)


SNAPSHOT_HASH = "a" * 64
FORMULA_HASH = "b" * 64
PLAN_HASH = "c" * 64
LEDGER_ID = "cfast-four-layer-ledger-2026-09"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _runtime_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def common_source(
    *,
    ledger_id: str,
    snapshot_hash: str,
    formula_hash: str,
    plan_hash: str,
    valuation_day: str,
    as_of_at_utc: str,
) -> dict[str, Any]:
    return {
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "ledger_id": ledger_id,
        "snapshot_hash": snapshot_hash,
        "formula_target_binding_sha256": formula_hash,
        "plan_hash": plan_hash,
        "valuation_day": valuation_day,
        "as_of_at_utc": as_of_at_utc,
    }


def terminal_checksum(facts: dict[str, Any]) -> str:
    payload = {
        "session_id": facts["session_id"],
        "plan_hash": facts["plan_hash"],
        "status": facts["terminal_status"],
        "completed_at_utc": facts["terminal_completed_at_utc"],
        "execution_state_checksum": facts["execution_state_checksum"],
    }
    return sha256_json(payload)


def source_inputs(
    *,
    ledger_id: str = LEDGER_ID,
    snapshot_hash: str = SNAPSHOT_HASH,
    formula_hash: str = FORMULA_HASH,
    plan_hash: str = PLAN_HASH,
    valuation_day: str = "2026-09-02",
    as_of_at_utc: str = "2026-09-02T08:02:00Z",
    fee_bound: bool = False,
    fill_state: str = "PARTIAL",
    actual_state: str = "none",
) -> dict[str, dict[str, Any]]:
    common = common_source(
        ledger_id=ledger_id,
        snapshot_hash=snapshot_hash,
        formula_hash=formula_hash,
        plan_hash=plan_hash,
        valuation_day=valuation_day,
        as_of_at_utc=as_of_at_utc,
    )
    theoretical = {
        **common,
        "schema_version": (
            "commodity_c_fast_theoretical_target_pnl_source_facts_v1"
        ),
        "held_lots": 7,
        "pending_virtual_lots": 3,
        "realized_pnl_cny": 1_000.0,
        "unrealized_pnl_cny": -120.0,
        "roll_pnl_cny": -30.0,
    }
    if fee_bound:
        fee = {
            **common,
            "schema_version": (
                "commodity_c_fast_fee_adjusted_pnl_source_facts_v2"
            ),
            "fee_binding_state": "BOUND",
            "fee_component_universe": (
                "official_exchange_fee",
                "broker_customer_fee",
                "preregistered_tick_stress",
                "roll_round_trip_cost",
            ),
            "official_exchange_fee_rate": 0.0001,
            "official_exchange_turnover_cny": 100_000.0,
            "preregistered_tick_stress_cny": 20.0,
            "roll_round_trip_cost_cny": 30.0,
            "broker_customer_fee_rate": 0.00005,
            "broker_customer_turnover_cny": 100_000.0,
            "fee_schedule_sha256": "d" * 64,
            "unbound_components": (),
        }
    else:
        fee = {
            **common,
            "schema_version": (
                "commodity_c_fast_fee_adjusted_pnl_source_facts_v2"
            ),
            "fee_binding_state": "UNBOUND_NOT_ASSUMED_ZERO",
            "fee_component_universe": (
                "official_exchange_fee",
                "broker_customer_fee",
                "preregistered_tick_stress",
                "roll_round_trip_cost",
            ),
            "official_exchange_fee_rate": 0.0001,
            "official_exchange_turnover_cny": 100_000.0,
            "preregistered_tick_stress_cny": 20.0,
            "roll_round_trip_cost_cny": 30.0,
            "broker_customer_fee_rate": None,
            "broker_customer_turnover_cny": None,
            "fee_schedule_sha256": None,
            "unbound_components": ("broker_customer_fee",),
        }
    execution = {
        **common,
        "schema_version": (
            "commodity_c_fast_execution_quality_interval_pnl_source_facts_v1"
        ),
        "fill_evidence_state": fill_state,
        "planned_lots": 10,
        "filled_lots_lower": 4,
        "filled_lots_upper": 7,
        "filled_lot_pnl_cny": 100.0,
        "unfilled_lot_opportunity_cost_cny": 20.0,
        "marketable_book_walk_pnl_cny": 700.0,
    }
    if fill_state == "FULL":
        execution.update(
            {
                "filled_lots_lower": 10,
                "filled_lots_upper": 10,
            }
        )
    elif fill_state == "UNFILLED":
        execution.update(
            {
                "filled_lots_lower": 0,
                "filled_lots_upper": 0,
                "marketable_book_walk_pnl_cny": None,
            }
        )
    elif fill_state == "UNIDENTIFIED_BOUNDS_ONLY":
        execution.update(
            {
                "filled_lots_lower": 0,
                "filled_lots_upper": 10,
                "marketable_book_walk_pnl_cny": None,
            }
        )
    if actual_state == "none":
        actual = {
            **common,
            "schema_version": (
                "commodity_c_fast_actual_simnow_not_provided_source_facts_v1"
            ),
            "actual_state": "NOT_PROVIDED",
        }
    else:
        as_of = datetime.fromisoformat(as_of_at_utc.replace("Z", "+00:00"))
        complete = actual_state == "complete"
        rejected = actual_state == "rejected"
        filled_lots = 10 if complete else 0 if rejected else 3
        outcome = (
            "FULL_FILL"
            if complete
            else "REJECTED"
            if rejected
            else "PARTIAL_FILL"
        )
        actual = {
            **common,
            "schema_version": "commodity_c_fast_actual_simnow_facts_v3",
            "actual_state": "FACTS_BOUND",
            "fact_source": (
                "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION"
            ),
            "execution_lane": "simnow_shakedown",
            "session_id": "cfast-simnow-session-20260902",
            "account_sha256": "1" * 64,
            "orders_sha256": "2" * 64,
            "trades_sha256": "3" * 64,
            "positions_sha256": "4" * 64,
            "reconciliation_sha256": "5" * 64,
            "execution_state_checksum": "6" * 64,
            "execution_state_checksum_verification_state": (
                "ARCHIVE_REFERENCE_ONLY_CORE_NOT_EMBEDDED"
            ),
            "terminal_checksum": "0" * 64,
            "terminal_status": "COMPLETE" if complete else "INCOMPLETE",
            "terminal_reconciliation_complete": complete,
            "terminal_completed_at_utc": (
                _runtime_iso(as_of - timedelta(seconds=30))
                if complete
                else None
            ),
            "valuation_at_utc": _iso(as_of - timedelta(minutes=2)),
            "execution_captured_at_utc": _iso(as_of - timedelta(minutes=1)),
            "expected_lots": 10,
            "filled_lots": filled_lots,
            "order_outcome": outcome,
            "trade_evidence_state": ("COMPLETE" if complete else "INCOMPLETE"),
            "actual_amount_verification_state": (
                "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"
            ),
            "countable_forward": False,
            "production_allowed": False,
        }
        actual["terminal_checksum"] = terminal_checksum(actual)
    return {
        "theoretical": theoretical,
        "fee": fee,
        "execution": execution,
        "actual": actual,
    }


def build(
    *,
    ledger_id: str = LEDGER_ID,
    snapshot_hash: str = SNAPSHOT_HASH,
    formula_hash: str = FORMULA_HASH,
    plan_hash: str = PLAN_HASH,
    sequence: int = 1,
    previous: str | None = None,
    valuation_day: str = "2026-09-02",
    created_at: str = "2026-09-02T08:03:00Z",
    payloads: dict[str, dict[str, Any]] | None = None,
):
    source = payloads or source_inputs(
        ledger_id=ledger_id,
        snapshot_hash=snapshot_hash,
        formula_hash=formula_hash,
        plan_hash=plan_hash,
        valuation_day=valuation_day,
    )
    return build_four_layer_pnl_entry(
        ledger_id=ledger_id,
        entry_sequence=sequence,
        previous_entry_hash=previous,
        snapshot_hash=snapshot_hash,
        formula_target_binding_sha256=formula_hash,
        plan_hash=plan_hash,
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


def _rehash_entry(payload: dict[str, Any], layer_name: str) -> None:
    layer = payload[layer_name]
    layer["layer_hash"] = sha256_json(
        {key: value for key, value in layer.items() if key != "layer_hash"}
    )
    index_key = {
        "theoretical_target_pnl": "theoretical_target_pnl_sha256",
        "fee_adjusted_pnl": "fee_adjusted_pnl_sha256",
        "execution_quality_interval_pnl": (
            "execution_quality_interval_pnl_sha256"
        ),
        "actual_simnow_calibration_pnl": (
            "actual_simnow_calibration_pnl_sha256"
        ),
    }[layer_name]
    payload["layer_hashes"][index_key] = layer["layer_hash"]
    identity = {
        "ledger_id": payload["ledger_id"],
        "entry_sequence": payload["entry_sequence"],
        "snapshot_hash": payload["snapshot_hash"],
        "formula_target_binding_sha256": (
            payload["formula_target_binding_sha256"]
        ),
        "plan_hash": payload["plan_hash"],
        "valuation_day": payload["valuation_day"],
        "layer_hashes": payload["layer_hashes"],
    }
    payload["entry_id"] = f"cfast-pnl-entry-v2-{sha256_json(identity)}"
    payload["entry_hash"] = sha256_json(
        {key: value for key, value in payload.items() if key != "entry_hash"}
    )


def test_happy_path_is_deterministic_and_fresh_source_bound() -> None:
    first = build()
    second = build()

    assert first == second
    assert first.schema_version == "commodity_c_fast_four_layer_pnl_ledger_v2"
    assert first.plan_hash == PLAN_HASH
    hashes = first.layer_hashes.model_dump(mode="json")
    assert len(set(hashes.values())) == 4
    assert first.fee_adjusted_pnl.fee_adjusted_total_pnl_cny is None
    assert first.actual_simnow_calibration_pnl.actual_state == "NOT_PROVIDED"
    for layer in (
        first.theoretical_target_pnl,
        first.fee_adjusted_pnl,
        first.execution_quality_interval_pnl,
        first.actual_simnow_calibration_pnl,
    ):
        facts_hash = sha256_json(layer.source_facts.model_dump(mode="json"))
        assert layer.lineage.source_payload_sha256 == facts_hash
        assert layer.lineage.source_artifact_sha256 == facts_hash


def test_reload_fresh_replay_rejects_self_hashed_derivation_substitution() -> (
    None
):
    payload = build().model_dump(mode="json")
    lineage = payload["theoretical_target_pnl"]["lineage"]
    lineage["derivation_rule_id"] = "attacker-selected-rule-v1"
    lineage["derivation_code_sha256"] = "9" * 64
    lineage["lineage_hash"] = sha256_json(
        {key: value for key, value in lineage.items() if key != "lineage_hash"}
    )
    _rehash_entry(payload, "theoretical_target_pnl")
    payload["fee_adjusted_pnl"]["source_theoretical_layer_hash"] = payload[
        "theoretical_target_pnl"
    ]["layer_hash"]
    _rehash_entry(payload, "fee_adjusted_pnl")

    CommodityCFastFourLayerPnlLedgerEntryDTO.model_validate(payload)
    assert_error(
        "LEDGER_ENTRY_FRESH_REPLAY_MISMATCH",
        reload_and_verify_four_layer_pnl_entry,
        payload,
    )


@pytest.mark.parametrize(
    ("envelope_field", "value"),
    [
        ("snapshot_hash", "8" * 64),
        ("plan_hash", "7" * 64),
        ("ledger_id", "different-ledger-id"),
    ],
)
def test_same_source_facts_cannot_attach_to_other_identity(
    envelope_field: str,
    value: str,
) -> None:
    kwargs = {envelope_field: value}
    assert_error(
        "SOURCE_IDENTITY_MISMATCH",
        build,
        payloads=source_inputs(),
        **kwargs,
    )


def test_actual_complete_binds_terminal_but_amounts_remain_unverified() -> (
    None
):
    entry = build(payloads=source_inputs(actual_state="complete"))
    actual = entry.actual_simnow_calibration_pnl
    facts = actual.source_facts

    assert actual.actual_state == "FACTS_BOUND"
    assert facts.snapshot_hash == SNAPSHOT_HASH
    assert facts.plan_hash == PLAN_HASH
    assert facts.session_id == "cfast-simnow-session-20260902"
    assert facts.terminal_completed_at_utc == "2026-09-02T08:01:30+00:00"
    assert facts.terminal_checksum == terminal_checksum(
        facts.model_dump(mode="json")
    )
    assert facts.filled_lots == facts.expected_lots == 10
    assert actual.stable_actual_fact_identity_sha256 is not None
    assert actual.gross_execution_pnl_cny is None
    assert actual.adverse_slippage_cny is None
    assert actual.actual_fees_cny is None
    assert actual.actual_net_pnl_cny is None
    assert (
        actual.actual_amount_verification_state
        == "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"
    )
    assert actual.fees_state == "UNVERIFIED"
    assert actual.countable_forward is False


@pytest.mark.parametrize("actual_state", ["partial", "rejected"])
def test_partial_and_rejected_are_incomplete_and_publish_no_amounts(
    actual_state: str,
) -> None:
    actual = build(
        payloads=source_inputs(actual_state=actual_state)
    ).actual_simnow_calibration_pnl
    assert actual.source_facts.trade_evidence_state == "INCOMPLETE"
    assert actual.gross_execution_pnl_cny is None
    assert actual.actual_fees_cny is None
    assert actual.actual_net_pnl_cny is None
    assert (
        actual.net_pnl_state
        == "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"
    )


def test_zero_fill_rejected_or_terminal_incomplete_cannot_claim_complete() -> (
    None
):
    zero_fill = source_inputs(actual_state="rejected")
    zero_fill["actual"].update(
        {
            "trade_evidence_state": "COMPLETE",
            "terminal_status": "COMPLETE",
            "terminal_reconciliation_complete": True,
            "terminal_completed_at_utc": "2026-09-02T08:01:30Z",
        }
    )
    zero_fill["actual"]["terminal_checksum"] = terminal_checksum(
        zero_fill["actual"]
    )
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=zero_fill,
    )

    terminal_incomplete = source_inputs(actual_state="complete")
    terminal_incomplete["actual"]["terminal_reconciliation_complete"] = False
    terminal_incomplete["actual"]["terminal_checksum"] = terminal_checksum(
        terminal_incomplete["actual"]
    )
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=terminal_incomplete,
    )


def test_actual_terminal_checksum_and_fact_identity_fail_closed() -> None:
    tampered = source_inputs(actual_state="complete")
    tampered["actual"]["execution_state_checksum"] = "7" * 64
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=tampered,
    )

    fake = source_inputs(actual_state="complete")
    fake["actual"]["fact_source"] = "SHADOW_OR_SYNTHETIC"
    fake["actual"]["terminal_checksum"] = terminal_checksum(fake["actual"])
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=fake,
    )


def test_actual_amount_substitution_with_coordinated_rehash_is_rejected() -> (
    None
):
    for gross, fee in ((90.0, 5.0), (777_777.0, 0.0)):
        source_claim = source_inputs(actual_state="complete")
        source_claim["actual"]["gross_execution_pnl_cny"] = gross
        source_claim["actual"]["actual_fees_cny"] = fee
        source_claim["actual"]["execution_state_checksum"] = sha256_json(
            {"gross_execution_pnl_cny": gross, "actual_fees_cny": fee}
        )
        source_claim["actual"]["terminal_checksum"] = terminal_checksum(
            source_claim["actual"]
        )
        assert_error(
            "INVALID_ACTUAL_SOURCE_FACTS",
            build,
            payloads=source_claim,
        )

    payload = build(
        payloads=source_inputs(actual_state="complete")
    ).model_dump(mode="json")
    actual = payload["actual_simnow_calibration_pnl"]
    actual["gross_execution_pnl_cny"] = 777_777.0
    actual["actual_fees_cny"] = 0.0
    actual["actual_net_pnl_cny"] = 777_777.0
    _rehash_entry(payload, "actual_simnow_calibration_pnl")

    assert_error(
        "LEDGER_ENTRY_VERIFICATION_FAILED",
        reload_and_verify_four_layer_pnl_entry,
        payload,
    )


def test_fee_bound_derives_net_and_unbound_cannot_use_zero_placeholders() -> (
    None
):
    bound = build(payloads=source_inputs(fee_bound=True))
    assert bound.fee_adjusted_pnl.all_in_cost_cny == 65.0
    assert bound.fee_adjusted_pnl.fee_adjusted_total_pnl_cny == 785.0
    assert bound.fee_adjusted_pnl.official_exchange_fee_cny == 10.0
    assert bound.fee_adjusted_pnl.broker_customer_fee_cny == 5.0

    broker_zero = source_inputs()
    broker_zero["fee"]["broker_customer_fee_rate"] = 0.0
    broker_zero["fee"]["broker_customer_fee_cny"] = 0.0
    assert_error(
        "INVALID_FEE_SOURCE_FACTS",
        build,
        payloads=broker_zero,
    )

    official_zero = source_inputs(fee_bound=True)
    official_zero["fee"].update(
        {
            "official_exchange_fee_rate": 1.0,
            "official_exchange_fee_cny": 0.0,
        }
    )
    assert_error(
        "INVALID_FEE_SOURCE_FACTS",
        build,
        payloads=official_zero,
    )

    omitted_tick = source_inputs()
    omitted_tick["fee"]["preregistered_tick_stress_cny"] = None
    assert_error(
        "INVALID_FEE_SOURCE_FACTS",
        build,
        payloads=omitted_tick,
    )

    named_tick = source_inputs()
    named_tick["fee"]["preregistered_tick_stress_cny"] = None
    named_tick["fee"]["unbound_components"] = (
        "broker_customer_fee",
        "preregistered_tick_stress",
    )
    named_tick_layer = build(payloads=named_tick).fee_adjusted_pnl
    assert named_tick_layer.official_exchange_fee_cny == 10.0
    assert named_tick_layer.broker_customer_fee_cny is None
    assert named_tick_layer.preregistered_tick_stress_cny is None
    assert named_tick_layer.roll_round_trip_cost_cny == 30.0
    assert named_tick_layer.all_in_cost_cny is None

    shortened_universe = source_inputs()
    shortened_universe["fee"]["fee_component_universe"] = (
        "official_exchange_fee",
        "broker_customer_fee",
        "roll_round_trip_cost",
    )
    assert_error(
        "INVALID_FEE_SOURCE_FACTS",
        build,
        payloads=shortened_universe,
    )


@pytest.mark.parametrize(
    (
        "state",
        "filled_lower",
        "filled_upper",
        "unfilled_lower",
        "unfilled_upper",
        "pnl_lower",
        "pnl_upper",
        "opportunity_lower",
        "opportunity_upper",
    ),
    [
        ("PARTIAL", 4, 7, 3, 6, 400.0, 700.0, 60.0, 120.0),
        ("UNFILLED", 0, 0, 10, 10, 0.0, 0.0, 200.0, 200.0),
        ("FULL", 10, 10, 0, 0, 1000.0, 1000.0, 0.0, 0.0),
        (
            "UNIDENTIFIED_BOUNDS_ONLY",
            0,
            10,
            0,
            10,
            0.0,
            1000.0,
            0.0,
            200.0,
        ),
    ],
)
def test_execution_interval_outputs_are_builder_derived(
    state: str,
    filled_lower: int,
    filled_upper: int,
    unfilled_lower: int,
    unfilled_upper: int,
    pnl_lower: float,
    pnl_upper: float,
    opportunity_lower: float,
    opportunity_upper: float,
) -> None:
    layer = build(
        payloads=source_inputs(fill_state=state)
    ).execution_quality_interval_pnl
    assert layer.filled_lots_lower == filled_lower
    assert layer.filled_lots_upper == filled_upper
    assert layer.unfilled_lots_lower == unfilled_lower
    assert layer.unfilled_lots_upper == unfilled_upper
    assert layer.conservative_fill_lower_bound_pnl_cny == pnl_lower
    assert layer.optimistic_fill_upper_bound_pnl_cny == pnl_upper
    assert layer.opportunity_cost_lower_bound_cny == opportunity_lower
    assert layer.opportunity_cost_upper_bound_cny == opportunity_upper


def test_execution_rejects_state_mismatch_and_caller_derived_fields() -> None:
    partial_full = source_inputs()
    partial_full["execution"]["filled_lots_upper"] = 10
    assert_error(
        "INVALID_EXECUTION_SOURCE_FACTS",
        build,
        payloads=partial_full,
    )

    fake_unfilled = source_inputs(fill_state="UNFILLED")
    fake_unfilled["execution"]["filled_lots_upper"] = 1
    assert_error(
        "INVALID_EXECUTION_SOURCE_FACTS",
        build,
        payloads=fake_unfilled,
    )

    caller_derived = source_inputs()
    caller_derived["execution"]["opportunity_cost_upper_bound_cny"] = 456.0
    assert_error(
        "INVALID_EXECUTION_SOURCE_FACTS",
        build,
        payloads=caller_derived,
    )


def test_chain_requires_hash_time_and_source_as_of_monotonicity() -> None:
    first = build()
    second_inputs = source_inputs(
        valuation_day="2026-09-03",
        as_of_at_utc="2026-09-03T08:02:00Z",
        actual_state="complete",
    )
    second = build(
        sequence=2,
        previous=first.entry_hash,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:03:00Z",
        payloads=second_inputs,
    )
    audit = verify_four_layer_pnl_chain(
        [first.model_dump(mode="json"), second.model_dump(mode="json")]
    )
    assert audit.entry_count == 2
    assert audit.actual_fact_entry_count == 1
    assert (
        audit.audit_state == "PASS_FRESH_REPLAY_STRUCTURE_AND_HASH_CHAIN_ONLY"
    )
    assert audit.external_genesis_anchor_state == "NOT_PROVIDED_STRUCTURE_ONLY"
    assert audit.external_tip_anchor_state == "NOT_PROVIDED_STRUCTURE_ONLY"

    same_created_inputs = source_inputs()
    same_created_inputs["theoretical"]["realized_pnl_cny"] = 1001.0
    same_created = build(
        sequence=2,
        previous=first.entry_hash,
        created_at="2026-09-02T08:03:00Z",
        payloads=same_created_inputs,
    )
    assert_error(
        "LEDGER_CREATED_AT_NOT_INCREASING",
        verify_four_layer_pnl_chain,
        [
            first.model_dump(mode="json"),
            same_created.model_dump(mode="json"),
        ],
    )

    regressed_inputs = source_inputs(
        valuation_day="2026-09-03",
        as_of_at_utc="2026-09-03T08:02:00Z",
    )
    regressed_inputs["fee"]["as_of_at_utc"] = "2026-09-01T08:02:00Z"
    regressed = build(
        sequence=2,
        previous=first.entry_hash,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:03:00Z",
        payloads=regressed_inputs,
    )
    assert_error(
        "LEDGER_SOURCE_AS_OF_REGRESSION",
        verify_four_layer_pnl_chain,
        [
            first.model_dump(mode="json"),
            regressed.model_dump(mode="json"),
        ],
    )


def test_duplicate_and_wrong_predecessor_fail_closed() -> None:
    first = build()
    assert_error(
        "LEDGER_DUPLICATE_ENTRY",
        verify_four_layer_pnl_chain,
        [first.model_dump(mode="json"), first.model_dump(mode="json")],
    )
    replay = build(
        sequence=2,
        previous=first.entry_hash,
        created_at="2026-09-03T08:03:00Z",
    )
    assert_error(
        "LEDGER_SOURCE_FACT_REPLAY",
        verify_four_layer_pnl_chain,
        [first.model_dump(mode="json"), replay.model_dump(mode="json")],
    )
    second_inputs = source_inputs(
        valuation_day="2026-09-03",
        as_of_at_utc="2026-09-03T08:02:00Z",
    )
    wrong = build(
        sequence=2,
        previous="0" * 64,
        valuation_day="2026-09-03",
        created_at="2026-09-03T08:03:00Z",
        payloads=second_inputs,
    )
    assert_error(
        "LEDGER_PREDECESSOR_MISMATCH",
        verify_four_layer_pnl_chain,
        [first.model_dump(mode="json"), wrong.model_dump(mode="json")],
    )


def test_same_actual_terminal_fact_cannot_replay_with_later_as_of() -> None:
    first_inputs = source_inputs(actual_state="complete")
    first = build(payloads=first_inputs)
    second_inputs = source_inputs(actual_state="complete")
    for source in second_inputs.values():
        source["as_of_at_utc"] = "2026-09-02T08:02:30Z"
    second_inputs["theoretical"]["realized_pnl_cny"] = 1_001.0
    second_inputs["actual"] = {
        **first_inputs["actual"],
        "as_of_at_utc": "2026-09-02T08:02:30Z",
    }
    second = build(
        sequence=2,
        previous=first.entry_hash,
        created_at="2026-09-02T08:03:30Z",
        payloads=second_inputs,
    )

    assert (
        first.actual_simnow_calibration_pnl.stable_actual_fact_identity_sha256
        == second.actual_simnow_calibration_pnl.stable_actual_fact_identity_sha256
    )
    assert_error(
        "LEDGER_ACTUAL_TERMINAL_REPLAY_OR_DIGEST_CONFLICT",
        verify_four_layer_pnl_chain,
        [
            first.model_dump(mode="json"),
            second.model_dump(mode="json"),
        ],
    )

    digest_conflict_inputs = source_inputs(actual_state="complete")
    for source in digest_conflict_inputs.values():
        source["as_of_at_utc"] = "2026-09-02T08:02:45Z"
    digest_conflict_inputs["theoretical"]["realized_pnl_cny"] = 1_002.0
    digest_conflict_inputs["actual"] = {
        **first_inputs["actual"],
        "as_of_at_utc": "2026-09-02T08:02:45Z",
        "trades_sha256": "7" * 64,
    }
    digest_conflict = build(
        sequence=2,
        previous=first.entry_hash,
        created_at="2026-09-02T08:03:45Z",
        payloads=digest_conflict_inputs,
    )
    assert (
        first.actual_simnow_calibration_pnl.stable_actual_fact_identity_sha256
        == digest_conflict.actual_simnow_calibration_pnl.stable_actual_fact_identity_sha256
    )
    assert_error(
        "LEDGER_ACTUAL_TERMINAL_REPLAY_OR_DIGEST_CONFLICT",
        verify_four_layer_pnl_chain,
        [
            first.model_dump(mode="json"),
            digest_conflict.model_dump(mode="json"),
        ],
    )


def test_actual_time_causality_is_valuation_execution_terminal_as_of() -> None:
    terminal_before_execution = source_inputs(actual_state="complete")
    terminal_before_execution["actual"]["terminal_completed_at_utc"] = (
        "2026-09-02T08:00:30Z"
    )
    terminal_before_execution["actual"]["terminal_checksum"] = (
        terminal_checksum(terminal_before_execution["actual"])
    )
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=terminal_before_execution,
    )

    execution_before_valuation = source_inputs(actual_state="complete")
    execution_before_valuation["actual"]["execution_captured_at_utc"] = (
        "2026-09-02T07:59:30Z"
    )
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=execution_before_valuation,
    )


@pytest.mark.parametrize("raw_false", [0, 0.0])
def test_literal_false_rejects_numeric_zero_before_coercion(
    raw_false: int | float,
) -> None:
    actual = source_inputs(actual_state="complete")
    actual["actual"]["countable_forward"] = raw_false
    actual["actual"]["terminal_checksum"] = terminal_checksum(actual["actual"])
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=actual,
    )

    envelope = build().model_dump(mode="json")
    envelope["countable_forward"] = raw_false
    assert_error(
        "LEDGER_ENTRY_VERIFICATION_FAILED",
        reload_and_verify_four_layer_pnl_entry,
        envelope,
    )


def test_decimal_raw_input_is_controlled_and_context_is_frozen() -> None:
    decimal_input = source_inputs()
    decimal_input["theoretical"]["realized_pnl_cny"] = Decimal("1000")
    assert_error(
        "DECIMAL_RAW_INPUT_NOT_ALLOWED",
        build,
        payloads=decimal_input,
    )

    baseline = build()
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.rounding = "ROUND_DOWN"
        changed_context = build()
    assert baseline == changed_context


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -float("inf")])
def test_nan_and_inf_fail_closed(bad: float) -> None:
    invalid = source_inputs()
    invalid["theoretical"]["realized_pnl_cny"] = bad
    assert_error(
        "INVALID_THEORETICAL_SOURCE_FACTS",
        build,
        payloads=invalid,
    )


def test_resource_limits_and_terminal_payload_tamper_fail_closed() -> None:
    lots = source_inputs()
    lots["execution"]["planned_lots"] = 100_001
    assert_error(
        "INVALID_EXECUTION_SOURCE_FACTS",
        build,
        payloads=lots,
    )

    terminal = source_inputs(actual_state="complete")
    terminal["actual"]["terminal_checksum"] = "0" * 64
    assert_error(
        "INVALID_ACTUAL_SOURCE_FACTS",
        build,
        payloads=terminal,
    )


def test_dto_json_schema_is_strict_and_has_four_separate_layers() -> None:
    schema = CommodityCFastFourLayerPnlLedgerEntryDTO.model_json_schema()
    assert schema["additionalProperties"] is False
    required = set(schema["required"])
    assert {
        "plan_hash",
        "theoretical_target_pnl",
        "fee_adjusted_pnl",
        "execution_quality_interval_pnl",
        "actual_simnow_calibration_pnl",
        "layer_hashes",
    } <= required


def test_pure_module_import_boundary_has_no_runtime_or_execution_capability() -> (
    None
):
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
            module == forbidden or module.startswith(f"{forbidden}.")
            for module in imported
            for forbidden in forbidden_modules
        )
        assert not (names & forbidden_names)
