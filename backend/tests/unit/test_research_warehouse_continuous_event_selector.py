# ruff: noqa: E402

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_c_fast_pure_producer_kernel as frozen
from research_warehouse import continuous_event_selector as selector
from research_warehouse.canonical import canonical_json, canonical_json_line, sha256
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.verified_daily_pit_main_roll_source import (
    BuiltVerifiedDailyPitMainRollSource,
)
import research_warehouse.verified_daily_pit_main_roll_source as verified_roll
from test_research_warehouse_verified_daily_pit_main_roll_source import _kwargs


def _contracts(suffix: str) -> dict[str, str]:
    return {
        product: f"{frozen.PRODUCT_SPECS[product]['exchange']}.{product}{suffix}"
        for product in frozen.PRODUCTS
    }


def _daily(
    *,
    mode: str = "LINKED_ROOT_CATALOG",
    changed_products: tuple[str, ...] = ("ag",),
) -> dict:
    previous = _contracts("2609")
    current = dict(previous)
    for product in changed_products:
        current[product] = f"{frozen.PRODUCT_SPECS[product]['exchange']}.{product}2610"
    continuity = {
        "mode": mode,
        "predecessor_exact_contract_map_sha256": selector._contract_map_sha(previous),
    }
    if mode == "GENESIS_STATIC_CORE_EQUAL":
        continuity["baseline_batch_raw_sha256"] = "d" * 64
    return {
        "schema_version": (
            "vnpy_research_commodity_verified_daily_pit_main_roll_source_v2"
        ),
        "artifact_id": "verified-daily-roll-" + "a" * 64,
        "official_day": "2026-08-03",
        "execution_day": "2026-08-04",
        "roll_change_detected": bool(changed_products),
        "changed_products": list(changed_products),
        "input_lineage_status": "VERIFIED_AT_CONSTRUCTION_V2",
        "execution_lane": "simnow_shakedown",
        "mains": [
            {
                "product": product,
                "previous_exact_contract": previous[product],
                "exact_contract": current[product],
                "changed": product in changed_products,
            }
            for product in frozen.PRODUCTS
        ],
        "verified_lineage": {"continuity": continuity},
        "authority": false_authority(),
    }


def _target(
    *,
    execution_day: str = "2026-08-03",
    contracts: dict[str, str] | None = None,
    quantities: dict[str, int] | None = None,
    baseline_sha256: str = "d" * 64,
) -> selector.MonthlyFinalTargetCandidate:
    contracts = _contracts("2609") if contracts is None else contracts
    quantities = (
        {product: index - 4 for index, product in enumerate(frozen.PRODUCTS)}
        if quantities is None
        else quantities
    )
    payload = {
        "schema_version": selector.FINAL_TARGET_SCHEMA_VERSION,
        "strategy_id": "STATIC_CORE_EQUAL",
        "baseline_scheduler_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "c_sleeve_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "c_map_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
        "d_sleeve_id": "D_DONCHIAN20_EXIT10_NEUTRAL",
        "sector_map_id": "COMMODITY_FROZEN_SECTOR_MAP_V1",
        "position_manager_id": "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
        "source_month": "2026-07",
        "execution_day": execution_day,
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "targets": [
            {
                "product": product,
                "sector": frozen.SECTOR_MAP[product],
                "exact_contract": contracts[product],
                "target_quantity": quantities[product],
                "reference_open_price": float(1000 + index),
                "multiplier": frozen.PRODUCT_SPECS[product]["multiplier"],
                "price_tick": frozen.PRODUCT_SPECS[product]["price_tick"],
            }
            for index, product in enumerate(frozen.PRODUCTS)
        ],
    }
    return selector.MonthlyFinalTargetCandidate(
        final_target_raw=canonical_json_line(payload),
        static_core_equal_sha256="b" * 64,
        position_manager_sha256="c" * 64,
        baseline_batch_raw_sha256=baseline_sha256,
    )


def _terminal(
    target: selector.MonthlyFinalTargetCandidate,
    *,
    exact_contracts: dict[str, str],
) -> selector.TerminalPredecessorPinCandidate:
    payload = json.loads(target.final_target_raw)
    quantities = {row["product"]: row["target_quantity"] for row in payload["targets"]}
    return selector.TerminalPredecessorPinCandidate(
        terminal_target_id="continuous-event-" + "e" * 64,
        terminal_target_raw_sha256="f" * 64,
        monthly_final_target_sha256=sha256(canonical_json(payload)),
        quantity_vector_sha256=selector._quantity_vector_sha(quantities),
        exact_contract_map_sha256=selector._contract_map_sha(exact_contracts),
        execution_day="2026-08-03",
    )


def _patch_daily(
    monkeypatch: pytest.MonkeyPatch, payload: dict
) -> BuiltVerifiedDailyPitMainRollSource:
    """Isolate pure selection algebra; this is not a root/catalog integration."""

    raw = canonical_json_line({"fixture": payload["artifact_id"]})
    monkeypatch.setattr(
        selector,
        "validate_structural_daily_pit_main_roll_source",
        lambda observed: payload if observed == raw else None,
    )
    return BuiltVerifiedDailyPitMainRollSource(
        artifact_raw=raw,
        artifact_id=payload["artifact_id"],
        artifact_raw_sha256=sha256(raw),
    )


def _fully_rehash_selection(payload: dict) -> bytes:
    candidates = payload["candidates"]
    selected = candidates[0] if candidates else None
    payload["candidate_ids"] = [row["candidate_id"] for row in candidates]
    payload["candidate_set_sha256"] = sha256(canonical_json(candidates))
    payload["selected_candidate_id"] = selected["candidate_id"] if selected else None
    payload["selected_trigger_kind"] = selected["trigger_kind"] if selected else None
    selection_core = {
        "strategy_id": payload["strategy_id"],
        "execution_lane": payload["execution_lane"],
        "execution_day": payload["execution_day"],
        "precedence_rule_id": payload["precedence_rule_id"],
        "verified_daily_artifact_id": payload["verified_daily_artifact_id"],
        "verified_daily_artifact_raw_sha256": payload[
            "verified_daily_artifact_raw_sha256"
        ],
        "candidate_set_sha256": payload["candidate_set_sha256"],
        "candidate_ids": payload["candidate_ids"],
        "observed_trigger_kinds": payload["observed_trigger_kinds"],
        "selected_candidate_id": payload["selected_candidate_id"],
        "selected_trigger_kind": payload["selected_trigger_kind"],
        "suppressed_trigger_kinds": payload["suppressed_trigger_kinds"],
        "monthly_precedence_applied": payload["monthly_precedence_applied"],
    }
    payload["selection_sha256"] = sha256(canonical_json(selection_core))
    payload["selection_id"] = f"continuous-selection-{payload['selection_sha256']}"
    return canonical_json_line(payload)


def test_monthly_precedence_is_exclusive_stable_and_no_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily = _daily(changed_products=("ag", "sc"))
    raw = _patch_daily(monkeypatch, daily)
    monthly = _target(
        contracts={row["product"]: row["exact_contract"] for row in daily["mains"]}
    )

    first = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=raw,
        monthly_candidate=monthly,
    )
    second = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=raw,
        monthly_candidate=monthly,
    )

    assert first == second
    assert first.selected_trigger_kind == selector.MONTHLY_REBALANCE
    selection = selector.validate_continuous_event_selection(first.selection_raw)
    assert selection["candidate_ids"] == [selection["selected_candidate_id"]]
    assert selection["observed_trigger_kinds"] == [
        selector.MONTHLY_REBALANCE,
        selector.ROLL_ONLY,
    ]
    assert selection["suppressed_trigger_kinds"] == [selector.ROLL_ONLY]
    assert selection["monthly_precedence_applied"] is True
    assert selection["candidate_set_sha256"] == first.candidate_set_sha256
    assert selection["selection_sha256"] == first.selection_sha256
    event = selector.validate_continuous_event_candidate(
        first.event_candidate_raw,
        expected_selection_raw=first.selection_raw,
    )
    assert event["event_id"] == first.event_candidate_id
    assert event["event_ready"] is False
    assert event["installable"] is False
    for payload in (selection, event):
        assert payload["production_allowed"] is False
        assert payload["live_trading_authorized"] is False
        assert payload["countable_forward"] is False
        assert payload["official_forward_claimed"] is False
        assert payload["dispatch_authorized"] is False
        assert payload["order_authorized"] is False
        assert payload["position_mutation_authorized"] is False
        assert payload["authority"] == false_authority()


def test_self_consistent_forged_dataclasses_never_become_ready(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    forged_payload = json.loads(built.artifact_raw)
    forged_payload["verified_lineage"]["runtime"]["runtime_input_raw_sha256"] = "0" * 64
    forged_payload["artifact_id"] = verified_roll._artifact_id(forged_payload)
    forged_raw = canonical_json_line(forged_payload)
    # The forged bytes pass the public structural validator after the caller
    # recomputes every self-identity.  That still does not prove the current
    # Warehouse root or an independently replayed monthly target.
    assert (
        verified_roll.validate_structural_daily_pit_main_roll_source(forged_raw)[
            "artifact_id"
        ]
        == forged_payload["artifact_id"]
    )
    forged = BuiltVerifiedDailyPitMainRollSource(
        artifact_raw=forged_raw,
        artifact_id=forged_payload["artifact_id"],
        artifact_raw_sha256=sha256(forged_raw),
    )
    contracts = {
        row["product"]: row["exact_contract"] for row in forged_payload["mains"]
    }
    result = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=forged,
        monthly_candidate=_target(
            execution_day=forged_payload["official_day"],
            contracts=contracts,
            baseline_sha256=forged_payload["verified_lineage"]["continuity"][
                "baseline_batch_raw_sha256"
            ],
        ),
    )

    selection = json.loads(result.selection_raw)
    event = json.loads(result.event_candidate_raw)
    assert selection["verification_status"] == selector.VERIFICATION_STATUS
    assert event["verification_status"] == selector.VERIFICATION_STATUS
    assert selection["event_ready"] is False
    assert selection["installable"] is False
    assert event["event_ready"] is False
    assert event["installable"] is False


def test_real_verified_genesis_output_is_accepted_as_typed_input(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kwargs, _inputs, _private = _kwargs(monkeypatch, tmp_path)
    built = verified_roll.build_verified_daily_pit_main_roll_source(**kwargs)
    daily = verified_roll.validate_structural_daily_pit_main_roll_source(
        built.artifact_raw
    )
    contracts = {row["product"]: row["exact_contract"] for row in daily["mains"]}

    result = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=built,
        monthly_candidate=_target(
            execution_day=daily["official_day"],
            contracts=contracts,
            baseline_sha256=daily["verified_lineage"]["continuity"][
                "baseline_batch_raw_sha256"
            ],
        ),
    )

    assert result.selected_trigger_kind == selector.MONTHLY_REBALANCE
    assert (
        selector.validate_continuous_event_candidate(
            result.event_candidate_raw,
            expected_selection_raw=result.selection_raw,
        )["event_id"]
        == result.event_candidate_id
    )


def test_pure_builder_roll_only_preserves_quantities_and_daily_contract_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Linked catalog/current-root verification is a later integration gate.
    # This test covers only the structural selection algebra.
    daily = _daily(changed_products=("ag", "cu"))
    raw = _patch_daily(monkeypatch, daily)
    predecessor_contracts = _contracts("2606")
    predecessor = _target(
        execution_day="2026-07-01",
        contracts=predecessor_contracts,
    )
    previous_daily_contracts = {
        row["product"]: row["previous_exact_contract"] for row in daily["mains"]
    }

    result = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=raw,
        predecessor_monthly_target=predecessor,
        predecessor_terminal=_terminal(
            predecessor,
            exact_contracts=previous_daily_contracts,
        ),
    )

    assert result.selected_trigger_kind == selector.ROLL_ONLY
    selection = json.loads(result.selection_raw)
    assert selection["observed_trigger_kinds"] == [selector.ROLL_ONLY]
    assert selection["suppressed_trigger_kinds"] == []
    candidate = selection["candidates"][0]
    assert candidate["roll_preserves_integer_lots"] is True
    assert [
        row["product"] for row in candidate["targets"] if row["exact_contract_changed"]
    ] == ["ag", "cu"]
    assert all(
        row["previous_target_quantity"] == row["target_quantity"]
        for row in candidate["targets"]
    )
    expected_quantities = {
        row["product"]: row["target_quantity"]
        for row in json.loads(predecessor.final_target_raw)["targets"]
    }
    assert candidate["quantity_vector_sha256"] == selector._quantity_vector_sha(
        expected_quantities
    )


def test_pure_builder_roll_only_rejects_terminal_quantity_or_exact_map_splice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This is deliberately not a real linked-catalog integration test.
    daily = _daily()
    raw = _patch_daily(monkeypatch, daily)
    predecessor = _target(execution_day="2026-07-01")
    terminal = _terminal(
        predecessor,
        exact_contracts={
            row["product"]: row["previous_exact_contract"] for row in daily["mains"]
        },
    )

    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="predecessor terminal target binding mismatch",
    ):
        selector.build_continuous_event_candidate_selection(
            verified_daily_artifact=raw,
            predecessor_monthly_target=predecessor,
            predecessor_terminal=selector.TerminalPredecessorPinCandidate(
                terminal_target_id=terminal.terminal_target_id,
                terminal_target_raw_sha256=terminal.terminal_target_raw_sha256,
                monthly_final_target_sha256=terminal.monthly_final_target_sha256,
                quantity_vector_sha256="0" * 64,
                exact_contract_map_sha256=terminal.exact_contract_map_sha256,
                execution_day=terminal.execution_day,
            ),
        )

    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="predecessor terminal target binding mismatch",
    ):
        selector.build_continuous_event_candidate_selection(
            verified_daily_artifact=raw,
            predecessor_monthly_target=predecessor,
            predecessor_terminal=selector.TerminalPredecessorPinCandidate(
                terminal_target_id=terminal.terminal_target_id,
                terminal_target_raw_sha256=terminal.terminal_target_raw_sha256,
                monthly_final_target_sha256=terminal.monthly_final_target_sha256,
                quantity_vector_sha256=terminal.quantity_vector_sha256,
                exact_contract_map_sha256="1" * 64,
                execution_day=terminal.execution_day,
            ),
        )


def test_genesis_requires_monthly_and_binds_baseline_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily = _daily(mode="GENESIS_STATIC_CORE_EQUAL", changed_products=())
    raw = _patch_daily(monkeypatch, daily)

    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="requires its monthly target",
    ):
        selector.build_continuous_event_candidate_selection(
            verified_daily_artifact=raw,
        )
    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="does not bind the verified Genesis baseline",
    ):
        selector.build_continuous_event_candidate_selection(
            verified_daily_artifact=raw,
            monthly_candidate=_target(baseline_sha256="0" * 64),
        )

    result = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=raw,
        monthly_candidate=_target(),
    )
    assert result.selected_trigger_kind == selector.MONTHLY_REBALANCE


def test_linked_no_change_builds_stable_no_event_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _patch_daily(monkeypatch, _daily(changed_products=()))

    result = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=raw,
    )
    selection = selector.validate_continuous_event_selection(result.selection_raw)

    assert result.event_candidate_raw is None
    assert result.event_candidate_id is None
    assert result.selected_trigger_kind is None
    assert selection["candidates"] == []
    assert selection["event_ready"] is False
    assert selection["installable"] is False


def test_unverified_v1_daily_detector_is_never_consumed() -> None:
    raw = canonical_json_line(
        {
            "schema_version": ("vnpy_research_commodity_daily_pit_main_roll_source_v1"),
            "source_kind": "DAILY_PIT_MAIN_ROLL_ONLY",
            "installable": False,
            "event_ready": False,
        }
    )

    with pytest.raises(selector.ContinuousEventSelectorError):
        selector.build_continuous_event_candidate_selection(
            verified_daily_artifact=BuiltVerifiedDailyPitMainRollSource(
                artifact_raw=raw,
                artifact_id="verified-daily-roll-" + "a" * 64,
                artifact_raw_sha256=sha256(raw),
            ),
        )


def test_monthly_contract_map_must_equal_verified_daily_current_map(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily = _daily(changed_products=())
    raw = _patch_daily(monkeypatch, daily)
    wrong = _contracts("2611")

    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="do not match verified daily PIT main",
    ):
        selector.build_continuous_event_candidate_selection(
            verified_daily_artifact=raw,
            monthly_candidate=_target(contracts=wrong),
        )


def test_selection_and_event_tampering_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily = _daily(changed_products=())
    raw = _patch_daily(monkeypatch, daily)
    result = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=raw,
        monthly_candidate=_target(),
    )

    selection = json.loads(result.selection_raw)
    selection["candidate_set_sha256"] = "0" * 64
    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="candidate-set hash mismatch",
    ):
        selector.validate_continuous_event_selection(canonical_json_line(selection))

    event = json.loads(result.event_candidate_raw)
    event["candidate"]["targets"][0]["target_quantity"] += 1
    with pytest.raises(selector.ContinuousEventSelectorError):
        selector.validate_continuous_event_candidate(
            canonical_json_line(event),
            expected_selection_raw=result.selection_raw,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("execution_day", "2026-08-05"),
        ("verified_daily_artifact_id", "verified-daily-roll-" + "9" * 64),
        ("verified_daily_artifact_raw_sha256", "8" * 64),
    ],
)
def test_selection_top_level_daily_binding_rejects_complete_rehash(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
) -> None:
    daily = _daily(changed_products=())
    raw = _patch_daily(monkeypatch, daily)
    result = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=raw,
        monthly_candidate=_target(),
    )
    selection = json.loads(result.selection_raw)
    selection[field] = replacement

    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="selection/daily candidate binding mismatch",
    ):
        selector.validate_continuous_event_selection(_fully_rehash_selection(selection))


def test_selection_rejects_candidate_cross_splice_after_complete_rehash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_daily = _daily(changed_products=())
    first = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=_patch_daily(monkeypatch, first_daily),
        monthly_candidate=_target(),
    )
    second_daily = _daily(changed_products=())
    second_daily["artifact_id"] = "verified-daily-roll-" + "7" * 64
    second = selector.build_continuous_event_candidate_selection(
        verified_daily_artifact=_patch_daily(monkeypatch, second_daily),
        monthly_candidate=_target(),
    )
    first_selection = json.loads(first.selection_raw)
    second_selection = json.loads(second.selection_raw)
    first_selection["candidates"] = second_selection["candidates"]
    first_selection["event_candidate_id"] = second_selection["event_candidate_id"]
    first_selection["event_candidate_raw_sha256"] = second_selection[
        "event_candidate_raw_sha256"
    ]

    with pytest.raises(
        selector.ContinuousEventSelectorError,
        match="selection/daily candidate binding mismatch",
    ):
        selector.validate_continuous_event_selection(
            _fully_rehash_selection(first_selection)
        )
