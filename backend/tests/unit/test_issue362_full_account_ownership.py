from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from app.core.commodity_strategy_identity import COMMODITY_FROZEN_SECTOR_MAP_V1
from app.execution.full_account_ownership import (
    DesiredContinuousTargetBinding,
    ExpectedPredecessorCompletionBinding,
    ExpectedSameEventCloseCompletionBinding,
    FullAccountOwnershipDisposition as Disposition,
    FullAccountOwnershipReason as Reason,
    FullAccountPredecessorMode as PredecessorMode,
    classify_full_account_ownership,
    classify_same_event_close_completion,
)
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    sha256_json,
    target_position_projection_hash,
)


NOW = datetime(2026, 8, 18, 9, 0, 0, tzinfo=timezone.utc)
SCOPE = "account:windows"
ENVIRONMENT = "SIMNOW"
TERMINAL_TARGET_ID = "terminal-target-issue362-0001"
TERMINAL_TARGET_RAW_SHA256 = "7" * 64
PRODUCTS = tuple(COMMODITY_FROZEN_SECTOR_MAP_V1)
AUTHORITY_FIELDS = (
    "account_data_read",
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "network_beyond_allowlist_authorized",
    "order_authorized",
    "permit_authorized",
    "position_mutation_authorized",
    "production_authorized",
    "rpc_authorized",
    "trading_authorized",
)


def _canonical_line(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        + b"\n"
    )


def _contract(product: str, month: str = "10") -> str:
    exchange = "INE" if product == "sc" else "SHFE"
    return f"{exchange}.{product}26{month}"


def _position_rows(
    quantities: dict[str, int], contracts: dict[str, str]
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for product in PRODUCTS:
        quantity = quantities.get(product, 0)
        if not quantity:
            continue
        exchange, symbol = contracts[product].split(".")
        direction = "LONG" if quantity > 0 else "SHORT"
        result[f"{symbol}.{exchange}.{direction}.CTP.test"] = {
            "gateway_name": "CTP",
            "symbol": symbol,
            "exchange": exchange,
            "direction": direction,
            "volume": abs(quantity),
        }
    return result


def _map_sha(contracts: dict[str, str]) -> str:
    return sha256_json(
        [
            {"product": product, "exact_contract": contracts[product]}
            for product in PRODUCTS
        ]
    )


def _quantity_sha(quantities: dict[str, int]) -> str:
    return sha256_json(
        [
            {"product": product, "target_quantity": quantities[product]}
            for product in PRODUCTS
        ]
    )


def _desired(
    quantities: dict[str, int] | None = None,
    *,
    current_month: str = "12",
    trigger_kind: str = "MONTHLY_REBALANCE",
) -> tuple[DesiredContinuousTargetBinding, dict[str, dict[str, object]]]:
    quantities = {product: (quantities or {}).get(product, 0) for product in PRODUCTS}
    monthly = {product: _contract(product, "10") for product in PRODUCTS}
    previous = {product: _contract(product, "10") for product in PRODUCTS}
    current = {product: _contract(product, current_month) for product in PRODUCTS}
    final_target = {
        "schema_version": "commodity_static_core_equal_final_target_projection_v1",
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
        "execution_day": "2026-07-31",
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "targets": [
            {
                "product": product,
                "sector": COMMODITY_FROZEN_SECTOR_MAP_V1[product],
                "exact_contract": monthly[product],
                "target_quantity": quantities[product],
                "reference_open_price": 100.0,
                "multiplier": 10,
                "price_tick": 1.0,
            }
            for product in PRODUCTS
        ],
    }
    final_raw = _canonical_line(final_target)
    final_sha = sha256_json(final_target)
    static_sha = "1" * 64
    position_sha = "2" * 64
    candidate = {
        "candidate_id": "",
        "trigger_kind": trigger_kind,
        "strategy_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "execution_day": "2026-08-03",
        "source_month": "2026-07",
        "verified_daily_artifact_id": "verified-daily-artifact-0001",
        "verified_daily_artifact_raw_sha256": "3" * 64,
        "verified_daily_continuity_mode": "LINKED_ROOT_CATALOG",
        "static_core_equal_sha256": static_sha,
        "position_manager_sha256": position_sha,
        "monthly_final_target_sha256": final_sha,
        "baseline_batch_raw_sha256": "4" * 64,
        "quantity_vector_sha256": _quantity_sha(quantities),
        "monthly_target_exact_contract_map_sha256": _map_sha(monthly),
        "previous_exact_contract_map_sha256": _map_sha(previous),
        "exact_contract_map_sha256": _map_sha(current),
        "roll_preserves_integer_lots": trigger_kind == "ROLL_ONLY",
        "predecessor_terminal_target_id": (
            TERMINAL_TARGET_ID if trigger_kind == "ROLL_ONLY" else None
        ),
        "predecessor_terminal_target_raw_sha256": (
            TERMINAL_TARGET_RAW_SHA256 if trigger_kind == "ROLL_ONLY" else None
        ),
        "targets": [
            {
                "product": product,
                "monthly_target_exact_contract": monthly[product],
                "previous_exact_contract": previous[product],
                "exact_contract": current[product],
                "previous_target_quantity": (
                    quantities[product] if trigger_kind == "ROLL_ONLY" else None
                ),
                "target_quantity": quantities[product],
                "exact_contract_changed": previous[product] != current[product],
            }
            for product in PRODUCTS
        ],
    }
    candidate["candidate_id"] = f"continuous-candidate-{sha256_json(candidate)}"
    selection_sha = "5" * 64
    event = {
        "schema_version": "vnpy_continuous_event_candidate_v1",
        "event_id": "",
        "selection_id": f"continuous-selection-{selection_sha}",
        "selection_sha256": selection_sha,
        "candidate_set_sha256": "6" * 64,
        "candidate": candidate,
        "verification_status": (
            "STRUCTURAL_ONLY_CURRENT_ROOT_AND_COMPLETION_PROOF_REQUIRED"
        ),
        "event_ready": False,
        "installable": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "dispatch_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "authority": {field: False for field in AUTHORITY_FIELDS},
    }
    event["event_id"] = f"continuous-event-{sha256_json(event)}"
    event_raw = _canonical_line(event)
    return (
        DesiredContinuousTargetBinding(
            event_id=event["event_id"],
            source_event_raw=event_raw,
            source_event_raw_sha256=hashlib.sha256(event_raw).hexdigest(),
            selection_sha256=selection_sha,
            final_target_raw=final_raw,
            final_target_sha256=final_sha,
            static_core_equal_sha256=static_sha,
            position_manager_sha256=position_sha,
            lineage_final_target_sha256=final_sha,
        ),
        _position_rows(quantities, current),
    )


def _rehash_event_binding(
    binding: DesiredContinuousTargetBinding,
    mutate_candidate: Any,
) -> DesiredContinuousTargetBinding:
    event = json.loads(binding.source_event_raw)
    candidate = event["candidate"]
    mutate_candidate(candidate)
    candidate["candidate_id"] = ""
    candidate["candidate_id"] = f"continuous-candidate-{sha256_json(candidate)}"
    event["event_id"] = ""
    event["event_id"] = f"continuous-event-{sha256_json(event)}"
    raw = _canonical_line(event)
    return replace(
        binding,
        event_id=event["event_id"],
        source_event_raw=raw,
        source_event_raw_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _rehash_final_binding(
    binding: DesiredContinuousTargetBinding,
    mutate_final: Any,
) -> DesiredContinuousTargetBinding:
    final_target = json.loads(binding.final_target_raw)
    mutate_final(final_target)
    final_raw = _canonical_line(final_target)
    final_sha = sha256_json(final_target)
    event = json.loads(binding.source_event_raw)
    candidate = event["candidate"]
    candidate["monthly_final_target_sha256"] = final_sha
    candidate["candidate_id"] = ""
    candidate["candidate_id"] = f"continuous-candidate-{sha256_json(candidate)}"
    event["event_id"] = ""
    event["event_id"] = f"continuous-event-{sha256_json(event)}"
    event_raw = _canonical_line(event)
    return replace(
        binding,
        event_id=event["event_id"],
        source_event_raw=event_raw,
        source_event_raw_sha256=hashlib.sha256(event_raw).hexdigest(),
        final_target_raw=final_raw,
        final_target_sha256=final_sha,
        lineage_final_target_sha256=final_sha,
    )


def _facts(
    positions: dict[str, dict[str, object]] | None = None,
    *,
    observed_at: datetime = NOW,
    lifecycle: str = "READY",
    reconciliation_state: str = "RECONCILED",
    unknown_outcomes: int = 0,
    active_orders: dict[str, dict[str, object]] | None = None,
    plan_state: str = "IDLE",
    send_intents: dict[str, dict[str, object]] | None = None,
    schema_version: str = "web_bridge_execution_account_facts_v2",
) -> dict[str, Any]:
    position_rows = deepcopy({} if positions is None else positions)
    order_rows = deepcopy({} if active_orders is None else active_orders)
    intents = deepcopy({} if send_intents is None else send_intents)
    timestamp = observed_at.isoformat().replace("+00:00", "Z")
    position_hash = sha256_json(position_rows)
    order_hash = sha256_json(order_rows)
    nonterminal = sum(
        row["state"] not in {"RECONCILED", "CANCELLED", "TERMINAL"}
        for row in intents.values()
    )
    preimage = {
        "schema_version": schema_version,
        "service": "execution-orchestrator",
        "service_version": "test",
        "account_scope": SCOPE,
        "environment": ENVIRONMENT,
        "snapshot_id": "snapshot-issue362-ownership-0001",
        "generation": 7,
        "observed_at": timestamp,
        "connected": True,
        "fresh": True,
        "position_snapshot_hash": position_hash,
        "positions": position_rows,
        "active_order_count": len(order_rows),
        "active_orders_sha256": order_hash,
        "active_orders": order_rows,
        "status_binding": {
            "status_schema_version": "web_bridge_execution_status_v1",
            "state_version": 11,
            "status_observed_at": timestamp,
            "lifecycle": lifecycle,
            "reconciliation": {
                "state": reconciliation_state,
                "run_id": "issue362-reconcile-0001",
                "last_completed_at": timestamp,
                "unknown_outcomes": unknown_outcomes,
                "fresh_snapshot_id": "snapshot-issue362-ownership-0001",
            },
            "broker": {
                "connected": True,
                "generation": 7,
                "active_order_count": len(order_rows),
                "position_snapshot_hash": position_hash,
                "last_snapshot_at": timestamp,
            },
            "durable_active_orders_sha256": order_hash,
            "durable_positions_sha256": position_hash,
            "snapshot_identity_mode": "GENERATION_FACT_HASH_EQUIVALENT",
        },
    }
    if schema_version.endswith("v2"):
        preimage["execution_binding"] = {
            "state_version": 11,
            "plan_state": plan_state,
            "send_intents": intents,
            "send_intents_sha256": sha256_json(intents),
            "nonterminal_send_intent_count": nonterminal,
        }
    return {**preimage, "account_facts_sha256": sha256_json(preimage)}


def _v3_send_intent() -> dict[str, Any]:
    return {
        "intent_id": "intent-issue421-0001",
        "idempotency_key": "idempotency-issue421-0001",
        "state": "RECONCILED",
        "plan_id": "plan-issue421-0001",
        "plan_hash": "a" * 64,
        "leader_epoch": 1,
        "fencing_token": 1,
        "created_at": "2026-08-18T09:00:00Z",
        "execution_start_quote_proof": {"opaque": True},
        "execution_start_quote_proof_sha256": "b" * 64,
    }


def test_account_facts_v2_accepts_legacy_send_intent_without_start_quote_proof():
    from app.schemas.control_execution import ExecutionAccountFactsProjectionV2

    facts = _facts(send_intents={"intent-issue421-0001": _v3_send_intent()})
    del facts["execution_binding"]["send_intents"][
        "intent-issue421-0001"
    ]["execution_start_quote_proof"]
    del facts["execution_binding"]["send_intents"][
        "intent-issue421-0001"
    ]["execution_start_quote_proof_sha256"]
    facts["execution_binding"]["send_intents_sha256"] = sha256_json(
        facts["execution_binding"]["send_intents"]
    )
    facts["account_facts_sha256"] = sha256_json(
        {key: value for key, value in facts.items() if key != "account_facts_sha256"}
    )

    ExecutionAccountFactsProjectionV2.from_mapping(facts)


def test_account_facts_v2_accepts_send_intent_with_start_quote_proof():
    from app.schemas.control_execution import ExecutionAccountFactsProjectionV2

    facts = _facts(send_intents={"intent-issue421-0001": _v3_send_intent()})

    ExecutionAccountFactsProjectionV2.from_mapping(facts)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda intent: intent.pop("execution_start_quote_proof"),
        lambda intent: intent.pop("execution_start_quote_proof_sha256"),
        lambda intent: intent.update(
            execution_start_quote_proof_sha256="not-a-sha256"
        ),
        lambda intent: intent.update(unexpected_v3_field=True),
    ],
)
def test_account_facts_v2_rejects_invalid_send_intent_start_quote_fields(mutation):
    from app.schemas.control_execution import ExecutionAccountFactsProjectionV2

    intent = _v3_send_intent()
    mutation(intent)
    facts = _facts(send_intents={"intent-issue421-0001": intent})

    with pytest.raises(ValueError, match="send intents are invalid"):
        ExecutionAccountFactsProjectionV2.from_mapping(facts)


def _completion(
    positions: dict[str, dict[str, object]],
    *,
    desired: DesiredContinuousTargetBinding | None = None,
    phase: str = "OPEN",
    suffix: str = "1",
) -> dict[str, Any]:
    target_hash = target_position_projection_hash(
        positions, account_scope=SCOPE, environment=ENVIRONMENT
    )
    return {
        "plan_id": f"static-core-full-{phase.lower()}-ownership-000{suffix}",
        "plan_hash": suffix * 64,
        "schema_version": KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        "phase": phase,
        "lineage": {
            "static_core_equal_sha256": (
                desired.static_core_equal_sha256 if desired else "1" * 64
            ),
            "position_manager_sha256": (
                desired.position_manager_sha256 if desired else "2" * 64
            ),
            "final_target_sha256": (
                desired.lineage_final_target_sha256 if desired else "3" * 64
            ),
        },
        "expected_after_position_hash": target_hash,
        "target_position_hash": target_hash,
        "archived_at": "2026-08-18T08:59:00Z",
    }


def _same_event_close_expected(
    desired: DesiredContinuousTargetBinding,
    *,
    before_positions: dict[str, dict[str, object]],
    after_positions: dict[str, dict[str, object]],
) -> tuple[ExpectedSameEventCloseCompletionBinding, dict[str, Any]]:
    before_hash = target_position_projection_hash(
        before_positions, account_scope=SCOPE, environment=ENVIRONMENT
    )
    after_hash = target_position_projection_hash(
        after_positions, account_scope=SCOPE, environment=ENVIRONMENT
    )
    recovery = {
        "schema_version": "web_bridge_execution_target_plan_recovery_v3",
        "state": "INSTALLED",
        "custody_idempotency_key": "issue362-same-event-close-0001",
        "custody_install_idempotency_key": ("install-issue362-same-event-close-0001"),
        "custody_version": 12,
        "receipt_id": "receipt-issue362-same-event-close-0001",
        "receipt_sha256": "8" * 64,
        "artifact_id": "artifact-issue362-same-event-close-0001",
        "artifact_sha256": "9" * 64,
        "artifact_envelope_sha256": "a" * 64,
        "installed": True,
        "target_plan_schema_version": KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        "plan_id": "static-core-full-close-same-event-0001",
        "plan_hash": "b" * 64,
        "phase": "CLOSE",
        "lineage": {
            "static_core_equal_sha256": desired.static_core_equal_sha256,
            "position_manager_sha256": desired.position_manager_sha256,
            "final_target_sha256": desired.lineage_final_target_sha256,
        },
        "account_scope": SCOPE,
        "environment": ENVIRONMENT,
        "gateway_name": "CTP",
        "generated_at": "2026-08-18T08:57:00Z",
        "expires_at": "2026-08-18T09:07:00Z",
        "expected_before_position_hash": before_hash,
        "expected_after_position_hash": after_hash,
        "order_set_sha256": "c" * 64,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "execution_run_id": "execution-run-same-event-close-0001",
        "creation_quote_proof_sha256": "d" * 64,
        "start_quote_proof_state": "STARTED_MATCHED",
        "start_quote_proof_sha256": "e" * 64,
        "can_start_same_plan": False,
    }
    recovery["recovery_sha256"] = sha256_json(recovery)
    recovery_raw = _canonical_line(recovery)
    return (
        ExpectedSameEventCloseCompletionBinding(
            installed_event_id=desired.event_id,
            installed_event_raw_sha256=desired.source_event_raw_sha256,
            close_recovery_raw=recovery_raw,
            close_recovery_raw_sha256=hashlib.sha256(recovery_raw).hexdigest(),
        ),
        recovery,
    )


def _same_event_close_completion_raw(
    recovery: dict[str, Any],
    *,
    archived_at: str = "2026-08-18T08:59:00Z",
) -> bytes:
    return _canonical_line(
        {
            "plan_id": recovery["plan_id"],
            "plan_hash": recovery["plan_hash"],
            "schema_version": recovery["target_plan_schema_version"],
            "phase": "CLOSE",
            "lineage": recovery["lineage"],
            "expected_after_position_hash": recovery["expected_after_position_hash"],
            "target_position_hash": recovery["expected_after_position_hash"],
            "archived_at": archived_at,
            "execution_run_id": recovery["execution_run_id"],
            "creation_quote_proof_sha256": recovery["creation_quote_proof_sha256"],
            "start_quote_proof_sha256": recovery["start_quote_proof_sha256"],
        }
    )


def _expected(
    completion: dict[str, Any],
    *,
    terminal_target_id: str | None,
    terminal_target_raw_sha256: str | None,
) -> ExpectedPredecessorCompletionBinding:
    lineage = completion["lineage"]
    return ExpectedPredecessorCompletionBinding(
        canonical_completion_sha256=sha256_json(completion),
        plan_id=completion["plan_id"],
        plan_hash=completion["plan_hash"],
        phase=completion["phase"],
        static_core_equal_sha256=lineage["static_core_equal_sha256"],
        position_manager_sha256=lineage["position_manager_sha256"],
        final_target_sha256=lineage["final_target_sha256"],
        target_position_hash=completion["target_position_hash"],
        terminal_target_id=terminal_target_id,
        terminal_target_raw_sha256=terminal_target_raw_sha256,
    )


def _roll_expected(
    completion: dict[str, Any],
    desired: DesiredContinuousTargetBinding,
) -> ExpectedPredecessorCompletionBinding:
    candidate = json.loads(desired.source_event_raw)["candidate"]
    return _expected(
        completion,
        terminal_target_id=candidate["predecessor_terminal_target_id"],
        terminal_target_raw_sha256=candidate["predecessor_terminal_target_raw_sha256"],
    )


def _classify(
    *,
    facts: dict[str, Any] | None = None,
    desired: DesiredContinuousTargetBinding | None = None,
    mode: PredecessorMode = PredecessorMode.GENESIS_FLAT,
    expected: ExpectedPredecessorCompletionBinding | None = None,
    completion: Any = None,
):
    if desired is None:
        desired = _desired()[0]
    return classify_full_account_ownership(
        account_facts=_facts() if facts is None else facts,
        predecessor_mode=mode,
        expected_predecessor=expected,
        completion=completion,
        desired_target=desired,
        now=NOW,
    )


class _CompletionMustNotBeRead:
    def __getattribute__(self, name: str) -> Any:
        raise AssertionError(f"completion read before facts stopped: {name}")


def test_facts_are_fully_rejected_before_completion_is_read() -> None:
    result = _classify(
        facts=_facts(plan_state="ACTIVE"),
        mode=PredecessorMode.COMPLETION,
        completion=_CompletionMustNotBeRead(),
    )
    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.ACCOUNT_PLAN_NOT_TERMINAL


def test_explicit_flat_genesis_admits_new_or_already_satisfied_target() -> None:
    desired, _ = _desired({"ag": 1})
    new = _classify(desired=desired)
    flat_desired, _ = _desired({})
    satisfied = _classify(desired=flat_desired)

    assert new.disposition is Disposition.NEW_TARGET
    assert new.reason_code is Reason.GENESIS_FLAT_NEW_TARGET
    assert satisfied.disposition is Disposition.ALREADY_SATISFIED
    assert satisfied.reason_code is Reason.GENESIS_FLAT_ALREADY_SATISFIED


def test_missing_completion_never_falls_back_to_genesis_or_nonflat_satisfied() -> None:
    desired, positions = _desired({"ag": 1})
    predecessor = _completion(positions, desired=desired)
    expected = _expected(
        predecessor,
        terminal_target_id=TERMINAL_TARGET_ID,
        terminal_target_raw_sha256=TERMINAL_TARGET_RAW_SHA256,
    )

    missing = _classify(
        facts=_facts(positions),
        desired=desired,
        mode=PredecessorMode.COMPLETION,
        expected=expected,
        completion=None,
    )
    false_genesis = _classify(facts=_facts(positions), desired=desired)

    assert missing.reason_code is Reason.COMPLETION_MISSING
    assert false_genesis.reason_code is Reason.GENESIS_ACCOUNT_NOT_FLAT


def test_exact_predecessor_binding_admits_next_target() -> None:
    prior_desired, prior_positions = _desired({"ag": 1}, current_month="10")
    next_desired, _ = _desired({"ag": 2}, current_month="12")
    completion = _completion(prior_positions, desired=prior_desired)
    result = _classify(
        facts=_facts(prior_positions),
        desired=next_desired,
        mode=PredecessorMode.COMPLETION,
        expected=_expected(
            completion,
            terminal_target_id=TERMINAL_TARGET_ID,
            terminal_target_raw_sha256=TERMINAL_TARGET_RAW_SHA256,
        ),
        completion=completion,
    )
    assert result.disposition is Disposition.NEW_TARGET
    assert result.reason_code is Reason.PREDECESSOR_TARGET_MATCHED


def test_completion_expected_binding_requires_independent_terminal_root_pins() -> None:
    desired, positions = _desired({"ag": 1})
    completion = _completion(positions, desired=desired)
    expected_without_root_pins = _expected(
        completion,
        terminal_target_id=None,
        terminal_target_raw_sha256=None,
    )

    result = _classify(
        facts=_facts(positions),
        desired=desired,
        mode=PredecessorMode.COMPLETION,
        expected=expected_without_root_pins,
        completion=completion,
    )

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.EXPECTED_PREDECESSOR_INVALID


def test_foreign_or_stale_completion_binding_stops() -> None:
    desired, positions = _desired({"ag": 1})
    expected_completion = _completion(positions, desired=desired, suffix="1")
    foreign = _completion(positions, desired=desired, suffix="2")
    result = _classify(
        facts=_facts(positions),
        desired=desired,
        mode=PredecessorMode.COMPLETION,
        expected=_expected(
            expected_completion,
            terminal_target_id=TERMINAL_TARGET_ID,
            terminal_target_raw_sha256=TERMINAL_TARGET_RAW_SHA256,
        ),
        completion=foreign,
    )
    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.COMPLETION_BINDING_MISMATCH


def test_completed_match_and_fresh_position_drift() -> None:
    desired, positions = _desired({"ag": 1})
    completion = _completion(positions, desired=desired)
    expected = _expected(
        completion,
        terminal_target_id=TERMINAL_TARGET_ID,
        terminal_target_raw_sha256=TERMINAL_TARGET_RAW_SHA256,
    )
    matched = _classify(
        facts=_facts(positions),
        desired=desired,
        mode=PredecessorMode.COMPLETION,
        expected=expected,
        completion=completion,
    )
    drifted = _position_rows(
        {product: (2 if product == "ag" else 0) for product in PRODUCTS},
        {product: _contract(product, "12") for product in PRODUCTS},
    )
    mismatch = _classify(
        facts=_facts(drifted),
        desired=desired,
        mode=PredecessorMode.COMPLETION,
        expected=expected,
        completion=completion,
    )
    assert matched.disposition is Disposition.ALREADY_COMPLETED_MATCHED
    assert matched.reason_code is Reason.COMPLETED_TARGET_ALREADY_MATCHED
    assert mismatch.reason_code is Reason.COMPLETED_TARGET_POSITION_MISMATCH


def test_close_completion_zero_mutation_or_exact_boundary_resume() -> None:
    boundary_desired, boundary = _desired({"ag": 1}, current_month="10")
    completion = _completion(boundary, desired=boundary_desired, phase="CLOSE")
    expected = _expected(
        completion,
        terminal_target_id=TERMINAL_TARGET_ID,
        terminal_target_raw_sha256=TERMINAL_TARGET_RAW_SHA256,
    )
    done = _classify(
        facts=_facts(boundary),
        desired=boundary_desired,
        mode=PredecessorMode.COMPLETION,
        expected=expected,
        completion=completion,
    )
    next_desired, _ = _desired({"ag": 1}, current_month="12")
    resume = _classify(
        facts=_facts(boundary),
        desired=next_desired,
        mode=PredecessorMode.COMPLETION,
        expected=expected,
        completion=completion,
    )
    mismatch = _classify(
        facts=_facts({}),
        desired=next_desired,
        mode=PredecessorMode.COMPLETION,
        expected=expected,
        completion=completion,
    )
    assert done.disposition is Disposition.ALREADY_COMPLETED_MATCHED
    assert done.reason_code is Reason.CLOSE_COMPLETION_TARGET_ALREADY_SATISFIED
    assert resume.disposition is Disposition.RESUME_AFTER_CLOSE
    assert resume.reason_code is Reason.CLOSE_COMPLETION_BOUNDARY_MATCHED
    assert mismatch.reason_code is Reason.COMPLETED_TARGET_POSITION_MISMATCH


def test_same_event_close_requires_valid_fresh_rooted_boundary() -> None:
    old_desired, before = _desired({"ag": 1}, current_month="10")
    del old_desired
    desired, _ = _desired({"ag": 1}, current_month="12")
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )

    result = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=expected,
        completion_raw=_same_event_close_completion_raw(recovery),
        desired_target=desired,
        now=NOW,
    )

    assert result.disposition is Disposition.RESUME_AFTER_CLOSE
    assert result.reason_code is Reason.CLOSE_COMPLETION_BOUNDARY_MATCHED
    assert (
        result.predecessor_target_position_hash
        == recovery["expected_after_position_hash"]
    )


def test_same_event_close_only_target_is_terminal_not_open_authority() -> None:
    old_desired, before = _desired({"ag": 1}, current_month="10")
    del old_desired
    desired, _ = _desired({})
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )

    result = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=expected,
        completion_raw=_same_event_close_completion_raw(recovery),
        desired_target=desired,
        now=NOW,
    )

    assert result.disposition is Disposition.ALREADY_COMPLETED_MATCHED
    assert result.reason_code is Reason.CLOSE_COMPLETION_TARGET_ALREADY_SATISFIED
    assert not hasattr(result, "target_plan")
    assert not hasattr(result, "open_authorized")


def test_same_event_close_foreign_or_noncanonical_completion_stops() -> None:
    _old_desired, before = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired({"ag": 1}, current_month="12")
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )
    foreign = json.loads(_same_event_close_completion_raw(recovery))
    foreign["plan_id"] = "static-core-full-close-foreign-event-0001"
    foreign_raw = _canonical_line(foreign)
    noncanonical_raw = json.dumps(foreign, indent=2, sort_keys=True).encode()

    foreign_result = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=expected,
        completion_raw=foreign_raw,
        desired_target=desired,
        now=NOW,
    )
    noncanonical_result = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=expected,
        completion_raw=noncanonical_raw,
        desired_target=desired,
        now=NOW,
    )

    assert foreign_result.reason_code is Reason.COMPLETION_BINDING_MISMATCH
    assert noncanonical_result.reason_code is Reason.COMPLETION_INVALID


def test_same_event_close_missing_or_foreign_installed_event_root_stops() -> None:
    _old_desired, before = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired({"ag": 1}, current_month="12")
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )
    missing = replace(expected, installed_event_raw_sha256=None)  # type: ignore[arg-type]
    foreign = replace(expected, installed_event_id="continuous-event-foreign-root")

    missing_result = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=missing,
        completion_raw=_same_event_close_completion_raw(recovery),
        desired_target=desired,
        now=NOW,
    )
    foreign_result = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=foreign,
        completion_raw=_same_event_close_completion_raw(recovery),
        desired_target=desired,
        now=NOW,
    )

    assert missing_result.reason_code is Reason.SAME_EVENT_CLOSE_EXPECTED_INVALID
    assert foreign_result.reason_code is Reason.SAME_EVENT_CLOSE_EVENT_ROOT_MISMATCH


def test_same_event_close_fully_rehashed_recovery_lineage_stops() -> None:
    _old_desired, before = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired({"ag": 1}, current_month="12")
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )
    rehashed = json.loads(expected.close_recovery_raw)
    rehashed["lineage"]["final_target_sha256"] = "f" * 64
    rehashed["recovery_sha256"] = sha256_json(
        {key: value for key, value in rehashed.items() if key != "recovery_sha256"}
    )
    rehashed_raw = _canonical_line(rehashed)
    tampered_expected = replace(
        expected,
        close_recovery_raw=rehashed_raw,
        close_recovery_raw_sha256=hashlib.sha256(rehashed_raw).hexdigest(),
    )

    result = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=tampered_expected,
        completion_raw=_same_event_close_completion_raw(recovery),
        desired_target=desired,
        now=NOW,
    )

    assert result.reason_code is Reason.SAME_EVENT_CLOSE_RECOVERY_BINDING_MISMATCH


def test_same_event_close_stale_facts_or_current_position_drift_stops() -> None:
    _old_desired, before = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired({"ag": 1}, current_month="12")
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )
    completion_raw = _same_event_close_completion_raw(recovery)

    stale = classify_same_event_close_completion(
        account_facts=_facts({}, observed_at=NOW - timedelta(seconds=61)),
        expected_close=expected,
        completion_raw=completion_raw,
        desired_target=desired,
        now=NOW,
    )
    drifted = classify_same_event_close_completion(
        account_facts=_facts(before),
        expected_close=expected,
        completion_raw=completion_raw,
        desired_target=desired,
        now=NOW,
    )

    assert stale.reason_code is Reason.ACCOUNT_FACTS_STALE
    assert drifted.reason_code is Reason.COMPLETED_TARGET_POSITION_MISMATCH


@pytest.mark.parametrize(
    ("facts", "reason"),
    [
        (
            _facts(schema_version="web_bridge_execution_account_facts_v1"),
            Reason.ACCOUNT_FACTS_V2_REQUIRED,
        ),
        (_facts(unknown_outcomes=1), Reason.ACCOUNT_UNKNOWN_OUTCOMES),
        (
            _facts(
                active_orders={
                    "same-event-active-order-0001": {
                        "gateway_name": "CTP",
                        "symbol": "ag2610",
                    }
                }
            ),
            Reason.ACCOUNT_ACTIVE_ORDERS,
        ),
        (
            _facts(
                send_intents={
                    "same-event-pending-intent-0001": {
                        "intent_id": "same-event-pending-intent-0001",
                        "state": "PERSISTED",
                    }
                }
            ),
            Reason.ACCOUNT_SEND_INTENTS_PENDING,
        ),
    ],
)
def test_same_event_close_requires_v2_zero_open_execution_state(
    facts: dict[str, Any], reason: Reason
) -> None:
    _old_desired, before = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired({"ag": 1}, current_month="12")
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )

    result = classify_same_event_close_completion(
        account_facts=facts,
        expected_close=expected,
        completion_raw=_same_event_close_completion_raw(recovery),
        desired_target=desired,
        now=NOW,
    )

    assert result.disposition is Disposition.STOP
    assert result.reason_code is reason


def test_same_event_close_rejects_fully_rehashed_actual_proof_and_future_archive() -> (
    None
):
    _old_desired, before = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired({"ag": 1}, current_month="12")
    expected, recovery = _same_event_close_expected(
        desired,
        before_positions=before,
        after_positions={},
    )
    proof_changed = json.loads(_same_event_close_completion_raw(recovery))
    proof_changed["start_quote_proof_sha256"] = "f" * 64

    wrong_proof = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=expected,
        completion_raw=_canonical_line(proof_changed),
        desired_target=desired,
        now=NOW,
    )
    future_archive = classify_same_event_close_completion(
        account_facts=_facts({}),
        expected_close=expected,
        completion_raw=_same_event_close_completion_raw(
            recovery, archived_at="2026-08-18T09:00:31Z"
        ),
        desired_target=desired,
        now=NOW,
    )

    assert wrong_proof.reason_code is Reason.COMPLETION_BINDING_MISMATCH
    assert future_archive.reason_code is Reason.COMPLETION_BINDING_MISMATCH


@pytest.mark.parametrize(
    ("facts", "reason"),
    [
        (
            _facts(schema_version="web_bridge_execution_account_facts_v1"),
            Reason.ACCOUNT_FACTS_V2_REQUIRED,
        ),
        (_facts(lifecycle="EXECUTING"), Reason.ACCOUNT_NOT_READY),
        (_facts(unknown_outcomes=1), Reason.ACCOUNT_UNKNOWN_OUTCOMES),
        (_facts(reconciliation_state="REQUIRED"), Reason.ACCOUNT_NOT_RECONCILED),
        (
            _facts(
                send_intents={
                    "pending-intent-0001": {
                        "intent_id": "pending-intent-0001",
                        "state": "PERSISTED",
                    }
                }
            ),
            Reason.ACCOUNT_SEND_INTENTS_PENDING,
        ),
        (
            _facts(
                active_orders={
                    "foreign-order-0001": {
                        "gateway_name": "CTP",
                        "symbol": "i2609",
                    }
                }
            ),
            Reason.ACCOUNT_ACTIVE_ORDERS,
        ),
        (
            _facts(observed_at=NOW - timedelta(seconds=61)),
            Reason.ACCOUNT_FACTS_STALE,
        ),
    ],
)
def test_unready_or_v1_facts_stop(facts: dict[str, Any], reason: Reason) -> None:
    result = _classify(facts=facts)
    assert result.disposition is Disposition.STOP
    assert result.reason_code is reason


def test_foreign_positions_and_fact_hash_drift_stop() -> None:
    foreign = {
        "i2609.DCE.LONG.CTP.foreign": {
            "gateway_name": "CTP",
            "symbol": "i2609",
            "exchange": "DCE",
            "direction": "LONG",
            "volume": 1,
        }
    }
    outside = _classify(facts=_facts(foreign))
    broken = _facts()
    broken["position_snapshot_hash"] = "f" * 64
    broken["account_facts_sha256"] = sha256_json(
        {key: value for key, value in broken.items() if key != "account_facts_sha256"}
    )
    invalid = _classify(facts=broken)
    assert outside.reason_code is Reason.ACCOUNT_POSITION_OUTSIDE_FROZEN_UNIVERSE
    assert invalid.reason_code is Reason.ACCOUNT_FACTS_INVALID


def test_desired_source_event_and_monthly_target_cross_splices_stop() -> None:
    desired, _ = _desired({"ag": 1})
    event_tampered = deepcopy(desired)
    object.__setattr__(event_tampered, "selection_sha256", "f" * 64)
    final_tampered = deepcopy(desired)
    object.__setattr__(final_tampered, "final_target_sha256", "e" * 64)

    assert _classify(desired=event_tampered).reason_code is (
        Reason.DESIRED_TARGET_BINDING_INVALID
    )
    assert _classify(desired=final_tampered).reason_code is (
        Reason.DESIRED_TARGET_BINDING_INVALID
    )


def test_roll_only_never_uses_genesis_flat() -> None:
    desired, _ = _desired(
        {"ag": 1},
        current_month="12",
        trigger_kind="ROLL_ONLY",
    )

    result = _classify(desired=desired)

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.ROLL_ONLY_REQUIRES_COMPLETION


def test_roll_completion_and_terminal_pins_are_admitted() -> None:
    prior_desired, prior_positions = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired(
        {"ag": 1},
        current_month="12",
        trigger_kind="ROLL_ONLY",
    )
    completion = _completion(prior_positions, desired=prior_desired)

    result = _classify(
        facts=_facts(prior_positions),
        desired=desired,
        mode=PredecessorMode.COMPLETION,
        expected=_roll_expected(completion, desired),
        completion=completion,
    )

    assert result.disposition is Disposition.NEW_TARGET
    assert result.reason_code is Reason.PREDECESSOR_TARGET_MATCHED


@pytest.mark.parametrize(
    ("field", "different_value"),
    [
        ("predecessor_terminal_target_id", "different-terminal-target-0001"),
        ("predecessor_terminal_target_raw_sha256", "8" * 64),
    ],
)
def test_fully_rehashed_roll_only_different_terminal_pin_stops(
    field: str,
    different_value: str,
) -> None:
    prior_desired, prior_positions = _desired({"ag": 1}, current_month="10")
    desired, _ = _desired(
        {"ag": 1},
        current_month="12",
        trigger_kind="ROLL_ONLY",
    )
    expected = _roll_expected(
        _completion(prior_positions, desired=prior_desired),
        desired,
    )
    tampered = _rehash_event_binding(
        desired,
        lambda candidate: candidate.__setitem__(field, different_value),
    )
    completion = _completion(prior_positions, desired=prior_desired)

    result = _classify(
        facts=_facts(prior_positions),
        desired=tampered,
        mode=PredecessorMode.COMPLETION,
        expected=expected,
        completion=completion,
    )

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.PREDECESSOR_TERMINAL_PIN_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("verified_daily_continuity_mode", "GENESIS_STATIC_CORE_EQUAL"),
        ("predecessor_terminal_target_id", None),
        ("predecessor_terminal_target_id", "foreign:terminal-target-0001"),
        ("predecessor_terminal_target_raw_sha256", None),
        ("predecessor_terminal_target_raw_sha256", "F" * 64),
        ("roll_preserves_integer_lots", False),
    ],
)
def test_fully_rehashed_roll_only_trigger_shape_mismatch_stops(
    field: str,
    value: object,
) -> None:
    desired, _ = _desired(
        {"ag": 1},
        current_month="12",
        trigger_kind="ROLL_ONLY",
    )
    tampered = _rehash_event_binding(
        desired,
        lambda candidate: candidate.__setitem__(field, value),
    )

    result = _classify(desired=tampered)

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.DESIRED_TARGET_BINDING_INVALID


def test_fully_rehashed_roll_only_without_contract_change_stops() -> None:
    desired, _ = _desired(
        {"ag": 1},
        current_month="10",
        trigger_kind="ROLL_ONLY",
    )

    result = _classify(desired=desired)

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.DESIRED_TARGET_BINDING_INVALID


@pytest.mark.parametrize(
    ("predecessor_id", "predecessor_sha"),
    [
        ("foreign-terminal-target-0001", "8" * 64),
        ("foreign-terminal-target-0001", None),
        (None, "8" * 64),
    ],
)
def test_fully_rehashed_monthly_foreign_predecessor_stops(
    predecessor_id: str | None,
    predecessor_sha: str | None,
) -> None:
    desired, _ = _desired({"ag": 1})

    def mutate(candidate: dict[str, Any]) -> None:
        candidate["predecessor_terminal_target_id"] = predecessor_id
        candidate["predecessor_terminal_target_raw_sha256"] = predecessor_sha

    tampered = _rehash_event_binding(desired, mutate)
    result = _classify(desired=tampered)

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.DESIRED_TARGET_BINDING_INVALID


def test_fully_rehashed_final_target_source_month_cross_splice_stops() -> None:
    desired, _ = _desired({"ag": 1})
    tampered = _rehash_final_binding(
        desired,
        lambda final: final.__setitem__("source_month", "2026-06"),
    )

    result = _classify(desired=tampered)

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.DESIRED_TARGET_BINDING_INVALID


def test_fully_rehashed_final_target_must_precede_daily_execution_day() -> None:
    desired, _ = _desired({"ag": 1})
    tampered = _rehash_final_binding(
        desired,
        lambda final: final.__setitem__("execution_day", "2026-08-03"),
    )

    result = _classify(desired=tampered)

    assert result.disposition is Disposition.STOP
    assert result.reason_code is Reason.DESIRED_TARGET_BINDING_INVALID
