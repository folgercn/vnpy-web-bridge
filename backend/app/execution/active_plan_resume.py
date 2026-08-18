"""Pure binding checks for the narrow ACTIVE exact-plan resume boundary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from shared.commodity_execution import TargetPlan, sha256_json

from .errors import PlanRejected

TERMINAL_INTENT_STATES = frozenset({"TERMINAL", "RECONCILED", "CANCELLED"})
RESUMABLE_INTENT_STATES = frozenset(
    {
        "PERSISTED",
        "SUBMITTED",
        "ACKNOWLEDGED",
        "UNKNOWN_OUTCOME",
        *TERMINAL_INTENT_STATES,
    }
)


def expected_send_intent_bindings(
    plan: TargetPlan, *, account_scope: str, environment: str
) -> tuple[dict[str, str], ...]:
    """Derive the only send-intent identities admitted by an exact plan."""

    bindings: list[dict[str, str]] = []
    for order in plan.orders:
        intent_seed = sha256_json(
            {
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "order_ref": order.reference,
            }
        )
        intent_id = f"intent-{intent_seed[:24]}"
        idempotency_key = f"send-{intent_seed[:32]}"
        request_hash = sha256_json(order.as_dict())
        receipt_id = f"receipt-{intent_id}"
        bindings.append(
            {
                "order_ref": order.reference,
                "intent_id": intent_id,
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
                "receipt_id": receipt_id,
                "receipt_hash": sha256_json(
                    {
                        "account_scope": account_scope,
                        "environment": environment,
                        "intent_id": intent_id,
                        "idempotency_key": idempotency_key,
                        "plan_id": plan.plan_id,
                        "plan_hash": plan.plan_hash,
                        "request_hash": request_hash,
                        "action": "send",
                    }
                ),
            }
        )
    return tuple(bindings)


def _require_active_start_receipt(
    state: Mapping[str, Any], *, plan_id: str, plan_hash: str
) -> None:
    expected_plan = dict(state["plan"])
    matches = [
        receipt
        for receipt in state.get("receipts", {}).values()
        if isinstance(receipt, Mapping)
        and receipt.get("service") == "control-api"
        and receipt.get("status") == "COMPLETED"
        and isinstance(receipt.get("result"), Mapping)
        and receipt["result"].get("accepted") is True
        and receipt["result"].get("plan") == expected_plan
        and expected_plan.get("state") == "ACTIVE"
        and expected_plan.get("plan_id") == plan_id
        and expected_plan.get("plan_hash") == plan_hash
    ]
    if len(matches) != 1:
        raise PlanRejected("ACTIVE target plan lacks one exact accepted start receipt")


def require_active_resume_boundary(
    state: Mapping[str, Any],
    *,
    plan: TargetPlan,
    snapshot: Mapping[str, Any],
    account_scope: str,
    environment: str,
) -> None:
    active = state.get("plan", {})
    if (
        active.get("state") != "ACTIVE"
        or active.get("plan_id") != plan.plan_id
        or active.get("plan_hash") != plan.plan_hash
    ):
        raise PlanRejected("target plan is not the exact ACTIVE plan")
    _require_active_start_receipt(state, plan_id=plan.plan_id, plan_hash=plan.plan_hash)
    binding = snapshot["state_binding"]
    if (
        snapshot["account_scope"] != account_scope
        or snapshot["environment"] != environment
        or binding["state_version"] > state["state_version"]
        or binding["durable_broker_generation"] != state["broker"]["generation"]
    ):
        raise PlanRejected(
            "fresh reconciliation snapshot does not bind current Execution state"
        )


def _existing_intent(
    state: Mapping[str, Any],
    *,
    plan: TargetPlan,
    binding: Mapping[str, str],
) -> Mapping[str, Any] | None:
    intent_id = binding["intent_id"]
    idempotency_key = binding["idempotency_key"]
    indexed = state.get("intent_keys", {}).get(idempotency_key)
    raw = state.get("send_intents", {}).get(intent_id)
    if raw is None and indexed is None:
        return None
    if indexed != intent_id or not isinstance(raw, Mapping):
        raise PlanRejected("deterministic send-intent index binding mismatches")
    expected = {
        "intent_id": intent_id,
        "idempotency_key": idempotency_key,
        "plan_id": plan.plan_id,
        "plan_hash": plan.plan_hash,
        "action": "send",
        "request_hash": binding["request_hash"],
        "target_intent_id": None,
        "receipt_id": binding["receipt_id"],
        "receipt_hash": binding["receipt_hash"],
    }
    if any(raw.get(field) != value for field, value in expected.items()):
        raise PlanRejected("deterministic send-intent binding mismatches")
    if raw.get("state") not in RESUMABLE_INTENT_STATES:
        raise PlanRejected("deterministic send-intent state is invalid")
    return raw


def classify_active_plan_intents(
    state: Mapping[str, Any],
    *,
    plan: TargetPlan,
    bindings: tuple[dict[str, str], ...],
) -> dict[str, Mapping[str, Any] | None]:
    expected_ids = {binding["intent_id"] for binding in bindings}
    actual_ids = {
        str(intent_id)
        for intent_id, raw in state.get("send_intents", {}).items()
        if isinstance(raw, Mapping)
        and raw.get("action") == "send"
        and raw.get("plan_id") == plan.plan_id
        and raw.get("plan_hash") == plan.plan_hash
    }
    if not actual_ids.issubset(expected_ids):
        raise PlanRejected(
            "ACTIVE target plan contains a non-deterministic send intent"
        )
    return {
        binding["intent_id"]: _existing_intent(state, plan=plan, binding=binding)
        for binding in bindings
    }


def require_snapshot_order_ownership(
    snapshot: Mapping[str, Any],
    *,
    existing: Mapping[str, Mapping[str, Any] | None],
) -> None:
    known = {
        intent_id: {
            str(raw.get(field))
            for field in ("intent_id", "idempotency_key", "broker_order_id")
            if raw.get(field)
        }
        for intent_id, raw in existing.items()
        if raw is not None
    }
    for order_key, row in snapshot["active_orders"].items():
        candidates = {str(order_key)} | {
            str(row.get(field))
            for field in (
                "intent_id",
                "send_intent_id",
                "idempotency_key",
                "broker_order_id",
            )
            if row.get(field)
        }
        matches = [
            intent_id
            for intent_id, values in known.items()
            if candidates.intersection(values)
        ]
        if len(matches) != 1:
            raise PlanRejected(
                "fresh reconciliation snapshot contains a foreign active order"
            )
        raw = existing[matches[0]]
        if raw is None or raw.get("state") in TERMINAL_INTENT_STATES:
            raise PlanRejected(
                "fresh reconciliation snapshot contradicts terminal intent state"
            )


def require_snapshot_state_compatibility(
    state: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    expected_intent_ids: set[str],
    has_missing_intent: bool,
) -> None:
    binding = snapshot["state_binding"]
    if (
        binding["state_version"] == state["state_version"]
        and binding["lifecycle"] == state["lifecycle"]
        and binding["reconciliation"] == state["reconciliation"]
    ):
        return
    unknown_ids = set(state.get("unknown_outcomes", {}))
    response_loss_only = (
        not has_missing_intent
        and bool(unknown_ids)
        and unknown_ids.issubset(expected_intent_ids)
        and state.get("lifecycle") == "HALTED_UNKNOWN_OUTCOME"
        and state.get("reconciliation", {}).get("state") == "UNKNOWN"
        and state.get("reconciliation", {}).get("unknown_outcomes") == len(unknown_ids)
    )
    same_control_boundary = (
        not has_missing_intent
        and binding["lifecycle"] == state["lifecycle"]
        and binding["reconciliation"] == state["reconciliation"]
    )
    if not (response_loss_only or same_control_boundary):
        raise PlanRejected(
            "reconciliation snapshot is stale for the current resume boundary"
        )


def require_first_send_snapshot_closure(
    state: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> None:
    broker = state["broker"]
    reconciliation = state["reconciliation"]
    binding = snapshot["state_binding"]
    if (
        binding["state_version"] != state["state_version"]
        or binding["lifecycle"] != state["lifecycle"]
        or binding["reconciliation"] != reconciliation
        or state["lifecycle"] != "READY"
        or reconciliation.get("state") != "RECONCILED"
        or reconciliation.get("unknown_outcomes") != 0
        or state.get("unknown_outcomes")
        or snapshot["generation"] != broker["generation"]
        or snapshot["position_snapshot_hash"] != broker["position_snapshot_hash"]
        or snapshot["positions"] != broker["positions"]
        or snapshot["active_order_count"] != broker["active_order_count"]
        or snapshot["active_orders"] != broker["orders"]
    ):
        raise PlanRejected(
            "missing intent requires exact reconciled broker fact closure"
        )


__all__ = [
    "TERMINAL_INTENT_STATES",
    "classify_active_plan_intents",
    "expected_send_intent_bindings",
    "require_active_resume_boundary",
    "require_first_send_snapshot_closure",
    "require_snapshot_order_ownership",
    "require_snapshot_state_compatibility",
]
