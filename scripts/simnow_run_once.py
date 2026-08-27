"""One fixed-tuple SIMNOW run: STATIC_CORE_EQUAL -> custody -> Execution.

The runner has no gateway/RPC import.  It uses the existing read-only facts,
Phase-C custody client and private Execution command client only.  A held
Execution leader lease is required before ``start``; this script never creates
or bypasses a leader/fence.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.control_execution_client import (  # noqa: E402
    ExecutionClient,
    ExecutionClientError,
)
from app.execution.models import CommandEnvelope  # noqa: E402
from app.execution.executable_target_adapter import (  # noqa: E402
    _contract,
    _without_terminal_execution_orders,
    build_static_core_equal_keyless_safety_flat_decision,
    build_static_core_equal_keyless_target_decision,
    peek_current_facts_to_snapshot,
)
from app.phase_c.client import RemotePhaseCWorkflowClient  # noqa: E402
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO  # noqa: E402
from commodity_relative_vol_snapshot_producer import (  # noqa: E402
    SnapshotProducerError,
    produce_snapshot as produce_position_manager_snapshot,
)
from commodity_static_core_equal_pure_producer import (  # noqa: E402
    StaticCoreEqualProducerError,
    produce_research_artifacts as produce_static_core_equal,
)
from simnow_keyless_pilot import (  # noqa: E402
    _fresh_utc,
    _formal_tick_binding,
    _require_tick_boundary,
    _require_same_execution_binding,
    _utc_clock,
)

from shared.trust_contracts.v1 import (  # noqa: E402
    ContractError,
    canonical_json_line,
)
from shared.commodity_execution import (  # noqa: E402
    before_position_projection_hash,
)

_TERMINAL_INTENT_STATES = frozenset({"TERMINAL", "RECONCILED", "CANCELLED"})


def _safety_flat_protected_tick_price(
    snapshot: Mapping[str, Any], *, product: str
) -> tuple[float, tuple[str, str, int, str, str, float], str, str]:
    """Derive the one reduce-only close price from the formal tick journal."""

    targets = snapshot.get("targets")
    if not isinstance(targets, list):
        raise ValueError("position-manager targets are invalid for SAFETY FLAT")
    rows = [row for row in targets if isinstance(row, Mapping) and row.get("product") == product]
    if len(rows) != 1:
        raise ValueError("selected SAFETY FLAT target is not unique")
    row = rows[0]
    target_quantity = row.get("shadow_target_quantity")
    exact_contract = row.get("exact_contract")
    price_tick = row.get("price_tick")
    if (
        isinstance(target_quantity, bool)
        or not isinstance(target_quantity, int)
        or target_quantity == 0
        or not isinstance(exact_contract, str)
    ):
        raise ValueError("selected SAFETY FLAT target is invalid")
    try:
        exchange, symbol = _contract(exact_contract)
    except Exception as exc:  # noqa: BLE001 - adapter owns canonical contract grammar
        raise ValueError("selected SAFETY FLAT contract is invalid") from exc
    try:
        tick = Decimal(str(price_tick))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("selected SAFETY FLAT price tick is invalid") from exc
    if not tick.is_finite() or tick <= 0:
        raise ValueError("selected SAFETY FLAT price tick is invalid")
    vt_symbol = f"{symbol}.{exchange}"
    price_field = "ask" if target_quantity < 0 else "bid"
    binding = _formal_tick_binding(
        clock=_utc_clock, vt_symbol=vt_symbol, price_field=price_field
    )
    try:
        quote = Decimal(str(binding[5]))
    except (InvalidOperation, ValueError) as exc:  # pragma: no cover - verifier validates
        raise ValueError("formal CTP protected quote is invalid") from exc
    protected = quote + tick if price_field == "ask" else quote - tick
    if not protected.is_finite() or protected <= 0 or protected % tick != 0:
        raise ValueError("formal CTP protected close price is invalid")
    return float(protected), binding, vt_symbol, price_field


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not isinstance(value, dict) or canonical_json_line(value) != raw:
        raise ValueError(f"{label} must be canonical JSON")
    return value


def _source_bytes(path: Path, label: str) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{label} cannot be read") from exc
    if not raw:
        raise ValueError(f"{label} is empty")
    return raw


def _generated_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not isinstance(value, dict) or canonical_json_line(value) != raw + b"\n":
        raise ValueError(f"{label} is not canonical JSON")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _command(
    *, name: str, suffix: str, version: int, actor: dict[str, str], payload: dict[str, Any], now: str, fence: dict[str, int] | None = None
) -> dict[str, Any]:
    expected: dict[str, Any] = {"state_version": version}
    if fence is not None:
        expected.update(fence)
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": f"simnow-run-once-{suffix}",
        "idempotency_key": f"simnow-run-once-{suffix}",
        "correlation_id": f"simnow-run-once-{suffix}",
        "issued_at": now,
        "actor": actor,
        "command": name,
        "expected": expected,
        "payload": payload,
    }


async def _submit_reconcile_with_ready_snapshot(
    execution: ExecutionClient,
    *,
    suffix: str,
    version: int,
    actor: Mapping[str, str],
    now: str,
    reconciliation_run_id: str,
    reason: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Submit reconciliation bound to one fresh full-facts snapshot."""

    try:
        projection = await execution.reconciliation_snapshot()
    except ExecutionClientError as exc:
        raise ValueError(
            "Execution reconciliation snapshot is unavailable; refusing reconciliation"
        ) from exc
    snapshot = projection.as_dict()
    state_binding = snapshot["state_binding"]
    if state_binding["state_version"] != version:
        raise ExecutionClientError(
            "Execution durable state changed after reconciliation snapshot"
        )
    command = _command(
        name="reconcile",
        suffix=suffix,
        version=version,
        actor=dict(actor),
        now=now,
        payload={
            "reconciliation_run_id": reconciliation_run_id,
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_fact_binding": {
                "generation": snapshot["generation"],
                "position_snapshot_hash": before_position_projection_hash(
                    snapshot["positions"],
                    account_scope=snapshot["account_scope"],
                    environment=snapshot["environment"],
                ),
                "active_order_count": snapshot["active_order_count"],
                "active_orders_sha256": snapshot["active_orders_sha256"],
                "state_version": state_binding["state_version"],
                "durable_broker_generation": state_binding[
                    "durable_broker_generation"
                ],
            },
            "reason": reason,
        },
    )
    return command, await execution.submit(command)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="fixed keyless SIMNOW run once")
    parser.add_argument("--static-core-source", required=True, type=Path)
    parser.add_argument("--position-manager-source", required=True, type=Path)
    parser.add_argument("--peek-current-facts", required=True, type=Path)
    parser.add_argument("--reconciliation-state", required=True, type=Path)
    parser.add_argument("--product", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--idempotency-suffix", required=True)
    parser.add_argument("--expected-custody-version", required=True, type=int)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--safety-flat",
        action="store_true",
        help=(
            "derive a reduce-only zero target only from the selected product's "
            "fresh current position"
        ),
    )
    parser.add_argument("--completion-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--completion-poll-seconds", type=float, default=1.0)
    return parser


def _incomplete(
    result: dict[str, Any], *, reason: str, status: dict[str, Any] | None = None
) -> dict[str, Any]:
    response = dict(result)
    # ``executed`` means the full terminal, reconciled, archived lifecycle;
    # a submitted start is deliberately not reported as successful execution.
    response.update({"executed": False, "completed": False, "archived": False, "reason": reason})
    if status is not None:
        response["execution_status"] = status
    return response


def _accepted_start_receipt(
    receipt: Any, *, command: Mapping[str, Any]
) -> bool:
    """Accept only the durable receipt for this exact start command."""

    try:
        envelope = CommandEnvelope.model_validate(command)
    except (TypeError, ValueError):  # pragma: no cover - command is locally built
        return False
    if not isinstance(receipt, Mapping) or not isinstance(receipt.get("result"), Mapping):
        return False
    return (
        receipt.get("service") == envelope.actor.service
        and receipt.get("idempotency_key") == envelope.idempotency_key
        and receipt.get("command_hash") == envelope.command_hash()
        and receipt.get("command_id") == envelope.command_id
        and receipt.get("correlation_id") == envelope.correlation_id
        and receipt.get("actor") == envelope.actor.as_dict()
        and receipt.get("status") == "COMPLETED"
        and receipt["result"].get("accepted") is True
    )


def _completion_state(
    status: dict[str, Any],
    *,
    plan_id: str,
    plan_hash: str,
    expected_intent_count: int | None = None,
) -> str:
    reconciliation = status.get("reconciliation", {})
    broker = status.get("broker", {})
    if (
        status.get("lifecycle") == "HALTED_UNKNOWN_OUTCOME"
        or reconciliation.get("state") == "UNKNOWN"
        or reconciliation.get("unknown_outcomes") != 0
    ):
        return "unknown_outcome"
    if broker.get("active_order_count") != 0:
        return "active_orders"
    intents = [
        item
        for item in status.get("send_intents", [])
        if item.get("plan_id") == plan_id and item.get("plan_hash") == plan_hash
    ]
    if not intents:
        return "missing_send_intent"
    if any(item.get("state") == "UNKNOWN_OUTCOME" for item in intents):
        return "unknown_outcome"
    if expected_intent_count is not None and len(intents) != expected_intent_count:
        return "incomplete_send_intents"
    if any(item.get("state") not in _TERMINAL_INTENT_STATES for item in intents):
        return "pending_intents"
    return "ready_for_final_reconcile"


def _completed(
    status: dict[str, Any],
    *,
    plan_id: str,
    plan_hash: str,
    expected_intent_count: int | None = None,
) -> bool:
    intents = [
        item
        for item in status.get("send_intents", [])
        if item.get("plan_id") == plan_id and item.get("plan_hash") == plan_hash
    ]
    return (
        status.get("lifecycle") == "READY"
        and status.get("plan", {}).get("state") == "TERMINAL"
        and status.get("plan", {}).get("plan_id") == plan_id
        and status.get("plan", {}).get("plan_hash") == plan_hash
        and status.get("authority", {}).get("state") == "REVOKED"
        and status.get("leader", {}).get("held") is False
        and status.get("reconciliation", {}).get("state") == "RECONCILED"
        and status.get("reconciliation", {}).get("unknown_outcomes") == 0
        and status.get("broker", {}).get("active_order_count") == 0
        and bool(status.get("safe_to_restart"))
        and bool(intents)
        and (
            expected_intent_count is None
            or len(intents) == expected_intent_count
        )
        and all(item.get("state") in _TERMINAL_INTENT_STATES for item in intents)
    )


def _execution_binding(status: dict[str, Any]) -> tuple[Any, ...]:
    """Bind the runner to fresh Execution facts, not a stale local raw hash.

    The local peek is still canonically committed as TargetPlan's expected
    before-position projection.  Execution's broker snapshot is independently
    required to remain present, fresh, reconciled and unchanged throughout
    preview/custody/start admission.  The two snapshots are collected at
    distinct controlled times and need not have identical raw JSON hashes.
    """

    intents = status.get("send_intents", [])
    if not isinstance(intents, list) or any(
        not isinstance(item, dict) or item.get("state") not in _TERMINAL_INTENT_STATES
        for item in intents
    ):
        raise ValueError("Execution has a pending or invalid send intent")
    now = _utc_clock()
    if now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise ValueError("Execution status clock must be explicit UTC")
    broker = status.get("broker")
    reconciliation = status.get("reconciliation")
    if (
        not isinstance(broker, Mapping)
        or status.get("lifecycle") != "READY"
        or broker.get("connected") is not True
        or broker.get("active_order_count") != 0
        or not isinstance(broker.get("position_snapshot_hash"), str)
        or not broker["position_snapshot_hash"]
        or not isinstance(reconciliation, Mapping)
        or reconciliation.get("state") != "RECONCILED"
        or reconciliation.get("unknown_outcomes") != 0
        or isinstance(status.get("state_version"), bool)
        or not isinstance(status.get("state_version"), int)
    ):
        raise ValueError("Execution hard gates/snapshot binding are not clean")
    last_snapshot_at = _fresh_utc(
        broker.get("last_snapshot_at"), label="Execution broker snapshot", now=now
    )
    last_completed_at = _fresh_utc(
        reconciliation.get("last_completed_at"),
        label="Execution reconciliation",
        now=now,
    )
    return (
        status["state_version"],
        status["lifecycle"],
        broker["position_snapshot_hash"],
        last_snapshot_at,
        reconciliation["state"],
        str(reconciliation["unknown_outcomes"]),
        last_completed_at,
    )


def _final_reconcile_completed(
    response: Any,
    *,
    plan_id: str,
    plan_hash: str,
    expected_after_position_hash: str,
    final_status: dict[str, Any],
    idempotency_key: str,
) -> bool:
    """Accept success only from this reconcile command's durable receipt.

    A terminal status alone is insufficient: an emergency stop can produce a
    terminal plan archive without proving the immutable target projection.
    ``ExecutionClient`` already validates that ``result`` is bound to the
    receipt; these checks bind runner success to the finalization path that
    writes the ``final_plan_completed`` archive entry.
    """

    if not isinstance(response, dict):
        return False
    receipt = response.get("receipt")
    result = response.get("result")
    if (
        not isinstance(receipt, dict)
        or receipt.get("status") != "COMPLETED"
        or receipt.get("idempotency_key") != idempotency_key
        or not isinstance(result, dict)
        or receipt.get("result") != result
        or result.get("accepted") is not True
    ):
        return False
    finalization = result.get("finalization")
    if not isinstance(finalization, dict) or finalization.get("state") != "COMPLETED":
        return False
    final_plan = finalization.get("plan")
    final_broker_hash = final_status.get("broker", {}).get("position_snapshot_hash")
    return (
        isinstance(final_plan, dict)
        and final_plan.get("state") == "TERMINAL"
        and final_plan.get("plan_id") == plan_id
        and final_plan.get("plan_hash") == plan_hash
        and finalization.get("target_position_hash") == expected_after_position_hash
        and isinstance(final_broker_hash, str)
        and finalization.get("final_position_hash") == final_broker_hash
    )


async def run(args: argparse.Namespace) -> dict[str, Any]:
    if (
        args.completion_timeout_seconds <= 0
        or args.completion_timeout_seconds > 3600
        or args.completion_poll_seconds <= 0
        or args.completion_poll_seconds > 60
    ):
        raise ValueError("completion polling bounds are invalid")
    now = _now()
    # Both official sources are replayed on every invocation.  The adapter
    # binds the thermostat's baseline rows to this exact STATIC_CORE_EQUAL
    # replay before it hashes the complete ten-product final target.
    static_result = produce_static_core_equal(
        _source_bytes(args.static_core_source, "STATIC_CORE_EQUAL source")
    )
    position_result = produce_position_manager_snapshot(
        _source_bytes(args.position_manager_source, "position-manager source")
    )
    facts = _object(args.peek_current_facts, "peek current facts")
    reconciliation = _object(args.reconciliation_state, "reconciliation state")
    if set(reconciliation) != {"state", "unknown_outcomes"}:
        raise ValueError("reconciliation state fields are invalid")
    peek = peek_current_facts_to_snapshot(
        _without_terminal_execution_orders(facts), account_scope="account:windows"
    )
    position_manager_snapshot = _generated_object(
        position_result.snapshot_draft,
        "position-manager snapshot",
    )
    safety_flat_tick: tuple[
        float, tuple[str, str, int, str, str, float], str, str
    ] | None = None
    if args.safety_flat:
        safety_flat_tick = _safety_flat_protected_tick_price(
            position_manager_snapshot, product=args.product
        )
    decision_builder = (
        build_static_core_equal_keyless_safety_flat_decision
        if args.safety_flat
        else build_static_core_equal_keyless_target_decision
    )
    decision = decision_builder(
        static_core_equal_projection=static_result.producer_projection,
        static_core_equal_freeze_contract=_generated_object(
            static_result.artifacts["freeze_contract"],
            "STATIC_CORE_EQUAL freeze contract",
        ),
        static_core_equal_target_evidence=_generated_object(
            static_result.artifacts["target_evidence"],
            "STATIC_CORE_EQUAL target evidence",
        ),
        position_manager_snapshot=position_manager_snapshot,
        position_manager_sha256=position_result.snapshot_draft_sha256,
        current_facts=peek.snapshot,
        reconciliation=reconciliation,
        product=args.product,
        run_id=args.idempotency_suffix,
        expires_at=args.expires_at,
        **(
            {"safety_flat_limit_price": safety_flat_tick[0]}
            if safety_flat_tick is not None
            else {}
        ),
        now=datetime.fromisoformat(now.replace("Z", "+00:00")),
    )
    lineage_result = {
        "static_core_equal_sha256": decision.static_core_equal_sha256,
        "position_manager_sha256": decision.position_manager_sha256,
        "final_target_sha256": decision.final_target_sha256,
        "selected_product": decision.selected_product,
        "selected_target_quantity": decision.selected_target_quantity,
        "current_quantity": decision.current_quantity,
    }
    execution: ExecutionClient | None = None
    initial_binding: tuple[Any, ...] | None = None
    if args.execute:
        execution = ExecutionClient()
        try:
            preflight_status = (await execution.status()).as_dict()
        except ExecutionClientError as exc:
            raise ValueError("Execution preflight is unavailable") from exc
        initial_binding = _execution_binding(preflight_status)
    if getattr(decision, "stopped", False):
        return {
            **lineage_result,
            "stopped": True,
            "reason": str(decision.stop_reason),
            "final_targets": [
                {
                    "product": row["product"],
                    "target_quantity": row["target_quantity"],
                }
                for row in decision.final_target_projection["targets"]
            ],
            "executed": False,
            "completed": False,
            "archived": False,
            "custody_mutated": False,
            "execution_mutated": False,
        }
    if decision.noop:
        return {
            **lineage_result,
            "noop": True,
            "reason": (
                "safety_flat_already_satisfied"
                if args.safety_flat
                else "target_already_satisfied"
            ),
            "executed": False,
            "completed": args.execute,
            "actual_execution_validated": args.execute,
            "archived": False,
            "custody_mutated": False,
            "execution_mutated": False,
        }
    handoff = decision.handoff
    if handoff is None:  # pragma: no cover - guarded by decision.noop
        raise ValueError("STATIC_CORE_EQUAL target decision is inconsistent")

    if args.execute:
        if execution is None or initial_binding is None:  # pragma: no cover
            raise ValueError("Execution preflight was not initialized")
        try:
            before_custody = (await execution.status()).as_dict()
        except ExecutionClientError as exc:
            raise ValueError("Execution pre-custody status is unavailable") from exc
        _require_same_execution_binding(
            initial_binding,
            _execution_binding(before_custody),
        )
    if safety_flat_tick is not None:
        _require_tick_boundary(
            safety_flat_tick[1],
            clock=_utc_clock,
            vt_symbol=safety_flat_tick[2],
            price_field=safety_flat_tick[3],
        )
    artifact = handoff.trusted_keyless_custody_artifact()
    custody = RemotePhaseCWorkflowClient()
    receipt = custody.install_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key=f"simnow-run-once-custody-{args.idempotency_suffix}",
            expected_custody_version=args.expected_custody_version,
            correlation_id=f"simnow-run-once-correlation-{args.idempotency_suffix}",
            artifact=artifact,
        )
    )
    result: dict[str, Any] = {
        **lineage_result,
        "plan_id": handoff.target_plan["plan_id"],
        "plan_hash": handoff.target_plan["plan_hash"],
        "receipt_id": receipt.receipt_id,
        "artifact_hash": receipt.artifact_sha256,
        "executed": False,
        "completed": False,
        "archived": False,
    }
    if not args.execute:
        return result

    actor = {"service": "control-api", "principal": args.principal, "operator": args.operator, "role": "admin"}
    if execution is None:  # pragma: no cover - guarded by args.execute
        raise ValueError("Execution client was not initialized")
    status = (await execution.status()).as_dict()
    if initial_binding is None:  # pragma: no cover - guarded by args.execute
        raise ValueError("Execution preflight binding is unavailable")
    _require_same_execution_binding(
        initial_binding,
        _execution_binding(status),
    )
    await execution.submit(_command(name="preview", suffix=f"preview-{args.idempotency_suffix}", version=status["state_version"], actor=actor, now=now, payload={"plan_hash": handoff.target_plan["plan_hash"], "artifact_hash": receipt.artifact_sha256, "mode": "simnow_preview", "receipt_id": receipt.receipt_id}))
    status = (await execution.status()).as_dict()
    await _submit_reconcile_with_ready_snapshot(
        execution,
        suffix=f"reconcile-{args.idempotency_suffix}",
        version=status["state_version"],
        actor=actor,
        now=now,
        reconciliation_run_id=f"simnow-run-once-reconcile-{args.idempotency_suffix}",
        reason="fresh fixed-tuple SIMNOW facts",
    )
    status = (await execution.status()).as_dict()
    await execution.submit(_command(name="enable", suffix=f"enable-{args.idempotency_suffix}", version=status["state_version"], actor=actor, now=now, payload={"authority_artifact_id": handoff.target_plan["plan_id"], "authority_hash": handoff.target_plan["plan_hash"], "expires_at": handoff.target_plan["expires_at"], "reason": "trusted keyless custody"}))
    status = (await execution.status()).as_dict()
    _execution_binding(status)
    leader = status["leader"]
    if not leader.get("held"):
        raise ValueError("Execution leader lease is not held; refusing start")
    start_command = _command(
        name="start",
        suffix=f"start-{args.idempotency_suffix}",
        version=status["state_version"],
        actor=actor,
        now=now,
        fence={
            "leader_epoch": int(leader["epoch"]),
            "fencing_token": int(leader["fencing_token"]),
        },
        payload={
            "plan_id": handoff.target_plan["plan_id"],
            "plan_hash": handoff.target_plan["plan_hash"],
            "reason": "start trusted keyless SIMNOW plan",
        },
    )
    try:
        await execution.submit(start_command)
    except ExecutionClientError:
        # Never resend the start/order path.  Resolve only this exact durable
        # receipt before deciding whether completion polling may continue.
        try:
            recovered_receipt = await execution.receipt(
                start_command["idempotency_key"], actor=actor
            )
        except ExecutionClientError:
            recovered_receipt = None
        if not _accepted_start_receipt(recovered_receipt, command=start_command):
            try:
                observed = (await execution.status()).as_dict()
            except ExecutionClientError:
                observed = None
            return _incomplete(result, reason="start_outcome_unknown", status=observed)
    result["start_submitted"] = True

    deadline = asyncio.get_running_loop().time() + args.completion_timeout_seconds
    plan_orders = handoff.target_plan.get("orders")
    expected_intent_count = (
        len(plan_orders) if isinstance(plan_orders, (list, tuple)) else None
    )
    reconciled_pending_versions: set[int] = set()
    while True:
        try:
            status = (await execution.status()).as_dict()
        except ExecutionClientError:
            return _incomplete(result, reason="completion_status_unknown")
        state = _completion_state(
            status,
            plan_id=handoff.target_plan["plan_id"],
            plan_hash=handoff.target_plan["plan_hash"],
            expected_intent_count=expected_intent_count,
        )
        if state == "unknown_outcome":
            return _incomplete(result, reason=state, status=status)
        if state == "ready_for_final_reconcile":
            break
        if state == "pending_intents":
            state_version = status.get("state_version")
            if isinstance(state_version, bool) or not isinstance(state_version, int):
                return _incomplete(
                    result, reason="completion_status_invalid", status=status
                )
            if state_version not in reconciled_pending_versions:
                # This is query-only reconciliation of the exact started plan;
                # it never recreates or resends its start/send intent.  One
                # probe per observed durable state prevents polling from
                # becoming a command retry loop.
                try:
                    completion_command, completion_response = (
                        await _submit_reconcile_with_ready_snapshot(
                            execution,
                            suffix=(
                                f"completion-reconcile-{args.idempotency_suffix}-"
                                f"{state_version}"
                            ),
                            version=state_version,
                            actor=actor,
                            now=_now(),
                            reconciliation_run_id=(
                                "simnow-run-once-completion-reconcile-"
                                f"{args.idempotency_suffix}-{state_version}"
                            ),
                            reason=(
                                "query-only pending SIMNOW send-intent "
                                "reconciliation"
                            ),
                        )
                    )
                    completion_status = (await execution.status()).as_dict()
                except (ExecutionClientError, ValueError):
                    return _incomplete(
                        result,
                        reason="completion_reconcile_outcome_unknown",
                        status=status,
                    )
                reconciled_pending_versions.add(state_version)
                # Reconciliation may atomically resolve the final pending
                # intent and archive the plan.  Its own durable receipt is
                # then the required final evidence; do not issue a second
                # reconcile command merely because polling observed SUBMITTED.
                if _final_reconcile_completed(
                    completion_response,
                    plan_id=handoff.target_plan["plan_id"],
                    plan_hash=handoff.target_plan["plan_hash"],
                    expected_after_position_hash=handoff.target_plan[
                        "expected_after_position_hash"
                    ],
                    final_status=completion_status,
                    idempotency_key=completion_command["idempotency_key"],
                ):
                    if not _completed(
                        completion_status,
                        plan_id=handoff.target_plan["plan_id"],
                        plan_hash=handoff.target_plan["plan_hash"],
                        expected_intent_count=expected_intent_count,
                    ):
                        return _incomplete(
                            result,
                            reason="completion_reconcile_not_completed",
                            status=completion_status,
                        )
                    return {
                        **result,
                        "executed": True,
                        "completed": True,
                        "archived": True,
                        "execution_status": completion_status,
                    }
                continue
        if asyncio.get_running_loop().time() >= deadline:
            return _incomplete(result, reason=f"completion_timeout:{state}", status=status)
        await asyncio.sleep(args.completion_poll_seconds)

    try:
        final_command, final_response = await _submit_reconcile_with_ready_snapshot(
            execution,
            suffix=f"final-reconcile-{args.idempotency_suffix}",
            version=status["state_version"],
            actor=actor,
            now=_now(),
            reconciliation_run_id=(
                f"simnow-run-once-final-reconcile-{args.idempotency_suffix}"
            ),
            reason="post-start final SIMNOW reconciliation",
        )
        final_status = (await execution.status()).as_dict()
    except ExecutionClientError:
        return _incomplete(result, reason="final_reconcile_outcome_unknown")
    if not _final_reconcile_completed(
        final_response,
        plan_id=handoff.target_plan["plan_id"],
        plan_hash=handoff.target_plan["plan_hash"],
        expected_after_position_hash=handoff.target_plan[
            "expected_after_position_hash"
        ],
        final_status=final_status,
        idempotency_key=final_command["idempotency_key"],
    ):
        return _incomplete(
            result,
            reason="final_reconcile_did_not_complete_final_plan",
            status=final_status,
        )
    if not _completed(
        final_status,
        plan_id=handoff.target_plan["plan_id"],
        plan_hash=handoff.target_plan["plan_hash"],
        expected_intent_count=expected_intent_count,
    ):
        return _incomplete(result, reason="final_reconcile_not_completed", status=final_status)
    return {**result, "executed": True, "completed": True, "archived": True, "execution_status": final_status}


def main(argv: list[str] | None = None) -> int:
    try:
        result = asyncio.run(run(build_parser().parse_args(argv)))
    except (
        ContractError,
        ExecutionClientError,
        SnapshotProducerError,
        StaticCoreEqualProducerError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
