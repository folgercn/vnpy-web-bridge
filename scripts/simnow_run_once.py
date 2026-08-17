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
from app.execution.executable_target_adapter import (  # noqa: E402
    _without_terminal_execution_orders,
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
    _require_execution_hard_gates,
    _require_same_execution_binding,
    _utc_clock,
)

from shared.trust_contracts.v1 import (  # noqa: E402
    ContractError,
    canonical_json_line,
)

_TERMINAL_INTENT_STATES = frozenset({"TERMINAL", "RECONCILED", "CANCELLED"})


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
    """Submit reconciliation against the immediately probed Gateway snapshot."""

    try:
        readiness = await execution.ready()
    except ExecutionClientError as exc:
        raise ValueError("Execution readiness is unavailable; refusing reconciliation") from exc
    if not isinstance(readiness, Mapping):
        raise ExecutionClientError("Execution readiness response is invalid")
    gateway_snapshot_id = readiness.get("gateway_snapshot_id")
    if not isinstance(gateway_snapshot_id, str) or not gateway_snapshot_id:
        raise ExecutionClientError("Execution readiness gateway snapshot id is invalid")
    command = _command(
        name="reconcile",
        suffix=suffix,
        version=version,
        actor=dict(actor),
        now=now,
        payload={
            "reconciliation_run_id": reconciliation_run_id,
            "snapshot_id": gateway_snapshot_id,
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


def _completion_state(status: dict[str, Any], *, plan_id: str, plan_hash: str) -> str:
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
    if any(item.get("state") not in _TERMINAL_INTENT_STATES for item in intents):
        return "pending_intents"
    return "ready_for_final_reconcile"


def _completed(status: dict[str, Any], *, plan_id: str, plan_hash: str) -> bool:
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
        and status.get("reconciliation", {}).get("state") == "RECONCILED"
        and status.get("reconciliation", {}).get("unknown_outcomes") == 0
        and status.get("broker", {}).get("active_order_count") == 0
        and bool(status.get("safe_to_restart"))
        and bool(intents)
        and all(item.get("state") in _TERMINAL_INTENT_STATES for item in intents)
    )


def _execution_binding(
    status: dict[str, Any], *, expected_position_snapshot_hash: str
) -> tuple[Any, ...]:
    intents = status.get("send_intents", [])
    if not isinstance(intents, list) or any(
        not isinstance(item, dict) or item.get("state") not in _TERMINAL_INTENT_STATES
        for item in intents
    ):
        raise ValueError("Execution has a pending or invalid send intent")
    return _require_execution_hard_gates(
        status,
        expected_position_snapshot_hash=expected_position_snapshot_hash,
        clock=_utc_clock,
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
    decision = build_static_core_equal_keyless_target_decision(
        static_core_equal_projection=static_result.producer_projection,
        static_core_equal_freeze_contract=_generated_object(
            static_result.artifacts["freeze_contract"],
            "STATIC_CORE_EQUAL freeze contract",
        ),
        static_core_equal_target_evidence=_generated_object(
            static_result.artifacts["target_evidence"],
            "STATIC_CORE_EQUAL target evidence",
        ),
        position_manager_snapshot=_generated_object(
            position_result.snapshot_draft,
            "position-manager snapshot",
        ),
        position_manager_sha256=position_result.snapshot_draft_sha256,
        current_facts=peek.snapshot,
        reconciliation=reconciliation,
        product=args.product,
        run_id=args.idempotency_suffix,
        expires_at=args.expires_at,
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
        initial_binding = _execution_binding(
            preflight_status,
            expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
        )
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
            "reason": "target_already_satisfied",
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
            _execution_binding(
                before_custody,
                expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
            ),
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
        _execution_binding(
            status,
            expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
        ),
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
    _require_execution_hard_gates(
        status,
        expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
        clock=_utc_clock,
    )
    leader = status["leader"]
    if not leader.get("held"):
        raise ValueError("Execution leader lease is not held; refusing start")
    try:
        await execution.submit(_command(name="start", suffix=f"start-{args.idempotency_suffix}", version=status["state_version"], actor=actor, now=now, fence={"leader_epoch": int(leader["epoch"]), "fencing_token": int(leader["fencing_token"])}, payload={"plan_id": handoff.target_plan["plan_id"], "plan_hash": handoff.target_plan["plan_hash"], "reason": "start trusted keyless SIMNOW plan"}))
    except ExecutionClientError:
        # Never resend the start/order path.  A later invocation must query the
        # same durable receipts and reconcile its existing intents.
        try:
            observed = (await execution.status()).as_dict()
        except ExecutionClientError:
            observed = None
        return _incomplete(result, reason="start_outcome_unknown", status=observed)
    result["start_submitted"] = True

    deadline = asyncio.get_running_loop().time() + args.completion_timeout_seconds
    while True:
        try:
            status = (await execution.status()).as_dict()
        except ExecutionClientError:
            return _incomplete(result, reason="completion_status_unknown")
        state = _completion_state(
            status,
            plan_id=handoff.target_plan["plan_id"],
            plan_hash=handoff.target_plan["plan_hash"],
        )
        if state == "unknown_outcome":
            return _incomplete(result, reason=state, status=status)
        if state == "ready_for_final_reconcile":
            break
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
