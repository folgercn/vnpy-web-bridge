"""One fixed SIMNOW keyless pilot: SHORT1 or FLAT from fresh broker facts.

This command deliberately has no contract, product, quantity, candidate JSON,
production, or live-mode input.  The sole target selector is ``--target``.
It creates the fixed pilot TargetPlan directly from fresh broker facts, then
uses trusted keyless custody and the existing Execution lifecycle.  It neither
imports a gateway/RPC transport nor submits an order itself.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable, Mapping
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
from app.execution import formal_tick_reader as _formal_tick_reader  # noqa: E402
from app.execution.executable_target_adapter import (  # noqa: E402
    ExecutableTargetAdapterError,
    _close_order_offset,
    _contract,
    _current_contract_positions,
    _without_terminal_execution_orders,
    peek_current_facts_to_snapshot,
)
from app.phase_c.client import RemotePhaseCWorkflowClient  # noqa: E402
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO  # noqa: E402
from shared.artifact_contracts.v1 import new_artifact_envelope  # noqa: E402
from shared.commodity_execution import (  # noqa: E402
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    before_position_projection_hash,
    build_trusted_keyless_target_plan,
    sha256_json,
    target_position_projection_hash,
)
from shared.trust_contracts.v1 import (  # noqa: E402
    ContractError,
    canonical_json_line,
)

_TARGETS = frozenset({"SHORT1", "FLAT"})
_FIXED_EXCHANGE = "SHFE"
_FIXED_SYMBOL = "ru2609"
_FIXED_VT_SYMBOL = f"{_FIXED_SYMBOL}.{_FIXED_EXCHANGE}"
_FORMAL_MARKET_STATE_DIR = Path("/run/market-data")
_FORMAL_MARKET_PROJECTION_DIR = Path("/run/market-projection")
_STATUS_MAX_AGE_SECONDS = 60.0
_STATUS_FUTURE_SKEW_SECONDS = 5.0
# The live tick admission boundary is intentionally stricter than the normal
# five-second quote policy: a pilot reference must be observed within two
# seconds, while retaining the existing two-second future-skew rejection.
_QUOTE_MAX_AGE_SECONDS = 2.0
_QUOTE_FUTURE_SKEW_SECONDS = 2.0
_TERMINAL_INTENT_STATES = frozenset({"TERMINAL", "RECONCILED", "CANCELLED"})
_FORMAL_TICK_TAIL_BYTES = 512 * 1024
_FORMAL_TICK_SNAPSHOT_MAX_WAIT_SECONDS = 1.0
_FORMAL_TICK_SNAPSHOT_RETRY_SECONDS = 0.05

DurableCorruptionError = _formal_tick_reader.DurableCorruptionError
_RetryableFormalTickTail = _formal_tick_reader.RetryableFormalTickTail


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not isinstance(value, dict) or canonical_json_line(value) != raw:
        raise ValueError(f"{label} must be canonical JSON")
    return value


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _command(
    *,
    name: str,
    suffix: str,
    version: int,
    actor: dict[str, str],
    payload: dict[str, Any],
    now: str,
    fence: dict[str, int] | None = None,
) -> dict[str, Any]:
    expected: dict[str, Any] = {"state_version": version}
    if fence is not None:
        expected.update(fence)
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": f"simnow-keyless-pilot-{suffix}",
        "idempotency_key": f"simnow-keyless-pilot-{suffix}",
        "correlation_id": f"simnow-keyless-pilot-{suffix}",
        "issued_at": now,
        "actor": actor,
        "command": name,
        "expected": expected,
        "payload": payload,
    }


def _incomplete(
    result: dict[str, Any], *, reason: str, status: dict[str, Any] | None = None
) -> dict[str, Any]:
    response = dict(result)
    response.update(
        {"executed": False, "completed": False, "archived": False, "reason": reason}
    )
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


def _final_reconcile_completed(
    response: Any,
    *,
    plan_id: str,
    plan_hash: str,
    expected_after_position_hash: str,
    final_status: dict[str, Any],
    idempotency_key: str,
) -> bool:
    if not isinstance(response, dict):
        return False
    receipt, result = response.get("receipt"), response.get("result")
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
    final_plan = finalization.get("plan") if isinstance(finalization, dict) else None
    final_broker_hash = final_status.get("broker", {}).get("position_snapshot_hash")
    return (
        isinstance(finalization, dict)
        and finalization.get("state") == "COMPLETED"
        and isinstance(final_plan, dict)
        and final_plan.get("state") == "TERMINAL"
        and final_plan.get("plan_id") == plan_id
        and final_plan.get("plan_hash") == plan_hash
        and finalization.get("target_position_hash") == expected_after_position_hash
        and isinstance(final_broker_hash, str)
        and finalization.get("final_position_hash") == final_broker_hash
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="fixed keyless SIMNOW pilot")
    parser.add_argument("--target", choices=sorted(_TARGETS), required=True)
    parser.add_argument("--peek-current-facts", required=True, type=Path)
    parser.add_argument("--reconciliation-state", required=True, type=Path)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--idempotency-suffix", required=True)
    parser.add_argument("--expected-custody-version", required=True, type=int)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--completion-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--completion-poll-seconds", type=float, default=1.0)
    return parser


def _require_reconciliation(value: Mapping[str, Any]) -> None:
    if (
        set(value) != {"state", "unknown_outcomes"}
        or value.get("state") != "RECONCILED"
        or value.get("unknown_outcomes") != 0
    ):
        raise ValueError("reconciliation state is not clean")


def _require_fixed_position_rows(positions: Mapping[str, Any]) -> None:
    """Admit only fixed-pilot CTP rows; empty/zero rows are a flat SHORT1 fact."""

    for key, raw in positions.items():
        if not isinstance(key, str) or not isinstance(raw, Mapping):
            raise TypeError("broker position projection is invalid")
        if str(raw.get("gateway_name", "")).upper() != "CTP":
            raise ValueError("broker position gateway is invalid")
        try:
            exchange, symbol = _contract(f"{raw.get('exchange')}.{raw.get('symbol')}")
        except ExecutableTargetAdapterError as exc:
            raise ValueError("broker position contract is invalid") from exc
        if exchange != _FIXED_EXCHANGE or symbol != _FIXED_SYMBOL:
            raise ValueError("broker position contract is not fixed ru2609.SHFE")
        volume = raw.get("volume")
        if isinstance(volume, bool) or not isinstance(volume, int) or volume < 0:
            raise ValueError("broker position volume is invalid")
        if str(raw.get("direction", "")).upper() not in {"LONG", "SHORT"}:
            raise ValueError("broker position direction is invalid")


def _current_position(
    snapshot: Any, *, exchange: str, symbol: str
) -> tuple[int, int, list[tuple[str, dict[str, Any]]]]:
    long_volume, short_volume, matching = _current_contract_positions(
        snapshot.positions,
        exchange=exchange,
        symbol=symbol,
        gateway_name="CTP",
    )
    return long_volume, short_volume, matching


def _safe_bounded_tail_info(info: object) -> bool:
    return _formal_tick_reader._safe_bounded_tail_info(info)  # type: ignore[arg-type]


def _same_bounded_tail_file(initial: object, current: object) -> bool:
    return _formal_tick_reader._same_bounded_tail_file(  # type: ignore[arg-type]
        initial, current
    )


def _read_bounded_range(descriptor: int, *, offset: int, length: int) -> bytes:
    return _formal_tick_reader._read_bounded_range(
        descriptor, offset=offset, length=length
    )


def _bounded_jsonl_tail(path: Path) -> list[dict[str, object]]:
    return _formal_tick_reader._bounded_jsonl_tail(
        path,
        tail_bytes=_FORMAL_TICK_TAIL_BYTES,
        read_range=_read_bounded_range,
    )


def _bounded_verified_tick_tail(path: Path) -> list[object]:
    return _formal_tick_reader._bounded_verified_tick_tail(
        path, tail_reader=_bounded_jsonl_tail
    )


def _formal_market_checkpoint() -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any]
]:
    return _formal_tick_reader._formal_market_checkpoint(
        state_dir=_FORMAL_MARKET_STATE_DIR,
        projection_dir=_FORMAL_MARKET_PROJECTION_DIR,
    )


def _wait_for_formal_snapshot(deadline: float) -> bool:
    return _formal_tick_reader._wait_for_formal_snapshot(
        deadline, retry_seconds=_FORMAL_TICK_SNAPSHOT_RETRY_SECONDS
    )


def _checkpoint_progressed(
    before_watermark: Mapping[str, Any],
    before_fence: Mapping[str, Any],
    after_watermark: Mapping[str, Any],
    after_fence: Mapping[str, Any],
) -> bool:
    return _formal_tick_reader._checkpoint_progressed(
        before_watermark, before_fence, after_watermark, after_fence
    )


def _formal_tick_binding(
    *,
    clock: Callable[[], datetime],
    vt_symbol: str = _FIXED_VT_SYMBOL,
    price_field: str = "last",
) -> tuple[str, str, int, str, str, float]:
    try:
        observed = _formal_tick_reader._read_observed_formal_tick(
            state_dir=_FORMAL_MARKET_STATE_DIR,
            projection_dir=_FORMAL_MARKET_PROJECTION_DIR,
            clock=clock,
            vt_symbol=vt_symbol,
            price_side=price_field,  # type: ignore[arg-type]
            max_age_seconds=_QUOTE_MAX_AGE_SECONDS,
            future_skew_seconds=_QUOTE_FUTURE_SKEW_SECONDS,
            snapshot_max_wait_seconds=_FORMAL_TICK_SNAPSHOT_MAX_WAIT_SECONDS,
            checkpoint_reader=_formal_market_checkpoint,
            verified_tail_reader=_bounded_verified_tick_tail,  # type: ignore[arg-type]
            jsonl_tail_reader=_bounded_jsonl_tail,
            snapshot_waiter=_wait_for_formal_snapshot,
            checkpoint_progress=_checkpoint_progressed,
        )
    except _formal_tick_reader.FormalTickReadError as exc:
        message = str(exc)
        if isinstance(
            exc, _formal_tick_reader.FormalTickSourceUnavailable
        ) or message.startswith("formal CTP durable tick"):
            message = "formal CTP durable tick state is invalid"
        raise ValueError(message) from exc
    return observed.as_legacy_tuple()


def _require_tick_fresh(
    binding: tuple[str, str, int, str, str, float], *, clock: Callable[[], datetime]
) -> None:
    _formal_tick_reader.require_tick_fresh(
        binding,
        clock=clock,
        max_age_seconds=_QUOTE_MAX_AGE_SECONDS,
        future_skew_seconds=_QUOTE_FUTURE_SKEW_SECONDS,
    )


def _require_current_tick_binding(
    expected: tuple[str, str, int, str, str, float],
    observed: tuple[str, str, int, str, str, float],
) -> None:
    _formal_tick_reader.require_current_tick_binding(expected, observed)


def _require_tick_boundary(
    expected: tuple[str, str, int, str, str, float],
    *,
    clock: Callable[[], datetime],
    vt_symbol: str = _FIXED_VT_SYMBOL,
    price_field: str = "last",
) -> None:
    _require_tick_fresh(expected, clock=clock)
    _require_current_tick_binding(
        expected,
        _formal_tick_binding(clock=clock, vt_symbol=vt_symbol, price_field=price_field),
    )


def _pilot_target_plan(
    *,
    positions: Mapping[str, Any],
    long_volume: int,
    short_volume: int,
    matching: list[tuple[str, dict[str, Any]]],
    target: str,
    price: float,
    expires_at: str,
    generated_at: str,
    run_identity: str,
) -> dict[str, Any]:
    """Build only the two fixed pilot transitions; never generalize a delta."""

    current_quantity = long_volume - short_volume
    if target == "SHORT1":
        if (long_volume, short_volume) != (0, 0):
            raise ValueError("SHORT1 requires a flat broker projection")
        direction, offset = "SHORT", "OPEN"
        after_positions = {
            f"{_FIXED_SYMBOL}.{_FIXED_EXCHANGE}.SHORT": {
                "gateway_name": "CTP",
                "symbol": _FIXED_SYMBOL,
                "exchange": _FIXED_EXCHANGE,
                "direction": "SHORT",
                "volume": 1,
            }
        }
    elif target == "FLAT":
        if (long_volume, short_volume) != (0, 1):
            raise ValueError("FLAT requires exactly one short broker position")
        direction, after_positions = "LONG", {}
        offset = _close_order_offset(
            matching, exchange=_FIXED_EXCHANGE, direction=direction
        )
    else:  # pragma: no cover - argparse and run enforce this first
        raise ValueError("pilot target is invalid")
    identity = sha256_json(
        {
            "pilot": "SIMNOW-keyless-v1",
            "run_identity": run_identity,
            "target": target,
            "exchange": _FIXED_EXCHANGE,
            "symbol": _FIXED_SYMBOL,
            "current_quantity": current_quantity,
            "expected_before_position_hash": before_position_projection_hash(
                positions, account_scope="account:windows", environment="SIMNOW"
            ),
        }
    )
    return build_trusted_keyless_target_plan(
        plan_id=f"simnow-keyless-pilot-v1-{identity}",
        account_scope="account:windows",
        environment="SIMNOW",
        gateway_name="CTP",
        # TargetPlan v1 still structurally requires these two legacy lineage
        # hashes.  Fixed zero sentinels expressly mean this pilot has no
        # MAP/C_FAST provenance; no producer or candidate is read or accepted.
        lineage={"map_sha256": "0" * 64, "c_fast_sha256": "0" * 64},
        scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        generated_at=generated_at,
        expires_at=expires_at,
        phase="OPEN" if offset == "OPEN" else "CLOSE",
        expected_before_position_hash=before_position_projection_hash(
            positions, account_scope="account:windows", environment="SIMNOW"
        ),
        expected_after_position_hash=target_position_projection_hash(
            after_positions, account_scope="account:windows", environment="SIMNOW"
        ),
        orders=[
            {
                "symbol": _FIXED_SYMBOL,
                "exchange": _FIXED_EXCHANGE,
                "direction": direction,
                "type": "LIMIT",
                "volume": 1,
                "price": price,
                "offset": offset,
                "reference": identity,
                "gateway_name": "CTP",
            }
        ],
    )


def _is_exact_target_gross(*, target: str, long_volume: int, short_volume: int) -> bool:
    return (target == "FLAT" and (long_volume, short_volume) == (0, 0)) or (
        target == "SHORT1" and (long_volume, short_volume) == (0, 1)
    )


def _utc_clock() -> datetime:
    return datetime.now(timezone.utc)


def _parse_explicit_utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be an explicit UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must be an explicit UTC timestamp")
    return parsed


def _fresh_utc(value: Any, *, label: str, now: datetime) -> str:
    parsed = _parse_explicit_utc(value, label=label)
    age = (now - parsed).total_seconds()
    if age > _STATUS_MAX_AGE_SECONDS or age < -_STATUS_FUTURE_SKEW_SECONDS:
        raise ValueError(f"{label} is stale or from the future")
    return value


def _require_execution_hard_gates(
    status: Mapping[str, Any],
    *,
    expected_position_snapshot_hash: str,
    clock: Callable[[], datetime],
) -> tuple[Any, ...]:
    """Bind the local canonical peek to Execution's current read-only snapshot."""

    now = clock()
    if now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise ValueError("Execution status clock must be explicit UTC")
    broker = status.get("broker")
    reconciliation = status.get("reconciliation")
    if (
        not isinstance(broker, Mapping)
        or status.get("lifecycle") != "READY"
        or broker.get("connected") is not True
        or broker.get("active_order_count") != 0
        or broker.get("position_snapshot_hash") != expected_position_snapshot_hash
        or not isinstance(reconciliation, Mapping)
        or reconciliation.get("state") != "RECONCILED"
        or reconciliation.get("unknown_outcomes") != 0
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
        int(status["state_version"]),
        str(status["lifecycle"]),
        str(broker["position_snapshot_hash"]),
        last_snapshot_at,
        str(reconciliation["state"]),
        str(reconciliation["unknown_outcomes"]),
        last_completed_at,
    )


def _require_same_execution_binding(
    expected: tuple[Any, ...], observed: tuple[Any, ...]
) -> None:
    if observed != expected:
        raise ValueError("Execution status changed before pilot mutation")


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
    """Submit reconciliation only against the immediately probed Gateway snapshot."""

    try:
        readiness = await execution.ready()
    except ExecutionClientError as exc:
        raise ValueError(
            "Execution readiness is unavailable; refusing reconciliation"
        ) from exc
    if not isinstance(readiness, Mapping):
        raise ExecutionClientError("Execution readiness response is invalid")
    gateway_snapshot_id = readiness.get("gateway_snapshot_id")
    if not isinstance(gateway_snapshot_id, str) or not gateway_snapshot_id:
        raise ExecutionClientError("Execution readiness gateway snapshot id is invalid")
    command = _command(
        name="reconcile",
        suffix=suffix,
        version=version,
        actor=actor,
        now=now,
        payload={
            "reconciliation_run_id": reconciliation_run_id,
            "snapshot_id": gateway_snapshot_id,
            "reason": reason,
        },
    )
    return command, await execution.submit(command)


async def run(args: argparse.Namespace) -> dict[str, Any]:
    if (
        args.target not in _TARGETS
        or args.completion_timeout_seconds <= 0
        or args.completion_timeout_seconds > 3600
        or args.completion_poll_seconds <= 0
        or args.completion_poll_seconds > 60
    ):
        raise ValueError("pilot arguments are invalid")
    now = _now()
    facts = _object(args.peek_current_facts, "peek current facts")
    reconciliation = _object(args.reconciliation_state, "reconciliation state")
    _require_reconciliation(reconciliation)
    peek = peek_current_facts_to_snapshot(
        _without_terminal_execution_orders(facts), account_scope="account:windows"
    )
    _require_fixed_position_rows(peek.snapshot.positions)
    long_volume, short_volume, matching = _current_position(
        peek.snapshot, exchange=_FIXED_EXCHANGE, symbol=_FIXED_SYMBOL
    )
    tick_binding = _formal_tick_binding(clock=_utc_clock)
    price = tick_binding[-1]
    current_quantity = long_volume - short_volume
    desired_quantity = -1 if args.target == "SHORT1" else 0
    base_result = {
        "target": args.target,
        "contract": f"{_FIXED_EXCHANGE}.{_FIXED_SYMBOL}",
        "current_quantity": current_quantity,
        "target_quantity": desired_quantity,
        "executed": False,
        "completed": False,
        "archived": False,
    }
    # This status query is read-only, but it is deliberately before custody so
    # an open order or unknown reconciliation can never publish a new plan.
    execution = ExecutionClient()
    try:
        preflight_status = (await execution.status()).as_dict()
    except ExecutionClientError as exc:
        raise ValueError("Execution preflight is unavailable") from exc
    initial_binding = _require_execution_hard_gates(
        preflight_status,
        expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
        clock=_utc_clock,
    )
    if _is_exact_target_gross(
        target=args.target, long_volume=long_volume, short_volume=short_volume
    ):
        return {**base_result, "no_op": True, "reason": "target_already_current"}

    target_plan = _pilot_target_plan(
        positions=peek.snapshot.positions,
        long_volume=long_volume,
        short_volume=short_volume,
        matching=matching,
        target=args.target,
        price=price,
        expires_at=args.expires_at,
        generated_at=now,
        run_identity=args.idempotency_suffix,
    )
    # Re-read immediately before the irreversible custody create.  The target
    # is bound to the first status; any intervening state/snapshot freshness
    # change must not publish it.
    try:
        before_custody = (await execution.status()).as_dict()
    except ExecutionClientError as exc:
        raise ValueError("Execution pre-custody status is unavailable") from exc
    _require_same_execution_binding(
        initial_binding,
        _require_execution_hard_gates(
            before_custody,
            expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
            clock=_utc_clock,
        ),
    )
    _require_tick_boundary(tick_binding, clock=_utc_clock)
    custody = RemotePhaseCWorkflowClient()
    receipt = custody.install_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key=f"simnow-keyless-pilot-custody-{args.idempotency_suffix}",
            expected_custody_version=args.expected_custody_version,
            correlation_id=f"simnow-keyless-pilot-correlation-{args.idempotency_suffix}",
            artifact=new_artifact_envelope(
                artifact_type="simnow-target-plan",
                trust_domain="runtime_authorization",
                producer_id="simnow-keyless-pilot",
                producer_version="v1",
                schema_ref="web-bridge-simnow-keyless-target-plan-v1",
                payload=target_plan,
                generated_at=target_plan["generated_at"],
                scope=target_plan["scope"],
                predecessor_refs=[],
                lineage=[],
            ),
        )
    )
    result = {
        **base_result,
        "plan_id": target_plan["plan_id"],
        "plan_hash": target_plan["plan_hash"],
        "receipt_id": receipt.receipt_id,
        "artifact_hash": receipt.artifact_sha256,
    }
    if not args.execute:
        return result

    actor = {
        "service": "control-api",
        "principal": args.principal,
        "operator": args.operator,
        "role": "admin",
    }
    status = (await execution.status()).as_dict()
    _require_same_execution_binding(
        initial_binding,
        _require_execution_hard_gates(
            status,
            expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
            clock=_utc_clock,
        ),
    )
    _require_tick_boundary(tick_binding, clock=_utc_clock)
    await execution.submit(
        _command(
            name="preview",
            suffix=f"preview-{args.idempotency_suffix}",
            version=status["state_version"],
            actor=actor,
            now=now,
            payload={
                "plan_hash": target_plan["plan_hash"],
                "artifact_hash": receipt.artifact_sha256,
                "mode": "simnow_preview",
                "receipt_id": receipt.receipt_id,
            },
        )
    )
    status = (await execution.status()).as_dict()
    await _submit_reconcile_with_ready_snapshot(
        execution,
        suffix=f"reconcile-{args.idempotency_suffix}",
        version=status["state_version"],
        actor=actor,
        now=now,
        reconciliation_run_id=f"simnow-keyless-pilot-reconcile-{args.idempotency_suffix}",
        reason="fresh fixed-tuple SIMNOW pilot facts",
    )
    status = (await execution.status()).as_dict()
    await execution.submit(
        _command(
            name="enable",
            suffix=f"enable-{args.idempotency_suffix}",
            version=status["state_version"],
            actor=actor,
            now=now,
            payload={
                "authority_artifact_id": target_plan["plan_id"],
                "authority_hash": target_plan["plan_hash"],
                "expires_at": target_plan["expires_at"],
                "reason": "trusted keyless SIMNOW pilot custody",
            },
        )
    )
    status = (await execution.status()).as_dict()
    _require_execution_hard_gates(
        status,
        expected_position_snapshot_hash=peek.snapshot.position_snapshot_hash,
        clock=_utc_clock,
    )
    leader = status["leader"]
    if not leader.get("held"):
        raise ValueError("Execution leader lease is not held; refusing start")
    _require_tick_boundary(tick_binding, clock=_utc_clock)
    try:
        await execution.submit(
            _command(
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
                    "plan_id": target_plan["plan_id"],
                    "plan_hash": target_plan["plan_hash"],
                    "reason": "start trusted keyless SIMNOW pilot plan",
                },
            )
        )
    except ExecutionClientError:
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
            status, plan_id=target_plan["plan_id"], plan_hash=target_plan["plan_hash"]
        )
        if state == "unknown_outcome":
            return _incomplete(result, reason=state, status=status)
        if state == "ready_for_final_reconcile":
            break
        if asyncio.get_running_loop().time() >= deadline:
            return _incomplete(
                result, reason=f"completion_timeout:{state}", status=status
            )
        await asyncio.sleep(args.completion_poll_seconds)

    try:
        final_command, final_response = await _submit_reconcile_with_ready_snapshot(
            execution,
            suffix=f"final-reconcile-{args.idempotency_suffix}",
            version=status["state_version"],
            actor=actor,
            now=_now(),
            reconciliation_run_id=(
                f"simnow-keyless-pilot-final-reconcile-{args.idempotency_suffix}"
            ),
            reason="post-start final SIMNOW pilot reconciliation",
        )
        final_status = (await execution.status()).as_dict()
    except ExecutionClientError:
        return _incomplete(result, reason="final_reconcile_outcome_unknown")
    if not _final_reconcile_completed(
        final_response,
        plan_id=target_plan["plan_id"],
        plan_hash=target_plan["plan_hash"],
        expected_after_position_hash=target_plan["expected_after_position_hash"],
        final_status=final_status,
        idempotency_key=final_command["idempotency_key"],
    ):
        return _incomplete(
            result,
            reason="final_reconcile_did_not_complete_final_plan",
            status=final_status,
        )
    if not _completed(
        final_status, plan_id=target_plan["plan_id"], plan_hash=target_plan["plan_hash"]
    ):
        return _incomplete(
            result, reason="final_reconcile_not_completed", status=final_status
        )
    return {
        **result,
        "executed": True,
        "completed": True,
        "archived": True,
        "execution_status": final_status,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        result = asyncio.run(run(build_parser().parse_args(argv)))
    except (ContractError, ExecutionClientError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
