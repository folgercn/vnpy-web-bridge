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
import re
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
from app.execution.executable_target_adapter import (  # noqa: E402
    ExecutableTargetAdapterError,
    _close_order_offset,
    _contract,
    _current_contract_positions,
    peek_current_facts_to_snapshot,
)
from app.phase_c.client import RemotePhaseCWorkflowClient  # noqa: E402
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO  # noqa: E402
from simnow_run_once import (  # noqa: E402
    _command,
    _completed,
    _completion_state,
    _final_reconcile_completed,
    _incomplete,
    _now,
)
from shared.trust_contracts.v1 import (  # noqa: E402
    ContractError,
    canonical_json_line,
)
from shared.commodity_execution import (  # noqa: E402
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    before_position_projection_hash,
    build_trusted_keyless_target_plan,
    sha256_json,
    target_position_projection_hash,
)
from shared.artifact_contracts.v1 import new_artifact_envelope  # noqa: E402

_TARGETS = frozenset({"SHORT1", "FLAT"})
_SYMBOL_PRODUCT = re.compile(r"^([A-Za-z]+)[0-9]{4}$")
_STATUS_MAX_AGE_SECONDS = 60.0
_STATUS_FUTURE_SKEW_SECONDS = 5.0


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not isinstance(value, dict) or canonical_json_line(value) != raw:
        raise ValueError(f"{label} must be canonical JSON")
    return value


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


def _project_single_contract(positions: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return exactly one normalized CTP commodity contract, including zero rows."""

    projections: dict[tuple[str, str], tuple[str, str, str]] = {}
    for key, raw in positions.items():
        if not isinstance(key, str) or not isinstance(raw, Mapping):
            raise ValueError("broker position projection is invalid")
        if str(raw.get("gateway_name", "")).upper() != "CTP":
            raise ValueError("broker position gateway is invalid")
        try:
            exchange, symbol = _contract(f"{raw.get('exchange')}.{raw.get('symbol')}")
        except ExecutableTargetAdapterError as exc:
            raise ValueError("broker position contract is invalid") from exc
        product_match = _SYMBOL_PRODUCT.fullmatch(symbol)
        if product_match is None:
            raise ValueError("broker position contract is invalid")
        volume = raw.get("volume")
        if isinstance(volume, bool) or not isinstance(volume, int) or volume < 0:
            raise ValueError("broker position volume is invalid")
        if str(raw.get("direction", "")).upper() not in {"LONG", "SHORT"}:
            raise ValueError("broker position direction is invalid")
        product = product_match.group(1).lower()
        normalized = (exchange, symbol.lower())
        existing = projections.setdefault(normalized, (product, exchange, symbol))
        if existing[0] != product:
            raise ValueError("broker position contract is ambiguous")
    if len(projections) != 1:
        raise ValueError("require exactly one broker commodity contract projection")
    return next(iter(projections.values()))


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


def _pilot_price(positions: Mapping[str, Any], *, exchange: str, symbol: str) -> float:
    """Require a broker-fact price; pilot mode never invents an opening price."""

    prices: set[float] = set()
    for raw in positions.values():
        if not isinstance(raw, Mapping):
            continue
        if (
            str(raw.get("exchange", "")).upper() != exchange
            or str(raw.get("symbol", "")).upper() != symbol.upper()
        ):
            continue
        price = raw.get("price")
        if isinstance(price, bool) or not isinstance(price, (int, float)):
            continue
        normalized = float(price)
        if normalized > 0 and normalized < float("inf"):
            prices.add(normalized)
    if len(prices) != 1:
        raise ValueError("require one unambiguous broker position price")
    return next(iter(prices))


def _pilot_target_plan(
    *,
    positions: Mapping[str, Any],
    product: str,
    exchange: str,
    symbol: str,
    long_volume: int,
    short_volume: int,
    matching: list[tuple[str, dict[str, Any]]],
    target: str,
    expires_at: str,
    generated_at: str,
) -> dict[str, Any]:
    """Build only the two fixed pilot transitions; never generalize a delta."""

    current_quantity = long_volume - short_volume
    if target == "SHORT1":
        if (long_volume, short_volume) != (0, 0):
            raise ValueError("SHORT1 requires a flat broker projection")
        direction, offset = "SHORT", "OPEN"
        after_positions = {
            f"{symbol}.{exchange}.SHORT": {
                "gateway_name": "CTP",
                "symbol": symbol,
                "exchange": exchange,
                "direction": "SHORT",
                "volume": 1,
            }
        }
    elif target == "FLAT":
        if (long_volume, short_volume) != (0, 1):
            raise ValueError("FLAT requires exactly one short broker position")
        direction, after_positions = "LONG", {}
        offset = _close_order_offset(matching, exchange=exchange, direction=direction)
    else:  # pragma: no cover - argparse and run enforce this first
        raise ValueError("pilot target is invalid")
    price = _pilot_price(positions, exchange=exchange, symbol=symbol)
    identity = sha256_json(
        {
            "pilot": "SIMNOW-keyless-v1",
            "target": target,
            "product": product,
            "exchange": exchange,
            "symbol": symbol,
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
                "symbol": symbol,
                "exchange": exchange,
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


def _fresh_utc(value: Any, *, label: str, now: datetime) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be an explicit UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must be an explicit UTC timestamp")
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
    fresh_snapshot_id = reconciliation.get("fresh_snapshot_id")
    if not isinstance(fresh_snapshot_id, str) or not fresh_snapshot_id:
        raise ValueError("Execution fresh snapshot id is invalid")
    return (
        int(status["state_version"]),
        str(status["lifecycle"]),
        str(broker["position_snapshot_hash"]),
        last_snapshot_at,
        str(reconciliation["state"]),
        str(reconciliation["unknown_outcomes"]),
        last_completed_at,
        fresh_snapshot_id,
    )


def _require_same_execution_binding(
    expected: tuple[Any, ...], observed: tuple[Any, ...]
) -> None:
    if observed != expected:
        raise ValueError("Execution status changed before pilot mutation")


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
    peek = peek_current_facts_to_snapshot(facts, account_scope="account:windows")
    product, exchange, symbol = _project_single_contract(peek.snapshot.positions)
    long_volume, short_volume, matching = _current_position(
        peek.snapshot, exchange=exchange, symbol=symbol
    )
    current_quantity = long_volume - short_volume
    desired_quantity = -1 if args.target == "SHORT1" else 0
    base_result = {
        "target": args.target,
        "contract": f"{exchange}.{symbol}",
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
        product=product,
        exchange=exchange,
        symbol=symbol,
        long_volume=long_volume,
        short_volume=short_volume,
        matching=matching,
        target=args.target,
        expires_at=args.expires_at,
        generated_at=now,
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
    await execution.submit(
        _command(
            name="reconcile",
            suffix=f"reconcile-{args.idempotency_suffix}",
            version=status["state_version"],
            actor=actor,
            now=now,
            payload={
                "reconciliation_run_id": f"simnow-keyless-pilot-reconcile-{args.idempotency_suffix}",
                "snapshot_id": str(status["reconciliation"]["fresh_snapshot_id"]),
                "reason": "fresh fixed-tuple SIMNOW pilot facts",
            },
        )
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
    leader = status["leader"]
    if not leader.get("held"):
        raise ValueError("Execution leader lease is not held; refusing start")
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
        final_command = _command(
            name="reconcile",
            suffix=f"final-reconcile-{args.idempotency_suffix}",
            version=status["state_version"],
            actor=actor,
            now=_now(),
            payload={
                "reconciliation_run_id": f"simnow-keyless-pilot-final-reconcile-{args.idempotency_suffix}",
                "snapshot_id": str(status["reconciliation"]["fresh_snapshot_id"]),
                "reason": "post-start final SIMNOW pilot reconciliation",
            },
        )
        final_response = await execution.submit(final_command)
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
