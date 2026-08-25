"""Synthetic-only timing/churn check for the experimental v3 start path.

This is deliberately a local harness, not a second runner.  It builds the
existing TargetPlan-v3 decision with synthetic facts/formal bindings, then
models the existing custody/install/Execution checkpoint order in memory.  No
HTTP client, journal reader, Gateway, CTP or broker mutation is constructed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.execution.formal_tick_reader import (
    FormalTickBinding,
    FormalTickRequest,
)
from app.execution.start_quote_proof import (
    ExecutionStartQuotePriceIncompatible,
    build_execution_start_quote_proof,
)
from simnow_experimental_materialize_target import (
    ExperimentalTargetError,
    materialize_target,
    read_json_stable,
    validate_planner_bundle,
    validate_target,
)
from simnow_experimental_run_once import (
    ExperimentalRunError,
    _planner_inputs,
    preview_once,
)

from shared.commodity_execution import TargetPlan, sha256_json

OFFLINE_TEST_MARKER = "SIMNOW_EXPERIMENTAL_EXECUTION_PATH_OFFLINE_TEST"
_DISCLAIMERS = (
    "OFFLINE TEST ONLY",
    "NOT REAL SIMNOW ACCEPTANCE",
    "NO EXECUTION OR GATEWAY MUTATION",
)
_CHURN_DEADLINE_SECONDS = 1.0
_CHANGE_SECONDS = (1.0, 2.0, 3.0, 5.0)
_FIXED_NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


class ExecutionPathHarnessError(RuntimeError):
    """The local synthetic path cannot establish the requested invariant."""


def _envelope(*, status: str, **payload: Any) -> dict[str, Any]:
    return {
        **payload,
        "marker": OFFLINE_TEST_MARKER,
        "disclaimers": list(_DISCLAIMERS),
        "status": status,
        "production": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "execution_mutated": False,
        "gateway_mutated": False,
    }


def _format_utc(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _facts() -> dict[str, Any]:
    positions: dict[str, Any] = {}
    return {
        "account_scope": "account:windows",
        "environment": "SIMNOW",
        "connected": True,
        "fresh": True,
        "snapshot_id": "execution-path-offline-snapshot-v1",
        "generation": 1,
        "position_snapshot_hash": sha256_json(positions),
        "observed_at": _format_utc(_FIXED_NOW),
        "positions": positions,
        "active_order_count": 0,
        "active_orders": {},
        "execution_binding": {"nonterminal_send_intent_count": 0},
        "status_binding": {
            "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0}
        },
    }


class _SyntheticFactsClient:
    """Only the account-facts method expected by the existing planner seam."""

    async def account_facts(self) -> SimpleNamespace:
        return SimpleNamespace(as_dict=_facts)


@dataclass(frozen=True, slots=True)
class _CheckpointResult:
    status: str
    attempts: int
    elapsed_seconds: float


def _strict_checkpoint(*, churn_count: int, retry_seconds: float) -> _CheckpointResult:
    """Model retries without extending the production one-second deadline."""

    if churn_count < 0 or retry_seconds <= 0:
        raise ExecutionPathHarnessError("strict checkpoint parameters are invalid")
    elapsed = 0.0
    for attempt in range(1, churn_count + 2):
        if attempt > 1:
            elapsed += retry_seconds
        if elapsed > _CHURN_DEADLINE_SECONDS:
            return _CheckpointResult("STOP", attempt - 1, elapsed)
        if attempt == churn_count + 1:
            return _CheckpointResult("PASS", attempt, elapsed)
    raise AssertionError("strict checkpoint loop is exhaustive")  # pragma: no cover


class _SyntheticFormalReader:
    """In-memory formal snapshot with an optional one-tick start-price move."""

    def __init__(
        self,
        *,
        changed: bool = False,
        stream_generation: str = "offline-generation-1",
    ) -> None:
        self.changed = changed
        self.stream_generation = stream_generation
        self.calls = 0
        self.elapsed_seconds = 0.0

    def __call__(
        self, requests: tuple[FormalTickRequest, ...], **_unused: Any
    ) -> tuple[FormalTickBinding, ...]:
        started = time.perf_counter()
        self.calls += 1
        rows: list[FormalTickBinding] = []
        for index, request in enumerate(requests, start=1):
            # The creation reader uses a deterministic protected price.  The
            # start reader changes only one protected price by one valid tick.
            reference = request.price_tick * 100_000
            if self.changed and index == 1:
                reference += request.price_tick
            rows.append(
                FormalTickBinding(
                    source="windows-tick-wire-v1",
                    vt_symbol=request.vt_symbol,
                    price_side=request.price_side,
                    price_tick=request.price_tick,
                    stream_generation=self.stream_generation,
                    ingest_id=f"offline-ingest-{self.calls}-{index}",
                    ingest_seq=index,
                    event_hash=hashlib.sha256(
                        f"{self.calls}:{index}:{request.vt_symbol}".encode()
                    ).hexdigest(),
                    received_at_utc=_format_utc(datetime.now(timezone.utc)),
                    reference_price=reference,
                )
            )
        self.elapsed_seconds += time.perf_counter() - started
        return tuple(rows)


class _PlanBoundFormalReader:
    """Return valid start bindings bound to the actual created TargetPlan."""

    def __init__(self, plan: TargetPlan, *, changed: bool) -> None:
        self.plan = plan
        self.changed = changed
        self.calls = 0

    def __call__(
        self, requests: tuple[FormalTickRequest, ...], **_unused: Any
    ) -> tuple[FormalTickBinding, ...]:
        self.calls += 1
        by_symbol: dict[str, tuple[float, str]] = {}
        for order in self.plan.orders:
            vt_symbol = f"{order.symbol}.{order.exchange}"
            side = "ask" if order.direction == "LONG" else "bid"
            exact_contract = f"{order.exchange}.{order.symbol}"
            tick = float(
                self.plan.raw["creation_quote_proof"]["bindings"][exact_contract][
                    "price_tick"
                ]
            )
            reference = (
                float(order.price) - tick
                if side == "ask"
                else float(order.price) + tick
            )
            existing = by_symbol.setdefault(vt_symbol, (reference, side))
            if existing != (reference, side):
                raise ExecutionPathHarnessError(
                    "plan has ambiguous formal symbol usage"
                )
        rows: list[FormalTickBinding] = []
        for index, request in enumerate(requests, start=1):
            try:
                reference, side = by_symbol[request.vt_symbol]
            except KeyError as exc:  # pragma: no cover - planner/start contract
                raise ExecutionPathHarnessError(
                    "start reader received foreign symbol"
                ) from exc
            if side != request.price_side:
                raise ExecutionPathHarnessError("start reader side mismatch")
            if self.changed and index == 1:
                reference += request.price_tick
            rows.append(
                FormalTickBinding(
                    source="windows-tick-wire-v1",
                    vt_symbol=request.vt_symbol,
                    price_side=request.price_side,
                    price_tick=request.price_tick,
                    stream_generation=f"offline-start-generation-{self.calls}",
                    ingest_id=f"offline-start-ingest-{self.calls}-{index}",
                    ingest_seq=index,
                    event_hash=hashlib.sha256(
                        f"start:{self.calls}:{index}:{request.vt_symbol}".encode()
                    ).hexdigest(),
                    received_at_utc=_format_utc(_FIXED_NOW),
                    reference_price=reference,
                )
            )
        return tuple(rows)


class _VersionedLifecycle:
    """Tiny in-memory state-version model for the existing command order."""

    def __init__(self) -> None:
        self.state_version = 0
        self.trace: list[dict[str, int | str]] = []

    def mutate(self, operation: str, *, command: bool = False) -> int:
        sent_version = self.state_version
        self.state_version += 1
        self.trace.append(
            {
                "operation": operation,
                "sent_state_version": sent_version if command else -1,
                "resulting_state_version": self.state_version,
            }
        )
        return sent_version


def _timed(callable_: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    value = callable_()
    return value, time.perf_counter() - started


async def run_execution_path_harness(
    target: Mapping[str, Any],
    planner_bundle: Mapping[str, Any],
    *,
    expires_at: str,
    expected_intents: int | None = None,
    checkpoint_churn: int = 0,
    checkpoint_retry_seconds: float = 0.1,
    observed_start_latency_seconds: float | None = None,
    daily_route: Mapping[str, Any] | None = None,
    planner_bundle_raw: bytes | None = None,
    daily_route_raw: bytes | None = None,
) -> dict[str, Any]:
    """Exercise the exact planner/start proof boundary entirely in memory."""

    target = validate_target(dict(target))
    bundle = validate_planner_bundle(dict(planner_bundle))
    checkpoint = _strict_checkpoint(
        churn_count=checkpoint_churn, retry_seconds=checkpoint_retry_seconds
    )
    if checkpoint.status != "PASS":
        return _envelope(
            status="STOP",
            reason="strict checkpoint churn exceeded original one-second deadline",
            strict_checkpoint={
                "deadline_seconds": _CHURN_DEADLINE_SECONDS,
                "attempts": checkpoint.attempts,
                "elapsed_seconds": checkpoint.elapsed_seconds,
            },
        )

    timings: dict[str, float] = {}
    if daily_route is not None:
        if planner_bundle_raw is None or daily_route_raw is None:
            raise ExecutionPathHarnessError(
                "daily materialization raw bytes are required"
            )
        rematerialized, timings["materialize"] = _timed(
            lambda: materialize_target(
                planner_bundle=bundle,
                planner_bundle_raw=planner_bundle_raw,
                daily_route=dict(daily_route),
                daily_route_raw=daily_route_raw,
                generated_at=str(target["generated_at"]),
            )
        )
        if rematerialized != target:
            raise ExecutionPathHarnessError(
                "materialized normal target differs from frozen target"
            )
    else:
        _unused, timings["materialize"] = _timed(
            lambda: _planner_inputs(target, bundle)
        )

    creation_reader = _SyntheticFormalReader()
    (preview, decision), preview_seconds = await _timed_async(
        lambda: preview_once(
            target,
            bundle,
            execution=_SyntheticFactsClient(),
            formal_state_dir=Path("/offline/no-journal"),
            formal_projection_dir=Path("/offline/no-projection"),
            expires_at=expires_at,
            formal_binding_reader=creation_reader,
            _return_decision=True,
        )
    )
    timings["quote"] = creation_reader.elapsed_seconds
    timings["plan"] = max(0.0, preview_seconds - creation_reader.elapsed_seconds)
    if preview.get("status") != "TARGET_PLAN_V3_DRY_RUN" or decision.noop:
        raise ExecutionPathHarnessError(
            "synthetic normal target did not create a TargetPlan"
        )
    handoff = decision.close_handoff or decision.open_handoff
    if handoff is None:  # pragma: no cover - existing planner contract
        raise ExecutionPathHarnessError("synthetic TargetPlan lacks immediate handoff")
    plan = TargetPlan.from_mapping(handoff.target_plan)
    intent_count = len(plan.orders)
    if expected_intents is not None and intent_count != expected_intents:
        raise ExecutionPathHarnessError(
            f"expected {expected_intents} intents, got {intent_count}"
        )

    lifecycle = _VersionedLifecycle()
    _unused, timings["custody"] = _timed(lambda: lifecycle.mutate("custody_publish"))
    _unused, timings["install"] = _timed(lambda: lifecycle.mutate("install"))
    _unused, timings["acquire_leader"] = _timed(
        lambda: lifecycle.mutate("acquire_leader")
    )
    _unused, timings["renew_before_preview"] = _timed(
        lambda: lifecycle.mutate("renew_before_preview")
    )
    preview_version, timings["preview"] = _timed(
        lambda: lifecycle.mutate("preview", command=True)
    )
    _unused, timings["reconcile"] = _timed(
        lambda: lifecycle.mutate("reconcile", command=True)
    )
    _unused, timings["enable"] = _timed(
        lambda: lifecycle.mutate("enable", command=True)
    )
    _unused, timings["renew_before_start"] = _timed(
        lambda: lifecycle.mutate("renew_before_start")
    )

    start_latency = (
        float(observed_start_latency_seconds)
        if observed_start_latency_seconds is not None
        else sum(timings.values())
    )
    if start_latency < 0:
        raise ExecutionPathHarnessError("observed start latency is invalid")
    start_scenarios: list[dict[str, Any]] = []
    timings["start"] = 0.0
    for changed_at in _CHANGE_SECONDS:
        reader = _PlanBoundFormalReader(plan, changed=changed_at <= start_latency)
        started = time.perf_counter()
        try:
            build_execution_start_quote_proof(
                plan, reader=reader, clock=lambda: _FIXED_NOW
            )
        except ExecutionStartQuotePriceIncompatible:
            state = "REPLAN_REQUIRED"
        else:
            state = "READY"
        timings["start"] += time.perf_counter() - started
        start_scenarios.append(
            {
                "quote_change_at_seconds": changed_at,
                "start_quote_proof_state": state,
            }
        )
    blocked = [
        item["quote_change_at_seconds"]
        for item in start_scenarios
        if item["start_quote_proof_state"] == "REPLAN_REQUIRED"
    ]
    if blocked:
        return _envelope(
            status="STOP",
            reason="exact-price start proof timing budget is infeasible",
            intent_count=intent_count,
            timings_seconds=timings,
            strict_checkpoint={
                "deadline_seconds": _CHURN_DEADLINE_SECONDS,
                "attempts": checkpoint.attempts,
                "elapsed_seconds": checkpoint.elapsed_seconds,
                "status": checkpoint.status,
            },
            state_version_trace=lifecycle.trace,
            timing_budget={
                "start_latency_seconds": start_latency,
                "status": "STOP",
                "replan_required_change_seconds": blocked,
                "scenarios": start_scenarios,
                "note": "local CPU timing plus optional measured end-to-end latency; no remote client was called",
            },
        )

    start_version, start_command_seconds = _timed(
        lambda: lifecycle.mutate("start", command=True)
    )
    timings["start"] += start_command_seconds
    if preview_version != 4 or start_version != 8:
        raise ExecutionPathHarnessError(
            "synthetic lifecycle used a stale state version"
        )
    return _envelope(
        status="PASS",
        reason="exact-price start proof remains READY for the tested churn points",
        intent_count=intent_count,
        timings_seconds=timings,
        strict_checkpoint={
            "deadline_seconds": _CHURN_DEADLINE_SECONDS,
            "attempts": checkpoint.attempts,
            "elapsed_seconds": checkpoint.elapsed_seconds,
            "status": checkpoint.status,
        },
        state_version_trace=lifecycle.trace,
        timing_budget={
            "start_latency_seconds": start_latency,
            "status": "PASS",
            "replan_required_change_seconds": [],
            "scenarios": start_scenarios,
            "note": (
                "local CPU timing plus optional measured end-to-end latency; "
                "no remote client was called"
            ),
        },
    )


async def _timed_async(callable_: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    value = await callable_()
    return value, time.perf_counter() - started


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=OFFLINE_TEST_MARKER)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--monthly-planner-bundle", required=True, type=Path)
    parser.add_argument("--daily-route", type=Path)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--expected-intents", type=int, default=181)
    parser.add_argument("--checkpoint-churn", type=int, default=0)
    parser.add_argument("--checkpoint-retry-seconds", type=float, default=0.1)
    parser.add_argument("--observed-start-latency-seconds", type=float)
    parser.add_argument("--execute", action="store_true", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.execute:
        print(
            json.dumps(
                _envelope(status="STOP", reason="--execute is forbidden"),
                sort_keys=True,
            )
        )
        return 2
    try:
        target, target_raw = read_json_stable(args.target, label="experimental target")
        target = validate_target(target, raw=target_raw)
        bundle, bundle_raw = read_json_stable(
            args.monthly_planner_bundle, label="monthly planner bundle"
        )
        bundle = validate_planner_bundle(bundle)
        if hashlib.sha256(bundle_raw).hexdigest() != target["monthly_quantity_sha256"]:
            raise ExecutionPathHarnessError(
                "monthly planner bundle hash does not bind target"
            )
        route = route_raw = None
        if args.daily_route is not None:
            route, route_raw = read_json_stable(args.daily_route, label="daily route")
        result = asyncio.run(
            run_execution_path_harness(
                target,
                bundle,
                expires_at=args.expires_at,
                expected_intents=args.expected_intents,
                checkpoint_churn=args.checkpoint_churn,
                checkpoint_retry_seconds=args.checkpoint_retry_seconds,
                observed_start_latency_seconds=args.observed_start_latency_seconds,
                daily_route=route,
                planner_bundle_raw=bundle_raw,
                daily_route_raw=route_raw,
            )
        )
    except (
        ExperimentalTargetError,
        ExperimentalRunError,
        ExecutionPathHarnessError,
    ) as exc:
        result = _envelope(status="STOP", reason=str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
