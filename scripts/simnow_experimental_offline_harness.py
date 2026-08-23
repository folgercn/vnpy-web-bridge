"""Local, synthetic-only planner harness for closed-market integration checks.

This script never constructs a real Execution client and never reads the
formal tick journal.  It injects synthetic account facts and valid in-memory
``FormalTickBinding`` values into the existing experimental preview seam.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.execution.formal_tick_reader import FormalTickBinding  # noqa: E402
from simnow_experimental_materialize_target import (  # noqa: E402
    ExperimentalTargetError,
    read_json_stable,
    validate_planner_bundle,
    validate_target,
)
from simnow_experimental_run_once import (  # noqa: E402
    ExperimentalRunError,
    preview_once,
)

from shared.commodity_execution import sha256_json  # noqa: E402

OFFLINE_TEST_MARKER = "SIMNOW_EXPERIMENTAL_OFFLINE_TEST"
_DISCLAIMERS = (
    "OFFLINE TEST ONLY",
    "NOT REAL SIMNOW ACCEPTANCE",
)


def _envelope(*, status: str, **payload: Any) -> dict[str, Any]:
    """Make every CLI result unambiguously offline and zero-mutation."""

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


class _SyntheticExecution:
    """Small account-facts-only stand-in; it has no mutation methods."""

    def __init__(self, facts: Mapping[str, Any]) -> None:
        self._facts = dict(facts)

    async def account_facts(self) -> SimpleNamespace:
        return SimpleNamespace(as_dict=lambda: copy.deepcopy(self._facts))


def _facts(
    *,
    positions: Mapping[str, Mapping[str, Any]] | None = None,
    active: int = 0,
    pending: int = 0,
    unknown: int = 0,
) -> dict[str, Any]:
    normalized_positions = dict(positions or {})
    return {
        "account_scope": "account:windows",
        "environment": "SIMNOW",
        "connected": True,
        "fresh": True,
        "snapshot_id": "offline-harness-snapshot-v1",
        "generation": 1,
        "position_snapshot_hash": sha256_json(normalized_positions),
        "observed_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "positions": normalized_positions,
        "active_order_count": active,
        "active_orders": {},
        "execution_binding": {"nonterminal_send_intent_count": pending},
        "status_binding": {
            "reconciliation": {"state": "RECONCILED", "unknown_outcomes": unknown}
        },
    }


def _target_positions(target: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    positions: dict[str, dict[str, Any]] = {}
    for row in target["targets"]:
        quantity = int(row["quantity"])
        if quantity == 0:
            continue
        exchange, symbol = str(row["exact_contract"]).split(".", 1)
        positions[f"{symbol}.{exchange}.{row['product']}"] = {
            "gateway_name": "CTP",
            "symbol": symbol,
            "exchange": exchange,
            "direction": "LONG" if quantity > 0 else "SHORT",
            "volume": abs(quantity),
            "yd_volume": 0,
        }
    return positions


def _formal_bindings(requests: Sequence[Any], **_unused: Any) -> tuple[FormalTickBinding, ...]:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    return tuple(
        FormalTickBinding(
            source="windows-tick-wire-v1",
            vt_symbol=request.vt_symbol,
            price_side=request.price_side,
            price_tick=request.price_tick,
            stream_generation="offline-harness-v1",
            ingest_id=f"offline-harness-{index}",
            ingest_seq=index,
            event_hash=hashlib.sha256(
                f"{request.vt_symbol}:{request.price_side}:{index}".encode()
            ).hexdigest(),
            received_at_utc=now,
            reference_price=request.price_tick * 100_000,
        )
        for index, request in enumerate(requests, start=1)
    )


async def _preview(
    target: Mapping[str, Any], bundle: Mapping[str, Any], facts: Mapping[str, Any], *, expires_at: str
) -> dict[str, Any]:
    return await preview_once(
        target,
        bundle,
        execution=_SyntheticExecution(facts),
        formal_state_dir=Path("/offline-harness/no-formal-state"),
        formal_projection_dir=Path("/offline-harness/no-formal-projection"),
        formal_binding_reader=_formal_bindings,
        expires_at=expires_at,
    )


def _changed_position(
    target: Mapping[str, Any], *, change: str
) -> dict[str, dict[str, Any]]:
    positions = _target_positions(target)
    key, position = next(iter(positions.items()))
    if change == "quantity":
        position["volume"] = int(position["volume"]) + 1
    elif change == "reverse":
        position["direction"] = "SHORT" if position["direction"] == "LONG" else "LONG"
    elif change == "contract":
        symbol = str(position["symbol"])
        replacement = f"{symbol[:-2]}99" if len(symbol) > 2 else f"{symbol}99"
        position["symbol"] = replacement
        positions[f"{replacement}.{position['exchange']}.{key.rsplit('.', 1)[-1]}"] = position
        del positions[key]
    else:  # pragma: no cover - call-site literals are fixed
        raise ValueError(f"unsupported synthetic position change: {change}")
    return positions


async def run_offline_harness(
    target: Mapping[str, Any], bundle: Mapping[str, Any], *, expires_at: str
) -> dict[str, Any]:
    """Exercise existing full-portfolio planning with zero external calls."""

    target = validate_target(dict(target))
    bundle = validate_planner_bundle(dict(bundle))
    scenarios: list[dict[str, Any]] = []

    flat_open = await _preview(target, bundle, _facts(), expires_at=expires_at)
    assert flat_open["status"] == "TARGET_PLAN_V3_DRY_RUN"
    assert flat_open["phase"] == "OPEN"
    scenarios.append({"scenario": "flat_to_open", "result": flat_open})

    same_target = await _preview(
        target, bundle, _facts(positions=_target_positions(target)), expires_at=expires_at
    )
    assert same_target["status"] == "NOOP" and same_target["new_intents"] == 0
    scenarios.append({"scenario": "same_target_noop", "result": same_target})

    for scenario, change in (
        ("quantity_change_close_then_open", "quantity"),
        ("direction_reversal_close_then_open", "reverse"),
        ("exact_contract_change_close_then_open", "contract"),
    ):
        close = await _preview(
            target,
            bundle,
            _facts(positions=_changed_position(target, change=change)),
            expires_at=expires_at,
        )
        post_close_open = await _preview(target, bundle, _facts(), expires_at=expires_at)
        assert close["phase"] == "CLOSE" and post_close_open["phase"] == "OPEN"
        scenarios.append(
            {
                "scenario": scenario,
                "close": close,
                "post_close_open": post_close_open,
            }
        )

    for blocked_by, facts in (
        ("active", _facts(active=1)),
        ("pending", _facts(pending=1)),
        ("unknown", _facts(unknown=1)),
    ):
        try:
            await _preview(target, bundle, facts, expires_at=expires_at)
        except ExperimentalRunError:
            scenarios.append(
                {"scenario": f"{blocked_by}_blocks_new_mutation", "status": "STOP"}
            )
        else:  # pragma: no cover - safety boundary, exercised by test
            raise ExperimentalRunError(f"synthetic {blocked_by} state was admitted")

    return _envelope(status="PASS", scenarios=scenarios)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{OFFLINE_TEST_MARKER} one-shot harness")
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--monthly-planner-bundle", required=True, type=Path)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--execute", action="store_true", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.execute:
        print(json.dumps(_envelope(status="STOP", error="--execute is forbidden"), sort_keys=True))
        return 2
    try:
        target, target_raw = read_json_stable(args.target, label="experimental target")
        target = validate_target(target, raw=target_raw)
        bundle, bundle_raw = read_json_stable(
            args.monthly_planner_bundle, label="monthly planner bundle"
        )
        if hashlib.sha256(bundle_raw).hexdigest() != target["monthly_quantity_sha256"]:
            raise ExperimentalRunError("monthly planner bundle hash does not bind target")
        result = asyncio.run(run_offline_harness(target, bundle, expires_at=args.expires_at))
    except (ExperimentalTargetError, ExperimentalRunError) as exc:
        result = _envelope(status="STOP", error=str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
