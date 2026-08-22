from __future__ import annotations

import asyncio
import copy
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.execution.formal_tick_reader import FormalTickBinding

from shared.commodity_execution import sha256_json

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import simnow_experimental_materialize_target as materializer
import simnow_experimental_run_once as runner
from test_issue353_static_core_keyless import (
    _position_manager_snapshot,
    _static_outputs,
)


def _bundle() -> dict:
    projection, freeze, evidence = _static_outputs()
    snapshot = _position_manager_snapshot(evidence, selected={"ag": 1, "au": -1})
    return {
        "schema_version": materializer.PLANNER_BUNDLE_SCHEMA_VERSION,
        "strategy_id": "STATIC_CORE_EQUAL",
        "source_mode": materializer.STATIC_CORE_EQUAL_MONTHLY,
        "source_month": snapshot["source_month"],
        "static_core_equal_projection": copy.deepcopy(projection),
        "static_core_equal_freeze_contract": copy.deepcopy(freeze),
        "static_core_equal_target_evidence": copy.deepcopy(evidence),
        "position_manager_snapshot": copy.deepcopy(snapshot),
    }


def _route(bundle: dict, *, ag: str | None = None) -> dict:
    contracts = {row["product"]: row["exact_contract"] for row in bundle["position_manager_snapshot"]["targets"]}
    if ag is not None:
        contracts["ag"] = ag
    return {"schema_version": "daily-pit-route-v1", "mains": [
        {"product": product, "exchange": materializer.PRODUCT_EXCHANGES[product], "exact_contract": contracts[product]}
        for product in materializer.PRODUCTS
    ]}


def _raw(value: dict) -> bytes:
    return materializer.canonical_json_line(value)


def _target(bundle: dict | None = None) -> dict:
    bundle = _bundle() if bundle is None else bundle
    route = _route(bundle)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return materializer.materialize_target(planner_bundle=bundle, planner_bundle_raw=_raw(bundle), daily_route=route, daily_route_raw=_raw(route), generated_at=generated_at)


def test_materializer_fixed_ten_contract_canonical_identity_and_false_authority(tmp_path: Path) -> None:
    target = _target()
    assert target["target_id"] == materializer._target_id(target)
    assert [row["product"] for row in target["targets"]] == list(materializer.PRODUCTS)
    assert {field: target[field] for field in ("production", "live_trading_authorized", "countable_forward", "official_forward_claimed")} == {"production": False, "live_trading_authorized": False, "countable_forward": False, "official_forward_claimed": False}
    output = tmp_path / "target.json"
    materializer.write_target_atomic(output, target)
    loaded, raw = materializer.read_json_stable(output, label="target")
    assert materializer.validate_target(loaded, raw=raw) == target


def test_daily_route_change_preserves_quantities_when_bound_to_bundle() -> None:
    bundle = _bundle()
    first = _target(bundle)
    route = _route(bundle, ag="SHFE.ag3012")
    second = materializer.materialize_target(planner_bundle=bundle, planner_bundle_raw=_raw(bundle), daily_route=route, daily_route_raw=_raw(route), generated_at=first["generated_at"])
    assert [row["quantity"] for row in first["targets"]] == [row["quantity"] for row in second["targets"]]
    assert first["targets"][0]["exact_contract"] != second["targets"][0]["exact_contract"]


def test_materializer_rejects_unmarked_manual_vector() -> None:
    with pytest.raises(materializer.ExperimentalTargetError, match="fields"):
        materializer.validate_planner_bundle({"strategy_id": "STATIC_CORE_EQUAL", "targets": []})


class _Execution:
    def __init__(self, facts: dict) -> None:
        self.facts = facts

    async def account_facts(self):
        return SimpleNamespace(as_dict=lambda: self.facts)


def _facts(*, positions: dict[str, dict] | None = None, active: int = 0, pending: int = 0, unknown: int = 0) -> dict:
    positions = {} if positions is None else positions
    return {
        "account_scope": "account:windows", "environment": "SIMNOW", "connected": True, "fresh": True,
        "snapshot_id": "snapshot-experimental-0001", "generation": 1, "position_snapshot_hash": sha256_json(positions),
        "observed_at": "2030-01-02T03:04:05Z", "positions": positions, "active_order_count": active, "active_orders": {},
        "execution_binding": {"nonterminal_send_intent_count": pending},
        "status_binding": {"reconciliation": {"state": "RECONCILED", "unknown_outcomes": unknown}},
    }


def _target_positions(target: dict) -> dict[str, dict]:
    positions: dict[str, dict] = {}
    for row in target["targets"]:
        if row["quantity"] == 0:
            continue
        exchange, symbol = row["exact_contract"].split(".", 1)
        positions[f"{symbol}.{exchange}.{row['product']}"] = {
            "gateway_name": "CTP", "symbol": symbol, "exchange": exchange,
            "direction": "LONG" if row["quantity"] > 0 else "SHORT", "volume": abs(row["quantity"]), "yd_volume": 0,
        }
    return positions


def _formal_bindings(requests) -> tuple[FormalTickBinding, ...]:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return tuple(FormalTickBinding(source="windows-tick-wire-v1", vt_symbol=request.vt_symbol, price_side=request.price_side, price_tick=request.price_tick, stream_generation="experimental-gen", ingest_id=f"experimental-{index}", ingest_seq=index, event_hash=sha256_json({"request": request.vt_symbol, "index": index}), received_at_utc=now, reference_price=request.price_tick * 100_000) for index, request in enumerate(requests, start=1))


def test_runner_uses_mature_planner_to_prove_same_target_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle()
    target = _target(bundle)
    monkeypatch.setattr(runner, "read_simnow_continuous_v3_formal_tick_bindings", lambda *_args, **_kwargs: pytest.fail("planner NOOP must not read quotes"))
    result = asyncio.run(runner.preview_once(target, bundle, execution=_Execution(_facts(positions=_target_positions(target))), formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))
    assert result == {"status": "NOOP", "target_id": target["target_id"], "new_intents": 0, "execution_mutated": False, "gateway_mutated": False}


def test_runner_builds_real_target_plan_v3_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle()
    target = _target(bundle)
    monkeypatch.setattr(runner, "read_simnow_continuous_v3_formal_tick_bindings", lambda requests, **_kwargs: _formal_bindings(requests))
    result = asyncio.run(runner.preview_once(target, bundle, execution=_Execution(_facts()), formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))
    assert result["status"] == "TARGET_PLAN_V3_DRY_RUN"
    assert result["phase"] == "OPEN"
    assert result["new_intents"] > 0
    assert len(result["plan_id"]) > 8 and len(result["plan_hash"]) == 64


def test_runner_rebinds_latest_daily_route_then_plans_close_and_fresh_open(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle()
    old_target = _target(bundle)
    route = _route(bundle, ag="SHFE.ag3012")
    new_target = materializer.materialize_target(planner_bundle=bundle, planner_bundle_raw=_raw(bundle), daily_route=route, daily_route_raw=_raw(route), generated_at=old_target["generated_at"])
    monkeypatch.setattr(runner, "read_simnow_continuous_v3_formal_tick_bindings", lambda requests, **_kwargs: _formal_bindings(requests))
    close = asyncio.run(runner.preview_once(new_target, bundle, execution=_Execution(_facts(positions=_target_positions(old_target))), formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))
    assert close["phase"] == "CLOSE"
    open_phase = asyncio.run(runner.preview_once(new_target, bundle, execution=_Execution(_facts()), formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))
    assert open_phase["phase"] == "OPEN"


@pytest.mark.parametrize("facts", [_facts(active=1), _facts(pending=1), _facts(unknown=1)])
def test_runner_active_pending_or_unknown_is_zero_mutation(facts: dict) -> None:
    bundle = _bundle()
    with pytest.raises(runner.ExperimentalRunError, match="fresh broker facts|active, pending, or unknown"):
        asyncio.run(runner.preview_once(_target(bundle), bundle, execution=_Execution(facts), formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))


def test_runner_formal_quote_failure_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle()
    monkeypatch.setattr(runner, "read_simnow_continuous_v3_formal_tick_bindings", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("stale")))
    with pytest.raises(runner.ExperimentalRunError, match="formal bid/ask"):
        asyncio.run(runner.preview_once(_target(bundle), bundle, execution=_Execution(_facts()), formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))


def test_completed_open_recovery_returns_fresh_planner_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle()
    target = _target(bundle)
    inputs = runner._planner_inputs(target, bundle)
    run_id = f"simnow-experimental-{target['target_id'][:48]}"
    _static_sha, static_rows, execution_day = runner._static_core_equal_outputs(
        producer_projection=inputs["static_core_equal_projection"],
        freeze_contract=inputs["static_core_equal_freeze_contract"],
        target_evidence=inputs["static_core_equal_target_evidence"],
    )
    final_projection, _final_rows = runner._position_manager_final_projection(
        snapshot=inputs["position_manager_snapshot"],
        expected_sha256=sha256_json(inputs["position_manager_snapshot"]),
        static_rows=static_rows,
        static_execution_day=execution_day,
    )

    def phase_key(phase: str) -> str:
        import hashlib
        import json

        return hashlib.sha256(json.dumps({"domain": "simnow-experimental-target-v1", "target_id": target["target_id"], "phase": phase}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    open_recovery = {
        "state": "INSTALLED", "target_plan_schema_version": runner.KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        "custody_idempotency_key": phase_key("OPEN"), "phase": "OPEN", "execution_run_id": run_id,
        "lineage": {"static_core_equal_sha256": sha256_json(inputs["static_core_equal_projection"]), "position_manager_sha256": sha256_json(inputs["position_manager_snapshot"]), "final_target_sha256": sha256_json(final_projection)},
    }

    class RecoveryExecution(_Execution):
        async def target_plan_recovery(self, key: str):
            return SimpleNamespace(as_dict=lambda: open_recovery if key == phase_key("OPEN") else {"state": "BEFORE_CUSTODY"})

    class RecoveryBackend:
        def __init__(self) -> None:
            self.execution = RecoveryExecution(_facts(positions=_target_positions(target)))
            self.install_calls: list[object] = []

        async def _install_or_recover_plan(self, *, phase_key: str, handoff):
            self.install_calls.append(handoff)
            assert phase_key == open_recovery["custody_idempotency_key"]
            return open_recovery

        async def _drive_installed_plan(self, recovery):
            assert recovery is open_recovery
            return {"state": "COMPLETED", "phase": "OPEN"}

    backend = RecoveryBackend()
    monkeypatch.setattr(runner, "read_simnow_continuous_v3_formal_tick_bindings", lambda *_args, **_kwargs: pytest.fail("completed recovery must reach NOOP without quotes"))
    result = asyncio.run(runner.execute_once(target, bundle, backend=backend, formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))
    assert result["status"] == "NOOP"
    assert backend.install_calls == [None]


def test_execute_once_drives_close_then_fresh_open_without_deferred_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle()
    old_target = _target(bundle)
    route = _route(bundle, ag="SHFE.ag3012")
    target = materializer.materialize_target(
        planner_bundle=bundle,
        planner_bundle_raw=_raw(bundle),
        daily_route=route,
        daily_route_raw=_raw(route),
        generated_at=old_target["generated_at"],
    )
    events: list[str] = []

    class LifecycleExecution:
        def __init__(self) -> None:
            self.facts = iter(
                (
                    _facts(positions=_target_positions(old_target)),
                    _facts(),
                )
            )

        async def target_plan_recovery(self, _key: str):
            return SimpleNamespace(as_dict=lambda: {"state": "BEFORE_CUSTODY"})

        async def account_facts(self):
            events.append("facts")
            return SimpleNamespace(as_dict=lambda: next(self.facts))

    class LifecycleBackend:
        def __init__(self) -> None:
            self.execution = LifecycleExecution()
            self.handoffs: list[object] = []

        async def _install_or_recover_plan(self, *, phase_key: str, handoff):
            assert handoff is not None
            self.handoffs.append(handoff)
            events.append(f"install-{handoff.target_plan['phase']}")
            return {"phase": handoff.target_plan["phase"], "phase_key": phase_key}

        async def _drive_installed_plan(self, recovery):
            events.append(f"drive-{recovery['phase']}")
            return {"state": "COMPLETED", "phase": recovery["phase"]}

    backend = LifecycleBackend()
    monkeypatch.setattr(
        runner,
        "read_simnow_continuous_v3_formal_tick_bindings",
        lambda requests, **_kwargs: _formal_bindings(requests),
    )
    result = asyncio.run(
        runner.execute_once(
            target,
            bundle,
            backend=backend,
            formal_state_dir=Path("/unused"),
            formal_projection_dir=Path("/unused"),
            expires_at="2099-01-01T00:00:00Z",
        )
    )
    assert result["phase"] == "OPEN"
    assert events == [
        "facts",
        "install-CLOSE",
        "drive-CLOSE",
        "facts",
        "install-OPEN",
        "drive-OPEN",
    ]
    close, open_phase = backend.handoffs
    assert close.target_plan["phase"] == "CLOSE"
    assert open_phase.target_plan["phase"] == "OPEN"
    assert close.target_plan["plan_id"] != open_phase.target_plan["plan_id"]
    assert close.target_plan["plan_hash"] != open_phase.target_plan["plan_hash"]
    assert "deferred_open_intent" not in close.target_plan
    assert "deferred_open_intent" not in open_phase.target_plan
