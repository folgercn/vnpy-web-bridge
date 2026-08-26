from __future__ import annotations

import asyncio
import copy
import stat
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

import simnow_experimental_materialize_target as materializer  # noqa: E402
import simnow_experimental_run_once as runner  # noqa: E402
from test_issue353_static_core_keyless import (  # noqa: E402
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


def _retired_execution_status() -> dict:
    return {
        "state_version": 10,
        "lifecycle": "READY",
        "plan": {
            "state": "TERMINAL",
            "plan_id": "retired-plan-0001",
            "plan_hash": "b" * 64,
        },
        "authority": {"state": "REVOKED"},
        "leader": {"held": False},
        "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
        "broker": {"active_order_count": 0},
        "send_intents": [{"state": "TERMINAL"}],
    }


def test_materializer_fixed_ten_contract_canonical_identity_and_false_authority(tmp_path: Path) -> None:
    target = _target()
    assert target["target_id"] == materializer._target_id(target)
    assert [row["product"] for row in target["targets"]] == list(materializer.PRODUCTS)
    assert {field: target[field] for field in ("production", "live_trading_authorized", "countable_forward", "official_forward_claimed")} == {"production": False, "live_trading_authorized": False, "countable_forward": False, "official_forward_claimed": False}
    output = tmp_path / "target.json"
    materializer.write_target_atomic(output, target)
    assert stat.S_IMODE(output.stat().st_mode) == 0o644
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o755
    loaded, raw = materializer.read_json_stable(output, label="target")
    assert materializer.validate_target(loaded, raw=raw) == target


def test_experimental_backend_replaces_foreign_retired_plan_with_preview() -> None:
    retired = _retired_execution_status()
    calls: list[str] = []

    class Execution:
        async def status(self) -> object:
            calls.append("status")
            return SimpleNamespace(as_dict=lambda: dict(retired))

        async def acquire_leader(self, _owner_id: str) -> object:
            calls.append("acquire")
            return SimpleNamespace(epoch=1, fencing_token=1)

        async def renew_leader(self, token: object) -> object:
            calls.append("renew")
            return token

        async def submit(self, command: dict) -> object:
            calls.append(command["command"])
            if command["command"] == "preview":
                raise RuntimeError("stop after preview admission")
            raise AssertionError("retired admission must preview before any other command")

        async def release_leader(self, _token: object) -> None:
            calls.append("release")

    backend = runner._ExperimentalBackend(execution=Execution(), phase_c=object())
    with pytest.raises(RuntimeError, match="stop after preview admission"):
        asyncio.run(
            backend._drive_installed_plan(
                {
                    "plan_id": "new-plan-0001",
                    "plan_hash": "a" * 64,
                    "phase": "OPEN",
                    "custody_idempotency_key": "c" * 64,
                    "artifact_sha256": "d" * 64,
                    "receipt_id": "receipt-0001",
                }
            )
        )

    assert calls == ["status", "acquire", "renew", "status", "preview", "release"]


@pytest.mark.parametrize(
    "mutate",
    (
        lambda status: status.update({"authority": {"state": "ENABLED"}}),
        lambda status: status["reconciliation"].update({"unknown_outcomes": 1}),
        lambda status: status["broker"].update({"active_order_count": 1}),
        lambda status: status.update({"send_intents": [{"state": "PERSISTED"}]}),
    ),
)
def test_experimental_backend_rejects_unsafe_foreign_terminal_plan_before_leader(
    mutate,
) -> None:
    status = _retired_execution_status()
    mutate(status)

    class Execution:
        def __init__(self) -> None:
            self.acquire_calls = 0

        async def status(self) -> object:
            return SimpleNamespace(as_dict=lambda: dict(status))

        async def acquire_leader(self, _owner_id: str) -> object:
            self.acquire_calls += 1
            raise AssertionError("unsafe terminal plan must not acquire leader")

    execution = Execution()
    backend = runner._ExperimentalBackend(execution=execution, phase_c=object())
    with pytest.raises(runner.ContinuousRunError, match="foreign non-idle TargetPlan"):
        asyncio.run(
            backend._drive_installed_plan(
                {
                    "plan_id": "new-plan-0001",
                    "plan_hash": "a" * 64,
                    "phase": "OPEN",
                    "custody_idempotency_key": "c" * 64,
                }
            )
        )
    assert execution.acquire_calls == 0


def test_experimental_backend_rejects_idle_with_enabled_authority_before_leader() -> None:
    status = _retired_execution_status()
    status["plan"] = {"state": "IDLE"}
    status["authority"] = {"state": "ENABLED"}

    class Execution:
        def __init__(self) -> None:
            self.acquire_calls = 0

        async def status(self) -> object:
            return SimpleNamespace(as_dict=lambda: dict(status))

        async def acquire_leader(self, _owner_id: str) -> object:
            self.acquire_calls += 1
            raise AssertionError("invalid idle authority must not acquire leader")

    execution = Execution()
    backend = runner._ExperimentalBackend(execution=execution, phase_c=object())
    with pytest.raises(runner.ContinuousRunError, match="admission boundary is invalid"):
        asyncio.run(
            backend._drive_installed_plan(
                {
                    "plan_id": "new-plan-0001",
                    "plan_hash": "a" * 64,
                    "phase": "OPEN",
                    "custody_idempotency_key": "c" * 64,
                }
            )
        )
    assert execution.acquire_calls == 0


@pytest.mark.parametrize("state", ("ACTIVE", "PREVIEWED"))
def test_experimental_backend_rejects_foreign_non_retired_plan_before_leader(
    state: str,
) -> None:
    status = _retired_execution_status()
    status["plan"]["state"] = state
    status["authority"] = {"state": "ENABLED"}

    class Execution:
        def __init__(self) -> None:
            self.acquire_calls = 0

        async def status(self) -> object:
            return SimpleNamespace(as_dict=lambda: dict(status))

        async def acquire_leader(self, _owner_id: str) -> object:
            self.acquire_calls += 1
            raise AssertionError("foreign active/previewed plan must not acquire leader")

    execution = Execution()
    backend = runner._ExperimentalBackend(execution=execution, phase_c=object())
    with pytest.raises(runner.ContinuousRunError, match="foreign non-idle TargetPlan"):
        asyncio.run(
            backend._drive_installed_plan(
                {
                    "plan_id": "new-plan-0001",
                    "plan_hash": "a" * 64,
                    "phase": "OPEN",
                    "custody_idempotency_key": "c" * 64,
                }
            )
        )
    assert execution.acquire_calls == 0


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


def test_test_target_is_explicit_overlay_of_validated_monthly_bundle() -> None:
    bundle = _bundle()
    route = _route(bundle)
    target = materializer.materialize_test_target(
        planner_bundle=bundle,
        planner_bundle_raw=_raw(bundle),
        daily_route=route,
        daily_route_raw=_raw(route),
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        quantity_overrides={"ag": 2},
    )
    base = _target(bundle)
    quantities = {row["product"]: row["quantity"] for row in target["targets"]}
    base_quantities = {row["product"]: row["quantity"] for row in base["targets"]}

    assert target["target_mode"] == materializer.SIMNOW_EXPERIMENTAL_TEST
    assert target["strategy_output_claim"] == materializer.NOT_OFFICIAL_STRATEGY_OUTPUT
    assert target["test_quantity_overrides"] == {"ag": 2}
    assert quantities == {**base_quantities, "ag": 2}
    assert target["target_id"] != base["target_id"]
    assert materializer.validate_test_target_bundle_binding(target, bundle) == target


@pytest.mark.parametrize("overrides", [{"bad": 1}, {"ag": True}, {"ag": 501}, {"ag": 1}])
def test_test_target_rejects_invalid_or_noop_override(overrides: dict) -> None:
    bundle = _bundle()
    route = _route(bundle)
    with pytest.raises(materializer.ExperimentalTargetError, match="overrides"):
        materializer.materialize_test_target(
            planner_bundle=bundle,
            planner_bundle_raw=_raw(bundle),
            daily_route=route,
            daily_route_raw=_raw(route),
            generated_at="2030-01-02T03:04:05Z",
            quantity_overrides=overrides,
        )


def test_test_target_rejects_manual_vector_not_matching_declared_overlay() -> None:
    bundle = _bundle()
    route = _route(bundle)
    target = materializer.materialize_test_target(
        planner_bundle=bundle,
        planner_bundle_raw=_raw(bundle),
        daily_route=route,
        daily_route_raw=_raw(route),
        generated_at="2030-01-02T03:04:05Z",
        quantity_overrides={"ag": 2},
    )
    target["targets"][1]["quantity"] = 3
    target["target_id"] = materializer._target_id(target)
    with pytest.raises(materializer.ExperimentalTargetError, match="does not bind"):
        materializer.validate_test_target_bundle_binding(target, bundle)


def test_test_target_rejects_manual_noop_override() -> None:
    bundle = _bundle()
    target = _target(bundle)
    target.update({
        "target_mode": materializer.SIMNOW_EXPERIMENTAL_TEST,
        "strategy_output_claim": materializer.NOT_OFFICIAL_STRATEGY_OUTPUT,
        "test_quantity_overrides": {"ag": 1},
    })
    target["target_id"] = materializer._target_id(target)
    with pytest.raises(materializer.ExperimentalTargetError, match="does not bind"):
        materializer.validate_test_target_bundle_binding(target, bundle)


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


def test_runner_plans_explicit_test_target_with_existing_targetplan_v3(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle()
    route = _route(bundle)
    target = materializer.materialize_test_target(
        planner_bundle=bundle,
        planner_bundle_raw=_raw(bundle),
        daily_route=route,
        daily_route_raw=_raw(route),
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        quantity_overrides={"ag": 2},
    )
    monkeypatch.setattr(runner, "read_simnow_continuous_v3_formal_tick_bindings", lambda requests, **_kwargs: _formal_bindings(requests))

    result = asyncio.run(runner.preview_once(target, bundle, execution=_Execution(_facts()), formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))

    assert result["status"] == "TARGET_PLAN_V3_DRY_RUN"
    assert result["target_mode"] == materializer.SIMNOW_EXPERIMENTAL_TEST
    assert result["strategy_output_claim"] == materializer.NOT_OFFICIAL_STRATEGY_OUTPUT


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


@pytest.mark.parametrize("reconciliation_state", ["RECONCILED", "UNKNOWN"])
def test_execute_once_recovers_existing_identity_before_new_target_planning(
    reconciliation_state: str,
) -> None:
    """A new target never replaces an ACTIVE/pending/UNKNOWN old identity."""

    bundle = _bundle()
    old_target = _target(bundle)
    new_route = _route(bundle, ag="SHFE.ag3012")
    new_target = materializer.materialize_target(
        planner_bundle=bundle,
        planner_bundle_raw=_raw(bundle),
        daily_route=new_route,
        daily_route_raw=_raw(new_route),
        generated_at=old_target["generated_at"],
    )
    old_plan_id = f"simnow-experimental-{old_target['target_id'][:32]}"
    old_plan_hash = "a" * 64
    events: list[str] = []

    def status(*, reconciled: bool, leader_held: bool, version: int) -> dict:
        return {
            "state_version": version,
            "lifecycle": "READY" if reconciled else "HALTED_UNKNOWN_OUTCOME",
            "plan": {"state": "ACTIVE", "plan_id": old_plan_id, "plan_hash": old_plan_hash},
            "leader": {
                "held": leader_held,
                "epoch": 1,
                "fencing_token": 1,
            },
            "reconciliation": {
                "state": "RECONCILED" if reconciled else "UNKNOWN",
                "unknown_outcomes": 0 if reconciled else 1,
            },
            "broker": {"active_order_count": 0},
            "send_intents": [{"plan_id": old_plan_id, "plan_hash": old_plan_hash, "state": "PERSISTED"}],
        }

    class Execution:
        def __init__(self) -> None:
            starts_reconciled = reconciliation_state == "RECONCILED"
            self.statuses = [
                status(reconciled=starts_reconciled, leader_held=False, version=9),
                status(reconciled=starts_reconciled, leader_held=True, version=9),
            ]
            if not starts_reconciled:
                self.statuses.append(
                    status(reconciled=True, leader_held=True, version=10)
                )
            self.statuses.append(
                status(reconciled=True, leader_held=True, version=10)
            )
            self.latest = self.statuses[0]

        async def status(self):
            events.append("status")
            self.latest = self.statuses.pop(0)
            return SimpleNamespace(as_dict=lambda: self.latest)

        async def acquire_leader(self, _owner_id: str):
            events.append("acquire")
            return SimpleNamespace(epoch=1, fencing_token=1)

        async def renew_leader(self, token):
            events.append("renew")
            return token

        async def reconciliation_snapshot(self):
            events.append("snapshot")
            version = self.latest["state_version"]
            return SimpleNamespace(
                as_dict=lambda: {
                    "snapshot_id": f"snapshot-peek-{'1' * 64}",
                    "generation": 17,
                    "position_snapshot_hash": "c" * 64,
                    "active_order_count": 0,
                    "active_orders_sha256": "0" * 64,
                    "state_binding": {
                        "state_version": version,
                        "durable_broker_generation": 17,
                    },
                }
            )

        async def submit(self, command):
            assert command["command"] == "reconcile"
            events.append("reconcile")
            return {"accepted": True}

        async def resume_active_plan(self, **kwargs):
            assert kwargs["plan_id"] == old_plan_id
            assert kwargs["plan_hash"] == old_plan_hash
            events.append("resume-old-identity")
            return SimpleNamespace(
                as_dict=lambda: {"state": "TERMINAL", "new_intent_count": 0}
            )

        async def release_leader(self, _token):
            events.append("release")

        async def target_plan_recovery(self, _key: str):
            pytest.fail("new target recovery lookup must wait for old identity terminal")

        async def account_facts(self):
            pytest.fail("new target planner must wait for old identity terminal")

    class Backend:
        _require_active_reconcile_status = (
            runner._ExperimentalBackend._require_active_reconcile_status
        )
        _require_post_renew_status = (
            runner._ExperimentalBackend._require_post_renew_status
        )
        _allows_retired_plan_replacement = (
            runner._ExperimentalBackend._allows_retired_plan_replacement
        )

        def __init__(self) -> None:
            self.config = SimpleNamespace(raw={"leader_owner_id": "experimental-test"})
            self.execution = Execution()

        async def _release_leader(self, token):
            await self.execution.release_leader(token)

        def _actor(self):
            return {
                "service": "control-api",
                "principal": "test",
                "operator": "test",
                "role": "admin",
            }

    result = asyncio.run(
        runner.execute_once(
            new_target,
            bundle,
            backend=Backend(),
            formal_state_dir=Path("/unused"),
            formal_projection_dir=Path("/unused"),
            expires_at="2099-01-01T00:00:00Z",
        )
    )

    assert result["status"] == "CURRENT_IDENTITY_RECOVERY"
    assert result["plan_id"] == old_plan_id
    assert result["plan_hash"] == old_plan_hash
    assert result["plan_state"] == "ACTIVE"
    assert result["new_intents"] == 0
    assert result["execution_mutated"] is True
    assert result["gateway_mutated"] is False
    assert result["reason"] == "pending_intents"
    if reconciliation_state == "UNKNOWN":
        assert events == [
            "status",
            "acquire",
            "renew",
            "status",
            "snapshot",
            "reconcile",
            "status",
            "snapshot",
            "resume-old-identity",
            "status",
            "release",
        ]
    else:
        assert events == [
            "status",
            "acquire",
            "renew",
            "status",
            "snapshot",
            "resume-old-identity",
            "status",
            "release",
        ]


def test_execute_once_allows_new_target_only_after_old_identity_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle()
    old_target = _target(bundle)
    new_route = _route(bundle, ag="SHFE.ag3012")
    new_target = materializer.materialize_target(
        planner_bundle=bundle,
        planner_bundle_raw=_raw(bundle),
        daily_route=new_route,
        daily_route_raw=_raw(new_route),
        generated_at=old_target["generated_at"],
    )
    old_plan_id = f"simnow-experimental-{old_target['target_id'][:32]}"
    old_plan_hash = "b" * 64
    events: list[str] = []

    def active_status() -> dict:
        return {
            "state_version": 9,
            "lifecycle": "READY",
            "plan": {"state": "ACTIVE", "plan_id": old_plan_id, "plan_hash": old_plan_hash},
            "leader": {"held": False},
            "authority": {"state": "ENABLED"},
            "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
            "broker": {"active_order_count": 0},
            "send_intents": [{"plan_id": old_plan_id, "plan_hash": old_plan_hash, "state": "TERMINAL"}],
            "safe_to_restart": False,
        }

    def terminal_status() -> dict:
        return {
            "state_version": 10,
            "lifecycle": "READY",
            "plan": {"state": "TERMINAL", "plan_id": old_plan_id, "plan_hash": old_plan_hash},
            "leader": {"held": False},
            "authority": {"state": "REVOKED"},
            "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
            "broker": {"active_order_count": 0},
            "send_intents": [{"plan_id": old_plan_id, "plan_hash": old_plan_hash, "state": "TERMINAL"}],
            "safe_to_restart": True,
        }

    class Execution:
        def __init__(self) -> None:
            self.statuses = iter((active_status(), active_status(), terminal_status()))

        async def status(self):
            events.append("status")
            return SimpleNamespace(as_dict=lambda: next(self.statuses))

        async def acquire_leader(self, _owner_id: str):
            events.append("acquire")
            return SimpleNamespace(epoch=1, fencing_token=1)

        async def renew_leader(self, token):
            events.append("renew")
            return token

        async def reconciliation_snapshot(self):
            events.append("snapshot")
            return SimpleNamespace(
                as_dict=lambda: {
                    "snapshot_id": f"snapshot-peek-{'1' * 64}",
                    "generation": 17,
                    "position_snapshot_hash": "c" * 64,
                    "active_order_count": 0,
                    "active_orders_sha256": "0" * 64,
                    "state_binding": {
                        "state_version": 9,
                        "durable_broker_generation": 17,
                    },
                }
            )

        async def resume_active_plan(self, **kwargs):
            assert kwargs["plan_id"] == old_plan_id
            assert kwargs["plan_hash"] == old_plan_hash
            events.append("resume-old-identity")
            return SimpleNamespace(
                as_dict=lambda: {"state": "TERMINAL", "new_intent_count": 0}
            )

        async def release_leader(self, _token):
            events.append("release")

        async def ready(self):
            events.append("ready")
            return {"gateway_snapshot_id": "old-identity-snapshot"}

        async def submit(self, command):
            assert command["command"] == "reconcile"
            assert command["expected"]["state_version"] == 9
            assert command["payload"]["snapshot_fact_binding"] == {
                "generation": 17,
                "position_snapshot_hash": "c" * 64,
                "active_order_count": 0,
                "active_orders_sha256": "0" * 64,
                "state_version": 9,
                "durable_broker_generation": 17,
            }
            events.append("final-reconcile-old-identity")
            return {"accepted": True}

        async def completion(self, plan_id: str):
            assert plan_id == old_plan_id
            events.append("old-identity-completion")
            return SimpleNamespace(
                as_dict=lambda: {"plan_id": old_plan_id, "plan_hash": old_plan_hash}
            )

        async def target_plan_recovery(self, _key: str):
            events.append("new-target-recovery")
            return SimpleNamespace(as_dict=lambda: {"state": "BEFORE_CUSTODY"})

        async def account_facts(self):
            events.append("new-target-facts")
            return SimpleNamespace(as_dict=lambda: _facts())

    class Backend:
        _require_post_renew_status = (
            runner._ExperimentalBackend._require_post_renew_status
        )
        _allows_retired_plan_replacement = (
            runner._ExperimentalBackend._allows_retired_plan_replacement
        )

        def __init__(self) -> None:
            self.config = SimpleNamespace(raw={"leader_owner_id": "experimental-test"})
            self.execution = Execution()

        async def _release_leader(self, token):
            await self.execution.release_leader(token)

        def _actor(self):
            return {"service": "control-api", "principal": "test", "operator": "test", "role": "admin"}

        async def _install_or_recover_plan(self, *, phase_key: str, handoff):
            assert handoff is not None
            events.append("install-new-target")
            return {"phase": handoff.target_plan["phase"], "phase_key": phase_key}

        async def _drive_installed_plan(
            self, recovery, *, expected_intent_count=None
        ):
            assert expected_intent_count is not None
            events.append("drive-new-target")
            return {"state": "COMPLETED", "phase": recovery["phase"]}

    monkeypatch.setattr(
        runner,
        "read_simnow_continuous_v3_formal_tick_bindings",
        lambda requests, **_kwargs: _formal_bindings(requests),
    )
    result = asyncio.run(
        runner.execute_once(
            new_target,
            bundle,
            backend=Backend(),
            formal_state_dir=Path("/unused"),
            formal_projection_dir=Path("/unused"),
            expires_at="2099-01-01T00:00:00Z",
        )
    )

    assert result["status"] == "TARGET_PLAN_V3_DRY_RUN"
    assert events.index("resume-old-identity") < events.index("new-target-recovery")
    assert events.index("old-identity-completion") < events.index(
        "new-target-recovery"
    )
    assert events.index("old-identity-completion") < events.index("new-target-recovery")
    assert events.index("new-target-recovery") < events.index("new-target-facts")
    assert events[-2:] == ["install-new-target", "drive-new-target"]


def test_execute_once_blocks_new_target_when_old_final_reconcile_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle()
    old_target = _target(bundle)
    new_route = _route(bundle, ag="SHFE.ag3012")
    new_target = materializer.materialize_target(
        planner_bundle=bundle,
        planner_bundle_raw=_raw(bundle),
        daily_route=new_route,
        daily_route_raw=_raw(new_route),
        generated_at=old_target["generated_at"],
    )
    old_plan_id = f"simnow-experimental-{old_target['target_id'][:32]}"
    old_plan_hash = "c" * 64
    events: list[str] = []
    active = {
        "state_version": 11,
        "lifecycle": "READY",
        "plan": {"state": "ACTIVE", "plan_id": old_plan_id, "plan_hash": old_plan_hash},
        "leader": {"held": False},
        "authority": {"state": "ENABLED"},
        "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
        "broker": {"active_order_count": 0},
        "send_intents": [{"plan_id": old_plan_id, "plan_hash": old_plan_hash, "state": "TERMINAL"}],
        "safe_to_restart": False,
    }

    class Execution:
        def __init__(self) -> None:
            self.statuses = iter((active, active, active))

        async def status(self):
            events.append("status")
            return SimpleNamespace(as_dict=lambda: next(self.statuses))

        async def acquire_leader(self, _owner_id: str):
            events.append("acquire")
            return SimpleNamespace(epoch=1, fencing_token=1)

        async def renew_leader(self, token):
            events.append("renew")
            return token

        async def reconciliation_snapshot(self):
            events.append("snapshot")
            return SimpleNamespace()

        async def resume_active_plan(self, **kwargs):
            assert kwargs["plan_id"] == old_plan_id
            assert kwargs["plan_hash"] == old_plan_hash
            events.append("resume-old-identity")
            return SimpleNamespace(
                as_dict=lambda: {"state": "TERMINAL", "new_intent_count": 0}
            )

        async def release_leader(self, _token):
            events.append("release")

        async def target_plan_recovery(self, _key: str):
            pytest.fail("unknown final reconcile must not derive a new target")

    class Backend:
        _require_post_renew_status = (
            runner._ExperimentalBackend._require_post_renew_status
        )
        _allows_retired_plan_replacement = (
            runner._ExperimentalBackend._allows_retired_plan_replacement
        )

        def __init__(self) -> None:
            self.config = SimpleNamespace(raw={"leader_owner_id": "experimental-test"})
            self.execution = Execution()

        def _actor(self):
            return {"service": "control-api", "principal": "test", "operator": "test", "role": "admin"}

        async def _release_leader(self, token):
            await self.execution.release_leader(token)

    async def unknown_final_reconcile(*_args, **_kwargs):
        events.append("final-reconcile-old-identity")
        raise runner.ExecutionClientError("unknown final reconcile")

    monkeypatch.setattr(
        runner, "_submit_reconcile_with_ready_snapshot", unknown_final_reconcile
    )
    result = asyncio.run(
        runner.execute_once(
            new_target,
            bundle,
            backend=Backend(),
            formal_state_dir=Path("/unused"),
            formal_projection_dir=Path("/unused"),
            expires_at="2099-01-01T00:00:00Z",
        )
    )

    assert result["status"] == "CURRENT_IDENTITY_RECOVERY"
    assert result["plan_id"] == old_plan_id
    assert result["plan_hash"] == old_plan_hash
    assert result["reason"] == "final_reconcile_outcome_unknown"
    assert events == [
        "status",
        "acquire",
        "renew",
        "status",
        "snapshot",
        "resume-old-identity",
        "status",
        "renew",
        "final-reconcile-old-identity",
        "release",
    ]


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
        def __init__(self, facts: dict) -> None:
            super().__init__(facts)
            self.recovery_keys: list[str] = []

        async def status(self):
            return SimpleNamespace(
                as_dict=lambda: {
                    "plan": {"state": "IDLE"},
                    "leader": {"held": False},
                }
            )

        async def target_plan_recovery(self, key: str):
            self.recovery_keys.append(key)
            return SimpleNamespace(as_dict=lambda: open_recovery if key == phase_key("OPEN") else {"state": "BEFORE_CUSTODY"})

    class RecoveryBackend(runner._ExperimentalBackend):
        def __init__(self) -> None:
            execution = RecoveryExecution(_facts(positions=_target_positions(target)))
            super().__init__(execution=execution, phase_c=object())
            self.recovery_execution = execution

        async def _drive_installed_plan(self, recovery):
            assert recovery is open_recovery
            return {"state": "COMPLETED", "phase": "OPEN"}

    backend = RecoveryBackend()
    monkeypatch.setattr(runner, "read_simnow_continuous_v3_formal_tick_bindings", lambda *_args, **_kwargs: pytest.fail("completed recovery must reach NOOP without quotes"))
    result = asyncio.run(runner.execute_once(target, bundle, backend=backend, formal_state_dir=Path("/unused"), formal_projection_dir=Path("/unused"), expires_at="2099-01-01T00:00:00Z"))
    assert result["status"] == "NOOP"
    assert backend.recovery_execution.recovery_keys == [
        phase_key("CLOSE"),
        phase_key("OPEN"),
    ]


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

        async def status(self):
            return SimpleNamespace(
                as_dict=lambda: {
                    "plan": {"state": "IDLE"},
                    "leader": {"held": False},
                }
            )

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

        async def _drive_installed_plan(
            self, recovery, *, expected_intent_count=None
        ):
            assert expected_intent_count is not None
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
