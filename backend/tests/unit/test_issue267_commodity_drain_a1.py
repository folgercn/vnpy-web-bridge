from __future__ import annotations

import threading
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from app.core.config import Settings
from app.core.errors import (
    CommoditySimNowStateError,
    DeploymentDrainActiveError,
)
from app.schemas.deployment_drain import (
    DeploymentDrainAcquireDTO,
    DeploymentSafetySnapshotDTO,
)
from app.schemas.commodity_simnow import CommoditySimNowDisableRequestDTO
from app.services.commodity_simnow import CommoditySimNowService
from app.services.deployment_drain import DeploymentDrainService


SHA_A = "a" * 64
SHA_B = "b" * 64

POSITIVE_MUTATIONS = {
    "_restore_c_fast_continuous_authority",
    "enable_c_fast_continuous",
    "enable_c_fast_runtime_authorization",
    "enable",
    "start_template",
    "preview",
    "execute",
    "reconcile",
    "auto_advance",
    "auto_candidate_shakedown_advance",
    "auto_position_manager_shakedown_advance",
    "auto_c_fast_continuous_advance",
    "auto_template_advance",
    "preview_c_fast_shakedown",
    "start_c_fast_shakedown",
    "preview_position_manager_shakedown",
    "start_position_manager_shakedown",
}
READ_OR_RISK_REDUCING = {
    "status",
    "_suspend_idle_c_fast_continuous_for_shutdown",
    "c_fast_runtime_authorization_status",
    "revoke_c_fast_runtime_authorization",
    "_revoke_auto_dispatch",
    "disable",
    "revoke_all_execution_authority",
    "_reconcile_during_drain",
    "_acceptance_passive_ttl_advance",
    "c_fast_shakedown_status",
    "stop_c_fast_shakedown",
    "position_manager_shadow",
    "position_manager_shakedown_status",
    "stop_position_manager_shakedown",
    "c_fast_shakedown_history",
    "plan",
    "list_events",
    "c_fast_shakedown_events",
    "c_fast_shakedown_pnl",
    "_begin_safe_halt",
}


class FakeRpc:
    def __init__(self, drain: DeploymentDrainService) -> None:
        self.deployment_drain = drain
        self.send_order_calls = 0

    def bind_c_fast_terminal_publication_owner(self, _owner: object) -> object:
        return object()

    def send_order(self, *_args: object, **_kwargs: object) -> None:
        self.send_order_calls += 1
        raise AssertionError("Commodity deployment tests must never send orders")


class FakeTrade:
    def __init__(self, drain: DeploymentDrainService, rpc: FakeRpc) -> None:
        self.deployment_drain = drain
        self.rpc = rpc


class FakeRisk:
    def __init__(self, drain: DeploymentDrainService) -> None:
        self.deployment_drain = drain

    def status(self) -> dict[str, bool]:
        return {"web_trade_enabled": False, "emergency_stopped": False}


class FakeAudit:
    def record(self, **_kwargs: object) -> None:
        return None


class FakeRuntimeAuthorization:
    def __init__(self) -> None:
        self.state = "ACTIVE"
        self.revoke_calls = 0

    def status(self) -> dict[str, str]:
        return {"state": self.state}

    def revoke(self, **_kwargs: object) -> dict[str, str]:
        self.revoke_calls += 1
        self.state = "REVOKED"
        return {"state": self.state}


def _gate(tmp_path, name: str = "drain") -> DeploymentDrainService:
    gate = DeploymentDrainService(
        tmp_path / name,
        runtime_instance_id=f"runtime-{name}",
        allow_initial_bootstrap=True,
    )
    gate.status()
    return gate


def _service(tmp_path, gate: DeploymentDrainService):
    rpc = FakeRpc(gate)
    trade = FakeTrade(gate, rpc)
    risk = FakeRisk(gate)
    runtime = FakeRuntimeAuthorization()
    service = CommoditySimNowService(
        settings=Settings(
            app_env="test",
            commodity_simnow_enabled=True,
            commodity_simnow_state_path=str(tmp_path / "commodity.json"),
            commodity_c_fast_simnow_state_path=str(tmp_path / "c-fast.json"),
            commodity_position_manager_shadow_state_path=str(
                tmp_path / "position-shadow.json"
            ),
        ),
        rpc=rpc,  # type: ignore[arg-type]
        trade=trade,  # type: ignore[arg-type]
        risk=risk,  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=object(),
        clock=lambda: datetime.now(timezone.utc),
        c_fast_runtime_authorization=runtime,  # type: ignore[arg-type]
        deployment_drain=gate,
    )
    return service, rpc, runtime


def _request(runtime_id: str) -> DeploymentDrainAcquireDTO:
    return DeploymentDrainAcquireDTO(
        schema_version="web_bridge_deployment_drain_acquire_v1",
        request_id="request-a1-0001",
        deployment_attempt_id="attempt-a1-0001",
        release_plan_id=f"release-plan-{SHA_A}",
        release_plan_core_sha256=SHA_A,
        restart_action_sha256=SHA_B,
        issuer_source_commit_sha="a" * 40,
        issuer_image_digest=f"sha256:{SHA_A}",
        issuer_config_sha256=SHA_A,
        issuer_runtime_instance_id=runtime_id,
        target_source_commit_sha="b" * 40,
        target_image_digest=f"sha256:{SHA_B}",
        target_config_sha256=SHA_B,
        rollback_image_digest=f"sha256:{SHA_A}",
        rollback_config_sha256=SHA_A,
        nonce="issue267-a1-nonce",
        ttl_seconds=60,
        operator="test-operator",
        reason="A1 lock order test",
    )


def test_every_serialized_entrypoint_has_an_explicit_drain_classification() -> None:
    classified = {
        name: bool(getattr(member, "_deployment_mutation"))
        for name, member in vars(CommoditySimNowService).items()
        if hasattr(member, "_deployment_mutation")
    }

    assert set(classified) == POSITIVE_MUTATIONS | READ_OR_RISK_REDUCING
    assert {name for name, gated in classified.items() if gated} == (
        POSITIVE_MUTATIONS
    )


def _snapshot() -> DeploymentSafetySnapshotDTO:
    return DeploymentSafetySnapshotDTO(
        schema_version="web_bridge_deployment_safety_snapshot_v1",
        captured_at=datetime.now(timezone.utc),
        execution_plan_status="IDLE",
        execution_plan_hash=None,
        plan_version=0,
        state_version="a1-test-state",
        state_sha256=SHA_A,
        active_orders_snapshot_sha256=SHA_A,
        positions_snapshot_sha256=SHA_B,
        checkpoint_sha256=SHA_B,
        rpc_generation=1,
        web_trade_enabled=False,
        execution_authority_revoked=True,
        auto_dispatch_stopped=True,
        active_orders=0,
        unknown_outcome=False,
        reconcile_required=False,
        checkpoint_durable=True,
    )


def test_commodity_uses_exact_trade_rpc_risk_deployment_gate(tmp_path) -> None:
    gate = _gate(tmp_path)
    service, rpc, _runtime = _service(tmp_path, gate)

    assert service.deployment_drain is gate
    assert service.trade.deployment_drain is gate
    assert service.rpc.deployment_drain is gate
    assert service.risk.deployment_drain is gate
    assert rpc.send_order_calls == 0

    other = _gate(tmp_path, "other-drain")
    service.trade.deployment_drain = other
    with pytest.raises(ValueError, match="must share deployment drain"):
        CommoditySimNowService(
            settings=service.settings,
            rpc=service.rpc,
            trade=service.trade,
            risk=service.risk,
            audit=FakeAudit(),  # type: ignore[arg-type]
            tick_store=object(),
        )


def test_non_test_commodity_rejects_any_dependency_without_a_drain(
    tmp_path,
) -> None:
    gate = _gate(tmp_path)
    service, _rpc, _runtime = _service(tmp_path, gate)
    del service.risk.deployment_drain

    with pytest.raises(
        ValueError, match="dependencies must expose deployment drain"
    ):
        CommoditySimNowService(
            settings=service.settings.model_copy(update={"app_env": "development"}),
            rpc=service.rpc,
            trade=service.trade,
            risk=service.risk,
            audit=FakeAudit(),  # type: ignore[arg-type]
            tick_store=object(),
            deployment_drain=gate,
        )


def test_constructor_does_not_cleanup_terminal_state_before_unfrozen_start(
    tmp_path,
    monkeypatch,
) -> None:
    gate = _gate(tmp_path)
    with gate._exclusive():
        state = gate._load_state()
        state.update(state="RESTARTED_FROZEN", freeze_reason="test")
        gate._write_state(state)
    cleanup_calls = 0

    def cleanup(_self) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1

    monkeypatch.setattr(
        CommoditySimNowService,
        "_cleanup_terminal_shakedown_active_plan",
        cleanup,
    )
    service, _rpc, _runtime = _service(tmp_path, gate)

    assert cleanup_calls == 0
    service.start()
    assert cleanup_calls == 0


def test_terminal_cleanup_does_not_clear_an_unrelated_state_error(
    tmp_path,
    monkeypatch,
) -> None:
    gate = _gate(tmp_path)
    service, _rpc, _runtime = _service(tmp_path, gate)
    session_id = "cfast-shakedown-" + "a" * 32
    checksum = "b" * 64
    service.current_plan = {
        "c_fast_shakedown_session_id": session_id,
        "plan_hash": SHA_A,
    }
    service._state_load_error = "completed_state:JSONDecodeError"
    monkeypatch.setattr(service, "_load_c_fast_shakedown_state", lambda: {})
    monkeypatch.setattr(
        service, "_recover_c_fast_terminal_archive_artifacts", lambda _sid: None
    )
    monkeypatch.setattr(
        service,
        "_load_c_fast_terminal_archive",
        lambda _sid: {"plan_hash": SHA_A, "terminal_checksum": checksum},
    )
    monkeypatch.setattr(
        service,
        "_c_fast_terminal_chain",
        lambda: ([{"terminal_checksum": checksum}], "VALID"),
    )
    monkeypatch.setattr(service, "_save_c_fast_shakedown_state", lambda _row: None)

    service._cleanup_terminal_shakedown_active_plan()

    assert service.current_plan is None
    assert service._state_load_error == "completed_state:JSONDecodeError"


def test_positive_command_takes_gate_before_cycle_and_drain_waits(
    tmp_path,
    monkeypatch,
) -> None:
    gate = _gate(tmp_path)
    service, rpc, _runtime = _service(tmp_path, gate)
    gate_entered = threading.Event()
    command_finished = threading.Event()
    drain_finished = threading.Event()
    original_guard = gate.mutation_guard

    @contextmanager
    def observed_guard():
        with original_guard():
            gate_entered.set()
            yield

    monkeypatch.setattr(gate, "mutation_guard", observed_guard)

    def positive_command() -> None:
        service.auto_advance()
        command_finished.set()

    def acquire_drain() -> None:
        gate.acquire_with_snapshot(
            _request(gate.runtime_instance_id), _snapshot
        )
        drain_finished.set()

    with service._cycle_lock:
        command_thread = threading.Thread(target=positive_command)
        command_thread.start()
        assert gate_entered.wait(timeout=2)
        drain_thread = threading.Thread(target=acquire_drain)
        drain_thread.start()
        assert not command_finished.wait(timeout=0.1)
        assert not drain_finished.wait(timeout=0.1)

    command_thread.join(timeout=2)
    drain_thread.join(timeout=2)
    assert command_finished.is_set()
    assert drain_finished.is_set()
    assert gate.status()["state"] == "SAFE_TO_RESTART"
    assert rpc.send_order_calls == 0


def test_nested_positive_commands_reenter_the_same_gate(tmp_path, monkeypatch) -> None:
    gate = _gate(tmp_path)
    service, rpc, _runtime = _service(tmp_path, gate)
    original_guard = gate.mutation_guard
    entries = 0

    @contextmanager
    def counted_guard():
        nonlocal entries
        entries += 1
        with original_guard():
            yield

    monkeypatch.setattr(gate, "mutation_guard", counted_guard)

    result = service.auto_position_manager_shakedown_advance()

    assert result == {"action": "idle", "reason": "no_shakedown_plan"}
    assert entries == 1
    assert rpc.send_order_calls == 0


def test_start_losing_the_drain_race_fails_closed(tmp_path, monkeypatch) -> None:
    gate = _gate(tmp_path)
    service, rpc, runtime = _service(tmp_path, gate)
    with gate._exclusive():
        state = gate._load_state()
        state.update(
            state="DRAINING",
            active_request_id="request-start-race-a1",
            active_request_sha256=SHA_A,
            freeze_reason="test_start_race",
        )
        gate._write_state(state)
    service.enabled = True
    service.auto_dispatch_authorized = True
    monkeypatch.setattr(service, "_deployment_execution_frozen", lambda: False)

    service.start()

    assert service._task is None
    assert service.enabled is False
    assert service.auto_dispatch_authorized is False
    assert runtime.revoke_calls == 1
    assert rpc.send_order_calls == 0


@pytest.mark.parametrize("drain_state", ["DRAINING", "RESTARTED_FROZEN"])
def test_frozen_start_clears_authority_starts_no_worker_and_allows_revoke(
    tmp_path,
    drain_state,
    monkeypatch,
) -> None:
    gate = _gate(tmp_path)
    service, rpc, runtime = _service(tmp_path, gate)
    with gate._exclusive():
        state = gate._load_state()
        state.update(
            state=drain_state,
            active_request_id="request-frozen-a1",
            active_request_sha256=SHA_A,
            freeze_reason="test_frozen_start",
        )
        gate._write_state(state)
    service.enabled = True
    service.manual_approval = True
    service.simnow_mode = True
    service.auto_dispatch_authorized = True
    service.shakedown_auto_dispatch_authorized = True
    service.c_fast_shakedown_auto_dispatch_authorized = True
    service.c_fast_continuous_authorized = True
    service.template_authorized = True
    restore = service._restore_c_fast_continuous_authority
    restore_calls = 0

    def forbidden_restore() -> dict[str, str]:
        nonlocal restore_calls
        restore_calls += 1
        raise AssertionError("frozen startup must not restore authority")

    monkeypatch.setattr(
        service, "_restore_c_fast_continuous_authority", forbidden_restore
    )

    service.start()

    assert restore_calls == 0
    assert service._task is None
    assert service.enabled is False
    assert service.manual_approval is False
    assert service.simnow_mode is False
    assert service.auto_dispatch_authorized is False
    assert service.shakedown_auto_dispatch_authorized is False
    assert service.c_fast_shakedown_auto_dispatch_authorized is False
    assert service.c_fast_continuous_authorized is False
    assert service.template_authorized is False
    assert runtime.revoke_calls == 1
    assert rpc.send_order_calls == 0
    monkeypatch.setattr(service, "_restore_c_fast_continuous_authority", restore)
    with pytest.raises(DeploymentDrainActiveError):
        service._restore_c_fast_continuous_authority()


def test_drain_allows_disable_and_global_revoke(tmp_path) -> None:
    gate = _gate(tmp_path)
    service, rpc, _runtime = _service(tmp_path, gate)
    gate.acquire_with_snapshot(_request(gate.runtime_instance_id), _snapshot)

    disabled = service.disable(
        CommoditySimNowDisableRequestDTO(reason="deployment drain"),
        operator="release-operator",
        role="admin",
        source_ip=None,
    )
    revoked = service.revoke_all_execution_authority(
        "deployment drain",
        operator="release-operator",
        source_ip=None,
    )

    assert disabled["enabled"] is False
    assert revoked["authority_revoked"] is True
    assert rpc.send_order_calls == 0

    # Read-only and risk-reducing paths remain available while drained.
    assert service.status()["enabled"] is False
    service._revoke_auto_dispatch("all")
    with pytest.raises(DeploymentDrainActiveError):
        service.auto_advance()
    assert rpc.send_order_calls == 0


@pytest.mark.parametrize(
    "status",
    ["CANCEL_PENDING", "HALTED_RECONCILE_REQUIRED", "HALTED_RECONCILED"],
)
def test_drain_internal_reconcile_accepts_only_halted_plans(
    tmp_path,
    monkeypatch,
    status,
) -> None:
    gate = _gate(tmp_path)
    service, rpc, _runtime = _service(tmp_path, gate)
    gate.acquire_with_snapshot(_request(gate.runtime_instance_id), _snapshot)
    monkeypatch.setattr(
        service,
        "_require_plan",
        lambda plan_hash: {"plan_hash": plan_hash, "status": status},
    )
    calls: list[dict[str, object]] = []

    def reconcile_impl(plan_hash, **kwargs):
        calls.append({"plan_hash": plan_hash, **kwargs})
        return {"status": status}

    monkeypatch.setattr(service, "_reconcile_impl", reconcile_impl)

    result = service._reconcile_during_drain(
        SHA_A,
        operator="release-operator",
        role="admin",
        source_ip=None,
    )

    assert result == {"status": status}
    assert calls == [
        {
            "plan_hash": SHA_A,
            "operator": "release-operator",
            "role": "admin",
            "source_ip": None,
            "dispatch_mode": "deployment_drain",
        }
    ]
    assert rpc.send_order_calls == 0


def test_drain_internal_reconcile_rejects_non_halted_plan(
    tmp_path,
    monkeypatch,
) -> None:
    gate = _gate(tmp_path)
    service, rpc, _runtime = _service(tmp_path, gate)
    gate.acquire_with_snapshot(_request(gate.runtime_instance_id), _snapshot)
    monkeypatch.setattr(
        service,
        "_require_plan",
        lambda plan_hash: {"plan_hash": plan_hash, "status": "READY_OPEN"},
    )
    monkeypatch.setattr(
        service,
        "_reconcile_impl",
        lambda *_args, **_kwargs: pytest.fail("non-halted plan reached reconcile"),
    )

    with pytest.raises(
        CommoditySimNowStateError,
        match="requires a halted plan",
    ):
        service._reconcile_during_drain(
            SHA_A,
            operator="release-operator",
            role="admin",
            source_ip=None,
        )
    assert rpc.send_order_calls == 0
