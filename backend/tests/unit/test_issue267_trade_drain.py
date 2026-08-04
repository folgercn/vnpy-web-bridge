from __future__ import annotations

import ast
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
from app.core.config import Settings
from app.core.errors import DeploymentDrainActiveError
from app.schemas.trade import OrderRequestDTO
from app.schemas.deployment_drain import (
    DeploymentDrainAcquireDTO,
    DeploymentSafetySnapshotDTO,
)
from app.services.deployment_drain import DeploymentDrainService
from app.services.commodity_simnow import commodity_simnow_service
from app.services.trade_service import TradeService
from app.services.risk_service import risk_service
from app.services.strategy_service import strategy_service
from app.services.trade_service import trade_service
from app.services.vnpy_rpc_service import VnpyRpcService, rpc_service

ROOT = Path(__file__).resolve().parents[3]


def _order() -> OrderRequestDTO:
    return OrderRequestDTO(
        symbol="rb2610",
        exchange="SHFE",
        direction="long",
        offset="open",
        type="limit",
        price=3000,
        volume=1,
        gateway_name="CTP",
        reference="issue267:gate:test",
        confirm=True,
    )


def _call(service: TradeService) -> dict:
    return service._send_order(
        _order(),
        source_ip=None,
        operator="test",
        pre_rpc_guard=None,
        send_linearization_lock=None,
        c_fast_order_owner=None,
        c_fast_order_volume_capability=None,
        manual_execution_owner=None,
        manual_execution_capability=None,
        baseline_execution_owner=None,
        baseline_execution_capability=None,
    )


def test_all_trade_send_lanes_stop_before_inner_send_when_frozen(
    tmp_path,
    monkeypatch,
) -> None:
    gate = DeploymentDrainService(
        tmp_path / "deployment-drain",
        runtime_instance_id="runtime-trade-test",
        allow_initial_bootstrap=True,
    )
    with gate._exclusive():
        state = gate._load_state()
        state.update(
            state="DRAIN_BLOCKED",
            blockers=["active_orders"],
            freeze_reason="test_frozen",
        )
        gate._write_state(state)
    service = TradeService(
        settings=Settings(
            deployment_drain_state_root=str(tmp_path / "unused")
        ),
        deployment_drain=gate,
    )
    inner = Mock(return_value={"accepted": True})
    monkeypatch.setattr(service, "_send_order_under_deployment_gate", inner)

    with pytest.raises(DeploymentDrainActiveError):
        _call(service)

    inner.assert_not_called()


def test_trade_send_holds_running_gate_through_inner_send(
    tmp_path,
    monkeypatch,
) -> None:
    gate = DeploymentDrainService(
        tmp_path / "deployment-drain",
        runtime_instance_id="runtime-trade-running",
        allow_initial_bootstrap=True,
    )
    service = TradeService(
        settings=Settings(
            deployment_drain_state_root=str(tmp_path / "unused")
        ),
        deployment_drain=gate,
    )
    inner = Mock(return_value={"accepted": True})
    monkeypatch.setattr(service, "_send_order_under_deployment_gate", inner)

    assert _call(service) == {"accepted": True}
    inner.assert_called_once()


def test_application_has_no_trade_send_bypass_outside_trade_service() -> None:
    offenders: list[str] = []
    services = ROOT / "backend/app"
    allowed = {
        services / "services/trade_service.py",
        services / "services/vnpy_rpc_service.py",
    }
    for path in services.rglob("*.py"):
        if path in allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "send_order":
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []


def test_final_rpc_send_boundary_rejects_direct_bypasses(tmp_path) -> None:
    gate = DeploymentDrainService(
        tmp_path / "rpc-drain",
        runtime_instance_id="runtime-rpc-frozen",
        allow_initial_bootstrap=True,
    )
    gate.status()
    with gate._exclusive():
        state = gate._load_state()
        state.update(
            state="DRAIN_BLOCKED",
            blockers=["active_orders"],
            freeze_reason="test_frozen",
        )
        gate._write_state(state)
    service = VnpyRpcService(
        Settings(deployment_drain_state_root=str(tmp_path / "unused")),
        deployment_drain=gate,
    )

    with pytest.raises(DeploymentDrainActiveError):
        service.send_order(object(), "CTP")
    with pytest.raises(DeploymentDrainActiveError):
        service.call("send_order", object(), "CTP")


def test_global_execution_services_share_the_final_rpc_gate() -> None:
    assert trade_service.deployment_drain is rpc_service.deployment_drain
    assert risk_service.deployment_drain is rpc_service.deployment_drain
    assert strategy_service.deployment_drain is rpc_service.deployment_drain
    assert commodity_simnow_service.trade.deployment_drain is rpc_service.deployment_drain


def test_application_never_awaits_while_holding_a_sync_deployment_gate() -> None:
    offenders: list[str] = []
    for path in (ROOT / "backend/app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.With):
                continue
            guards = (
                item.context_expr
                for item in node.items
                if isinstance(item.context_expr, ast.Call)
            )
            if not any(
                isinstance(call.func, ast.Attribute)
                and call.func.attr in {"_mutation_guard", "mutation_guard"}
                for call in guards
            ):
                continue
            if any(isinstance(child, ast.Await) for child in ast.walk(node)):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []


def test_final_rpc_send_linearizes_before_drain_snapshot(tmp_path) -> None:
    gate = DeploymentDrainService(
        tmp_path / "linearized-rpc-drain",
        runtime_instance_id="runtime-linearized",
        allow_initial_bootstrap=True,
    )
    send_entered = threading.Event()
    release_send = threading.Event()
    drain_finished = threading.Event()
    thread_errors: list[BaseException] = []

    class BlockingClient:
        def send_order(self, *_args, timeout: int) -> str:
            send_entered.set()
            assert timeout > 0
            assert release_send.wait(timeout=2)
            return "CTP.1"

    rpc = VnpyRpcService(
        Settings(deployment_drain_state_root=str(tmp_path / "unused")),
        deployment_drain=gate,
    )
    rpc.started = True
    rpc.client = BlockingClient()  # type: ignore[assignment]
    now = datetime(2026, 8, 4, tzinfo=timezone.utc)
    request = DeploymentDrainAcquireDTO(
        schema_version="web_bridge_deployment_drain_acquire_v1",
        request_id="request-linearized-0001",
        deployment_attempt_id="attempt-linearized-0001",
        release_plan_id=f"release-plan-{'a' * 64}",
        release_plan_core_sha256="a" * 64,
        restart_action_sha256="b" * 64,
        issuer_source_commit_sha="a" * 40,
        issuer_image_digest=f"sha256:{'a' * 64}",
        issuer_config_sha256="a" * 64,
        issuer_runtime_instance_id="runtime-linearized",
        target_source_commit_sha="b" * 40,
        target_image_digest=f"sha256:{'b' * 64}",
        target_config_sha256="b" * 64,
        rollback_image_digest=f"sha256:{'a' * 64}",
        rollback_config_sha256="a" * 64,
        nonce="linearized_nonce_0001",
        ttl_seconds=60,
        operator="test-operator",
        reason="prove final send precedes drain snapshot",
    )
    snapshot = DeploymentSafetySnapshotDTO(
        schema_version="web_bridge_deployment_safety_snapshot_v1",
        captured_at=now,
        execution_plan_status="IDLE",
        execution_plan_hash=None,
        plan_version=1,
        state_version="test-state-v1",
        state_sha256="a" * 64,
        active_orders_snapshot_sha256="a" * 64,
        positions_snapshot_sha256="b" * 64,
        checkpoint_sha256="b" * 64,
        rpc_generation=1,
        web_trade_enabled=False,
        execution_authority_revoked=True,
        auto_dispatch_stopped=True,
        active_orders=0,
        unknown_outcome=False,
        reconcile_required=False,
        checkpoint_durable=True,
    )

    def send() -> None:
        try:
            rpc.send_order(object(), "CTP")
        except BaseException as exc:  # noqa: BLE001 - relay thread failure
            thread_errors.append(exc)

    def drain() -> None:
        try:
            gate.acquire_with_snapshot(request, lambda: snapshot)
            drain_finished.set()
        except BaseException as exc:  # noqa: BLE001 - relay thread failure
            thread_errors.append(exc)

    send_thread = threading.Thread(target=send)
    drain_thread = threading.Thread(target=drain)
    send_thread.start()
    assert send_entered.wait(timeout=2)
    drain_thread.start()
    assert not drain_finished.wait(timeout=0.1)
    release_send.set()
    send_thread.join(timeout=2)
    drain_thread.join(timeout=2)

    assert not send_thread.is_alive()
    assert not drain_thread.is_alive()
    assert thread_errors == []
    assert drain_finished.is_set()
    assert gate.status()["state"] == "SAFE_TO_RESTART"


def test_private_unguarded_rpc_primitive_has_no_external_callers() -> None:
    offenders: list[str] = []
    allowed = ROOT / "backend/app/services/vnpy_rpc_service.py"
    for path in (ROOT / "backend/app").rglob("*.py"):
        if path == allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "_call_under_deployment_gate"
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []
