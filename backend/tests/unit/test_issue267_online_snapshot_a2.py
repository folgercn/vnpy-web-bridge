from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.core.config import Settings
from app.schemas.deployment_drain import (
    DeploymentDrainAcquireDTO,
    DeploymentOnlineCheckpointDTO,
    DeploymentRpcFactsDTO,
)
from app.services.commodity_simnow import CommoditySimNowService
from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
)
from jsonschema import Draft202012Validator


SHA_A = "a" * 64
SHA_B = "b" * 64
ACCOUNT_ID = "sim-account-a2"
ACCOUNT_HASH = hashlib.sha256(ACCOUNT_ID.encode()).hexdigest()
ROOT = Path(__file__).resolve().parents[3]


class FakeRpc:
    def __init__(self, drain: DeploymentDrainService) -> None:
        self.deployment_drain = drain
        self.facts = DeploymentRpcFactsDTO(
            schema_version="windows_rpc_deployment_safety_snapshot_v1",
            request_id="request-online-a2-0001",
            challenge="issue267-online-a2-nonce",
            server_instance_id="windows-rpc-a2-instance",
            fact_generation=7,
            captured_at=datetime.now(timezone.utc),
            execution_admission_frozen=True,
            pending_send_outcomes=0,
            strategy_execution_enabled=False,
            account_hashes=[ACCOUNT_HASH],
            orders=[],
            active_orders=[],
            trades=[],
            positions=[
                {
                    "direction": "long",
                    "volume": 0,
                    "vt_symbol": "rb2610.SHFE",
                }
            ],
        )
        self.capture_calls = 0
        self.send_order_calls = 0

    def bind_c_fast_terminal_publication_owner(self, _owner: object) -> object:
        return object()

    def capture_deployment_facts(
        self,
        *,
        request_id: str,
        challenge: str,
    ) -> DeploymentRpcFactsDTO:
        self.capture_calls += 1
        assert request_id == self.facts.request_id
        assert challenge == self.facts.challenge
        return self.facts

    def send_order(self, *_args: object, **_kwargs: object) -> None:
        self.send_order_calls += 1
        raise AssertionError("A2 snapshot tests must never send orders")


class FakeTrade:
    def __init__(self, drain: DeploymentDrainService, rpc: FakeRpc) -> None:
        self.deployment_drain = drain
        self.rpc = rpc


class FakeRisk:
    def __init__(self, drain: DeploymentDrainService) -> None:
        self.deployment_drain = drain
        self.web_trade_enabled = False

    def status(self) -> dict[str, object]:
        return {
            "web_trade_enabled": self.web_trade_enabled,
            "emergency_stopped": False,
            "rules_version": 1,
        }


class FakeAudit:
    def record(self, **_kwargs: object) -> None:
        return None


class FakeRuntimeAuthorization:
    def __init__(self) -> None:
        self.state = "REVOKED"

    def status(self) -> dict[str, str]:
        return {"state": self.state}

    def revoke(self, **_kwargs: object) -> dict[str, str]:
        self.state = "REVOKED"
        return {"state": self.state}


def gate(tmp_path, *, runtime_id: str) -> DeploymentDrainService:
    service = DeploymentDrainService(
        tmp_path / "deployment-drain",
        runtime_instance_id=runtime_id,
        allow_initial_bootstrap=True,
    )
    service.status()
    return service


def commodity(tmp_path, drain: DeploymentDrainService):
    rpc = FakeRpc(drain)
    risk = FakeRisk(drain)
    service = CommoditySimNowService(
        settings=Settings(
            app_env="test",
            commodity_simnow_enabled=True,
            commodity_simnow_account_hashes=ACCOUNT_HASH,
            commodity_simnow_state_path=str(tmp_path / "commodity.json"),
            commodity_c_fast_simnow_state_path=str(tmp_path / "c-fast.json"),
            commodity_position_manager_shadow_state_path=str(
                tmp_path / "position-shadow.json"
            ),
        ),
        rpc=rpc,  # type: ignore[arg-type]
        trade=FakeTrade(drain, rpc),  # type: ignore[arg-type]
        risk=risk,  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=object(),
        clock=lambda: datetime.now(timezone.utc),
        c_fast_runtime_authorization=(
            FakeRuntimeAuthorization()  # type: ignore[arg-type]
        ),
        deployment_drain=drain,
    )
    return service, rpc, risk


def request(runtime_id: str) -> DeploymentDrainAcquireDTO:
    return DeploymentDrainAcquireDTO(
        schema_version="web_bridge_deployment_drain_acquire_v1",
        request_id="request-online-a2-0001",
        deployment_attempt_id="attempt-online-a2-0001",
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
        nonce="issue267-online-a2-nonce",
        ttl_seconds=60,
        operator="test-operator",
        reason="A2 online checkpoint test",
    )


def test_online_snapshot_persists_hash_bound_checkpoint_and_receipt(
    tmp_path,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, rpc, _risk = commodity(tmp_path, drain)

    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )

    assert result["state"]["state"] == "SAFE_TO_RESTART"
    snapshot = result["receipt"]["snapshot"]
    assert snapshot["state_version"] == (
        "web_bridge_deployment_online_checkpoint_v1"
    )
    assert snapshot["execution_plan_status"] == "IDLE"
    assert snapshot["plan_version"] == 0
    assert snapshot["rpc_generation"] == 7
    assert snapshot["checkpoint_durable"] is True
    assert rpc.capture_calls == 1
    assert rpc.send_order_calls == 0

    path = drain._checkpoint_path(snapshot["checkpoint_sha256"])
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == snapshot["checkpoint_sha256"]
    assert path.stat().st_mode & 0o777 == 0o600
    checkpoint = DeploymentOnlineCheckpointDTO.model_validate_json(raw)
    schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-deployment-online-checkpoint-v1.schema.json"
        ).read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(
        checkpoint.model_dump(mode="json")
    )
    assert checkpoint.state_sha256 == snapshot["state_sha256"]
    assert checkpoint.active_orders_snapshot_sha256 == snapshot[
        "active_orders_snapshot_sha256"
    ]
    assert checkpoint.positions_snapshot_sha256 == snapshot[
        "positions_snapshot_sha256"
    ]
    assert checkpoint.rpc.account_hashes == [ACCOUNT_HASH]


def test_online_snapshot_lock_order_is_gate_then_cycle_then_rpc(
    tmp_path,
    monkeypatch,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-lock-order")
    service, rpc, _risk = commodity(tmp_path, drain)
    trace: list[str] = []
    original_exclusive = drain._exclusive_initialized
    original_cycle = service._cycle_lock
    original_capture = rpc.capture_deployment_facts

    @contextmanager
    def recorded_exclusive():
        with original_exclusive():
            trace.append("gate")
            yield

    class RecordedCycle:
        def __enter__(self):
            value = original_cycle.__enter__()
            trace.append("cycle")
            return value

        def __exit__(self, *args):
            return original_cycle.__exit__(*args)

    def recorded_capture(*, request_id, challenge):
        trace.append("rpc")
        return original_capture(
            request_id=request_id,
            challenge=challenge,
        )

    monkeypatch.setattr(drain, "_exclusive_initialized", recorded_exclusive)
    monkeypatch.setattr(service, "_cycle_lock", RecordedCycle())
    monkeypatch.setattr(rpc, "capture_deployment_facts", recorded_capture)

    service.acquire_deployment_drain(request(drain.runtime_instance_id))

    assert trace.index("gate") < trace.index("cycle") < trace.index("rpc")
    assert rpc.send_order_calls == 0


def test_restart_verifies_checkpoint_but_remains_frozen(tmp_path) -> None:
    first = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, rpc, _risk = commodity(tmp_path, first)
    result = service.acquire_deployment_drain(request(first.runtime_instance_id))

    restarted = DeploymentDrainService(
        first.root,
        runtime_instance_id="runtime-online-a2-new",
        allow_initial_bootstrap=True,
    )
    status = restarted.status()

    assert status["state"] == "RESTARTED_FROZEN"
    assert status["execution_epoch"] == result["receipt"]["execution_epoch"] + 1
    assert restarted.verified_restart_checkpoint is not None
    assert restarted.verified_restart_checkpoint.request_id == (
        result["receipt"]["request_id"]
    )
    assert status["deployment_authorized"] is False
    assert rpc.send_order_calls == 0


def test_every_restarted_frozen_epoch_reverifies_checkpoint(tmp_path) -> None:
    first = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, _rpc, _risk = commodity(tmp_path, first)
    service.acquire_deployment_drain(request(first.runtime_instance_id))
    second = DeploymentDrainService(
        first.root,
        runtime_instance_id="runtime-online-a2-second",
        allow_initial_bootstrap=True,
    )
    second_status = second.status()
    assert second.verified_restart_checkpoint is not None

    third = DeploymentDrainService(
        first.root,
        runtime_instance_id="runtime-online-a2-third",
        allow_initial_bootstrap=True,
    )
    third_status = third.status()

    assert third_status["state"] == "RESTARTED_FROZEN"
    assert third_status["execution_epoch"] == second_status["execution_epoch"] + 1
    assert third.verified_restart_checkpoint is not None
    assert third.verified_restart_checkpoint.request_id == (
        second.verified_restart_checkpoint.request_id
    )


def test_restart_rejects_exact_byte_receipt_rewrite(tmp_path) -> None:
    first = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, _rpc, _risk = commodity(tmp_path, first)
    result = service.acquire_deployment_drain(request(first.runtime_instance_id))
    receipt_path = first._receipt_path(result["receipt"]["receipt_id"])
    receipt_path.write_text(
        json.dumps(json.loads(receipt_path.read_text()), indent=2) + "\n"
    )
    receipt_path.chmod(0o600)
    restarted = DeploymentDrainService(
        first.root,
        runtime_instance_id="runtime-online-a2-new",
        allow_initial_bootstrap=True,
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        restarted.status()

    assert exc_info.value.code == "SAFE_RESTART_RECEIPT_RAW_HASH_MISMATCH"
    assert restarted.status()["blockers"] == [
        "checkpoint_verification_failed:SAFE_RESTART_RECEIPT_RAW_HASH_MISMATCH"
    ]


def test_safe_idempotent_acquire_rejects_exact_byte_receipt_rewrite(
    tmp_path,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, _rpc, _risk = commodity(tmp_path, drain)
    acquire = request(drain.runtime_instance_id)
    result = service.acquire_deployment_drain(acquire)
    receipt_path = drain._receipt_path(result["receipt"]["receipt_id"])
    receipt_path.write_text(
        json.dumps(json.loads(receipt_path.read_text()), indent=2) + "\n"
    )
    receipt_path.chmod(0o600)

    with pytest.raises(DeploymentDrainError) as exc_info:
        service.acquire_deployment_drain(acquire)

    assert exc_info.value.code == "SAFE_RESTART_RECEIPT_RAW_HASH_MISMATCH"
    assert drain.status()["state"] == "DRAIN_BLOCKED"
    assert drain.status()["blockers"] == [
        "safe_receipt_verification_failed:SAFE_RESTART_RECEIPT_RAW_HASH_MISMATCH"
    ]


@pytest.mark.parametrize(
    "unsafe",
    [
        "authority",
        "web_trade",
        "active_order",
        "pending_send",
        "state_error",
        "worker_alive",
    ],
)
def test_online_snapshot_records_unsafe_facts_and_issues_no_receipt(
    tmp_path,
    unsafe,
) -> None:
    drain = gate(tmp_path, runtime_id=f"runtime-online-a2-{unsafe}")
    service, rpc, risk = commodity(tmp_path, drain)
    if unsafe == "authority":
        service.enabled = True
    elif unsafe == "web_trade":
        risk.web_trade_enabled = True
    elif unsafe == "active_order":
        rpc.facts = rpc.facts.model_copy(
            update={
                "active_orders": [
                    {
                        "status": "not_traded",
                        "vt_orderid": "CTP.1",
                    }
                ],
                "orders": [
                    {
                        "status": "not_traded",
                        "vt_orderid": "CTP.1",
                    }
                ],
            }
        )
    elif unsafe == "pending_send":
        rpc.facts = rpc.facts.model_copy(
            update={"pending_send_outcomes": 1}
        )
    elif unsafe == "state_error":
        service._state_load_error = "active_plan:JSONDecodeError"
    else:
        service._task = type(
            "LiveTask",
            (),
            {"done": lambda self: False},
        )()  # type: ignore[assignment]

    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )

    assert result["state"]["state"] == "DRAIN_BLOCKED"
    assert result["receipt"] is None
    assert result["blockers"]
    assert not list(drain.receipt_dir.iterdir())
    assert len(list(drain.checkpoint_dir.iterdir())) == 1
    assert rpc.send_order_calls == 0


def test_checkpoint_capture_outside_gate_is_rejected(tmp_path) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-outside")
    service, rpc, _risk = commodity(tmp_path, drain)

    with pytest.raises(DeploymentDrainError) as exc_info:
        service._capture_online_deployment_snapshot()

    assert exc_info.value.code == "DEPLOYMENT_SNAPSHOT_OUTSIDE_GATE"
    assert rpc.capture_calls == 0
    assert not list(drain.checkpoint_dir.iterdir())


def test_online_snapshot_rejects_an_extra_unapproved_account(tmp_path) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-extra-account")
    service, rpc, _risk = commodity(tmp_path, drain)
    rpc.facts = rpc.facts.model_copy(
        update={"account_hashes": sorted([ACCOUNT_HASH, SHA_A])}
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        service.acquire_deployment_drain(request(drain.runtime_instance_id))

    assert exc_info.value.code == "DEPLOYMENT_SNAPSHOT_ACCOUNT_MISMATCH"
    assert drain.status()["blockers"] == [
        "snapshot_capture_failed:DeploymentDrainError"
    ]
    assert not list(drain.receipt_dir.iterdir())


def test_online_snapshot_blocks_nonzero_position_without_durable_target(
    tmp_path,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-position-drift")
    service, rpc, _risk = commodity(tmp_path, drain)
    rpc.facts = rpc.facts.model_copy(
        update={
            "positions": [
                {
                    "direction": "long",
                    "volume": 1,
                    "vt_symbol": "rb2610.SHFE",
                }
            ]
        }
    )

    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )

    assert result["state"]["state"] == "DRAIN_BLOCKED"
    assert result["blockers"] == ["reconcile_required"]


def test_online_snapshot_cannot_use_legacy_release_after_windows_fence(
    tmp_path,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-no-release")
    service, _rpc, _risk = commodity(tmp_path, drain)
    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        drain.release(
            expected_drain_epoch=result["state"]["drain_epoch"],
            request_id=result["state"]["active_request_id"],
            operator="test-operator",
            reason="A2 must remain frozen",
        )

    assert exc_info.value.code == (
        "ONLINE_SNAPSHOT_RELEASE_INACTIVE_PHASE_1_PRE_B_A2"
    )
    assert drain.status()["state"] == "SAFE_TO_RESTART"


def test_expired_online_snapshot_remains_unreleasable(tmp_path) -> None:
    now = [datetime(2026, 8, 4, tzinfo=timezone.utc)]
    drain = DeploymentDrainService(
        tmp_path / "deployment-drain",
        clock=lambda: now[0],
        runtime_instance_id="runtime-online-a2-expiry",
        allow_initial_bootstrap=True,
    )
    drain.status()
    service, rpc, _risk = commodity(tmp_path, drain)
    rpc.facts = rpc.facts.model_copy(update={"captured_at": now[0]})
    service.clock = lambda: now[0]
    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )
    now[0] = now[0].replace(minute=2)

    assert drain.status()["state"] == "DRAIN_BLOCKED"
    with pytest.raises(DeploymentDrainError) as exc_info:
        drain.release(
            expected_drain_epoch=result["state"]["drain_epoch"],
            request_id=result["state"]["active_request_id"],
            operator="test-operator",
            reason="expired A2 fence must remain closed",
        )

    assert exc_info.value.code == (
        "ONLINE_SNAPSHOT_RELEASE_INACTIVE_PHASE_1_PRE_B_A2"
    )


def test_expired_online_snapshot_revalidates_checkpoint_on_restart(
    tmp_path,
) -> None:
    now = [datetime(2026, 8, 4, tzinfo=timezone.utc)]
    first = DeploymentDrainService(
        tmp_path / "deployment-drain",
        clock=lambda: now[0],
        runtime_instance_id="runtime-online-a2-expired-old",
        allow_initial_bootstrap=True,
    )
    first.status()
    service, rpc, _risk = commodity(tmp_path, first)
    rpc.facts = rpc.facts.model_copy(update={"captured_at": now[0]})
    service.clock = lambda: now[0]
    service.acquire_deployment_drain(request(first.runtime_instance_id))
    now[0] = now[0].replace(minute=2)
    assert first.status()["state"] == "DRAIN_BLOCKED"

    restarted = DeploymentDrainService(
        first.root,
        clock=lambda: now[0],
        runtime_instance_id="runtime-online-a2-expired-new",
        allow_initial_bootstrap=True,
    )

    assert restarted.status()["state"] == "RESTARTED_FROZEN"
    assert restarted.verified_restart_checkpoint is not None


def test_expired_online_snapshot_tamper_fails_restart(tmp_path) -> None:
    now = [datetime(2026, 8, 4, tzinfo=timezone.utc)]
    first = DeploymentDrainService(
        tmp_path / "deployment-drain",
        clock=lambda: now[0],
        runtime_instance_id="runtime-online-a2-expired-old",
        allow_initial_bootstrap=True,
    )
    first.status()
    service, rpc, _risk = commodity(tmp_path, first)
    rpc.facts = rpc.facts.model_copy(update={"captured_at": now[0]})
    service.clock = lambda: now[0]
    result = service.acquire_deployment_drain(request(first.runtime_instance_id))
    now[0] = now[0].replace(minute=2)
    assert first.status()["state"] == "DRAIN_BLOCKED"
    first._checkpoint_path(
        result["receipt"]["snapshot"]["checkpoint_sha256"]
    ).write_text('{"tampered":true}\n')

    restarted = DeploymentDrainService(
        first.root,
        clock=lambda: now[0],
        runtime_instance_id="runtime-online-a2-expired-new",
        allow_initial_bootstrap=True,
    )
    with pytest.raises(DeploymentDrainError) as exc_info:
        restarted.status()

    assert exc_info.value.code == "DEPLOYMENT_CHECKPOINT_HASH_MISMATCH"


@pytest.mark.parametrize(
    "position",
    [
        {"direction": "long", "volume": 0.5, "vt_symbol": "rb2610.SHFE"},
        {
            "direction": "long",
            "frozen": 0.5,
            "volume": 1,
            "vt_symbol": "rb2610.SHFE",
        },
        {
            "direction": "long",
            "volume": 1,
            "yd_volume": 1.5,
            "vt_symbol": "rb2610.SHFE",
        },
        {
            "direction": "long",
            "volume": 1,
            "yd_volume": 0,
            "ydPosition": 0.5,
            "vt_symbol": "rb2610.SHFE",
        },
    ],
)
def test_online_snapshot_blocks_fractional_position_facts(
    tmp_path,
    position,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-fractional")
    service, rpc, _risk = commodity(tmp_path, drain)
    rpc.facts = rpc.facts.model_copy(update={"positions": [position]})

    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )

    assert result["state"]["state"] == "DRAIN_BLOCKED"
    assert result["blockers"] == ["reconcile_required"]


@pytest.mark.parametrize(
    "position",
    [
        {
            "symbol": "ag2612",
            "exchange": "SHFE",
            "vt_symbol": "rb2610.SHFE",
            "direction": "long",
            "volume": 1,
            "yd_volume": 1,
        },
        {
            "symbol": "rb2610",
            "exchange": "DCE",
            "vt_symbol": "rb2610.SHFE",
            "direction": "long",
            "volume": 1,
            "yd_volume": 1,
        },
    ],
)
def test_online_snapshot_blocks_contradictory_position_identity(
    tmp_path,
    position,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-position-id")
    service, rpc, _risk = commodity(tmp_path, drain)
    service._completed_state = {
        "last_completed_batch_hash": SHA_A,
        "targets": [
            {
                "product": "rb",
                "exact_contract": "SHFE.rb2610",
                "target_quantity": 1,
            }
        ],
    }
    rpc.facts = rpc.facts.model_copy(update={"positions": [position]})

    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )

    assert result["state"]["state"] == "DRAIN_BLOCKED"
    assert result["blockers"] == ["reconcile_required"]


def test_online_snapshot_accepts_position_matching_durable_target(
    tmp_path,
) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-position-match")
    service, rpc, _risk = commodity(tmp_path, drain)
    service._completed_state = {
        "last_completed_batch_hash": SHA_A,
        "targets": [
            {
                "product": "rb",
                "exact_contract": "SHFE.rb2610",
                "target_quantity": 1,
            }
        ],
    }
    rpc.facts = rpc.facts.model_copy(
        update={
            "positions": [
                {
                    "symbol": "rb2610",
                    "exchange": "SHFE",
                    "vt_symbol": "rb2610.SHFE",
                    "direction": "long",
                    "volume": 1,
                    "yd_volume": 1,
                }
            ]
        }
    )

    result = service.acquire_deployment_drain(
        request(drain.runtime_instance_id)
    )

    assert result["state"]["state"] == "SAFE_TO_RESTART"
    assert result["receipt"]["snapshot"]["reconcile_required"] is False


def test_rpc_facts_reject_active_order_omitted_from_active_snapshot() -> None:
    with pytest.raises(ValueError, match="missing from active orders"):
        DeploymentRpcFactsDTO(
            schema_version="windows_rpc_deployment_safety_snapshot_v1",
            request_id="request-online-a2-0001",
            challenge="issue267-online-a2-nonce",
            server_instance_id="windows-rpc-a2-instance",
            fact_generation=1,
            captured_at=datetime.now(timezone.utc),
            execution_admission_frozen=True,
            pending_send_outcomes=0,
            strategy_execution_enabled=False,
            account_hashes=[ACCOUNT_HASH],
            orders=[{"status": "not_traded", "vt_orderid": "CTP.1"}],
            active_orders=[],
            trades=[],
            positions=[],
        )


@pytest.mark.parametrize("status", ["提交中", "未成交", "部分成交"])
def test_rpc_facts_normalize_real_vnpy_active_statuses(status) -> None:
    row = {"status": status, "vt_orderid": "CTP.1"}
    facts = DeploymentRpcFactsDTO(
        schema_version="windows_rpc_deployment_safety_snapshot_v1",
        request_id="request-online-a2-0001",
        challenge="issue267-online-a2-nonce",
        server_instance_id="windows-rpc-a2-instance",
        fact_generation=1,
        captured_at=datetime.now(timezone.utc),
        execution_admission_frozen=True,
        pending_send_outcomes=0,
        strategy_execution_enabled=False,
        account_hashes=[ACCOUNT_HASH],
        orders=[row],
        active_orders=[row],
        trades=[],
        positions=[],
    )
    assert facts.active_orders == [row]

    missing = facts.model_dump(mode="python")
    missing["active_orders"] = []
    with pytest.raises(ValueError, match="missing from active orders"):
        DeploymentRpcFactsDTO(**missing)


def test_tampered_checkpoint_fences_old_epoch_and_fails_restart(tmp_path) -> None:
    first = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, _rpc, _risk = commodity(tmp_path, first)
    result = service.acquire_deployment_drain(request(first.runtime_instance_id))
    checkpoint_path = first._checkpoint_path(
        result["receipt"]["snapshot"]["checkpoint_sha256"]
    )
    checkpoint_path.write_text(json.dumps({"tampered": True}))
    checkpoint_path.chmod(0o600)
    restarted = DeploymentDrainService(
        first.root,
        runtime_instance_id="runtime-online-a2-new",
        allow_initial_bootstrap=True,
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        restarted.status()

    assert exc_info.value.code == "DEPLOYMENT_CHECKPOINT_HASH_MISMATCH"
    durable = json.loads(first.state_path.read_text())
    assert durable["state"] == "RESTARTED_FROZEN"
    assert durable["execution_epoch"] == result["receipt"]["execution_epoch"] + 1
    assert durable["blockers"] == [
        "checkpoint_verification_failed:DEPLOYMENT_CHECKPOINT_HASH_MISMATCH"
    ]
    observed = restarted.status()
    assert observed["state"] == "RESTARTED_FROZEN"
    assert observed["execution_epoch"] == durable["execution_epoch"]
    assert observed["blockers"] == durable["blockers"]


def test_restart_rejects_checkpoint_challenge_not_bound_to_receipt_nonce(
    tmp_path,
) -> None:
    first = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, _rpc, _risk = commodity(tmp_path, first)
    result = service.acquire_deployment_drain(request(first.runtime_instance_id))

    checkpoint_path = first._checkpoint_path(
        result["receipt"]["snapshot"]["checkpoint_sha256"]
    )
    checkpoint = json.loads(checkpoint_path.read_text())
    checkpoint["rpc"]["challenge"] = "different-online-a2-nonce"
    checkpoint_raw = (
        json.dumps(
            checkpoint,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    checkpoint_sha = hashlib.sha256(checkpoint_raw).hexdigest()
    replacement_checkpoint_path = first._checkpoint_path(checkpoint_sha)
    replacement_checkpoint_path.write_bytes(checkpoint_raw)
    replacement_checkpoint_path.chmod(0o600)

    receipt = dict(result["receipt"])
    receipt["snapshot"] = dict(receipt["snapshot"])
    receipt["snapshot"]["checkpoint_sha256"] = checkpoint_sha
    receipt.pop("receipt_id")
    receipt.pop("receipt_core_sha256")
    receipt_core_raw = json.dumps(
        receipt,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    receipt_core_sha = hashlib.sha256(receipt_core_raw).hexdigest()
    receipt.update(
        receipt_id=f"safe-restart-{receipt_core_sha}",
        receipt_core_sha256=receipt_core_sha,
    )
    receipt_raw = (
        json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    replacement_receipt_path = first._receipt_path(receipt["receipt_id"])
    replacement_receipt_path.write_bytes(receipt_raw)
    replacement_receipt_path.chmod(0o600)
    with first._exclusive():
        state = first._load_state()
        state["active_receipt_id"] = receipt["receipt_id"]
        state["active_receipt_raw_sha256"] = hashlib.sha256(
            receipt_raw
        ).hexdigest()
        first._write_state(state)

    restarted = DeploymentDrainService(
        first.root,
        runtime_instance_id="runtime-online-a2-new",
        allow_initial_bootstrap=True,
    )
    with pytest.raises(DeploymentDrainError) as exc_info:
        restarted.status()

    assert exc_info.value.code == "DEPLOYMENT_CHECKPOINT_RECEIPT_MISMATCH"


def test_missing_checkpoint_is_persistently_fail_closed_on_restart(
    tmp_path,
) -> None:
    first = gate(tmp_path, runtime_id="runtime-online-a2-old")
    service, _rpc, _risk = commodity(tmp_path, first)
    result = service.acquire_deployment_drain(request(first.runtime_instance_id))
    first._checkpoint_path(
        result["receipt"]["snapshot"]["checkpoint_sha256"]
    ).unlink()
    restarted = DeploymentDrainService(
        first.root,
        runtime_instance_id="runtime-online-a2-new",
        allow_initial_bootstrap=True,
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        restarted.status()

    assert exc_info.value.code == "DEPLOYMENT_CHECKPOINT_MISSING"
    assert restarted.status()["blockers"] == [
        "checkpoint_verification_failed:DEPLOYMENT_CHECKPOINT_MISSING"
    ]


def test_consume_and_reconciliation_remain_inactive_after_a2(tmp_path) -> None:
    drain = gate(tmp_path, runtime_id="runtime-online-a2-inactive")

    with pytest.raises(DeploymentDrainError) as consume:
        drain.consume(  # type: ignore[arg-type]
            object(), consumer_run_id="workflow-a2", operator="operator"
        )
    with pytest.raises(DeploymentDrainError) as reconcile:
        drain.complete_reconciliation(
            expected_execution_epoch=drain.execution_epoch,
            operator="operator",
            reason="A2 must remain frozen",
        )

    assert consume.value.code == "SAFE_RESTART_CONSUMER_INACTIVE_PHASE_1_PRE_A"
    assert reconcile.value.code == "RECONCILIATION_INACTIVE_PHASE_1_PRE_A"
