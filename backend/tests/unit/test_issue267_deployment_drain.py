from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.schemas.deployment_drain import (
    DeploymentDrainAcquireDTO,
    DeploymentSafetySnapshotDTO,
    SafeRestartConsumeMarkerDTO,
    SafeRestartReceiptDTO,
    SafeRestartRecheckDTO,
)
from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
    deployment_drain_for,
)
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SHA_A = "a" * 64
SHA_B = "b" * 64
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 4, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def _request(runtime_id: str = "runtime-one") -> DeploymentDrainAcquireDTO:
    return DeploymentDrainAcquireDTO(
        schema_version="web_bridge_deployment_drain_acquire_v1",
        request_id="request-id-0001",
        deployment_attempt_id="attempt-id-0001",
        release_plan_id=f"release-plan-{SHA_A}",
        release_plan_core_sha256=SHA_A,
        restart_action_sha256=SHA_B,
        issuer_source_commit_sha=COMMIT_A,
        issuer_image_digest=f"sha256:{SHA_A}",
        issuer_config_sha256=SHA_A,
        issuer_runtime_instance_id=runtime_id,
        target_source_commit_sha=COMMIT_B,
        target_image_digest=f"sha256:{SHA_B}",
        target_config_sha256=SHA_B,
        rollback_image_digest=f"sha256:{SHA_A}",
        rollback_config_sha256=SHA_A,
        nonce="restart_nonce_0001",
        ttl_seconds=60,
        operator="release-operator",
        reason="issue 267 safe restart test",
    )


def _snapshot(clock: Clock, **updates: object) -> DeploymentSafetySnapshotDTO:
    values: dict[str, object] = {
        "schema_version": "web_bridge_deployment_safety_snapshot_v1",
        "captured_at": clock(),
        "execution_plan_status": "IDLE",
        "execution_plan_hash": None,
        "plan_version": 7,
        "state_version": "commodity-simnow-v1",
        "state_sha256": SHA_A,
        "active_orders_snapshot_sha256": SHA_A,
        "positions_snapshot_sha256": SHA_B,
        "checkpoint_sha256": SHA_B,
        "rpc_generation": 3,
        "web_trade_enabled": False,
        "execution_authority_revoked": True,
        "auto_dispatch_stopped": True,
        "active_orders": 0,
        "unknown_outcome": False,
        "reconcile_required": False,
        "checkpoint_durable": True,
    }
    values.update(updates)
    return DeploymentSafetySnapshotDTO.model_validate(values)


def _service(tmp_path: Path, clock: Clock) -> DeploymentDrainService:
    return DeploymentDrainService(
        tmp_path / "deployment-drain",
        clock=clock,
        runtime_instance_id="runtime-one",
        allow_initial_bootstrap=True,
    )


def _acquire(
    service: DeploymentDrainService,
    clock: Clock,
    snapshot: DeploymentSafetySnapshotDTO | None = None,
) -> dict[str, object]:
    return service.acquire_with_snapshot(
        _request(), lambda: snapshot or _snapshot(clock)
    )


def _recheck(
    service: DeploymentDrainService,
    clock: Clock,
    receipt: SafeRestartReceiptDTO,
) -> SafeRestartRecheckDTO:
    status = service.status()
    later_snapshot = receipt.snapshot.model_copy(
        update={"captured_at": clock()}
    )
    return SafeRestartRecheckDTO(
        schema_version="web_bridge_safe_restart_recheck_v1",
        receipt_id=receipt.receipt_id,
        receipt_raw_sha256=status["active_receipt_raw_sha256"],
        deployment_attempt_id=receipt.deployment_attempt_id,
        release_plan_core_sha256=receipt.release_plan_core_sha256,
        restart_action_sha256=receipt.restart_action_sha256,
        drain_epoch=receipt.drain_epoch,
        execution_epoch=receipt.execution_epoch,
        checked_at=clock(),
        snapshot=later_snapshot,
    )


def test_default_is_inert_and_execution_epoch_is_durable(tmp_path: Path) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    first = service.status()
    assert first["state"] == "RUNNING"
    assert first["execution_epoch"] == 1
    assert first["deployment_authorized"] is False
    assert first["automatic_deploy_allowed"] is False
    assert first["production_allowed"] is False

    restarted = _service(tmp_path, clock).status()
    assert restarted["state"] == "RUNNING"
    assert restarted["execution_epoch"] == 2


def test_construction_is_lazy_and_has_no_filesystem_or_epoch_side_effect(
    tmp_path: Path,
) -> None:
    root = tmp_path / "lazy-drain"
    service = DeploymentDrainService(
        root,
        clock=Clock(),
        runtime_instance_id="runtime-lazy",
        allow_initial_bootstrap=True,
    )

    assert not root.exists()
    assert service.execution_epoch == 0
    assert service.status()["execution_epoch"] == 1
    assert root.is_dir()


def test_missing_or_rolled_back_state_never_bootstraps_implicitly(
    tmp_path: Path,
) -> None:
    root = tmp_path / "missing-state"
    with pytest.raises(DeploymentDrainError) as missing:
        DeploymentDrainService(root, clock=Clock()).status()
    assert missing.value.code == "DEPLOYMENT_DRAIN_BOOTSTRAP_REQUIRED"

    service = DeploymentDrainService(
        root,
        clock=Clock(),
        runtime_instance_id="runtime-bootstrap",
        allow_initial_bootstrap=True,
    )
    assert service.status()["execution_epoch"] == 1
    state = service._load_state()
    service.state_path.unlink()
    with pytest.raises(DeploymentDrainError) as deleted:
        DeploymentDrainService(
            root,
            clock=Clock(),
            runtime_instance_id="runtime-after-delete",
            allow_initial_bootstrap=True,
        ).status()
    assert deleted.value.code == "DEPLOYMENT_DRAIN_BOOTSTRAP_REQUIRED"

    state["execution_epoch"] = 0
    service._atomic_write(
        service.state_path,
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        + b"\n",
    )
    with pytest.raises(DeploymentDrainError) as rollback:
        DeploymentDrainService(
            root,
            clock=Clock(),
            runtime_instance_id="runtime-after-rollback",
            allow_initial_bootstrap=True,
        ).status()
    assert rollback.value.code == "DEPLOYMENT_DRAIN_EPOCH_ROLLBACK"


def test_acquire_is_idempotent_and_captures_inside_gate(tmp_path: Path) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    observed_states: list[str] = []

    def provider() -> DeploymentSafetySnapshotDTO:
        payload = json.loads((service.root / "state.json").read_text())
        observed_states.append(payload["state"])
        return _snapshot(clock)

    first = service.acquire_with_snapshot(_request(), provider)
    second = service.acquire_with_snapshot(_request(), provider)
    assert observed_states == ["DRAINING"]
    assert first["state"]["state"] == "SAFE_TO_RESTART"
    assert first["receipt"] == second["receipt"]
    assert first["state"]["drain_epoch"] == 1
    assert first["state"]["deployment_authorized"] is False

    receipt = SafeRestartReceiptDTO.model_validate(first["receipt"])
    canonical_core = receipt.model_dump(mode="json")
    canonical_core.pop("receipt_id")
    canonical_core.pop("receipt_core_sha256")
    encoded = json.dumps(
        canonical_core, sort_keys=True, separators=(",", ":")
    ).encode()
    assert receipt.receipt_core_sha256 == hashlib.sha256(encoded).hexdigest()
    assert receipt.receipt_id.endswith(receipt.receipt_core_sha256)


def test_unsafe_snapshot_blocks_and_explicit_release_is_required(
    tmp_path: Path,
) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    result = _acquire(
        service,
        clock,
        _snapshot(clock, web_trade_enabled=True, active_orders=1),
    )
    assert result["state"]["state"] == "DRAIN_BLOCKED"
    assert set(result["blockers"]) == {"web_trade_enabled", "active_orders"}
    assert service.is_frozen() is True
    with (
        pytest.raises(DeploymentDrainError, match="mutation rejected"),
        service.mutation_guard(),
    ):
        pass

    released = service.release(
        expected_drain_epoch=1,
        request_id=_request().request_id,
        operator="release-operator",
        reason="unsafe snapshot fixed outside drain",
    )
    assert released["state"] == "RUNNING"
    assert released["deployment_authorized"] is False


def test_expiry_never_unlocks_the_gate(tmp_path: Path) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    _acquire(service, clock)
    clock.advance(60)
    status = service.status()
    assert status["state"] == "DRAIN_BLOCKED"
    assert status["blockers"] == ["receipt_expired"]
    assert status["deployment_authorized"] is False
    with pytest.raises(DeploymentDrainError):
        service.assert_mutation_allowed()


def test_consume_and_reconciliation_stay_inactive_until_phase_1_pre_b(
    tmp_path: Path,
) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    result = _acquire(service, clock)
    receipt = SafeRestartReceiptDTO.model_validate(result["receipt"])
    clock.advance(1)
    recheck = _recheck(service, clock, receipt)
    with pytest.raises(DeploymentDrainError) as inactive:
        service.consume(
            recheck,
            consumer_run_id="workflow-run-0001",
            operator="release-operator",
        )
    assert inactive.value.code == "SAFE_RESTART_CONSUMER_INACTIVE_PHASE_1_PRE_A"
    assert service.status()["deployment_authorized"] is False
    assert not list(service.consume_dir.iterdir())

    restarted = _service(tmp_path, clock)
    frozen = restarted.status()
    assert frozen["state"] == "RESTARTED_FROZEN"
    assert frozen["execution_epoch"] == receipt.execution_epoch + 1
    assert frozen["active_receipt_id"] is None
    assert frozen["deployment_authorized"] is False
    with pytest.raises(DeploymentDrainError):
        restarted.acquire_with_snapshot(_request(), lambda: _snapshot(clock))
    with pytest.raises(DeploymentDrainError) as reconcile:
        restarted.complete_reconciliation(
            expected_execution_epoch=frozen["execution_epoch"],
            operator="reconcile-operator",
            reason="post restart state verified",
        )
    assert reconcile.value.code == "RECONCILIATION_INACTIVE_PHASE_1_PRE_A"
    assert restarted.status()["state"] == "RESTARTED_FROZEN"


@pytest.mark.parametrize(
    "unsafe_state",
    ["DRAINING", "DRAIN_BLOCKED"],
)
def test_restart_freezes_all_incomplete_drain_states(
    tmp_path: Path, unsafe_state: str
) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    if unsafe_state == "DRAINING":
        with pytest.raises(RuntimeError):
            service.acquire_with_snapshot(
                _request(), lambda: (_ for _ in ()).throw(RuntimeError("boom"))
            )
    else:
        _acquire(service, clock, _snapshot(clock, active_orders=1))
    assert service.status()["state"] == unsafe_state
    assert _service(tmp_path, clock).status()["state"] == "RESTARTED_FROZEN"


def test_mutation_guard_linearizes_with_acquire(tmp_path: Path) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    mutation_entered = threading.Event()
    release_mutation = threading.Event()
    acquire_finished = threading.Event()

    def mutation() -> None:
        with service.mutation_guard():
            mutation_entered.set()
            assert release_mutation.wait(timeout=2)

    def acquire() -> None:
        service.acquire_with_snapshot(_request(), lambda: _snapshot(clock))
        acquire_finished.set()

    mutation_thread = threading.Thread(target=mutation)
    acquire_thread = threading.Thread(target=acquire)
    mutation_thread.start()
    assert mutation_entered.wait(timeout=2)
    acquire_thread.start()
    assert not acquire_finished.wait(timeout=0.1)
    release_mutation.set()
    mutation_thread.join(timeout=2)
    acquire_thread.join(timeout=2)
    assert acquire_finished.is_set()
    assert service.status()["state"] == "SAFE_TO_RESTART"


def test_insecure_root_and_files_are_rejected(tmp_path: Path) -> None:
    clock = Clock()
    wide = tmp_path / "wide"
    wide.mkdir(mode=0o777)
    wide.chmod(0o755)
    with pytest.raises(DeploymentDrainError) as insecure_dir:
        DeploymentDrainService(wide, clock=clock).status()
    assert insecure_dir.value.code == "DEPLOYMENT_DRAIN_PATH_INSECURE"

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(DeploymentDrainError):
        DeploymentDrainService(symlink, clock=clock).status()

    service = _service(tmp_path, clock)
    service.status()
    service.state_path.chmod(0o644)
    with pytest.raises(DeploymentDrainError):
        service.status()


def test_receipt_and_consume_json_schemas_match_dtos(tmp_path: Path) -> None:
    clock = Clock()
    service = _service(tmp_path, clock)
    result = _acquire(service, clock)
    receipt = SafeRestartReceiptDTO.model_validate(result["receipt"])
    clock.advance(1)
    recheck = _recheck(service, clock, receipt)
    marker_core = {
        "schema_version": "web_bridge_safe_restart_consume_v1",
        "purpose": "consume_safe_restart_receipt_once",
        "receipt_id": receipt.receipt_id,
        "receipt_raw_sha256": service.status()["active_receipt_raw_sha256"],
        "receipt_core_sha256": receipt.receipt_core_sha256,
        "deployment_attempt_id": receipt.deployment_attempt_id,
        "release_plan_core_sha256": receipt.release_plan_core_sha256,
        "restart_action_sha256": receipt.restart_action_sha256,
        "drain_epoch": receipt.drain_epoch,
        "execution_epoch": receipt.execution_epoch,
        "consumed_at": clock().isoformat().replace("+00:00", "Z"),
        "consumer_run_id": "workflow-run-0001",
        "operator": "release-operator",
        "recheck_canonical_sha256": hashlib.sha256(
            json.dumps(
                recheck.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "one_shot_consumed": True,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
    }
    marker_sha = hashlib.sha256(
        json.dumps(
            marker_core,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    marker = SafeRestartConsumeMarkerDTO.model_validate(
        {
            **marker_core,
            "consume_id": f"safe-restart-consume-{marker_sha}",
            "consume_core_sha256": marker_sha,
        }
    )
    receipt_schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-safe-restart-receipt-v1.schema.json"
        ).read_text()
    )
    consume_schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-safe-restart-consume-v1.schema.json"
        ).read_text()
    )
    recheck_schema = json.loads(
        (
            ROOT
            / "docs/schemas/web-bridge-safe-restart-recheck-v1.schema.json"
        ).read_text()
    )
    Draft202012Validator.check_schema(receipt_schema)
    Draft202012Validator.check_schema(recheck_schema)
    Draft202012Validator.check_schema(consume_schema)
    Draft202012Validator(receipt_schema).validate(
        receipt.model_dump(mode="json")
    )
    Draft202012Validator(recheck_schema).validate(
        recheck.model_dump(mode="json")
    )
    Draft202012Validator(consume_schema).validate(marker.model_dump(mode="json"))

    with pytest.raises(ValueError, match="receipt core hash mismatch"):
        SafeRestartReceiptDTO.model_validate(
            {**receipt.model_dump(mode="json"), "receipt_core_sha256": SHA_B}
        )
    with pytest.raises(ValueError, match="consume marker core hash mismatch"):
        SafeRestartConsumeMarkerDTO.model_validate(
            {**marker.model_dump(mode="json"), "consume_core_sha256": SHA_B}
        )
    with pytest.raises(ValueError, match="zero identity"):
        DeploymentDrainAcquireDTO.model_validate(
            {
                **_request().model_dump(mode="json"),
                "release_plan_id": f"release-plan-{'0' * 64}",
            }
        )


def test_ttl_and_issuer_instance_are_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        DeploymentDrainAcquireDTO.model_validate(
            {**_request().model_dump(mode="json"), "ttl_seconds": 301}
        )
    clock = Clock()
    service = _service(tmp_path, clock)
    with pytest.raises(DeploymentDrainError) as mismatch:
        service.acquire_with_snapshot(
            _request("runtime-other"), lambda: _snapshot(clock)
        )
    assert mismatch.value.code == "ISSUER_RUNTIME_INSTANCE_MISMATCH"


def test_lazy_factory_shares_one_process_gate_per_root(tmp_path: Path) -> None:
    clock = Clock()
    root = tmp_path / "registry-drain"
    first = deployment_drain_for(
        root,
        clock=clock,
        runtime_instance_id="registry-runtime",
        allow_initial_bootstrap=True,
    )
    second = deployment_drain_for(root)
    assert first is second


def test_mutation_guard_is_reentrant_for_nested_execution_layers(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, Clock())

    with service.mutation_guard(), service.mutation_guard():
        assert service.status()["state"] == "RUNNING"


def test_new_runtime_epoch_fences_an_older_service_object(tmp_path: Path) -> None:
    clock = Clock()
    root = tmp_path / "epoch-fence"
    old = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="runtime-old",
        allow_initial_bootstrap=True,
    )
    assert old.status()["execution_epoch"] == 1
    new = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="runtime-new",
        allow_initial_bootstrap=True,
    )
    assert new.status()["execution_epoch"] == 2
    assert old.is_frozen() is True
    assert new.status()["runtime_current"] is True
    with pytest.raises(DeploymentDrainError) as stale, old.mutation_guard():
        pass
    assert stale.value.code == "EXECUTION_EPOCH_STALE"
