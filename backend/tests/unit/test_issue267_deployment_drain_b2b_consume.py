from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest
from app.core.config import Settings
from app.schemas.deployment_drain import (
    DeploymentDrainAcquireDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.commodity_simnow import CommoditySimNowService
from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
)
from app.services.deployment_online_recheck import MAX_RECHECK_AGE
from app.services.deployment_reconciliation_custody import (
    DeploymentReconciliationCustodyError,
    DeploymentReconciliationCustodyRepository,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
ACCOUNT_ID = "sim-account-b2b"
ACCOUNT_HASH = hashlib.sha256(ACCOUNT_ID.encode()).hexdigest()
AUTHORITY_FIELDS = (
    "consume_authorized",
    "reconciliation_authorized",
    "deployment_authorized",
    "automatic_deploy_allowed",
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
)
CONSUMPTION_EVIDENCE_FIELDS = (
    "consumed_at",
    "consume_id",
    "consumed_receipt_id",
    "consume_intent_raw_sha256",
    "consume_marker_raw_sha256",
    "consume_state_projection_sha256",
    "consumed_online_recheck_id",
    "consumed_online_recheck_raw_sha256",
    "preconsume_state_commitment_raw_sha256",
)


class FakeRpc:
    def __init__(self, drain: DeploymentDrainService) -> None:
        self.deployment_drain = drain
        self.facts = DeploymentRpcFactsDTO(
            schema_version="windows_rpc_deployment_safety_snapshot_v1",
            request_id="request-online-b2b-0001",
            challenge="issue267-online-b2b-nonce",
            server_instance_id="windows-rpc-b2b-instance",
            fact_generation=11,
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
        self.send_order_calls = 0

    def bind_c_fast_terminal_publication_owner(self, _owner: object) -> object:
        return object()

    def capture_deployment_facts(
        self, *, request_id: str, challenge: str
    ) -> DeploymentRpcFactsDTO:
        assert request_id == self.facts.request_id
        assert challenge == self.facts.challenge
        return self.facts

    def capture_deployment_recheck_facts(
        self, **binding: object
    ) -> DeploymentRpcRecheckFactsDTO:
        return DeploymentRpcRecheckFactsDTO(
            schema_version="windows_rpc_deployment_safety_recheck_v1",
            request_id=str(binding["request_id"]),
            owner_challenge=str(binding["owner_challenge"]),
            recheck_id=str(binding["recheck_id"]),
            fresh_challenge=str(binding["fresh_challenge"]),
            original_server_instance_id=str(binding["original_server_instance_id"]),
            original_fact_generation=int(binding["original_fact_generation"]),
            original_execution_facts_canonical_sha256=str(
                binding["original_execution_facts_canonical_sha256"]
            ),
            server_instance_id=self.facts.server_instance_id,
            fact_generation=self.facts.fact_generation,
            execution_facts_canonical_sha256=(
                deployment_rpc_execution_facts_sha256(self.facts)
            ),
            captured_at=datetime.now(timezone.utc),
            execution_admission_frozen=True,
            pending_send_outcomes=0,
            strategy_execution_enabled=False,
            account_hashes=self.facts.account_hashes,
            orders=[],
            active_orders=[],
            trades=[],
            positions=self.facts.positions,
        )

    def send_order(self, *_args: object, **_kwargs: object) -> None:
        self.send_order_calls += 1
        raise AssertionError("B2b consume tests must never send orders")


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


def commodity(tmp_path, drain: DeploymentDrainService) -> CommoditySimNowService:
    rpc = FakeRpc(drain)
    return CommoditySimNowService(
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
        risk=FakeRisk(drain),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=object(),
        clock=lambda: datetime.now(timezone.utc),
        c_fast_runtime_authorization=(
            FakeRuntimeAuthorization()  # type: ignore[arg-type]
        ),
        deployment_drain=drain,
    )


def request(runtime_id: str) -> DeploymentDrainAcquireDTO:
    return DeploymentDrainAcquireDTO(
        schema_version="web_bridge_deployment_drain_acquire_v1",
        request_id="request-online-b2b-0001",
        deployment_attempt_id="attempt-online-b2b-0001",
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
        nonce="issue267-online-b2b-nonce",
        ttl_seconds=60,
        operator="test-operator",
        reason="B2b consume WAL integration test",
    )


def prepared(tmp_path, *, runtime_id: str = "runtime-online-b2b-old"):
    drain = gate(tmp_path, runtime_id=runtime_id)
    service = commodity(tmp_path, drain)
    result = service.acquire_deployment_drain(request(runtime_id))
    recheck = service.recheck_deployment_drain()
    return drain, service, result["receipt"], recheck


def assert_no_authority(value: object) -> None:
    for field in AUTHORITY_FIELDS:
        if isinstance(value, dict):
            assert value[field] is False
        else:
            assert getattr(value, field) is False


def test_real_owner_chain_consumes_once_and_is_identity_idempotent(tmp_path) -> None:
    drain, service, _receipt, _recheck = prepared(tmp_path)

    marker = service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    repeated = service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    status = drain.status()
    intent = drain._parse_consume_intent(
        drain._consume_intent_path(marker.receipt_id).read_bytes()
    )

    assert repeated == marker
    assert status["receipt_consumed"] is True
    assert status["consume_id"] == marker.consume_marker_id
    assert status["freeze_reason"] == (
        "safe_restart_consumed_deployment_still_inactive"
    )
    assert_no_authority(marker)
    assert_no_authority(marker.consume_state_projection)
    assert_no_authority(intent)
    assert_no_authority(intent.consume_state_projection)
    assert_no_authority(status)
    with pytest.raises(DeploymentDrainError) as conflict:
        service.consume_deployment_drain(
            consumer_run_id="consumer-b2b-other",
            operator="another-operator",
        )
    assert conflict.value.code == "SAFE_RESTART_CONSUME_CONFLICT"
    with pytest.raises(DeploymentDrainError) as guard, drain.mutation_guard():
        pass
    assert guard.value.code == "DEPLOYMENT_DRAIN_ACTIVE"


def test_c2a_custody_recognizes_exact_consumed_restart_lineage(tmp_path) -> None:
    drain, service, _receipt, _recheck = prepared(tmp_path)
    marker = service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-c2a-0001",
        operator="test-operator",
    )
    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-c2a-new",
        allow_initial_bootstrap=False,
    )
    status = restarted.status()

    snapshot = DeploymentReconciliationCustodyRepository(restarted.root).snapshot()

    assert status["state"] == "RESTARTED_FROZEN"
    assert snapshot.inventory.mode == "PLANNED_RESTART"
    assert snapshot.inventory.actual_runtime_instance_id == (
        "runtime-online-b2b-c2a-new"
    )
    assert snapshot.inventory.actual_state["consume_id"] == (marker.consume_marker_id)
    assert snapshot.inventory.custody_inventory_verified is True
    assert snapshot.inventory.reconciliation_completed is False
    assert snapshot.inventory.windows_fence_released is False
    assert snapshot.inventory.authority_restore_allowed is False


def test_c2a_custody_rejects_corrupt_planned_restart_checkpoint(tmp_path) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-c2a-corrupt",
        operator="test-operator",
    )
    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-c2a-corrupt-new",
        allow_initial_bootstrap=False,
    )
    restarted.status()
    drain._checkpoint_path(receipt["snapshot"]["checkpoint_sha256"]).write_bytes(
        b"{}\n"
    )

    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        DeploymentReconciliationCustodyRepository(restarted.root).snapshot()

    assert caught.value.code == "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID"


def test_c2a_custody_rejects_orphan_planned_restart_artifact(tmp_path) -> None:
    drain, service, _receipt, _recheck = prepared(tmp_path)
    service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-c2a-orphan",
        operator="test-operator",
    )
    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-c2a-orphan-new",
        allow_initial_bootstrap=False,
    )
    restarted.status()
    orphan = drain.checkpoint_dir / f"checkpoint-{'1' * 64}.json"
    orphan.write_bytes(b"{}\n")
    orphan.chmod(0o600)

    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        DeploymentReconciliationCustodyRepository(restarted.root).snapshot()

    assert caught.value.code == "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID"


def test_c2a_custody_accepts_complete_history_before_current_restart(tmp_path) -> None:
    drain, first_owner, _receipt, _recheck = prepared(tmp_path)
    first_owner.consume_deployment_drain(
        consumer_run_id="consumer-b2b-c2a-history-first",
        operator="test-operator",
    )
    first_restart = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-c2a-history-middle",
        allow_initial_bootstrap=False,
    )
    first_restart.status()
    with first_restart._exclusive():
        state = first_restart._load_state()
        state.update(
            state="RUNNING",
            active_request_id=None,
            active_request_sha256=None,
            active_receipt_id=None,
            active_receipt_raw_sha256=None,
            receipt_consumed=False,
            consumed_at=None,
            consume_id=None,
            consumed_receipt_id=None,
            consume_intent_raw_sha256=None,
            consume_marker_raw_sha256=None,
            consume_state_projection_sha256=None,
            consumed_online_recheck_id=None,
            consumed_online_recheck_raw_sha256=None,
            preconsume_state_commitment_raw_sha256=None,
            active_online_recheck_id=None,
            active_online_recheck_raw_sha256=None,
            active_recheck_checkpoint_raw_sha256=None,
            online_rechecked_at=None,
            last_invalidated_online_recheck_id=None,
            last_invalidated_receipt_id=None,
            blockers=[],
            expires_at=None,
            freeze_reason="test_only_completed_reconciliation",
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        first_restart._write_state(state)

    second_owner = commodity(tmp_path, first_restart)
    second_owner.acquire_deployment_drain(
        request("runtime-online-b2b-c2a-history-middle")
    )
    second_owner.recheck_deployment_drain()
    second_owner.consume_deployment_drain(
        consumer_run_id="consumer-b2b-c2a-history-second",
        operator="test-operator",
    )
    second_restart = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-c2a-history-current",
        allow_initial_bootstrap=False,
    )
    second_restart.status()

    snapshot = DeploymentReconciliationCustodyRepository(second_restart.root).snapshot()

    assert snapshot.inventory.mode == "PLANNED_RESTART"
    assert (
        len(
            [
                entry
                for entry in snapshot.inventory.entries
                if entry.role == "CONSUME_MARKER"
            ]
        )
        == 2
    )

    current_receipt_id = snapshot.inventory.actual_state["consumed_receipt_id"]
    historical_marker = next(
        path
        for path in drain.consume_dir.glob("*.consume-marker.json")
        if not path.name.startswith(f"{current_receipt_id}.")
    )
    historical_marker.unlink()
    with pytest.raises(DeploymentReconciliationCustodyError) as caught:
        DeploymentReconciliationCustodyRepository(second_restart.root).snapshot()
    assert caught.value.code == "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID"


def test_wrong_owner_and_old_caller_supplied_consume_api_are_inactive(tmp_path) -> None:
    drain, _service, _receipt, _recheck = prepared(tmp_path)

    with pytest.raises(DeploymentDrainError) as wrong_owner:
        drain.consume_active_online_recheck(
            owner=object(),
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )
    assert wrong_owner.value.code == "SAFE_RESTART_CONSUME_OWNER_INVALID"
    with pytest.raises(DeploymentDrainError) as legacy:
        drain.consume(  # type: ignore[arg-type]
            object(),
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )
    assert legacy.value.code == "SAFE_RESTART_CONSUMER_INACTIVE_PHASE_1_PRE_A"


def test_marker_before_state_crash_recovers_committed_consume_and_freezes(
    tmp_path, monkeypatch
) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    original_write_state = drain._write_state

    def crash_after_marker(state):
        if state.get("receipt_consumed"):
            raise OSError("injected crash after marker before state")
        return original_write_state(state)

    monkeypatch.setattr(drain, "_write_state", crash_after_marker)
    with pytest.raises(DeploymentDrainError) as crashed:
        service.consume_deployment_drain(
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )
    assert crashed.value.code == "SAFE_RESTART_CONSUME_STATE_COMMIT_FAILED"
    monkeypatch.setattr(drain, "_write_state", original_write_state)

    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-restarted",
        allow_initial_bootstrap=True,
    )
    status = restarted.status()

    assert status["state"] == "RESTARTED_FROZEN"
    assert status["receipt_consumed"] is True
    assert status["consumed_receipt_id"] == receipt["receipt_id"]
    assert all(status[field] is not None for field in CONSUMPTION_EVIDENCE_FIELDS)
    assert_no_authority(status)
    with pytest.raises(DeploymentDrainError), restarted.mutation_guard():
        pass


def test_intent_only_same_process_retry_commits(tmp_path, monkeypatch) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    marker_path = drain._consume_marker_path(receipt["receipt_id"])
    original_persist = drain._persist_consume_artifact

    def fail_marker(path, raw, *, error_code, before_publish=None):
        if path == marker_path:
            raise DeploymentDrainError(error_code, "injected marker failure")
        return original_persist(
            path,
            raw,
            error_code=error_code,
            before_publish=before_publish,
        )

    monkeypatch.setattr(drain, "_persist_consume_artifact", fail_marker)
    with pytest.raises(DeploymentDrainError) as failed:
        service.consume_deployment_drain(
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )
    assert failed.value.code == "SAFE_RESTART_CONSUME_MARKER_PERSIST_FAILED"
    assert drain._consume_intent_path(receipt["receipt_id"]).exists()
    assert not marker_path.exists()

    monkeypatch.setattr(drain, "_persist_consume_artifact", original_persist)
    marker = service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    assert marker.one_shot_consume_committed is True
    assert drain.status()["receipt_consumed"] is True


def test_intent_retry_marker_uses_fresh_commit_time(tmp_path, monkeypatch) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    marker_path = drain._consume_marker_path(receipt["receipt_id"])
    original_persist = drain._persist_consume_artifact

    def fail_marker(path, raw, *, error_code, before_publish=None):
        if path == marker_path:
            raise DeploymentDrainError(error_code, "injected marker failure")
        return original_persist(
            path,
            raw,
            error_code=error_code,
            before_publish=before_publish,
        )

    monkeypatch.setattr(drain, "_persist_consume_artifact", fail_marker)
    with pytest.raises(DeploymentDrainError):
        service.consume_deployment_drain(
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )
    intent = drain._parse_consume_intent(
        drain._consume_intent_path(receipt["receipt_id"]).read_bytes()
    )
    retry_time = intent.prepared_at + timedelta(seconds=1)
    drain.clock = lambda: retry_time
    monkeypatch.setattr(drain, "_persist_consume_artifact", original_persist)

    marker = service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )

    assert marker.committed_at == retry_time
    assert marker.committed_at > intent.prepared_at


@pytest.mark.parametrize("clock_jump", ["past_deadline", "rollback"])
def test_marker_publish_boundary_rechecks_freshness(
    tmp_path, monkeypatch, clock_jump
) -> None:
    drain, service, receipt, recheck = prepared(tmp_path)
    marker_path = drain._consume_marker_path(receipt["receipt_id"])
    current = [recheck.checked_at]
    drain.clock = lambda: current[0]
    original_atomic = drain._write_create_only_atomic

    def cross_deadline(path, raw, *, before_publish=None):
        if path == marker_path:
            current[0] = {
                "past_deadline": (
                    recheck.checked_at + MAX_RECHECK_AGE + timedelta(microseconds=1)
                ),
                "rollback": recheck.checked_at - timedelta(microseconds=1),
            }[clock_jump]
        return original_atomic(path, raw, before_publish=before_publish)

    monkeypatch.setattr(drain, "_write_create_only_atomic", cross_deadline)
    with pytest.raises(DeploymentDrainError) as stale:
        service.consume_deployment_drain(
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )

    assert stale.value.code == "SAFE_RESTART_CONSUME_RECHECK_STALE"
    assert not marker_path.exists()


def test_clock_rollback_rejects_consume_without_marker(tmp_path) -> None:
    drain, service, receipt, recheck = prepared(tmp_path)
    drain.clock = lambda: recheck.checked_at - timedelta(hours=1)

    with pytest.raises(DeploymentDrainError) as stale:
        service.consume_deployment_drain(
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )

    assert stale.value.code == "SAFE_RESTART_CONSUME_RECHECK_STALE"
    assert not drain._consume_marker_path(receipt["receipt_id"]).exists()


@pytest.mark.parametrize("artifact", ["intent", "marker"])
def test_published_consume_hardlink_temp_is_recovered(tmp_path, artifact) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    final = (
        drain._consume_intent_path(receipt["receipt_id"])
        if artifact == "intent"
        else drain._consume_marker_path(receipt["receipt_id"])
    )
    temporary = final.with_name(f".{final.name}.{'f' * 32}.tmp")
    os.link(final, temporary)

    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-temp-recovery",
        allow_initial_bootstrap=True,
    )
    status = restarted.status()

    assert status["receipt_consumed"] is True
    assert not temporary.exists()
    assert final.stat().st_nlink == 1


def test_external_hardlink_to_custody_artifact_fails_closed(tmp_path) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    intent_path = drain._consume_intent_path(receipt["receipt_id"])
    os.link(intent_path, tmp_path / "external-intent-hardlink.json")

    with pytest.raises(DeploymentDrainError) as insecure:
        drain.status()

    assert insecure.value.code == "DEPLOYMENT_DRAIN_PATH_INSECURE"


def test_completed_historical_wal_does_not_require_current_pointer(tmp_path) -> None:
    drain, service, _receipt, _recheck = prepared(tmp_path)
    service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    historical_state = drain._load_state()
    historical_state.update(
        receipt_consumed=False,
        consumed_receipt_id=None,
        active_receipt_id=None,
        last_invalidated_receipt_id=None,
    )

    recovered = drain._recover_consume_wal(historical_state, startup=False)

    assert recovered is historical_state


def test_intent_only_restart_is_quarantined_not_consumed(tmp_path, monkeypatch) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    marker_path = drain._consume_marker_path(receipt["receipt_id"])
    original_persist = drain._persist_consume_artifact

    def fail_marker(path, raw, *, error_code, before_publish=None):
        if path == marker_path:
            raise DeploymentDrainError(error_code, "injected marker failure")
        return original_persist(
            path,
            raw,
            error_code=error_code,
            before_publish=before_publish,
        )

    monkeypatch.setattr(drain, "_persist_consume_artifact", fail_marker)
    with pytest.raises(DeploymentDrainError):
        service.consume_deployment_drain(
            consumer_run_id="consumer-b2b-0001",
            operator="test-operator",
        )

    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-restarted",
        allow_initial_bootstrap=True,
    )
    status = restarted.status()

    assert status["state"] == "RESTARTED_FROZEN"
    assert status["receipt_consumed"] is False
    assert "consume_intent_orphaned_after_restart" in status["blockers"]
    assert_no_authority(status)


def test_completed_consume_restart_retains_all_evidence_and_guard_rejects(
    tmp_path,
) -> None:
    drain, service, _receipt, _recheck = prepared(tmp_path)
    service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    before = drain.status()
    evidence = {field: before[field] for field in CONSUMPTION_EVIDENCE_FIELDS}

    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-restarted",
        allow_initial_bootstrap=True,
    )
    after = restarted.status()

    assert after["state"] == "RESTARTED_FROZEN"
    assert after["receipt_consumed"] is True
    assert {field: after[field] for field in CONSUMPTION_EVIDENCE_FIELDS} == evidence
    assert after["blockers"] == [
        "process_restarted_consumed_receipt_requires_reconciliation"
    ]
    assert_no_authority(after)
    with pytest.raises(DeploymentDrainError) as guard, restarted.mutation_guard():
        pass
    assert guard.value.code == "DEPLOYMENT_DRAIN_ACTIVE"


@pytest.mark.parametrize("artifact", ["intent", "marker", "precommit"])
def test_consume_chain_tamper_is_rejected_on_restart(tmp_path, artifact) -> None:
    drain, service, receipt, _recheck = prepared(tmp_path)
    marker = service.consume_deployment_drain(
        consumer_run_id="consumer-b2b-0001",
        operator="test-operator",
    )
    if artifact == "intent":
        path = drain._consume_intent_path(receipt["receipt_id"])
    elif artifact == "marker":
        path = drain._consume_marker_path(receipt["receipt_id"])
    else:
        path = drain._state_commitment_path(marker.preconsume_state_generation)
    raw = path.read_bytes()
    path.write_bytes(raw[:-1] + b" \n")
    path.chmod(0o600)

    restarted = DeploymentDrainService(
        drain.root,
        runtime_instance_id="runtime-online-b2b-restarted",
        allow_initial_bootstrap=True,
    )
    with pytest.raises(DeploymentDrainError) as rejected:
        restarted.status()

    if artifact == "intent":
        assert rejected.value.code == "SAFE_RESTART_CONSUME_INTENT_INVALID"
    elif artifact == "marker":
        assert rejected.value.code == "SAFE_RESTART_CONSUME_MARKER_INVALID"
    else:
        assert rejected.value.code == "DEPLOYMENT_STATE_COMMITMENT_INVALID"
