from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.core.config import Settings
from app.schemas.deployment_drain import (
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.commodity_simnow import CommoditySimNowService
from app.services.deployment_drain import DeploymentDrainService
from app.services.deployment_initial_baseline_reconciliation import (
    DeploymentInitialBaselineError,
)
from app.services.deployment_legacy_migration_reconciliation import (
    DeploymentLegacyMigrationError,
)
from app.services.deployment_reconciliation_activation import (
    DeploymentReconciliationActivationError,
)
from app.services.deployment_reconciliation_custody import (
    DeploymentReconciliationCustodySession,
)

ACCOUNT_HASH = "a" * 64
NOW = datetime(2026, 8, 6, 1, tzinfo=timezone.utc)


class Clock:
    def __call__(self) -> datetime:
        return NOW


class Risk:
    deployment_drain = None

    @staticmethod
    def status() -> dict[str, object]:
        return {
            "web_trade_enabled": False,
            "emergency_stopped": False,
            "rules_version": "test-rules-v1",
        }


class Trade:
    deployment_drain = None


class Rpc:
    deployment_drain = None

    def __init__(self) -> None:
        self.initial_calls: list[tuple[str, str]] = []
        self.fresh_calls: list[tuple[str, str, str, str]] = []
        self.initial: DeploymentRpcFactsDTO | None = None
        self.fail_fresh_once = False
        self.reject_cached_replay_after_generation_advance = False
        self.after_fresh_hook = None

    def capture_deployment_facts(
        self,
        *,
        request_id: str,
        challenge: str,
        allow_cached_replay: bool = False,
    ) -> DeploymentRpcFactsDTO:
        assert allow_cached_replay is False
        self.initial_calls.append((request_id, challenge))
        self.initial = DeploymentRpcFactsDTO.model_validate(
            {
                "schema_version": "windows_rpc_deployment_safety_snapshot_v1",
                "request_id": request_id,
                "challenge": challenge,
                "server_instance_id": "windows-rpc-c2b-initial",
                "fact_generation": 11,
                "captured_at": NOW,
                "execution_admission_frozen": True,
                "pending_send_outcomes": 0,
                "strategy_execution_enabled": False,
                "account_hashes": [ACCOUNT_HASH],
                "orders": [],
                "active_orders": [],
                "trades": [],
                "positions": [],
            }
        )
        return self.initial

    def capture_deployment_recheck_facts(
        self,
        *,
        request_id: str,
        owner_challenge: str,
        recheck_id: str,
        fresh_challenge: str,
        original_server_instance_id: str,
        original_fact_generation: int,
        original_execution_facts_canonical_sha256: str,
        allow_cached_replay: bool = False,
    ) -> DeploymentRpcRecheckFactsDTO:
        assert allow_cached_replay is True
        self.fresh_calls.append(
            (request_id, owner_challenge, recheck_id, fresh_challenge)
        )
        assert self.initial is not None
        assert original_server_instance_id == self.initial.server_instance_id
        assert original_fact_generation == self.initial.fact_generation
        assert original_execution_facts_canonical_sha256 == (
            deployment_rpc_execution_facts_sha256(self.initial)
        )
        result = DeploymentRpcRecheckFactsDTO.model_validate(
            {
                "schema_version": "windows_rpc_deployment_safety_recheck_v1",
                "request_id": request_id,
                "owner_challenge": owner_challenge,
                "recheck_id": recheck_id,
                "fresh_challenge": fresh_challenge,
                "original_server_instance_id": original_server_instance_id,
                "original_fact_generation": original_fact_generation,
                "original_execution_facts_canonical_sha256": (
                    original_execution_facts_canonical_sha256
                ),
                "server_instance_id": original_server_instance_id,
                "fact_generation": original_fact_generation,
                "execution_facts_canonical_sha256": (
                    original_execution_facts_canonical_sha256
                ),
                "captured_at": NOW,
                "execution_admission_frozen": True,
                "pending_send_outcomes": 0,
                "strategy_execution_enabled": False,
                "account_hashes": self.initial.account_hashes,
                "orders": self.initial.orders,
                "active_orders": self.initial.active_orders,
                "trades": self.initial.trades,
                "positions": self.initial.positions,
            }
        )
        if self.after_fresh_hook is not None:
            self.after_fresh_hook()
        if self.fail_fresh_once:
            self.fail_fresh_once = False
            raise TimeoutError("injected lost response after server completion")
        if self.reject_cached_replay_after_generation_advance:
            raise RuntimeError("cached recheck is stale after generation advance")
        return result


def _owner(tmp_path: Path) -> tuple[CommoditySimNowService, Rpc, Path]:
    root = (tmp_path / "deployment-drain").absolute()
    clock = Clock()
    bootstrap = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="bootstrap-frozen-runtime",
        allow_initial_bootstrap=True,
        initial_bootstrap_state="RESTARTED_FROZEN",
    )
    bootstrap.status()
    current = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="c2b-initial-online-runtime",
        allow_initial_bootstrap=True,
    )
    current.status()
    settings = Settings(
        app_env="test",
        deployment_drain_state_root=str(root),
        commodity_simnow_state_path=str(tmp_path / "commodity-state.json"),
        commodity_simnow_account_hashes=ACCOUNT_HASH,
        web_trade_enabled=False,
    )
    rpc = Rpc()
    owner = CommoditySimNowService(
        settings=settings,
        rpc=rpc,
        trade=Trade(),
        risk=Risk(),
        deployment_drain=current,
        clock=clock,
    )
    return owner, rpc, root


def _legacy_owner(tmp_path: Path) -> tuple[CommoditySimNowService, Rpc, Path]:
    root = (tmp_path / "deployment-drain").absolute()
    clock = Clock()
    old = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="legacy-runtime-old",
        allow_initial_bootstrap=True,
    )
    old.status()
    state = old._load_state()
    for field in (
        "state_generation",
        "previous_state_commitment_raw_sha256",
        "consumed_receipt_id",
        "consume_intent_raw_sha256",
        "consume_marker_raw_sha256",
        "consume_state_projection_sha256",
        "consumed_online_recheck_id",
        "consumed_online_recheck_raw_sha256",
        "preconsume_state_commitment_raw_sha256",
    ):
        state.pop(field)
    state["schema_version"] = "web_bridge_deployment_drain_state_v2"
    source_raw = (
        json.dumps(
            state,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    anchor_raw = (
        json.dumps(
            {
                "schema_version": "web_bridge_deployment_drain_epoch_anchor_v1",
                "drain_epoch": state["drain_epoch"],
                "execution_epoch": state["execution_epoch"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    for path in old.state_commitment_dir.iterdir():
        path.unlink()
    old._atomic_write(old.state_path, source_raw)
    old._atomic_write(old.epoch_anchor_path, anchor_raw)
    current = DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id="legacy-c2b-online-runtime",
        allow_initial_bootstrap=True,
    )
    current.status()
    settings = Settings(
        app_env="test",
        deployment_drain_state_root=str(root),
        commodity_simnow_state_path=str(tmp_path / "commodity-state.json"),
        commodity_simnow_account_hashes=ACCOUNT_HASH,
        web_trade_enabled=False,
    )
    rpc = Rpc()
    owner = CommoditySimNowService(
        settings=settings,
        rpc=rpc,
        trade=Trade(),
        risk=Risk(),
        deployment_drain=current,
        clock=clock,
    )
    return owner, rpc, root


def _planned_owner(tmp_path: Path):
    from test_issue267_deployment_drain_b2b_consume import commodity, prepared

    old, old_owner, _receipt, _online = prepared(tmp_path)
    old_owner.consume_deployment_drain(
        consumer_run_id="consumer-c2b-planned-0001",
        operator="planned-c2b-operator",
    )
    restarted = DeploymentDrainService(
        old.root,
        runtime_instance_id="runtime-c2b-planned-restarted",
        allow_initial_bootstrap=False,
    )
    restarted.status()
    owner = commodity(tmp_path, restarted)
    return owner, owner.rpc, old.root


def test_initial_c2b_activation_is_idempotent_and_non_authorizing(
    tmp_path: Path,
) -> None:
    owner, rpc, root = _owner(tmp_path)

    first = owner.reconcile_deployment_custody(
        operator="c2b-test-operator",
        reason="capture exact initial baseline owner evidence",
    )
    second = owner.reconcile_deployment_custody(
        operator="c2b-test-operator",
        reason="capture exact initial baseline owner evidence",
    )

    assert second == first
    assert first.mode == "INITIAL_BASELINE"
    assert first.owner_reconciliation_activation_recorded is True
    for field in (
        "external_high_water_verified",
        "target_runtime_verified",
        "reconciliation_completed",
        "windows_fence_released",
        "authority_restore_allowed",
        "consume_authorized",
        "reconciliation_authorized",
        "deployment_authorized",
        "automatic_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    ):
        assert getattr(first, field) is False
    assert len(rpc.initial_calls) == 1
    assert len(rpc.fresh_calls) == 1
    assert (root / first.activation_head_path).is_file()
    assert (root / first.marker.marker_path).is_file()
    commodity_slots = list(
        (root / "reconciliation-blobs").glob("*.commodity-checkpoint.json")
    )
    assert len(commodity_slots) == 1
    commodity_raw = commodity_slots[0].read_bytes()
    assert (
        root
        / "reconciliation-blobs"
        / f"{hashlib.sha256(commodity_raw).hexdigest()}.json"
    ).read_bytes() == commodity_raw


def test_existing_intent_rejects_audit_rebinding_before_rpc(tmp_path: Path) -> None:
    owner, rpc, _root = _owner(tmp_path)
    owner.reconcile_deployment_custody(
        operator="first-operator",
        reason="first exact reason",
    )

    with pytest.raises(DeploymentReconciliationActivationError) as caught:
        owner.reconcile_deployment_custody(
            operator="different-operator",
            reason="first exact reason",
        )
    assert caught.value.code == "RECONCILIATION_INTENT_COLLISION"
    assert len(rpc.initial_calls) == 1
    assert len(rpc.fresh_calls) == 1


def test_legacy_c2b_activation_uses_exact_archived_source(tmp_path: Path) -> None:
    owner, rpc, root = _legacy_owner(tmp_path)

    head = owner.reconcile_deployment_custody(
        operator="legacy-c2b-operator",
        reason="activate exact clean v2 migration evidence",
    )

    assert head.mode == "LEGACY_MIGRATION_BASELINE"
    assert head.marker.mode_evidence_schema_version == (
        "web_bridge_legacy_migration_reconciliation_v1"
    )
    assert len(rpc.initial_calls) == 1
    assert len(rpc.fresh_calls) == 1
    assert (root / head.activation_head_path).is_file()


def test_planned_c2b_reuses_consumed_recheck_without_new_initial_capture(
    tmp_path: Path,
) -> None:
    current_owner, rpc, _root = _planned_owner(tmp_path)
    capture_deployment_facts = rpc.capture_deployment_facts

    def forbidden_initial(*_args, **_kwargs):
        raise AssertionError("planned C2b must not take a new initial snapshot")

    rpc.capture_deployment_facts = forbidden_initial
    try:
        head = current_owner.reconcile_deployment_custody(
            operator="planned-c2b-operator",
            reason="activate exact planned restart reconciliation evidence",
        )
    finally:
        rpc.capture_deployment_facts = capture_deployment_facts

    assert head.mode == "PLANNED_RESTART"
    assert head.marker.mode_evidence_schema_version == (
        "web_bridge_safe_restart_reconciliation_v1"
    )
    assert head.marker.capture_pair_id.startswith(
        "deployment-reconciliation-capture-pair-"
    )


def test_fresh_timeout_recovers_without_repeating_persisted_initial_capture(
    tmp_path: Path,
) -> None:
    owner, rpc, root = _owner(tmp_path)
    rpc.fail_fresh_once = True

    with pytest.raises(DeploymentReconciliationActivationError) as caught:
        owner.reconcile_deployment_custody(
            operator="crash-recovery-operator",
            reason="recover exact initial capture after fresh timeout",
        )
    assert caught.value.code == "RECONCILIATION_FRESH_CAPTURE_INDETERMINATE"
    assert list((root / "reconciliation-heads").glob("*.json")) == []

    owner.clock = lambda: NOW + timedelta(seconds=31)

    head = owner.reconcile_deployment_custody(
        operator="crash-recovery-operator",
        reason="recover exact initial capture after fresh timeout",
    )
    assert head.owner_reconciliation_activation_recorded is True
    assert head.marker.capture_pair.captured_at == NOW
    assert len(rpc.initial_calls) == 1
    assert len(rpc.fresh_calls) == 2


@pytest.mark.parametrize(
    ("writer_name", "suffix"),
    [
        ("write_blob", ".commodity-checkpoint.json"),
        ("write_blob", ".capture-pair.json"),
        ("write_blob", ".mode-checkpoint.json"),
        ("write_blob", ".mode-evidence.json"),
        ("write_blob", ".activation-marker.json"),
        ("write_head", ".json"),
    ],
)
def test_every_durable_crash_point_resumes_without_repeating_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer_name: str,
    suffix: str,
) -> None:
    owner, rpc, _root = _owner(tmp_path)
    original = getattr(DeploymentReconciliationCustodySession, writer_name)
    crashed = False

    def crash_after_publish(self, basename, payload):
        nonlocal crashed
        stored = original(self, basename, payload)
        if not crashed and basename.endswith(suffix):
            crashed = True
            raise RuntimeError(f"crash after {writer_name}:{suffix}")
        return stored

    monkeypatch.setattr(
        DeploymentReconciliationCustodySession,
        writer_name,
        crash_after_publish,
    )
    with pytest.raises(RuntimeError, match="crash after"):
        owner.reconcile_deployment_custody(
            operator="stage-crash-operator",
            reason=f"resume exact durable stage {writer_name} {suffix}",
        )
    monkeypatch.setattr(DeploymentReconciliationCustodySession, writer_name, original)

    head = owner.reconcile_deployment_custody(
        operator="stage-crash-operator",
        reason=f"resume exact durable stage {writer_name} {suffix}",
    )
    assert head.owner_reconciliation_activation_recorded is True
    assert len(rpc.initial_calls) == 1
    assert len(rpc.fresh_calls) == 1


def test_capture_pair_recovers_after_freshness_window_without_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, rpc, _root = _owner(tmp_path)
    original = DeploymentReconciliationCustodySession.write_blob
    crashed = False

    def crash_after_pair(self, basename, payload):
        nonlocal crashed
        stored = original(self, basename, payload)
        if not crashed and basename.endswith(".capture-pair.json"):
            crashed = True
            raise RuntimeError("crash after durable capture pair")
        return stored

    monkeypatch.setattr(
        DeploymentReconciliationCustodySession, "write_blob", crash_after_pair
    )
    with pytest.raises(RuntimeError, match="durable capture pair"):
        owner.reconcile_deployment_custody(
            operator="late-recovery-operator",
            reason="resume a durable pair after the RPC freshness window",
        )
    monkeypatch.setattr(DeploymentReconciliationCustodySession, "write_blob", original)
    owner.clock = lambda: NOW.replace(minute=NOW.minute + 5)

    head = owner.reconcile_deployment_custody(
        operator="late-recovery-operator",
        reason="resume a durable pair after the RPC freshness window",
    )
    assert head.owner_reconciliation_activation_recorded is True
    assert len(rpc.initial_calls) == 1
    assert len(rpc.fresh_calls) == 1


def test_lost_fresh_response_then_generation_advance_never_commits_head(
    tmp_path: Path,
) -> None:
    owner, rpc, root = _owner(tmp_path)
    rpc.fail_fresh_once = True
    reason = "reject stale cached response after Windows generation advances"

    with pytest.raises(DeploymentReconciliationActivationError):
        owner.reconcile_deployment_custody(
            operator="generation-advance-operator", reason=reason
        )
    rpc.reject_cached_replay_after_generation_advance = True
    owner.clock = lambda: NOW + timedelta(seconds=31)

    with pytest.raises(DeploymentReconciliationActivationError) as caught:
        owner.reconcile_deployment_custody(
            operator="generation-advance-operator", reason=reason
        )
    assert caught.value.code == "RECONCILIATION_FRESH_CAPTURE_INDETERMINATE"
    assert list((root / "reconciliation-heads").glob("*.json")) == []


@pytest.mark.parametrize(
    ("mode", "checkpoint_prefix"),
    [
        (
            "INITIAL_BASELINE",
            "deployment-initial-baseline-commodity-checkpoint-",
        ),
        (
            "LEGACY_MIGRATION_BASELINE",
            "deployment-legacy-migration-commodity-checkpoint-",
        ),
    ],
)
def test_coherently_rehashed_commodity_wal_fails_before_fresh_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    checkpoint_prefix: str,
) -> None:
    if mode == "INITIAL_BASELINE":
        owner, rpc, root = _owner(tmp_path)
    else:
        owner, rpc, root = _legacy_owner(tmp_path)
    original = DeploymentReconciliationCustodySession.write_blob
    crashed = False

    def crash_after_checkpoint(self, basename, payload):
        nonlocal crashed
        stored = original(self, basename, payload)
        if not crashed and basename.endswith(".commodity-checkpoint.json"):
            crashed = True
            raise RuntimeError("crash after Commodity WAL")
        return stored

    monkeypatch.setattr(
        DeploymentReconciliationCustodySession,
        "write_blob",
        crash_after_checkpoint,
    )
    reason = f"reject coherently rehashed {mode.lower()} WAL"
    with pytest.raises(RuntimeError, match="Commodity WAL"):
        owner.reconcile_deployment_custody(
            operator="wal-rehash-operator", reason=reason
        )
    monkeypatch.setattr(
        DeploymentReconciliationCustodySession, "write_blob", original
    )

    wal_path = next(
        (root / "reconciliation-blobs").glob("*.commodity-checkpoint.json")
    )
    payload = json.loads(wal_path.read_bytes())
    payload["initial_rpc"]["request_id"] = "coherently-rehashed-wrong-request"
    core = dict(payload)
    core.pop("checkpoint_id")
    core.pop("checkpoint_core_sha256")
    digest = hashlib.sha256(
        json.dumps(
            core,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    payload["checkpoint_id"] = checkpoint_prefix + digest
    payload["checkpoint_core_sha256"] = digest
    wal_path.write_bytes(
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )

    with pytest.raises(
        (DeploymentInitialBaselineError, DeploymentLegacyMigrationError),
        match="safely bound",
    ):
        owner.reconcile_deployment_custody(
            operator="wal-rehash-operator", reason=reason
        )
    assert len(rpc.initial_calls) == 1
    assert len(rpc.fresh_calls) == 0


@pytest.mark.parametrize("mode", ["INITIAL_BASELINE", "LEGACY_MIGRATION_BASELINE", "PLANNED_RESTART"])
def test_all_modes_resume_from_durable_capture_pair_without_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    if mode == "INITIAL_BASELINE":
        owner, rpc, _root = _owner(tmp_path)
    elif mode == "LEGACY_MIGRATION_BASELINE":
        owner, rpc, _root = _legacy_owner(tmp_path)
    else:
        owner, rpc, _root = _planned_owner(tmp_path)

    initial_count = 0
    fresh_count = 0
    original_initial = rpc.capture_deployment_facts
    original_fresh = rpc.capture_deployment_recheck_facts

    def counted_initial(*args, **kwargs):
        nonlocal initial_count
        initial_count += 1
        return original_initial(*args, **kwargs)

    def counted_fresh(*args, **kwargs):
        nonlocal fresh_count
        fresh_count += 1
        return original_fresh(*args, **kwargs)

    rpc.capture_deployment_facts = counted_initial
    rpc.capture_deployment_recheck_facts = counted_fresh
    original_write = DeploymentReconciliationCustodySession.write_blob
    crashed = False

    def crash_after_pair(self, basename, payload):
        nonlocal crashed
        stored = original_write(self, basename, payload)
        if not crashed and basename.endswith(".capture-pair.json"):
            crashed = True
            raise RuntimeError("three-mode capture-pair crash")
        return stored

    monkeypatch.setattr(
        DeploymentReconciliationCustodySession, "write_blob", crash_after_pair
    )
    reason = f"resume exact {mode.lower()} capture pair"
    with pytest.raises(RuntimeError, match="three-mode"):
        owner.reconcile_deployment_custody(operator="three-mode-operator", reason=reason)
    monkeypatch.setattr(
        DeploymentReconciliationCustodySession, "write_blob", original_write
    )
    head = owner.reconcile_deployment_custody(
        operator="three-mode-operator", reason=reason
    )

    assert head.mode == mode
    assert fresh_count == 1
    assert initial_count == (0 if mode == "PLANNED_RESTART" else 1)


def test_custody_drift_during_rpc_never_publishes_activation_head(
    tmp_path: Path,
) -> None:
    owner, rpc, root = _owner(tmp_path)

    def mutate_input_metadata() -> None:
        state_path = root / "state.json"
        metadata = state_path.stat()
        # Preserve bytes but change a committed input inode timestamp.
        Path(state_path).touch()
        assert state_path.stat().st_mtime_ns >= metadata.st_mtime_ns

    rpc.after_fresh_hook = mutate_input_metadata
    with pytest.raises(DeploymentReconciliationActivationError) as caught:
        owner.reconcile_deployment_custody(
            operator="drift-test-operator",
            reason="reject custody drift across owner RPC capture",
        )
    assert caught.value.code == "RECONCILIATION_CUSTODY_CHANGED"
    assert list((root / "reconciliation-heads").glob("*.json")) == []


def test_second_commodity_owner_is_rejected_before_rpc(tmp_path: Path) -> None:
    owner, _rpc, _root = _owner(tmp_path)
    owner.reconcile_deployment_custody(
        operator="first-owner-operator",
        reason="bind the unique Commodity owner",
    )
    second_rpc = Rpc()
    second = CommoditySimNowService(
        settings=owner.settings,
        rpc=second_rpc,
        trade=Trade(),
        risk=Risk(),
        deployment_drain=owner.deployment_drain,
        clock=owner.clock,
    )

    from app.services.deployment_drain import DeploymentDrainError

    with pytest.raises(DeploymentDrainError) as caught:
        second.reconcile_deployment_custody(
            operator="second-owner-operator",
            reason="must not replace the first owner",
        )
    assert caught.value.code == "DEPLOYMENT_RECONCILIATION_OWNER_CONFLICT"
    assert second_rpc.initial_calls == []
    assert second_rpc.fresh_calls == []


def test_unsafe_local_owner_is_rejected_before_intent_or_rpc(tmp_path: Path) -> None:
    owner, rpc, root = _owner(tmp_path)
    owner.enabled = True

    from app.services.deployment_drain import DeploymentDrainError

    with pytest.raises(DeploymentDrainError) as caught:
        owner.reconcile_deployment_custody(
            operator="unsafe-owner-operator",
            reason="unsafe owner must fail closed",
        )
    assert caught.value.code == "DEPLOYMENT_RECONCILIATION_OWNER_NOT_FROZEN"
    assert rpc.initial_calls == []
    assert rpc.fresh_calls == []
    assert not (root / "reconciliation-intents").exists()


def test_simnow_mode_owner_is_rejected_before_intent_or_rpc(tmp_path: Path) -> None:
    owner, rpc, root = _owner(tmp_path)
    owner.simnow_mode = True

    from app.services.deployment_drain import DeploymentDrainError

    with pytest.raises(DeploymentDrainError) as caught:
        owner.reconcile_deployment_custody(
            operator="simnow-mode-owner-operator",
            reason="SimNow execution mode is still active authority",
        )
    assert caught.value.code == "DEPLOYMENT_RECONCILIATION_OWNER_NOT_FROZEN"
    assert rpc.initial_calls == []
    assert rpc.fresh_calls == []
    assert not (root / "reconciliation-intents").exists()


def test_reconciliation_does_not_invert_process_lock_and_flock(
    tmp_path: Path,
) -> None:
    owner, rpc, _root = _owner(tmp_path)
    drain = owner.deployment_drain
    assert drain is not None
    rendezvous = threading.Barrier(2, timeout=2)
    original_capture = rpc.capture_deployment_facts
    errors: list[BaseException] = []
    heads = []

    def capture_after_flock(
        *,
        request_id: str,
        challenge: str,
        allow_cached_replay: bool = False,
    ):
        rendezvous.wait()
        return original_capture(
            request_id=request_id,
            challenge=challenge,
            allow_cached_replay=allow_cached_replay,
        )

    def hold_process_lock_then_wait_for_flock() -> None:
        try:
            with drain._process_lock:
                rendezvous.wait()
                drain.status()
        except Exception as exc:  # noqa: BLE001 - thread reports to parent
            errors.append(exc)

    def reconcile_while_process_lock_is_held() -> None:
        try:
            heads.append(
                owner.reconcile_deployment_custody(
                    operator="lock-order-operator",
                    reason="prove process lock and deployment flock cannot deadlock",
                )
            )
        except Exception as exc:  # noqa: BLE001 - thread reports to parent
            errors.append(exc)

    rpc.capture_deployment_facts = capture_after_flock
    process_thread = threading.Thread(target=hold_process_lock_then_wait_for_flock)
    reconcile_thread = threading.Thread(target=reconcile_while_process_lock_is_held)
    process_thread.start()
    reconcile_thread.start()
    process_thread.join(timeout=5)
    reconcile_thread.join(timeout=5)

    assert not process_thread.is_alive()
    assert not reconcile_thread.is_alive()
    assert errors == []
    assert len(heads) == 1


def test_activation_preflight_never_calls_mutating_runtime_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, _rpc, _root = _owner(tmp_path)

    def forbidden_status() -> dict[str, object]:
        raise AssertionError("C2b read-only preflight must not mutate audit state")

    monkeypatch.setattr(owner.c_fast_runtime_authorization, "status", forbidden_status)

    head = owner.reconcile_deployment_custody(
        operator="readonly-runtime-operator",
        reason="prove reconciliation preflight has no audit side effects",
    )

    assert head.owner_reconciliation_activation_recorded is True


def test_activation_head_is_committed_while_commodity_guard_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.deployment_reconciliation_custody import (
        DeploymentReconciliationCustodySession,
    )

    owner, _rpc, _root = _owner(tmp_path)
    original = DeploymentReconciliationCustodySession.write_head
    observed_guard: list[bool] = []

    def guarded_write_head(self, basename, payload):
        observed_guard.append(bool(owner._cycle_lock._is_owned()))
        return original(self, basename, payload)

    monkeypatch.setattr(
        DeploymentReconciliationCustodySession, "write_head", guarded_write_head
    )

    owner.reconcile_deployment_custody(
        operator="atomic-head-operator",
        reason="commit activation under the exact Commodity guard",
    )

    assert observed_guard == [True]


def test_activation_service_rejects_non_commodity_owner(tmp_path: Path) -> None:
    from app.services.deployment_reconciliation_activation import (
        DeploymentReconciliationActivationService,
    )
    from app.services.deployment_reconciliation_custody import (
        DeploymentReconciliationCustodyRepository,
    )

    root = (tmp_path / "fake-root").absolute()

    class Fake:
        deployment_drain = type("Drain", (), {"root": root})()

    with pytest.raises(TypeError):
        DeploymentReconciliationActivationService(
            repository=DeploymentReconciliationCustodyRepository(root),
            commodity_owner=Fake(),
        )
