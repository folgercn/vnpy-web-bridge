from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.schemas.deployment_drain import (
    DeploymentDrainAcquireDTO,
    DeploymentSafetySnapshotDTO,
)
from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
V1 = "web_bridge_deployment_drain_state_v1"
V2 = "web_bridge_deployment_drain_state_v2"
V3 = "web_bridge_deployment_drain_state_v3"


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 4, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def service(root: Path, clock: Clock, runtime: str) -> DeploymentDrainService:
    return DeploymentDrainService(
        root,
        clock=clock,
        runtime_instance_id=runtime,
        allow_initial_bootstrap=True,
        allow_untrusted_snapshot_provider=True,
    )


def request(runtime: str) -> DeploymentDrainAcquireDTO:
    return DeploymentDrainAcquireDTO(
        schema_version="web_bridge_deployment_drain_acquire_v1",
        request_id="request-b1b-state-0001",
        deployment_attempt_id="attempt-b1b-state-0001",
        release_plan_id=f"release-plan-{SHA_A}",
        release_plan_core_sha256=SHA_A,
        restart_action_sha256=SHA_B,
        issuer_source_commit_sha="a" * 40,
        issuer_image_digest=f"sha256:{SHA_A}",
        issuer_config_sha256=SHA_A,
        issuer_runtime_instance_id=runtime,
        target_source_commit_sha="b" * 40,
        target_image_digest=f"sha256:{SHA_B}",
        target_config_sha256=SHA_B,
        rollback_image_digest=f"sha256:{SHA_A}",
        rollback_config_sha256=SHA_A,
        nonce="issue267-b1b-state-nonce",
        ttl_seconds=60,
        operator="test-operator",
        reason="B1b state transition test",
    )


def snapshot(clock: Clock) -> DeploymentSafetySnapshotDTO:
    return DeploymentSafetySnapshotDTO(
        schema_version="web_bridge_deployment_safety_snapshot_v1",
        captured_at=clock(),
        execution_plan_status="IDLE",
        execution_plan_hash=None,
        plan_version=1,
        state_version="commodity-simnow-v1",
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


def write_v1(drain: DeploymentDrainService, **updates: object) -> dict[str, object]:
    state = drain._load_state()
    for field in (
        "active_online_recheck_id",
        "active_online_recheck_raw_sha256",
        "active_recheck_checkpoint_raw_sha256",
        "online_rechecked_at",
        "last_invalidated_online_recheck_id",
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
    state.update(schema_version=V1, **updates)
    for path in drain.state_commitment_dir.iterdir():
        path.unlink()
    drain._atomic_write(
        drain.state_path,
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )
    legacy_anchor = {
        "schema_version": "web_bridge_deployment_drain_epoch_anchor_v1",
        "drain_epoch": state["drain_epoch"],
        "execution_epoch": state["execution_epoch"],
    }
    drain._atomic_write(
        drain.epoch_anchor_path,
        json.dumps(legacy_anchor, sort_keys=True, separators=(",", ":")).encode()
        + b"\n",
    )
    return state


def write_v2(drain: DeploymentDrainService, **updates: object) -> dict[str, object]:
    state = drain._load_state()
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
    state.update(schema_version=V2, **updates)
    for path in drain.state_commitment_dir.iterdir():
        path.unlink()
    drain._atomic_write(
        drain.state_path,
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )
    legacy_anchor = {
        "schema_version": "web_bridge_deployment_drain_epoch_anchor_v1",
        "drain_epoch": state["drain_epoch"],
        "execution_epoch": state["execution_epoch"],
    }
    drain._atomic_write(
        drain.epoch_anchor_path,
        json.dumps(legacy_anchor, sort_keys=True, separators=(",", ":")).encode()
        + b"\n",
    )
    return state


def recheck_id(label: str) -> str:
    return f"safe-restart-online-recheck-{hashlib.sha256(label.encode()).hexdigest()}"


def set_recheck(drain: DeploymentDrainService, label: str) -> str:
    active_id = recheck_id(label)
    with drain._exclusive():
        state = drain._load_state()
        state.update(
            active_online_recheck_id=active_id,
            active_online_recheck_raw_sha256=SHA_A,
            active_recheck_checkpoint_raw_sha256=SHA_B,
            online_rechecked_at="2026-08-04T00:00:00+00:00",
        )
        drain._write_state(state)
    return active_id


def assert_no_authority(status: dict[str, object]) -> None:
    assert status["receipt_consumed"] is False
    assert status["deployment_authorized"] is False
    assert status["consume_authorized"] is False
    assert status["reconciliation_authorized"] is False
    assert status["countable_forward"] is False


def test_clean_v1_state_migrates_to_v3_without_granting_authority(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "clean-v1"
    old = service(root, clock, "runtime-old")
    old.status()
    write_v1(old)

    migrated = service(root, clock, "runtime-new")
    status = migrated.status()

    assert status["schema_version"] == V3
    assert status["state"] == "RESTARTED_FROZEN"
    assert status["freeze_reason"] == (
        "legacy_state_migrated_to_v3_requires_reconciliation"
    )
    assert status["execution_epoch"] == 2
    assert status["active_online_recheck_id"] is None
    assert status["last_invalidated_online_recheck_id"] is None
    assert_no_authority(status)
    with pytest.raises(DeploymentDrainError) as caught, migrated.mutation_guard():
        pass
    assert caught.value.code == "DEPLOYMENT_DRAIN_ACTIVE"


@pytest.mark.parametrize(
    "legacy_field", ["receipt_consumed", "consumed_at", "consume_id"]
)
def test_v1_consumption_fields_are_quarantined(
    tmp_path: Path, legacy_field: str
) -> None:
    clock = Clock()
    root = tmp_path / legacy_field
    old = service(root, clock, "runtime-old")
    old.status()
    value: object = True if legacy_field == "receipt_consumed" else "legacy"
    write_v1(old, **{legacy_field: value})

    status = service(root, clock, "runtime-new").status()

    assert status["state"] == "RESTARTED_FROZEN"
    assert status["freeze_reason"] == "legacy_v1_consumption_evidence_quarantined"
    assert status["blockers"] == ["legacy_v1_consumption_evidence_quarantined"]
    assert status["active_receipt_id"] is None
    assert_no_authority(status)


def test_v1_consume_inventory_is_quarantined(tmp_path: Path) -> None:
    clock = Clock()
    root = tmp_path / "legacy-inventory"
    old = service(root, clock, "runtime-old")
    old.status()
    write_v1(old)
    old._write_create_only(old.consume_dir / "legacy.json", b"{}\n")

    status = service(root, clock, "runtime-new").status()

    assert status["state"] == "RESTARTED_FROZEN"
    assert status["freeze_reason"] == "legacy_v1_consumption_evidence_quarantined"
    assert_no_authority(status)


@pytest.mark.parametrize("version", [V1, V2])
def test_unknown_state_fields_are_rejected(tmp_path: Path, version: str) -> None:
    clock = Clock()
    root = tmp_path / version
    old = service(root, clock, "runtime-old")
    old.status()
    if version == V1:
        state = write_v1(old)
    else:
        state = write_v2(old)
    state["unknown_authority"] = True
    old._atomic_write(
        old.state_path,
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        service(root, clock, "runtime-new").status()
    assert exc_info.value.code == "DEPLOYMENT_DRAIN_STATE_INVALID"


def test_recheck_pointers_must_be_all_present_or_all_absent(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "partial-recheck"
    old = service(root, clock, "runtime-old")
    old.status()
    state = write_v2(old)
    state["active_online_recheck_id"] = "online-recheck-partial"
    old._atomic_write(
        old.state_path,
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        service(root, clock, "runtime-new").status()
    assert exc_info.value.code == "DEPLOYMENT_DRAIN_STATE_INVALID"


def test_v2_legacy_consumption_fields_can_never_be_restored(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "v2-consumed"
    old = service(root, clock, "runtime-old")
    old.status()
    state = write_v2(old)
    state.update(
        receipt_consumed=True,
        consumed_at="2026-08-04T00:00:00+00:00",
        consume_id="legacy-consume-id",
    )
    old._atomic_write(
        old.state_path,
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode() + b"\n",
    )

    with pytest.raises(DeploymentDrainError) as exc_info:
        service(root, clock, "runtime-new").status()
    assert exc_info.value.code == "DEPLOYMENT_DRAIN_STATE_INVALID"


def test_restart_rejects_online_recheck_pointer_without_artifact(
    tmp_path: Path,
) -> None:
    clock = Clock()
    root = tmp_path / "restart"
    old = service(root, clock, "runtime-old")
    old.status()
    set_recheck(old, "online-recheck-before-restart")

    with pytest.raises(DeploymentDrainError):
        service(root, clock, "runtime-new").status()


def test_acquire_release_and_expiry_invalidate_recheck_pointers(
    tmp_path: Path,
) -> None:
    clock = Clock()
    drain = service(tmp_path / "transitions", clock, "runtime-one")
    drain.status()

    acquire_recheck_id = set_recheck(drain, "online-recheck-before-acquire")
    acquired = drain.acquire_with_snapshot(
        request("runtime-one"), lambda: snapshot(clock)
    )
    assert acquired["state"]["active_online_recheck_id"] is None
    assert acquired["state"]["last_invalidated_online_recheck_id"] == (
        acquire_recheck_id
    )

    release_recheck_id = set_recheck(drain, "online-recheck-before-release")
    released = drain.release(
        expected_drain_epoch=1,
        request_id="request-b1b-state-0001",
        operator="test-operator",
        reason="test release invalidation",
    )
    assert released["active_online_recheck_id"] is None
    assert released["last_invalidated_online_recheck_id"] == (release_recheck_id)

    drain.acquire_with_snapshot(request("runtime-one"), lambda: snapshot(clock))
    expiry_recheck_id = set_recheck(drain, "online-recheck-before-expiry")
    clock.advance(60)
    expired = drain.status()
    assert expired["state"] == "DRAIN_BLOCKED"
    assert expired["active_online_recheck_id"] is None
    assert expired["last_invalidated_online_recheck_id"] == (expiry_recheck_id)
    assert_no_authority(expired)
