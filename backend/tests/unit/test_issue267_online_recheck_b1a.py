from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from app.schemas.deployment_drain import (
    DeploymentOnlineCheckpointDTO,
    DeploymentOnlineRecheckCheckpointDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    DeploymentSafetySnapshotDTO,
    SafeRestartReceiptDTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.deployment_online_recheck import (
    DeploymentOnlineRecheckError,
    build_safe_restart_online_recheck,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
NOW = datetime(2026, 8, 4, 8, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def fixed_recheck_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.services.deployment_online_recheck._utc_now", lambda: NOW
    )


def canonical_raw(value: object) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_sha(value: object) -> str:
    return sha256(canonical_raw(value)[:-1])


def artifact_chain() -> tuple[bytes, bytes, bytes]:
    state = {"execution": {"plan_version": 0, "status": "IDLE"}}
    original_rpc = DeploymentRpcFactsDTO(
        schema_version="windows_rpc_deployment_safety_snapshot_v1",
        request_id="request-recheck-b1a-0001",
        challenge="owner-challenge-recheck-0001",
        server_instance_id="windows-server-recheck-0001",
        fact_generation=17,
        captured_at=NOW - timedelta(seconds=10),
        execution_admission_frozen=True,
        pending_send_outcomes=0,
        strategy_execution_enabled=False,
        account_hashes=[SHA_A],
        orders=[],
        active_orders=[],
        trades=[],
        positions=[{"direction": "long", "volume": 0, "vt_symbol": "rb2610.SHFE"}],
    )
    original = DeploymentOnlineCheckpointDTO(
        schema_version="web_bridge_deployment_online_checkpoint_v1",
        request_id=original_rpc.request_id,
        runtime_instance_id="runtime-recheck-b1a-0001",
        drain_epoch=3,
        execution_epoch=5,
        execution_plan_status="IDLE",
        execution_plan_hash=None,
        plan_version=0,
        state_version="web_bridge_deployment_online_checkpoint_v1",
        state=state,
        state_sha256=canonical_sha(state),
        rpc=original_rpc,
        active_orders_snapshot_sha256=canonical_sha([]),
        positions_snapshot_sha256=canonical_sha(original_rpc.positions),
        web_trade_enabled=False,
        execution_authority_revoked=True,
        auto_dispatch_stopped=True,
        active_orders=0,
        unknown_outcome=False,
        reconcile_required=False,
        automatic_deploy_allowed=False,
        production_allowed=False,
        live_trading_authorized=False,
    )
    original_raw = canonical_raw(original)
    original_raw_sha = sha256(original_raw)
    original_facts_sha = deployment_rpc_execution_facts_sha256(original_rpc)
    recheck_rpc = DeploymentRpcRecheckFactsDTO(
        schema_version="windows_rpc_deployment_safety_recheck_v1",
        request_id=original.request_id,
        owner_challenge=original_rpc.challenge,
        recheck_id=f"deployment-recheck-{SHA_C}",
        fresh_challenge="fresh-challenge-recheck-0001",
        original_server_instance_id=original_rpc.server_instance_id,
        original_fact_generation=original_rpc.fact_generation,
        original_execution_facts_canonical_sha256=original_facts_sha,
        server_instance_id=original_rpc.server_instance_id,
        fact_generation=original_rpc.fact_generation,
        execution_facts_canonical_sha256=original_facts_sha,
        captured_at=NOW - timedelta(seconds=1),
        execution_admission_frozen=True,
        pending_send_outcomes=0,
        strategy_execution_enabled=False,
        account_hashes=original_rpc.account_hashes,
        orders=original_rpc.orders,
        active_orders=original_rpc.active_orders,
        trades=original_rpc.trades,
        positions=original_rpc.positions,
    )
    recheck = DeploymentOnlineRecheckCheckpointDTO(
        schema_version="web_bridge_deployment_online_recheck_checkpoint_v1",
        checkpoint_role="RECHECK",
        recheck_id=recheck_rpc.recheck_id,
        original_checkpoint_raw_sha256=original_raw_sha,
        request_id=original.request_id,
        runtime_instance_id=original.runtime_instance_id,
        drain_epoch=original.drain_epoch,
        execution_epoch=original.execution_epoch,
        state_version="web_bridge_deployment_online_recheck_checkpoint_v1",
        state=state,
        state_sha256=original.state_sha256,
        rpc=recheck_rpc,
        active_orders_snapshot_sha256=original.active_orders_snapshot_sha256,
        positions_snapshot_sha256=original.positions_snapshot_sha256,
        captured_at=recheck_rpc.captured_at,
        deployment_authorized=False,
        one_shot_consume_allowed=False,
        automatic_deploy_allowed=False,
        production_allowed=False,
        live_trading_authorized=False,
        countable_forward=False,
    )
    recheck_raw = canonical_raw(recheck)
    issued_at = NOW - timedelta(seconds=5)
    snapshot = DeploymentSafetySnapshotDTO(
        schema_version="web_bridge_deployment_safety_snapshot_v1",
        captured_at=original_rpc.captured_at,
        execution_plan_status="IDLE",
        execution_plan_hash=None,
        plan_version=0,
        state_version=original.state_version,
        state_sha256=original.state_sha256,
        active_orders_snapshot_sha256=original.active_orders_snapshot_sha256,
        positions_snapshot_sha256=original.positions_snapshot_sha256,
        checkpoint_sha256=original_raw_sha,
        rpc_generation=original_rpc.fact_generation,
        web_trade_enabled=False,
        execution_authority_revoked=True,
        auto_dispatch_stopped=True,
        active_orders=0,
        unknown_outcome=False,
        reconcile_required=False,
        checkpoint_durable=True,
    )
    receipt_core = {
        "schema_version": "web_bridge_safe_restart_receipt_v1",
        "purpose": "authorize_one_bound_web_bridge_restart_attempt",
        "request_id": original.request_id,
        "deployment_attempt_id": "deployment-attempt-b1a-0001",
        "release_plan_id": f"release-plan-{SHA_A}",
        "release_plan_core_sha256": SHA_A,
        "restart_action_sha256": SHA_B,
        "unit": "web-bridge",
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued_at + timedelta(seconds=60))
        .isoformat()
        .replace("+00:00", "Z"),
        "ttl_seconds": 60,
        "drain_epoch": original.drain_epoch,
        "execution_epoch": original.execution_epoch,
        "issuer_source_commit_sha": "a" * 40,
        "issuer_image_digest": f"sha256:{SHA_A}",
        "issuer_config_sha256": SHA_A,
        "issuer_runtime_instance_id": original.runtime_instance_id,
        "target_source_commit_sha": "b" * 40,
        "target_image_digest": f"sha256:{SHA_B}",
        "target_config_sha256": SHA_B,
        "rollback_image_digest": f"sha256:{SHA_A}",
        "rollback_config_sha256": SHA_A,
        "nonce": "receipt-nonce-recheck-0001",
        "snapshot": snapshot.model_dump(mode="json"),
        "safe_to_restart": True,
        "one_shot": True,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
    }
    receipt_core_sha = canonical_sha(receipt_core)
    receipt = SafeRestartReceiptDTO.model_validate(
        {
            **receipt_core,
            "receipt_id": f"safe-restart-{receipt_core_sha}",
            "receipt_core_sha256": receipt_core_sha,
        }
    )
    return canonical_raw(receipt), original_raw, recheck_raw


def mutate_raw(raw: bytes, mutation) -> bytes:
    value = json.loads(raw)
    mutation(value)
    return canonical_raw(value)


def mutate_receipt_raw(raw: bytes, mutation) -> bytes:
    value = json.loads(raw)
    mutation(value)
    core = dict(value)
    core.pop("receipt_id")
    core.pop("receipt_core_sha256")
    core_sha = canonical_sha(core)
    value["receipt_id"] = f"safe-restart-{core_sha}"
    value["receipt_core_sha256"] = core_sha
    return canonical_raw(value)


def test_build_online_recheck_emits_content_bound_non_authority() -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()

    result = build_safe_restart_online_recheck(
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_raw,
        recheck_checkpoint_raw=recheck_raw,
    )

    assert result.semantic_safety_unchanged is True
    assert result.receipt_raw_sha256 == sha256(receipt_raw)
    assert result.original_checkpoint_raw_sha256 == sha256(original_raw)
    assert result.recheck_checkpoint_raw_sha256 == sha256(recheck_raw)
    assert result.online_recheck_id.endswith(result.recheck_core_sha256)
    for field in (
        "one_shot_consume_allowed",
        "reconciliation_authorized",
        "deployment_authorized",
        "automatic_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    ):
        assert getattr(result, field) is False


def test_recheck_checkpoint_and_artifact_match_published_json_schemas() -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()
    result = build_safe_restart_online_recheck(
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_raw,
        recheck_checkpoint_raw=recheck_raw,
    )
    cases = (
        (
            "web-bridge-deployment-online-recheck-checkpoint-v1.schema.json",
            json.loads(recheck_raw),
        ),
        (
            "web-bridge-safe-restart-online-recheck-v1.schema.json",
            result.model_dump(mode="json"),
        ),
    )
    for filename, value in cases:
        schema = json.loads((ROOT / "docs" / "schemas" / filename).read_text())
        Draft202012Validator(schema).validate(value)


def test_online_recheck_schema_rejects_every_authority_true() -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()
    result = build_safe_restart_online_recheck(
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_raw,
        recheck_checkpoint_raw=recheck_raw,
    ).model_dump(mode="json")
    schema = json.loads(
        (
            ROOT
            / "docs"
            / "schemas"
            / "web-bridge-safe-restart-online-recheck-v1.schema.json"
        ).read_text()
    )
    for field in (
        "one_shot_consume_allowed",
        "reconciliation_authorized",
        "deployment_authorized",
        "automatic_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    ):
        changed = {**result, field: True}
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(changed)


@pytest.mark.parametrize(
    ("target", "mutation", "message"),
    [
        (
            "receipt",
            lambda value: value.update(request_id="request-other-b1a-0001"),
            "invalid",
        ),
        (
            "recheck",
            lambda value: value.update(runtime_instance_id="runtime-other-b1a-0001"),
            "owner bindings differ",
        ),
        (
            "recheck",
            lambda value: value["rpc"].update(
                server_instance_id="windows-other-b1a-0001"
            ),
            "server, generation, challenge, or execution facts changed",
        ),
        (
            "recheck",
            lambda value: value["rpc"].update(fact_generation=18),
            "server, generation, challenge, or execution facts changed",
        ),
        ("recheck", lambda value: value.update(state_sha256=SHA_B), "invalid"),
        (
            "recheck",
            lambda value: value["rpc"].update(
                owner_challenge="different-owner-challenge-0001"
            ),
            "server, generation, challenge, or execution facts changed",
        ),
    ],
    ids=["receipt-binding", "owner", "server", "generation", "state-hash", "challenge"],
)
def test_build_online_recheck_fails_closed_on_binding_drift(
    target: str,
    mutation,
    message: str,
) -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()
    if target == "receipt":
        receipt_raw = mutate_raw(receipt_raw, mutation)
    elif target == "original":
        original_raw = mutate_raw(original_raw, mutation)
    else:
        recheck_raw = mutate_raw(recheck_raw, mutation)

    with pytest.raises(DeploymentOnlineRecheckError, match=message):
        build_safe_restart_online_recheck(
            receipt_raw=receipt_raw,
            original_checkpoint_raw=original_raw,
            recheck_checkpoint_raw=recheck_raw,
        )


def test_build_online_recheck_rejects_noncanonical_exact_bytes() -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()

    with pytest.raises(DeploymentOnlineRecheckError, match="not canonical"):
        build_safe_restart_online_recheck(
            receipt_raw=b" " + receipt_raw,
            original_checkpoint_raw=original_raw,
            recheck_checkpoint_raw=recheck_raw,
        )


@pytest.mark.parametrize(
    "observed_at",
    [
        NOW - timedelta(seconds=20),
        NOW + timedelta(seconds=30),
        NOW + timedelta(minutes=2),
    ],
    ids=["before-recheck", "stale-recheck", "expired-receipt"],
)
def test_build_online_recheck_rejects_invalid_time_chain(
    observed_at: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()
    monkeypatch.setattr(
        "app.services.deployment_online_recheck._utc_now",
        lambda: observed_at,
    )

    with pytest.raises(DeploymentOnlineRecheckError):
        build_safe_restart_online_recheck(
            receipt_raw=receipt_raw,
            original_checkpoint_raw=original_raw,
            recheck_checkpoint_raw=recheck_raw,
        )


def test_build_online_recheck_rejects_capture_before_receipt_issue() -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()
    too_early = (NOW - timedelta(seconds=6)).isoformat().replace("+00:00", "Z")
    recheck_raw = mutate_raw(
        recheck_raw,
        lambda value: (
            value["rpc"].update(captured_at=too_early),
            value.update(captured_at=too_early),
        ),
    )

    with pytest.raises(DeploymentOnlineRecheckError, match="timestamps"):
        build_safe_restart_online_recheck(
            receipt_raw=receipt_raw,
            original_checkpoint_raw=original_raw,
            recheck_checkpoint_raw=recheck_raw,
        )


def test_build_online_recheck_binds_receipt_and_checkpoint_capture_time() -> None:
    receipt_raw, original_raw, recheck_raw = artifact_chain()
    receipt_raw = mutate_receipt_raw(
        receipt_raw,
        lambda value: value["snapshot"].update(
            captured_at=(NOW - timedelta(seconds=11))
            .isoformat()
            .replace("+00:00", "Z")
        ),
    )

    with pytest.raises(DeploymentOnlineRecheckError, match="timestamps"):
        build_safe_restart_online_recheck(
            receipt_raw=receipt_raw,
            original_checkpoint_raw=original_raw,
            recheck_checkpoint_raw=recheck_raw,
        )
