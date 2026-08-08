from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from app.execution import (
    AuthorityRejected,
    DurableTargetPlanRepository,
    ExecutionOrchestrator,
    FencingError,
    GatewayTimeout,
    InMemoryExecutionRepository,
    InMemoryGateway,
    InMemoryTargetPlanRepository,
    PlanRejected,
)
from app.execution.final_runtime import FinalExecutionRuntime

from shared.commodity_execution import (
    CommodityExecutionContractError,
    VerifiedCustodyReceipt,
    build_target_plan,
)

SCOPE = "account:simnow-final"
ARTIFACT_HASH = "a" * 64
KEYRING_HASH = "b" * 64
SIGNED_HASH = "c" * 64


def receipt() -> dict:
    return {
        "receipt_id": "custody-install-0001",
        "receipt_type": "install",
        "artifact_id": "artifact-final-0001",
        "artifact_type": "runtime-authorization",
        "trust_domain": "runtime_authorization",
        "schema_ref": "phase-c-runtime-authorization-v1",
        "artifact_sha256": ARTIFACT_HASH,
        "signer_key_id": "offline-key-0001",
        "signer_key_version": "v1",
        "keyring_raw_sha256": KEYRING_HASH,
        "signed_artifact_sha256": SIGNED_HASH,
        "scope": {"account_scope": SCOPE, "environment": "SIMNOW"},
        "expires_at": "2099-01-01T00:00:00Z",
        "custody_version": 2,
        "idempotency_key": "custody-install-key-0001",
        "verified": True,
        "installed": True,
        "custody_writer": "artifact-custody",
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }


def plan(source: dict | None = None) -> dict:
    source = source or receipt()
    verified = VerifiedCustodyReceipt.from_mapping(source)
    return build_target_plan(
        plan_id="plan-final-0001",
        account_scope=SCOPE,
        environment="SIMNOW",
        artifact_id=source["artifact_id"],
        artifact_sha256=source["artifact_sha256"],
        custody_receipt_id=source["receipt_id"],
        custody_receipt_sha256=verified.receipt_sha256,
        signer_key_id=source["signer_key_id"],
        signer_key_version=source["signer_key_version"],
        keyring_raw_sha256=source["keyring_raw_sha256"],
        scope=source["scope"],
        expires_at=source["expires_at"],
        orders=[
            {
                "order_ref": "order-ref-0001",
                "request": {"symbol": "RB", "volume": 1},
            }
        ],
    )


def command(
    name: str, key: str, version: int, payload: dict, *, fence: dict | None = None
) -> dict:
    expected = {"state_version": version}
    if fence:
        expected |= fence
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": f"command-{key[-8:]}",
        "idempotency_key": key,
        "correlation_id": f"correlation-{key[-8:]}",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "final-test",
            "operator": "final-test",
            "role": "admin",
        },
        "command": name,
        "expected": expected,
        "payload": payload,
    }


def runtime(*, execute: bool = False, receipt_value: dict | None = None):
    current = receipt_value or receipt()
    repo = InMemoryExecutionRepository(scope=SCOPE)
    gateway = InMemoryGateway(account_scope=SCOPE, environment="SIMNOW")
    core = ExecutionOrchestrator(
        repo, gateway, scope=SCOPE, environment="SIMNOW", test_mode=True
    )
    service = FinalExecutionRuntime(
        core,
        plans=InMemoryTargetPlanRepository(),
        custody_receipt=lambda receipt_id: (
            current if receipt_id == current["receipt_id"] else None
        ),
        allowed_scope=current["scope"],
        allow_simnow_execution=execute,
    )
    return service, core, repo, gateway, current


def reconcile_enable_start(service, core, repo, target: dict):
    service.install_target_plan(target)
    service.process_command(
        command(
            "reconcile",
            "reconcile-final-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-final-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh SIMNOW facts",
            },
        )
    )
    service.process_command(
        command(
            "enable",
            "enable-final-000001",
            repo.state_version,
            {
                "authority_artifact_id": target["artifact_id"],
                "authority_hash": target["artifact_sha256"],
                "expires_at": target["expires_at"],
                "reason": "verified custody authority",
            },
        )
    )
    response = service.process_command(
        command(
            "start",
            "start-final-000001",
            repo.state_version,
            {
                "plan_id": target["plan_id"],
                "plan_hash": target["plan_hash"],
                "reason": "start verified SIMNOW plan",
            },
        )
    )
    assert response.result["accepted"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("artifact_sha256", "f" * 64),
        ("scope", {"account_scope": "foreign", "environment": "SIMNOW"}),
        ("expires_at", "2000-01-01T00:00:00Z"),
        ("keyring_raw_sha256", "f" * 64),
    ],
)
def test_receipt_tamper_scope_expiry_and_key_pin_block_install(field, value) -> None:
    source = receipt()
    target = plan(source)
    source[field] = value
    service, _core, _repo, gateway, _ = runtime(receipt_value=source)
    with pytest.raises(AuthorityRejected):
        service.install_target_plan(target)
    assert gateway.send_calls == []


def test_target_plan_hash_and_order_refs_are_immutable() -> None:
    target = plan()
    assert target["plan_hash"]
    tampered = deepcopy(target)
    tampered["orders"][0]["request"]["volume"] = 2
    with pytest.raises(CommodityExecutionContractError, match="hash mismatch"):
        from shared.commodity_execution import TargetPlan

        TargetPlan.from_mapping(tampered)
    duplicate = deepcopy(target)
    duplicate["orders"].append(deepcopy(duplicate["orders"][0]))
    with pytest.raises(
        CommodityExecutionContractError, match="references must be unique"
    ):
        build_target_plan(
            **{key: value for key, value in duplicate.items() if key != "plan_hash"}
        )


def test_start_requires_installed_receipt_bound_plan() -> None:
    service, _core, repo, gateway, _ = runtime()
    target = plan()
    with pytest.raises(PlanRejected):
        service.process_command(
            command(
                "start",
                "start-final-000002",
                repo.state_version,
                {
                    "plan_id": target["plan_id"],
                    "plan_hash": target["plan_hash"],
                    "reason": "must be installed first",
                },
            )
        )
    assert gateway.send_calls == []


def test_exact_scope_and_expiry_are_revalidated_after_plan_hash_verification() -> None:
    expired = receipt()
    expired["expires_at"] = "2000-01-01T00:00:00Z"
    service, _core, _repo, _gateway, _ = runtime(receipt_value=expired)
    with pytest.raises(AuthorityRejected, match="does not match immutable"):
        service.install_target_plan(plan(expired))

    foreign = receipt()
    foreign["scope"] = {"account_scope": "account:foreign", "environment": "SIMNOW"}
    repo = InMemoryExecutionRepository(scope=SCOPE)
    core = ExecutionOrchestrator(
        repo,
        InMemoryGateway(account_scope=SCOPE, environment="SIMNOW"),
        scope=SCOPE,
        environment="SIMNOW",
        test_mode=True,
    )
    scoped = FinalExecutionRuntime(
        core,
        plans=InMemoryTargetPlanRepository(),
        custody_receipt=lambda _: foreign,
        allowed_scope=receipt()["scope"],
    )
    with pytest.raises(AuthorityRejected, match="does not match immutable"):
        scoped.install_target_plan(plan(foreign))


def test_internal_order_uses_core_fence_and_local_gate() -> None:
    service, core, repo, gateway, _ = runtime(execute=False)
    target = plan()
    reconcile_enable_start(service, core, repo, target)
    token = core.acquire_leader("leader-final-0001")
    with pytest.raises(AuthorityRejected, match="locally disabled"):
        service.send_plan_order(target["plan_id"], "order-ref-0001", token=token)
    assert gateway.send_calls == []


def test_partial_unknown_same_intent_cancel_fence_and_restart_reconcile(
    tmp_path: Path,
) -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    reconcile_enable_start(service, core, repo, target)
    token = core.acquire_leader("leader-final-0001")
    gateway.fail_send = TimeoutError("network partition")
    with pytest.raises(GatewayTimeout):
        service.send_plan_order(target["plan_id"], "order-ref-0001", token=token)
    assert len(gateway.send_calls) == 1
    # A same plan/order reference derives the same idempotency key and cannot
    # replay an unknown outbound broker call.
    same_intent = service.send_plan_order(
        target["plan_id"], "order-ref-0001", token=token
    )
    assert same_intent["reused"] is True and same_intent["accepted"] is False
    assert len(gateway.send_calls) == 1

    # Recover via the established reconcile command, then exercise the same
    # adapter's fenced send/cancel path with a fresh, terminal plan state.
    gateway.fail_send = None
    intent_id = next(iter(repo.snapshot()["unknown_outcomes"]))
    gateway.intent_outcomes[intent_id] = {"state": "TERMINAL", "resolved": True}
    service.process_command(
        command(
            "reconcile",
            "reconcile-final-0002",
            repo.state_version,
            {
                "reconciliation_run_id": "run-final-0002",
                "snapshot_id": "snapshot-default",
                "reason": "resolve same intent only",
            },
        )
    )
    result = service.send_plan_order(target["plan_id"], "order-ref-0001", token=token)
    # Same idempotency key remains the resolved historical intent, no duplicate send.
    assert result["reused"] is True
    assert len(gateway.send_calls) == 1

    # A stale fence is refused by the core before a cancellation gateway call.
    core.release_leader(token)
    with pytest.raises(FencingError):
        service.cancel_plan_intent(target["plan_id"], intent_id, token=token)
    assert gateway.cancel_calls == []

    # The durable plan repository survives independently; the Execution core's
    # own restart safety is covered by its existing durable-state tests.
    plans = DurableTargetPlanRepository(tmp_path / "plans")
    service2, _core2, _repo2, _gateway2, _ = runtime()
    service2 = FinalExecutionRuntime(
        service2.orchestrator,
        plans=plans,
        custody_receipt=lambda _: receipt(),
        allowed_scope=receipt()["scope"],
    )
    service2.install_target_plan(target)
    assert plans.get(target["plan_id"]).plan_hash == target["plan_hash"]
    restarted = DurableTargetPlanRepository(tmp_path / "plans")
    assert restarted.get(target["plan_id"]).plan_hash == target["plan_hash"]
