from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import pytest
from app.execution import (
    AuthorityRejected,
    DurableExecutionRepository,
    DurableTargetPlanRepository,
    ExecutionOrchestrator,
    FencingError,
    GatewaySnapshot,
    GatewayTimeout,
    InMemoryExecutionRepository,
    InMemoryGateway,
    InMemoryTargetPlanRepository,
    MutationRejected,
    PlanRejected,
    RepositoryUnavailableError,
)
from app.execution.errors import GatewayConfigurationError, GatewayUnavailable
from app.execution.final_runtime import FinalExecutionRuntime
from app.execution_orchestrator import _HttpCustodyReadClient

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    TARGET_PLAN_SCHEMA_VERSION,
    CommodityExecutionContractError,
    VerifiedCustodyReceipt,
    before_position_projection_hash,
    build_target_plan,
    canonical_before_position_projection,
    sha256_json,
    target_position_projection_hash,
)
from shared.trust_contracts.v1 import canonical_json_line, sha256_bytes

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


def target_position_rows(**overrides: object) -> dict:
    row = {
        "vt_positionid": "RB.SHFE.LONG.gateway-0001",
        "symbol": "RB",
        "exchange": "SHFE",
        "direction": "LONG",
        "volume": 1,
        "yd_volume": 0,
        "frozen": 0,
        "price": 1.0,
        "pnl": 0.0,
        "commission": 0.0,
        "gateway_name": "gateway-0001",
    }
    row.update(overrides)
    return {str(row["vt_positionid"]): row}


def target_position_hash(
    positions: dict | None = None,
    *,
    account_scope: str = SCOPE,
    environment: str = "SIMNOW",
) -> str:
    return target_position_projection_hash(
        target_position_rows() if positions is None else positions,
        account_scope=account_scope,
        environment=environment,
    )


def before_position_hash(
    positions: dict | None = None,
    *,
    account_scope: str = SCOPE,
    environment: str = "SIMNOW",
) -> str:
    return before_position_projection_hash(
        target_position_rows() if positions is None else positions,
        account_scope=account_scope,
        environment=environment,
    )


def plan(
    source: dict | None = None,
    *,
    expected_before: str | None = None,
    expected_after: str | None = None,
) -> dict:
    source = source or receipt()
    verified = VerifiedCustodyReceipt.from_mapping(source)
    return build_target_plan(
        plan_id="plan-final-0001",
        account_scope=SCOPE,
        environment="SIMNOW",
        authority_artifact_id=source["artifact_id"],
        authority_artifact_sha256=source["artifact_sha256"],
        authority_receipt_id=source["receipt_id"],
        authority_receipt_sha256=verified.receipt_sha256,
        signer_key_id=source["signer_key_id"],
        signer_key_version=source["signer_key_version"],
        keyring_raw_sha256=source["keyring_raw_sha256"],
        scope=source["scope"],
        expires_at=source["expires_at"],
        phase="OPEN",
        expected_before_position_hash=expected_before or before_position_hash({}),
        expected_after_position_hash=expected_after or target_position_hash(),
        orders=[
            {
                "symbol": "RB",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 1.0,
                "offset": "OPEN",
                "reference": "order-ref-0001",
                "gateway_name": "gateway-0001",
            }
        ],
    )


def final_position_snapshot(positions: dict, *, generation: int = 2) -> GatewaySnapshot:
    return GatewaySnapshot(
        snapshot_id=f"snapshot-final-{generation:04d}",
        generation=generation,
        connected=True,
        position_snapshot_hash=sha256_json(positions),
        positions=positions,
        account_scope=SCOPE,
        environment="SIMNOW",
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


def target_artifact(target: dict) -> dict:
    return new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="final-execution-fixture",
        producer_version="v1",
        schema_ref=TARGET_PLAN_SCHEMA_VERSION,
        payload=target,
        generated_at="2020-01-01T00:00:00Z",
        scope=target["scope"],
        predecessor_refs=[],
        lineage=[],
    )


class Custody:
    """Read-only custody fixture with separately installed target artifacts."""

    def __init__(self, authority: dict) -> None:
        self.authority = authority
        self.receipts = {authority["receipt_id"]: authority}
        self.artifacts: dict[str, dict] = {}

    def add_target(self, target: dict) -> dict:
        artifact = target_artifact(target)
        envelope_hash = sha256_bytes(canonical_json_line(artifact))
        target_receipt = self.authority | {
            "receipt_id": f"custody-plan-{len(self.artifacts) + 1:06d}",
            "artifact_id": artifact["artifact_id"],
            "artifact_type": "simnow-target-plan",
            "schema_ref": TARGET_PLAN_SCHEMA_VERSION,
            "artifact_sha256": artifact["raw_sha256"],
        }
        self.receipts[target_receipt["receipt_id"]] = target_receipt
        self.artifacts[target_receipt["artifact_id"]] = {
            "artifact_id": target_receipt["artifact_id"],
            "artifact_raw_sha256": envelope_hash,
            "artifact": artifact,
        }
        return target_receipt

    def receipt(self, receipt_id: str):
        return self.receipts.get(receipt_id)

    def artifact(self, artifact_id: str):
        return self.artifacts.get(artifact_id)

    def probe(self):
        return None


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
        custody=Custody(current),
        allowed_scope=current["scope"],
        allow_simnow_execution=execute,
    )
    return service, core, repo, gateway, current


def reconcile_enable_start(
    service, core, repo, target: dict, *, snapshot_id: str = "snapshot-default"
):
    target_receipt = service.custody.add_target(target)
    service.process_command(
        command(
            "preview",
            "preview-final-0001",
            repo.state_version,
            {
                "plan_hash": target["plan_hash"],
                "artifact_hash": target_receipt["artifact_sha256"],
                "mode": "simnow_preview",
                "receipt_id": target_receipt["receipt_id"],
            },
        )
    )
    service.process_command(
        command(
            "reconcile",
            "reconcile-final-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-final-0001",
                "snapshot_id": snapshot_id,
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
                "authority_artifact_id": target["authority_artifact_id"],
                "authority_hash": target["authority_artifact_sha256"],
                "expires_at": target["expires_at"],
                "reason": "verified custody authority",
            },
        )
    )
    token = core.acquire_leader("leader-final-0001")
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
            fence={"leader_epoch": token.epoch, "fencing_token": token.fencing_token},
        )
    )
    assert response.result["accepted"] is True
    return token


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


def test_target_plan_receipt_cannot_be_reused_as_plan_authority() -> None:
    service, _core, _repo, gateway, _ = runtime()
    target_plan_receipt = service.custody.add_target(plan())
    poisoned_plan = plan(target_plan_receipt)
    preview_receipt = service.custody.add_target(poisoned_plan)

    with pytest.raises(AuthorityRejected, match="runtime authorization"):
        service.preview_from_custody(preview_receipt["receipt_id"])
    with pytest.raises(AuthorityRejected, match="runtime authorization"):
        service.install_target_plan(poisoned_plan)
    assert service.plans.get(poisoned_plan["plan_id"]) is None
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []


def test_target_plan_hash_and_order_refs_are_immutable() -> None:
    target = plan()
    assert target["plan_hash"]
    tampered = deepcopy(target)
    tampered["orders"][0]["volume"] = 2
    with pytest.raises(CommodityExecutionContractError):
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


@pytest.mark.parametrize(
    "change",
    [
        {"unknown": True},
        {"type": "MARKET"},
        {"volume": 2},
        {"price": float("nan")},
        {"offset": "CLOSE"},
    ],
)
def test_target_plan_rejects_non_limit_overbound_nan_unknown_and_mixed_phase(
    change,
) -> None:
    raw = plan()
    raw["orders"][0].update(change)
    with pytest.raises(CommodityExecutionContractError):
        raw["order_set_sha256"] = __import__(
            "shared.commodity_execution.v1", fromlist=["sha256_json"]
        ).sha256_json(raw["orders"])
        raw["plan_hash"] = __import__(
            "shared.commodity_execution.v1", fromlist=["sha256_json"]
        ).sha256_json({key: value for key, value in raw.items() if key != "plan_hash"})
        from shared.commodity_execution import TargetPlan

        TargetPlan.from_mapping(raw)


@pytest.mark.parametrize(
    ("exchange", "offset"),
    (("CFFEX", "CLOSETODAY"), ("DCE", "CLOSEYESTERDAY")),
)
def test_target_plan_rejects_close_today_yesterday_outside_shfe_ine(
    exchange: str,
    offset: str,
) -> None:
    raw = plan()
    raw["phase"] = "CLOSE"
    raw["orders"][0].update({"exchange": exchange, "offset": offset})
    raw["order_set_sha256"] = sha256_json(raw["orders"])
    raw["plan_hash"] = sha256_json(
        {key: value for key, value in raw.items() if key != "plan_hash"}
    )
    from shared.commodity_execution import TargetPlan

    with pytest.raises(CommodityExecutionContractError, match="strict SIMNOW"):
        TargetPlan.from_mapping(raw)


def test_start_requires_installed_receipt_bound_plan() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    token = core.acquire_leader("leader-final-0001")
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
                fence={
                    "leader_epoch": token.epoch,
                    "fencing_token": token.fencing_token,
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
    token = core.acquire_leader("leader-final-0001")
    with pytest.raises(AuthorityRejected, match="locally disabled"):
        service.process_command(
            command(
                "start",
                "start-final-000001",
                repo.state_version,
                {
                    "plan_id": target["plan_id"],
                    "plan_hash": target["plan_hash"],
                    "reason": "must stay disabled",
                },
                fence={
                    "leader_epoch": token.epoch,
                    "fencing_token": token.fencing_token,
                },
            )
        )
    assert gateway.send_calls == []


@pytest.mark.parametrize(
    ("expected_before", "actual_positions", "should_start"),
    [
        (
            before_position_hash(),
            target_position_rows(frozen=9, price=999.5, pnl=-42.25, commission=123.45),
            True,
        ),
        (before_position_hash(), target_position_rows(volume=2), False),
        (before_position_hash(), target_position_rows(direction="SHORT"), False),
        (before_position_hash(), target_position_rows(symbol="CU"), False),
        (before_position_hash(), target_position_rows(exchange="DCE"), False),
        (before_position_hash(), target_position_rows(yd_volume=1), False),
        (
            before_position_hash(account_scope="account:foreign"),
            target_position_rows(),
            False,
        ),
        (
            before_position_hash(environment="foreign"),
            target_position_rows(),
            False,
        ),
    ],
)
def test_start_uses_current_position_projection_and_fails_closed(
    expected_before: str, actual_positions: dict, should_start: bool
) -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan(expected_before=expected_before)
    gateway.snapshots.append(final_position_snapshot(actual_positions))

    if should_start:
        reconcile_enable_start(
            service, core, repo, target, snapshot_id="snapshot-final-0002"
        )
        assert len(gateway.send_calls) == 1
    else:
        with pytest.raises(PlanRejected, match="matching preview/reconciliation"):
            reconcile_enable_start(
                service, core, repo, target, snapshot_id="snapshot-final-0002"
            )
        assert gateway.send_calls == []


def test_final_runtime_uses_only_plan_scoped_execution_mutation_delegates() -> None:
    runtime_path = (
        Path(__file__).resolve().parents[2] / "app/execution/final_runtime.py"
    )
    tree = ast.parse(runtime_path.read_text(encoding="utf-8"))
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }

    assert {"submit_planned_order", "cancel_planned_intent"} <= attributes
    assert "send_order" not in attributes
    assert "cancel_order" not in attributes


def test_offline_preview_never_bypasses_final_simnow_start() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    service.install_target_plan(target)
    service.process_command(
        command(
            "preview",
            "preview-offline-0001",
            repo.state_version,
            {
                "plan_hash": target["plan_hash"],
                "artifact_hash": target["authority_artifact_sha256"],
                "mode": "offline_preview",
            },
        )
    )
    service.process_command(
        command(
            "reconcile",
            "reconcile-offline-01",
            repo.state_version,
            {
                "reconciliation_run_id": "run-offline-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh offline preview facts",
            },
        )
    )
    service.process_command(
        command(
            "enable",
            "enable-offline-00001",
            repo.state_version,
            {
                "authority_artifact_id": target["authority_artifact_id"],
                "authority_hash": target["authority_artifact_sha256"],
                "expires_at": target["expires_at"],
                "reason": "verified offline authority",
            },
        )
    )
    token = core.acquire_leader("leader-offline-0001")
    with pytest.raises(PlanRejected, match="matching preview"):
        service.process_command(
            command(
                "start",
                "start-offline-00001",
                repo.state_version,
                {
                    "plan_id": target["plan_id"],
                    "plan_hash": target["plan_hash"],
                    "reason": "offline must not execute",
                },
                fence={
                    "leader_epoch": token.epoch,
                    "fencing_token": token.fencing_token,
                },
            )
        )
    assert gateway.send_calls == []


def test_simnow_preview_proof_survives_execution_restart(tmp_path: Path) -> None:
    authority = receipt()
    durable_state = DurableExecutionRepository(tmp_path / "execution.json", scope=SCOPE)
    gateway = InMemoryGateway(account_scope=SCOPE, environment="SIMNOW")
    custody = Custody(authority)
    plans = DurableTargetPlanRepository(tmp_path / "plans")
    core = ExecutionOrchestrator(
        durable_state, gateway, scope=SCOPE, environment="SIMNOW", test_mode=True
    )
    service = FinalExecutionRuntime(
        core,
        plans=plans,
        custody=custody,
        allowed_scope=authority["scope"],
        allow_simnow_execution=True,
    )
    target = plan(authority)
    target_receipt = custody.add_target(target)
    service.process_command(
        command(
            "preview",
            "preview-restart-0001",
            durable_state.state_version,
            {
                "plan_hash": target["plan_hash"],
                "artifact_hash": target_receipt["artifact_sha256"],
                "mode": "simnow_preview",
                "receipt_id": target_receipt["receipt_id"],
            },
        )
    )
    proof = durable_state.snapshot()["plan"]
    assert proof["preview_mode"] == "simnow_preview"
    assert proof["preview_receipt_id"] == target_receipt["receipt_id"]

    restarted_core = ExecutionOrchestrator(
        DurableExecutionRepository(tmp_path / "execution.json", scope=SCOPE),
        gateway,
        scope=SCOPE,
        environment="SIMNOW",
        test_mode=True,
    )
    restarted = FinalExecutionRuntime(
        restarted_core,
        plans=DurableTargetPlanRepository(tmp_path / "plans"),
        custody=custody,
        allowed_scope=authority["scope"],
        allow_simnow_execution=True,
    )
    restored = restarted_core.repository.snapshot()["plan"]
    assert restored["preview_mode"] == "simnow_preview"
    assert restored["preview_receipt_sha256"] == proof["preview_receipt_sha256"]
    assert restored["preview_artifact_sha256"] == proof["preview_artifact_sha256"]
    restarted_core.acquire_leader("leader-restart-0001")
    # The restart must still reconcile before any start; durable preview proof
    # is retained but does not bypass the existing reconciliation gate.
    with pytest.raises(PlanRejected, match="matching preview/reconciliation"):
        restarted.process_command(
            command(
                "start",
                "start-restart-0001",
                restarted_core.repository.state_version,
                {
                    "plan_id": target["plan_id"],
                    "plan_hash": target["plan_hash"],
                    "reason": "restart requires fresh facts",
                },
                fence={
                    "leader_epoch": restarted_core.fencer.token.epoch,
                    "fencing_token": restarted_core.fencer.token.fencing_token,
                },
            )
        )
    assert gateway.send_calls == []
    restarted.process_command(
        command(
            "reconcile",
            "reconcile-restart-01",
            restarted_core.repository.state_version,
            {
                "reconciliation_run_id": "run-restart-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh facts after restart",
            },
        )
    )
    restarted.process_command(
        command(
            "enable",
            "enable-restart-00001",
            restarted_core.repository.state_version,
            {
                "authority_artifact_id": target["authority_artifact_id"],
                "authority_hash": target["authority_artifact_sha256"],
                "expires_at": target["expires_at"],
                "reason": "verified authority after restart",
            },
        )
    )
    token = restarted_core.fencer.token
    assert token is not None
    restarted.process_command(
        command(
            "start",
            "start-restart-0002",
            restarted_core.repository.state_version,
            {
                "plan_id": target["plan_id"],
                "plan_hash": target["plan_hash"],
                "reason": "durable SIMNOW preview proof",
            },
            fence={"leader_epoch": token.epoch, "fencing_token": token.fencing_token},
        )
    )
    assert len(gateway.send_calls) == 1


def test_simnow_preview_fetches_receipt_then_exact_custody_artifact() -> None:
    authority = receipt()
    target = plan(authority)
    artifact = target_artifact(target)
    envelope_hash = sha256_bytes(canonical_json_line(artifact))
    plan_receipt = receipt() | {
        "receipt_id": "custody-plan-000001",
        "artifact_id": artifact["artifact_id"],
        "artifact_type": "simnow-target-plan",
        "schema_ref": TARGET_PLAN_SCHEMA_VERSION,
        "artifact_sha256": artifact["raw_sha256"],
    }

    class Custody:
        def receipt(self, receipt_id: str):
            return {
                plan_receipt["receipt_id"]: plan_receipt,
                authority["receipt_id"]: authority,
            }.get(receipt_id)

        def artifact(self, artifact_id: str):
            if artifact_id != plan_receipt["artifact_id"]:
                return None
            return {
                "artifact_id": artifact_id,
                "artifact_raw_sha256": envelope_hash,
                "artifact": artifact,
            }

        def probe(self):
            return None

    repo = InMemoryExecutionRepository(scope=SCOPE)
    core = ExecutionOrchestrator(
        repo,
        InMemoryGateway(account_scope=SCOPE, environment="SIMNOW"),
        scope=SCOPE,
        environment="SIMNOW",
        test_mode=True,
    )
    service = FinalExecutionRuntime(
        core,
        plans=InMemoryTargetPlanRepository(),
        custody=Custody(),
        allowed_scope=authority["scope"],
    )
    envelope = command(
        "preview",
        "preview-final-0001",
        repo.state_version,
        {
            "plan_hash": target["plan_hash"],
            "artifact_hash": artifact["raw_sha256"],
            "mode": "simnow_preview",
            "receipt_id": plan_receipt["receipt_id"],
        },
    )
    before = repo.state_version
    result = service.process_command(envelope)
    assert result.result["accepted"] is True
    assert service.plans.get(target["plan_id"]).plan_hash == target["plan_hash"]
    state = repo.snapshot()
    assert state["state_version"] == before + 1 == result.receipt["state_version"]
    assert result.result["plan"] == state["plan"]
    assert result.receipt["result"]["plan"] == state["plan"]
    assert state["plan"]["preview_receipt_sha256"] != "0" * 64
    assert state["plan"]["preview_artifact_sha256"] == artifact["raw_sha256"]
    retry = service.process_command(envelope)
    assert retry.reused is True
    assert retry.receipt == result.receipt
    assert repo.state_version == before + 1


@pytest.mark.parametrize(
    "hash_field",
    ["receipt_payload_raw", "response_envelope_raw"],
)
def test_simnow_preview_keeps_receipt_and_response_hashes_distinct(
    hash_field: str,
) -> None:
    service, _core, _repo, gateway, _ = runtime()
    target_receipt = service.custody.add_target(plan())
    response = service.custody.artifacts[target_receipt["artifact_id"]]
    if hash_field == "receipt_payload_raw":
        target_receipt["artifact_sha256"] = response["artifact_raw_sha256"]
    else:
        response["artifact_raw_sha256"] = target_receipt["artifact_sha256"]

    with pytest.raises(PlanRejected, match="artifact/receipt binding mismatch"):
        service.preview_from_custody(target_receipt["receipt_id"])
    assert gateway.send_calls == []


def test_core_rejects_simnow_preview_without_internal_proof() -> None:
    _service, core, repo, _gateway, _ = runtime()
    before = repo.state_version
    with pytest.raises(MutationRejected, match="verified internal evidence"):
        core.process_command(
            command(
                "preview",
                "preview-core-only01",
                before,
                {
                    "plan_hash": "a" * 64,
                    "artifact_hash": "b" * 64,
                    "mode": "simnow_preview",
                    "receipt_id": "custody-plan-000001",
                },
            )
        )
    assert repo.state_version == before
    assert repo.snapshot()["plan"]["state"] == "IDLE"


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/custody",
        "http://user:pass@custody",
        "https://custody/path",
        "https://custody?next=http://internal",
        "https://custody#fragment",
    ],
)
def test_custody_http_client_rejects_ssrf_style_base_urls(url: str) -> None:
    with pytest.raises(GatewayConfigurationError):
        _HttpCustodyReadClient(base_url=url, secret="secret")


def test_custody_http_client_rejects_redirect_response(monkeypatch) -> None:
    from urllib.error import HTTPError

    client = _HttpCustodyReadClient(base_url="https://custody", secret="secret")

    class Redirect:
        def open(self, *_args, **_kwargs):
            raise HTTPError("https://custody/redirect", 302, "redirect", {}, None)

    monkeypatch.setattr(client, "_opener", Redirect())
    with pytest.raises(GatewayUnavailable):
        client.probe()


def test_runner_rejected_first_order_halts_before_second_order() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    second = deepcopy(target["orders"][0])
    second["reference"] = "order-ref-0002"
    source = {
        key: value
        for key, value in target.items()
        if key not in {"plan_hash", "order_set_sha256"}
    }
    source["orders"] = [target["orders"][0], second]
    target = build_target_plan(**source)

    def reject(request, context):
        gateway.send_calls.append((dict(request), context))
        return {"accepted": False, "state": "REJECTED", "intent_id": context.intent_id}

    gateway.send_order = reject
    with pytest.raises(MutationRejected):
        reconcile_enable_start(service, core, repo, target)
    assert len(gateway.send_calls) == 1
    assert core.status()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"


def test_runner_second_failure_cancels_first_ack_and_halts() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    second = deepcopy(target["orders"][0])
    second["reference"] = "order-ref-0002"
    source = {
        key: value
        for key, value in target.items()
        if key not in {"plan_hash", "order_set_sha256"}
    }
    source["orders"] = [target["orders"][0], second]
    target = build_target_plan(**source)
    original_send = gateway.send_order

    def reject_second(request, context):
        if len(gateway.send_calls) == 1:
            gateway.send_calls.append((dict(request), context))
            return {
                "accepted": False,
                "state": "REJECTED",
                "intent_id": context.intent_id,
            }
        return original_send(request, context)

    gateway.send_order = reject_second
    with pytest.raises(MutationRejected):
        reconcile_enable_start(service, core, repo, target)
    assert len(gateway.send_calls) == 2
    assert len(gateway.cancel_calls) == 1
    assert core.status()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"


def test_runner_timeout_cancels_ack_sibling_without_replaying_unknown_intent() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    second = deepcopy(target["orders"][0])
    second["reference"] = "order-ref-0002"
    source = {
        key: value
        for key, value in target.items()
        if key not in {"plan_hash", "order_set_sha256"}
    }
    source["orders"] = [target["orders"][0], second]
    target = build_target_plan(**source)
    original_send = gateway.send_order

    def timeout_second(request, context):
        if len(gateway.send_calls) == 1:
            gateway.send_calls.append((dict(request), context))
            raise TimeoutError("second order outcome unknown")
        return original_send(request, context)

    gateway.send_order = timeout_second
    with pytest.raises(GatewayTimeout):
        reconcile_enable_start(service, core, repo, target)
    token = core.fencer.token
    assert token is not None
    assert len(gateway.send_calls) == 2
    assert len(gateway.cancel_calls) == 1
    assert core.status()["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"
    unknown = next(iter(repo.snapshot()["unknown_outcomes"]))
    assert gateway.cancel_calls[0][0]["target_intent_id"] != unknown
    assert repo.snapshot()["reconciliation"]["state"] == "UNKNOWN"
    replay = service.send_plan_order(target["plan_id"], "order-ref-0002", token=token)
    assert replay["reused"] is True
    assert replay["accepted"] is False
    assert replay["intent_id"] == unknown
    assert len(gateway.send_calls) == 2


@pytest.mark.parametrize(
    ("expected_after", "actual_positions", "should_complete"),
    [
        (
            target_position_hash(),
            target_position_rows(
                frozen=9,
                price=999.5,
                pnl=-42.25,
                commission=123.45,
            ),
            True,
        ),
        (target_position_hash(), target_position_rows(volume=2), False),
        (target_position_hash(), target_position_rows(direction="SHORT"), False),
        (target_position_hash(), target_position_rows(symbol="CU"), False),
        (target_position_hash(), target_position_rows(exchange="DCE"), False),
        (
            target_position_hash(),
            target_position_rows(gateway_name="foreign-gateway"),
            False,
        ),
        (target_position_hash(), target_position_rows(gateway_name=""), False),
        (target_position_hash(), target_position_rows(volume=-1), False),
        (target_position_hash(), target_position_rows(volume="1"), False),
        # TargetPlan v1 plans signed with the former full-row after semantics
        # must not complete, even when those same complete rows are observed.
        (
            sha256_json(target_position_rows()),
            target_position_rows(),
            False,
        ),
        (
            target_position_hash(account_scope="account:foreign"),
            target_position_rows(),
            False,
        ),
        (
            target_position_hash(environment="foreign"),
            target_position_rows(),
            False,
        ),
    ],
)
def test_reconcile_final_target_projection_completes_or_halts(
    expected_after: str, actual_positions: dict, should_complete: bool
) -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan(expected_after=expected_after)
    assert target["expected_before_position_hash"] == before_position_hash({})
    reconcile_enable_start(service, core, repo, target)
    intent_id = next(iter(repo.snapshot()["send_intents"]))

    def terminalize(state):
        state["send_intents"][intent_id]["state"] = "TERMINAL"

    repo.mutate(terminalize)
    gateway.snapshots.append(final_position_snapshot(actual_positions))
    command_value = command(
        "reconcile",
        f"reconcile-final-{expected_after[0]}002",
        repo.state_version,
        {
            "reconciliation_run_id": f"run-final-{expected_after[0]}002",
            "snapshot_id": "snapshot-final-0002",
            "reason": "terminal final position check",
        },
    )
    if should_complete:
        before = repo.state_version
        response = service.process_command(command_value)
        state = repo.snapshot()
        assert state["state_version"] == before + 1 == response.receipt["state_version"]
        assert response.result == response.receipt["result"]
        assert response.result["finalization"]["plan"] == state["plan"]
        assert state["plan"]["state"] == "TERMINAL"
        assert state["authority"]["state"] == "REVOKED"
        archive = state["terminal_archive"][-1]
        assert archive["kind"] == "final_plan_completed"
        assert archive["plan_hash"] == target["plan_hash"]
        assert archive["receipt_id"] == target["authority_receipt_id"]
        assert archive["positions"] == actual_positions
        assert archive["final_position_hash"] == sha256_json(actual_positions)
        assert archive["target_position_hash"] == expected_after
        archive_count = len(state["terminal_archive"])
        retry = service.process_command(command_value)
        assert retry.reused is True
        assert len(repo.snapshot()["terminal_archive"]) == archive_count
    else:
        before = repo.state_version
        response = service.process_command(command_value)
        assert response.result["accepted"] is False
        assert response.result["finalization"]["state"] == "POSITION_MISMATCH"
        assert response.receipt["status"] == "REJECTED"
        assert response.receipt["state_version"] == before + 1
        assert core.status()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"


def test_reconcile_query_only_terminal_submitted_intent_completes_finalization() -> None:
    service, _core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    reconcile_enable_start(service, _core, repo, target)
    intent_id = next(iter(repo.snapshot()["send_intents"]))

    repo.mutate(
        lambda state: state["send_intents"][intent_id].update({"state": "SUBMITTED"})
    )
    gateway.intent_outcomes[intent_id] = {"state": "TERMINAL", "resolved": True}
    gateway.snapshots.append(final_position_snapshot(target_position_rows()))
    gateway.send_calls.clear()
    gateway.cancel_calls.clear()
    before = repo.state_version

    command_value = command(
        "reconcile",
        "reconcile-submitted-terminal-0001",
        repo.state_version,
        {
            "reconciliation_run_id": "run-submitted-terminal-0001",
            "snapshot_id": "snapshot-final-0002",
            "reason": "query-only submitted terminal recovery",
        },
    )
    response = service.process_command(command_value)

    state = repo.snapshot()
    assert state["state_version"] == before + 1 == response.receipt["state_version"]
    assert gateway.query_calls == [intent_id]
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []
    assert state["send_intents"][intent_id]["state"] == "TERMINAL"
    assert response.result["finalization"]["state"] == "COMPLETED"
    assert state["plan"]["state"] == "TERMINAL"
    intent_archives = [
        archive
        for archive in state["terminal_archive"]
        if archive["kind"] == "intent_terminal" and archive["intent_id"] == intent_id
    ]
    assert len(intent_archives) == 1
    archive_count = len(state["terminal_archive"])
    query_calls = list(gateway.query_calls)

    retry = service.process_command(command_value)

    assert retry.reused is True
    assert retry.receipt == response.receipt
    assert len(repo.snapshot()["terminal_archive"]) == archive_count
    assert gateway.query_calls == query_calls
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []


def test_reconcile_query_only_nonterminal_submitted_intent_stays_pending() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    reconcile_enable_start(service, core, repo, target)
    intent_id = next(iter(repo.snapshot()["send_intents"]))

    repo.mutate(
        lambda state: state["send_intents"][intent_id].update({"state": "SUBMITTED"})
    )
    gateway.intent_outcomes[intent_id] = {"state": "ACKNOWLEDGED", "resolved": True}
    gateway.snapshots.append(final_position_snapshot(target_position_rows()))
    gateway.send_calls.clear()
    gateway.cancel_calls.clear()

    response = service.process_command(
        command(
            "reconcile",
            "reconcile-submitted-pending-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-submitted-pending-0001",
                "snapshot_id": "snapshot-final-0002",
                "reason": "query-only submitted pending recovery",
            },
        )
    )

    state = repo.snapshot()
    assert gateway.query_calls == [intent_id]
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []
    assert state["send_intents"][intent_id]["state"] == "SUBMITTED"
    assert response.result["finalization"]["state"] == "PENDING"
    assert state["plan"]["state"] == "ACTIVE"


@pytest.mark.parametrize("query_failure", [None, GatewayTimeout("query unavailable")])
def test_reconcile_query_only_submitted_unknown_or_error_fails_closed(
    query_failure: Exception | None,
) -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    reconcile_enable_start(service, core, repo, target)
    intent_id = next(iter(repo.snapshot()["send_intents"]))

    repo.mutate(
        lambda state: state["send_intents"][intent_id].update({"state": "SUBMITTED"})
    )
    if query_failure is None:
        gateway.intent_outcomes[intent_id] = {"state": "UNKNOWN"}
    else:
        gateway.fail_query = query_failure
    gateway.snapshots.append(final_position_snapshot(target_position_rows()))
    gateway.send_calls.clear()
    gateway.cancel_calls.clear()

    response = service.process_command(
        command(
            "reconcile",
            "reconcile-submitted-unknown-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-submitted-unknown-0001",
                "snapshot_id": "snapshot-final-0002",
                "reason": "query-only submitted unknown recovery",
            },
        )
    )

    state = repo.snapshot()
    assert gateway.query_calls == [intent_id]
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []
    assert state["send_intents"][intent_id]["state"] == "UNKNOWN_OUTCOME"
    assert intent_id in state["unknown_outcomes"]
    assert response.receipt["status"] == "REJECTED"
    assert response.result["accepted"] is False
    assert "finalization" not in response.result
    assert core.status()["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"


def test_target_position_projection_normalizes_aggregates_and_rejects_bad_rows() -> (
    None
):
    first = target_position_rows(
        vt_positionid="first-row",
        symbol="rb",
        exchange="shfe",
        direction="long",
        gateway_name="gateway-0001",
        volume=1,
        price=1.0,
    )
    second = target_position_rows(
        vt_positionid="second-row",
        symbol="RB",
        exchange="SHFE",
        direction="LONG",
        gateway_name="GATEWAY-0001",
        volume=2,
        price=999.0,
    )
    rows = first | second
    assert target_position_hash(rows) == target_position_hash(
        target_position_rows(volume=3)
    )
    assert target_position_hash({}) == target_position_hash(
        target_position_rows(volume=0)
    )
    assert target_position_hash(account_scope=f" {SCOPE} ") == target_position_hash()
    assert target_position_hash(account_scope=SCOPE.upper()) != target_position_hash()
    for invalid in (
        target_position_rows(gateway_name=""),
        target_position_rows(volume=-1),
        target_position_rows(volume="1"),
        target_position_rows(symbol="INVALID!"),
        target_position_rows(exchange="NYSE"),
        target_position_rows(direction="FLAT"),
        target_position_rows(gateway_name="short"),
    ):
        with pytest.raises(CommodityExecutionContractError):
            target_position_hash(invalid)
    with pytest.raises(CommodityExecutionContractError):
        target_position_hash(account_scope="bad")


def test_before_position_projection_binds_and_requires_shfe_ine_yd_volume() -> None:
    today = target_position_rows(yd_volume=0)
    yesterday = target_position_rows(yd_volume=1)

    assert before_position_hash(today) != before_position_hash(yesterday)
    missing = target_position_rows()
    del next(iter(missing.values()))["yd_volume"]
    with pytest.raises(CommodityExecutionContractError, match="yd_volume"):
        before_position_hash(missing)


def test_before_position_projection_aggregates_shfe_yd_volume_once_per_row() -> None:
    first = target_position_rows(vt_positionid="first-row", yd_volume=1)
    second = target_position_rows(vt_positionid="second-row", yd_volume=0)

    projection = canonical_before_position_projection(
        first | second, account_scope=SCOPE, environment="SIMNOW"
    )

    assert projection["positions"] == [
        {
            "gateway_name": "GATEWAY-0001",
            "symbol": "RB",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 2,
            "yd_volume": 1,
        }
    ]


def test_durable_final_archive_accepts_legacy_readonly_and_requires_new_full_hash(
    tmp_path: Path,
) -> None:
    repository = DurableExecutionRepository(tmp_path / "execution.json", scope=SCOPE)
    legacy = {
        "kind": "final_plan_completed",
        "plan_id": "plan-final-0001",
        "plan_hash": "a" * 64,
        "plan_version": 1,
        "receipt_id": "custody-install-0001",
        "final_position_hash": "0" * 64,
        "archived_at": "2030-01-01T00:00:00Z",
    }
    repository.append_terminal_archive(legacy)
    restarted = DurableExecutionRepository(tmp_path / "execution.json", scope=SCOPE)
    assert restarted.snapshot()["terminal_archive"] == [legacy]

    positions = target_position_rows(price=999.5, pnl=-42.25)
    current = {
        **legacy,
        "plan_id": "plan-final-0002",
        "plan_hash": "b" * 64,
        "final_position_hash": sha256_json(positions),
        "target_position_hash": target_position_hash(positions),
        "positions": positions,
    }
    assert restarted.append_terminal_archive(current) == current
    invalid = {**current, "positions": target_position_rows(volume=2)}
    with pytest.raises(RepositoryUnavailableError, match="full position hash"):
        restarted.append_terminal_archive(invalid)


def test_partial_unknown_same_intent_cancel_fence_and_restart_reconcile(
    tmp_path: Path,
) -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    gateway.fail_send = TimeoutError("network partition")
    with pytest.raises(GatewayTimeout):
        reconcile_enable_start(service, core, repo, target)
    token = core.fencer.token
    assert token is not None
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
