from __future__ import annotations

import ast
import asyncio
import importlib.util
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.execution import (
    ExecutionOrchestrator,
    GatewaySnapshot,
    InMemoryExecutionRepository,
    InMemoryGateway,
)
from app.execution.errors import AuthorityRejected, PlanRejected
from app.execution.final_runtime import (
    FinalExecutionRuntime,
    InMemoryTargetPlanRepository,
)
from app.phase_c.adapters import WorkflowAdapterError
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyPolicy,
    CustodySettings,
    create_app,
)
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO
from fastapi.testclient import TestClient

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    CommodityExecutionContractError,
    before_position_projection_hash,
    build_trusted_keyless_target_plan,
    sha256_json,
    target_position_projection_hash,
)
from shared.trust_contracts.v1 import canonical_json_line, sha256_bytes


def keyless_plan(
    *,
    generated_at: str = "2030-01-01T00:00:00Z",
    expires_at: str = "2099-01-01T00:00:00Z",
) -> dict:
    before = before_position_projection_hash(
        {}, account_scope="account:windows", environment="SIMNOW"
    )
    after = target_position_projection_hash(
        {
            "RB2601.SHFE.LONG": {
                "gateway_name": "CTP",
                "symbol": "RB2601",
                "exchange": "SHFE",
                "direction": "LONG",
                "volume": 1,
            }
        },
        account_scope="account:windows",
        environment="SIMNOW",
    )
    return build_trusted_keyless_target_plan(
        plan_id="keyless-target-plan-0001",
        account_scope="account:windows",
        environment="SIMNOW",
        gateway_name="CTP",
        lineage={"map_sha256": "a" * 64, "c_fast_sha256": "b" * 64},
        scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        generated_at=generated_at,
        expires_at=expires_at,
        phase="OPEN",
        expected_before_position_hash=before,
        expected_after_position_hash=after,
        orders=[
            {
                "symbol": "rb2601",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 3500.0,
                "offset": "OPEN",
                "reference": "keyless-order-0001",
                "gateway_name": "CTP",
            }
        ],
    )


class KeylessCustody:
    def __init__(self, plan: dict) -> None:
        self.artifact_value = new_artifact_envelope(
            artifact_type="simnow-target-plan",
            trust_domain="runtime_authorization",
            producer_id="issue325-fixture",
            producer_version="v1",
            schema_ref=KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
            payload=plan,
            generated_at=plan["generated_at"],
            scope=plan["scope"],
            predecessor_refs=[],
            lineage=[],
        )
        self.receipt_value = {
            "receipt_id": "keyless-install-0001",
            "receipt_type": "install",
            "artifact_id": self.artifact_value["artifact_id"],
            "artifact_type": "simnow-target-plan",
            "trust_domain": "runtime_authorization",
            "schema_ref": KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
            "artifact_sha256": self.artifact_value["raw_sha256"],
            "scope": plan["scope"],
            "expires_at": plan["expires_at"],
            "custody_version": 2,
            "idempotency_key": "keyless-install-idem-0001",
            "verified": True,
            "installed": True,
            "custody_writer": "artifact-custody",
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }

    def receipt(self, receipt_id: str):
        return (
            self.receipt_value
            if receipt_id == self.receipt_value["receipt_id"]
            else None
        )

    def artifact_for_test(self):
        return {
            "artifact_id": self.artifact_value["artifact_id"],
            "artifact_raw_sha256": sha256_bytes(
                canonical_json_line(self.artifact_value)
            ),
            "artifact": self.artifact_value,
        }

    def artifact(self, artifact_id: str):
        return (
            self.artifact_for_test()
            if artifact_id == self.artifact_value["artifact_id"]
            else None
        )

    def probe(self):
        return None


def runtime(plan: dict, *, enabled: bool = True) -> FinalExecutionRuntime:
    core = ExecutionOrchestrator(
        InMemoryExecutionRepository(scope="account:windows"),
        InMemoryGateway(account_scope="account:windows", environment="SIMNOW"),
        scope="account:windows",
        environment="SIMNOW",
        test_mode=True,
    )
    return FinalExecutionRuntime(
        core,
        plans=InMemoryTargetPlanRepository(),
        custody=KeylessCustody(plan),
        allowed_scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        allow_trusted_keyless_simnow=enabled,
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
            "principal": "keyless-test",
            "operator": "keyless-test",
            "role": "admin",
        },
        "command": name,
        "expected": expected,
        "payload": payload,
    }


def test_keyless_plan_is_canonical_and_has_no_signing_or_runtime_authority_fields() -> (
    None
):
    plan = keyless_plan()
    assert plan["schema_version"] == KEYLESS_TARGET_PLAN_SCHEMA_VERSION
    assert plan["plan_hash"] == sha256_json(
        {key: value for key, value in plan.items() if key != "plan_hash"}
    )
    assert {"signer_key_id", "keyring_raw_sha256", "authority_receipt_id"}.isdisjoint(
        plan
    )


def test_keyless_custody_preview_recomputes_artifact_and_plan_hashes() -> None:
    plan = keyless_plan()
    service = runtime(plan)
    installed = service.preview_from_custody("keyless-install-0001")
    assert installed.plan_hash == plan["plan_hash"]
    with pytest.raises(PlanRejected, match="installed from custody"):
        service.install_target_plan(plan)

    tampered = keyless_plan()
    tampered["orders"][0]["price"] = 1.0
    with pytest.raises(PlanRejected, match="artifact is invalid"):
        runtime(tampered).preview_from_custody("keyless-install-0001")


def test_keyless_preview_enable_start_keeps_existing_fencing_and_send_intent() -> None:
    plan = keyless_plan()
    service = runtime(plan)
    service.allow_simnow_execution = True
    core = service.orchestrator
    repo = core.repository
    gateway = core.gateway
    receipt = service.custody.receipt_value
    service.process_command(
        command(
            "preview",
            "keyless-preview-0001",
            repo.state_version,
            {
                "plan_hash": plan["plan_hash"],
                "artifact_hash": receipt["artifact_sha256"],
                "mode": "simnow_preview",
                "receipt_id": receipt["receipt_id"],
            },
        )
    )
    service.process_command(
        command(
            "reconcile",
            "keyless-reconcile-001",
            repo.state_version,
            {
                "reconciliation_run_id": "keyless-run-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh SIMNOW facts",
            },
        )
    )
    service.process_command(
        command(
            "enable",
            "keyless-enable-00001",
            repo.state_version,
            {
                "authority_artifact_id": plan["plan_id"],
                "authority_hash": plan["plan_hash"],
                "expires_at": plan["expires_at"],
                "reason": "fixed keyless custody",
            },
        )
    )
    token = core.acquire_leader("keyless-leader-0001")
    response = service.process_command(
        command(
            "start",
            "keyless-start-000001",
            repo.state_version,
            {
                "plan_id": plan["plan_id"],
                "plan_hash": plan["plan_hash"],
                "reason": "start keyless plan",
            },
            fence={"leader_epoch": token.epoch, "fencing_token": token.fencing_token},
        )
    )
    assert response.result["accepted"] is True
    assert len(gateway.send_calls) == 1
    assert repo.snapshot()["send_intents"]


def test_keyless_expired_active_plan_reconciles_but_new_preview_stays_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = keyless_plan(expires_at="2030-01-01T00:00:00Z")
    service = runtime(plan)
    service.allow_simnow_execution = True
    core = service.orchestrator
    repo = core.repository
    gateway = core.gateway
    receipt = service.custody.receipt_value
    service.process_command(
        command(
            "preview",
            "keyless-expired-preview-0001",
            repo.state_version,
            {
                "plan_hash": plan["plan_hash"],
                "artifact_hash": receipt["artifact_sha256"],
                "mode": "simnow_preview",
                "receipt_id": receipt["receipt_id"],
            },
        )
    )
    service.process_command(
        command(
            "reconcile",
            "keyless-expired-pre-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "keyless-expired-pre-run-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh SIMNOW facts",
            },
        )
    )
    service.process_command(
        command(
            "enable",
            "keyless-expired-enable-0001",
            repo.state_version,
            {
                "authority_artifact_id": plan["plan_id"],
                "authority_hash": plan["plan_hash"],
                "expires_at": plan["expires_at"],
                "reason": "fixed keyless custody",
            },
        )
    )
    token = core.acquire_leader("keyless-expired-leader-0001")
    service.process_command(
        command(
            "start",
            "keyless-expired-start-0001",
            repo.state_version,
            {
                "plan_id": plan["plan_id"],
                "plan_hash": plan["plan_hash"],
                "reason": "start historical keyless plan",
            },
            fence={"leader_epoch": token.epoch, "fencing_token": token.fencing_token},
        )
    )
    intent_id = next(iter(repo.snapshot()["send_intents"]))
    target_positions = {
        "RB2601.SHFE.LONG": {
            "gateway_name": "CTP",
            "symbol": "RB2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 1,
        }
    }

    repo.mutate(
        lambda state: state["send_intents"][intent_id].update({"state": "SUBMITTED"})
    )
    gateway.intent_outcomes[intent_id] = {"state": "TERMINAL", "resolved": True}
    gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id="snapshot-keyless-final-0002",
            generation=2,
            connected=True,
            position_snapshot_hash=sha256_json(target_positions),
            positions=target_positions,
            account_scope="account:windows",
            environment="SIMNOW",
        )
    )
    gateway.send_calls.clear()
    gateway.cancel_calls.clear()
    monkeypatch.setattr(
        "app.execution.final_runtime.utc_now",
        lambda: datetime(2031, 1, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(PlanRejected, match="receipt scope/expiry mismatch"):
        service.preview_from_custody("keyless-install-0001")

    response = service.process_command(
        command(
            "reconcile",
            "keyless-expired-final-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "keyless-expired-run-0001",
                "snapshot_id": "snapshot-keyless-final-0002",
                "reason": "query-only expired historical plan recovery",
            },
        )
    )

    state = repo.snapshot()
    assert gateway.query_calls == [intent_id]
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []
    assert state["send_intents"][intent_id]["state"] == "TERMINAL"
    assert response.result["finalization"]["state"] == "COMPLETED"
    assert state["plan"]["state"] == "TERMINAL"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_scope", "account:foreign"),
        ("gateway_name", "OTHER"),
        ("environment", "production"),
        ("production_allowed", True),
        ("live_trading_authorized", True),
        ("countable_forward", True),
    ],
)
def test_keyless_plan_rejects_any_tuple_or_authority_flag_deviation(
    field: str, value: object
) -> None:
    raw = keyless_plan()
    raw[field] = value
    raw["plan_hash"] = sha256_json(
        {key: item for key, item in raw.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError):
        from shared.commodity_execution import TargetPlan

        TargetPlan.from_mapping(raw)


def test_keyless_plan_rejects_order_gateway_and_empty_position_transition() -> None:
    raw = keyless_plan()
    raw["orders"][0]["gateway_name"] = "gateway-OTHER"
    raw["order_set_sha256"] = sha256_json(raw["orders"])
    raw["plan_hash"] = sha256_json(
        {key: item for key, item in raw.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError, match="order gateway"):
        from shared.commodity_execution import TargetPlan

        TargetPlan.from_mapping(raw)

    raw = keyless_plan()
    raw["expected_after_position_hash"] = raw["expected_before_position_hash"]
    raw["plan_hash"] = sha256_json(
        {key: item for key, item in raw.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError, match="position transition"):
        TargetPlan.from_mapping(raw)


def test_keyless_custody_is_disabled_without_explicit_runtime_gate() -> None:
    with pytest.raises(AuthorityRejected, match="keyless SIMNOW custody is disabled"):
        runtime(keyless_plan(), enabled=False).preview_from_custody(
            "keyless-install-0001"
        )


def test_trusted_keyless_custody_is_create_only_and_returns_no_signing_fields(
    tmp_path: Path,
) -> None:
    service = ArtifactCustodyService(
        CustodySettings(
            tmp_path / "custody",
            "artifact-custody",
            1,
            "control-secret",
            frozenset({"control-api"}),
            {
                name: CustodyPolicy(str(tmp_path / f"{name}.json"), "0" * 64, "unused")
                for name in (
                    "map_acceptance",
                    "c_fast_acceptance",
                    "runtime_authorization",
                )
            },
            "execution-read-secret",
            None,
            True,
        )
    )
    plan = keyless_plan()
    artifact = KeylessCustody(plan).artifact_value
    receipt = service.publish_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key="keyless-publish-0001",
            expected_custody_version=0,
            correlation_id="keyless-correlation-0001",
            artifact=artifact,
        ),
        principal="control-api",
    )
    assert receipt["artifact_sha256"] == artifact["raw_sha256"]
    assert {"signer_key_id", "keyring_raw_sha256", "signed_artifact_sha256"}.isdisjoint(
        receipt
    )
    assert (
        service.artifact_for_execution(receipt["artifact_id"])["artifact"] == artifact
    )
    assert service.receipt_by_idempotency("keyless-publish-0001") == receipt
    with TestClient(create_app(service)) as client:
        recovered = client.get(
            "/internal/v1/receipts-by-idempotency/keyless-publish-0001",
            headers={
                "X-Phase-C-Principal": "control-api",
                "X-Phase-C-Custody-Secret": "control-secret",
            },
        )
    assert recovered.status_code == 200
    assert recovered.json()["receipt_id"] == receipt["receipt_id"]
    with pytest.raises(
        WorkflowAdapterError, match="CUSTODY_ARTIFACT_ALREADY_PUBLISHED"
    ):
        service.publish_trusted_keyless_target_plan(
            TrustedKeylessTargetPlanUploadDTO(
                idempotency_key="keyless-publish-0002",
                expected_custody_version=2,
                correlation_id="keyless-correlation-0002",
                artifact=artifact,
            ),
            principal="control-api",
        )


def test_keyless_custody_publish_is_closed_without_settings_gate(
    tmp_path: Path,
) -> None:
    service = ArtifactCustodyService(
        CustodySettings(
            tmp_path / "custody",
            "artifact-custody",
            1,
            "control-secret",
            frozenset({"control-api"}),
            {},
            "execution-read-secret",
        )
    )
    payload = TrustedKeylessTargetPlanUploadDTO(
        idempotency_key="keyless-disabled-0001",
        expected_custody_version=0,
        correlation_id="keyless-disabled-correlation-0001",
        artifact=KeylessCustody(keyless_plan()).artifact_value,
    )
    with pytest.raises(Exception, match="keyless SIMNOW custody is disabled"):
        service.publish_trusted_keyless_target_plan(payload, principal="control-api")
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/internal/v1/publish-keyless-simnow-target-plan",
            json=payload.model_dump(mode="json"),
            headers={
                "X-Phase-C-Principal": "control-api",
                "X-Phase-C-Custody-Secret": "control-secret",
            },
        )
    assert response.status_code == 409


def test_keyless_only_custody_configuration_needs_no_keyring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PHASE_C_CUSTODY_ROOT", str(tmp_path / "custody"))
    monkeypatch.setenv("PHASE_C_CUSTODY_SHARED_SECRET", "control-secret")
    monkeypatch.setenv("PHASE_C_CUSTODY_EXECUTION_READ_SECRET", "read-secret")
    monkeypatch.setenv("PHASE_C_CUSTODY_WRITER_EPOCH", "1")
    monkeypatch.setenv("SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED", "true")
    monkeypatch.delenv("PHASE_C_CUSTODY_POLICIES_JSON", raising=False)
    assert CustodySettings.from_env().policies == {}


def test_simnow_run_once_uses_only_existing_custody_and_execution_clients() -> None:
    source = (
        Path(__file__).resolve().parents[3] / "scripts" / "simnow_run_once.py"
    ).read_text(encoding="utf-8")
    assert "RemotePhaseCWorkflowClient" in source
    assert "ExecutionClient" in source
    assert "send_order" not in source and "VnpyWindowsGateway" not in source
    assert 'parser.add_argument("--execute", action="store_true")' in source
    assert 'parser.add_argument("--map-candidate"' not in source
    assert 'parser.add_argument("--c-fast-candidate"' not in source
    assert "produce_static_core_equal(" in source
    assert "produce_position_manager_snapshot(" in source


def test_simnow_runner_image_keeps_the_real_import_closure_and_no_direct_gateway_rpc_or_order_import() -> (
    None
):
    root = Path(__file__).resolve().parents[3]
    source_path = root / "scripts" / "simnow_run_once.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    direct_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    direct_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden_modules = {
        "app.execution.gateway",
        "app.execution.orchestrator",
        "app.execution.repository",
        "app.execution.final_runtime",
        "zmq",
        "vnpy",
    }
    forbidden_names = {
        "ExecutionGateway",
        "VnpyWindowsGateway",
        "ZmqRpcTransport",
        "send_order",
        "cancel_order",
    }
    assert not direct_modules.intersection(forbidden_modules)
    assert not direct_names.intersection(forbidden_names)

    containerfile = (
        root / "deployments" / "phase-b" / "Containerfile.simnow-runner"
    ).read_text(encoding="utf-8")
    copied_sources = {
        line.split()[1]
        for line in containerfile.splitlines()
        if line.startswith("COPY ")
    }
    assert copied_sources == {
        "deployments/phase-b/requirements-simnow-runner.txt",
        "backend/app/__init__.py",
        "backend/app/control_execution_client.py",
        "backend/app/control_execution_projection.py",
        "backend/app/core/__init__.py",
        "backend/app/core/commodity_strategy_identity.py",
        "docs/schemas/web-bridge-execution-status-v1.schema.json",
        "backend/app/schemas/__init__.py",
        "backend/app/schemas/control_execution.py",
        "backend/app/execution/__init__.py",
        "backend/app/execution/errors.py",
        "backend/app/execution/executable_target_adapter.py",
        "backend/app/execution/gateway_contracts.py",
        "backend/app/execution/models.py",
        "backend/app/phase_c/__init__.py",
        "backend/app/phase_c/adapters.py",
        "backend/app/phase_c/client.py",
        "backend/app/phase_c/models.py",
        "scripts/simnow_keyless_pilot.py",
        "scripts/simnow_run_once.py",
        "scripts/phase_b_workers/__init__.py",
        "scripts/phase_b_workers/contracts.py",
        "scripts/phase_b_workers/durable.py",
        "scripts/phase_b_workers/projections.py",
        "scripts/c_fast_producer",
        "scripts/map",
        "scripts/commodity_c_fast_pure_producer_kernel.py",
        "scripts/commodity_static_core_equal_formula_v1.py",
        "scripts/commodity_static_core_equal_pure_producer.py",
        "scripts/commodity_relative_vol_snapshot_producer.py",
        "shared/artifact_contracts",
        "shared/commodity_execution",
        "shared/phase_c_workflow",
        "shared/trust_contracts",
    }
    assert "backend/app/execution/gateway.py" not in copied_sources
    assert 'ENTRYPOINT ["python", "/app/scripts/simnow_run_once.py"]' in containerfile


def test_simnow_run_once_accepts_canonical_sources_and_rejects_candidate_inputs() -> (
    None
):
    path = Path(__file__).resolve().parents[3] / "scripts" / "simnow_run_once.py"
    spec = importlib.util.spec_from_file_location("issue325_run_once", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parser = module.build_parser()
    args = parser.parse_args(
        [
            "--static-core-source",
            "static-core-source.json",
            "--position-manager-source",
            "position-manager-source.json",
            "--peek-current-facts",
            "peek.json",
            "--reconciliation-state",
            "reconcile.json",
            "--product",
            "rb",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--principal",
            "runner-admin",
            "--operator",
            "runner-admin",
            "--idempotency-suffix",
            "run-0001",
            "--expected-custody-version",
            "0",
        ]
    )
    assert args.static_core_source == Path("static-core-source.json")
    assert args.position_manager_source == Path("position-manager-source.json")
    with pytest.raises(SystemExit):
        parser.parse_args(["--map-candidate", "arbitrary.json"])


def test_simnow_run_once_direct_python_help_has_no_external_pythonpath() -> None:
    root = Path(__file__).resolve().parents[3]
    completed = subprocess.run(
        [sys.executable, "scripts/simnow_run_once.py", "--help"],
        cwd=root,
        env={},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--static-core-source" in completed.stdout
    assert "--position-manager-source" in completed.stdout


def test_simnow_run_once_completion_fails_closed_for_pending_unknown_and_active() -> (
    None
):
    path = Path(__file__).resolve().parents[3] / "scripts" / "simnow_run_once.py"
    spec = importlib.util.spec_from_file_location("issue325_completion", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    base = {
        "lifecycle": "ACTIVE",
        "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
        "broker": {"active_order_count": 0},
        "send_intents": [
            {"plan_id": "plan-0001", "plan_hash": "a" * 64, "state": "ACKNOWLEDGED"}
        ],
    }
    assert (
        module._completion_state(base, plan_id="plan-0001", plan_hash="a" * 64)
        == "pending_intents"
    )
    unknown = {**base, "reconciliation": {"state": "UNKNOWN", "unknown_outcomes": 1}}
    assert (
        module._completion_state(unknown, plan_id="plan-0001", plan_hash="a" * 64)
        == "unknown_outcome"
    )
    active = {**base, "broker": {"active_order_count": 1}}
    assert (
        module._completion_state(active, plan_id="plan-0001", plan_hash="a" * 64)
        == "active_orders"
    )


def _run_once_module(name: str):
    path = Path(__file__).resolve().parents[3] / "scripts" / "simnow_run_once.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_once_args(module, *, timeout: float = 1.0) -> object:
    return module.build_parser().parse_args(
        [
            "--static-core-source",
            "static-core-source.json",
            "--position-manager-source",
            "position-manager-source.json",
            "--peek-current-facts",
            "peek.json",
            "--reconciliation-state",
            "reconcile.json",
            "--product",
            "rb",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--principal",
            "runner-admin",
            "--operator",
            "runner-admin",
            "--idempotency-suffix",
            "run-0001",
            "--expected-custody-version",
            "0",
            "--execute",
            "--completion-timeout-seconds",
            str(timeout),
            "--completion-poll-seconds",
            "0.001",
        ]
    )


def _runner_status(
    *,
    version: int,
    plan_id: str = "plan-0001",
    plan_hash: str = "a" * 64,
    intent_state: str = "ACKNOWLEDGED",
    active_orders: int = 0,
    lifecycle: str = "READY",
    reconciliation: str = "RECONCILED",
    unknown_outcomes: int = 0,
    terminal: bool = False,
) -> dict:
    return {
        "state_version": version,
        "leader": {"held": True, "epoch": 1, "fencing_token": 1},
        "broker": {
            "snapshot_id": f"snapshot-{version}",
            "connected": True,
            "active_order_count": active_orders,
            "position_snapshot_hash": "c" * 64,
            "last_snapshot_at": "2030-01-01T00:00:00Z",
        },
        "lifecycle": "READY" if terminal else lifecycle,
        "safe_to_restart": terminal,
        "reconciliation": {
            "state": reconciliation,
            "unknown_outcomes": unknown_outcomes,
            "last_completed_at": "2030-01-01T00:00:00Z",
        },
        "send_intents": (
            []
            if version < 4
            else [
                {
                    "plan_id": plan_id,
                    "plan_hash": plan_hash,
                    "state": intent_state,
                }
            ]
        ),
        "plan": {
            "state": "TERMINAL" if terminal else "ACTIVE",
            "plan_id": plan_id,
            "plan_hash": plan_hash,
        },
        "authority": {"state": "REVOKED" if terminal else "ACTIVE"},
    }


def _runner_preflight_status() -> dict:
    return {
        "state_version": 0,
        "leader": {"held": True, "epoch": 1, "fencing_token": 1},
        "broker": {
            "snapshot_id": "snapshot-preflight",
            "connected": True,
            "active_order_count": 0,
            "position_snapshot_hash": "c" * 64,
            "last_snapshot_at": "2030-01-01T00:00:00Z",
        },
        "lifecycle": "READY",
        "safe_to_restart": True,
        "reconciliation": {
            "state": "RECONCILED",
            "unknown_outcomes": 0,
            "last_completed_at": "2030-01-01T00:00:00Z",
        },
        "send_intents": [],
        "plan": {"state": "IDLE"},
        "authority": {"state": "DISABLED"},
    }


def _install_fake_runner_dependencies(
    module,
    monkeypatch: pytest.MonkeyPatch,
    statuses: list[dict],
    *,
    final_response: dict | None = None,
) -> SimpleNamespace:
    plan = {
        "plan_id": "plan-0001",
        "plan_hash": "a" * 64,
        "expected_after_position_hash": "d" * 64,
        "expires_at": "2099-01-01T00:00:00Z",
    }
    handoff = SimpleNamespace(
        target_plan=plan,
        trusted_keyless_custody_artifact=lambda: {"artifact": "trusted-keyless"},
    )
    calls: list[str] = []

    class FakeCustody:
        def install_trusted_keyless_target_plan(self, _upload):
            calls.append("custody")
            return SimpleNamespace(
                receipt_id="keyless-receipt-0001", artifact_sha256="b" * 64
            )

    class FakeExecution:
        def __init__(self) -> None:
            self.statuses = iter(
                [_runner_preflight_status(), _runner_preflight_status(), *statuses]
            )
            self.latest = statuses[-1]

        async def status(self):
            try:
                self.latest = next(self.statuses)
            except StopIteration:
                pass
            return SimpleNamespace(as_dict=lambda: self.latest)

        async def submit(self, envelope):
            calls.append(envelope["command"])
            if envelope["command"] == "reconcile" and len(calls) == 6:
                return final_response or _final_reconcile_response(
                    idempotency_key=envelope["idempotency_key"]
                )
            return {"accepted": True}

    static_result = SimpleNamespace(
        producer_projection={},
        artifacts={"freeze_contract": b"{}", "target_evidence": b"{}"},
    )
    position_result = SimpleNamespace(
        snapshot_draft=b"{}", snapshot_draft_sha256="e" * 64
    )
    decision = SimpleNamespace(
        handoff=handoff,
        noop=False,
        static_core_equal_sha256="1" * 64,
        position_manager_sha256="2" * 64,
        final_target_sha256="3" * 64,
        selected_product="rb",
        selected_target_quantity=-1,
        current_quantity=0,
    )
    monkeypatch.setattr(module, "_source_bytes", lambda *_args: b"source")
    monkeypatch.setattr(module, "produce_static_core_equal", lambda _raw: static_result)
    monkeypatch.setattr(
        module,
        "produce_position_manager_snapshot",
        lambda _raw: position_result,
    )
    monkeypatch.setattr(module, "_generated_object", lambda *_args: {})
    monkeypatch.setattr(
        module,
        "_object",
        lambda _path, label: (
            {"state": "RECONCILED", "unknown_outcomes": 0}
            if label == "reconciliation state"
            else {"execution": {"orders": {}}}
        ),
    )
    monkeypatch.setattr(
        module,
        "peek_current_facts_to_snapshot",
        lambda *_args, **_kwargs: SimpleNamespace(
            snapshot=SimpleNamespace(position_snapshot_hash="c" * 64)
        ),
    )
    monkeypatch.setattr(
        module,
        "build_static_core_equal_keyless_target_decision",
        lambda **_kwargs: decision,
    )
    monkeypatch.setattr(module, "RemotePhaseCWorkflowClient", FakeCustody)
    monkeypatch.setattr(module, "ExecutionClient", FakeExecution)
    monkeypatch.setattr(
        module, "_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
    )
    return SimpleNamespace(calls=calls)


def _final_reconcile_response(
    *,
    finalization_state: str = "COMPLETED",
    receipt_status: str = "COMPLETED",
    idempotency_key: str = "simnow-run-once-final-reconcile-run-0001",
    final_position_hash: str = "c" * 64,
    target_position_hash: str = "d" * 64,
) -> dict:
    finalization = {
        "state": finalization_state,
        "final_position_hash": final_position_hash,
        "target_position_hash": target_position_hash,
        "plan": {"state": "TERMINAL", "plan_id": "plan-0001", "plan_hash": "a" * 64},
    }
    result = {"accepted": True, "finalization": finalization}
    return {
        "receipt": {
            "status": receipt_status,
            "idempotency_key": idempotency_key,
            "result": result,
        },
        "result": result,
        "reused": False,
    }


def test_simnow_run_once_fake_e2e_final_reconcile_archives_after_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _run_once_module("issue325_runner_e2e")
    fake = _install_fake_runner_dependencies(
        module,
        monkeypatch,
        [
            _runner_status(version=0),
            _runner_status(version=1),
            _runner_status(version=2),
            _runner_status(version=3),
            _runner_status(version=4, intent_state="TERMINAL"),
            _runner_status(version=5, intent_state="TERMINAL", terminal=True),
        ],
    )

    result = asyncio.run(module.run(_run_once_args(module)))

    assert result["executed"] is True
    assert result["completed"] is True
    assert result["archived"] is True
    assert fake.calls == [
        "custody",
        "preview",
        "reconcile",
        "enable",
        "start",
        "reconcile",
    ]


@pytest.mark.parametrize(
    ("final_response", "label"),
    [
        (
            _final_reconcile_response(target_position_hash="e" * 64),
            "target-position-hash-mismatch",
        ),
        (
            _final_reconcile_response(final_position_hash="f" * 64),
            "final-broker-position-hash-mismatch",
        ),
    ],
)
def test_simnow_run_once_rejects_finalization_position_hash_mismatch(
    monkeypatch: pytest.MonkeyPatch, final_response: dict, label: str
) -> None:
    module = _run_once_module(f"issue325_runner_hash_mismatch_{label}")
    fake = _install_fake_runner_dependencies(
        module,
        monkeypatch,
        [
            _runner_status(version=0),
            _runner_status(version=1),
            _runner_status(version=2),
            _runner_status(version=3),
            _runner_status(version=4, intent_state="TERMINAL"),
            _runner_status(version=5, intent_state="TERMINAL", terminal=True),
        ],
        final_response=final_response,
    )

    result = asyncio.run(module.run(_run_once_args(module)))

    assert result["executed"] is False
    assert result["completed"] is False
    assert result["archived"] is False
    assert result["reason"] == "final_reconcile_did_not_complete_final_plan"
    assert fake.calls == [
        "custody",
        "preview",
        "reconcile",
        "enable",
        "start",
        "reconcile",
    ]


@pytest.mark.parametrize(
    ("final_response", "label"),
    [
        (
            {
                "receipt": {
                    "status": "COMPLETED",
                    "idempotency_key": "simnow-run-once-final-reconcile-run-0001",
                    "result": {"accepted": True},
                },
                "result": {"accepted": True},
                "reused": False,
            },
            "ordinary-terminal-without-finalization",
        ),
        (
            _final_reconcile_response(finalization_state="STOPPED"),
            "emergency-stop-race",
        ),
        (
            _final_reconcile_response(receipt_status="REJECTED"),
            "halted-final-reconcile",
        ),
    ],
)
def test_simnow_run_once_rejects_terminal_or_stopped_race_without_final_plan_completion(
    monkeypatch: pytest.MonkeyPatch, final_response: dict, label: str
) -> None:
    module = _run_once_module(f"issue325_runner_terminal_race_{label}")
    fake = _install_fake_runner_dependencies(
        module,
        monkeypatch,
        [
            _runner_status(version=0),
            _runner_status(version=1),
            _runner_status(version=2),
            _runner_status(version=3),
            _runner_status(version=4, intent_state="TERMINAL"),
            _runner_status(version=5, intent_state="TERMINAL", terminal=True),
        ],
        final_response=final_response,
    )

    result = asyncio.run(module.run(_run_once_args(module)))

    assert result["executed"] is False
    assert result["completed"] is False
    assert result["archived"] is False
    assert result["reason"] == "final_reconcile_did_not_complete_final_plan"
    assert fake.calls == [
        "custody",
        "preview",
        "reconcile",
        "enable",
        "start",
        "reconcile",
    ]


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (
            _runner_status(version=4, intent_state="ACKNOWLEDGED"),
            "completion_timeout:pending_intents",
        ),
        (
            _runner_status(version=4, reconciliation="UNKNOWN", unknown_outcomes=1),
            "unknown_outcome",
        ),
    ],
)
def test_simnow_run_once_does_not_replay_or_finalize_unknown_or_pending(
    monkeypatch: pytest.MonkeyPatch, status: dict, reason: str
) -> None:
    module = _run_once_module(f"issue325_runner_reject_{reason}")
    fake = _install_fake_runner_dependencies(
        module,
        monkeypatch,
        [
            _runner_status(version=0),
            _runner_status(version=1),
            _runner_status(version=2),
            _runner_status(version=3),
            status,
        ],
    )

    result = asyncio.run(module.run(_run_once_args(module, timeout=0.001)))

    assert result["completed"] is False
    assert result["archived"] is False
    assert result["executed"] is False
    assert result["reason"] == reason
    assert fake.calls == ["custody", "preview", "reconcile", "enable", "start"]
