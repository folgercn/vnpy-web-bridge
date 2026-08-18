from __future__ import annotations

import asyncio
from copy import deepcopy
from pathlib import Path

import httpx
import pytest
from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientSettings,
    ExecutionProtocolError,
)
from app.execution import (
    DurableExecutionRepository,
    DurableTargetPlanRepository,
    ExecutionOrchestrator,
    GatewaySnapshot,
    InMemoryGateway,
    PlanRejected,
)
from app.execution.final_runtime import FinalExecutionRuntime
from app.execution.formal_tick_reader import FormalTickSourceUnavailable
from app.execution_orchestrator import create_app
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO
from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    before_position_projection_hash,
    sha256_json,
    target_position_projection_hash,
)
from test_issue291_final_execution import command
from test_issue362_execution_control_facts_recovery import (
    _CustodyReader,
    _empty_custody,
    _tree,
)
from test_issue362_execution_two_quote_proofs import QUOTE_TIME, _Reader
from test_issue362_target_plan_v3 import _v3_plan


SCOPE = "account:windows"
ENVIRONMENT = "SIMNOW"
PUBLISH_KEY = "issue362-v3-recovery-publish-0001"
SECRET = "issue362-v3-recovery-execution-secret"


def _positions() -> dict[str, dict[str, object]]:
    return {
        "ag2609.SHFE.LONG.CTP.v3": {
            "gateway_name": "CTP",
            "symbol": "ag2609",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 1,
        }
    }


def _plan() -> dict[str, object]:
    return _v3_plan(
        expected_before_position_hash=before_position_projection_hash(
            {}, account_scope=SCOPE, environment=ENVIRONMENT
        ),
        expected_after_position_hash=target_position_projection_hash(
            _positions(), account_scope=SCOPE, environment=ENVIRONMENT
        ),
    )


def _artifact() -> dict[str, object]:
    plan = _plan()
    return new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="issue362-v3-recovery-fixture",
        producer_version="v3",
        schema_ref=KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        payload=plan,
        generated_at=str(plan["generated_at"]),
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
    )


def _publish_installed(tmp_path: Path):
    custody = _empty_custody(tmp_path)
    artifact = _artifact()
    receipt = custody.publish_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key=PUBLISH_KEY,
            expected_custody_version=0,
            correlation_id="issue362-v3-recovery-correlation-0001",
            artifact=artifact,
        ),
        principal="control-api",
    )
    return custody, artifact, receipt


def _runtime(
    tmp_path: Path,
    custody,
    reader: _Reader,
) -> tuple[
    FinalExecutionRuntime,
    DurableExecutionRepository,
    DurableTargetPlanRepository,
    InMemoryGateway,
]:
    repository = DurableExecutionRepository(
        tmp_path / "execution-state.json", scope=SCOPE
    )
    plans = DurableTargetPlanRepository(tmp_path / "plans")
    gateway = InMemoryGateway(account_scope=SCOPE, environment=ENVIRONMENT)
    runtime = FinalExecutionRuntime(
        ExecutionOrchestrator(
            repository,
            gateway,
            scope=SCOPE,
            environment=ENVIRONMENT,
            test_mode=True,
        ),
        plans=plans,
        custody=_CustodyReader(custody),
        allowed_scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        allow_simnow_execution=True,
        allow_trusted_keyless_simnow=True,
        formal_tick_bindings_reader=reader,
        quote_clock=lambda: QUOTE_TIME,
    )
    return runtime, repository, plans, gateway


def _preview_reconcile_enable(
    runtime: FinalExecutionRuntime,
    repository: DurableExecutionRepository,
    receipt: dict[str, object],
    artifact: dict[str, object],
    plan: dict[str, object],
) -> None:
    runtime.process_command(
        command(
            "preview",
            "preview-v3-recovery-0001",
            repository.state_version,
            {
                "plan_hash": plan["plan_hash"],
                "artifact_hash": artifact["raw_sha256"],
                "mode": "simnow_preview",
                "receipt_id": receipt["receipt_id"],
            },
        )
    )
    runtime.process_command(
        command(
            "reconcile",
            "reconcile-v3-recovery-0001",
            repository.state_version,
            {
                "reconciliation_run_id": "run-v3-recovery-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh v3 recovery start boundary",
            },
        )
    )
    runtime.process_command(
        command(
            "enable",
            "enable-v3-recovery-0001",
            repository.state_version,
            {
                "authority_artifact_id": plan["plan_id"],
                "authority_hash": plan["plan_hash"],
                "expires_at": plan["expires_at"],
                "reason": "enable exact v3 recovery plan",
            },
        )
    )


def _start(
    runtime: FinalExecutionRuntime,
    repository: DurableExecutionRepository,
    plan: dict[str, object],
):
    token = runtime.orchestrator.acquire_leader("leader-v3-recovery-0001")
    start = command(
        "start",
        "start-v3-recovery-0001",
        repository.state_version,
        {
            "plan_id": plan["plan_id"],
            "plan_hash": plan["plan_hash"],
            "reason": "start exact v3 recovery plan",
        },
        fence={"leader_epoch": token.epoch, "fencing_token": token.fencing_token},
    )
    return runtime.process_command(start)


def _complete(
    runtime: FinalExecutionRuntime,
    repository: DurableExecutionRepository,
    gateway: InMemoryGateway,
) -> dict[str, object]:
    intent_id = next(iter(repository.snapshot()["send_intents"]))
    repository.mutate(
        lambda state: state["send_intents"][intent_id].update({"state": "TERMINAL"})
    )
    gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id="snapshot-v3-recovery-final-0001",
            generation=7,
            connected=True,
            active_order_count=0,
            position_snapshot_hash=sha256_json(_positions()),
            positions=_positions(),
            account_scope=SCOPE,
            environment=ENVIRONMENT,
        )
    )
    response = runtime.process_command(
        command(
            "reconcile",
            "reconcile-v3-final-0001",
            repository.state_version,
            {
                "reconciliation_run_id": "run-v3-final-0001",
                "snapshot_id": "snapshot-v3-recovery-final-0001",
                "reason": "terminal v3 target closure",
            },
        )
    )
    assert response.result["finalization"]["state"] == "COMPLETED"
    return repository.snapshot()["terminal_archive"][-1]


def test_v3_publish_lost_and_install_recovery_are_strict_zero_write(
    tmp_path: Path,
) -> None:
    custody = _empty_custody(tmp_path)
    artifact = _artifact()
    with custody._custody() as writer:
        writer.publish(
            artifact,
            actor_id="control-api",
            idempotency_key=PUBLISH_KEY,
            correlation_id="issue362-v3-recovery-correlation-0001",
            expected_version=0,
        )
    reader = _Reader()
    runtime, repository, plans, gateway = _runtime(tmp_path, custody, reader)
    plan_before = _tree(plans.root)
    custody_before = _tree(custody.settings.root)
    execution_before = repository.snapshot()

    projection = runtime.recovery_projection(custody_idempotency_key=PUBLISH_KEY)

    assert projection["schema_version"] == (
        "web_bridge_execution_target_plan_recovery_v3"
    )
    assert projection["state"] == "CUSTODY_PUBLISHED_NOT_INSTALLED"
    assert projection["target_plan_schema_version"] == (
        KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    )
    assert projection["execution_run_id"] == _plan()["execution_run_id"]
    assert projection["creation_quote_proof_sha256"] == sha256_json(
        _plan()["creation_quote_proof"]
    )
    assert projection["install_only_allowed"] is True
    assert projection["recovery_action"] == "INSTALL_ONLY"
    assert "start_quote_proof_state" not in projection
    assert projection["recovery_sha256"] == sha256_json(
        {key: value for key, value in projection.items() if key != "recovery_sha256"}
    )
    assert _tree(plans.root) == plan_before
    assert _tree(custody.settings.root) == custody_before
    assert repository.snapshot() == execution_before
    assert reader.calls == []
    assert gateway.send_calls == []


def test_v3_installed_preview_ready_replan_and_source_states_are_zero_write(
    tmp_path: Path,
) -> None:
    custody, artifact, receipt = _publish_installed(tmp_path)
    plan = _plan()
    reader = _Reader()
    runtime, repository, plans, gateway = _runtime(tmp_path, custody, reader)

    custody_only = runtime.recovery_projection(custody_idempotency_key=PUBLISH_KEY)
    assert custody_only["state"] == "CUSTODY_PUBLISHED_NOT_PREVIEWED"
    assert custody_only["start_quote_proof_state"] == "NOT_INSTALLED"
    assert custody_only["start_quote_proof_sha256"] is None
    assert custody_only["can_start_same_plan"] is False

    runtime.preview_from_custody(str(receipt["receipt_id"]))
    installed = runtime.recovery_projection(custody_idempotency_key=PUBLISH_KEY)
    assert installed["state"] == "INSTALLED"
    assert installed["start_quote_proof_state"] == "NOT_STARTED"
    assert installed["can_start_same_plan"] is False
    assert reader.calls == []

    _preview_reconcile_enable(runtime, repository, receipt, artifact, plan)
    state_bytes = (tmp_path / "execution-state.json").read_bytes()
    plans_before = _tree(plans.root)
    custody_before = _tree(custody.settings.root)
    ready = runtime.recovery_projection(custody_idempotency_key=PUBLISH_KEY)
    assert ready["start_quote_proof_state"] == "READY"
    assert ready["start_quote_proof_sha256"] is not None
    assert ready["can_start_same_plan"] is True
    assert "creation_quote_proof" not in ready
    assert "bindings" not in ready
    assert (tmp_path / "execution-state.json").read_bytes() == state_bytes
    assert _tree(plans.root) == plans_before
    assert _tree(custody.settings.root) == custody_before
    assert gateway.send_calls == []

    reader.reference_price = 5001.0
    replan = runtime.recovery_projection(custody_idempotency_key=PUBLISH_KEY)
    assert replan["start_quote_proof_state"] == "REPLAN_REQUIRED"
    assert replan["start_quote_proof_sha256"] is None
    assert replan["can_start_same_plan"] is False
    assert (tmp_path / "execution-state.json").read_bytes() == state_bytes

    reader.reference_price = 5000.0
    reader.error = FormalTickSourceUnavailable("formal source unavailable")
    unavailable = runtime.recovery_projection(custody_idempotency_key=PUBLISH_KEY)
    assert unavailable["start_quote_proof_state"] == "SOURCE_UNAVAILABLE"
    assert unavailable["start_quote_proof_sha256"] is None
    assert unavailable["can_start_same_plan"] is False
    assert (tmp_path / "execution-state.json").read_bytes() == state_bytes


def test_v3_start_active_terminal_completion_and_restart_close_both_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    custody, artifact, receipt = _publish_installed(tmp_path)
    plan = _plan()
    reader = _Reader()
    runtime, repository, _plans, gateway = _runtime(tmp_path, custody, reader)
    runtime.preview_from_custody(str(receipt["receipt_id"]))
    _preview_reconcile_enable(runtime, repository, receipt, artifact, plan)

    accepted = _start(runtime, repository, plan)
    start_proof = accepted.result["execution_start_quote_proof"]
    reader.error = AssertionError("recovery of a started plan must not reread ticks")
    active = runtime.recovery_projection(custody_idempotency_key=PUBLISH_KEY)
    assert active["start_quote_proof_state"] == "STARTED_MATCHED"
    assert active["start_quote_proof_sha256"] == start_proof["proof_sha256"]
    assert active["can_start_same_plan"] is False

    archive = _complete(runtime, repository, gateway)
    assert archive["execution_run_id"] == plan["execution_run_id"]
    assert archive["creation_quote_proof_sha256"] == sha256_json(
        plan["creation_quote_proof"]
    )
    assert archive["start_quote_proof_sha256"] == start_proof["proof_sha256"]
    completion = runtime.completion_projection(plan_id=str(plan["plan_id"]))
    assert completion is not None
    assert completion["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    assert completion["execution_run_id"] == plan["execution_run_id"]
    assert (
        completion["creation_quote_proof_sha256"]
        == archive["creation_quote_proof_sha256"]
    )
    assert completion["start_quote_proof_sha256"] == archive["start_quote_proof_sha256"]
    assert "positions" not in completion
    assert "creation_quote_proof" not in completion

    restarted, restarted_repo, _restarted_plans, restarted_gateway = _runtime(
        tmp_path, custody, reader
    )
    assert restarted_repo.snapshot()["plan"]["state"] == "TERMINAL"
    assert restarted.completion_projection(plan_id=str(plan["plan_id"])) == completion
    assert restarted_gateway.send_calls == []

    app = create_app(restarted)

    async def read() -> tuple[dict[str, object], dict[str, object]]:
        client = ExecutionClient(
            ExecutionClientSettings(base_url="http://execution", shared_secret=SECRET),
            transport=httpx.ASGITransport(app=app),
        )
        completed = await client.completion(str(plan["plan_id"]))
        recovered = await client.target_plan_recovery(PUBLISH_KEY)
        assert completed is not None
        return completed.as_dict(), recovered.as_dict()

    client_completion, client_recovery = asyncio.run(read())
    assert client_completion == completion
    assert client_recovery["start_quote_proof_state"] == "STARTED_MATCHED"


@pytest.mark.parametrize(
    "field", ["creation_quote_proof_sha256", "start_quote_proof_sha256"]
)
def test_v3_completion_rejects_full_state_rehashed_archive_cross_splice(
    tmp_path: Path, field: str
) -> None:
    custody, artifact, receipt = _publish_installed(tmp_path)
    plan = _plan()
    reader = _Reader()
    runtime, repository, _plans, gateway = _runtime(tmp_path, custody, reader)
    runtime.preview_from_custody(str(receipt["receipt_id"]))
    _preview_reconcile_enable(runtime, repository, receipt, artifact, plan)
    _start(runtime, repository, plan)
    archive = _complete(runtime, repository, gateway)
    spliced = deepcopy(archive)
    spliced[field] = "f" * 64
    spliced["archived_at"] = "2030-01-01T00:01:00Z"
    repository.append_terminal_archive(spliced)

    with pytest.raises(PlanRejected, match="quote proof binding mismatches"):
        runtime.completion_projection(plan_id=str(plan["plan_id"]))


def test_client_rejects_foreign_v3_completion_on_exact_plan_lookup() -> None:
    plan = _plan()
    body = {
        "plan_id": "static-core-full-open-v3-foreign-completion",
        "plan_hash": plan["plan_hash"],
        "schema_version": KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        "phase": plan["phase"],
        "lineage": plan["lineage"],
        "expected_after_position_hash": plan["expected_after_position_hash"],
        "target_position_hash": plan["expected_after_position_hash"],
        "archived_at": "2030-01-01T00:01:00Z",
        "execution_run_id": plan["execution_run_id"],
        "creation_quote_proof_sha256": sha256_json(plan["creation_quote_proof"]),
        "start_quote_proof_sha256": "a" * 64,
    }

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ExecutionProtocolError, match="plan_id"):
        asyncio.run(client.completion(str(plan["plan_id"])))
