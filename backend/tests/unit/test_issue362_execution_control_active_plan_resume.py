from __future__ import annotations

import asyncio
from copy import deepcopy

import httpx
import pytest
from fastapi.testclient import TestClient

from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientSettings,
    ExecutionProtocolError,
    ExecutionUnknownOutcomeError,
)
from app.execution import GatewaySnapshot, PlanRejected
from app.execution.active_plan_resume import expected_send_intent_bindings
from app.execution.models import format_utc, sha256_json, utc_now
from app.execution_orchestrator import create_app
from shared.commodity_execution import TargetPlan, build_target_plan
from test_issue291_final_execution import (
    command,
    final_position_snapshot,
    plan,
    reconcile_enable_start,
    runtime,
    target_position_rows,
)
from test_issue362_execution_control_facts_recovery import (
    _custody as keyless_custody,
)
from test_issue362_execution_control_facts_recovery import (
    _runtime as keyless_runtime,
)


SECRET = "issue362-active-resume-secret"
HEADERS = {
    "X-Control-Execution-Secret": SECRET,
    "X-Control-Service": "control-api",
}


def _bound_snapshot(service) -> dict:
    core = service.orchestrator
    state = core.repository.snapshot()
    broker = state["broker"]
    snapshot = GatewaySnapshot(
        snapshot_id=f"snapshot-active-resume-{state['state_version']:04d}",
        generation=broker["generation"],
        connected=True,
        active_order_count=broker["active_order_count"],
        position_snapshot_hash=broker["position_snapshot_hash"],
        observed_at=format_utc(utc_now()),
        orders=broker["orders"],
        positions=broker["positions"],
        account_scope=core.scope,
        environment=core.environment,
    )
    return core.reconciliation_snapshot_projection(
        snapshot,
        expected_state_version=state["state_version"],
        expected_durable_broker_generation=broker["generation"],
    )


def _request(target: dict, token, snapshot: dict) -> dict:
    return {
        "schema_version": "web_bridge_execution_active_plan_resume_request_v1",
        "plan_id": target["plan_id"],
        "plan_hash": target["plan_hash"],
        "leader_token": token.as_dict(),
        "reconciliation_snapshot": snapshot,
    }


def _start_without_dispatch(service, core, repo, target: dict):
    target_receipt = service.custody.add_target(target)
    service.process_command(
        command(
            "preview",
            "preview-resume-0001",
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
            "reconcile-resume-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-resume-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh resume account facts",
            },
        )
    )
    service.process_command(
        command(
            "enable",
            "enable-resume-000001",
            repo.state_version,
            {
                "authority_artifact_id": target["authority_artifact_id"],
                "authority_hash": target["authority_artifact_sha256"],
                "expires_at": target["expires_at"],
                "reason": "verified resume authority",
            },
        )
    )
    token = core.acquire_leader("leader-resume-0001")
    response = core.process_command(
        command(
            "start",
            "start-resume-000001",
            repo.state_version,
            {
                "plan_id": target["plan_id"],
                "plan_hash": target["plan_hash"],
                "reason": "accepted resume target plan",
            },
            fence={
                "leader_epoch": token.epoch,
                "fencing_token": token.fencing_token,
            },
        )
    )
    assert response.result["accepted"] is True
    return token


def _two_order_plan() -> dict:
    first = plan()
    second = deepcopy(first["orders"][0])
    second["reference"] = "order-ref-resume-0002"
    source = {
        key: value
        for key, value in first.items()
        if key not in {"plan_hash", "order_set_sha256"}
    }
    source["orders"] = [first["orders"][0], second]
    return build_target_plan(**source)


def test_authenticated_endpoint_and_client_reuse_ack_without_order_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    token = reconcile_enable_start(service, core, repo, target)
    payload = _request(target, token, _bound_snapshot(service))
    before = repo.snapshot()
    send_count = len(gateway.send_calls)
    app = create_app(service)

    with TestClient(app) as client:
        assert (
            client.post("/internal/v1/active-plans/resume", json=payload).status_code
            == 401
        )
        response = client.post(
            "/internal/v1/active-plans/resume", json=payload, headers=HEADERS
        )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "ACTIVE"
    assert body["intents"][0]["resume_action"] == "REUSED"
    assert body["intents"][0]["state"] == "ACKNOWLEDGED"
    assert body["queried_intent_count"] == 0
    assert body["new_intent_count"] == 0
    assert all(
        forbidden not in str(body)
        for forbidden in ("symbol", "exchange", "direction", "price", "volume")
    )
    assert len(gateway.send_calls) == send_count
    assert gateway.query_calls == []
    assert repo.snapshot() == before

    async def call_client():
        client = ExecutionClient(
            ExecutionClientSettings(base_url="http://execution", shared_secret=SECRET),
            transport=httpx.ASGITransport(app=app),
        )
        return await client.resume_active_plan(
            plan_id=target["plan_id"],
            plan_hash=target["plan_hash"],
            leader_token=token.as_dict(),
            reconciliation_snapshot=payload["reconciliation_snapshot"],
        )

    assert asyncio.run(call_client()).as_dict() == body
    assert len(gateway.send_calls) == send_count

    foreign = deepcopy(body)
    foreign["plan_id"] = "foreign-active-resume-plan-0001"
    foreign["plan_hash"] = "f" * 64
    foreign["resume_sha256"] = sha256_json(
        {key: value for key, value in foreign.items() if key != "resume_sha256"}
    )

    async def call_foreign_projection():
        async def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=foreign)

        client = ExecutionClient(
            ExecutionClientSettings(base_url="http://execution"),
            transport=httpx.MockTransport(handler),
        )
        return await client.resume_active_plan(
            plan_id=target["plan_id"],
            plan_hash=target["plan_hash"],
            leader_token=token.as_dict(),
            reconciliation_snapshot=payload["reconciliation_snapshot"],
        )

    with pytest.raises(ExecutionProtocolError, match="未回绑"):
        asyncio.run(call_foreign_projection())


def test_terminal_intent_is_reused_without_query() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    token = reconcile_enable_start(service, core, repo, target)
    intent_id = next(iter(repo.snapshot()["send_intents"]))
    repo.mutate(
        lambda state: state["send_intents"][intent_id].update({"state": "TERMINAL"})
    )
    gateway.send_calls.clear()

    result = service.resume_active_plan(
        _request(target, token, _bound_snapshot(service))
    )

    assert result["state"] == "TERMINAL"
    assert result["intents"][0]["resume_action"] == "TERMINAL_REUSED"
    assert gateway.send_calls == []
    assert gateway.query_calls == []


@pytest.mark.parametrize("state", ["PERSISTED", "SUBMITTED", "UNKNOWN_OUTCOME"])
def test_existing_uncertain_intents_are_query_only(state: str) -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    token = reconcile_enable_start(service, core, repo, target)
    intent_id = next(iter(repo.snapshot()["send_intents"]))

    def mark(candidate: dict) -> None:
        candidate["send_intents"][intent_id]["state"] = state
        if state == "UNKNOWN_OUTCOME":
            candidate["unknown_outcomes"][intent_id] = {"reason": "response lost"}
            candidate["lifecycle"] = "HALTED_UNKNOWN_OUTCOME"
            candidate["reconciliation"].update(
                {"state": "UNKNOWN", "unknown_outcomes": 1}
            )

    repo.mutate(mark)
    gateway.intent_outcomes[intent_id] = {"state": "TERMINAL", "resolved": True}
    gateway.send_calls.clear()
    result = service.resume_active_plan(
        _request(target, token, _bound_snapshot(service))
    )

    assert result["state"] == "TERMINAL"
    assert result["intents"] == [
        {
            "intent_id": intent_id,
            "state": "RECONCILED",
            "resume_action": "QUERY_ONLY",
        }
    ]
    assert gateway.query_calls == [intent_id]
    assert gateway.send_calls == []


def test_missing_signed_intent_response_loss_exact_retry_never_resends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    token = _start_without_dispatch(service, core, repo, target)
    payload = _request(target, token, _bound_snapshot(service))

    def response_lost(request, context):
        gateway.send_calls.append((dict(request), context))
        gateway.intent_outcomes[context.intent_id] = {
            "accepted": True,
            "state": "ACKNOWLEDGED",
            "intent_id": context.intent_id,
            "broker_order_id": "order-response-lost-0001",
        }
        raise TimeoutError("response lost after remote acceptance")

    gateway.send_order = response_lost
    app = create_app(service)
    execution_client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution", shared_secret=SECRET),
        transport=httpx.ASGITransport(app=app),
    )

    async def resume():
        return await execution_client.resume_active_plan(
            plan_id=target["plan_id"],
            plan_hash=target["plan_hash"],
            leader_token=token.as_dict(),
            reconciliation_snapshot=payload["reconciliation_snapshot"],
        )

    with pytest.raises(ExecutionUnknownOutcomeError) as caught:
        asyncio.run(resume())
    assert caught.value.detail == {
        "code": "EXECUTION_ACTIVE_PLAN_RESUME_OUTCOME_UNKNOWN",
        "message": "gateway send outcome unknown",
        "retryable": True,
        "plan_id": target["plan_id"],
        "plan_hash": target["plan_hash"],
        "retry_exact_resume_only": True,
    }
    assert repo.snapshot()["send_intents"]
    assert repo.snapshot()["unknown_outcomes"]

    second = asyncio.run(resume())
    assert second.value["new_intent_count"] == 0
    assert second.value["queried_intent_count"] == 1
    assert second.value["state"] == "TERMINAL"
    assert len(gateway.send_calls) == 1
    assert len(gateway.query_calls) == 1

    stale_fence = deepcopy(payload)
    stale_fence["leader_token"]["fencing_token"] += 1
    with TestClient(app) as wire_client:
        rejected = wire_client.post(
            "/internal/v1/active-plans/resume", json=stale_fence, headers=HEADERS
        )
    assert rejected.status_code == 409
    assert len(gateway.send_calls) == 1


def test_foreign_active_order_and_fully_rehashed_future_snapshot_are_zero_send() -> (
    None
):
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    token = reconcile_enable_start(service, core, repo, target)
    gateway.send_calls.clear()
    state = repo.snapshot()
    broker = state["broker"]
    foreign = GatewaySnapshot(
        snapshot_id="snapshot-active-resume-foreign-0001",
        generation=broker["generation"],
        connected=True,
        active_order_count=1,
        position_snapshot_hash=broker["position_snapshot_hash"],
        observed_at=format_utc(utc_now()),
        orders={"foreign-order": {"intent_id": "foreign-intent-0001"}},
        positions=broker["positions"],
        account_scope=core.scope,
        environment=core.environment,
    )
    foreign_projection = core.reconciliation_snapshot_projection(
        foreign,
        expected_state_version=state["state_version"],
        expected_durable_broker_generation=broker["generation"],
    )
    with pytest.raises(PlanRejected, match="foreign active order"):
        service.resume_active_plan(_request(target, token, foreign_projection))

    future = _bound_snapshot(service)
    future["state_binding"]["state_version"] += 1
    future["reconciliation_snapshot_sha256"] = sha256_json(
        {
            key: value
            for key, value in future.items()
            if key != "reconciliation_snapshot_sha256"
        }
    )
    with pytest.raises(PlanRejected, match="does not bind current"):
        service.resume_active_plan(_request(target, token, future))
    assert gateway.send_calls == []
    assert gateway.query_calls == []


def test_v2_missing_intent_fails_closed_without_quote_proof(tmp_path) -> None:
    custody, receipt = keyless_custody(tmp_path)
    service, _plans = keyless_runtime(tmp_path, custody)
    service.allow_simnow_execution = True
    target_plan = service.preview_from_custody(str(receipt["receipt_id"]))
    target = target_plan.as_dict()
    core = service.orchestrator
    repo = core.repository
    service.process_command(
        command(
            "preview",
            "preview-keyless-resume-0001",
            repo.state_version,
            {
                "plan_hash": target["plan_hash"],
                "artifact_hash": receipt["artifact_sha256"],
                "mode": "simnow_preview",
                "receipt_id": receipt["receipt_id"],
            },
        )
    )
    service.process_command(
        command(
            "reconcile",
            "reconcile-keyless-resume-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-keyless-resume-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh keyless resume facts",
            },
        )
    )
    service.process_command(
        command(
            "enable",
            "enable-keyless-resume-0001",
            repo.state_version,
            {
                "authority_artifact_id": target["plan_id"],
                "authority_hash": target["plan_hash"],
                "expires_at": target["expires_at"],
                "reason": "verified keyless plan authority",
            },
        )
    )
    token = core.acquire_leader("leader-keyless-resume-0001")
    response = core.process_command(
        command(
            "start",
            "start-keyless-resume-0001",
            repo.state_version,
            {
                "plan_id": target["plan_id"],
                "plan_hash": target["plan_hash"],
                "reason": "accepted keyless resume plan",
            },
            fence={
                "leader_epoch": token.epoch,
                "fencing_token": token.fencing_token,
            },
        )
    )
    assert response.result["accepted"] is True

    with pytest.raises(PlanRejected, match="no formal quote proof"):
        service.resume_active_plan(_request(target, token, _bound_snapshot(service)))
    gateway = core.gateway
    assert gateway.send_calls == []
    assert gateway.query_calls == []


def test_finalization_requires_complete_deterministic_expected_intent_set() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = _two_order_plan()
    token = _start_without_dispatch(service, core, repo, target)
    first = service.send_plan_order(
        target["plan_id"], target["orders"][0]["reference"], token=token
    )
    repo.mutate(
        lambda state: state["send_intents"][first["intent_id"]].update(
            {"state": "TERMINAL"}
        )
    )
    gateway.snapshots.append(
        final_position_snapshot(target_position_rows(), generation=2)
    )

    pending = service.process_command(
        command(
            "reconcile",
            "reconcile-resume-incomplete-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-resume-incomplete-0001",
                "snapshot_id": "snapshot-final-0002",
                "reason": "incomplete deterministic intent set",
            },
        )
    )
    assert pending.result["finalization"] == {"state": "PENDING"}
    assert repo.snapshot()["plan"]["state"] == "ACTIVE"

    second = service.send_plan_order(
        target["plan_id"], target["orders"][1]["reference"], token=token
    )
    repo.mutate(
        lambda state: state["send_intents"][second["intent_id"]].update(
            {"state": "TERMINAL"}
        )
    )
    gateway.snapshots.append(
        final_position_snapshot(target_position_rows(), generation=3)
    )
    complete = service.process_command(
        command(
            "reconcile",
            "reconcile-resume-complete-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-resume-complete-0001",
                "snapshot_id": "snapshot-final-0003",
                "reason": "complete deterministic intent set",
            },
        )
    )
    assert complete.result["finalization"]["state"] == "COMPLETED"
    assert repo.snapshot()["plan"]["state"] == "TERMINAL"


def test_finalization_rejects_same_intent_identity_with_wrong_order_payload() -> None:
    service, core, repo, gateway, _ = runtime(execute=True)
    target = plan()
    token = _start_without_dispatch(service, core, repo, target)
    binding = expected_send_intent_bindings(
        TargetPlan.from_mapping(target),
        account_scope=core.scope,
        environment=core.environment,
    )[0]
    wrong_order = deepcopy(target["orders"][0])
    wrong_order["price"] = 2.0
    result = core.submit_planned_order(
        wrong_order,
        idempotency_key=binding["idempotency_key"],
        plan_id=target["plan_id"],
        plan_hash=target["plan_hash"],
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
        intent_id=binding["intent_id"],
    )
    repo.mutate(
        lambda state: state["send_intents"][result["intent_id"]].update(
            {"state": "TERMINAL"}
        )
    )
    gateway.snapshots.append(
        final_position_snapshot(target_position_rows(), generation=2)
    )
    snapshot_calls: list[bool] = []
    readiness_snapshot = gateway.readiness_snapshot

    def counted_snapshot():
        snapshot_calls.append(True)
        return readiness_snapshot()

    gateway.readiness_snapshot = counted_snapshot
    send_count = len(gateway.send_calls)

    with pytest.raises(PlanRejected, match="send-intent binding mismatches"):
        service.process_command(
            command(
                "reconcile",
                "reconcile-resume-wrong-payload-0001",
                repo.state_version,
                {
                    "reconciliation_run_id": "run-resume-wrong-payload-0001",
                    "snapshot_id": "snapshot-final-0002",
                    "reason": "reject wrong frozen order payload",
                },
            )
        )

    assert snapshot_calls == []
    assert len(gateway.send_calls) == send_count
    assert gateway.query_calls == []
    assert repo.snapshot()["plan"]["state"] == "ACTIVE"
