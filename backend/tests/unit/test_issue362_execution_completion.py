from __future__ import annotations

import asyncio
from copy import deepcopy

import httpx
import pytest
from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientSettings,
    ExecutionProtocolError,
    ExecutionRejectedError,
)
from app.execution import (
    DurableExecutionRepository,
    DurableTargetPlanRepository,
    ExecutionOrchestrator,
    InMemoryExecutionRepository,
    InMemoryGateway,
    InMemoryTargetPlanRepository,
    PlanRejected,
)
from app.execution.final_runtime import FinalExecutionRuntime
from app.execution_orchestrator import create_app
from fastapi.testclient import TestClient
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    TargetPlan,
    before_position_projection_hash,
    build_trusted_keyless_target_plan,
    build_trusted_keyless_target_plan_v2,
    sha256_json,
    target_position_projection_hash,
)


SCOPE = "account:windows"
ENVIRONMENT = "SIMNOW"


def _positions() -> dict[str, dict[str, object]]:
    return {
        "rb2601.SHFE.LONG.CTP.test": {
            "gateway_name": "CTP",
            "symbol": "rb2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 1,
        }
    }


def _v2_plan(
    plan_id: str = "static-core-full-open-v2-completion-test",
) -> TargetPlan:
    positions = _positions()
    raw = build_trusted_keyless_target_plan_v2(
        plan_id=plan_id,
        account_scope=SCOPE,
        environment=ENVIRONMENT,
        gateway_name="CTP",
        lineage={
            "static_core_equal_sha256": "a" * 64,
            "position_manager_sha256": "b" * 64,
            "final_target_sha256": "c" * 64,
        },
        scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
        generated_at="2026-08-18T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        phase="OPEN",
        expected_before_position_hash=before_position_projection_hash(
            {}, account_scope=SCOPE, environment=ENVIRONMENT
        ),
        expected_after_position_hash=target_position_projection_hash(
            positions, account_scope=SCOPE, environment=ENVIRONMENT
        ),
        orders=[
            {
                "symbol": "rb2601",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 3500.0,
                "offset": "OPEN",
                "reference": "completion-open-order-0001",
                "gateway_name": "CTP",
            }
        ],
    )
    return TargetPlan.from_mapping(raw)


def _v1_plan() -> TargetPlan:
    positions = _positions()
    raw = build_trusted_keyless_target_plan(
        plan_id="c-fast-open-v1-completion-test",
        account_scope=SCOPE,
        environment=ENVIRONMENT,
        gateway_name="CTP",
        lineage={"map_sha256": "a" * 64, "c_fast_sha256": "b" * 64},
        scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
        generated_at="2026-08-18T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        phase="OPEN",
        expected_before_position_hash=before_position_projection_hash(
            {}, account_scope=SCOPE, environment=ENVIRONMENT
        ),
        expected_after_position_hash=target_position_projection_hash(
            positions, account_scope=SCOPE, environment=ENVIRONMENT
        ),
        orders=[
            {
                "symbol": "rb2601",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 3500.0,
                "offset": "OPEN",
                "reference": "completion-open-order-v1-0001",
                "gateway_name": "CTP",
            }
        ],
    )
    return TargetPlan.from_mapping(raw)


def _runtime() -> tuple[
    FinalExecutionRuntime,
    InMemoryExecutionRepository,
    InMemoryTargetPlanRepository,
]:
    repository = InMemoryExecutionRepository(scope=SCOPE)
    orchestrator = ExecutionOrchestrator(
        repository=repository,
        gateway=InMemoryGateway(account_scope=SCOPE, environment=ENVIRONMENT),
        scope=SCOPE,
        environment=ENVIRONMENT,
        test_mode=True,
    )
    plans = InMemoryTargetPlanRepository()
    return (
        FinalExecutionRuntime(
            orchestrator,
            plans=plans,
            custody_receipt=lambda _: None,
        ),
        repository,
        plans,
    )


def _append_completion(
    repository: InMemoryExecutionRepository,
    plan: TargetPlan,
    *,
    plan_hash: str | None = None,
    target_position_hash: str | None = None,
    positions: dict[str, dict[str, object]] | None = None,
) -> None:
    archived_positions = _positions() if positions is None else positions
    repository.append_terminal_archive(
        {
            "kind": "final_plan_completed",
            "plan_id": plan.plan_id,
            "plan_hash": plan_hash or plan.plan_hash,
            "plan_version": 2,
            "receipt_id": "completion-receipt-0001",
            "final_position_hash": sha256_json(archived_positions),
            "target_position_hash": target_position_hash
            or plan.raw["expected_after_position_hash"],
            "positions": archived_positions,
            "archived_at": "2026-08-18T00:01:00Z",
        }
    )


def test_latest_completion_is_empty_and_read_only() -> None:
    runtime, repository, _ = _runtime()
    before = repository.snapshot()

    assert runtime.latest_completion_projection() is None
    assert repository.snapshot() == before


def test_latest_completion_projects_only_v2_identity() -> None:
    runtime, repository, plans = _runtime()
    plan = _v2_plan()
    plans.put(plan)
    _append_completion(repository, plan)
    repository.append_terminal_archive(
        {
            "kind": "plan_terminal",
            "plan_id": "later-non-completion-plan",
            "plan_hash": "d" * 64,
            "plan_version": 3,
            "archived_at": "2026-08-18T00:02:00Z",
        }
    )

    projection = runtime.latest_completion_projection()

    assert projection == {
        "plan_id": plan.plan_id,
        "plan_hash": plan.plan_hash,
        "schema_version": KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        "phase": "OPEN",
        "lineage": {
            "static_core_equal_sha256": "a" * 64,
            "position_manager_sha256": "b" * 64,
            "final_target_sha256": "c" * 64,
        },
        "expected_after_position_hash": plan.raw["expected_after_position_hash"],
        "target_position_hash": plan.raw["expected_after_position_hash"],
        "archived_at": "2026-08-18T00:01:00Z",
    }
    assert "positions" not in projection
    assert "receipt_id" not in projection


@pytest.mark.parametrize(
    ("install", "plan_hash", "target_position_hash", "message"),
    [
        (False, None, None, "not installed"),
        (True, "d" * 64, None, "plan hash mismatches"),
        (True, None, "e" * 64, "position hash mismatches"),
    ],
)
def test_latest_completion_fails_closed_on_missing_or_tampered_binding(
    install: bool,
    plan_hash: str | None,
    target_position_hash: str | None,
    message: str,
) -> None:
    runtime, repository, plans = _runtime()
    plan = _v2_plan()
    if install:
        plans.put(plan)
    _append_completion(
        repository,
        plan,
        plan_hash=plan_hash,
        target_position_hash=target_position_hash,
    )

    with pytest.raises(PlanRejected, match=message):
        runtime.latest_completion_projection()


def test_latest_completion_recomputes_archived_target_semantics() -> None:
    runtime, repository, plans = _runtime()
    plan = _v2_plan()
    plans.put(plan)
    _append_completion(
        repository,
        plan,
        positions={
            "cu2601.SHFE.LONG.CTP.splice": {
                "gateway_name": "CTP",
                "symbol": "cu2601",
                "exchange": "SHFE",
                "direction": "LONG",
                "volume": 1,
            }
        },
    )

    with pytest.raises(PlanRejected, match="archived positions"):
        runtime.latest_completion_projection()


def test_exact_completion_lookup_survives_newer_unrelated_completion() -> None:
    runtime, repository, plans = _runtime()
    first = _v2_plan("static-core-full-open-v2-completion-first")
    second = _v2_plan("static-core-full-open-v2-completion-second")
    plans.put(first)
    plans.put(second)
    _append_completion(repository, first)
    _append_completion(repository, second)

    assert runtime.latest_completion_projection()["plan_id"] == second.plan_id
    assert runtime.completion_projection(plan_id=first.plan_id)["plan_id"] == (
        first.plan_id
    )
    assert runtime.completion_projection(plan_id="missing-completion-plan") is None


def test_completion_projection_survives_durable_restart(tmp_path) -> None:
    state_path = tmp_path / "execution-state.json"
    plan_root = tmp_path / "plans"
    repository = DurableExecutionRepository(state_path, scope=SCOPE)
    plans = DurableTargetPlanRepository(plan_root)
    plan = _v2_plan()
    plans.put(plan)
    _append_completion(repository, plan)

    restarted_repository = DurableExecutionRepository(state_path, scope=SCOPE)
    restarted_plans = DurableTargetPlanRepository(plan_root)
    restarted_runtime = FinalExecutionRuntime(
        ExecutionOrchestrator(
            repository=restarted_repository,
            gateway=InMemoryGateway(account_scope=SCOPE, environment=ENVIRONMENT),
            scope=SCOPE,
            environment=ENVIRONMENT,
            test_mode=True,
        ),
        plans=restarted_plans,
        custody_receipt=lambda _: None,
    )

    assert (
        restarted_runtime.completion_projection(plan_id=plan.plan_id)["plan_hash"]
        == plan.plan_hash
    )


def test_latest_completion_explicitly_fails_closed_for_historical_v1() -> None:
    runtime, repository, plans = _runtime()
    plan = _v1_plan()
    plans.put(plan)
    _append_completion(repository, plan)

    with pytest.raises(PlanRejected, match="not v2"):
        runtime.latest_completion_projection()


def test_latest_completion_http_is_authenticated_and_client_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, repository, plans = _runtime()
    plan = _v2_plan()
    plans.put(plan)
    _append_completion(repository, plan)
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", "s" * 32)
    app = create_app(runtime)
    headers = {
        "X-Control-Execution-Secret": "s" * 32,
        "X-Control-Service": "control-api",
    }
    with TestClient(app) as client:
        assert client.get("/internal/v1/completions/latest").status_code == 401
        response = client.get("/internal/v1/completions/latest", headers=headers)
    assert response.status_code == 200
    assert response.json()["plan_id"] == plan.plan_id

    async def read_with_client() -> dict[str, object]:
        execution = ExecutionClient(
            ExecutionClientSettings(
                base_url="http://execution",
                shared_secret="s" * 32,
            ),
            transport=httpx.ASGITransport(app=app),
        )
        projection = await execution.latest_completion()
        assert projection is not None
        exact = await execution.completion(plan.plan_id)
        assert exact is not None
        assert exact.plan_id == plan.plan_id
        return projection.as_dict()

    assert asyncio.run(read_with_client())["plan_hash"] == plan.plan_hash


def test_execution_client_rejects_completion_projection_with_extra_state() -> None:
    runtime, repository, plans = _runtime()
    plan = _v2_plan()
    plans.put(plan)
    _append_completion(repository, plan)
    body = runtime.latest_completion_projection()
    assert body is not None
    tampered = deepcopy(body)
    tampered["positions"] = _positions()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=tampered)

    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ExecutionProtocolError, match="completion projection"):
        asyncio.run(client.latest_completion())


def test_execution_client_rejects_non_json_completion_response() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not-json")

    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ExecutionProtocolError, match="非 JSON"):
        asyncio.run(client.latest_completion())


def test_completion_http_codes_distinguish_invalid_from_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, repository, _plans = _runtime()
    plan = _v2_plan()
    _append_completion(repository, plan)
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", "s" * 32)
    app = create_app(runtime)
    client = ExecutionClient(
        ExecutionClientSettings(
            base_url="http://execution",
            shared_secret="s" * 32,
        ),
        transport=httpx.ASGITransport(app=app),
    )

    with pytest.raises(ExecutionRejectedError) as invalid:
        asyncio.run(client.latest_completion())
    assert invalid.value.detail == {
        "code": "EXECUTION_COMPLETION_INVALID",
        "message": "latest completed target plan is not installed",
        "retryable": False,
    }

    repository.available = False
    with pytest.raises(ExecutionRejectedError) as unavailable:
        asyncio.run(client.latest_completion())
    assert unavailable.value.detail == {
        "code": "EXECUTION_COMPLETION_REPOSITORY_UNAVAILABLE",
        "message": "durable execution repository unavailable",
        "retryable": True,
    }
