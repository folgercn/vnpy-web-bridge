from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientSettings,
    ExecutionProtocolError,
)
from app.execution_orchestrator import create_app
from app.schemas.control_execution import ExecutionReconciliationSnapshotProjection
from test_issue362_execution_control_facts_recovery import (
    EXECUTION_HEADERS,
    EXECUTION_SECRET,
    _active_orders,
    _fresh_snapshot,
    _orchestrator,
    _positions,
)

from app.execution import GatewaySnapshot
from app.execution.models import sha256_json


def test_reconciliation_snapshot_allows_active_unreconciled_and_is_zero_write(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    snapshot = _fresh_snapshot(with_active_order=True)
    service = _orchestrator(snapshot, reconciled=False)
    service.repository.mutate(
        lambda state: (
            state.update({"lifecycle": "HALTED_RECONCILE_REQUIRED"}),
            state["plan"].update(
                {
                    "state": "ACTIVE",
                    "plan_id": "issue362-active-plan-0001",
                    "plan_hash": "a" * 64,
                }
            ),
            state["reconciliation"].update(
                {
                    "state": "REQUIRED",
                    "unknown_outcomes": 0,
                }
            ),
        )
    )
    before = service.repository.snapshot()
    app = create_app(service)
    with TestClient(app) as client:
        assert client.get("/internal/v1/reconciliation-snapshot").status_code == 401
        response = client.get(
            "/internal/v1/reconciliation-snapshot", headers=EXECUTION_HEADERS
        )
    assert response.status_code == 200
    body = response.json()
    assert body["positions"] == _positions()
    assert body["active_orders"] == _active_orders()
    assert body["active_order_count"] == 1
    assert body["state_binding"] == {
        "state_version": before["state_version"],
        "durable_broker_generation": before["broker"]["generation"],
        "lifecycle": "HALTED_RECONCILE_REQUIRED",
        "reconciliation": before["reconciliation"],
    }
    assert body["reconciliation_snapshot_sha256"] == sha256_json(
        {
            key: value
            for key, value in body.items()
            if key != "reconciliation_snapshot_sha256"
        }
    )
    assert all(
        body[field] is False
        for field in (
            "production_allowed",
            "live_trading_authorized",
            "countable_forward",
            "official_forward_claimed",
        )
    )
    assert service.repository.snapshot() == before
    assert service.gateway.send_calls == []
    assert service.gateway.cancel_calls == []
    assert service.gateway.query_calls == []

    async def read_with_client() -> ExecutionReconciliationSnapshotProjection:
        execution = ExecutionClient(
            ExecutionClientSettings(
                base_url="http://execution", shared_secret=EXECUTION_SECRET
            ),
            transport=httpx.ASGITransport(app=app),
        )
        return await execution.reconciliation_snapshot()

    projection = asyncio.run(read_with_client())
    assert projection.as_dict() == body


def test_reconciliation_snapshot_dto_and_route_reject_cross_splice(monkeypatch) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    snapshot = _fresh_snapshot(with_active_order=True)
    service = _orchestrator(snapshot, reconciled=False)
    body = service.stable_reconciliation_snapshot_projection(lambda: snapshot)
    tampered = deepcopy(body)
    tampered["active_orders"] = {}
    try:
        ExecutionReconciliationSnapshotProjection.model_validate(tampered)
    except ValueError as exc:
        assert "facts do not close" in str(exc)
    else:  # pragma: no cover - explicit fail-closed assertion
        raise AssertionError("tampered rows were accepted")

    foreign = GatewaySnapshot(
        **{**snapshot.as_dict(), "account_scope": "account:foreign"}
    )
    service.gateway.snapshots.append(foreign)
    before = service.repository.snapshot()
    with TestClient(create_app(service)) as client:
        response = client.get(
            "/internal/v1/reconciliation-snapshot", headers=EXECUTION_HEADERS
        )
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "EXECUTION_RECONCILIATION_SNAPSHOT_UNAVAILABLE",
        "message": "gateway readiness account scope mismatch",
        "retryable": True,
    }
    assert service.repository.snapshot() == before


def test_reconciliation_snapshot_requires_canonical_service_and_client_fails_closed(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    snapshot = _fresh_snapshot()
    service = _orchestrator(snapshot, reconciled=False)
    app = create_app(service)
    foreign_headers = {
        **EXECUTION_HEADERS,
        "X-Control-Service": "foreign-control",
    }
    before = service.repository.snapshot()
    with TestClient(app) as client:
        response = client.get(
            "/internal/v1/reconciliation-snapshot", headers=foreign_headers
        )
    assert response.status_code == 403
    assert service.repository.snapshot() == before

    valid = service.stable_reconciliation_snapshot_projection(lambda: snapshot)
    malformed = deepcopy(valid)
    malformed["reconciliation_snapshot_sha256"] = "f" * 64

    async def read_malformed() -> None:
        async def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=malformed)

        execution = ExecutionClient(
            ExecutionClientSettings(base_url="http://execution"),
            transport=httpx.MockTransport(handler),
        )
        with pytest.raises(ExecutionProtocolError, match="snapshot"):
            await execution.reconciliation_snapshot()

    asyncio.run(read_malformed())
    assert service.repository.snapshot() == before


def test_reconciliation_snapshot_rejects_fully_rehashed_generation_cross_splice() -> (
    None
):
    snapshot = _fresh_snapshot(with_active_order=True)
    service = _orchestrator(snapshot, reconciled=False)
    earlier = service.stable_reconciliation_snapshot_projection(lambda: snapshot)

    later_snapshot = GatewaySnapshot(
        **{**snapshot.as_dict(), "generation": snapshot.generation + 1}
    )
    service.repository.mutate(
        lambda state: state["broker"].update({"generation": later_snapshot.generation})
    )
    later = service.stable_reconciliation_snapshot_projection(lambda: later_snapshot)
    spliced = deepcopy(earlier)
    spliced["state_binding"] = deepcopy(later["state_binding"])
    spliced["reconciliation_snapshot_sha256"] = sha256_json(
        {
            key: value
            for key, value in spliced.items()
            if key != "reconciliation_snapshot_sha256"
        }
    )
    with pytest.raises(ValueError, match="generation regressed"):
        ExecutionReconciliationSnapshotProjection.model_validate(spliced)


@pytest.mark.parametrize(
    "observed_at",
    ["2020-01-01T00:00:00Z", "2030-01-01T00:00:03Z"],
)
def test_reconciliation_snapshot_consumer_rejects_rehashed_stale_or_future_time(
    observed_at: str,
) -> None:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    snapshot = _fresh_snapshot()
    service = _orchestrator(snapshot, reconciled=False)
    body = service.stable_reconciliation_snapshot_projection(lambda: snapshot)
    tampered = deepcopy(body)
    tampered["observed_at"] = observed_at
    tampered["reconciliation_snapshot_sha256"] = sha256_json(
        {
            key: value
            for key, value in tampered.items()
            if key != "reconciliation_snapshot_sha256"
        }
    )
    with pytest.raises(ValueError, match="timestamp is stale"):
        ExecutionReconciliationSnapshotProjection.from_mapping(tampered, now=now)


def test_reconciliation_snapshot_route_rejects_durable_mutation_during_probe(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    snapshot = _fresh_snapshot()
    service = _orchestrator(snapshot, reconciled=False)
    before = service.repository.snapshot()

    def racing_probe() -> GatewaySnapshot:
        service.repository.mutate(
            lambda state: state["reconciliation"].update({"state": "IN_PROGRESS"})
        )
        return snapshot

    monkeypatch.setattr(service.gateway, "readiness_snapshot", racing_probe)
    with TestClient(create_app(service)) as client:
        response = client.get(
            "/internal/v1/reconciliation-snapshot", headers=EXECUTION_HEADERS
        )
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "EXECUTION_RECONCILIATION_SNAPSHOT_UNAVAILABLE",
        "message": "reconciliation snapshot durable state changed during probe",
        "retryable": True,
    }
    after = service.repository.snapshot()
    assert after["state_version"] == before["state_version"] + 1
    assert after["reconciliation"]["state"] == "IN_PROGRESS"
    assert service.gateway.send_calls == []
    assert service.gateway.cancel_calls == []
    assert service.gateway.query_calls == []
