from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from app.execution import InMemoryExecutionRepository, LeaderFencer
from app.execution.errors import ClockRollbackError, FencingError, LeaseNotHeldError
from fastapi.testclient import TestClient


def test_epoch_and_fencing_token_are_strictly_monotonic() -> None:
    repo = InMemoryExecutionRepository()
    first = LeaderFencer(repo, lease_seconds=1)
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    token1 = first.acquire("leader-0001", now=now)
    with pytest.raises(LeaseNotHeldError):
        LeaderFencer(repo).acquire("leader-0002", now=now)
    first.release(token1, now=now)
    token2 = LeaderFencer(repo, lease_seconds=1).acquire(
        "leader-0002", now=now + timedelta(seconds=1)
    )
    assert token2.epoch > token1.epoch
    assert token2.fencing_token > token1.fencing_token
    with pytest.raises(FencingError):
        first.validate(token1, now=now + timedelta(seconds=1))


def test_expiry_foreign_token_and_clock_rollback_fail_closed() -> None:
    repo = InMemoryExecutionRepository()
    fencer = LeaderFencer(repo, lease_seconds=1)
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    token = fencer.acquire("leader-0001", now=now)
    with pytest.raises(FencingError):
        fencer.validate(token, now=now + timedelta(seconds=2))
    with pytest.raises(ClockRollbackError):
        fencer.acquire("leader-0001", now=now - timedelta(seconds=1))


def test_same_owner_reacquire_gets_new_instance_and_http_leader_receipt_api(
    monkeypatch,
) -> None:
    from app.execution import ExecutionOrchestrator
    from app.execution_orchestrator import create_app

    monkeypatch.delenv("CONTROL_EXECUTION_SHARED_SECRET", raising=False)
    monkeypatch.delenv("CONTROL_EXECUTION_SECRET", raising=False)
    repository = InMemoryExecutionRepository()
    service = ExecutionOrchestrator(repository=repository)
    first = service.acquire_leader("leader-0001")
    service.release_leader(first)
    second = service.acquire_leader("leader-0001")
    assert second.epoch > first.epoch
    assert second.fencing_token > first.fencing_token
    assert second.instance_id and second.instance_id != first.instance_id

    headers = {
        "X-Control-Service": "control-api",
    }
    with TestClient(create_app(service)) as client:
        response = client.get("/internal/v1/leader", headers=headers)
        assert response.status_code == 200
        assert response.json()["epoch"] == second.epoch
        conflict = client.post(
            "/internal/v1/leader/acquire",
            headers=headers,
            json={"owner_id": "leader-0001"},
        )
        assert conflict.status_code == 409
