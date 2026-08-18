from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from app.execution import InMemoryExecutionRepository, LeaderFencer
from app.execution.errors import (
    ClockRollbackError,
    FencingError,
    LeaseNotHeldError,
    RepositoryUnavailableError,
)
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


def test_planned_dispatch_snapshot_allows_only_forward_same_lease_renew() -> None:
    repo = InMemoryExecutionRepository()
    fencer = LeaderFencer(repo, lease_seconds=2)
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    snapshot = fencer.acquire("leader-0001", now=now)
    renewed = fencer.renew(snapshot, now=now + timedelta(seconds=1))

    accepted = LeaderFencer(repo).planned_dispatch_admission(
        leader_epoch=snapshot.epoch,
        fencing_token=snapshot.fencing_token,
        token=snapshot,
        now=now + timedelta(seconds=2, milliseconds=500),
    )
    assert accepted == snapshot
    with pytest.raises(FencingError, match="expiry mismatch"):
        fencer.renew(snapshot, now=now + timedelta(seconds=1, milliseconds=500))
    with pytest.raises(FencingError, match="expiry mismatch"):
        fencer.release(snapshot, now=now + timedelta(seconds=1, milliseconds=500))
    with pytest.raises(FencingError, match="newer than durable"):
        fencer.planned_dispatch_admission(
            leader_epoch=renewed.epoch,
            fencing_token=renewed.fencing_token,
            token=replace(
                renewed,
                lease_expires_at="2030-01-01T00:00:04Z",
            ),
            now=now + timedelta(seconds=2, milliseconds=500),
        )


def test_planned_dispatch_snapshot_rejects_failed_renew_release_and_successor() -> None:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)

    failed_repo = InMemoryExecutionRepository()
    failed = LeaderFencer(failed_repo, lease_seconds=1)
    expired = failed.acquire("leader-0001", now=now)
    failed_repo.set_available(False)
    with pytest.raises(RepositoryUnavailableError):
        failed.renew(expired, now=now + timedelta(milliseconds=500))
    failed_repo.set_available(True)
    with pytest.raises(FencingError, match="expired"):
        LeaderFencer(failed_repo).planned_dispatch_admission(
            leader_epoch=expired.epoch,
            fencing_token=expired.fencing_token,
            token=expired,
            now=now + timedelta(seconds=2),
        )

    released_repo = InMemoryExecutionRepository()
    released_fencer = LeaderFencer(released_repo, lease_seconds=3)
    released = released_fencer.acquire("leader-0001", now=now)
    released_fencer.release(released, now=now + timedelta(seconds=1))
    with pytest.raises(FencingError, match="stale or foreign"):
        LeaderFencer(released_repo).planned_dispatch_admission(
            leader_epoch=released.epoch,
            fencing_token=released.fencing_token,
            token=released,
            now=now + timedelta(seconds=1),
        )

    successor_repo = InMemoryExecutionRepository()
    former = LeaderFencer(successor_repo, lease_seconds=1).acquire(
        "leader-0001", now=now
    )
    successor = LeaderFencer(successor_repo, lease_seconds=3).acquire(
        "leader-0002", now=now + timedelta(seconds=2)
    )
    restarted = LeaderFencer(successor_repo)
    with pytest.raises(FencingError, match="stale or foreign"):
        restarted.planned_dispatch_admission(
            leader_epoch=former.epoch,
            fencing_token=former.fencing_token,
            token=former,
            now=now + timedelta(seconds=2),
        )
    for stale in (
        replace(successor, owner_id="leader-0001"),
        replace(successor, fencing_token=successor.fencing_token - 1),
        replace(successor, instance_id=former.instance_id),
    ):
        with pytest.raises(FencingError, match="stale or foreign"):
            restarted.planned_dispatch_admission(
                leader_epoch=stale.epoch,
                fencing_token=stale.fencing_token,
                token=stale,
                now=now + timedelta(seconds=2),
            )


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
