from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Event

import pytest
from app.execution import (
    GatewaySnapshot,
    InMemoryExecutionRepository,
    InMemoryGateway,
    VnpyWindowsGateway,
)
from app.execution.errors import SnapshotRejected
from app.execution.models import format_utc
from app.execution.orchestrator import ExecutionOrchestrator
from app.execution.readiness import GatewayReadinessProbe
from app.execution_orchestrator import create_app
from fastapi.testclient import TestClient


class DownGateway(InMemoryGateway):
    def snapshot(self) -> GatewaySnapshot:
        raise RuntimeError("proxy unavailable")


class SlowGateway(InMemoryGateway):
    def __init__(self, blocker: Event) -> None:
        super().__init__(account_scope="account:readiness", environment="simnow")
        self.blocker = blocker

    def snapshot(self) -> GatewaySnapshot:
        self.blocker.wait(1)
        return _snapshot()


def _ready_service(
    gateway: InMemoryGateway | VnpyWindowsGateway,
) -> ExecutionOrchestrator:
    repository = InMemoryExecutionRepository(scope="account:readiness")
    service = ExecutionOrchestrator(
        repository=repository,
        gateway=gateway,
        scope="account:readiness",
        environment=gateway.environment,
        test_mode=True,
    )

    def ready(state):
        state["lifecycle"] = "READY"
        state["reconciliation"]["state"] = "RECONCILED"

    repository.mutate(ready)
    return service


def _headers() -> dict[str, str]:
    return {
        "X-Control-Execution-Secret": "s" * 32,
        "X-Control-Service": "control-api",
    }


def _snapshot(**changes) -> GatewaySnapshot:
    values = {
        "snapshot_id": "snapshot-readiness",
        "generation": 1,
        "connected": True,
        "account_scope": "account:readiness",
        "environment": "simnow",
        "fresh": True,
    }
    values.update(changes)
    return GatewaySnapshot(**values)


@pytest.fixture(autouse=True)
def readiness_auth(monkeypatch):
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", "s" * 32)
    monkeypatch.setenv("EXECUTION_READINESS_TIMEOUT_SECONDS", "0.2")


def test_readiness_returns_503_when_gateway_is_down_without_mutation() -> None:
    gateway = DownGateway(account_scope="account:readiness", environment="simnow")
    service = _ready_service(gateway)
    before = service.repository.snapshot()
    with TestClient(create_app(service)) as client:
        response = client.get("/health/ready", headers=_headers())
    assert response.status_code == 503
    assert service.repository.snapshot() == before
    assert gateway.send_calls == [] and gateway.cancel_calls == []


def test_readiness_timeout_is_bounded_and_second_probe_fails_closed(
    monkeypatch,
) -> None:
    monkeypatch.setenv("EXECUTION_READINESS_TIMEOUT_SECONDS", "0.02")
    blocker = Event()
    gateway = SlowGateway(blocker)
    service = _ready_service(gateway)
    before = service.repository.snapshot()
    with TestClient(create_app(service)) as client:
        timed_out = client.get("/health/ready", headers=_headers())
        still_inflight = client.get("/health/ready", headers=_headers())
    blocker.set()
    assert timed_out.status_code == 503
    assert "timed out" in timed_out.json()["detail"]["reason"]
    assert still_inflight.status_code == 503
    assert "already in flight" in still_inflight.json()["detail"]["reason"]
    assert service.repository.snapshot() == before
    assert gateway.send_calls == [] and gateway.cancel_calls == []


@pytest.mark.parametrize(
    "snapshot",
    [
        _snapshot(
            observed_at=format_utc(datetime.now(timezone.utc) - timedelta(minutes=2))
        ),
        _snapshot(fresh=False),
        _snapshot(account_scope="account:foreign"),
        _snapshot(environment="other"),
    ],
)
def test_readiness_rejects_stale_or_cross_scope_snapshot(snapshot) -> None:
    gateway = InMemoryGateway(account_scope="account:readiness", environment="simnow")
    gateway.snapshots.append(snapshot)
    service = _ready_service(gateway)
    before_version = service.repository.state_version
    with TestClient(create_app(service)) as client:
        response = client.get("/health/ready", headers=_headers())
    assert response.status_code == 503
    assert service.repository.state_version == before_version
    assert gateway.send_calls == [] and gateway.cancel_calls == []


@pytest.mark.parametrize(
    ("delta", "accepted"),
    [
        (timedelta(seconds=2), True),
        (timedelta(seconds=2, microseconds=1), False),
        (timedelta(seconds=-60), True),
        (timedelta(seconds=-60, microseconds=-1), False),
    ],
)
def test_readiness_snapshot_clock_skew_and_staleness_boundaries(
    monkeypatch, delta: timedelta, accepted: bool
) -> None:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr("app.execution.readiness.utc_now", lambda: now)
    gateway = InMemoryGateway(account_scope="account:readiness", environment="simnow")
    snapshot = _snapshot(observed_at=format_utc(now + delta))
    service = _ready_service(gateway)
    probe = GatewayReadinessProbe(service, timeout_seconds=0.2)

    if accepted:
        assert probe._validate(snapshot) is snapshot
    else:
        with pytest.raises(SnapshotRejected, match="timestamp is stale"):
            probe._validate(snapshot)


def test_readiness_rejects_regressed_generation() -> None:
    gateway = InMemoryGateway(account_scope="account:readiness", environment="simnow")
    gateway.snapshots.append(_snapshot(generation=4))
    service = _ready_service(gateway)

    def advance(state):
        state["broker"]["generation"] = 5

    service.repository.mutate(advance)
    with TestClient(create_app(service)) as client:
        response = client.get("/health/ready", headers=_headers())
    assert response.status_code == 503


def test_final_validation_pure_readiness_ignores_durable_generation_floor() -> None:
    class PurePeekTransport:
        def __init__(self) -> None:
            self.calls = []

        def start(self):
            return None

        def stop(self):
            return None

        def call(self, method, payload, context=None):
            self.calls.append((method, payload, context))
            return {
                "schema_version": "windows_execution_current_facts_v1",
                "account": {"CTP.sim-account": {"gateway_name": "CTP"}},
                "positions": {},
                "active_orders": {},
                "gateway": {
                    "gateway_name": "CTP",
                    "account_scope": "account:readiness",
                    "environment": "simnow",
                    "connected": True,
                },
                "execution": {"orders": {}},
                "admission": {
                    "account_scope": "account:readiness",
                    "environment": "simnow",
                    "durable_state_version": 5,
                    "durable_state_hash": "a" * 64,
                    "snapshot_generation": 0,
                    "fence": {
                        "active": False,
                        "current_epoch": 0,
                        "current_fencing_token": 0,
                        "high_water_epoch": 0,
                        "high_water_fencing_token": 0,
                    },
                    "receipt_intents": [],
                },
            }

    transport = PurePeekTransport()
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:readiness",
        environment="SIMNOW",
        transport=transport,
        readonly_transport=transport,
        readiness_snapshot_source="final-validation-peek-current-facts-v1",
    )
    gateway.start()
    service = _ready_service(gateway)

    def advance(state):
        state["broker"]["generation"] = 5

    service.repository.mutate(advance)
    before = service.repository.snapshot()

    snapshot = GatewayReadinessProbe(service, timeout_seconds=0.2).probe()

    assert snapshot.generation == 0
    assert snapshot.environment == "SIMNOW"
    assert service.repository.snapshot() == before
    assert transport.calls == [
        (
            "peek_current_facts_v1",
            {"account_scope": "account:readiness", "environment": "simnow"},
            None,
        )
    ]


def test_readiness_healthy_probe_is_current_read_only_and_authenticated() -> None:
    gateway = InMemoryGateway(account_scope="account:readiness", environment="simnow")
    gateway.snapshots.append(_snapshot())
    service = _ready_service(gateway)
    before = service.repository.snapshot()
    with TestClient(create_app(service)) as client:
        forbidden = client.get(
            "/health/ready",
            headers={"X-Control-Execution-Secret": "s" * 32},
        )
        response = client.get("/health/ready", headers=_headers())
    assert forbidden.status_code == 403
    assert response.status_code == 200
    assert response.json()["gateway_snapshot_id"] == "snapshot-readiness"
    assert service.repository.snapshot() == before
    assert gateway.send_calls == [] and gateway.cancel_calls == []
