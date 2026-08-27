from __future__ import annotations

import pytest
from app.execution import (
    ExecutionOrchestrator,
    GatewaySnapshot,
    InMemoryExecutionRepository,
    InMemoryGateway,
)
from app.execution.errors import SnapshotRejected
from app.execution.models import sha256_json

from scripts.windows_fence_foundation.final_admission_v1 import (
    WindowsRpcFencedAdmissionV1,
)


def _snapshot(
    *,
    epoch: int | None = None,
    token: int | None = None,
) -> GatewaySnapshot:
    return GatewaySnapshot(
        snapshot_id="snapshot-fence-high-water-0001",
        generation=0,
        connected=True,
        position_snapshot_hash=sha256_json({}),
        account_scope="account:prod",
        environment="simnow",
        fence_high_water_epoch=epoch,
        fence_high_water_fencing_token=token,
    )


def _reconcile_command(service: ExecutionOrchestrator) -> dict:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": "command-fence-reconcile-0001",
        "idempotency_key": "fence-reconcile-0001",
        "correlation_id": "fence-reconcile-correlation-0001",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "tester",
            "operator": "tester",
            "role": "admin",
        },
        "command": "reconcile",
        "expected": {"state_version": service.repository.state_version},
        "payload": {
            "reconciliation_run_id": "run-fence-high-water-0001",
            "snapshot_id": "snapshot-fence-high-water-0001",
            "reason": "recover verified Windows fence high-water",
        },
    }


def _service(
    *, epoch: int | None = None, token: int | None = None
) -> tuple[ExecutionOrchestrator, InMemoryExecutionRepository]:
    repository = InMemoryExecutionRepository(scope="account:prod")
    gateway = InMemoryGateway(account_scope="account:prod", environment="simnow")
    gateway.snapshots.append(_snapshot(epoch=epoch, token=token))
    return (
        ExecutionOrchestrator(
            repository,
            gateway,
            scope="account:prod",
            environment="simnow",
            test_mode=True,
        ),
        repository,
    )


def _set_lease_floor(
    repository: InMemoryExecutionRepository, *, epoch: int, token: int
) -> None:
    repository.mutate(
        lambda state: state["lease"].update(
            {"epoch": epoch, "fencing_token": token}
        )
    )


def test_reconcile_advances_idle_lease_floor_then_next_acquire_is_strictly_newer(
) -> None:
    service, repository = _service(epoch=49, token=49)

    service.process_command(_reconcile_command(service))

    lease = repository.snapshot()["lease"]
    assert (lease["epoch"], lease["fencing_token"]) == (49, 49)
    next_token = service.acquire_leader("leader-0001")
    assert (next_token.epoch, next_token.fencing_token) == (50, 50)
    admission = WindowsRpcFencedAdmissionV1(
        account_scope="account:prod",
        environment="simnow",
        current_epoch=49,
        current_fencing_token=49,
        send_handler=lambda _request, _context: {},
        cancel_handler=lambda _request, _context: {},
    )
    accepted = admission.install_fence(
        epoch=next_token.epoch,
        fencing_token=next_token.fencing_token,
    )
    assert accepted["high_water_epoch"] == 50
    assert accepted["high_water_fencing_token"] == 50


def test_reconcile_never_regresses_higher_local_fence_floor() -> None:
    service, repository = _service(epoch=49, token=49)
    _set_lease_floor(repository, epoch=60, token=60)

    service.process_command(_reconcile_command(service))

    lease = repository.snapshot()["lease"]
    assert (lease["epoch"], lease["fencing_token"]) == (60, 60)


def test_reconcile_floors_epoch_and_token_independently() -> None:
    service, repository = _service(epoch=49, token=52)
    _set_lease_floor(repository, epoch=34, token=40)

    service.process_command(_reconcile_command(service))

    lease = repository.snapshot()["lease"]
    assert (lease["epoch"], lease["fencing_token"]) == (49, 52)
    next_token = service.acquire_leader("leader-0001")
    assert (next_token.epoch, next_token.fencing_token) == (50, 53)


def test_reconcile_rejects_remote_floor_above_live_local_leader() -> None:
    service, repository = _service(epoch=49, token=49)
    service.acquire_leader("leader-0001")

    with pytest.raises(SnapshotRejected, match="conflicts with a live local leader"):
        service.process_command(_reconcile_command(service))

    lease = repository.snapshot()["lease"]
    assert (lease["epoch"], lease["fencing_token"]) == (1, 1)
    assert repository.snapshot()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"


def test_non_final_snapshot_without_remote_fence_high_water_is_unchanged() -> None:
    service, repository = _service()

    service.process_command(_reconcile_command(service))

    lease = repository.snapshot()["lease"]
    assert (lease["epoch"], lease["fencing_token"]) == (0, 0)


@pytest.mark.parametrize(
    ("epoch", "token"),
    [(49, None), (None, 49)],
    ids=["missing-token", "missing-epoch"],
)
def test_partial_remote_fence_high_water_fails_closed(
    epoch: int | None, token: int | None
) -> None:
    service, repository = _service(epoch=epoch, token=token)

    with pytest.raises(SnapshotRejected, match="remote fence high-water is invalid"):
        service.process_command(_reconcile_command(service))

    assert repository.snapshot()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"
