"""Cross-process, loopback-only fault runner for Phase C evidence.

This module intentionally has no dependency on a deployed RPC client.  It
uses POSIX child processes, OS signals and a loopback TCP stand-in to make the
failure boundary observable while exercising the real Phase A durable state
machine.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import signal
import socket
import struct
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Self

from app.execution import DurableExecutionRepository, ExecutionOrchestrator, NullGateway
from app.execution.errors import GatewayTimeout
from app.execution.fencing import LeaderFencer
from app.execution.gateway import GatewaySnapshot, MutationContext
from app.execution.models import SendIntent, sha256_json

HASH = "b" * 64
SCOPE = "account:phase-c-process"
ENVIRONMENT = "simnow"


def _emit(path: str, event_type: str, payload: Mapping[str, Any]) -> None:
    record = {
        "event_type": event_type,
        "observed_at_ns": time.time_ns(),
        "pid": os.getpid(),
        "payload": dict(payload),
    }
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def _events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _wait_event(path: Path, event_type: str, timeout: float = 3.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = [
            event for event in _events(path) if event["event_type"] == event_type
        ]
        if matches:
            return matches[-1]
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {event_type}")


def _leader_worker(state_path: str, event_path: str, owner: str, hold: bool) -> None:
    repo = DurableExecutionRepository(state_path, scope=SCOPE)
    token = LeaderFencer(repo, scope=SCOPE, lease_seconds=0.10).acquire(owner)
    _emit(event_path, "leader_acquired", {"owner": owner, **token.as_dict()})
    if hold:
        while True:
            time.sleep(1)


def _gateway_worker(event_path: str, mode: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])
        _emit(event_path, "loopback_gateway_ready", {"port": port, "mode": mode})
        connection, _address = listener.accept()
        with connection:
            request = json.loads(connection.recv(65536).decode())
            _emit(event_path, "loopback_gateway_received", request)
            if mode == "kill":
                _emit(event_path, "loopback_gateway_killed_at_boundary", request)
                os.kill(os.getpid(), signal.SIGKILL)
            if mode == "reset":
                connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_LINGER,
                    struct.pack("ii", 1, 0),
                )
                _emit(event_path, "loopback_gateway_reset_connection", request)
                return
            response = {
                "state": "ACKNOWLEDGED",
                "accepted": True,
                "broker_order_id": "loopback-order-001",
            }
            if request["operation"] == "query":
                response = {
                    "state": "ACKNOWLEDGED",
                    "broker_order_id": "loopback-order-001",
                }
            elif request["operation"] == "snapshot":
                generation = (
                    int(mode.split("-", 1)[1]) if mode.startswith("ack-") else 1
                )
                response = GatewaySnapshot(
                    snapshot_id="snapshot-phase-c-process-001",
                    generation=generation,
                    connected=True,
                    position_snapshot_hash=sha256_json({}),
                    account_scope=SCOPE,
                    environment=ENVIRONMENT,
                ).as_dict()
            connection.sendall(json.dumps(response, sort_keys=True).encode())
            _emit(event_path, "loopback_gateway_replied", response)


class _LoopbackGateway:
    def __init__(self, port: int) -> None:
        self.port = port

    def _call(
        self, operation: str, context: MutationContext | None = None
    ) -> dict[str, Any]:
        request = {
            "operation": operation,
            "context": context.as_dict() if context else {},
        }
        with socket.create_connection(
            ("127.0.0.1", self.port), timeout=1
        ) as connection:
            connection.settimeout(1)
            connection.sendall(json.dumps(request, sort_keys=True).encode())
            response = connection.recv(65536)
        if not response:
            raise ConnectionResetError("loopback boundary closed without a receipt")
        return dict(json.loads(response.decode()))

    def send_order(
        self, _request: Mapping[str, Any], context: MutationContext
    ) -> dict[str, Any]:
        return self._call("send", context)

    def cancel_order(
        self, _request: Mapping[str, Any], context: MutationContext
    ) -> dict[str, Any]:
        return self._call("cancel", context)

    def query_intent(
        self, _intent: SendIntent, context: MutationContext | None = None
    ) -> dict[str, Any]:
        return self._call("query", context)

    def snapshot(self) -> GatewaySnapshot:
        return GatewaySnapshot(**self._call("snapshot"))

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


def _start_gateway(
    context: multiprocessing.context.BaseContext, events: Path, mode: str
) -> tuple[multiprocessing.Process, int]:
    before = len(_events(events))
    process = context.Process(target=_gateway_worker, args=(str(events), mode))
    process.start()
    deadline = time.monotonic() + 3
    ready: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        candidates = [
            event
            for event in _events(events)[before:]
            if event["event_type"] == "loopback_gateway_ready"
        ]
        if candidates:
            ready = candidates[-1]
            break
        time.sleep(0.01)
    if ready is None:
        process.kill()
        process.join(1)
        raise AssertionError("loopback gateway did not become ready")
    return process, int(ready["payload"]["port"])


def _command(
    command: str, key: str, version: int, payload: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": f"command-{key[-12:]}",
        "idempotency_key": key,
        "correlation_id": f"correlation-{key[-12:]}",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "phase-c-process",
            "operator": "offline",
            "role": "admin",
        },
        "command": command,
        "expected": {"state_version": version},
        "payload": payload,
    }


def _ready_service(path: Path) -> tuple[ExecutionOrchestrator, object]:
    repo = DurableExecutionRepository(path, scope=SCOPE)
    service = ExecutionOrchestrator(
        repo, NullGateway(), scope=SCOPE, environment=ENVIRONMENT, test_mode=True
    )
    token = service.acquire_leader("leader-process-mutation")
    service.process_command(
        _command(
            "enable",
            "enable-process-000001",
            repo.state_version,
            {
                "authority_artifact_id": "artifact-process-001",
                "authority_hash": HASH,
                "expires_at": "2030-01-01T00:00:00Z",
                "reason": "offline process fault",
            },
        )
    )
    snapshot_process, snapshot_port = _start_gateway(
        multiprocessing.get_context("spawn"), path.with_name("events.jsonl"), "ack"
    )
    service.gateway = _LoopbackGateway(snapshot_port)
    service.process_command(
        _command(
            "reconcile",
            "reconcile-process-001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-process-001",
                "snapshot_id": "snapshot-phase-c-process-001",
                "reason": "offline process fault",
            },
        )
    )
    snapshot_process.join(2)
    service.process_command(
        _command(
            "start",
            "start-process-000001",
            repo.state_version,
            {
                "plan_id": "plan-process-000001",
                "plan_hash": HASH,
                "reason": "offline process fault",
            },
        )
    )
    return service, token


def _send(service: ExecutionOrchestrator, token: object, key: str) -> dict[str, Any]:
    return service.send_order(
        {"symbol": "RB", "volume": 1},
        idempotency_key=key,
        plan_id="plan-process-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )


def run_process_faults(workdir: Path) -> list[dict[str, Any]]:
    """Return raw records from real child-process and loopback-boundary faults."""
    workdir.mkdir(parents=True, exist_ok=True)
    context = multiprocessing.get_context("spawn")
    leader_state, leader_events = (
        workdir / "leader-state.json",
        workdir / "leader-events.jsonl",
    )
    first = context.Process(
        target=_leader_worker,
        args=(str(leader_state), str(leader_events), "leader-process-a", True),
    )
    first.start()
    _wait_event(leader_events, "leader_acquired")
    os.kill(first.pid, signal.SIGSTOP)
    _emit(str(leader_events), "leader_process_paused", {"pid": first.pid})
    time.sleep(0.15)
    second = context.Process(
        target=_leader_worker,
        args=(str(leader_state), str(leader_events), "leader-process-b", False),
    )
    second.start()
    second.join(2)
    time.sleep(0.15)
    third = context.Process(
        target=_leader_worker,
        args=(str(leader_state), str(leader_events), "leader-process-c", False),
    )
    third.start()
    third.join(2)
    os.kill(first.pid, signal.SIGKILL)
    first.join(2)
    _emit(
        str(leader_events),
        "leader_process_killed",
        {"pid": first.pid, "exitcode": first.exitcode},
    )
    leader_snapshot = DurableExecutionRepository(leader_state, scope=SCOPE).snapshot()

    mutation_state, mutation_events = (
        workdir / "mutation-state.json",
        workdir / "mutation-events.jsonl",
    )
    reset_process, reset_port = _start_gateway(context, mutation_events, "reset")
    service, token = _ready_service(mutation_state)
    service.gateway = _LoopbackGateway(reset_port)
    with _expect(GatewayTimeout):
        _send(service, token, "send-process-reset-001")
    reset_process.join(2)
    after_send = DurableExecutionRepository(mutation_state, scope=SCOPE).snapshot()
    service.release_leader(token)
    query_process, query_port = _start_gateway(context, mutation_events, "ack")
    restarted = ExecutionOrchestrator(
        DurableExecutionRepository(mutation_state, scope=SCOPE),
        _LoopbackGateway(query_port),
        scope=SCOPE,
        environment=ENVIRONMENT,
        test_mode=True,
    )
    unknown_id = next(iter(after_send["unknown_outcomes"]))
    query_result = restarted.query_intent(unknown_id)
    query_process.join(2)
    snapshot_process, snapshot_port = _start_gateway(context, mutation_events, "ack-2")
    restarted.gateway = _LoopbackGateway(snapshot_port)
    reconcile_result = restarted.process_command(
        _command(
            "reconcile",
            "reconcile-process-002",
            restarted.repository.state_version,
            {
                "reconciliation_run_id": "run-process-002",
                "snapshot_id": "snapshot-phase-c-process-001",
                "reason": "same intent query closure",
            },
        )
    )
    snapshot_process.join(2)

    send_crash_state, send_crash_events = (
        workdir / "send-crash-state.json",
        workdir / "send-crash-events.jsonl",
    )
    send_crash_service, send_crash_token = _ready_service(send_crash_state)
    send_kill_process, send_kill_port = _start_gateway(
        context, send_crash_events, "kill"
    )
    send_crash_service.gateway = _LoopbackGateway(send_kill_port)
    with _expect(GatewayTimeout):
        _send(send_crash_service, send_crash_token, "send-process-kill-001")
    send_kill_process.join(2)
    after_send_kill = DurableExecutionRepository(
        send_crash_state, scope=SCOPE
    ).snapshot()

    cancel_state, cancel_events = (
        workdir / "cancel-state.json",
        workdir / "cancel-events.jsonl",
    )
    cancel_service, cancel_token = _ready_service(cancel_state)
    send_process, send_port = _start_gateway(context, cancel_events, "ack")
    cancel_service.gateway = _LoopbackGateway(send_port)
    accepted = _send(cancel_service, cancel_token, "send-process-cancel-001")
    send_process.join(2)
    kill_process, kill_port = _start_gateway(context, cancel_events, "kill")
    cancel_service.gateway = _LoopbackGateway(kill_port)
    with _expect(GatewayTimeout):
        cancel_service.cancel_order(
            accepted["intent_id"],
            idempotency_key="cancel-process-kill-001",
            plan_id="plan-process-000001",
            plan_hash=HASH,
            leader_epoch=cancel_token.epoch,
            fencing_token=cancel_token.fencing_token,
            token=cancel_token,
        )
    kill_process.join(2)
    after_cancel = DurableExecutionRepository(cancel_state, scope=SCOPE).snapshot()

    return [
        {
            "case_id": "process_pause_lease_expiry_kill_restart",
            "records": _events(leader_events)
            + [{"event_type": "durable_leader_state", "payload": leader_snapshot}],
        },
        {
            "case_id": "loopback_partition_reset_unknown_restart_reconcile",
            "records": _events(mutation_events)
            + [
                {"event_type": "durable_state_after_reset", "payload": after_send},
                {"event_type": "same_intent_query", "payload": query_result},
                {
                    "event_type": "reconcile_receipt",
                    "payload": dict(reconcile_result.receipt),
                },
            ],
        },
        {
            "case_id": "loopback_send_cancel_crash_boundaries",
            "records": _events(send_crash_events)
            + [
                {
                    "event_type": "durable_state_after_send_kill",
                    "payload": after_send_kill,
                }
            ]
            + _events(cancel_events)
            + [
                {
                    "event_type": "durable_state_after_cancel_kill",
                    "payload": after_cancel,
                }
            ],
        },
    ]


class _expect:
    def __init__(self, expected: type[BaseException]) -> None:
        self.expected = expected

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, _value: object, _traceback: object
    ) -> bool:
        if exc_type is None:
            raise AssertionError(f"expected {self.expected.__name__}")
        return issubclass(exc_type, self.expected)
