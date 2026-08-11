from __future__ import annotations

import sys
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, socket
from threading import Event, Thread
from types import SimpleNamespace

import pytest
from app.execution import (
    ExecutionOrchestrator,
    GatewaySnapshot,
    InMemoryExecutionRepository,
    MutationContext,
    VnpyWindowsGateway,
)
from app.execution.errors import (
    GatewayConfigurationError,
    GatewayTimeout,
    GatewayUnavailable,
    SnapshotRejected,
)
from app.execution.gateway import ZmqRpcTransport
from app.execution.models import sha256_json


def _free_tcp_address() -> str:
    with socket(AF_INET, SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return f"tcp://127.0.0.1:{probe.getsockname()[1]}"


class _Socket:
    def __init__(self, outcome):
        self.outcome = outcome
        self.closed = False
        self.sent = []

    def setsockopt(self, *_args):
        return None

    def connect(self, _address):
        return None

    def send_pyobj(self, value):
        self.sent.append(value)

    def recv_pyobj(self):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome

    def close(self, *, linger):
        assert linger == 0
        self.closed = True


def test_req_timeout_discards_socket_then_same_intent_query_uses_rebuilt_socket(
    monkeypatch,
) -> None:
    first = _Socket(TimeoutError("missing reply"))
    second = _Socket([True, {"intent_id": "intent-000001", "state": "UNKNOWN"}])

    class Context:
        def __init__(self):
            self.sockets = [first, second]

        def socket(self, _kind):
            return self.sockets.pop(0)

    context = Context()
    fake_zmq = SimpleNamespace(
        REQ=1,
        LINGER=2,
        RCVTIMEO=3,
        SNDTIMEO=4,
        Context=SimpleNamespace(instance=lambda: context),
    )
    monkeypatch.setitem(sys.modules, "zmq", fake_zmq)
    transport = ZmqRpcTransport("tcp://127.0.0.1:2014", timeout_ms=20)
    transport.start()
    with pytest.raises(GatewayTimeout, match="rebuilt"):
        transport.call("send_order_fenced_v1", {"symbol": "RB"})
    assert first.closed is True
    result = transport.call(
        "query_intent_v1",
        {"intent_id": "intent-000001", "account_scope": "account:prod"},
    )
    assert result["intent_id"] == "intent-000001"
    assert [request[0] for request in first.sent + second.sent] == [
        "send_order_fenced_v1",
        "query_intent_v1",
    ]
    assert second.sent[0] == [
        "query_intent_v1",
        (
            {
                "intent_id": "intent-000001",
                "account_scope": "account:prod",
            },
        ),
        {},
    ]


def test_transport_interoperates_with_vnpy_rpc_server_wire() -> None:
    from vnpy.rpc import RpcServer

    request_seen = []

    def query_intent_v1(request):
        request_seen.append(request)
        return {"intent_id": request["intent_id"], "state": "ACKNOWLEDGED"}

    server = RpcServer()
    server.register(query_intent_v1)
    req_address = _free_tcp_address()
    pub_address = _free_tcp_address()
    while pub_address == req_address:
        pub_address = _free_tcp_address()
    server.start(req_address, pub_address)
    transport = ZmqRpcTransport(req_address)
    try:
        transport.start()
        result = transport.call(
            "query_intent_v1",
            {"intent_id": "intent-000001", "account_scope": "account:prod"},
        )
        assert result == {
            "intent_id": "intent-000001",
            "state": "ACKNOWLEDGED",
        }
        assert request_seen == [
            {"intent_id": "intent-000001", "account_scope": "account:prod"}
        ]
    finally:
        transport.stop()
        server.stop()
        server.join()


class _MutationTransport:
    def __init__(self, entered: Event, release: Event):
        self.entered = entered
        self.release = release
        self.calls = []

    def start(self):
        return None

    def stop(self):
        return None

    def call(self, method, payload, context=None):
        self.calls.append(method)
        if method == "install_fence_v1":
            return {
                "schema_version": "windows_execution_fenced_mutation_v1",
                "account_scope": "account:prod",
                "environment": "simnow",
                "current_epoch": 3,
                "current_fencing_token": 7,
            }
        if method == "register_receipt_v1":
            return {
                "schema_version": "windows_execution_fenced_mutation_v1",
                "admission": "REGISTERED",
                "account_scope": "account:prod",
                "environment": "simnow",
                "intent_id": context.intent_id if context else payload["intent_id"],
                "receipt_id": payload["receipt"]["receipt_id"],
                "leader_epoch": 3,
                "fencing_token": 7,
            }
        self.entered.set()
        assert self.release.wait(1)
        return {
            "admission": "ACCEPTED",
            **context.as_dict(),
            "operation": context.action,
            "state": "ACKNOWLEDGED",
            "accepted": True,
        }


class _ReadonlyTransport:
    def __init__(self):
        self.calls = []

    def start(self):
        return None

    def stop(self):
        return None

    def call(self, method, _payload, context=None):
        assert context is None
        self.calls.append(method)
        return GatewaySnapshot(
            snapshot_id="snapshot-readonly",
            generation=1,
            connected=True,
            account_scope="account:prod",
            environment="simnow",
        ).as_dict()


def test_readiness_snapshot_has_independent_socket_during_mutation() -> None:
    entered, release = Event(), Event()
    mutation = _MutationTransport(entered, release)
    readonly = _ReadonlyTransport()
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="simnow",
        transport=mutation,
        readonly_transport=readonly,
    )
    gateway.start()
    request = {"symbol": "RB"}
    context = MutationContext(
        account_scope="account:prod",
        environment="simnow",
        leader_epoch=3,
        fencing_token=7,
        plan_id="plan-000001",
        plan_hash="b" * 64,
        intent_id="intent-000001",
        idempotency_key="send-key-concurrent-01",
        action="send",
        receipt_id="receipt-intent-000001",
        receipt_hash="c" * 64,
        request_hash=sha256_json(request),
    )
    outcome = []
    thread = Thread(target=lambda: outcome.append(gateway.send_order(request, context)))
    thread.start()
    assert entered.wait(1)
    snapshot = gateway.snapshot()
    assert snapshot.snapshot_id == "snapshot-readonly"
    assert readonly.calls == ["get_execution_snapshot_v1"]
    release.set()
    thread.join(1)
    assert outcome[0]["state"] == "ACKNOWLEDGED"
    assert mutation.calls.count("send_order_fenced_v1") == 1


class _FinalValidationPeekTransport:
    def __init__(self, facts):
        self.facts = facts
        self.calls = []

    def start(self):
        return None

    def stop(self):
        return None

    def call(self, method, payload, context=None):
        self.calls.append((method, payload, context))
        if method == "get_execution_snapshot_v1":
            return GatewaySnapshot(
                snapshot_id="snapshot-durable",
                generation=7,
                connected=True,
                position_snapshot_hash=sha256_json({}),
                account_scope="account:prod",
                environment="simnow",
            ).as_dict()
        return self.facts


def _final_validation_facts() -> dict:
    return {
        "schema_version": "windows_execution_current_facts_v1",
        "account": {"CTP.sim-account": {"gateway_name": "CTP", "available": 90}},
        "positions": {"rb-long": {"symbol": "rb", "volume": 2}},
        "active_orders": {"CTP.1": {"symbol": "rb", "status": "NOTTRADED"}},
        "gateway": {
            "gateway_name": "CTP",
            "account_scope": "account:prod",
            "environment": "simnow",
            "connected": True,
        },
        "execution": {"orders": {"CTP.1": {"symbol": "rb"}}},
        "admission": {
            "account_scope": "account:prod",
            "environment": "simnow",
            "durable_state_version": 4,
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


def _final_validation_gateway(transport):
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="SIMNOW",
        transport=transport,
        readonly_transport=transport,
        readiness_snapshot_source="final-validation-peek-current-facts-v1",
    )
    gateway.start()
    return gateway


def _reconcile_command(snapshot_id: str, version: int) -> dict:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": "command-reconcile-0001",
        "idempotency_key": "reconcile-transport-0001",
        "correlation_id": "correlation-reconcile-0001",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "tester",
            "operator": "tester",
            "role": "admin",
        },
        "command": "reconcile",
        "expected": {"state_version": version},
        "payload": {
            "reconciliation_run_id": "run-transport-0001",
            "snapshot_id": snapshot_id,
            "reason": "verify read-only snapshot transport",
        },
    }


def _reconcile_service(gateway: VnpyWindowsGateway) -> ExecutionOrchestrator:
    return ExecutionOrchestrator(
        InMemoryExecutionRepository(scope="account:prod"),
        gateway,
        scope="account:prod",
        environment=gateway.environment,
        test_mode=True,
    )


def _record_broker_generation(service: ExecutionOrchestrator, generation: int) -> None:
    def writer(state: dict) -> None:
        state["broker"].update(
            {
                "generation": generation,
                "connected": True,
                "last_snapshot_at": "2020-01-01T00:00:00Z",
            }
        )

    service.repository.mutate(writer)


def test_final_validation_readiness_uses_fixed_pure_peek_and_hash_binds_facts() -> None:
    facts = _final_validation_facts()
    transport = _FinalValidationPeekTransport(facts)
    snapshot = _final_validation_gateway(transport).readiness_snapshot()

    assert transport.calls == [
        (
            "peek_current_facts_v1",
            {"account_scope": "account:prod", "environment": "simnow"},
            None,
        )
    ]
    assert snapshot.snapshot_id == f"snapshot-peek-{sha256_json(facts)}"
    assert snapshot.position_snapshot_hash == sha256_json(facts["positions"])
    assert snapshot.active_order_count == 1
    assert snapshot.generation == 0
    assert facts["admission"]["snapshot_generation"] == 0
    assert snapshot.orders == facts["active_orders"]
    assert snapshot.positions == facts["positions"]
    assert snapshot.account_scope == "account:prod"
    assert snapshot.environment == "SIMNOW"
    assert snapshot.fresh is True


def test_final_validation_does_not_replace_durable_snapshot_path() -> None:
    transport = _FinalValidationPeekTransport(_final_validation_facts())
    snapshot = _final_validation_gateway(transport).snapshot()

    assert snapshot.generation == 7
    assert snapshot.environment == "SIMNOW"
    assert transport.calls == [
        (
            "get_execution_snapshot_v1",
            {"environment": "simnow", "account_scope": "account:prod"},
            None,
        )
    ]


def test_final_validation_reconcile_uses_only_pure_peek_snapshot() -> None:
    facts = _final_validation_facts()
    facts["active_orders"] = {}
    facts["execution"]["orders"] = {}
    transport = _FinalValidationPeekTransport(facts)
    gateway = _final_validation_gateway(transport)
    service = _reconcile_service(gateway)
    snapshot_id = f"snapshot-peek-{sha256_json(facts)}"

    response = service.process_command(
        _reconcile_command(snapshot_id, service.repository.state_version)
    )

    assert response.result["accepted"] is True
    assert response.result["snapshot_id"] == snapshot_id
    assert [method for method, _payload, _context in transport.calls] == [
        "peek_current_facts_v1"
    ]


def test_final_validation_reconcile_accepts_equal_pure_peek_generation() -> None:
    facts = _final_validation_facts()
    facts["active_orders"] = {}
    facts["execution"]["orders"] = {}
    transport = _FinalValidationPeekTransport(facts)
    service = _reconcile_service(_final_validation_gateway(transport))
    _record_broker_generation(service, generation=0)

    response = service.process_command(
        _reconcile_command(
            f"snapshot-peek-{sha256_json(facts)}", service.repository.state_version
        )
    )

    assert response.result["accepted"] is True


def test_final_validation_reconcile_rejects_regressed_pure_peek_generation() -> None:
    facts = _final_validation_facts()
    facts["active_orders"] = {}
    facts["execution"]["orders"] = {}
    transport = _FinalValidationPeekTransport(facts)
    service = _reconcile_service(_final_validation_gateway(transport))
    _record_broker_generation(service, generation=1)

    with pytest.raises(SnapshotRejected, match="generation regressed"):
        service.process_command(
            _reconcile_command(
                f"snapshot-peek-{sha256_json(facts)}", service.repository.state_version
            )
        )


def test_normal_reconcile_keeps_durable_snapshot_transport() -> None:
    transport = _FinalValidationPeekTransport(_final_validation_facts())
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="simnow",
        transport=transport,
        readonly_transport=transport,
    )
    gateway.start()
    service = _reconcile_service(gateway)

    response = service.process_command(
        _reconcile_command("snapshot-durable", service.repository.state_version)
    )

    assert response.result["accepted"] is True
    assert [method for method, _payload, _context in transport.calls] == [
        "get_execution_snapshot_v1"
    ]


def test_durable_reconcile_rejects_equal_generation() -> None:
    transport = _FinalValidationPeekTransport(_final_validation_facts())
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="simnow",
        transport=transport,
        readonly_transport=transport,
    )
    gateway.start()
    service = _reconcile_service(gateway)
    _record_broker_generation(service, generation=7)

    with pytest.raises(SnapshotRejected, match="generation is stale"):
        service.process_command(
            _reconcile_command("snapshot-durable", service.repository.state_version)
        )


def test_final_validation_reconcile_snapshot_mismatch_fails_closed() -> None:
    facts = _final_validation_facts()
    facts["active_orders"] = {}
    facts["execution"]["orders"] = {}
    transport = _FinalValidationPeekTransport(facts)
    service = _reconcile_service(_final_validation_gateway(transport))

    with pytest.raises(SnapshotRejected, match="does not match"):
        service.process_command(
            _reconcile_command(
                "snapshot-requested", service.repository.state_version
            )
        )

    assert service.status()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"
    assert [method for method, _payload, _context in transport.calls] == [
        "peek_current_facts_v1"
    ]


def test_durable_snapshot_keeps_service_environment_binding() -> None:
    transport = _FinalValidationPeekTransport(_final_validation_facts())
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="SIMNOW",
        transport=transport,
        readonly_transport=transport,
    )
    gateway.start()

    snapshot = gateway.snapshot()

    assert snapshot.environment == "simnow"
    assert transport.calls == [
        (
            "get_execution_snapshot_v1",
            {"environment": "SIMNOW", "account_scope": "account:prod"},
            None,
        )
    ]


def test_final_validation_snapshot_fails_closed_when_durable_rpc_is_absent() -> None:
    class ValidationOnlyTransport(_FinalValidationPeekTransport):
        def call(self, method, payload, context=None):
            self.calls.append((method, payload, context))
            raise GatewayUnavailable("method is not registered")

    transport = ValidationOnlyTransport(_final_validation_facts())

    with pytest.raises(GatewayUnavailable, match="not registered"):
        _final_validation_gateway(transport).snapshot()
    assert [method for method, _payload, _context in transport.calls] == [
        "get_execution_snapshot_v1"
    ]


def test_final_validation_peek_rejects_nonfixed_service_environment() -> None:
    with pytest.raises(
        GatewayConfigurationError,
        match="requires EXECUTION_ENVIRONMENT=SIMNOW",
    ):
        VnpyWindowsGateway(
            req_address="tcp://127.0.0.1:2014",
            pub_address="tcp://127.0.0.1:4102",
            account_scope="account:prod",
            environment="simnow",
            readiness_snapshot_source="final-validation-peek-current-facts-v1",
        )


def test_final_validation_from_env_maps_only_readiness_to_fixed_windows_scope(
    monkeypatch,
) -> None:
    monkeypatch.setenv("EXECUTION_RPC_REQ_ADDRESS", "tcp://127.0.0.1:2014")
    monkeypatch.setenv("EXECUTION_RPC_PUB_ADDRESS", "tcp://127.0.0.1:4102")
    monkeypatch.setenv("EXECUTION_SCOPE", "account:prod")
    monkeypatch.delenv("EXECUTION_ACCOUNT_SCOPE", raising=False)
    monkeypatch.setenv("EXECUTION_ENVIRONMENT", "SIMNOW")
    monkeypatch.setenv(
        "EXECUTION_READINESS_SNAPSHOT_SOURCE",
        "final-validation-peek-current-facts-v1",
    )
    transport = _FinalValidationPeekTransport(_final_validation_facts())
    gateway = VnpyWindowsGateway.from_env()
    gateway.transport = transport
    gateway.readonly_transport = transport
    gateway.start()

    snapshot = gateway.readiness_snapshot()

    assert snapshot.environment == "SIMNOW"
    assert transport.calls == [
        (
            "peek_current_facts_v1",
            {"account_scope": "account:prod", "environment": "simnow"},
            None,
        )
    ]
    compose = Path("deployments/docker-compose.final.yml").read_text(encoding="utf-8")
    assert "EXECUTION_ENVIRONMENT: SIMNOW" in compose
    assert (
        "EXECUTION_READINESS_SNAPSHOT_SOURCE: "
        "final-validation-peek-current-facts-v1" in compose
    )


def test_final_validation_readiness_exposes_only_active_orders() -> None:
    facts = _final_validation_facts()
    facts["active_orders"] = {}
    expected_snapshot_id = f"snapshot-peek-{sha256_json(facts)}"
    transport = _FinalValidationPeekTransport(facts)

    snapshot = _final_validation_gateway(transport).readiness_snapshot()

    assert facts["execution"]["orders"]
    assert snapshot.snapshot_id == expected_snapshot_id
    assert snapshot.active_order_count == 0
    assert snapshot.orders == {}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda facts: facts.pop("active_orders"),
        lambda facts: facts["gateway"].update({"account_scope": "account:foreign"}),
        lambda facts: facts["gateway"].update({"environment": "SIMNOW"}),
        lambda facts: facts.update({"observed_at": "1970-01-01T00:00:00Z"}),
    ],
    ids=[
        "malformed",
        "foreign-gateway",
        "foreign-windows-environment",
        "stale-like-extra-fact",
    ],
)
def test_final_validation_readiness_rejects_non_exact_or_foreign_facts(mutate) -> None:
    facts = _final_validation_facts()
    mutate(facts)
    transport = _FinalValidationPeekTransport(facts)

    with pytest.raises(GatewayUnavailable, match="final-validation current facts"):
        _final_validation_gateway(transport).readiness_snapshot()
    assert [method for method, _payload, _context in transport.calls] == [
        "peek_current_facts_v1"
    ]
