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
    SendIntent,
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


class _FinalAdmissionWireTransport:
    def __init__(self) -> None:
        from scripts.windows_fence_foundation.final_admission_v1 import (
            WindowsRpcFencedAdmissionV1,
        )

        self.calls = []
        self.send_calls = 0
        self.cancel_calls = 0
        self.query_handler_calls = 0

        def send_handler(_request, _context):
            self.send_calls += 1
            return {"state": "ACKNOWLEDGED", "accepted": True}

        def cancel_handler(_request, _context):
            self.cancel_calls += 1
            return {"state": "CANCELLED", "accepted": True}

        def query_handler(_request, _context):
            self.query_handler_calls += 1
            return {
                "state": "REJECTED",
                "accepted": False,
                "account_scope": "account:prod",
                "environment": "simnow",
            }

        self.admission = WindowsRpcFencedAdmissionV1(
            account_scope="account:prod",
            environment="simnow",
            send_handler=send_handler,
            cancel_handler=cancel_handler,
            query_handler=query_handler,
        )

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def call(self, method, payload, context=None):
        self.calls.append((method, payload, context))
        return getattr(self.admission, method)(payload, context)


def test_final_admission_query_rejects_only_definitive_missing_receipt() -> None:
    from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceDenied
    from scripts.windows_fence_foundation.final_admission_v1 import (
        WindowsRpcFencedAdmissionV1,
        _receipt_digest,
    )

    query_calls = []
    admission = WindowsRpcFencedAdmissionV1(
        account_scope="account:prod",
        environment="simnow",
        send_handler=lambda *_args: pytest.fail("send must not be called"),
        cancel_handler=lambda *_args: pytest.fail("cancel must not be called"),
        query_handler=lambda request, context: query_calls.append(
            (request, context)
        )
        or {
            "state": "ACKNOWLEDGED",
            "accepted": True,
            "account_scope": "account:prod",
            "environment": "simnow",
        },
    )
    query = {
        "account_scope": "account:prod",
        "environment": "simnow",
        "intent_id": "intent-000001",
        "broker_order_id": None,
    }

    assert admission.query_intent_v1(query) == {
        "intent_id": "intent-000001",
        "state": "REJECTED",
        "accepted": False,
        "account_scope": "account:prod",
        "environment": "simnow",
    }
    assert query_calls == []
    with pytest.raises(WindowsRpcDurableFenceDenied, match="not registered"):
        admission.query_intent_v1({**query, "broker_order_id": "CTP.1"})
    assert query_calls == []

    receipt = {
        "intent_id": "intent-000001",
        "receipt_id": "receipt-intent-000001",
        "receipt_hash": "",
        "request_hash": "a" * 64,
        "account_scope": "account:prod",
        "environment": "simnow",
        "leader_epoch": 1,
        "fencing_token": 1,
        "idempotency_key": "send-key-query-0001",
        "plan_id": "plan-000001",
        "plan_hash": "b" * 64,
        "action": "send",
    }
    receipt["receipt_hash"] = _receipt_digest(receipt)
    admission.install_fence(epoch=1, fencing_token=1)
    admission.register_receipt(intent_id=receipt["intent_id"], receipt=receipt)

    assert admission.query_intent_v1(query) == {
        "intent_id": "intent-000001",
        "state": "ACKNOWLEDGED",
        "accepted": True,
        "account_scope": "account:prod",
        "environment": "simnow",
    }
    assert query_calls == [(query, None)]


def test_simnow_durable_fence_wire_maps_only_windows_environment() -> None:
    transport = _FinalAdmissionWireTransport()
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="SIMNOW",
        transport=transport,
        readonly_transport=transport,
    )
    gateway.start()
    request = {"symbol": "RB"}
    context = MutationContext(
        account_scope="account:prod",
        environment="SIMNOW",
        leader_epoch=3,
        fencing_token=7,
        plan_id="plan-000001",
        plan_hash="b" * 64,
        intent_id="intent-000001",
        idempotency_key="send-key-wire-00001",
        action="send",
        receipt_id="receipt-intent-000001",
        receipt_hash=sha256_json(
            {
                "account_scope": "account:prod",
                "environment": "SIMNOW",
                "intent_id": "intent-000001",
                "idempotency_key": "send-key-wire-00001",
                "plan_id": "plan-000001",
                "plan_hash": "b" * 64,
                "request_hash": sha256_json(request),
                "action": "send",
            }
        ),
        request_hash=sha256_json(request),
    )

    send_result = gateway.send_order(request, context)
    query_result = gateway.query_intent(
        SendIntent(
            intent_id=context.intent_id,
            idempotency_key=context.idempotency_key,
            state="UNKNOWN_OUTCOME",
            plan_id=context.plan_id,
            plan_hash=context.plan_hash,
            leader_epoch=context.leader_epoch,
            fencing_token=context.fencing_token,
            created_at="2030-01-01T00:00:00Z",
            request_hash=context.request_hash,
            receipt_id=context.receipt_id,
            receipt_hash=context.receipt_hash,
        ),
        context,
    )

    assert gateway.environment == context.environment == "SIMNOW"
    assert send_result["environment"] == query_result["environment"] == "simnow"
    assert send_result["receipt_hash"] != context.receipt_hash
    assert transport.admission.snapshot()["receipt_intents"] == [context.intent_id]
    install, register, send, query = transport.calls
    assert install == (
        "install_fence_v1",
        {
            "account_scope": "account:prod",
            "environment": "simnow",
            "leader_epoch": 3,
            "fencing_token": 7,
        },
        None,
    )
    assert register[0] == "register_receipt_v1"
    assert register[1]["receipt"]["environment"] == "simnow"
    assert register[2] is None
    assert send[0] == "send_order_fenced_v1"
    assert send[2].environment == "simnow"
    assert query == (
        "query_intent_v1",
        {
            "account_scope": "account:prod",
            "environment": "simnow",
            "intent_id": "intent-000001",
            "broker_order_id": None,
        },
        send[2],
    )


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


def test_equal_pure_peek_reconcile_keeps_unknown_halted_without_new_send() -> None:
    class UnknownIntentTransport(_FinalValidationPeekTransport):
        def call(self, method, payload, context=None):
            if method == "query_intent_v1":
                self.calls.append((method, payload, context))
                return {
                    "intent_id": payload["intent_id"],
                    "account_scope": payload["account_scope"],
                    "environment": payload["environment"],
                    "state": "UNKNOWN",
                }
            return super().call(method, payload, context)

    facts = _final_validation_facts()
    facts["active_orders"] = {}
    facts["execution"]["orders"] = {}
    transport = UnknownIntentTransport(facts)
    service = _reconcile_service(_final_validation_gateway(transport))
    intent_id = "intent-unknown-0001"
    idempotency_key = "send-key-unknown-0001"

    def record_unknown(state: dict) -> None:
        state["broker"].update(
            {
                "generation": 0,
                "connected": True,
                "last_snapshot_at": "2020-01-01T00:00:00Z",
            }
        )
        state["send_intents"][intent_id] = {
            "intent_id": intent_id,
            "idempotency_key": idempotency_key,
            "state": "UNKNOWN_OUTCOME",
            "plan_id": "plan-unknown-0001",
            "plan_hash": "b" * 64,
            "leader_epoch": 1,
            "fencing_token": 1,
            "created_at": "2020-01-01T00:00:00Z",
        }
        state["intent_keys"][idempotency_key] = intent_id
        state["unknown_outcomes"][intent_id] = {"reason": "rpc timeout"}
        state["reconciliation"].update({"state": "UNKNOWN", "unknown_outcomes": 1})
        state["lifecycle"] = "HALTED_UNKNOWN_OUTCOME"

    service.repository.mutate(record_unknown)
    response = service.process_command(
        _reconcile_command(
            f"snapshot-peek-{sha256_json(facts)}", service.repository.state_version
        )
    )

    state = service.repository.snapshot()
    methods = [method for method, _payload, _context in transport.calls]
    assert response.result == {
        "accepted": False,
        "snapshot_id": f"snapshot-peek-{sha256_json(facts)}",
        "unknown_outcomes": 1,
        "lifecycle": "HALTED_UNKNOWN_OUTCOME",
    }
    assert methods == ["peek_current_facts_v1", "query_intent_v1"]
    assert "send_order_fenced_v1" not in methods
    assert state["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"
    assert state["send_intents"][intent_id]["state"] == "UNKNOWN_OUTCOME"
    assert intent_id in state["unknown_outcomes"]


def test_missing_receipt_reconcile_clears_unknown_without_order_mutation() -> None:
    class MissingReceiptTransport(_FinalAdmissionWireTransport):
        def __init__(self, facts):
            super().__init__()
            self.facts = facts

        def call(self, method, payload, context=None):
            if method == "peek_current_facts_v1":
                self.calls.append((method, payload, context))
                return self.facts
            return super().call(method, payload, context)

    facts = _final_validation_facts()
    facts["active_orders"] = {}
    facts["execution"]["orders"] = {}
    transport = MissingReceiptTransport(facts)
    service = _reconcile_service(_final_validation_gateway(transport))
    intent_id = "intent-missing-receipt-0001"
    idempotency_key = "send-key-missing-receipt-0001"

    def record_unknown(state: dict) -> None:
        state["broker"].update(
            {
                "generation": 0,
                "connected": True,
                "last_snapshot_at": "2020-01-01T00:00:00Z",
            }
        )
        state["send_intents"][intent_id] = {
            "intent_id": intent_id,
            "idempotency_key": idempotency_key,
            "state": "UNKNOWN_OUTCOME",
            "plan_id": "plan-missing-receipt-0001",
            "plan_hash": "b" * 64,
            "leader_epoch": 1,
            "fencing_token": 1,
            "created_at": "2020-01-01T00:00:00Z",
        }
        state["intent_keys"][idempotency_key] = intent_id
        state["unknown_outcomes"][intent_id] = {"reason": "pre-install timeout"}
        state["reconciliation"].update({"state": "UNKNOWN", "unknown_outcomes": 1})
        state["lifecycle"] = "HALTED_UNKNOWN_OUTCOME"

    service.repository.mutate(record_unknown)
    response = service.process_command(
        _reconcile_command(
            f"snapshot-peek-{sha256_json(facts)}", service.repository.state_version
        )
    )

    state = service.repository.snapshot()
    assert response.result == {
        "accepted": True,
        "snapshot_id": f"snapshot-peek-{sha256_json(facts)}",
        "unknown_outcomes": 0,
        "lifecycle": "READY",
    }
    assert state["send_intents"][intent_id]["state"] == "RECONCILED"
    assert state["unknown_outcomes"] == {}
    assert transport.send_calls == transport.cancel_calls == 0
    assert transport.query_handler_calls == 0
    assert [method for method, _payload, _context in transport.calls] == [
        "peek_current_facts_v1",
        "query_intent_v1",
    ]


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
