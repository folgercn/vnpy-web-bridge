from __future__ import annotations

import sys
from socket import AF_INET, SOCK_STREAM, socket
from threading import Event, Thread
from types import SimpleNamespace

import pytest
from app.execution import GatewaySnapshot, MutationContext, VnpyWindowsGateway
from app.execution.errors import GatewayTimeout
from app.execution.gateway import ZmqRpcTransport


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
    from app.execution.models import sha256_json

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
