from __future__ import annotations

import json
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import SimpleNamespace
from typing import Any

import pytest
from scripts.windows_rpc_deployment_snapshot_v1 import (
    RPC_CALLABLE_NAME,
    SCHEMA_VERSION,
    SNAPSHOT_EVENT_TYPE,
    WindowsRpcDeploymentSnapshotError,
    register_windows_rpc_deployment_snapshot_v1,
)


@dataclass
class FakeEvent:
    type: str
    data: Any = None


class FakeServer:
    def __init__(self) -> None:
        self.send_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.cancel_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self._functions: dict[str, Any] = {
            "send_order": self._send_order,
            "cancel_order": self._cancel_order,
        }
        self.registered = self._functions

    def register(self, function: Any) -> None:
        self._functions[function.__name__] = function

    def _send_order(self, *args: Any, **kwargs: Any) -> str:
        self.send_calls.append((args, kwargs))
        return "CTP.1001"

    def _cancel_order(self, *args: Any, **kwargs: Any) -> bool:
        self.cancel_calls.append((args, kwargs))
        return True


class SyncEventEngine:
    def __init__(self) -> None:
        self.handlers: dict[str, list[Any]] = {}

    def register(self, event_type: str, handler: Any) -> None:
        self.handlers.setdefault(event_type, []).append(handler)

    def put(self, event: FakeEvent) -> None:
        for handler in tuple(self.handlers.get(event.type, ())):
            handler(event)


class AsyncEventEngine(SyncEventEngine):
    def __init__(self) -> None:
        super().__init__()
        self.events: queue.Queue[FakeEvent | None] = queue.Queue()
        self.worker_ident: int | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def put(self, event: FakeEvent) -> None:
        self.events.put(event)

    def close(self) -> None:
        self.events.put(None)
        self.thread.join(timeout=2)

    def _run(self) -> None:
        self.worker_ident = threading.get_ident()
        while True:
            event = self.events.get()
            if event is None:
                return
            for handler in tuple(self.handlers.get(event.type, ())):
                handler(event)


class Direction(Enum):
    LONG = "long"


@dataclass
class OrderFact:
    vt_orderid: str
    direction: Direction
    price: float


class FactSource:
    def __init__(self) -> None:
        self.engines = {"log": None, "oms": None}
        self.apps = {"RpcService": None}
        self.calls: list[str] = []
        self.call_threads: list[int] = []
        self.accounts: list[Any] = [
            {"gateway_name": "CTP", "accountid": "sim-account"}
        ]
        self.orders: list[Any] = [
            OrderFact("CTP.2", Direction.LONG, 20.0),
            OrderFact("CTP.1", Direction.LONG, 10.0),
        ]
        self.active_orders: list[Any] = []
        self.trades: list[Any] = []
        self.positions: list[Any] = [
            {
                "vt_symbol": "rb2610.SHFE",
                "volume": 0,
                "observed_at": datetime(
                    2026, 8, 4, 1, 2, 3, tzinfo=timezone.utc
                ),
            }
        ]

    def _get(self, name: str, value: list[Any]) -> list[Any]:
        self.calls.append(name)
        self.call_threads.append(threading.get_ident())
        return value

    def get_all_accounts(self) -> list[Any]:
        return self._get("accounts", self.accounts)

    def get_all_orders(self) -> list[Any]:
        return self._get("orders", self.orders)

    def get_all_active_orders(self) -> list[Any]:
        return self._get("active_orders", self.active_orders)

    def get_all_trades(self) -> list[Any]:
        return self._get("trades", self.trades)

    def get_all_positions(self) -> list[Any]:
        return self._get("positions", self.positions)


def event_factory(event_type: str, data: Any) -> FakeEvent:
    return FakeEvent(event_type, data)


def fixed_clock() -> datetime:
    return datetime(2026, 8, 4, 0, 0, tzinfo=timezone.utc)


def install(
    event_engine: Any,
    source: FactSource,
    *,
    timeout_seconds: float = 1,
    server: FakeServer | None = None,
) -> tuple[Any, FakeServer]:
    server = server or FakeServer()
    extension = register_windows_rpc_deployment_snapshot_v1(
        SimpleNamespace(server=server),
        event_engine,
        source,
        event_factory=event_factory,
        timeout_seconds=timeout_seconds,
        clock=fixed_clock,
    )
    return extension, server


def test_registers_exact_readonly_rpc_name_and_event_handlers() -> None:
    engine = SyncEventEngine()
    extension, server = install(engine, FactSource())

    assert set(server.registered) == {
        "cancel_order",
        RPC_CALLABLE_NAME,
        "send_order",
    }
    assert server.registered[RPC_CALLABLE_NAME] is extension.rpc_callable
    assert set(engine.handlers) == {
        "eOrder.",
        "eTrade.",
        "ePosition.",
        "eAccount.",
        SNAPSHOT_EVENT_TYPE,
    }
    assert extension.register() is extension.rpc_callable
    assert len(server.registered) == 3


def test_sync_engine_returns_strict_stably_sorted_plain_json() -> None:
    source = FactSource()
    extension, server = install(SyncEventEngine(), source)

    snapshot = server.registered[RPC_CALLABLE_NAME](
        "request-snapshot-0001", "challenge-snapshot-0001"
    )

    assert snapshot == extension.get_deployment_safety_snapshot_v1(
        "request-snapshot-0001", "challenge-snapshot-0001"
    )
    assert snapshot["schema_version"] == SCHEMA_VERSION
    assert snapshot["server_instance_id"].startswith("windows-rpc-")
    assert snapshot["fact_generation"] == 0
    assert snapshot["request_id"] == "request-snapshot-0001"
    assert snapshot["challenge"] == "challenge-snapshot-0001"
    assert snapshot["execution_admission_frozen"] is True
    assert snapshot["pending_send_outcomes"] == 0
    assert snapshot["captured_at_utc"] == "2026-08-04T00:00:00Z"
    assert snapshot["strategy_execution_enabled"] is False
    assert [row["vt_orderid"] for row in snapshot["orders"]] == [
        "CTP.1",
        "CTP.2",
    ]
    assert snapshot["orders"][0]["direction"] == "long"
    assert snapshot["positions"][0]["observed_at"].endswith("Z")
    assert source.calls == [
        "accounts",
        "orders",
        "active_orders",
        "trades",
        "positions",
    ] * 2
    json.dumps(snapshot, allow_nan=False)


def test_order_and_trade_events_precede_snapshot_and_increment_generation() -> None:
    engine = SyncEventEngine()
    extension, _ = install(engine, FactSource())

    engine.put(FakeEvent("eOrder.", {"vt_orderid": "CTP.1"}))
    engine.put(FakeEvent("eTrade.", {"vt_tradeid": "CTP.1"}))

    first = extension.get_deployment_safety_snapshot_v1(
        "request-events-0001", "challenge-events-0001"
    )
    assert first["fact_generation"] == 2
    engine.put(FakeEvent("eOrder.", {"vt_orderid": "CTP.2"}))
    assert extension.get_deployment_safety_snapshot_v1(
        "request-events-0001", "challenge-events-0001"
    )["fact_generation"] == 3


def test_position_and_account_events_increment_generation() -> None:
    engine = SyncEventEngine()
    extension, _ = install(engine, FactSource())
    engine.put(FakeEvent("ePosition."))
    engine.put(FakeEvent("eAccount."))

    snapshot = extension.get_deployment_safety_snapshot_v1(
        "request-account-0001", "challenge-account-0001"
    )

    assert snapshot["fact_generation"] == 2


def test_async_engine_copies_all_facts_on_event_thread_in_queue_order() -> None:
    engine = AsyncEventEngine()
    try:
        source = FactSource()
        extension, _ = install(engine, source)
        caller_ident = threading.get_ident()
        engine.put(FakeEvent("eOrder."))
        engine.put(FakeEvent("eTrade."))

        snapshot = extension.get_deployment_safety_snapshot_v1(
            "request-async-0001", "challenge-async-0001"
        )

        assert snapshot["fact_generation"] == 2
        assert source.call_threads == [engine.worker_ident] * 5
        assert engine.worker_ident != caller_ident
    finally:
        engine.close()


def test_timeout_fails_when_event_engine_does_not_dispatch() -> None:
    class DroppingEventEngine(SyncEventEngine):
        def put(self, _event: FakeEvent) -> None:
            return

    extension, _ = install(
        DroppingEventEngine(), FactSource(), timeout_seconds=0.01
    )

    with pytest.raises(TimeoutError, match="EventEngine"):
        extension.get_deployment_safety_snapshot_v1(
            "request-timeout-0001", "challenge-timeout-0001"
        )


@pytest.mark.parametrize(
    "bad_value,match",
    [
        (float("nan"), "non-finite"),
        (object(), "plain-JSON"),
        ({"api_secret": "must-not-leak"}, "credential field"),
    ],
)
def test_rejects_unsafe_or_unserializable_fact_values(
    bad_value: Any, match: str
) -> None:
    source = FactSource()
    source.orders = [{"value": bad_value}]
    extension, _ = install(SyncEventEngine(), source)

    with pytest.raises(WindowsRpcDeploymentSnapshotError, match=match):
        extension.get_deployment_safety_snapshot_v1(
            "request-invalid-0001", "challenge-invalid-0001"
        )


def test_each_extension_has_a_random_server_instance_identity() -> None:
    first, _ = install(SyncEventEngine(), FactSource())
    second, _ = install(SyncEventEngine(), FactSource())

    assert first.server_instance_id != second.server_instance_id


def test_registration_rejects_a_strategy_capable_gateway() -> None:
    source = FactSource()
    source.start_strategy = lambda _name: None

    with pytest.raises(
        WindowsRpcDeploymentSnapshotError,
        match="strategy-capable Windows gateway",
    ):
        install(SyncEventEngine(), source)


@pytest.mark.parametrize("registry", ["engines", "apps"])
def test_registration_rejects_unknown_engine_or_app(registry: str) -> None:
    source = FactSource()
    getattr(source, registry)["UnknownExecution"] = None

    with pytest.raises(
        WindowsRpcDeploymentSnapshotError,
        match=f"unknown {registry} component",
    ):
        install(SyncEventEngine(), source)


def test_send_reply_is_pending_until_delayed_event_and_fence_rejects_mutations(
) -> None:
    engine = SyncEventEngine()
    extension, server = install(engine, FactSource())
    send = server.registered["send_order"]
    cancel = server.registered["cancel_order"]

    assert send("order-request", "CTP") == "CTP.1001"
    snapshot = extension.get_deployment_safety_snapshot_v1(
        "request-fence-0001", "challenge-fence-0001"
    )

    assert snapshot["pending_send_outcomes"] == 1
    assert snapshot["execution_admission_frozen"] is True
    with pytest.raises(WindowsRpcDeploymentSnapshotError, match="frozen"):
        send("second-order", "CTP")
    with pytest.raises(WindowsRpcDeploymentSnapshotError, match="frozen"):
        cancel("cancel-request", "CTP")

    engine.put(FakeEvent("eOrder.", {"vt_orderid": "CTP.1001"}))
    settled = extension.get_deployment_safety_snapshot_v1(
        "request-fence-0001", "challenge-fence-0001"
    )
    assert settled["pending_send_outcomes"] == 0


def test_snapshot_waits_for_an_inflight_send_reply_before_event_capture() -> None:
    entered = threading.Event()
    finish = threading.Event()
    server = FakeServer()

    def blocking_send(*_args: Any, **_kwargs: Any) -> str:
        entered.set()
        assert finish.wait(timeout=2)
        return "CTP.2002"

    server._functions["send_order"] = blocking_send
    extension, server = install(
        SyncEventEngine(), FactSource(), server=server
    )
    send_result: list[str] = []
    snapshot_result: list[dict[str, Any]] = []
    send_thread = threading.Thread(
        target=lambda: send_result.append(
            server.registered["send_order"]("order", "CTP")
        )
    )
    snapshot_thread = threading.Thread(
        target=lambda: snapshot_result.append(
            extension.get_deployment_safety_snapshot_v1(
                "request-inflight-0001", "challenge-inflight-0001"
            )
        )
    )
    send_thread.start()
    assert entered.wait(timeout=1)
    snapshot_thread.start()
    assert not snapshot_result

    finish.set()
    send_thread.join(timeout=2)
    snapshot_thread.join(timeout=2)

    assert send_result == ["CTP.2002"]
    assert snapshot_result[0]["pending_send_outcomes"] == 1


def test_historical_same_order_id_does_not_settle_a_new_send() -> None:
    engine = SyncEventEngine()
    extension, server = install(engine, FactSource())
    engine.put(FakeEvent("eOrder.", {"vt_orderid": "CTP.1001"}))

    server.registered["send_order"]("order", "CTP")
    first = extension.get_deployment_safety_snapshot_v1(
        "request-reused-id-0001", "challenge-reused-id-0001"
    )

    assert first["pending_send_outcomes"] == 1
    engine.put(FakeEvent("eOrder.", {"vt_orderid": "CTP.1001"}))
    second = extension.get_deployment_safety_snapshot_v1(
        "request-reused-id-0001", "challenge-reused-id-0001"
    )
    assert second["pending_send_outcomes"] == 0


def test_a2_exposes_no_unfreeze_rpc_and_fence_remains_closed() -> None:
    extension, server = install(SyncEventEngine(), FactSource())
    extension.get_deployment_safety_snapshot_v1(
        "request-release-0001", "challenge-release-0001"
    )

    assert "release_deployment_snapshot_v1" not in server.registered
    with pytest.raises(WindowsRpcDeploymentSnapshotError, match="frozen"):
        server.registered["cancel_order"]("cancel", "CTP")


def test_frozen_snapshot_rejects_a_different_challenge() -> None:
    extension, _ = install(SyncEventEngine(), FactSource())
    extension.get_deployment_safety_snapshot_v1(
        "request-challenge-0001", "challenge-owner-0001"
    )

    with pytest.raises(WindowsRpcDeploymentSnapshotError, match="another request"):
        extension.get_deployment_safety_snapshot_v1(
            "request-challenge-0001", "challenge-attacker-0001"
        )


def test_import_and_registration_do_not_require_vnpy_when_factory_is_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    original_import = __import__

    def guarded_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("vnpy"):
            imported.append(name)
            raise AssertionError("vnpy must not be imported")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", guarded_import)
    extension, _ = install(SyncEventEngine(), FactSource())
    assert extension.get_deployment_safety_snapshot_v1(
        "request-import-0001", "challenge-import-0001"
    )["fact_generation"] == 0
    assert imported == []
