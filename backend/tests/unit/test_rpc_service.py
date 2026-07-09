from __future__ import annotations

import pytest

from app.core.errors import RpcCallError, RpcTimeoutError, RpcUnavailableError
from app.services.vnpy_rpc_service import VnpyRpcService
from app.stores.memory_store import memory_store


class TimeoutClient:
    def get_all_contracts(self, *, timeout: int):
        raise TimeoutError("timeout")


class TimeoutRestartClient:
    def __init__(self) -> None:
        self.stopped = False
        self.joined = False

    def get_all_contracts(self, *, timeout: int):
        raise TimeoutError("timeout")

    def stop(self) -> None:
        self.stopped = True

    def join(self) -> None:
        self.joined = True


class BrokenClient:
    def get_all_contracts(self, *, timeout: int):
        raise RuntimeError("boom")


class BadStateClient:
    def __init__(self) -> None:
        self.stopped = False
        self.joined = False

    def get_all_contracts(self, *, timeout: int):
        raise RuntimeError("Operation cannot be accomplished in current state")

    def send_order(self, *args, timeout: int):
        raise RuntimeError("Operation cannot be accomplished in current state")

    def stop(self) -> None:
        self.stopped = True

    def join(self) -> None:
        self.joined = True


class HealthyClient:
    def get_all_contracts(self, *, timeout: int):
        return [{"symbol": "rb2610"}]


class ProbeClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_all_accounts(self, *, timeout: int):
        self.calls += 1
        return []


class FlakyProbeClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_all_accounts(self, *, timeout: int):
        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("timeout")
        return []


class TickEvent:
    type = "eTick.UNIT999.SHFE"

    def __init__(self) -> None:
        self.data = TickPayload()


class TickPayload:
    def __init__(self) -> None:
        self.symbol = "UNIT999"
        self.exchange = "SHFE"
        self.last_price = 3126

    @property
    def vt_symbol(self) -> str:
        return f"{self.symbol}.{self.exchange}"


def test_rpc_call_timeout_is_normalized(monkeypatch) -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = TimeoutClient()  # type: ignore[assignment]
    monkeypatch.setattr(service, "start", lambda: (_ for _ in ()).throw(RpcUnavailableError("start failed")))

    with pytest.raises(RpcTimeoutError):
        service.call("get_all_contracts", timeout=1)


def test_rpc_call_timeout_rebuilds_client_before_next_request(monkeypatch) -> None:
    service = VnpyRpcService()
    client = TimeoutRestartClient()
    service.started = True
    service.client = client  # type: ignore[assignment]
    service._last_probe_at = 123.0
    service._last_probe_connected = False

    def start() -> None:
        service.started = True
        service.client = HealthyClient()  # type: ignore[assignment]
        service.last_error = None

    monkeypatch.setattr(service, "start", start)

    with pytest.raises(RpcTimeoutError):
        service.call("get_all_contracts", timeout=1)

    assert client.stopped is True
    assert client.joined is True
    assert isinstance(service.client, HealthyClient)
    assert service.started is True
    assert service._last_probe_at == 0.0
    assert service._last_probe_connected is None


def test_rpc_call_error_is_normalized() -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = BrokenClient()  # type: ignore[assignment]

    with pytest.raises(RpcCallError):
        service.call("get_all_contracts", timeout=1)


def test_rpc_call_reconnects_and_retries_idempotent_bad_client_state(monkeypatch) -> None:
    service = VnpyRpcService()
    client = BadStateClient()
    service.started = True
    service.client = client  # type: ignore[assignment]

    def start() -> None:
        service.started = True
        service.client = HealthyClient()  # type: ignore[assignment]

    monkeypatch.setattr(service, "start", start)

    result = service.call("get_all_contracts", timeout=1)

    assert result == [{"symbol": "rb2610"}]
    assert client.stopped is True
    assert client.joined is True
    assert service.last_error is None


def test_rpc_call_rebuilds_but_does_not_retry_non_idempotent_bad_client_state(monkeypatch) -> None:
    service = VnpyRpcService()
    client = BadStateClient()
    service.started = True
    service.client = client  # type: ignore[assignment]

    def start() -> None:
        service.started = True
        service.client = HealthyClient()  # type: ignore[assignment]

    monkeypatch.setattr(service, "start", start)

    with pytest.raises(RpcCallError) as exc_info:
        service.call("send_order", object(), "CTP", timeout=1)

    assert client.stopped is True
    assert client.joined is True
    assert exc_info.value.detail["client_rebuilt"] is True
    assert exc_info.value.detail["retry_suppressed"] == "non_idempotent_method"


def test_rpc_restart_client_clears_state_when_start_fails(monkeypatch) -> None:
    service = VnpyRpcService()
    client = TimeoutRestartClient()
    service.started = True
    service.client = client  # type: ignore[assignment]
    service._last_probe_at = 123.0
    service._last_probe_connected = False

    def start() -> None:
        service.started = False
        service.client = None
        raise RpcUnavailableError("start failed")

    monkeypatch.setattr(service, "start", start)

    with pytest.raises(RpcUnavailableError):
        service._restart_client()

    assert client.stopped is True
    assert client.joined is True
    assert service.started is False
    assert service.client is None
    assert service._last_probe_at == 0.0
    assert service._last_probe_connected is None


def test_rpc_status_probe_marks_connection_false_on_probe_failure(monkeypatch) -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = TimeoutClient()  # type: ignore[assignment]
    monkeypatch.setattr(service, "start", lambda: (_ for _ in ()).throw(RpcUnavailableError("start failed")))

    status = service.status(probe=True)

    assert status["connected"] is False
    assert status["last_error"]


def test_rpc_status_probe_recovers_after_single_timeout(monkeypatch) -> None:
    service = VnpyRpcService()
    client = FlakyProbeClient()
    service.started = True
    service.client = client  # type: ignore[assignment]
    service._probe_ttl_seconds = 0

    def start() -> None:
        service.started = True
        service.client = client  # type: ignore[assignment]

    monkeypatch.setattr(service, "start", start)

    failed = service.status(probe=True)
    recovered = service.status(probe=True)

    assert failed["connected"] is False
    assert recovered["connected"] is True
    assert recovered["last_error"] is None
    assert service.started is True
    assert client.calls == 2


def test_rpc_status_probe_uses_ttl() -> None:
    service = VnpyRpcService()
    client = ProbeClient()
    service.started = True
    service.client = client  # type: ignore[assignment]

    service.status(probe=True)
    service.status(probe=True)

    assert client.calls == 1


def test_handle_tick_event_saves_computed_vt_symbol() -> None:
    service = VnpyRpcService()
    service._market_subscriptions.add("UNIT999.SHFE")

    service.handle_event("", TickEvent())

    tick = memory_store.get_tick("UNIT999.SHFE")
    assert tick
    assert tick["vt_symbol"] == "UNIT999.SHFE"
    assert tick["last_price"] == 3126


def test_handle_tick_event_ignores_unsubscribed_symbol() -> None:
    service = VnpyRpcService()
    memory_store.delete_tick("UNIT999.SHFE")

    service.handle_event("", TickEvent())

    assert memory_store.get_tick("UNIT999.SHFE") is None


def test_handle_tick_event_enqueues_unsubscribed_symbol_for_persistence(monkeypatch) -> None:
    saved: list[dict] = []
    monkeypatch.setattr("app.services.vnpy_rpc_service.tick_persistence_service.enqueue_tick", saved.append)
    service = VnpyRpcService()

    service.handle_event("", TickEvent())

    assert saved[0]["vt_symbol"] == "UNIT999.SHFE"


def test_unsubscribe_market_removes_subscription_and_tick() -> None:
    service = VnpyRpcService()
    service._market_subscriptions.add("UNIT999.SHFE")
    memory_store.save_tick("UNIT999.SHFE", {"vt_symbol": "UNIT999.SHFE"})

    result = service.unsubscribe_market("UNIT999", "SHFE")

    assert result["subscribed"] is False
    assert result["vt_symbol"] == "UNIT999.SHFE"
    assert memory_store.get_tick("UNIT999.SHFE") is None
    assert "UNIT999.SHFE" not in service._market_subscriptions
