from __future__ import annotations

import pytest

from app.core.errors import RpcCallError, RpcTimeoutError
from app.services.vnpy_rpc_service import VnpyRpcService
from app.stores.memory_store import memory_store


class TimeoutClient:
    def get_all_contracts(self, *, timeout: int):
        raise TimeoutError("timeout")


class BrokenClient:
    def get_all_contracts(self, *, timeout: int):
        raise RuntimeError("boom")


class ProbeClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_all_accounts(self, *, timeout: int):
        self.calls += 1
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


def test_rpc_call_timeout_is_normalized() -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = TimeoutClient()  # type: ignore[assignment]

    with pytest.raises(RpcTimeoutError):
        service.call("get_all_contracts", timeout=1)


def test_rpc_call_error_is_normalized() -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = BrokenClient()  # type: ignore[assignment]

    with pytest.raises(RpcCallError):
        service.call("get_all_contracts", timeout=1)


def test_rpc_status_probe_marks_connection_false_on_probe_failure() -> None:
    service = VnpyRpcService()
    service.started = True
    service.client = TimeoutClient()  # type: ignore[assignment]

    status = service.status(probe=True)

    assert status["connected"] is False
    assert status["last_error"]


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

    service.handle_event("", TickEvent())

    tick = memory_store.get_tick("UNIT999.SHFE")
    assert tick
    assert tick["vt_symbol"] == "UNIT999.SHFE"
    assert tick["last_price"] == 3126
