from __future__ import annotations

import pytest

from app.core.errors import RpcCallError, RpcTimeoutError
from app.services.vnpy_rpc_service import VnpyRpcService


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
