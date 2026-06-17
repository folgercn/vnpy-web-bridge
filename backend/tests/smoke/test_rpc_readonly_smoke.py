from __future__ import annotations

import os

import pytest

from app.services.vnpy_rpc_service import VnpyRpcService


@pytest.mark.skipif(
    not os.getenv("VNPY_RPC_REQ_ADDRESS") or not os.getenv("VNPY_RPC_PUB_ADDRESS"),
    reason="需要配置 VNPY_RPC_REQ_ADDRESS 和 VNPY_RPC_PUB_ADDRESS",
)
def test_rpc_readonly_smoke() -> None:
    service = VnpyRpcService()
    service.start()
    try:
        assert isinstance(service.get_contracts(), list)
        assert isinstance(service.get_accounts(), list)
        assert isinstance(service.get_positions(), list)
    finally:
        service.stop()
