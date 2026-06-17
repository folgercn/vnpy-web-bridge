from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.errors import OrderConfirmRequiredError, OrderNotCancelableError, OrderNotFoundError, TradeDisabledError
from app.schemas.trade import CancelAllRequestDTO, CancelRequestDTO, OrderRequestDTO
from app.services.audit_service import AuditService
from app.services.risk_service import RiskService
from app.services.trade_service import TradeService, is_cancelable_status, normalize_status
from app.services.vnpy_rpc_service import rpc_service
from vnpy.trader.constant import Direction, Exchange, Offset, OrderType, Status


class FakeOrder:
    def __init__(
        self,
        vt_orderid: str = "CTP.1",
        status: Status = Status.NOTTRADED,
        symbol: str = "rb2610",
        exchange: Exchange = Exchange.SHFE,
        gateway_name: str = "CTP",
    ) -> None:
        self.vt_orderid = vt_orderid
        self.status = status
        self.symbol = symbol
        self.exchange = exchange
        self.gateway_name = gateway_name

    def create_cancel_request(self) -> dict:
        return {"vt_orderid": self.vt_orderid}


def make_service(tmp_path: Path, *, enabled: bool = True, confirm_required: bool = True) -> TradeService:
    settings = Settings(
        web_trade_enabled=enabled,
        order_confirm_required=confirm_required,
        default_gateway_name="CTP",
        trade_reference_prefix="test_ref",
    )
    return TradeService(
        settings=settings,
        audit=AuditService(tmp_path / "audit.log"),
        risk=RiskService(settings),
    )


def make_order(**kwargs) -> OrderRequestDTO:
    data = {
        "symbol": "rb2610",
        "exchange": "SHFE",
        "direction": "long",
        "offset": "open",
        "type": "limit",
        "price": 3000,
        "volume": 1,
        "confirm": True,
    }
    data.update(kwargs)
    return OrderRequestDTO(**data)


def test_order_request_converts_to_vnpy_order_request(tmp_path) -> None:
    service = make_service(tmp_path)

    req = service.to_vnpy_order_request(make_order())

    assert req.symbol == "rb2610"
    assert req.exchange == Exchange.SHFE
    assert req.direction == Direction.LONG
    assert req.offset == Offset.OPEN
    assert req.type == OrderType.LIMIT
    assert req.reference.startswith("test_ref_")


def test_trade_disabled_rejects_before_rpc(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path, enabled=False)
    monkeypatch.setattr(rpc_service, "send_order", lambda *_: pytest.fail("RPC should not be called"))

    with pytest.raises(TradeDisabledError):
        service.send_order(make_order())


def test_confirm_required_rejects_before_rpc(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path, enabled=True, confirm_required=True)
    monkeypatch.setattr(rpc_service, "send_order", lambda *_: pytest.fail("RPC should not be called"))

    with pytest.raises(OrderConfirmRequiredError):
        service.send_order(make_order(confirm=False))


def test_send_order_returns_vt_orderid(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path)
    monkeypatch.setattr(rpc_service, "send_order", lambda *_: "CTP.123")
    monkeypatch.setattr(rpc_service, "status", lambda: {"connected": True})
    monkeypatch.setattr(rpc_service, "get_positions", lambda: [])
    monkeypatch.setattr(rpc_service, "get_contracts", lambda: [{"vt_symbol": "rb2610.SHFE", "pricetick": 1}])

    result = service.send_order(make_order())

    assert result == {"vt_orderid": "CTP.123", "accepted": True}


def test_status_mapping_and_cancelable_status() -> None:
    assert normalize_status(Status.NOTTRADED) == "not_traded"
    assert normalize_status(Status.CANCELLED) == "cancelled"
    assert is_cancelable_status(Status.PARTTRADED) is True
    assert is_cancelable_status(Status.ALLTRADED) is False


def test_cancel_order_not_found(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path)
    monkeypatch.setattr(rpc_service, "get_order_raw", lambda _: None)

    with pytest.raises(OrderNotFoundError):
        service.cancel_order("CTP.missing", CancelRequestDTO())


def test_cancel_order_not_cancelable(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path)
    monkeypatch.setattr(rpc_service, "get_order_raw", lambda _: FakeOrder(status=Status.ALLTRADED))

    with pytest.raises(OrderNotCancelableError):
        service.cancel_order("CTP.done", CancelRequestDTO())


def test_cancel_all_returns_partial_failures(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path)
    orders = [FakeOrder(vt_orderid="CTP.1"), FakeOrder(vt_orderid="CTP.2")]
    monkeypatch.setattr(rpc_service, "get_active_orders_raw", lambda: orders)

    def cancel(cancel_request, gateway_name):
        if cancel_request["vt_orderid"] == "CTP.2":
            raise RuntimeError("cancel failed")

    monkeypatch.setattr(rpc_service, "cancel_order", cancel)

    result = service.cancel_all(CancelAllRequestDTO())

    assert result["requested"] == 2
    assert result["success"] == 1
    assert result["failed"] == 1
    assert result["items"][1]["error"] == "cancel failed"


def test_cancel_all_can_bypass_trade_check_for_emergency_stop(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path, enabled=False)
    monkeypatch.setattr(rpc_service, "get_active_orders_raw", lambda: [])

    result = service.cancel_all(CancelAllRequestDTO(), bypass_trade_check=True)

    assert result["requested"] == 0
