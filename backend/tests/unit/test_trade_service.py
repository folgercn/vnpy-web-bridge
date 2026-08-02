from __future__ import annotations

from pathlib import Path
from threading import RLock
from types import MethodType

import pytest

from app.core.config import Settings
from app.core.errors import OrderConfirmRequiredError, OrderNotCancelableError, OrderNotFoundError, TradeDisabledError
from app.schemas.trade import CancelAllRequestDTO, CancelRequestDTO, OrderRequestDTO
from app.services.audit_service import AuditService
from app.services.commodity_simnow import CommoditySimNowService
from app.services.risk_service import RiskService
from app.services.trade_service import (
    TradeService,
    _CFastOrderVolumeCapability,
    is_cancelable_status,
    normalize_status,
)
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


def test_pre_rpc_guard_runs_after_risk_and_immediately_before_send(
    monkeypatch,
    tmp_path,
) -> None:
    service = make_service(tmp_path)
    events: list[str] = []
    monkeypatch.setattr(
        service.risk,
        "check_order",
            lambda _payload, **_kwargs: events.append("risk"),
    )
    monkeypatch.setattr(
        rpc_service,
        "send_order",
        lambda *_args: (
            events.append("send") or "CTP.123"
        ),
    )

    service.send_order(
        make_order(),
        pre_rpc_guard=lambda: events.append("guard"),
    )

    assert events == ["risk", "guard", "send"]


def test_public_send_cannot_select_a_volume_override(
    monkeypatch,
    tmp_path,
) -> None:
    service = make_service(tmp_path)
    events: list[str] = []
    monkeypatch.setattr(
        rpc_service,
        "send_order",
        lambda *_args: (
            events.append("send") or "CTP.123"
        ),
    )
    monkeypatch.setattr(
        rpc_service, "status", lambda: {"connected": True}
    )
    monkeypatch.setattr(rpc_service, "get_positions", lambda: [])
    monkeypatch.setattr(
        rpc_service,
        "get_contracts",
        lambda: [
            {"vt_symbol": "rb2610.SHFE", "pricetick": 1}
        ],
    )

    with pytest.raises(TypeError):
        service.send_order(
            make_order(volume=2),
            max_order_volume_override=0,  # type: ignore[call-arg]
            pre_rpc_guard=lambda: events.append("final"),
        )

    assert events == []


def test_c_fast_volume_capability_cannot_be_forged_or_misused(
    tmp_path,
) -> None:
    service = make_service(tmp_path)

    with pytest.raises(TypeError, match="cannot be constructed"):
        _CFastOrderVolumeCapability(
            object(), construction_key=object()
        )

    with pytest.raises(RuntimeError, match="capability is invalid"):
        service._send_c_fast_order(
            make_order(
                reference=(
                    "commodity_cf:sh:0123456789abcdef:open:ag2610:1"
                )
            ),
            c_fast_order_owner=object(),
            c_fast_order_volume_capability=object(),
            pre_rpc_guard=lambda: None,
            send_linearization_lock=object(),
        )

    with pytest.raises(RuntimeError, match="capability is invalid"):
        service._send_order(
            make_order(),
            source_ip=None,
            operator="test",
            pre_rpc_guard=None,
            send_linearization_lock=None,
            c_fast_order_owner=None,
            c_fast_order_volume_capability=object(),
        )


def _capability_test_owner() -> CommoditySimNowService:
    owner = object.__new__(CommoditySimNowService)
    owner._dispatch_abort_lock = RLock()
    return owner


def test_c_fast_capability_rejects_unregistered_object_new_owner(
    tmp_path,
) -> None:
    service = make_service(tmp_path)
    owner = _capability_test_owner()
    owner.trade = service

    with pytest.raises(TypeError, match="owner is invalid"):
        service._bind_c_fast_order_volume_capability(owner)


def test_c_fast_capability_binds_exact_owner_guard_and_lock(
    tmp_path,
) -> None:
    owner = _capability_test_owner()
    wrong_owner = _capability_test_owner()
    settings = Settings(
        web_trade_enabled=True,
        order_confirm_required=True,
        default_gateway_name="CTP",
        trade_reference_prefix="test_ref",
    )
    service = TradeService(
        settings=settings,
        audit=AuditService(tmp_path / "audit.log"),
        risk=RiskService(settings),
        _c_fast_capability_issuers=(owner, wrong_owner),
    )
    owner.trade = service
    wrong_owner.trade = service
    capability = service._bind_c_fast_order_volume_capability(owner)
    request = make_order(
        reference=(
            "commodity_cf:sh:0123456789abcdef:open:ag2610:1"
        )
    )

    with pytest.raises(RuntimeError, match="capability is invalid"):
        service._send_c_fast_order(
            request,
            c_fast_order_owner=wrong_owner,
            c_fast_order_volume_capability=capability,
            pre_rpc_guard=wrong_owner._c_fast_pre_rpc_guard,
            send_linearization_lock=wrong_owner._dispatch_abort_lock,
        )

    with pytest.raises(RuntimeError, match="guarded-send contract"):
        service._send_c_fast_order(
            request,
            c_fast_order_owner=owner,
            c_fast_order_volume_capability=capability,
            pre_rpc_guard=MethodType(lambda _owner: None, owner),
            send_linearization_lock=owner._dispatch_abort_lock,
        )

    with pytest.raises(RuntimeError, match="guarded-send contract"):
        service._send_c_fast_order(
            request,
            c_fast_order_owner=owner,
            c_fast_order_volume_capability=capability,
            pre_rpc_guard=owner._c_fast_pre_rpc_guard,
            send_linearization_lock=RLock(),
        )

    owner.trade = object()
    with pytest.raises(RuntimeError, match="capability is invalid"):
        service._send_c_fast_order(
            request,
            c_fast_order_owner=owner,
            c_fast_order_volume_capability=capability,
            pre_rpc_guard=owner._c_fast_pre_rpc_guard,
            send_linearization_lock=owner._dispatch_abort_lock,
        )


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


def test_cancel_order_can_bypass_trade_check_for_emergency_stop(monkeypatch, tmp_path) -> None:
    service = make_service(tmp_path, enabled=False)
    monkeypatch.setattr(rpc_service, "get_order_raw", lambda _: FakeOrder())
    calls = []
    monkeypatch.setattr(
        rpc_service,
        "cancel_order",
        lambda request, gateway: calls.append((request, gateway)),
    )

    result = service.cancel_order("CTP.1", bypass_trade_check=True)

    assert result["cancel_requested"] is True
    assert calls == [({"vt_orderid": "CTP.1"}, "CTP")]


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
