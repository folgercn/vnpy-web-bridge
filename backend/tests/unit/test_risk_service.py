from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import (
    ClosePositionNotEnoughError,
    RiskExchangeNotAllowedError,
    RiskMaxOrderVolumeError,
    RiskPriceProtectionError,
    RiskSymbolBlockedError,
    TradeDisabledError,
)
from app.schemas.risk import RiskRulesPatchDTO
from app.schemas.trade import OrderRequestDTO
from app.services.risk_service import RiskService
from app.services.vnpy_rpc_service import rpc_service
from app.stores.memory_store import memory_store


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


def make_service(*, max_order_volume: int = 1) -> RiskService:
    return RiskService(
        Settings(
            web_trade_enabled=True,
            risk_max_order_volume=max_order_volume,
            risk_allowed_exchanges="SHFE",
            risk_blocked_symbols="bad",
            risk_price_protection_percent=3,
        )
    )


def allow_rpc(monkeypatch) -> None:
    monkeypatch.setattr(rpc_service, "status", lambda: {"connected": True})
    monkeypatch.setattr(rpc_service, "get_positions", lambda: [])
    monkeypatch.setattr(
        rpc_service,
        "get_contracts",
        lambda: [{"symbol": "rb2610", "exchange": "SHFE", "vt_symbol": "rb2610.SHFE", "pricetick": 1}],
    )


def test_trade_disabled() -> None:
    service = RiskService(Settings(web_trade_enabled=False))

    with pytest.raises(TradeDisabledError):
        service.check_trade_allowed(confirm=True)


def test_update_rules_bumps_version() -> None:
    service = make_service()

    result = service.update_rules(RiskRulesPatchDTO(max_order_volume=2))

    assert result["max_order_volume"] == 2
    assert service.status()["rules_version"] == 2


def test_exchange_not_allowed(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)

    with pytest.raises(RiskExchangeNotAllowedError):
        service.check_order(make_order(exchange="DCE"))


def test_symbol_blocked(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)

    with pytest.raises(RiskSymbolBlockedError):
        service.check_order(make_order(symbol="bad"))


def test_max_order_volume(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)

    with pytest.raises(RiskMaxOrderVolumeError):
        service.check_order(make_order(volume=2))


def test_fractional_volume_is_rejected_by_schema() -> None:
    with pytest.raises(ValueError):
        make_order(volume=1.5)


def test_price_protection(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)
    memory_store.save_tick("rb2610.SHFE", {"last_price": 3000})

    with pytest.raises(RiskPriceProtectionError):
        service.check_order(make_order(price=3300))


def test_missing_contract_rejects_order(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)
    monkeypatch.setattr(rpc_service, "get_contracts", lambda: [])

    with pytest.raises(RiskSymbolBlockedError):
        service.check_order(make_order())


def test_close_order_does_not_apply_position_limit(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)
    monkeypatch.setattr(rpc_service, "get_positions", lambda: [{"vt_symbol": "rb2610.SHFE", "direction": "空", "volume": 5}])

    service.check_order(make_order(offset="close"))


def test_close_order_rejects_when_position_not_enough(monkeypatch) -> None:
    service = make_service(max_order_volume=5)
    allow_rpc(monkeypatch)
    monkeypatch.setattr(rpc_service, "get_positions", lambda: [{"vt_symbol": "rb2610.SHFE", "direction": "空", "volume": 1}])

    with pytest.raises(ClosePositionNotEnoughError):
        service.check_order(make_order(offset="close", volume=2))


def test_close_today_checks_today_position(monkeypatch) -> None:
    service = make_service(max_order_volume=5)
    allow_rpc(monkeypatch)
    monkeypatch.setattr(rpc_service, "get_positions", lambda: [{"vt_symbol": "rb2610.SHFE", "direction": "空", "volume": 3, "yd_volume": 2}])

    service.check_order(make_order(offset="closetoday", volume=1))

    with pytest.raises(ClosePositionNotEnoughError):
        service.check_order(make_order(offset="closetoday", volume=2))


def test_price_must_match_contract_tick(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)

    with pytest.raises(RiskPriceProtectionError):
        service.check_order(make_order(price=3000.5))
