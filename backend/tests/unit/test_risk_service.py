from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import (
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


def make_service() -> RiskService:
    return RiskService(
        Settings(
            web_trade_enabled=True,
            risk_max_order_volume=1,
            risk_allowed_exchanges="SHFE",
            risk_blocked_symbols="bad",
            risk_price_protection_percent=3,
        )
    )


def allow_rpc(monkeypatch) -> None:
    monkeypatch.setattr(rpc_service, "status", lambda: {"connected": True})
    monkeypatch.setattr(rpc_service, "get_positions", lambda: [])


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


def test_price_protection(monkeypatch) -> None:
    service = make_service()
    allow_rpc(monkeypatch)
    memory_store.save_tick("rb2610.SHFE", {"last_price": 3000})

    with pytest.raises(RiskPriceProtectionError):
        service.check_order(make_order(price=3300))
