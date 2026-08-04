from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from app.core.config import Settings
from app.core.errors import (
    ClosePositionNotEnoughError,
    DeploymentDrainActiveError,
    RiskExchangeNotAllowedError,
    RiskMaxOrderVolumeError,
    RiskPriceProtectionError,
    RiskSymbolBlockedError,
    RiskTradingTimeError,
    TradeDisabledError,
)
from app.schemas.risk import RiskRulesPatchDTO
from app.schemas.trade import OrderRequestDTO
from app.services.deployment_drain import DeploymentDrainError
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


class FakeDeploymentDrain:
    def __init__(self, state: str = "RUNNING") -> None:
        self.state = state
        self.guard_entries = 0

    @contextmanager
    def mutation_guard(self) -> Iterator[dict[str, str]]:
        self.guard_entries += 1
        if self.state != "RUNNING":
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_ACTIVE", "sensitive internal path omitted"
            )
        yield {"state": self.state}

    def status(self) -> dict[str, str]:
        return {"state": self.state}


def allow_rpc(monkeypatch, *, contracts: list[dict] | None = None) -> None:
    monkeypatch.setattr(rpc_service, "status", lambda: {"connected": True})
    monkeypatch.setattr(rpc_service, "get_positions", list)
    monkeypatch.setattr(
        rpc_service,
        "get_contracts",
        lambda: contracts or [{"symbol": "rb2610", "exchange": "SHFE", "vt_symbol": "rb2610.SHFE", "pricetick": 1}],
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


def test_frozen_drain_blocks_positive_risk_mutations_without_state_change() -> None:
    drain = FakeDeploymentDrain("DRAINING")
    service = RiskService(
        Settings(web_trade_enabled=False, risk_max_order_volume=1),
        deployment_drain=drain,  # type: ignore[arg-type]
    )
    rules_before = service.get_rules()

    with pytest.raises(DeploymentDrainActiveError) as enable_error:
        service.enable_trade()
    with pytest.raises(DeploymentDrainActiveError) as rules_error:
        service.update_rules(RiskRulesPatchDTO(max_order_volume=9))

    assert enable_error.value.detail == {"gate_code": "DEPLOYMENT_DRAIN_ACTIVE"}
    assert rules_error.value.detail == {"gate_code": "DEPLOYMENT_DRAIN_ACTIVE"}
    assert service.web_trade_enabled is False
    assert service.get_rules() == rules_before
    assert service.rules_version == 1
    assert drain.guard_entries == 2


def test_frozen_drain_allows_disable_emergency_and_status() -> None:
    drain = FakeDeploymentDrain("SAFE_TO_RESTART")
    service = RiskService(
        Settings(web_trade_enabled=True),
        deployment_drain=drain,  # type: ignore[arg-type]
    )

    disabled = service.disable_trade()
    stopped = service.emergency_stop()

    assert disabled["web_trade_enabled"] is False
    assert stopped["web_trade_enabled"] is False
    assert stopped["emergency_stopped"] is True
    assert service.status() == stopped
    assert drain.guard_entries == 0


def test_running_drain_preserves_positive_risk_behavior() -> None:
    drain = FakeDeploymentDrain()
    service = RiskService(
        Settings(web_trade_enabled=False, risk_max_order_volume=1),
        deployment_drain=drain,  # type: ignore[arg-type]
    )

    enabled = service.enable_trade()
    rules = service.update_rules(RiskRulesPatchDTO(max_order_volume=3))

    assert enabled["web_trade_enabled"] is True
    assert rules["max_order_volume"] == 3
    assert service.rules_version == 2
    assert drain.guard_entries == 2


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


def test_public_risk_entry_rejects_volume_override(
    monkeypatch,
) -> None:
    service = make_service(max_order_volume=1)
    allow_rpc(monkeypatch)
    service.rules["max_symbol_position"] = 0

    with pytest.raises(RiskMaxOrderVolumeError):
        service.check_order(make_order(volume=20))

    with pytest.raises(TypeError):
        service.check_order(
            make_order(volume=20),
            max_order_volume_override=0,  # type: ignore[call-arg]
        )


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
    monkeypatch.setattr(rpc_service, "get_contracts", list)

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


def test_trading_time_check_rejects_legal_holiday(monkeypatch) -> None:
    service = make_service()
    service.update_rules(RiskRulesPatchDTO(trading_time_check_enabled=True))
    allow_rpc(monkeypatch)
    monkeypatch.setattr(
        "app.services.risk_service.calendar_service.trading_session_status",
        lambda now, symbols: {"active": False, "trading_day": "2026-02-16", "session": "day", "reason": "holiday"},
    )

    with pytest.raises(RiskTradingTimeError):
        service.check_order(make_order())


def test_trading_time_check_rejects_inactive_symbol_session(monkeypatch) -> None:
    service = make_service()
    service.update_rules(RiskRulesPatchDTO(trading_time_check_enabled=True))
    allow_rpc(monkeypatch)
    monkeypatch.setattr(
        "app.services.risk_service.calendar_service.trading_session_status",
        lambda now, symbols: {"active": False, "trading_day": "2026-06-18", "session": None, "reason": "closed"},
    )

    with pytest.raises(RiskTradingTimeError) as exc:
        service.check_order(make_order())

    assert exc.value.detail["session_active"] is False


def test_trading_time_check_allows_sunday_night_for_next_trading_day(monkeypatch) -> None:
    service = make_service()
    service.update_rules(RiskRulesPatchDTO(trading_time_check_enabled=True))
    allow_rpc(
        monkeypatch,
        contracts=[{"symbol": "au2612", "exchange": "SHFE", "vt_symbol": "au2612.SHFE", "pricetick": 1}],
    )
    fixed_now = datetime(2026, 6, 21, 13, 30, tzinfo=timezone.utc)  # Sunday 21:30 Asia/Shanghai

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now.astimezone(tz) if tz else fixed_now

    monkeypatch.setattr("app.services.risk_service.datetime", FixedDatetime)

    service.check_order(make_order(symbol="au2612"))


def test_trading_time_check_rejects_friday_night_without_next_trading_day(monkeypatch) -> None:
    service = make_service()
    service.update_rules(RiskRulesPatchDTO(trading_time_check_enabled=True))
    allow_rpc(
        monkeypatch,
        contracts=[{"symbol": "au2612", "exchange": "SHFE", "vt_symbol": "au2612.SHFE", "pricetick": 1}],
    )
    fixed_now = datetime(2026, 6, 19, 13, 30, tzinfo=timezone.utc)  # Friday 21:30 Asia/Shanghai

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now.astimezone(tz) if tz else fixed_now

    monkeypatch.setattr("app.services.risk_service.datetime", FixedDatetime)

    with pytest.raises(RiskTradingTimeError) as exc:
        service.check_order(make_order(symbol="au2612"))

    assert exc.value.detail["date"] == "2026-06-20"
    assert exc.value.detail["reason"] == "next_trading_day"
