from __future__ import annotations

import pytest

from app.core.errors import StrategyInvalidSettingError, StrategyNotFoundError, StrategyRpcMethodNotAvailableError, TradeDisabledError
from app.schemas.strategy import StrategySettingDTO
from app.services.risk_service import risk_service
from app.services.strategy_service import StrategyService
from app.services.vnpy_rpc_service import rpc_service


def install_strategy_rpc(monkeypatch, calls: list[tuple[str, tuple]]) -> None:
    def fake_call(name: str, *args, **kwargs):
        calls.append((name, args))
        if name in {"get_all_strategy_status", "get_strategy_status", "get_all_strategies"}:
            return [
                {
                    "strategy_name": "ma_demo",
                    "class_name": "MaStrategy",
                    "vt_symbol": "rb2610.SHFE",
                    "inited": True,
                    "trading": False,
                }
            ]
        if name in {"get_strategy_parameters", "get_strategy_setting", "get_strategy_config"}:
            return {"fast_window": 10}
        if name in {"get_strategy_variables", "get_strategy_variable"}:
            return {"pos": 0}
        if name in {"init_strategy", "start_strategy", "stop_strategy", "edit_strategy"}:
            return True
        raise RuntimeError(name)

    monkeypatch.setattr(rpc_service, "call", fake_call)


def test_list_and_detail_strategy(monkeypatch) -> None:
    calls: list[tuple[str, tuple]] = []
    install_strategy_rpc(monkeypatch, calls)

    service = StrategyService()

    strategies = service.list_strategies()
    detail = service.get_strategy("ma_demo")

    assert strategies[0]["strategy_name"] == "ma_demo"
    assert detail["setting"]["fast_window"] == 10
    assert detail["variables"]["pos"] == 0


def test_strategy_not_found(monkeypatch) -> None:
    calls: list[tuple[str, tuple]] = []
    install_strategy_rpc(monkeypatch, calls)

    with pytest.raises(StrategyNotFoundError):
        StrategyService().get_strategy("missing")


def test_empty_setting_rejected() -> None:
    import asyncio

    async def run() -> None:
        await StrategyService().update_setting(
            "ma_demo",
            StrategySettingDTO(setting={}),
            user_id="admin",
            role="admin",
        )

    with pytest.raises(StrategyInvalidSettingError):
        asyncio.run(run())


def test_missing_rpc_method_is_explicit(monkeypatch) -> None:
    monkeypatch.setattr(rpc_service, "call", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("missing")))

    with pytest.raises(StrategyRpcMethodNotAvailableError):
        StrategyService().list_strategies()


def test_start_strategy_requires_risk_trade_enabled(monkeypatch) -> None:
    import asyncio

    async def run() -> None:
        await StrategyService().start_strategy("ma_demo", user_id="admin", role="admin")

    calls: list[tuple[str, tuple]] = []
    install_strategy_rpc(monkeypatch, calls)
    monkeypatch.setattr(rpc_service, "status", lambda: {"connected": True})
    risk_service.disable_trade()

    with pytest.raises(TradeDisabledError):
        asyncio.run(run())
