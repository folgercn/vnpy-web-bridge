from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.config import Settings, get_settings
from app.core.errors import (
    ClosePositionNotEnoughError,
    OrderConfirmRequiredError,
    RiskDailyLossLimitError,
    RiskExchangeNotAllowedError,
    RiskMaxOrderVolumeError,
    RiskMaxSymbolPositionError,
    RiskPriceProtectionError,
    RiskSymbolBlockedError,
    RiskTradingTimeError,
    RpcUnavailableError,
    TradeDisabledError,
)
from app.schemas.risk import RiskRulesPatchDTO
from app.schemas.trade import OrderRequestDTO
from app.services.calendar_service import CHINA_TZ, calendar_service
from app.services.vnpy_rpc_service import rpc_service
from app.stores.memory_store import memory_store


class RiskService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.web_trade_enabled = self.settings.web_trade_enabled
        self.emergency_stopped = False
        self.rules_version = 1
        self.rules = {
            "max_order_volume": self.settings.risk_max_order_volume,
            "max_symbol_position": self.settings.risk_max_symbol_position,
            "max_daily_loss": self.settings.risk_max_daily_loss,
            "price_protection_percent": self.settings.risk_price_protection_percent,
            "allowed_exchanges": _csv(self.settings.risk_allowed_exchanges),
            "allowed_symbols": _csv(self.settings.risk_allowed_symbols),
            "blocked_symbols": _csv(self.settings.risk_blocked_symbols),
            "trading_time_check_enabled": self.settings.risk_trading_time_check_enabled,
        }

    def status(self) -> dict[str, Any]:
        return {
            "risk_enabled": True,
            "web_trade_enabled": self.web_trade_enabled,
            "emergency_stopped": self.emergency_stopped,
            "rules_version": self.rules_version,
        }

    def get_rules(self) -> dict[str, Any]:
        return dict(self.rules)

    def update_rules(self, patch: RiskRulesPatchDTO) -> dict[str, Any]:
        data = patch.model_dump(exclude_none=True)
        if data:
            self.rules.update(data)
            self.rules_version += 1
        return self.get_rules()

    def enable_trade(self) -> dict[str, Any]:
        self.web_trade_enabled = True
        self.emergency_stopped = False
        return self.status()

    def disable_trade(self) -> dict[str, Any]:
        self.web_trade_enabled = False
        return self.status()

    def emergency_stop(self) -> dict[str, Any]:
        self.web_trade_enabled = False
        self.emergency_stopped = True
        return self.status()

    def check_trade_allowed(self, *, confirm: bool) -> None:
        if not self.web_trade_enabled or self.emergency_stopped:
            raise TradeDisabledError()
        if self.settings.order_confirm_required and not confirm:
            raise OrderConfirmRequiredError()

    def check_order(self, payload: OrderRequestDTO) -> None:
        self.check_trade_allowed(confirm=payload.confirm)
        if not rpc_service.status()["connected"]:
            raise RpcUnavailableError()

        exchange = payload.exchange
        vt_symbol = f"{payload.symbol}.{payload.exchange}"

        allowed_exchanges = self.rules["allowed_exchanges"]
        if allowed_exchanges and exchange not in allowed_exchanges:
            raise RiskExchangeNotAllowedError(detail={"exchange": exchange})

        if payload.symbol in self.rules["blocked_symbols"] or vt_symbol in self.rules["blocked_symbols"]:
            raise RiskSymbolBlockedError(detail={"symbol": payload.symbol, "vt_symbol": vt_symbol})

        allowed_symbols = self.rules["allowed_symbols"]
        if allowed_symbols and payload.symbol not in allowed_symbols and vt_symbol not in allowed_symbols:
            raise RiskSymbolBlockedError("合约不在白名单", detail={"symbol": payload.symbol, "vt_symbol": vt_symbol})

        contract = self._get_contract(vt_symbol)
        if contract is None:
            raise RiskSymbolBlockedError("合约不存在", detail={"vt_symbol": vt_symbol})

        if payload.volume > self.rules["max_order_volume"]:
            raise RiskMaxOrderVolumeError(
                detail={"volume": payload.volume, "max_order_volume": self.rules["max_order_volume"]}
            )

        self._check_contract_constraints(payload, contract)
        self._check_symbol_position(payload)
        self._check_close_position_available(payload)
        self._check_price_protection(payload)
        self._check_daily_loss()
        self._check_trading_time(payload)

    def _check_symbol_position(self, payload: OrderRequestDTO) -> None:
        max_position = self.rules["max_symbol_position"]
        if max_position <= 0 or payload.offset != "open":
            return
        vt_symbol = f"{payload.symbol}.{payload.exchange}"
        positions = rpc_service.get_positions()
        current_volume = 0.0
        for position in positions:
            symbol = position.get("vt_symbol") or f"{position.get('symbol')}.{position.get('exchange')}"
            if symbol == vt_symbol:
                current_volume += float(position.get("volume") or 0)
        if current_volume + payload.volume > max_position:
            raise RiskMaxSymbolPositionError(
                detail={"vt_symbol": vt_symbol, "current_volume": current_volume, "order_volume": payload.volume}
            )

    def _check_close_position_available(self, payload: OrderRequestDTO) -> None:
        if payload.offset == "open":
            return
        vt_symbol = f"{payload.symbol}.{payload.exchange}"
        target_direction = "short" if payload.direction == "long" else "long"
        available = 0.0
        for position in rpc_service.get_positions():
            symbol = position.get("vt_symbol") or f"{position.get('symbol')}.{position.get('exchange')}"
            direction = _normalize_position_direction(position.get("direction"))
            if symbol != vt_symbol or direction != target_direction:
                continue

            volume = float(position.get("volume") or 0)
            frozen = float(position.get("frozen") or 0)
            yd_volume = float(position.get("yd_volume") or position.get("ydPosition") or 0)
            today_volume = max(volume - yd_volume, 0)
            if payload.offset == "closetoday":
                available += max(today_volume - frozen, 0)
            elif payload.offset == "closeyesterday":
                available += max(yd_volume - frozen, 0)
            else:
                available += max(volume - frozen, 0)

        if available < payload.volume:
            raise ClosePositionNotEnoughError(
                detail={
                    "vt_symbol": vt_symbol,
                    "direction": payload.direction,
                    "offset": payload.offset,
                    "available": available,
                    "order_volume": payload.volume,
                }
            )

    def _get_contract(self, vt_symbol: str) -> dict[str, Any] | None:
        for contract in rpc_service.get_contracts():
            contract_vt_symbol = contract.get("vt_symbol") or f"{contract.get('symbol')}.{contract.get('exchange')}"
            if contract_vt_symbol == vt_symbol:
                return contract
        return None

    def _check_contract_constraints(self, payload: OrderRequestDTO, contract: dict[str, Any]) -> None:
        price_tick = float(contract.get("pricetick") or contract.get("price_tick") or 0)
        if price_tick > 0 and not _is_multiple(payload.price, price_tick):
            raise RiskPriceProtectionError(detail={"price": payload.price, "pricetick": price_tick})
        min_volume = float(contract.get("min_volume") or 1)
        if not _is_multiple(payload.volume, min_volume):
            raise RiskMaxOrderVolumeError(detail={"volume": payload.volume, "min_volume": min_volume})

    def _check_price_protection(self, payload: OrderRequestDTO) -> None:
        percent = self.rules["price_protection_percent"]
        if percent <= 0:
            return
        tick = memory_store.get_tick(f"{payload.symbol}.{payload.exchange}")
        if not tick:
            return
        last_price = float(tick.get("last_price") or 0)
        if last_price <= 0:
            return
        limit = last_price * percent / 100
        if abs(payload.price - last_price) > limit:
            raise RiskPriceProtectionError(
                detail={"price": payload.price, "last_price": last_price, "price_protection_percent": percent}
            )

    def _check_daily_loss(self) -> None:
        max_loss = self.rules["max_daily_loss"]
        if max_loss <= 0:
            return
        positions = rpc_service.get_positions()
        total_pnl = sum(float(position.get("pnl") or 0) for position in positions)
        if total_pnl < 0 and abs(total_pnl) > max_loss:
            raise RiskDailyLossLimitError(detail={"daily_loss": abs(total_pnl), "max_daily_loss": max_loss})

    def _check_trading_time(self, payload: OrderRequestDTO) -> None:
        if not self.rules["trading_time_check_enabled"]:
            return
        now = datetime.now(timezone.utc)
        vt_symbol = f"{payload.symbol}.{payload.exchange}"
        session_status = calendar_service.trading_session_status(now, [vt_symbol])
        if not session_status["active"]:
            raise RiskTradingTimeError(
                detail={
                    "date": session_status.get("trading_day") or now.astimezone(CHINA_TZ).date().isoformat(),
                    "symbol": payload.symbol,
                    "exchange": payload.exchange,
                    "session_active": False,
                    "session": session_status.get("session"),
                    "reason": session_status.get("reason"),
                    "source": calendar_service.source,
                }
            )


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _is_multiple(value: float, step: float) -> bool:
    return abs(round(value / step) * step - value) < 1e-8


def _normalize_position_direction(value: Any) -> str:
    raw = str(getattr(value, "value", value)).lower()
    return {"多": "long", "空": "short"}.get(raw, raw)


risk_service = RiskService()
