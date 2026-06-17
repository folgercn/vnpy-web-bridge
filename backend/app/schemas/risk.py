from __future__ import annotations

from pydantic import BaseModel, Field


class RiskRulesDTO(BaseModel):
    max_order_volume: float = Field(gt=0)
    max_symbol_position: float = Field(ge=0)
    max_daily_loss: float = Field(ge=0)
    price_protection_percent: float = Field(ge=0)
    allowed_exchanges: list[str] = []
    allowed_symbols: list[str] = []
    blocked_symbols: list[str] = []
    trading_time_check_enabled: bool = False


class RiskRulesPatchDTO(BaseModel):
    max_order_volume: float | None = Field(default=None, gt=0)
    max_symbol_position: float | None = Field(default=None, ge=0)
    max_daily_loss: float | None = Field(default=None, ge=0)
    price_protection_percent: float | None = Field(default=None, ge=0)
    allowed_exchanges: list[str] | None = None
    allowed_symbols: list[str] | None = None
    blocked_symbols: list[str] | None = None
    trading_time_check_enabled: bool | None = None


class EmergencyStopRequestDTO(BaseModel):
    cancel_all: bool = False
    reason: str | None = None
