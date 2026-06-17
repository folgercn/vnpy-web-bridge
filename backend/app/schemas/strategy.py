from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

StrategyStatus = Literal["stopped", "initializing", "running", "error"]


class StrategySummaryDTO(BaseModel):
    strategy_name: str
    class_name: str | None = None
    vt_symbol: str | None = None
    status: StrategyStatus | str = "stopped"
    inited: bool = False
    trading: bool = False


class StrategyDetailDTO(StrategySummaryDTO):
    setting: dict[str, Any] = {}
    variables: dict[str, Any] = {}


class StrategySettingDTO(BaseModel):
    setting: dict[str, str | int | float | bool] = Field(default_factory=dict)


class StrategyVariableDTO(BaseModel):
    variables: dict[str, Any] = Field(default_factory=dict)


class StrategyOperationResponseDTO(BaseModel):
    strategy_name: str
    operation: str
    accepted: bool


class StrategyLogDTO(BaseModel):
    ts: str
    strategy_name: str | None = None
    level: str = "info"
    message: str
