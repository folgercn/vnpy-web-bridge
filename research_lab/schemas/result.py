from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class PerformanceMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_return: float
    sharpe: float
    max_drawdown: float
    turnover: float
    transaction_cost: float
    final_equity: float


class ExperimentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_version: Literal["research_lab.result.v1"] = "research_lab.result.v1"
    experiment_id: str
    status: Literal["completed", "failed"]
    strategy_name: str
    factor_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metrics: PerformanceMetrics | None = None
    artifact_location: str | None = None
    report_location: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
