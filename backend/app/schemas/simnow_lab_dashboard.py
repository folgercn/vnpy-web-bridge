"""Stable, read-only DTOs for the SIMNOW_LAB dashboard boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _RemoteDTO(BaseModel):
    """Accept an additive Windows payload while emitting this fixed HTTP shape."""

    model_config = ConfigDict(extra="ignore")


class SimNowLabSeriesPointDTO(_RemoteDTO):
    time: str
    value: float


class SimNowLabSummaryDTO(_RemoteDTO):
    status: str
    blocker: str | None = None
    last_run_id: str | None = None
    target_id: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    active_order_count: int = Field(ge=0)
    unknown_order_count: int = Field(ge=0)
    aligned_products: int = Field(ge=0)
    total_products: int = Field(ge=0)


class SimNowLabMetricsDTO(_RemoteDTO):
    equity: float | None = None
    available: float | None = None
    margin: float | None = None
    unrealized_pnl: float | None = None
    realized_pnl: float | None = None
    cumulative_pnl: float | None = None
    daily_pnl: float | None = None
    max_drawdown: float | None = None
    slippage: float | None = None
    trade_count: int = Field(ge=0)


class SimNowLabSeriesDTO(_RemoteDTO):
    equity: list[SimNowLabSeriesPointDTO]
    cumulative_pnl: list[SimNowLabSeriesPointDTO]
    drawdown: list[SimNowLabSeriesPointDTO]
    daily_pnl: list[SimNowLabSeriesPointDTO]


class SimNowLabPortfolioRowDTO(_RemoteDTO):
    product: str
    vt_symbol: str
    target_quantity: int
    current_quantity: int
    delta: int
    unrealized_pnl: float | None = None
    status: str


class SimNowLabRunDTO(_RemoteDTO):
    run_id: str
    target_id: str
    status: str
    started_at: datetime
    ended_at: datetime | None = None
    error: str | None = None


class SimNowLabOrderDTO(_RemoteDTO):
    client_order_id: str
    run_id: str
    symbol: str
    direction: str
    offset: str
    quantity: int
    limit_price: float
    status: str
    traded: float
    created_at: datetime
    updated_at: datetime
    broker_order_id: str | None = None


class SimNowLabTradeDTO(_RemoteDTO):
    trade_key: str
    run_id: str
    client_order_id: str | None = None
    broker_order_id: str
    trade_id: str
    symbol: str
    direction: str
    offset: str
    price: float
    volume: float
    trade_time: str | None = None
    slippage: float | None = None
    created_at: datetime


class SimNowLabIncidentDTO(_RemoteDTO):
    code: str
    message: str
    observed_at: datetime | None = None
    run_id: str | None = None


class SimNowLabSnapshotDTO(_RemoteDTO):
    snapshot_id: str
    run_id: str
    phase: str
    observed_at: datetime
    equity: float | None = None
    available: float | None = None
    margin: float | None = None
    unrealized_pnl: float | None = None


class SimNowLabDashboardDTO(_RemoteDTO):
    schema_version: Literal["simnow_lab_dashboard_v1"]
    generated_at: datetime
    runtime_version: str
    summary: SimNowLabSummaryDTO
    metrics: SimNowLabMetricsDTO
    series: SimNowLabSeriesDTO
    portfolio: list[SimNowLabPortfolioRowDTO]
    runs: list[SimNowLabRunDTO]
    orders: list[SimNowLabOrderDTO]
    trades: list[SimNowLabTradeDTO]
    snapshots: list[SimNowLabSnapshotDTO]
    incidents: list[SimNowLabIncidentDTO]


class SimNowLabRunDetailDTO(_RemoteDTO):
    run: SimNowLabRunDTO
    orders: list[SimNowLabOrderDTO]
    trades: list[SimNowLabTradeDTO]
    snapshots: list[SimNowLabSnapshotDTO]


class SimNowLabDashboardResponseDTO(_RemoteDTO):
    stale: bool
    last_success_at: datetime | None = None
    web_version: str
    dashboard: SimNowLabDashboardDTO


class SimNowLabRunsResponseDTO(_RemoteDTO):
    stale: bool
    last_success_at: datetime | None = None
    runs: list[SimNowLabRunDTO]


class SimNowLabRunResponseDTO(_RemoteDTO):
    stale: bool
    last_success_at: datetime | None = None
    run: SimNowLabRunDetailDTO
