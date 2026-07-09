from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


MakV2Instrument = Literal["lc", "ps"]
MakV2Side = Literal["long", "short"]
MakV2DataQuality = Literal["pass", "degraded", "blocked"]


class MakV2ObserverEnableRequestDTO(BaseModel):
    manual_approval: bool = False
    testnet_mode: bool = False
    reason: str = Field(min_length=8, max_length=240)
    confirm_testnet_only: bool = False
    confirm_no_production: bool = False
    confirm_max_one_lot: bool = False
    confirm_no_auto_promotion: bool = False


class MakV2ObserverDisableRequestDTO(BaseModel):
    reason: str = Field(default="manual disable", min_length=4, max_length=240)


class MakV2DryRunSignalRequestDTO(BaseModel):
    instrument: MakV2Instrument
    exact_contract: str = Field(min_length=4, max_length=32)
    signal_time_utc: Optional[datetime] = None
    side: MakV2Side
    z_score: float
    rolling_mean: Optional[float] = None
    rolling_std: Optional[float] = None
    last_price: float = Field(gt=0)
    bid_price_1: float = Field(gt=0)
    ask_price_1: float = Field(gt=0)
    bid_volume_1: float = Field(ge=0)
    ask_volume_1: float = Field(ge=0)
    quote_age_ms: int = Field(default=0, ge=0)
    cluster_id: str = Field(default="manual_dry_run", max_length=80)
    active_overlap_900s: int = Field(default=0, ge=0)
    cooldown_state: str = Field(default="clear", max_length=80)
    data_quality_status: MakV2DataQuality = "pass"


class MakV2ObserverStatusDTO(BaseModel):
    mode: str
    candidate_id: str
    profile_id: str
    capacity_status: str
    enabled: bool
    manual_approval: bool
    testnet_mode: bool
    dry_run_only: bool
    production_allowed: bool
    max_order_lots: int
    max_testnet_orders_per_day: int
    max_testnet_orders_per_instrument_per_day: int
    max_active_testnet_positions_total: int
    max_active_testnet_position_per_instrument: int
    cooldown_after_testnet_order_seconds: int
    cooldown_after_reject_seconds: int
    signals_total: int
    dry_run_intents_total: int
    blocked_signals_total: int
    guardrail_events_total: int
    order_endpoint_touched: bool
