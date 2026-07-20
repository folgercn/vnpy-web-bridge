from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Product = Literal["ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CommoditySimNowEnableRequestDTO(StrictModel):
    manual_approval: bool
    simnow_mode: bool
    reason: str = Field(min_length=8, max_length=500)
    confirm_simnow_only: bool
    confirm_no_production: bool
    confirm_cold_start_or_reconciled_state: bool
    confirm_manual_two_phase_dispatch: bool
    confirm_auto_dispatch: bool
    confirm_no_auto_promotion: bool


class CommoditySimNowDisableRequestDTO(StrictModel):
    reason: str = Field(min_length=3, max_length=500)


class CommodityTemplateStartRequestDTO(StrictModel):
    reason: str = Field(min_length=8, max_length=500)
    confirm_strategy_template: bool
    confirm_simnow_only: bool
    confirm_auto_dispatch: bool
    confirm_no_production: bool


class CommodityCandidateWeightsDTO(StrictModel):
    C: float
    D: float


class CommodityGuardbandDTO(StrictModel):
    product: float
    sector: float
    gross: float
    target_net: float


class CommodityAllocatorDTO(StrictModel):
    algorithm_id: Literal["FINITE_NEIGHBOURHOOD_BEAM_V1"]
    neighbourhood_radius_lots: Literal[2]
    beam_width: Literal[2048]
    net_error_penalty: Literal[1.0]
    monthly_target_dates_only: Literal[True]
    daily_auto_reweight: Literal[False]
    roll_preserves_integer_lots: Literal[True]


class CommodityTargetRowDTO(StrictModel):
    product: Product
    previous_exact_contract: str | None = None
    previous_target_quantity: int
    exact_contract: str = Field(min_length=8, max_length=32)
    target_quantity: int
    source_target_weight: float
    buffered_target_weight: float
    reference_open_price: float = Field(gt=0)
    multiplier: int = Field(gt=0)
    price_tick: float = Field(gt=0)


class CommodityTargetBatchDTO(StrictModel):
    schema_version: Literal["commodity_static_core_equal_target_batch_v2"]
    batch_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    scheduler_id: Literal["STATIC_CORE_EQUAL"]
    source_combination_arm: Literal["CORE_EQUAL_TARGET"]
    execution_lane: Literal["simnow_shakedown", "official_forward"]
    source_month: str = Field(pattern=r"^\d{4}-\d{2}$")
    execution_day: date
    virtual_nav_cny: Literal[20_000_000]
    candidate_weights: CommodityCandidateWeightsDTO
    guardband: CommodityGuardbandDTO
    allocator: CommodityAllocatorDTO
    previous_batch_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    targets: list[CommodityTargetRowDTO] = Field(min_length=10, max_length=10)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=40, max_length=256)


class CommodityTargetPreviewRequestDTO(StrictModel):
    batch: CommodityTargetBatchDTO


class CommodityPositionManagerShadowTargetDTO(StrictModel):
    product: Product
    exact_contract: str = Field(min_length=8, max_length=32)
    baseline_target_quantity: int
    shadow_target_quantity: int
    baseline_source_target_weight: float
    shadow_source_target_weight: float
    baseline_buffered_target_weight: float
    shadow_buffered_target_weight: float
    reference_open_price: float = Field(gt=0)
    multiplier: int = Field(gt=0)
    price_tick: float = Field(gt=0)


class CommodityPositionManagerShadowDTO(StrictModel):
    schema_version: Literal["commodity_relative_vol_position_manager_shadow_v2"]
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    position_manager_id: Literal["MONTHLY_RELATIVE_VOL_THERMOSTAT_V1"]
    sector_map_id: Literal["POSITION_MANAGER_SECTOR_MAP_V1"]
    mode: Literal["shadow_only"]
    baseline_scheduler_id: Literal["STATIC_CORE_EQUAL"]
    baseline_batch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_month: str = Field(pattern=r"^\d{4}-\d{2}$")
    execution_day: date
    input_cutoff_day: date
    fast_lookback_days: Literal[21]
    slow_lookback_days: Literal[126]
    annualization_days: Literal[252]
    fast_annual_vol: float = Field(gt=0)
    slow_annual_vol: float = Field(gt=0)
    scale_min: Literal[0.8]
    scale_max: Literal[1.2]
    raw_scale: float = Field(ge=0.8, le=1.2)
    continuity_mode: Literal["genesis", "linked"]
    previous_snapshot_hash: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    previous_smoothed_scale: float = Field(ge=0.8, le=1.2)
    smoothing_alpha: Literal[0.5]
    smoothed_scale: float = Field(ge=0.8, le=1.2)
    daily_auto_reweight: Literal[False]
    guardband_reapplied: Literal[True]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    targets: list[CommodityPositionManagerShadowTargetDTO] = Field(min_length=10, max_length=10)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=40, max_length=256)


class CommodityPlanExecuteRequestDTO(StrictModel):
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    phase: Literal["close", "open"]
    confirm: bool
    confirm_simnow_only: bool
    confirm_manual_one_shot: bool
    acceptance_passive_limit: bool = False
    confirm_acceptance_passive_limit: bool = False
    reason: str = Field(min_length=8, max_length=500)


class CommodityPlanReconcileRequestDTO(StrictModel):
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
