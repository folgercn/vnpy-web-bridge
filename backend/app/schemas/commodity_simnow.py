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
    confirm_no_auto_promotion: bool


class CommoditySimNowDisableRequestDTO(StrictModel):
    reason: str = Field(min_length=3, max_length=500)


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
    schema_version: Literal["commodity_static_core_equal_target_batch_v1"]
    batch_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    scheduler_id: Literal["STATIC_CORE_EQUAL"]
    source_combination_arm: Literal["CORE_EQUAL_TARGET"]
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


class CommodityPlanExecuteRequestDTO(StrictModel):
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    phase: Literal["close", "open"]
    confirm: bool
    confirm_simnow_only: bool
    confirm_manual_one_shot: bool
    reason: str = Field(min_length=8, max_length=500)


class CommodityPlanReconcileRequestDTO(StrictModel):
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
