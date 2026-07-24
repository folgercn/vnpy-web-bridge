from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Product = Literal["ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn"]
Sector = Literal[
    "precious",
    "nonferrous",
    "energy_chemical",
    "ferrous",
    "energy",
    "light_industry",
]
TrendSign = Literal[-1, 0, 1]


class StrictFiniteModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class CFastResearchBindingsDTO(StrictFiniteModel):
    research_contract_sha256: Literal[
        "c1639d5f7714fd3989da799ece2743ca392ac8a8edad64a7f1238dd2e51c9d31"
    ]
    formula_builder_sha256: Literal[
        "7ebe1529173b46cbae17680d872680c7bb7bae39863d09b2d9a37183828a43a9"
    ]
    target_builder_sha256: Literal[
        "40fd1a27bb1e6dedf483a4c7dcec6d181d325d9c9958d6620f79f04fbdb696db"
    ]
    historical_fresh_exact_runner_sha256: Literal[
        "7e75ad73a8b037b80937cb449b863305753ec7b2860568422906fd55bb2a2fbe"
    ]
    snapshot_producer_status: Literal[
        "NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY"
    ]
    research_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    calendar_authority_sha256: Literal[
        "57b5341b45cb92d7e991f028d780580ab712e87c9cc86c7036917b638cddc76f"
    ]
    allocator_runner_sha256: Literal[
        "66497283d1c35383d620ef3c92f2c23316046a9b4b0cbe6f1dcf3f361041f307"
    ]
    guardband_runner_sha256: Literal[
        "e9871b26af4f0ebebed6e697e8fa1c3064bc3d6557df739bcef9b80697eab353"
    ]
    allocator_manifest_sha256: Literal[
        "8595fb3d4df57e4b6db0e8a64b02bbc0e90d243d0e6a93060837f5a748c8057f"
    ]
    allocation_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    daily_roll_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CFastGuardrailsDTO(StrictFiniteModel):
    source_product_abs_cap: Literal[0.2]
    source_sector_gross_cap: Literal[0.35]
    source_portfolio_gross_cap: Literal[1.0]
    source_target_net: Literal[0.0]
    buffered_product_abs_cap: Literal[0.12]
    buffered_sector_gross_cap: Literal[0.27]
    buffered_portfolio_gross_cap: Literal[0.8]
    buffered_target_net: Literal[0.0]
    integer_product_abs_hard_cap: Literal[0.15]
    integer_sector_gross_hard_cap: Literal[0.35]
    integer_portfolio_gross_hard_cap: Literal[1.0]
    integer_abs_net_hard_cap: Literal[0.1]


class CFastAllocatorDTO(StrictFiniteModel):
    algorithm_id: Literal["FINITE_NEIGHBOURHOOD_BEAM_V1"]
    neighbourhood_radius_lots: Literal[2]
    beam_width: Literal[2048]
    net_error_penalty: Literal[1.0]
    monthly_target_dates_only: Literal[True]
    daily_auto_reweight: Literal[False]
    roll_preserves_integer_lots: Literal[True]


class CFastShadowTargetDTO(StrictFiniteModel):
    product: Product
    sector: Sector
    trend_21_sign: TrendSign
    trend_63_sign: TrendSign
    trend_126_sign: TrendSign
    source_score: float = Field(ge=-1.0, le=1.0)
    vol60_annualized: float = Field(gt=0)
    raw_risk_score: float
    source_target_weight: float
    buffered_target_weight: float
    previous_exact_contract: str | None = Field(default=None, min_length=8, max_length=32)
    exact_contract: str = Field(min_length=8, max_length=32)
    previous_target_quantity: int
    target_quantity: int
    reference_open_price: float = Field(gt=0)
    reference_price_field: Literal["official_open"]
    reference_price_observed_at_utc: datetime
    reference_price_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    multiplier: int = Field(gt=0)
    price_tick: float = Field(gt=0)
    pit_main_exact_contract: str = Field(min_length=8, max_length=32)
    pit_main_dte: int = Field(gt=10)
    pit_main_official_last_trading_day: date
    pit_main_following_official_day: date
    pit_main_following_dte: int = Field(gt=10)
    pit_main_target_position_allowed: Literal[True]
    pit_main_roll: bool


class CommodityCFastShadowDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_cross_section_neutral_shadow_v1"]
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    frozen_rule_id: Literal["commodity_fast_tsmom_forward_freeze_v1"]
    frozen_rule_sha256: Literal[
        "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
    ]
    mode: Literal["shadow_only"]
    execution_lane: Literal["official_forward"]
    frequency: Literal["MONTHLY"]
    pit_main_definition: Literal["DAILY_PIT_OI_MAIN"]
    trend_horizons_official_days: tuple[Literal[21], Literal[63], Literal[126]]
    volatility_lookback_official_days: Literal[60]
    volatility_floor: Literal[0.05]
    virtual_nav_cny: Literal[20_000_000]
    source_month: str = Field(pattern=r"^\d{4}-\d{2}$")
    source_official_day: date
    execution_day: date
    input_cutoff_at_utc: datetime
    snapshot_created_at_utc: datetime
    source_is_month_last_official_day: Literal[True]
    execution_is_next_cross_month_official_day: Literal[True]
    input_cutoff_after_source_close: Literal[True]
    calendar_alignment: Literal["SIGNED_ASSERTION_NOT_RUNTIME_VERIFIED"]
    allocator_output_validation: Literal[
        "SIGNED_ALLOCATOR_OUTPUT_NOT_RECOMPUTED"
    ]
    daily_roll_alignment: Literal[
        "SIGNED_DAILY_ROLL_ASSERTION_NOT_RUNTIME_VERIFIED"
    ]
    previous_snapshot_hash: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    research_bindings: CFastResearchBindingsDTO
    guardrails: CFastGuardrailsDTO
    allocator: CFastAllocatorDTO
    formula_target_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    dynamic_selection_allowed: Literal[False]
    production_allowed: Literal[False]
    targets: list[CFastShadowTargetDTO] = Field(min_length=10, max_length=10)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=40, max_length=256)


class CFastShadowStateTargetDTO(StrictFiniteModel):
    product: Product
    exact_contract: str = Field(min_length=8, max_length=32)
    target_quantity: int


class CommodityCFastShadowStateDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_shadow_state_v1"]
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_month: str = Field(pattern=r"^\d{4}-\d{2}$")
    source_official_day: date
    execution_day: date
    continuity_state: Literal["genesis", "verified"]
    accepted_at_utc: datetime
    targets: list[CFastShadowStateTargetDTO] = Field(
        min_length=10, max_length=10
    )
    state_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
