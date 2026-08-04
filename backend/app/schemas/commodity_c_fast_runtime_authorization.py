from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.commodity_c_fast_shadow import Product, Sector


class StrictFiniteModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class CommodityMapStrategyVersionProjectionDTO(StrictFiniteModel):
    schema_version: Literal["commodity_map_strategy_version_projection_v1"]
    strategy_identity: Literal["commodity_fast_tsmom_forward_freeze_v1"]
    strategy_model_version_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_data_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    formula_builder_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    producer_code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trend_horizons_official_days: tuple[Literal[21], Literal[63], Literal[126]]
    volatility_lookback_official_days: Literal[60]
    volatility_floor: Literal[0.05]
    frequency: Literal["MONTHLY"]
    signal_semantics: Literal["SIGNED_MONTHLY_TSMOM_RISK_SCORE_V1"]
    allowed_output_products: list[Product] = Field(min_length=10, max_length=10)
    max_source_product_abs: Literal[0.2]
    max_source_sector_gross: Literal[0.35]
    max_source_portfolio_gross: Literal[1.0]
    source_target_net: Literal[0.0]

    @model_validator(mode="after")
    def validate_products(self) -> CommodityMapStrategyVersionProjectionDTO:
        if self.allowed_output_products != sorted(self.allowed_output_products):
            raise ValueError("MAP output products must be sorted")
        if len(set(self.allowed_output_products)) != 10:
            raise ValueError("MAP output products must be unique")
        return self


class CommodityCFastAllocationPolicyProjectionDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_allocation_policy_projection_v1"]
    allocation_policy_identity: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    map_output_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    allocator_runner_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    guardband_runner_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    allocator_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    product_pool: list[Product] = Field(min_length=10, max_length=10)
    sector_map: dict[Product, Sector]
    algorithm_id: Literal["FINITE_NEIGHBOURHOOD_BEAM_V1"]
    neighbourhood_radius_lots: Literal[2]
    beam_width: Literal[2048]
    net_error_penalty: Literal[1.0]
    monthly_target_dates_only: Literal[True]
    daily_auto_reweight: Literal[False]
    roll_preserves_integer_lots: Literal[True]
    pit_main_definition: Literal["DAILY_PIT_OI_MAIN"]
    previous_current_target_semantics: Literal[
        "SIGNED_PREVIOUS_AND_CURRENT_EXACT_CONTRACT_INTEGER_TARGET_V1"
    ]
    max_buffered_product_abs: Literal[0.12]
    max_buffered_sector_gross: Literal[0.27]
    max_buffered_portfolio_gross: Literal[0.8]
    buffered_target_net: Literal[0.0]
    max_integer_product_abs: Literal[0.15]
    max_integer_sector_gross: Literal[0.35]
    max_integer_portfolio_gross: Literal[1.0]
    max_integer_abs_net: Literal[0.1]
    executable_snapshot_schema: Literal[
        "commodity_map_c_fast_simnow_executable_target_snapshot_v1"
    ]
    execution_policy: Literal["SIMNOW_TWO_PHASE_CLOSE_RECONCILE_OPEN_V1"]

    @model_validator(mode="after")
    def validate_policy_scope(self) -> CommodityCFastAllocationPolicyProjectionDTO:
        if self.product_pool != sorted(self.product_pool):
            raise ValueError("C_FAST product pool must be sorted")
        if len(set(self.product_pool)) != 10:
            raise ValueError("C_FAST product pool must be unique")
        if sorted(self.sector_map) != self.product_pool:
            raise ValueError("C_FAST sector map must cover the product pool")
        return self


class CommodityMapStrategyAcceptanceDTO(StrictFiniteModel):
    schema_version: Literal["commodity_map_strategy_acceptance_v1"]
    purpose: Literal["commodity_map_strategy_version_acceptance"]
    acceptance_id: str = Field(pattern=r"^commodity-map-accept-v1-[0-9a-f]{64}$")
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    accepted_by: str = Field(min_length=1, max_length=128)
    reviewer_role: str = Field(min_length=1, max_length=128)
    projection: CommodityMapStrategyVersionProjectionDTO
    projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_to_c_fast_only: Literal[True]
    production_allowed: Literal[False]
    live_allowed: Literal[False]
    countable_forward: Literal[False]
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    signature: str = Field(min_length=88, max_length=88)


class CommodityCFastAllocationAcceptanceDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_allocation_acceptance_v1"]
    purpose: Literal["commodity_c_fast_allocation_policy_acceptance"]
    acceptance_id: str = Field(pattern=r"^commodity-c-fast-allocation-accept-v1-[0-9a-f]{64}$")
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    accepted_by: str = Field(min_length=1, max_length=128)
    reviewer_role: str = Field(min_length=1, max_length=128)
    map_strategy_identity: Literal["commodity_fast_tsmom_forward_freeze_v1"]
    map_output_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection: CommodityCFastAllocationPolicyProjectionDTO
    projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_production_allowed: Literal[False]
    live_allowed: Literal[False]
    countable_forward: Literal[False]
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    signature: str = Field(min_length=88, max_length=88)


class CommodityCFastRuntimeRiskLimitsDTO(StrictFiniteModel):
    max_product_abs_weight: float = Field(gt=0, le=0.15)
    max_sector_gross_weight: float = Field(gt=0, le=0.35)
    max_portfolio_gross_weight: float = Field(gt=0, le=1.0)
    max_portfolio_abs_net_weight: float = Field(ge=0, le=0.1)


class CommodityCFastRuntimeAuthorizationDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_simnow_runtime_authorization_v1"]
    purpose: Literal["commodity_c_fast_simnow_continuous_runtime_authorization"]
    authorization_id: str = Field(pattern=r"^commodity-c-fast-runtime-auth-v1-[0-9a-f]{64}$")
    issued_at: datetime
    valid_from: datetime
    valid_until: datetime | None = None
    until_revoked: bool
    authorized_by: str = Field(min_length=1, max_length=128)
    reviewer_role: str = Field(min_length=1, max_length=128)
    map_acceptance_id: str = Field(pattern=r"^commodity-map-accept-v1-[0-9a-f]{64}$")
    map_acceptance_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    map_strategy_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    c_fast_allocation_acceptance_id: str = Field(
        pattern=r"^commodity-c-fast-allocation-accept-v1-[0-9a-f]{64}$"
    )
    c_fast_allocation_acceptance_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    c_fast_allocation_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_simnow_account_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_products: list[Product] = Field(min_length=1, max_length=10)
    max_selected_products: int = Field(ge=1, le=2)
    max_child_order_lots: int = Field(ge=1, le=100)
    risk_limits: CommodityCFastRuntimeRiskLimitsDTO
    allowed_execution_lane: Literal["simnow_shakedown"]
    signed_snapshots_only: Literal[True]
    continuous: Literal[True]
    production_allowed: Literal[False]
    live_allowed: Literal[False]
    countable_forward: Literal[False]
    automatic_promotion_allowed: Literal[False]
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    signature: str = Field(min_length=88, max_length=88)

    @model_validator(mode="after")
    def validate_authorization(self) -> CommodityCFastRuntimeAuthorizationDTO:
        if self.allowed_products != sorted(self.allowed_products):
            raise ValueError("runtime allowed products must be sorted")
        if len(set(self.allowed_products)) != len(self.allowed_products):
            raise ValueError("runtime allowed products must be unique")
        if self.until_revoked != (self.valid_until is None):
            raise ValueError("until_revoked and valid_until are inconsistent")
        return self


class CommodityCFastRuntimeTrustedKeyDTO(StrictFiniteModel):
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    public_key_base64: str = Field(min_length=44, max_length=44)
    signer_role: Literal[
        "map_strategy_acceptance",
        "c_fast_allocation_acceptance",
        "simnow_runtime_authorization",
    ]
    reviewer_role: str = Field(min_length=1, max_length=128)


class CommodityCFastRuntimeTrustedKeysDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_runtime_authority_trusted_keys_v1"]
    purpose: Literal["commodity_c_fast_runtime_authority_verification"]
    trusted_keys: list[CommodityCFastRuntimeTrustedKeyDTO] = Field(
        min_length=3, max_length=32
    )

    @model_validator(mode="after")
    def validate_keys(self) -> CommodityCFastRuntimeTrustedKeysDTO:
        ids = [row.key_id for row in self.trusted_keys]
        materials = [row.public_key_base64 for row in self.trusted_keys]
        if len(ids) != len(set(ids)) or len(materials) != len(set(materials)):
            raise ValueError("runtime authority keys must be unique")
        roles = {row.signer_role for row in self.trusted_keys}
        if roles != {
            "map_strategy_acceptance",
            "c_fast_allocation_acceptance",
            "simnow_runtime_authorization",
        }:
            raise ValueError("runtime authority key roles are incomplete")
        return self


class CommodityCFastRuntimeAuthorizationEventDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_runtime_authorization_event_v1"]
    sequence: int = Field(ge=1)
    event_id: str = Field(pattern=r"^cfast-runtime-event-[0-9a-f]{64}$")
    event_type: Literal["ENABLED", "REVOKED", "EXPIRED", "HARD_DRIFT_REVOKED"]
    occurred_at: datetime
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=500)
    authorization_id: str = Field(pattern=r"^commodity-c-fast-runtime-auth-v1-[0-9a-f]{64}$")
    authorization_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    map_acceptance_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    c_fast_allocation_acceptance_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_event_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
