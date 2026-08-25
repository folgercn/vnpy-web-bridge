"""Dependency-free contracts for the final SIMNOW execution handoff.

This package carries immutable plans and verified custody facts only.  It does
not know about FastAPI, RPC, signing keys, or the legacy trading services.
"""

from .v1 import (
    FORMAL_QUOTE_PROOF_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    TARGET_PLAN_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
    CommodityExecutionContractError,
    TargetPlan,
    TargetPlanOrder,
    TrustedKeylessCustodyReceipt,
    VerifiedCustodyReceipt,
    before_position_projection_hash,
    build_target_plan,
    build_trusted_keyless_target_plan,
    build_trusted_keyless_target_plan_v2,
    build_trusted_keyless_target_plan_v3,
    canonical_before_position_projection,
    canonical_target_position_projection,
    is_simnow_experimental_execution_run_id,
    sha256_json,
    simnow_experimental_adverse_cushion_ticks,
    target_position_projection_hash,
    trusted_keyless_target_plan_v3_plan_id,
)

__all__ = [
    "FORMAL_QUOTE_PROOF_SCHEMA_VERSION",
    "KEYLESS_TARGET_PLAN_SCHEMA_VERSION",
    "KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION",
    "KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION",
    "TARGET_PLAN_SCHEMA_VERSION",
    "TRUSTED_KEYLESS_SIMNOW_SCOPE",
    "V3_FORMAL_QUOTE_MAX_AGE_SECONDS",
    "CommodityExecutionContractError",
    "TargetPlan",
    "TargetPlanOrder",
    "TrustedKeylessCustodyReceipt",
    "VerifiedCustodyReceipt",
    "before_position_projection_hash",
    "build_target_plan",
    "build_trusted_keyless_target_plan",
    "build_trusted_keyless_target_plan_v2",
    "build_trusted_keyless_target_plan_v3",
    "canonical_before_position_projection",
    "canonical_target_position_projection",
    "is_simnow_experimental_execution_run_id",
    "sha256_json",
    "simnow_experimental_adverse_cushion_ticks",
    "target_position_projection_hash",
    "trusted_keyless_target_plan_v3_plan_id",
]
