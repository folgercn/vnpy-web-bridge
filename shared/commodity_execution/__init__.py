"""Dependency-free contracts for the final SIMNOW execution handoff.

This package carries immutable plans and verified custody facts only.  It does
not know about FastAPI, RPC, signing keys, or the legacy trading services.
"""

from .v1 import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    TARGET_PLAN_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    CommodityExecutionContractError,
    TargetPlan,
    TargetPlanOrder,
    TrustedKeylessCustodyReceipt,
    VerifiedCustodyReceipt,
    before_position_projection_hash,
    build_target_plan,
    build_trusted_keyless_target_plan,
    canonical_before_position_projection,
    canonical_target_position_projection,
    sha256_json,
    target_position_projection_hash,
)

__all__ = [
    "KEYLESS_TARGET_PLAN_SCHEMA_VERSION",
    "TARGET_PLAN_SCHEMA_VERSION",
    "TRUSTED_KEYLESS_SIMNOW_SCOPE",
    "CommodityExecutionContractError",
    "TargetPlan",
    "TargetPlanOrder",
    "TrustedKeylessCustodyReceipt",
    "VerifiedCustodyReceipt",
    "before_position_projection_hash",
    "build_target_plan",
    "build_trusted_keyless_target_plan",
    "canonical_before_position_projection",
    "canonical_target_position_projection",
    "sha256_json",
    "target_position_projection_hash",
]
