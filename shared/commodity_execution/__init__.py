"""Dependency-free contracts for the final SIMNOW execution handoff.

This package carries immutable plans and verified custody facts only.  It does
not know about FastAPI, RPC, signing keys, or the legacy trading services.
"""

from .v1 import (
    TARGET_PLAN_SCHEMA_VERSION,
    CommodityExecutionContractError,
    TargetPlan,
    TargetPlanOrder,
    VerifiedCustodyReceipt,
    build_target_plan,
)

__all__ = [
    "TARGET_PLAN_SCHEMA_VERSION",
    "CommodityExecutionContractError",
    "TargetPlan",
    "TargetPlanOrder",
    "VerifiedCustodyReceipt",
    "build_target_plan",
]
