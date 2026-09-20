"""ScreeningPlan Contract, Data Models, Content Hashing, and Validation.

Implements #564 cheap screening plan definitions.
Guarantees absolute determinism:
- Stable plan_id, content_hash, and method ordering.
- Strict forbidden field checks (no run_id, sharpe, ic, score, rank, decision, promote, reject, etc.).
- Explicit UNSUPPORTED for unknown screening methods.
- Explicit INSUFFICIENT_DATA for missing required fields.
- Zero parameter tuning, zero critic score, zero trading decisions.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from research_lab.alpha_discovery.hypothesis import HypothesisRef
from research_lab.contracts import v2

SCHEMA_VERSION = "research_lab.screening_plan.v1"
HASH_PROFILE = "research-json-v1"

ALLOWED_METHODS = frozenset({
    "coverage",
    "simple_correlation",
    "direction_consistency",
    "stability_split",
})

ALLOWED_PLAN_METHOD_STATUSES = frozenset({
    "PLANNED",
    "UNSUPPORTED",
    "INSUFFICIENT_DATA",
})

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
TIME_PATTERN = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")

# Strictly forbidden fields at top-level or method request levels
# to avoid leaking execution runtime facts, critic assessments, or trading decisions into plans.
FORBIDDEN_TOP_LEVEL_FIELDS = frozenset({
    # Runtime & Execution
    "run_id",
    "spec_id",
    "task_id",
    "execution_engine",
    "snapshot_path",
    "seed",
    "fee_model",
    "output_dir",
    "worker",
    "retry",
    # Results & Evidence
    "evidence",
    "evidence_id",
    "result",
    "metrics",
    "sharpe",
    "ic",
    "pnl",
    "returns",
    "drawdown",
    "win_rate",
    "trade_blotter",
    "equity_curve",
    # Critic & Promotion Gate
    "review",
    "review_id",
    "critic",
    "score",
    "rank",
    "recommendation",
    "decision",
    "gate_decision",
    "status",
    "promote",
    "reject",
    "need_more_evidence",
})

FORBIDDEN_METHOD_FIELDS = frozenset({
    "run_id",
    "spec_id",
    "task_id",
    "evidence_id",
    "score",
    "rank",
    "decision",
    "promote",
    "reject",
    "recommendation",
    "sharpe",
    "ic",
    "pnl",
    "returns",
    "drawdown",
})

ALLOWED_TOP_LEVEL_FIELDS = frozenset({
    "schema_version",
    "hash_profile",
    "plan_id",
    "plan_content_hash",
    "hypothesis_ref",
    "scientific_identity_hash",
    "methods",
    "falsification_context",
    "dataset_requirements",
    "provenance",
})


class DatasetRequirements(BaseModel):
    """Dataset snapshot requirements embedded within a screening plan."""

    model_config = ConfigDict(extra="forbid")

    snapshot_locator: str = Field(min_length=1)
    snapshot_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    snapshot_byte_length: int = Field(gt=0)
    required_fields: list[str] = Field(min_length=1)
    provenance: str = Field(min_length=1)
    time_range: dict[str, str] | None = None

    @field_validator("required_fields")
    @classmethod
    def validate_fields(cls, items: list[str]) -> list[str]:
        if not items:
            raise ValueError("required_fields must not be empty")
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("required_fields entries must be non-empty strings")
        return items


class ScreeningMethodRequest(BaseModel):
    """Specification of an individual screening method in a ScreeningPlan."""

    model_config = ConfigDict(extra="forbid")

    method: str = Field(min_length=1)
    status: Literal["PLANNED", "UNSUPPORTED", "INSUFFICIENT_DATA"]
    reason: str | None = None
    missing_fields: list[str] | None = None
    required_fields: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("parameters")
    @classmethod
    def validate_no_forbidden_in_parameters(cls, params: dict[str, Any]) -> dict[str, Any]:
        for forbidden in FORBIDDEN_METHOD_FIELDS:
            if forbidden in params:
                raise ValueError(f"Forbidden field in method parameters: {forbidden!r}")
        return params


class PlanProvenance(BaseModel):
    """Provenance and origin tracking for ScreeningPlan."""

    model_config = ConfigDict(extra="forbid")

    created_by: str = Field(min_length=1)
    planned_at: str
    origin_hypothesis_id: str = Field(min_length=1)
    origin_hypothesis_revision: str = Field(min_length=1)
    origin_hypothesis_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    origin_scientific_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("planned_at")
    @classmethod
    def validate_planned_at(cls, v: str) -> str:
        if not TIME_PATTERN.fullmatch(v):
            raise ValueError(f"planned_at must be UTC timestamp YYYY-MM-DDTHH:MM:SS.ffffffZ, got {v!r}")
        return v


class ScreeningPlan(BaseModel):
    """Contract for an immutable, deterministic Screening Plan (#564).

    Maps an AlphaHypothesis to one or more deterministic cheap screening method requests.
    Strictly forbids runtime execution state, backtest configuration, parameter tuning,
    critic assessments, or trading promotion/rejection decisions.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research_lab.screening_plan.v1"] = SCHEMA_VERSION
    hash_profile: Literal["research-json-v1"] = HASH_PROFILE
    plan_id: str
    plan_content_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[a-f0-9]{64}$",
        description="Canonical SHA-256 digest of the entire plan record (excluding itself).",
    )

    hypothesis_ref: HypothesisRef
    scientific_identity_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    methods: list[ScreeningMethodRequest] = Field(min_length=1)
    falsification_context: list[str] = Field(default_factory=list)
    dataset_requirements: DatasetRequirements | None = None
    provenance: PlanProvenance

    @field_validator("plan_id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not ID_PATTERN.fullmatch(v):
            raise ValueError(f"Invalid plan_id: {v!r}")
        return v

    @field_validator("methods")
    @classmethod
    def validate_methods_order(cls, items: list[ScreeningMethodRequest]) -> list[ScreeningMethodRequest]:
        if not items:
            raise ValueError("ScreeningPlan must contain at least one method")
        names = [item.method for item in items]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate method in ScreeningPlan: {names}")
        if names != sorted(names):
            raise ValueError(f"Methods in ScreeningPlan must be sorted alphabetically: {names} != {sorted(names)}")
        return items


def _clean_for_hash(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: _clean_for_hash(v) for k, v in val.items() if v is not None and k != "plan_content_hash"}
    elif isinstance(val, list):
        return [_clean_for_hash(x) for x in val]
    return val


def compute_plan_content_hash(data: dict[str, Any]) -> str:
    """Compute repository-pinned research-json-v1 SHA-256 digest of ScreeningPlan."""
    clean = _clean_for_hash(data)
    return v2.digest(clean)


def validate_screening_plan(data: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed validation of a ScreeningPlan dictionary against contract.

    Returns validated clean dictionary or raises ValueError/TypeError.
    """
    if not isinstance(data, dict):
        raise TypeError(f"ScreeningPlan must be a dict, got {type(data)}")

    # Check for unknown top-level fields (fail closed)
    extra_fields = set(data.keys()) - ALLOWED_TOP_LEVEL_FIELDS
    if extra_fields:
        raise ValueError(f"Forbidden extra fields in ScreeningPlan: {sorted(extra_fields)}")

    # Check for forbidden fields at top-level
    for forbidden in FORBIDDEN_TOP_LEVEL_FIELDS:
        if forbidden in data:
            raise ValueError(f"Forbidden field present in ScreeningPlan: {forbidden!r}")

    # Check schema version and hash profile
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Unknown or unsupported schema_version: {data.get('schema_version')!r}")
    if data.get("hash_profile") != HASH_PROFILE:
        raise ValueError(f"Unknown or unsupported hash_profile: {data.get('hash_profile')!r}")

    # Enforce non-empty, valid plan_content_hash matching canonical content
    if "plan_content_hash" not in data:
        raise ValueError("Missing required field: 'plan_content_hash'")
    declared_hash = data.get("plan_content_hash")
    if not isinstance(declared_hash, str) or not declared_hash.strip():
        raise ValueError(f"plan_content_hash must be non-empty string, got {declared_hash!r}")
    if not HASH_PATTERN.fullmatch(declared_hash):
        raise ValueError(f"plan_content_hash must be 64-char hex SHA-256 digest, got {declared_hash!r}")

    expected_hash = compute_plan_content_hash(data)
    if declared_hash != expected_hash:
        raise ValueError(f"plan_content_hash mismatch: declared {declared_hash}, computed {expected_hash}")

    # Pydantic model validation
    try:
        model = ScreeningPlan.model_validate(data)
    except Exception as err:
        raise ValueError(f"ScreeningPlan validation failed: {err}") from err

    return model.model_dump(exclude_none=True)
