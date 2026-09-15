from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_REVIEW_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


class CriticFinding(BaseModel):
    """One bounded, evidence-backed review conclusion."""

    model_config = ConfigDict(extra="forbid")

    category: Literal[
        "fold_boundary", "future_data", "overfit_degradation", "sample_selection",
        "parameter_stability", "transaction_cost", "regime_dependence",
    ]
    assessment: Literal["pass", "risk", "insufficient_evidence"]
    severity: Literal["info", "warning", "critical"]
    summary: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)
    required_additional_tests: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_evidence_for_pass(self) -> "CriticFinding":
        if self.assessment == "pass" and not self.evidence:
            raise ValueError("a pass finding must include evidence")
        return self


class CriticReview(BaseModel):
    """Versioned local Critic result; a research recommendation only."""

    model_config = ConfigDict(extra="forbid")

    review_version: Literal["research_lab.critic-review.v1"] = "research_lab.critic-review.v1"
    review_id: str
    validation_id: str
    candidate_id: str
    recommendation: Literal["accept", "improve", "reject"]
    confidence: float = Field(ge=0, le=1)
    findings: list[CriticFinding] = Field(min_length=7)
    artifact_location: str | None = None
    report_location: str | None = None

    @field_validator("review_id", "validation_id", "candidate_id")
    @classmethod
    def ids_must_be_safe(cls, value: str) -> str:
        if _REVIEW_ID.fullmatch(value) is None:
            raise ValueError("review, validation, and candidate IDs must use letters, digits, '.', '_' or '-'")
        return value

    @model_validator(mode="after")
    def require_one_finding_per_critic_category(self) -> "CriticReview":
        expected = {
            "fold_boundary", "future_data", "overfit_degradation", "sample_selection",
            "parameter_stability", "transaction_cost", "regime_dependence",
        }
        if {item.category for item in self.findings} != expected or len(self.findings) != len(expected):
            raise ValueError("critic review must contain exactly one finding for every critic category")
        return self
