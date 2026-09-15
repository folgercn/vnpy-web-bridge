from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .experiment import ExperimentSpec


_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


class ResearchMaterial(BaseModel):
    """Explicit, offline research input for the deterministic Discovery MVP."""

    model_config = ConfigDict(extra="forbid")

    material_id: str
    source_kind: Literal["public_research", "quant_research", "exchange_report", "market_anomaly"]
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)
    factor_names: list[str] = Field(default_factory=list)
    hypothesis: str | None = None
    economic_logic: str | None = None
    expected_edge: str | None = None
    required_data: list[str] = Field(default_factory=list)
    validation_plan: list[str] = Field(default_factory=list)
    experiment: dict[str, Any] | None = None
    observed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str = ""

    @field_validator("material_id")
    @classmethod
    def id_must_be_safe(cls, value: str) -> str:
        if _IDENTITY.fullmatch(value) is None:
            raise ValueError("material_id must use letters, digits, '.', '_' or '-'")
        return value


class ResearchProposal(BaseModel):
    """Evidence-linked Discovery output; it never represents a trading decision."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    material_id: str
    title: str = Field(min_length=1)
    hypothesis: str | None = None
    economic_logic: str | None = None
    expected_edge: str | None = None
    required_data: list[str] = Field(default_factory=list)
    validation_plan: list[str] = Field(default_factory=list)
    factor_names: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(min_length=1)
    related_idea_ids: list[str] = Field(default_factory=list)
    related_experiment_ids: list[str] = Field(default_factory=list)
    related_failure_pattern_ids: list[str] = Field(default_factory=list)
    related_literature_ids: list[str] = Field(default_factory=list)
    failed_pattern_notes: list[str] = Field(default_factory=list)
    status: Literal["ready", "blocked"]
    blocked_reasons: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str = ""

    @field_validator("proposal_id", "material_id")
    @classmethod
    def ids_must_be_safe(cls, value: str) -> str:
        if _IDENTITY.fullmatch(value) is None:
            raise ValueError("proposal and material IDs must use letters, digits, '.', '_' or '-'")
        return value

    @model_validator(mode="after")
    def status_must_match_reasons(self) -> "ResearchProposal":
        if self.status == "blocked" and not self.blocked_reasons:
            raise ValueError("blocked proposals require blocked_reasons")
        if self.status == "ready" and self.blocked_reasons:
            raise ValueError("ready proposals must not include blocked_reasons")
        return self


class ResearchTask(BaseModel):
    """A future-Sol consumable artifact, without a queue or execution side effect."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    proposal_id: str
    status: Literal["ready", "blocked"]
    experiment: ExperimentSpec | None = None
    evidence: list[str] = Field(min_length=1)
    blocked_reasons: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str = ""

    @field_validator("task_id", "proposal_id")
    @classmethod
    def ids_must_be_safe(cls, value: str) -> str:
        if _IDENTITY.fullmatch(value) is None:
            raise ValueError("task and proposal IDs must use letters, digits, '.', '_' or '-'")
        return value

    @model_validator(mode="after")
    def task_must_match_status(self) -> "ResearchTask":
        if self.status == "ready" and (self.experiment is None or self.blocked_reasons):
            raise ValueError("ready tasks require an ExperimentSpec and no blocked_reasons")
        if self.status == "blocked" and (self.experiment is not None or not self.blocked_reasons):
            raise ValueError("blocked tasks require reasons and no ExperimentSpec")
        return self
