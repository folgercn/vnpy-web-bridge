from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


_ASSET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


class _AlphaAsset(BaseModel):
    """Shared, file-backed Alpha Database asset metadata."""

    model_config = ConfigDict(extra="forbid")

    # This is intentionally data rather than a model literal: a later reader
    # can retain a versioned historical asset even after the schema evolves.
    asset_version: str = Field(default="research_lab.alpha-database.v1", min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str = ""
    created_commit: str = ""


class AlphaIdea(_AlphaAsset):
    idea_id: str
    title: str = Field(min_length=1)
    hypothesis: str = Field(min_length=1)
    strategy_name: str | None = None
    factor_names: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("idea_id")
    @classmethod
    def id_must_be_safe(cls, value: str) -> str:
        if _ASSET_ID.fullmatch(value) is None:
            raise ValueError("idea_id must use letters, digits, '.', '_' or '-'")
        return value


class ExperimentRecord(_AlphaAsset):
    experiment_id: str
    status: Literal["completed", "failed"]
    strategy_name: str
    factor_name: str
    result_artifact: str | None = None
    report_location: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    metrics: dict[str, float] | None = None

    @field_validator("experiment_id")
    @classmethod
    def id_must_be_safe(cls, value: str) -> str:
        if _ASSET_ID.fullmatch(value) is None:
            raise ValueError("experiment_id must use letters, digits, '.', '_' or '-'")
        return value


class FailurePattern(_AlphaAsset):
    pattern_id: str
    source_kind: Literal["experiment", "critic_review"]
    source_id: str
    strategy_name: str | None = None
    factor_name: str | None = None
    category: str
    severity: Literal["warning", "critical"] = "warning"
    summary: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)

    @field_validator("pattern_id", "source_id")
    @classmethod
    def ids_must_be_safe(cls, value: str) -> str:
        if _ASSET_ID.fullmatch(value) is None:
            raise ValueError("pattern and source IDs must use letters, digits, '.', '_' or '-'")
        return value


class FactorKnowledge(_AlphaAsset):
    factor_name: str = Field(min_length=1)
    experiment_ids: list[str] = Field(default_factory=list)
    strategy_names: list[str] = Field(default_factory=list)
    failure_pattern_ids: list[str] = Field(default_factory=list)
    feature_lineage: list[dict[str, Any]] = Field(default_factory=list)
    dataset_lineage: list[dict[str, Any]] = Field(default_factory=list)
    literature_reference_ids: list[str] = Field(default_factory=list)
    validation_result_ids: list[str] = Field(default_factory=list)


class LiteratureReference(_AlphaAsset):
    reference_id: str
    title: str = Field(min_length=1)
    citation: str = Field(min_length=1)
    url: str | None = None
    factor_names: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("reference_id")
    @classmethod
    def id_must_be_safe(cls, value: str) -> str:
        if _ASSET_ID.fullmatch(value) is None:
            raise ValueError("reference_id must use letters, digits, '.', '_' or '-'")
        return value
