from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .experiment import ExperimentSpec
from .result import ExperimentResult


_VALIDATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


class ValidationSpec(BaseModel):
    """Declarative local validation plan expressed in observation counts."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research_lab.validation.v1"]
    validation_id: str
    experiment: ExperimentSpec
    method: Literal["train_test_split", "rolling_window", "walk_forward"]
    train_size: int = Field(ge=2)
    test_size: int = Field(ge=2)
    step_size: int | None = Field(default=None, ge=1)

    @field_validator("validation_id")
    @classmethod
    def validation_id_must_be_safe(cls, value: str) -> str:
        if _VALIDATION_ID.fullmatch(value) is None:
            raise ValueError("validation_id must use letters, digits, '.', '_' or '-'")
        return value

    @model_validator(mode="after")
    def validate_method_window(self) -> "ValidationSpec":
        if self.method == "train_test_split" and self.step_size is not None:
            raise ValueError("train_test_split does not accept step_size")
        if self.method != "train_test_split" and self.step_size is not None and self.step_size < self.test_size:
            raise ValueError("rolling and walk_forward step_size must be at least test_size to avoid overlapping OOS windows")
        return self

    @property
    def effective_step_size(self) -> int:
        return self.step_size or self.test_size


class ValidationFold(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=1)
    train_start: int = Field(ge=0)
    train_end: int = Field(ge=2)
    test_start: int = Field(ge=2)
    test_end: int = Field(ge=4)

    @model_validator(mode="after")
    def require_disjoint_ordered_windows(self) -> "ValidationFold":
        if self.train_start >= self.train_end:
            raise ValueError("fold train window must be nonempty")
        if self.test_start >= self.test_end:
            raise ValueError("fold test window must be nonempty")
        if self.train_end > self.test_start:
            raise ValueError("fold test window must begin after train window")
        return self


class ValidationFoldResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fold: ValidationFold
    in_sample: ExperimentResult
    out_of_sample: ExperimentResult


class DegradationAnalysis(BaseModel):
    """Aggregate IS/OOS deltas; a negative delta means OOS was weaker."""

    model_config = ConfigDict(extra="forbid")

    completed_folds: int = Field(ge=1)
    mean_in_sample_total_return: float
    mean_out_of_sample_total_return: float
    total_return_delta: float
    mean_in_sample_sharpe: float
    mean_out_of_sample_sharpe: float
    sharpe_delta: float


class StabilityAnalysis(BaseModel):
    """Heuristic 0-100 fold consistency score, not a promotion decision."""

    model_config = ConfigDict(extra="forbid")

    completed_folds: int = Field(ge=1)
    stability_score: float = Field(ge=0, le=100)
    positive_oos_fraction: float = Field(ge=0, le=1)
    oos_sharpe_stddev: float = Field(ge=0)


class RegimeSummary(BaseModel):
    """Minimal OOS return-sign regime summary, not market-regime inference."""

    model_config = ConfigDict(extra="forbid")

    regime: Literal["positive", "flat", "negative"]
    completed_folds: int = Field(ge=0)
    mean_total_return: float | None = None


class ValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_version: Literal["research_lab.validation-result.v1"] = "research_lab.validation-result.v1"
    validation_id: str
    status: Literal["completed", "completed_with_failures"]
    method: Literal["train_test_split", "rolling_window", "walk_forward"]
    folds: list[ValidationFoldResult]
    stability: StabilityAnalysis | None = None
    degradation: DegradationAnalysis | None = None
    regimes: list[RegimeSummary]
    artifact_location: str | None = None
    report_location: str | None = None
