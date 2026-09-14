from __future__ import annotations

import json
import math
import re
from typing import Literal

from pydantic import (
    BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr,
    field_validator, model_validator,
)

from .experiment import ExperimentSpec
from .result import ExperimentResult, PerformanceMetrics


_SWEEP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_PARAMETER_PATH = re.compile(r"^(?:strategy\.parameters|factor\.parameters|parameters)\.[A-Za-z][A-Za-z0-9_]{0,63}$")
_DIRECT_PARAMETER_PATHS = {
    "execution.initial_capital",
    "execution.position_size",
    "cost_model.bps",
}

ParameterValue = StrictBool | StrictFloat | StrictInt | StrictStr
RankingMetric = Literal["total_return", "sharpe", "max_drawdown", "turnover", "transaction_cost", "final_equity"]


class SweepParameter(BaseModel):
    """A finite, explicitly permitted path and its candidate values."""

    model_config = ConfigDict(extra="forbid")

    path: str
    values: list[ParameterValue] = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def path_must_be_supported(cls, value: str) -> str:
        if value not in _DIRECT_PARAMETER_PATHS and _PARAMETER_PATH.fullmatch(value) is None:
            raise ValueError("sweep path is not supported")
        return value

    @field_validator("values")
    @classmethod
    def values_must_be_finite_and_unique(cls, value: list[ParameterValue]) -> list[ParameterValue]:
        identities: set[str] = set()
        for candidate in value:
            if isinstance(candidate, float) and not math.isfinite(candidate):
                raise ValueError("sweep values must be finite")
            identity = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
            if identity in identities:
                raise ValueError("sweep values must be unique")
            identities.add(identity)
        return value


class SweepRanking(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric: RankingMetric = "sharpe"
    direction: Literal["maximize", "minimize"] = "maximize"


class SweepSpec(BaseModel):
    """A declarative local-only Cartesian parameter sweep."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research_lab.sweep.v1"]
    sweep_id: str
    experiment: ExperimentSpec
    search_strategy: Literal["cartesian"] = "cartesian"
    parameters: list[SweepParameter] = Field(min_length=1)
    ranking: SweepRanking = Field(default_factory=SweepRanking)

    @field_validator("sweep_id")
    @classmethod
    def sweep_id_must_be_safe(cls, value: str) -> str:
        if _SWEEP_ID.fullmatch(value) is None:
            raise ValueError("sweep_id must use letters, digits, '.', '_' or '-'")
        return value

    @field_validator("parameters")
    @classmethod
    def paths_must_be_unique(cls, value: list[SweepParameter]) -> list[SweepParameter]:
        if len({parameter.path for parameter in value}) != len(value):
            raise ValueError("sweep parameter paths must be unique")
        return value

    @model_validator(mode="after")
    def direct_values_must_match_experiment_fields(self) -> "SweepSpec":
        for parameter in self.parameters:
            if parameter.path == "execution.initial_capital":
                self._require_positive_number(parameter)
            elif parameter.path == "execution.position_size":
                self._require_positive_number(parameter)
            elif parameter.path == "cost_model.bps":
                for value in parameter.values:
                    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                        raise ValueError("cost_model.bps sweep values must be non-negative numbers")
        return self

    @staticmethod
    def _require_positive_number(parameter: SweepParameter) -> None:
        for value in parameter.values:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{parameter.path} sweep values must be positive numbers")


class SweepTrial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    experiment: ExperimentSpec
    parameter_values: dict[str, ParameterValue]


class RankedTrial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rank: int = Field(ge=1)
    experiment_id: str
    parameter_values: dict[str, ParameterValue]
    metrics: PerformanceMetrics


class ParameterStability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    value: ParameterValue
    completed_trials: int = Field(ge=1)
    mean_score: float
    best_score: float
    score_stddev: float = Field(ge=0)


class SweepTrialResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parameter_values: dict[str, ParameterValue]
    result: ExperimentResult


class SweepResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_version: Literal["research_lab.sweep-result.v1"] = "research_lab.sweep-result.v1"
    sweep_id: str
    status: Literal["completed", "completed_with_failures"]
    ranking: SweepRanking
    trials: list[SweepTrialResult]
    ranked_trials: list[RankedTrial]
    stability: list[ParameterStability]
    artifact_location: str | None = None
    report_location: str | None = None
