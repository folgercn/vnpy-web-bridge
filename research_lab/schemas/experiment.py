from __future__ import annotations

import math
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_EXPERIMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


class StrategySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal["buy_and_hold", "flat"]
    parameters: dict[str, float | int | str | bool] = Field(default_factory=dict)


class FactorSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    parameters: dict[str, float | int | str | bool] = Field(default_factory=dict)


class DatasetSpec(BaseModel):
    """A data request resolved by a MarketDataProvider."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    provider: Literal["inline", "local_csv"] = "inline"
    prices: list[float] | None = None
    path: str | None = None

    @field_validator("prices")
    @classmethod
    def prices_must_be_positive(cls, value: list[float] | None) -> list[float] | None:
        if value is None:
            return value
        if any(not math.isfinite(price) or price <= 0 for price in value):
            raise ValueError("prices must all be finite and positive")
        return value

    @model_validator(mode="after")
    def validate_provider_request(self) -> "DatasetSpec":
        if self.provider == "inline":
            if self.prices is None or len(self.prices) < 2:
                raise ValueError("inline datasets require at least two prices")
            if self.path is not None:
                raise ValueError("inline datasets must not declare path")
        elif self.path is None or not self.path.strip():
            raise ValueError("local_csv datasets require path")
        elif self.prices is not None:
            raise ValueError("local_csv datasets must not declare prices")
        return self


class ExecutionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    initial_capital: float = Field(default=100_000.0, gt=0)
    position_size: float = Field(default=1.0, gt=0)


class CostModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bps: float = Field(default=0.0, ge=0)


class ValidationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["in_sample", "holdout"] = "in_sample"


class OutputSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["json"] = "json"


class ExperimentSpec(BaseModel):
    """Versioned YAML protocol consumed by the MVP runner."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research_lab.experiment.v1"]
    experiment_id: str
    strategy: StrategySpec
    factor: FactorSpec
    universe: list[str] = Field(min_length=1)
    dataset: DatasetSpec
    parameters: dict[str, Any] = Field(default_factory=dict)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    cost_model: CostModel = Field(default_factory=CostModel)
    validation: ValidationSpec = Field(default_factory=ValidationSpec)
    output: OutputSpec = Field(default_factory=OutputSpec)

    @field_validator("experiment_id")
    @classmethod
    def experiment_id_must_be_safe(cls, value: str) -> str:
        if _EXPERIMENT_ID.fullmatch(value) is None:
            raise ValueError("experiment_id must use letters, digits, '.', '_' or '-'")
        return value

    @field_validator("universe")
    @classmethod
    def universe_symbols_must_be_nonempty(cls, value: list[str]) -> list[str]:
        if any(not symbol.strip() for symbol in value):
            raise ValueError("universe symbols must be nonempty")
        return value
