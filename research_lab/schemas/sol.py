from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .astra import ResearchTask
from .experiment import ExperimentSpec


PlanStatus = Literal[
    "received", "planning", "pending_approval", "queued", "running", "retry",
    "review", "archived", "failed",
]


class WorkerDescriptor(BaseModel):
    """One local, explicitly registered execution capability."""

    model_config = ConfigDict(extra="forbid")

    worker_id: str = Field(min_length=3, max_length=128)
    kind: Literal["runner"] = "runner"
    available: bool = True


class PlanEvent(BaseModel):
    """Append-only state evidence for a locally persisted plan."""

    model_config = ConfigDict(extra="forbid")

    status: PlanStatus
    reason: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    previous_hash: str | None = None
    integrity_hash: str = ""


class ExperimentPlan(BaseModel):
    """Auditable Sol plan; it is never a promotion or trading decision."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str = Field(min_length=3, max_length=128)
    task_id: str
    task_content_hash: str = Field(min_length=64, max_length=64)
    proposal_id: str
    proposal_content_hash: str = Field(min_length=64, max_length=64)
    experiment: ExperimentSpec
    status: PlanStatus
    worker_id: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    retry_count: int = Field(default=0, ge=0)
    max_retries: int = Field(default=0, ge=0, le=10)
    result_experiment_id: str | None = None
    validation_id: str | None = None
    critic_review_id: str | None = None
    review_status: Literal["awaiting_validation", "reviewed", "skipped"] | None = None
    error_message: str | None = None
    events: list[PlanEvent] = Field(min_length=1)
    integrity_hash: str = ""


class SolTaskInput(BaseModel):
    """Explicit handoff from Astra to Sol, including task version identity."""

    model_config = ConfigDict(extra="forbid")

    task: ResearchTask
    max_retries: int = Field(default=0, ge=0, le=10)
