from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .result import ExperimentResult


FarmTaskStatus = Literal["queued", "claimed", "completed", "failed"]
WorkerStatus = Literal["online", "offline"]


class FarmWorker(BaseModel):
    """Persisted local Farm worker registration and heartbeat evidence."""

    model_config = ConfigDict(extra="forbid")

    worker_id: str = Field(min_length=3, max_length=128)
    status: WorkerStatus = "online"
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    heartbeat_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FarmTask(BaseModel):
    """An immutable queue binding for one already-approved Sol plan version."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=8, max_length=128)
    plan_id: str = Field(min_length=3, max_length=128)
    task_content_hash: str = Field(min_length=64, max_length=64)
    proposal_content_hash: str = Field(min_length=64, max_length=64)
    plan_integrity_hash: str = Field(min_length=64, max_length=64)
    status: FarmTaskStatus = "queued"
    attempt: int = Field(default=0, ge=0)
    worker_id: str | None = None
    lease_expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: str | None = None


class FarmClaim(BaseModel):
    """Owner- and attempt-bound lease returned by an atomic queue claim."""

    model_config = ConfigDict(extra="forbid")

    task: FarmTask
    worker_id: str = Field(min_length=3, max_length=128)
    attempt: int = Field(ge=1)
    lease_expires_at: datetime


class FarmResultCallback(BaseModel):
    """A result can only be reported by the active owner of its claim attempt."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=8, max_length=128)
    worker_id: str = Field(min_length=3, max_length=128)
    attempt: int = Field(ge=1)
    result: ExperimentResult
