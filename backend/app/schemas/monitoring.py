from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class SilenceCreateDTO(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    expires_at: datetime
    rule_id: str | None = None
    scope_id: str | None = None
    incident_id: str | None = None


class TelegramTestDTO(BaseModel):
    message: str | None = Field(default=None, max_length=500)
