"""Immutable acquisition, observation, and PIT models."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class HttpResponse:
    final_url: str
    status: int
    headers: Mapping[str, str]
    chunks: Iterator[bytes]


@dataclass(frozen=True)
class AcquiredObject:
    object_id: str
    observation_id: str
    raw_sha256: str
    raw_bytes: int
    raw_path: Path
    first_seen_at: datetime
    last_seen_at: datetime
    supersedes_object_id: str | None
    idempotent_raw: bool


@dataclass(frozen=True)
class PitSelection:
    object_id: str
    raw_sha256: str
    raw_bytes: int
    raw_path: Path
    first_seen_at: datetime
    batch_id: str
    batch_seal_sha256: str
