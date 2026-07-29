"""Typed results for deterministic Research normalization."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NormalizationBinding:
    tool_commit_sha: str
    dependency_lock_sha256: str
    registry_raw_sha256: str


@dataclass(frozen=True)
class NormalizedArtifact:
    normalization_id: str
    revision_id: str
    source_id: str
    exchange: str
    trade_day: str
    raw_sha256: str
    row_count: int
    parquet_sha256: str
    parquet_bytes: int
    parquet_path: Path
    parquet_relative_path: str
    schema_sha256: str
    sort_sha256: str
