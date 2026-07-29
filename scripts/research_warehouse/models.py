"""Immutable source-registry models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SourceEndpoint:
    source_id: str
    exchange: str
    owner: str
    owner_reference_url: str
    license_policy: str
    use_terms_url: str
    endpoint_template: str
    documentation_url: str
    allowed_hosts: tuple[str, ...]
    media_type: str
    endpoint_schema_version: str
    availability_policy: str
    required_top_level_fields: tuple[str, ...]
    required_row_fields: tuple[str, ...]


@dataclass(frozen=True)
class SourceRegistry:
    registry_id: str
    schema_version: str
    published_at: str
    raw: bytes
    raw_sha256: str
    timezone: str
    timestamp_storage: str
    authority: dict[str, Any]
    sources: tuple[SourceEndpoint, ...]

    def source(self, source_id: str) -> SourceEndpoint:
        for source in self.sources:
            if source.source_id == source_id:
                return source
        raise KeyError(source_id)
