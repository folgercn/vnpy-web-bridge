"""Canonical observation and revision-occurrence contracts."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from .canonical import canonical_json, sha256
from .errors import RegistryError
from .models import SourceEndpoint

OBSERVATION_SCHEMA = "vnpy_research_raw_observation_v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
HTTP_METADATA_KEYS = {
    "content-length",
    "content-type",
    "etag",
    "last-modified",
}
OBSERVATION_KEYS = {
    "schema_version",
    "observation_id",
    "observation_sequence",
    "revision_id",
    "object_id",
    "source_id",
    "exchange",
    "trade_day",
    "source_url",
    "http_status",
    "http_metadata",
    "observed_at",
    "first_seen_at",
    "last_seen_at",
    "raw_sha256",
    "raw_bytes",
    "raw_relative_path",
    "supersedes_revision_id",
    "supersedes_object_id",
    "collector_version",
    "registry_raw_sha256",
    "endpoint_schema_version",
    "custody_identity_sha256",
    "authority",
}


def validate_trade_day(value: str) -> str:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"invalid trade day: {value}") from exc
    if parsed.isoformat() != value:
        raise RegistryError(f"non-canonical trade day: {value}")
    return value


def raw_object_id(
    source: SourceEndpoint,
    trade_day: str,
    raw_sha256: str,
) -> str:
    binding = {
        "exchange": source.exchange,
        "raw_sha256": raw_sha256,
        "source_id": source.source_id,
        "trade_day": trade_day,
    }
    return "raw-" + sha256(canonical_json(binding))


def revision_occurrence_id(
    *,
    source_id: str,
    trade_day: str,
    observation_sequence: int,
    object_id: str,
    supersedes_revision_id: str | None,
) -> str:
    return "revision-" + sha256(
        canonical_json(
            {
                "object_id": object_id,
                "observation_sequence": observation_sequence,
                "source_id": source_id,
                "supersedes_revision_id": supersedes_revision_id,
                "trade_day": trade_day,
            }
        )
    )


def observation_id(payload: dict[str, Any]) -> str:
    unsigned = {
        key: value for key, value in payload.items() if key != "observation_id"
    }
    return "obs-" + sha256(canonical_json(unsigned))
