"""Canonical daily-manifest contracts and digest primitives."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from .canonical import canonical_json, sha256
from .errors import RegistryError

MANIFEST_SCHEMA = "vnpy_research_daily_batch_manifest_v1"
MANIFEST_AUTHORITY = "RESEARCH_EVIDENCE_ONLY_NO_EXECUTION_AUTHORITY"
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_KEYS = {
    "schema_version",
    "batch_id",
    "trade_day",
    "sealed_at",
    "registry_raw_sha256",
    "input_fingerprint_sha256",
    "parent_batch_seal_sha256",
    "parent_commit_seal_sha256",
    "batch_seal_sha256",
    "revisions",
    "observation_ids",
    "revision_count",
    "unique_raw_object_count",
    "observation_count",
    "total_unique_raw_bytes",
    "signer_key_id",
    "signer_public_key_sha256",
    "authority",
    "ready",
    "signature",
}


def seal_base(payload: dict[str, Any]) -> dict[str, Any]:
    excluded = {"batch_id", "batch_seal_sha256", "signature"}
    return {key: value for key, value in payload.items() if key not in excluded}


def input_fingerprint(
    registry_raw_sha256: str,
    observation_ids: list[str],
) -> str:
    return sha256(
        canonical_json(
            {
                "observation_ids": observation_ids,
                "registry_raw_sha256": registry_raw_sha256,
            }
        )
    )


def validate_manifest_trade_day(value: object) -> str:
    if not isinstance(value, str):
        raise RegistryError("manifest trade_day must be a string")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError("manifest trade_day is invalid") from exc
    if parsed.isoformat() != value:
        raise RegistryError("manifest trade_day is not canonical")
    return value
