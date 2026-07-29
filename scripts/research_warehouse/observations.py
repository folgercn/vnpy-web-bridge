"""Append-only HTTP observations and revision lineage."""

from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .filesystem import (
    SAFE_COMPONENT,
    WarehousePaths,
    create_only_bytes,
    custody_identity,
    read_regular_strict,
)
from .models import SourceEndpoint
from .timeutil import format_utc, parse_utc

OBSERVATION_SCHEMA = "vnpy_research_raw_observation_v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OBSERVATION_KEYS = {
    "schema_version",
    "observation_id",
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
    "supersedes_object_id",
    "collector_version",
    "registry_raw_sha256",
    "endpoint_schema_version",
    "custody_identity_sha256",
    "authority",
}


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


def observation_id(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "observation_id"}
    return "obs-" + sha256(canonical_json(unsigned))


def _validate_trade_day(value: str) -> str:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"invalid trade day: {value}") from exc
    if parsed.isoformat() != value:
        raise RegistryError(f"non-canonical trade day: {value}")
    return value


def _safe_relative(paths: WarehousePaths, value: object) -> Path:
    if not isinstance(value, str):
        raise RegistryError("raw_relative_path must be a string")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise RegistryError("raw_relative_path is unsafe")
    absolute = paths.root / relative
    try:
        absolute.relative_to(paths.raw)
    except ValueError as exc:
        raise RegistryError("raw_relative_path is outside raw custody") from exc
    return absolute


def validate_observation(
    paths: WarehousePaths,
    payload: object,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != OBSERVATION_KEYS:
        raise RegistryError("observation fields do not match v1 schema")
    if payload["schema_version"] != OBSERVATION_SCHEMA:
        raise RegistryError("observation schema mismatch")
    claimed = payload["observation_id"]
    if not isinstance(claimed, str) or claimed != observation_id(payload):
        raise RegistryError("observation ID binding mismatch")
    if payload["authority"] != "RESEARCH_EVIDENCE_ONLY":
        raise RegistryError("observation authority mismatch")
    text_fields = (
        "source_id",
        "exchange",
        "trade_day",
        "source_url",
        "collector_version",
        "endpoint_schema_version",
    )
    if any(not isinstance(payload[field], str) for field in text_fields):
        raise RegistryError("observation text field type mismatch")
    if any(
        SAFE_COMPONENT.fullmatch(payload[field]) is None
        for field in ("source_id", "exchange")
    ):
        raise RegistryError("observation source/exchange binding is unsafe")
    _validate_trade_day(payload["trade_day"])
    first = parse_utc(payload["first_seen_at"], "first_seen_at")
    last = parse_utc(payload["last_seen_at"], "last_seen_at")
    observed = parse_utc(payload["observed_at"], "observed_at")
    if first > observed or last != observed:
        raise RegistryError("observation first/last seen ordering is invalid")
    digest = payload["raw_sha256"]
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise RegistryError("observation raw SHA256 is invalid")
    raw_path = _safe_relative(paths, payload["raw_relative_path"])
    expected_relative = (
        Path("raw")
        / payload["exchange"].lower()
        / payload["trade_day"]
        / payload["source_id"]
        / f"{digest}.raw"
    )
    if Path(payload["raw_relative_path"]) != expected_relative:
        raise RegistryError("observation raw custody path binding mismatch")
    if (
        not isinstance(payload["raw_bytes"], int)
        or isinstance(payload["raw_bytes"], bool)
        or payload["raw_bytes"] < 0
    ):
        raise RegistryError("observation raw byte count is invalid")
    expected_object_id = "raw-" + sha256(
        canonical_json(
            {
                "exchange": payload["exchange"],
                "raw_sha256": digest,
                "source_id": payload["source_id"],
                "trade_day": payload["trade_day"],
            }
        )
    )
    if payload["object_id"] != expected_object_id:
        raise RegistryError("observation object ID binding mismatch")
    if payload["custody_identity_sha256"] != custody_identity(paths):
        raise RegistryError("observation custody identity binding mismatch")
    for field in ("registry_raw_sha256", "custody_identity_sha256"):
        value = payload[field]
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise RegistryError(f"observation {field} is invalid")
    raw = read_regular_strict(raw_path, "observation raw object")
    if len(raw) != payload["raw_bytes"] or sha256(raw) != digest:
        raise RegistryError("observation/raw exact-byte binding mismatch")
    return payload


def load_observations(
    paths: WarehousePaths,
    *,
    source_id: str | None = None,
    trade_day: str | None = None,
) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for path in sorted(paths.observations.rglob("obs-*.json")):
        raw = read_regular_strict(path, "observation receipt", limit=2 * 1024 * 1024)
        payload = validate_observation(
            paths, parse_json_strict(raw, "observation receipt")
        )
        if raw != canonical_json_line(payload):
            raise RegistryError("observation receipt is not exact canonical JSON")
        expected = (
            paths.observations
            / payload["exchange"].lower()
            / payload["trade_day"]
            / payload["source_id"]
            / f"{payload['observation_id']}.json"
        )
        if path != expected:
            raise RegistryError("observation receipt custody path binding mismatch")
        if source_id is not None and payload["source_id"] != source_id:
            continue
        if trade_day is not None and payload["trade_day"] != trade_day:
            continue
        payloads.append(payload)
    payloads.sort(key=lambda item: (item["observed_at"], item["observation_id"]))
    return payloads


def revision_state(
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_object: dict[str, list[dict[str, Any]]] = {}
    for item in observations:
        by_object.setdefault(item["object_id"], []).append(item)
    revisions: list[dict[str, Any]] = []
    for object_id, items in by_object.items():
        ordered = sorted(
            items, key=lambda item: (item["observed_at"], item["observation_id"])
        )
        latest = ordered[-1]
        revisions.append(
            {
                "object_id": object_id,
                "raw_sha256": latest["raw_sha256"],
                "raw_bytes": latest["raw_bytes"],
                "raw_relative_path": latest["raw_relative_path"],
                "first_seen_at": ordered[0]["first_seen_at"],
                "last_seen_at": latest["last_seen_at"],
                "supersedes_object_id": ordered[0]["supersedes_object_id"],
                "observation_ids": [item["observation_id"] for item in ordered],
            }
        )
    revisions.sort(key=lambda item: (item["first_seen_at"], item["object_id"]))
    return revisions


def create_observation(
    paths: WarehousePaths,
    *,
    source: SourceEndpoint,
    trade_day: str,
    source_url: str,
    http_status: int,
    http_metadata: dict[str, str | None],
    observed_at: datetime,
    raw_sha256: str,
    raw_bytes: int,
    raw_path: Path,
    collector_version: str,
    registry_raw_sha256: str,
) -> dict[str, Any]:
    _validate_trade_day(trade_day)
    existing = load_observations(
        paths, source_id=source.source_id, trade_day=trade_day
    )
    if existing:
        latest_time = parse_utc(existing[-1]["observed_at"], "observed_at")
        if observed_at < latest_time:
            raise RegistryError("observation clock moved backwards")
    object_id = raw_object_id(source, trade_day, raw_sha256)
    same = [item for item in existing if item["object_id"] == object_id]
    if same:
        first_seen = same[0]["first_seen_at"]
        supersedes = same[0]["supersedes_object_id"]
    else:
        first_seen = format_utc(observed_at, "observed_at")
        revisions = revision_state(existing)
        supersedes = revisions[-1]["object_id"] if revisions else None
    relative = raw_path.relative_to(paths.root)
    payload: dict[str, Any] = {
        "schema_version": OBSERVATION_SCHEMA,
        "observation_id": "",
        "object_id": object_id,
        "source_id": source.source_id,
        "exchange": source.exchange,
        "trade_day": trade_day,
        "source_url": source_url,
        "http_status": http_status,
        "http_metadata": http_metadata,
        "observed_at": format_utc(observed_at, "observed_at"),
        "first_seen_at": first_seen,
        "last_seen_at": format_utc(observed_at, "observed_at"),
        "raw_sha256": raw_sha256,
        "raw_bytes": raw_bytes,
        "raw_relative_path": str(relative),
        "supersedes_object_id": supersedes,
        "collector_version": collector_version,
        "registry_raw_sha256": registry_raw_sha256,
        "endpoint_schema_version": source.endpoint_schema_version,
        "custody_identity_sha256": custody_identity(paths),
        "authority": "RESEARCH_EVIDENCE_ONLY",
    }
    payload["observation_id"] = observation_id(payload)
    parent = paths.private_subdir(
        paths.observations,
        source.exchange.lower(),
        trade_day,
        source.source_id,
    )
    receipt = parent / f"{payload['observation_id']}.json"
    create_only_bytes(
        receipt, canonical_json_line(payload), "observation receipt"
    )
    return validate_observation(paths, payload)
