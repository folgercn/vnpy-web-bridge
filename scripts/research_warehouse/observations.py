"""Append and load immutable HTTP observation receipts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .acquisition_models import AcquiredObject
from .canonical import canonical_json_line, parse_json_strict
from .errors import RegistryError
from .filesystem import (
    WarehousePaths,
    create_only_bytes,
    custody_lock,
    read_regular_strict,
    recover_atomic_publishes,
    stable_custody_identity,
)
from .models import SourceEndpoint, SourceRegistry
from .observation_contracts import (
    CUSTODY_IDENTITY_SCHEME_V2,
    OBSERVATION_SCHEMA_V2,
    observation_id,
    raw_object_id,
    revision_occurrence_id,
    validate_trade_day,
)
from .observation_validation import validate_observation
from .revisions import revision_state, validate_lineage
from .timeutil import format_utc, parse_utc

__all__ = [
    "latest_acquired_observation",
    "load_observations",
    "load_observations_readonly",
    "observation_id",
    "raw_object_id",
    "revision_occurrence_id",
    "revision_state",
]


def latest_acquired_observation(
    paths: WarehousePaths,
    registry: SourceRegistry,
    *,
    source_id: str,
    trade_day: str,
    not_before: datetime,
) -> AcquiredObject | None:
    """Recover the latest fully validated acquisition after a trusted cutoff."""
    values = load_observations(
        paths,
        registry,
        source_id=source_id,
        trade_day=trade_day,
    )
    if not values:
        return None
    latest = values[-1]
    first_seen = parse_utc(latest["first_seen_at"], "first_seen_at")
    last_seen = parse_utc(latest["last_seen_at"], "last_seen_at")
    if first_seen < not_before or last_seen < not_before:
        return None
    return AcquiredObject(
        object_id=latest["object_id"],
        observation_id=latest["observation_id"],
        revision_id=latest["revision_id"],
        raw_sha256=latest["raw_sha256"],
        raw_bytes=latest["raw_bytes"],
        raw_path=paths.root / latest["raw_relative_path"],
        first_seen_at=first_seen,
        last_seen_at=last_seen,
        supersedes_object_id=latest["supersedes_object_id"],
        supersedes_revision_id=latest["supersedes_revision_id"],
        idempotent_raw=True,
    )


def _load_observations_unlocked(
    paths: WarehousePaths,
    registry: SourceRegistry,
    *,
    source_id: str | None = None,
    trade_day: str | None = None,
) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    if source_id is not None and trade_day is not None:
        validate_trade_day(trade_day)
        try:
            source = registry.source(source_id)
        except KeyError as exc:
            raise RegistryError(
                "observation source is not in audited registry"
            ) from exc
        target = (
            paths.observations
            / source.exchange.lower()
            / trade_day
            / source_id
        )
        candidates = sorted(target.glob("obs-*.json")) if target.exists() else []
    else:
        candidates = sorted(paths.observations.rglob("obs-*.json"))
    for path in candidates:
        raw = read_regular_strict(
            path, "observation receipt", limit=2 * 1024 * 1024
        )
        payload = validate_observation(
            paths,
            parse_json_strict(raw, "observation receipt"),
            registry,
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
        payloads.append(payload)
    validate_lineage(payloads)
    filtered = [
        item
        for item in payloads
        if (source_id is None or item["source_id"] == source_id)
        and (trade_day is None or item["trade_day"] == trade_day)
    ]
    filtered.sort(
        key=lambda item: (
            item["source_id"],
            item["trade_day"],
            item["observation_sequence"],
        )
    )
    return filtered


def load_observations(
    paths: WarehousePaths,
    registry: SourceRegistry,
    *,
    source_id: str | None = None,
    trade_day: str | None = None,
) -> list[dict[str, Any]]:
    with custody_lock(paths, "observation-metadata"):
        recover_atomic_publishes(
            temporary_dir=paths.temporary,
            final_root=paths.observations,
            temporary_name_prefix=".publish-obs-",
            final_name_glob="obs-*.json",
        )
        return _load_observations_unlocked(
            paths,
            registry,
            source_id=source_id,
            trade_day=trade_day,
        )


def load_observations_readonly(
    paths: WarehousePaths,
    registry: SourceRegistry,
    *,
    source_id: str | None = None,
    trade_day: str | None = None,
) -> list[dict[str, Any]]:
    """Load fully validated observations without writer recovery or locks."""
    return _load_observations_unlocked(
        paths,
        registry,
        source_id=source_id,
        trade_day=trade_day,
    )


def _create_observation_unlocked(
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
    registry: SourceRegistry,
) -> dict[str, Any]:
    validate_trade_day(trade_day)
    existing = _load_observations_unlocked(
        paths,
        registry,
        source_id=source.source_id,
        trade_day=trade_day,
    )
    latest = existing[-1] if existing else None
    if latest is not None:
        latest_time = parse_utc(latest["observed_at"], "observed_at")
        if observed_at < latest_time:
            raise RegistryError("observation clock moved backwards")
    sequence = len(existing) + 1
    object_id = raw_object_id(source, trade_day, raw_sha256)
    if latest is not None and latest["object_id"] == object_id:
        revision_id = latest["revision_id"]
        first_seen = latest["first_seen_at"]
        supersedes_revision = latest["supersedes_revision_id"]
        supersedes_object = latest["supersedes_object_id"]
    else:
        supersedes_revision = latest["revision_id"] if latest else None
        supersedes_object = latest["object_id"] if latest else None
        revision_id = revision_occurrence_id(
            source_id=source.source_id,
            trade_day=trade_day,
            observation_sequence=sequence,
            object_id=object_id,
            supersedes_revision_id=supersedes_revision,
        )
        first_seen = format_utc(observed_at, "observed_at")
    relative = raw_path.relative_to(paths.root)
    payload: dict[str, Any] = {
        "schema_version": OBSERVATION_SCHEMA_V2,
        "observation_id": "",
        "observation_sequence": sequence,
        "revision_id": revision_id,
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
        "supersedes_revision_id": supersedes_revision,
        "supersedes_object_id": supersedes_object,
        "collector_version": collector_version,
        "registry_raw_sha256": registry.raw_sha256,
        "endpoint_schema_version": source.endpoint_schema_version,
        "custody_identity_scheme": CUSTODY_IDENTITY_SCHEME_V2,
        "custody_identity_sha256": stable_custody_identity(paths),
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
        receipt,
        canonical_json_line(payload),
        "observation receipt",
        temporary_dir=paths.temporary,
    )
    return validate_observation(paths, payload, registry)


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
    registry: SourceRegistry,
) -> dict[str, Any]:
    with custody_lock(paths, "observation-metadata"):
        recover_atomic_publishes(
            temporary_dir=paths.temporary,
            final_root=paths.observations,
            temporary_name_prefix=".publish-obs-",
            final_name_glob="obs-*.json",
        )
        return _create_observation_unlocked(
            paths,
            source=source,
            trade_day=trade_day,
            source_url=source_url,
            http_status=http_status,
            http_metadata=http_metadata,
            observed_at=observed_at,
            raw_sha256=raw_sha256,
            raw_bytes=raw_bytes,
            raw_path=raw_path,
            collector_version=collector_version,
            registry=registry,
        )
