"""Deterministic replay of append-only revision occurrences."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .errors import RegistryError
from .observation_contracts import revision_occurrence_id
from .timeutil import parse_utc


def validate_lineage(payloads: list[dict[str, Any]]) -> None:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in payloads:
        groups.setdefault((item["source_id"], item["trade_day"]), []).append(item)
    for (source_id, trade_day), items in groups.items():
        ordered = sorted(items, key=lambda item: item["observation_sequence"])
        if [item["observation_sequence"] for item in ordered] != list(
            range(1, len(ordered) + 1)
        ):
            raise RegistryError("observation sequence is not contiguous")
        current_revision: str | None = None
        current_object: str | None = None
        current_first_seen: str | None = None
        current_supersedes_revision: str | None = None
        current_supersedes_object: str | None = None
        previous_observed: datetime | None = None
        for item in ordered:
            observed = parse_utc(item["observed_at"], "observed_at")
            if previous_observed is not None and observed < previous_observed:
                raise RegistryError("observation clock moved backwards")
            if current_object != item["object_id"]:
                supersedes_revision = current_revision
                supersedes_object = current_object
                current_revision = revision_occurrence_id(
                    source_id=source_id,
                    trade_day=trade_day,
                    observation_sequence=item["observation_sequence"],
                    object_id=item["object_id"],
                    supersedes_revision_id=supersedes_revision,
                )
                current_object = item["object_id"]
                current_first_seen = item["observed_at"]
                current_supersedes_revision = supersedes_revision
                current_supersedes_object = supersedes_object
            if (
                item["revision_id"] != current_revision
                or item["first_seen_at"] != current_first_seen
                or item["supersedes_revision_id"] != current_supersedes_revision
                or item["supersedes_object_id"] != current_supersedes_object
            ):
                raise RegistryError("observation revision lineage is invalid")
            previous_observed = observed


def revision_state(
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_revision: dict[str, list[dict[str, Any]]] = {}
    for item in observations:
        by_revision.setdefault(item["revision_id"], []).append(item)
    revisions: list[dict[str, Any]] = []
    for revision_id, items in by_revision.items():
        ordered = sorted(items, key=lambda item: item["observation_sequence"])
        first = ordered[0]
        latest = ordered[-1]
        revisions.append(
            {
                "revision_id": revision_id,
                "revision_sequence": first["observation_sequence"],
                "object_id": first["object_id"],
                "source_id": first["source_id"],
                "exchange": first["exchange"],
                "trade_day": first["trade_day"],
                "raw_sha256": first["raw_sha256"],
                "raw_bytes": first["raw_bytes"],
                "raw_relative_path": first["raw_relative_path"],
                "first_seen_at": first["first_seen_at"],
                "last_seen_at": latest["last_seen_at"],
                "supersedes_revision_id": first["supersedes_revision_id"],
                "supersedes_object_id": first["supersedes_object_id"],
                "observation_ids": [
                    item["observation_id"] for item in ordered
                ],
            }
        )
    revisions.sort(
        key=lambda item: (
            item["source_id"],
            item["trade_day"],
            item["revision_sequence"],
        )
    )
    return revisions
