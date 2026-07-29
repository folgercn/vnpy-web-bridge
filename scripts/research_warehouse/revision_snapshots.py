"""Validate and merge monotonic revision snapshots across signed batches."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import RegistryError
from .timeutil import parse_utc

EVOLVING_FIELDS = {"last_seen_at", "observation_ids"}


@dataclass(frozen=True)
class RevisionSnapshot:
    first_batch_sequence: int
    revision: dict[str, Any]


def _merge_revision(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    immutable = set(previous) - EVOLVING_FIELDS
    if set(current) != set(previous) or any(
        current[key] != previous[key] for key in immutable
    ):
        raise RegistryError("signed revision immutable fields changed")
    old_ids = previous["observation_ids"]
    new_ids = current["observation_ids"]
    if new_ids[: len(old_ids)] != old_ids:
        raise RegistryError("signed revision observations are not a prefix extension")
    old_seen = parse_utc(previous["last_seen_at"], "last_seen_at")
    new_seen = parse_utc(current["last_seen_at"], "last_seen_at")
    if new_seen < old_seen:
        raise RegistryError("signed revision last_seen_at moved backwards")
    if new_ids == old_ids and new_seen != old_seen:
        raise RegistryError("signed revision time changed without a new observation")
    return current


def latest_revision_snapshots(
    chain: list[dict[str, Any]],
) -> list[RevisionSnapshot]:
    values: dict[str, RevisionSnapshot] = {}
    for batch_sequence, manifest in enumerate(chain, start=1):
        for revision in manifest["revisions"]:
            revision_id = revision["revision_id"]
            existing = values.get(revision_id)
            if existing is None:
                values[revision_id] = RevisionSnapshot(
                    first_batch_sequence=batch_sequence,
                    revision=revision,
                )
            else:
                values[revision_id] = RevisionSnapshot(
                    first_batch_sequence=existing.first_batch_sequence,
                    revision=_merge_revision(existing.revision, revision),
                )
    return sorted(
        values.values(),
        key=lambda item: (
            item.revision["source_id"],
            item.revision["trade_day"],
            item.revision["revision_sequence"],
            item.revision["revision_id"],
        ),
    )
