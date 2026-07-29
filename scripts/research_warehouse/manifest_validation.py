"""Validate a signed manifest against trusted registry and raw evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import RegistryError
from .filesystem import WarehousePaths
from .manifest_envelope import validate_manifest_envelope
from .models import SourceRegistry
from .observations import load_observations
from .revisions import revision_state
from .timeutil import parse_utc


def _validate_claimed_prefix(
    selected: list[dict[str, Any]],
    sealed_at: datetime,
) -> None:
    groups: dict[str, list[int]] = {}
    for item in selected:
        if parse_utc(item["observed_at"], "observed_at") > sealed_at:
            raise RegistryError("manifest cannot predate a claimed observation")
        groups.setdefault(item["source_id"], []).append(item["observation_sequence"])
    for sequences in groups.values():
        ordered = sorted(sequences)
        if ordered != list(range(1, ordered[-1] + 1)):
            raise RegistryError("manifest observation set is not a lineage prefix")


def validate_manifest(
    paths: WarehousePaths,
    payload: object,
    public_key: Ed25519PublicKey,
    registry: SourceRegistry,
) -> dict[str, Any]:
    payload = validate_manifest_envelope(paths, payload, public_key, registry)
    trade_day = payload["trade_day"]
    sealed_at = parse_utc(payload["sealed_at"], "sealed_at")
    observations = load_observations(paths, registry, trade_day=trade_day)
    by_id = {item["observation_id"]: item for item in observations}
    claimed_ids = payload["observation_ids"]
    if (
        not isinstance(claimed_ids, list)
        or not claimed_ids
        or claimed_ids != sorted(set(claimed_ids))
        or any(item not in by_id for item in claimed_ids)
    ):
        raise RegistryError("manifest observation set is invalid")
    selected = [by_id[item] for item in claimed_ids]
    _validate_claimed_prefix(selected, sealed_at)
    expected_revisions = revision_state(selected)
    if payload["revisions"] != expected_revisions:
        raise RegistryError("manifest revision lineage mismatch")
    return payload
