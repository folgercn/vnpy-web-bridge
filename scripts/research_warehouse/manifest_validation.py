"""Validate a signed manifest against trusted registry and raw evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, sha256
from .errors import RegistryError
from .filesystem import WarehousePaths
from .manifest_contracts import (
    ID_PATTERN,
    MANIFEST_AUTHORITY,
    MANIFEST_KEYS,
    MANIFEST_SCHEMA,
    SHA256_PATTERN,
    input_fingerprint,
    seal_base,
    validate_manifest_trade_day,
)
from .models import SourceRegistry
from .observations import load_observations
from .revisions import revision_state
from .signing import public_key_sha256, verify_payload
from .timeutil import parse_utc


def _validate_claimed_prefix(
    selected: list[dict[str, Any]],
    sealed_at: datetime,
) -> None:
    groups: dict[str, list[int]] = {}
    for item in selected:
        if parse_utc(item["observed_at"], "observed_at") > sealed_at:
            raise RegistryError("manifest cannot predate a claimed observation")
        groups.setdefault(item["source_id"], []).append(
            item["observation_sequence"]
        )
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
    if not isinstance(payload, dict) or set(payload) != MANIFEST_KEYS:
        raise RegistryError("daily manifest fields do not match v1 schema")
    if payload["schema_version"] != MANIFEST_SCHEMA:
        raise RegistryError("daily manifest schema mismatch")
    if payload["authority"] != MANIFEST_AUTHORITY or payload["ready"] is not False:
        raise RegistryError("daily manifest authority/prepared state mismatch")
    if payload["registry_raw_sha256"] != registry.raw_sha256:
        raise RegistryError("daily manifest trusted registry pin mismatch")
    if not isinstance(payload["signer_key_id"], str) or ID_PATTERN.fullmatch(
        payload["signer_key_id"]
    ) is None:
        raise RegistryError("manifest signer key ID is invalid")
    if payload["signer_public_key_sha256"] != public_key_sha256(public_key):
        raise RegistryError("manifest signer public-key binding mismatch")
    unsigned = verify_payload(payload, public_key)
    trade_day = validate_manifest_trade_day(payload["trade_day"])
    sealed_at = parse_utc(payload["sealed_at"], "sealed_at")
    claimed_seal = payload["batch_seal_sha256"]
    if not isinstance(claimed_seal, str) or SHA256_PATTERN.fullmatch(
        claimed_seal
    ) is None:
        raise RegistryError("batch seal SHA256 is invalid")
    parent = payload["parent_batch_seal_sha256"]
    if parent is not None and (
        not isinstance(parent, str) or SHA256_PATTERN.fullmatch(parent) is None
    ):
        raise RegistryError("manifest parent seal SHA256 is invalid")
    if sha256(canonical_json(seal_base(unsigned))) != claimed_seal:
        raise RegistryError("batch seal payload binding mismatch")
    expected_id = f"batch-{trade_day}-{claimed_seal[:24]}"
    if payload["batch_id"] != expected_id:
        raise RegistryError("batch ID binding mismatch")
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
    if payload["revision_count"] != len(expected_revisions):
        raise RegistryError("manifest revision count mismatch")
    unique_objects = {
        item["object_id"]: item["raw_bytes"] for item in expected_revisions
    }
    if payload["unique_raw_object_count"] != len(unique_objects):
        raise RegistryError("manifest unique raw object count mismatch")
    if payload["observation_count"] != len(selected):
        raise RegistryError("manifest observation count mismatch")
    if payload["total_unique_raw_bytes"] != sum(unique_objects.values()):
        raise RegistryError("manifest total unique raw bytes mismatch")
    expected_fingerprint = input_fingerprint(
        registry.raw_sha256,
        claimed_ids,
    )
    if payload["input_fingerprint_sha256"] != expected_fingerprint:
        raise RegistryError("manifest input fingerprint mismatch")
    return payload
