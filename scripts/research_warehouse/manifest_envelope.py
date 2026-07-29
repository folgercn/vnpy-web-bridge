"""Offline validation of signed manifests using only raw evidence."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, sha256
from .errors import RegistryError
from .filesystem import WarehousePaths, read_regular_strict
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
from .observation_contracts import raw_object_id, revision_occurrence_id
from .signing import public_key_sha256, verify_payload
from .timeutil import parse_utc
from .validation import validate_source_bytes

REVISION_KEYS = {
    "revision_id",
    "revision_sequence",
    "object_id",
    "source_id",
    "exchange",
    "trade_day",
    "raw_sha256",
    "raw_bytes",
    "raw_relative_path",
    "first_seen_at",
    "last_seen_at",
    "supersedes_revision_id",
    "supersedes_object_id",
    "observation_ids",
}


def _validate_revision(
    paths: WarehousePaths,
    item: object,
    *,
    registry: SourceRegistry,
    trade_day: str,
    sealed_at,
) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != REVISION_KEYS:
        raise RegistryError("signed manifest revision schema mismatch")
    for label in ("revision_id", "object_id"):
        value = item[label]
        if not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None:
            raise RegistryError(f"signed revision {label} is invalid")
    raw_hash = item["raw_sha256"]
    if not isinstance(raw_hash, str) or SHA256_PATTERN.fullmatch(raw_hash) is None:
        raise RegistryError("signed revision raw SHA256 is invalid")
    if (
        not isinstance(item["revision_sequence"], int)
        or isinstance(item["revision_sequence"], bool)
        or item["revision_sequence"] < 1
    ):
        raise RegistryError("signed revision sequence is invalid")
    if (
        not isinstance(item["raw_bytes"], int)
        or isinstance(item["raw_bytes"], bool)
        or item["raw_bytes"] < 1
    ):
        raise RegistryError("signed revision raw byte count is invalid")
    try:
        source = registry.source(item["source_id"])
    except (KeyError, TypeError) as exc:
        raise RegistryError("signed revision source is not trusted") from exc
    if item["exchange"] != source.exchange or item["trade_day"] != trade_day:
        raise RegistryError("signed revision source/day binding mismatch")
    expected_object_id = raw_object_id(source, trade_day, raw_hash)
    if item["object_id"] != expected_object_id:
        raise RegistryError("signed revision object ID binding mismatch")
    expected_revision_id = revision_occurrence_id(
        source_id=source.source_id,
        trade_day=trade_day,
        observation_sequence=item["revision_sequence"],
        object_id=expected_object_id,
        supersedes_revision_id=item["supersedes_revision_id"],
    )
    if item["revision_id"] != expected_revision_id:
        raise RegistryError("signed revision ID binding mismatch")
    expected_relative = (
        f"raw/{source.exchange.lower()}/{trade_day}/{source.source_id}/"
        f"{raw_hash}.raw"
    )
    if item["raw_relative_path"] != expected_relative:
        raise RegistryError("signed revision raw custody path mismatch")
    first_seen = parse_utc(item["first_seen_at"], "first_seen_at")
    last_seen = parse_utc(item["last_seen_at"], "last_seen_at")
    if first_seen > last_seen or last_seen > sealed_at:
        raise RegistryError("signed revision observation time is invalid")
    observation_ids = item["observation_ids"]
    if (
        not isinstance(observation_ids, list)
        or not observation_ids
        or len(set(observation_ids)) != len(observation_ids)
        or any(
            not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None
            for value in observation_ids
        )
    ):
        raise RegistryError("signed revision observation IDs are invalid")
    raw_path = paths.root / expected_relative
    raw = read_regular_strict(raw_path, "signed manifest raw evidence")
    if len(raw) != item["raw_bytes"] or sha256(raw) != raw_hash:
        raise RegistryError("signed manifest raw evidence binding mismatch")
    validate_source_bytes(raw, source, trade_day)
    return item


def _validate_revision_chain(revisions: list[dict[str, Any]]) -> None:
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in revisions:
        groups.setdefault(item["source_id"], []).append(item)
    for items in groups.values():
        ordered = sorted(
            items,
            key=lambda item: (item["revision_sequence"], item["revision_id"]),
        )
        if ordered != items:
            raise RegistryError("signed revisions are not deterministically sorted")
        previous = None
        for item in ordered:
            if previous is None:
                if (
                    item["supersedes_revision_id"] is not None
                    or item["supersedes_object_id"] is not None
                ):
                    raise RegistryError("first signed revision supersedes evidence")
            elif (
                item["revision_sequence"] <= previous["revision_sequence"]
                or item["supersedes_revision_id"] != previous["revision_id"]
                or item["supersedes_object_id"] != previous["object_id"]
            ):
                raise RegistryError("signed revision lineage is invalid")
            previous = item


def validate_manifest_envelope(
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
    if (
        not isinstance(payload["signer_key_id"], str)
        or ID_PATTERN.fullmatch(payload["signer_key_id"]) is None
    ):
        raise RegistryError("manifest signer key ID is invalid")
    if payload["signer_public_key_sha256"] != public_key_sha256(public_key):
        raise RegistryError("manifest signer public-key binding mismatch")
    unsigned = verify_payload(payload, public_key)
    trade_day = validate_manifest_trade_day(payload["trade_day"])
    sealed_at = parse_utc(payload["sealed_at"], "sealed_at")
    claimed_seal = payload["batch_seal_sha256"]
    if (
        not isinstance(claimed_seal, str)
        or SHA256_PATTERN.fullmatch(claimed_seal) is None
    ):
        raise RegistryError("batch seal SHA256 is invalid")
    for label in ("parent_batch_seal_sha256", "parent_commit_seal_sha256"):
        value = payload[label]
        if value is not None and (
            not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None
        ):
            raise RegistryError(f"manifest {label} is invalid")
    if (payload["parent_batch_seal_sha256"] is None) != (
        payload["parent_commit_seal_sha256"] is None
    ):
        raise RegistryError("manifest parent seals must be paired")
    if sha256(canonical_json(seal_base(unsigned))) != claimed_seal:
        raise RegistryError("batch seal payload binding mismatch")
    if payload["batch_id"] != f"batch-{trade_day}-{claimed_seal[:24]}":
        raise RegistryError("batch ID binding mismatch")
    claimed_ids = payload["observation_ids"]
    if (
        not isinstance(claimed_ids, list)
        or not claimed_ids
        or claimed_ids != sorted(set(claimed_ids))
        or any(
            not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None
            for value in claimed_ids
        )
    ):
        raise RegistryError("manifest observation set is invalid")
    values = payload["revisions"]
    if not isinstance(values, list) or not values:
        raise RegistryError("signed manifest revisions are invalid")
    revisions = [
        _validate_revision(
            paths,
            item,
            registry=registry,
            trade_day=trade_day,
            sealed_at=sealed_at,
        )
        for item in values
    ]
    _validate_revision_chain(revisions)
    revision_observations = [
        observation_id
        for revision in revisions
        for observation_id in revision["observation_ids"]
    ]
    if (
        len(set(revision_observations)) != len(revision_observations)
        or sorted(revision_observations) != claimed_ids
    ):
        raise RegistryError("signed revision/observation binding mismatch")
    if payload["revision_count"] != len(revisions):
        raise RegistryError("manifest revision count mismatch")
    unique_objects: dict[str, int] = {}
    for revision in revisions:
        existing = unique_objects.setdefault(
            revision["object_id"],
            revision["raw_bytes"],
        )
        if existing != revision["raw_bytes"]:
            raise RegistryError("signed object byte count changed")
    if payload["unique_raw_object_count"] != len(unique_objects):
        raise RegistryError("manifest unique raw object count mismatch")
    if payload["observation_count"] != len(claimed_ids):
        raise RegistryError("manifest observation count mismatch")
    if payload["total_unique_raw_bytes"] != sum(unique_objects.values()):
        raise RegistryError("manifest total unique raw bytes mismatch")
    if payload["input_fingerprint_sha256"] != input_fingerprint(
        registry.raw_sha256,
        claimed_ids,
    ):
        raise RegistryError("manifest input fingerprint mismatch")
    return payload
