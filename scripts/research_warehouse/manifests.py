"""Signed append-only daily batch seals and parent-chain verification."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .filesystem import (
    WarehousePaths,
    create_only_bytes,
    custody_lock,
    read_regular_strict,
)
from .observations import load_observations, revision_state
from .registry import SourceRegistry
from .signing import (
    load_private_key,
    load_public_key,
    public_key_sha256,
    sign_payload,
    verify_payload,
)
from .timeutil import format_utc, parse_utc, require_utc

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
    "batch_seal_sha256",
    "objects",
    "observation_ids",
    "object_count",
    "observation_count",
    "total_raw_bytes",
    "signer_key_id",
    "signer_public_key_sha256",
    "authority",
    "ready",
    "signature",
}


def _seal_base(payload: dict[str, Any]) -> dict[str, Any]:
    excluded = {"batch_id", "batch_seal_sha256", "signature"}
    return {key: value for key, value in payload.items() if key not in excluded}


def _input_fingerprint(
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


def validate_manifest(
    paths: WarehousePaths,
    payload: object,
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != MANIFEST_KEYS:
        raise RegistryError("daily manifest fields do not match v1 schema")
    if payload["schema_version"] != MANIFEST_SCHEMA:
        raise RegistryError("daily manifest schema mismatch")
    if payload["authority"] != MANIFEST_AUTHORITY or payload["ready"] is not True:
        raise RegistryError("daily manifest authority/READY state mismatch")
    if not isinstance(payload["signer_key_id"], str) or ID_PATTERN.fullmatch(
        payload["signer_key_id"]
    ) is None:
        raise RegistryError("manifest signer key ID is invalid")
    if payload["signer_public_key_sha256"] != public_key_sha256(public_key):
        raise RegistryError("manifest signer public-key binding mismatch")
    unsigned = verify_payload(payload, public_key)
    claimed_seal = payload["batch_seal_sha256"]
    if not isinstance(claimed_seal, str) or SHA256_PATTERN.fullmatch(
        claimed_seal
    ) is None:
        raise RegistryError("batch seal SHA256 is invalid")
    if sha256(canonical_json(_seal_base(unsigned))) != claimed_seal:
        raise RegistryError("batch seal payload binding mismatch")
    expected_id = (
        f"batch-{payload['trade_day']}-{payload['batch_seal_sha256'][:24]}"
    )
    if payload["batch_id"] != expected_id:
        raise RegistryError("batch ID binding mismatch")
    parse_utc(payload["sealed_at"], "sealed_at")
    observations = load_observations(paths, trade_day=payload["trade_day"])
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
    expected_objects = revision_state(selected)
    if payload["objects"] != expected_objects:
        raise RegistryError("manifest revision/object lineage mismatch")
    if payload["object_count"] != len(expected_objects):
        raise RegistryError("manifest object count mismatch")
    if payload["observation_count"] != len(selected):
        raise RegistryError("manifest observation count mismatch")
    if payload["total_raw_bytes"] != sum(
        item["raw_bytes"] for item in expected_objects
    ):
        raise RegistryError("manifest total raw bytes mismatch")
    expected_fingerprint = _input_fingerprint(
        payload["registry_raw_sha256"], claimed_ids
    )
    if payload["input_fingerprint_sha256"] != expected_fingerprint:
        raise RegistryError("manifest input fingerprint mismatch")
    return payload


def load_manifest_chain(
    paths: WarehousePaths,
    public_key: Ed25519PublicKey,
) -> list[dict[str, Any]]:
    manifests: list[dict[str, Any]] = []
    for path in sorted(paths.manifests.rglob("batch-*.json")):
        raw = read_regular_strict(path, "daily batch manifest", limit=16 * 1024 * 1024)
        payload = validate_manifest(
            paths,
            parse_json_strict(raw, "daily batch manifest"),
            public_key,
        )
        if raw != canonical_json_line(payload):
            raise RegistryError("daily batch manifest is not canonical JSON")
        expected = (
            paths.manifests
            / payload["trade_day"]
            / f"{payload['batch_id']}.json"
        )
        if path != expected:
            raise RegistryError("daily batch manifest custody path binding mismatch")
        manifests.append(payload)
    if not manifests:
        return []
    by_seal = {item["batch_seal_sha256"]: item for item in manifests}
    if len(by_seal) != len(manifests):
        raise RegistryError("duplicate batch seal in manifest chain")
    roots = [
        item
        for item in manifests
        if item["parent_batch_seal_sha256"] is None
    ]
    if len(roots) != 1:
        raise RegistryError("manifest chain must have exactly one root")
    children: dict[str, list[dict[str, Any]]] = {}
    for item in manifests:
        parent = item["parent_batch_seal_sha256"]
        if parent is None:
            continue
        if parent not in by_seal:
            raise RegistryError("manifest parent seal is missing")
        children.setdefault(parent, []).append(item)
    if any(len(values) != 1 for values in children.values()):
        raise RegistryError("manifest chain fork detected")
    ordered = [roots[0]]
    while ordered[-1]["batch_seal_sha256"] in children:
        child = children[ordered[-1]["batch_seal_sha256"]][0]
        if parse_utc(child["sealed_at"], "sealed_at") <= parse_utc(
            ordered[-1]["sealed_at"], "sealed_at"
        ):
            raise RegistryError("manifest sealed_at must increase along chain")
        ordered.append(child)
    if len(ordered) != len(manifests):
        raise RegistryError("manifest chain contains a cycle or disconnected node")
    return ordered


def seal_daily_batch(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    trade_day: str,
    private_key_path: Path,
    signer_key_id: str,
    sealed_at: datetime | None = None,
) -> Path:
    if ID_PATTERN.fullmatch(signer_key_id) is None:
        raise RegistryError("manifest signer key ID is invalid")
    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    sealed = require_utc(
        sealed_at or datetime.now(timezone.utc), "sealed_at"
    )
    with custody_lock(paths, "manifest-chain"):
        chain = load_manifest_chain(paths, public_key)
        observations = load_observations(paths, trade_day=trade_day)
        if not observations:
            raise RegistryError("cannot seal a day with no raw observations")
        observation_ids = sorted(item["observation_id"] for item in observations)
        fingerprint = _input_fingerprint(registry.raw_sha256, observation_ids)
        if chain and chain[-1]["input_fingerprint_sha256"] == fingerprint:
            existing = (
                paths.root
                / "manifests"
                / chain[-1]["trade_day"]
                / f"{chain[-1]['batch_id']}.json"
            )
            return existing
        if chain and sealed <= parse_utc(chain[-1]["sealed_at"], "sealed_at"):
            raise RegistryError("sealed_at must be later than parent batch")
        objects = revision_state(observations)
        payload: dict[str, Any] = {
            "schema_version": MANIFEST_SCHEMA,
            "batch_id": "",
            "trade_day": trade_day,
            "sealed_at": format_utc(sealed, "sealed_at"),
            "registry_raw_sha256": registry.raw_sha256,
            "input_fingerprint_sha256": fingerprint,
            "parent_batch_seal_sha256": (
                chain[-1]["batch_seal_sha256"] if chain else None
            ),
            "batch_seal_sha256": "",
            "objects": objects,
            "observation_ids": observation_ids,
            "object_count": len(objects),
            "observation_count": len(observations),
            "total_raw_bytes": sum(item["raw_bytes"] for item in objects),
            "signer_key_id": signer_key_id,
            "signer_public_key_sha256": public_key_sha256(public_key),
            "authority": MANIFEST_AUTHORITY,
            "ready": True,
        }
        payload["batch_seal_sha256"] = sha256(
            canonical_json(_seal_base(payload))
        )
        payload["batch_id"] = (
            f"batch-{trade_day}-{payload['batch_seal_sha256'][:24]}"
        )
        signed = sign_payload(payload, private_key)
        parent = paths.private_subdir(paths.manifests, trade_day)
        output = parent / f"{signed['batch_id']}.json"
        create_only_bytes(
            output, canonical_json_line(signed), "daily batch manifest"
        )
        validate_manifest(paths, signed, public_key)
        return output


def verify_manifest_chain(
    *,
    paths: WarehousePaths,
    public_key_path: Path,
) -> list[dict[str, Any]]:
    return load_manifest_chain(paths, load_public_key(public_key_path))
