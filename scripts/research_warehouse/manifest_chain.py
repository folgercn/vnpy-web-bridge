"""Load, order, and externally anchor signed manifest chains."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json_line, parse_json_strict
from .errors import RegistryError
from .filesystem import WarehousePaths, read_regular_strict
from .manifest_commits import commit_receipt_path, load_commit_receipt
from .manifest_contracts import SHA256_PATTERN
from .manifest_validation import validate_manifest
from .models import SourceRegistry
from .timeutil import parse_utc


def load_manifest_chain(
    paths: WarehousePaths,
    public_key: Ed25519PublicKey,
    registry: SourceRegistry,
    *,
    allow_uncommitted_head: bool = False,
) -> list[dict[str, Any]]:
    manifests: list[dict[str, Any]] = []
    for path in sorted(paths.manifests.rglob("batch-*.json")):
        raw = read_regular_strict(
            path, "daily batch manifest", limit=16 * 1024 * 1024
        )
        payload = validate_manifest(
            paths,
            parse_json_strict(raw, "daily batch manifest"),
            public_key,
            registry,
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
        receipt_path = commit_receipt_path(path, payload["batch_id"])
        enriched = dict(payload)
        enriched["commit_receipt"] = (
            load_commit_receipt(receipt_path, payload, public_key)
            if receipt_path.exists()
            else None
        )
        manifests.append(enriched)
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
    uncommitted = [
        index
        for index, item in enumerate(ordered)
        if item["commit_receipt"] is None
    ]
    allowed = [len(ordered) - 1] if allow_uncommitted_head else []
    if uncommitted and uncommitted != allowed:
        raise RegistryError("manifest chain contains an uncommitted batch")
    return ordered


def require_chain_anchors(
    chain: list[dict[str, Any]],
    *,
    expected_genesis_seal_sha256: str | None,
    expected_head_seal_sha256: str | None,
) -> None:
    if not chain:
        if (
            expected_genesis_seal_sha256 is not None
            or expected_head_seal_sha256 is not None
        ):
            raise RegistryError("manifest chain is empty but trusted anchors are not")
        return
    for label, value in (
        ("genesis", expected_genesis_seal_sha256),
        ("head", expected_head_seal_sha256),
    ):
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise RegistryError(f"trusted {label} seal anchor is required")
    if chain[0]["batch_seal_sha256"] != expected_genesis_seal_sha256:
        raise RegistryError("manifest genesis does not match trusted anchor")
    if chain[-1]["batch_seal_sha256"] != expected_head_seal_sha256:
        raise RegistryError("manifest head does not match trusted anchor")
