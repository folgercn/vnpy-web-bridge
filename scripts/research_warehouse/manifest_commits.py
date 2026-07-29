"""Signed commit receipts created only after manifest parent fsync succeeds."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json_line, parse_json_strict
from .errors import RegistryError
from .filesystem import WarehousePaths, create_only_bytes, read_regular_strict
from .manifest_contracts import ID_PATTERN, SHA256_PATTERN
from .signing import public_key_sha256, sign_payload, verify_payload
from .timeutil import format_utc, parse_utc

COMMIT_SCHEMA = "vnpy_research_manifest_commit_receipt_v1"
COMMIT_AUTHORITY = "RESEARCH_EVIDENCE_COMMIT_ONLY"
COMMIT_KEYS = {
    "schema_version",
    "batch_id",
    "batch_seal_sha256",
    "registry_raw_sha256",
    "committed_at",
    "signer_key_id",
    "signer_public_key_sha256",
    "authority",
    "ready",
    "signature",
}


def commit_receipt_path(manifest_path: Path, batch_id: str) -> Path:
    return manifest_path.parent / f"commit-{batch_id}.json"


def validate_commit_receipt(
    payload: object,
    manifest: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != COMMIT_KEYS:
        raise RegistryError("manifest commit receipt fields do not match v1 schema")
    if payload["schema_version"] != COMMIT_SCHEMA:
        raise RegistryError("manifest commit receipt schema mismatch")
    if payload["authority"] != COMMIT_AUTHORITY or payload["ready"] is not True:
        raise RegistryError("manifest commit receipt READY/authority mismatch")
    if (
        payload["batch_id"] != manifest["batch_id"]
        or payload["batch_seal_sha256"] != manifest["batch_seal_sha256"]
        or payload["registry_raw_sha256"] != manifest["registry_raw_sha256"]
    ):
        raise RegistryError("manifest commit receipt batch binding mismatch")
    if not isinstance(payload["batch_seal_sha256"], str) or SHA256_PATTERN.fullmatch(
        payload["batch_seal_sha256"]
    ) is None:
        raise RegistryError("manifest commit receipt seal is invalid")
    if not isinstance(payload["signer_key_id"], str) or ID_PATTERN.fullmatch(
        payload["signer_key_id"]
    ) is None:
        raise RegistryError("manifest commit receipt signer ID is invalid")
    if (
        payload["signer_key_id"] != manifest["signer_key_id"]
        or payload["signer_public_key_sha256"]
        != manifest["signer_public_key_sha256"]
        or payload["signer_public_key_sha256"] != public_key_sha256(public_key)
    ):
        raise RegistryError("manifest commit receipt signer binding mismatch")
    verify_payload(payload, public_key)
    committed_at = parse_utc(payload["committed_at"], "committed_at")
    if committed_at < parse_utc(manifest["sealed_at"], "sealed_at"):
        raise RegistryError("manifest commit receipt predates manifest signature")
    return payload


def load_commit_receipt(
    path: Path,
    manifest: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    raw = read_regular_strict(
        path,
        "manifest commit receipt",
        limit=2 * 1024 * 1024,
    )
    payload = validate_commit_receipt(
        parse_json_strict(raw, "manifest commit receipt"),
        manifest,
        public_key,
    )
    if raw != canonical_json_line(payload):
        raise RegistryError("manifest commit receipt is not canonical JSON")
    expected = path.parent / f"commit-{manifest['batch_id']}.json"
    if path != expected:
        raise RegistryError("manifest commit receipt custody path mismatch")
    return payload


def create_commit_receipt(
    *,
    paths: WarehousePaths,
    manifest_path: Path,
    manifest: dict[str, Any],
    private_key: Ed25519PrivateKey,
    committed_at: datetime,
) -> dict[str, Any]:
    payload = {
        "schema_version": COMMIT_SCHEMA,
        "batch_id": manifest["batch_id"],
        "batch_seal_sha256": manifest["batch_seal_sha256"],
        "registry_raw_sha256": manifest["registry_raw_sha256"],
        "committed_at": format_utc(committed_at, "committed_at"),
        "signer_key_id": manifest["signer_key_id"],
        "signer_public_key_sha256": manifest["signer_public_key_sha256"],
        "authority": COMMIT_AUTHORITY,
        "ready": True,
    }
    signed = sign_payload(payload, private_key)
    output = commit_receipt_path(manifest_path, manifest["batch_id"])
    create_only_bytes(
        output,
        canonical_json_line(signed),
        "manifest commit receipt",
        temporary_dir=paths.temporary,
    )
    return load_commit_receipt(output, manifest, private_key.public_key())
