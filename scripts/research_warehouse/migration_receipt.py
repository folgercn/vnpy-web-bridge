"""Create-only signed receipts for logical Research custody migration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .backup_contracts import (
    AUTHORITY_FIELDS,
    MIGRATION_PURPOSE,
    MIGRATION_RECEIPT_SCHEMA,
    WarehouseSnapshot,
    false_authority,
    require_identifier,
    require_sha256,
)
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .custody_paths import normalized_absolute, require_private_dir
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict
from .migration_contracts import MigrationLineage, parse_migration_lineage
from .publication import create_only_bytes
from .signing import (
    load_private_key,
    load_public_key,
    public_key_sha256,
    sign_payload,
    verify_payload,
)
from .timeutil import format_utc, parse_utc, require_utc

RECEIPT_KEYS = {
    "schema_version",
    "migration_id",
    "purpose",
    "migrated_at",
    "source_custody_identity",
    "destination_custody_identity",
    "snapshot_root_sha256",
    "object_count",
    "total_bytes",
    "raw_object_count",
    "manifest_object_count",
    "lineage",
    "genesis_batch_seal_sha256",
    "head_batch_seal_sha256",
    "head_commit_seal_sha256",
    "original_batches_resigned",
    "authority",
    "signer_key_id",
    "signer_public_key_sha256",
    "signature",
}


@dataclass(frozen=True)
class MigrationReceiptPaths:
    root: Path
    receipts: Path
    temporary: Path

    @classmethod
    def initialize(cls, root: Path) -> MigrationReceiptPaths:
        absolute = normalized_absolute(root)
        if absolute.exists():
            raise RegistryError("migration receipt root already exists")
        absolute.mkdir(mode=0o700)
        fsync_dir(absolute.parent)
        for name in ("receipts", "tmp"):
            path = absolute / name
            path.mkdir(mode=0o700)
            fsync_dir(path)
            fsync_dir(absolute)
        return cls.open(absolute)

    @classmethod
    def open(cls, root: Path) -> MigrationReceiptPaths:
        absolute = normalized_absolute(root)
        require_private_dir(absolute, "migration receipt root")
        receipts = absolute / "receipts"
        temporary = absolute / "tmp"
        require_private_dir(receipts, "migration receipts directory")
        require_private_dir(temporary, "migration receipt temporary directory")
        if (
            absolute.lstat().st_dev != receipts.lstat().st_dev
            or absolute.lstat().st_dev != temporary.lstat().st_dev
        ):
            raise RegistryError("migration receipt layout spans filesystems")
        return cls(root=absolute, receipts=receipts, temporary=temporary)


@dataclass(frozen=True)
class VerifiedMigrationReceipt:
    path: Path
    raw_sha256: str
    migration_id: str
    source_custody_identity: str
    destination_custody_identity: str
    snapshot: WarehouseSnapshot
    lineage: MigrationLineage
    payload: dict[str, Any]


def _migration_id(payload: dict[str, Any]) -> str:
    value = dict(payload)
    value["migration_id"] = ""
    return "migration-" + sha256(canonical_json(value))


def _validate(
    payload: object,
    *,
    public_key_path: Path,
    expected_public_key_sha256: str,
) -> tuple[dict[str, Any], MigrationLineage]:
    if (
        not isinstance(payload, dict)
        or set(payload) != RECEIPT_KEYS
        or payload["schema_version"] != MIGRATION_RECEIPT_SCHEMA
        or payload["purpose"] != MIGRATION_PURPOSE
    ):
        raise RegistryError("migration receipt contract mismatch")
    if payload["authority"] != false_authority() or set(
        payload["authority"]
    ) != set(AUTHORITY_FIELDS):
        raise RegistryError("migration receipt grants authority")
    if payload["original_batches_resigned"] is not False:
        raise RegistryError("migration receipt claims original batches were re-signed")
    parse_utc(payload["migrated_at"], "migration migrated_at")
    source_identity = require_sha256(
        payload["source_custody_identity"],
        "migration source custody identity",
    )
    destination_identity = require_sha256(
        payload["destination_custody_identity"],
        "migration destination custody identity",
    )
    if source_identity == destination_identity:
        raise RegistryError("migration source/destination custody identities match")
    for label in (
        "snapshot_root_sha256",
        "genesis_batch_seal_sha256",
        "head_batch_seal_sha256",
        "head_commit_seal_sha256",
    ):
        require_sha256(payload[label], f"migration {label}")
    for label in (
        "object_count",
        "total_bytes",
        "raw_object_count",
        "manifest_object_count",
    ):
        value = payload[label]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
        ):
            raise RegistryError(f"migration {label} is invalid")
    lineage = parse_migration_lineage(payload["lineage"])
    require_identifier(payload["signer_key_id"], "migration signer key ID")
    trusted = require_sha256(
        expected_public_key_sha256,
        "trusted migration signer public key",
    )
    public_key = load_public_key(public_key_path)
    if (
        public_key_sha256(public_key) != trusted
        or payload["signer_public_key_sha256"] != trusted
    ):
        raise RegistryError("migration signer public key pin mismatch")
    unsigned = verify_payload(payload, public_key)
    if payload["migration_id"] != _migration_id(unsigned):
        raise RegistryError("migration receipt ID binding mismatch")
    return payload, lineage


def _create_migration_receipt(
    *,
    paths: MigrationReceiptPaths,
    snapshot: WarehouseSnapshot,
    lineage: MigrationLineage,
    source_custody_identity: str,
    destination_custody_identity: str,
    genesis_batch_seal_sha256: str,
    head_batch_seal_sha256: str,
    head_commit_seal_sha256: str,
    signer_key_id: str,
    private_key_path: Path,
    public_key_path: Path,
    expected_public_key_sha256: str,
    now: datetime,
) -> VerifiedMigrationReceipt:
    migrated = require_utc(now, "migration migrated_at")
    private_key = load_private_key(private_key_path)
    trusted = require_sha256(
        expected_public_key_sha256,
        "trusted migration signer public key",
    )
    if public_key_sha256(private_key.public_key()) != trusted:
        raise RegistryError("migration private key is not trusted")
    unsigned: dict[str, Any] = {
        "schema_version": MIGRATION_RECEIPT_SCHEMA,
        "migration_id": "",
        "purpose": MIGRATION_PURPOSE,
        "migrated_at": format_utc(migrated, "migration migrated_at"),
        "source_custody_identity": source_custody_identity,
        "destination_custody_identity": destination_custody_identity,
        "snapshot_root_sha256": snapshot.root_sha256,
        "object_count": snapshot.object_count,
        "total_bytes": snapshot.total_bytes,
        "raw_object_count": snapshot.raw_object_count,
        "manifest_object_count": snapshot.manifest_object_count,
        "lineage": lineage.as_dict(),
        "genesis_batch_seal_sha256": genesis_batch_seal_sha256,
        "head_batch_seal_sha256": head_batch_seal_sha256,
        "head_commit_seal_sha256": head_commit_seal_sha256,
        "original_batches_resigned": False,
        "authority": false_authority(),
        "signer_key_id": require_identifier(
            signer_key_id,
            "migration signer key ID",
        ),
        "signer_public_key_sha256": trusted,
    }
    unsigned["migration_id"] = _migration_id(unsigned)
    signed = sign_payload(unsigned, private_key)
    _validate(
        signed,
        public_key_path=public_key_path,
        expected_public_key_sha256=trusted,
    )
    raw = canonical_json_line(signed)
    path = paths.receipts / f"{unsigned['migration_id']}.json"
    create_only_bytes(
        path,
        raw,
        "signed migration receipt",
        temporary_dir=paths.temporary,
    )
    return verify_migration_receipt(
        path=path,
        expected_raw_sha256=sha256(raw),
        public_key_path=public_key_path,
        expected_public_key_sha256=trusted,
        snapshot=snapshot,
    )


def verify_migration_receipt(
    *,
    path: Path,
    expected_raw_sha256: str,
    public_key_path: Path,
    expected_public_key_sha256: str,
    snapshot: WarehouseSnapshot,
) -> VerifiedMigrationReceipt:
    expected = require_sha256(
        expected_raw_sha256,
        "trusted migration receipt",
    )
    raw = read_regular_strict(
        path,
        "migration receipt",
        limit=64 * 1024 * 1024,
    )
    if sha256(raw) != expected:
        raise RegistryError("migration receipt raw hash mismatch")
    payload = parse_json_strict(raw, "migration receipt")
    validated, lineage = _validate(
        payload,
        public_key_path=public_key_path,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    if raw != canonical_json_line(validated):
        raise RegistryError("migration receipt is not canonical JSON line")
    if (
        validated["snapshot_root_sha256"] != snapshot.root_sha256
        or validated["object_count"] != snapshot.object_count
        or validated["total_bytes"] != snapshot.total_bytes
        or validated["raw_object_count"] != snapshot.raw_object_count
        or validated["manifest_object_count"] != snapshot.manifest_object_count
    ):
        raise RegistryError("migration receipt snapshot metrics mismatch")
    if path.name != f"{validated['migration_id']}.json":
        raise RegistryError("migration receipt custody filename mismatch")
    return VerifiedMigrationReceipt(
        path=path,
        raw_sha256=expected,
        migration_id=validated["migration_id"],
        source_custody_identity=validated["source_custody_identity"],
        destination_custody_identity=validated["destination_custody_identity"],
        snapshot=snapshot,
        lineage=lineage,
        payload=validated,
    )
