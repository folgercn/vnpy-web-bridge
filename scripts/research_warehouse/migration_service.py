"""Logical warehouse migration and signed transfer-receipt verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .backup_chain_binding import require_complete_chain_snapshot
from .backup_custody import custody_identity, materialize_snapshot
from .backup_inventory import scan_warehouse_snapshot
from .errors import RegistryError
from .filesystem import WarehousePaths
from .manifests import verify_manifest_chain
from .migration_contracts import migration_lineage
from .migration_receipt import (
    MigrationReceiptPaths,
    VerifiedMigrationReceipt,
    _create_migration_receipt,
    verify_migration_receipt,
)
from .models import SourceRegistry

CUSTODY_DOMAIN = "vnpy-research-warehouse-custody-v1"


@dataclass(frozen=True)
class VerifiedMigration:
    destination: WarehousePaths
    receipt: VerifiedMigrationReceipt


def _destination_parent(paths: WarehousePaths, relative_path: str) -> Path:
    parts = Path(relative_path).parts
    if parts[0] == "raw":
        base = paths.raw
    elif parts[0] == "manifests":
        base = paths.manifests
    else:
        raise RegistryError("migration object is outside warehouse custody")
    components = parts[1:-1]
    return paths.private_subdir(base, *components) if components else base


def migrate_warehouse(
    *,
    source: WarehousePaths,
    destination_root: Path,
    receipt_paths: MigrationReceiptPaths,
    manifest_public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    expected_head_commit_seal_sha256: str,
    migration_signer_key_id: str,
    migration_private_key_path: Path,
    migration_public_key_path: Path,
    expected_migration_public_key_sha256: str,
    minimum_free_bytes_after: int,
    now: datetime,
) -> VerifiedMigration:
    source_chain = verify_manifest_chain(
        paths=source,
        public_key_path=manifest_public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        offline=True,
    )
    snapshot = scan_warehouse_snapshot(source)
    require_complete_chain_snapshot(snapshot, source_chain)
    destination = WarehousePaths.initialize(destination_root)
    materialize_snapshot(
        source_root=source.root,
        destination_root=destination.root,
        temporary_dir=destination.temporary,
        snapshot=snapshot,
        minimum_free_bytes_after=minimum_free_bytes_after,
        destination_parent=lambda relative: _destination_parent(
            destination,
            relative,
        ),
    )
    if scan_warehouse_snapshot(destination) != snapshot:
        raise RegistryError("migration destination snapshot differs from source")
    destination_chain = verify_manifest_chain(
        paths=destination,
        public_key_path=manifest_public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        offline=True,
    )
    source_lineage = migration_lineage(source_chain)
    if migration_lineage(destination_chain) != source_lineage:
        raise RegistryError("migration logical raw lineage changed")
    source_identity = custody_identity(source.root, domain=CUSTODY_DOMAIN)
    destination_identity = custody_identity(
        destination.root,
        domain=CUSTODY_DOMAIN,
    )
    receipt = _create_migration_receipt(
        paths=receipt_paths,
        snapshot=snapshot,
        lineage=source_lineage,
        source_custody_identity=source_identity,
        destination_custody_identity=destination_identity,
        genesis_batch_seal_sha256=expected_genesis_seal_sha256,
        head_batch_seal_sha256=expected_head_seal_sha256,
        head_commit_seal_sha256=expected_head_commit_seal_sha256,
        signer_key_id=migration_signer_key_id,
        private_key_path=migration_private_key_path,
        public_key_path=migration_public_key_path,
        expected_public_key_sha256=expected_migration_public_key_sha256,
        now=now,
    )
    return VerifiedMigration(destination=destination, receipt=receipt)


def verify_completed_migration(
    *,
    source: WarehousePaths,
    destination: WarehousePaths,
    receipt_path: Path,
    expected_receipt_raw_sha256: str,
    manifest_public_key_path: Path,
    registry: SourceRegistry,
    migration_public_key_path: Path,
    expected_migration_public_key_sha256: str,
) -> VerifiedMigrationReceipt:
    source_snapshot = scan_warehouse_snapshot(source)
    if scan_warehouse_snapshot(destination) != source_snapshot:
        raise RegistryError("migration source/destination snapshot mismatch")
    receipt = verify_migration_receipt(
        path=receipt_path,
        expected_raw_sha256=expected_receipt_raw_sha256,
        public_key_path=migration_public_key_path,
        expected_public_key_sha256=expected_migration_public_key_sha256,
        snapshot=source_snapshot,
    )
    payload = receipt.payload
    source_chain = verify_manifest_chain(
        paths=source,
        public_key_path=manifest_public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=payload[
            "genesis_batch_seal_sha256"
        ],
        expected_head_seal_sha256=payload["head_batch_seal_sha256"],
        expected_head_commit_seal_sha256=payload[
            "head_commit_seal_sha256"
        ],
        offline=True,
    )
    destination_chain = verify_manifest_chain(
        paths=destination,
        public_key_path=manifest_public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=payload[
            "genesis_batch_seal_sha256"
        ],
        expected_head_seal_sha256=payload["head_batch_seal_sha256"],
        expected_head_commit_seal_sha256=payload[
            "head_commit_seal_sha256"
        ],
        offline=True,
    )
    lineage = migration_lineage(source_chain)
    if migration_lineage(destination_chain) != lineage or receipt.lineage != lineage:
        raise RegistryError("migration receipt lineage does not match custody")
    if (
        receipt.source_custody_identity
        != custody_identity(source.root, domain=CUSTODY_DOMAIN)
        or receipt.destination_custody_identity
        != custody_identity(destination.root, domain=CUSTODY_DOMAIN)
    ):
        raise RegistryError("migration receipt was replayed to different custody")
    return receipt
