"""Logical warehouse migration and signed transfer-receipt verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .backup_chain_binding import require_complete_chain_snapshot
from .errors import RegistryError
from .filesystem import WarehousePaths
from .held_custody import (
    hold_custody_root,
    materialize_held_snapshot,
    scan_held_snapshot,
)
from .manifests import verify_manifest_chain
from .migration_contracts import migration_lineage
from .migration_receipt import (
    MigrationReceiptPaths,
    VerifiedMigrationReceipt,
    _create_migration_receipt,
    _migration_receipt_location,
    _verify_migration_receipt_held,
)
from .models import SourceRegistry

CUSTODY_DOMAIN = "vnpy-research-warehouse-custody-v1"


@dataclass(frozen=True)
class VerifiedMigration:
    destination: WarehousePaths
    receipt: VerifiedMigrationReceipt


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
    with hold_custody_root(source.root) as source_held:
        source_chain = verify_manifest_chain(
            paths=source,
            public_key_path=manifest_public_key_path,
            registry=registry,
            expected_genesis_seal_sha256=expected_genesis_seal_sha256,
            expected_head_seal_sha256=expected_head_seal_sha256,
            expected_head_commit_seal_sha256=(
                expected_head_commit_seal_sha256
            ),
            offline=True,
        )
        snapshot = scan_held_snapshot(
            source_held,
            raw_prefix="raw",
            manifests_prefix="manifests",
        )
        require_complete_chain_snapshot(snapshot, source_chain)
        destination = WarehousePaths.initialize(destination_root)
        with (
            hold_custody_root(destination.root) as destination_held,
            hold_custody_root(receipt_paths.root) as receipt_held,
        ):
            materialize_held_snapshot(
                source=source_held,
                destination=destination_held,
                source_prefix="",
                destination_prefix="",
                snapshot=snapshot,
                minimum_free_bytes_after=minimum_free_bytes_after,
            )
            destination_snapshot = scan_held_snapshot(
                destination_held,
                raw_prefix="raw",
                manifests_prefix="manifests",
            )
            if destination_snapshot != snapshot:
                raise RegistryError(
                    "migration destination snapshot differs from source"
                )
            destination_chain = verify_manifest_chain(
                paths=destination,
                public_key_path=manifest_public_key_path,
                registry=registry,
                expected_genesis_seal_sha256=(
                    expected_genesis_seal_sha256
                ),
                expected_head_seal_sha256=expected_head_seal_sha256,
                expected_head_commit_seal_sha256=(
                    expected_head_commit_seal_sha256
                ),
                offline=True,
            )
            require_complete_chain_snapshot(
                destination_snapshot,
                destination_chain,
            )
            source_lineage = migration_lineage(source_chain)
            if migration_lineage(destination_chain) != source_lineage:
                raise RegistryError("migration logical raw lineage changed")
            receipt = _create_migration_receipt(
                paths=receipt_paths,
                source_held=source_held,
                destination_held=destination_held,
                receipt_held=receipt_held,
                snapshot=snapshot,
                lineage=source_lineage,
                genesis_batch_seal_sha256=expected_genesis_seal_sha256,
                head_batch_seal_sha256=expected_head_seal_sha256,
                head_commit_seal_sha256=(
                    expected_head_commit_seal_sha256
                ),
                signer_key_id=migration_signer_key_id,
                private_key_path=migration_private_key_path,
                public_key_path=migration_public_key_path,
                expected_public_key_sha256=(
                    expected_migration_public_key_sha256
                ),
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
    receipt_root, canonical_receipt_path = _migration_receipt_location(
        receipt_path
    )
    with (
        hold_custody_root(source.root) as source_held,
        hold_custody_root(destination.root) as destination_held,
        hold_custody_root(receipt_root) as receipt_held,
    ):
        source_snapshot = scan_held_snapshot(
            source_held,
            raw_prefix="raw",
            manifests_prefix="manifests",
        )
        if (
            scan_held_snapshot(
                destination_held,
                raw_prefix="raw",
                manifests_prefix="manifests",
            )
            != source_snapshot
        ):
            raise RegistryError("migration source/destination snapshot mismatch")
        receipt = _verify_migration_receipt_held(
            path=canonical_receipt_path,
            held=receipt_held,
            expected_raw_sha256=expected_receipt_raw_sha256,
            public_key_path=migration_public_key_path,
            expected_public_key_sha256=(
                expected_migration_public_key_sha256
            ),
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
        require_complete_chain_snapshot(source_snapshot, source_chain)
        lineage = migration_lineage(source_chain)
        if (
            migration_lineage(destination_chain) != lineage
            or receipt.lineage != lineage
        ):
            raise RegistryError("migration receipt lineage does not match custody")
        if (
            receipt.source_custody_identity
            != source_held.identity_sha256(domain=CUSTODY_DOMAIN)
            or receipt.destination_custody_identity
            != destination_held.identity_sha256(domain=CUSTODY_DOMAIN)
        ):
            raise RegistryError(
                "migration receipt was replayed to different custody"
            )
        return receipt
