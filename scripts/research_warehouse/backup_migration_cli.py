"""Thin CLI for Research backup, restore, and custody migration drills."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .backup_custody import BackupPaths
from .backup_service import create_append_only_backup
from .commit_anchors import load_commit_anchor_ledger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .filesystem import WarehousePaths
from .migration_receipt import MigrationReceiptPaths
from .migration_service import migrate_warehouse, verify_completed_migration
from .rebuild_binding import load_normalization_binding
from .registry import load_registry
from .restore_service import restore_and_verify
from .timeutil import parse_utc

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _sha(value: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected lowercase SHA256")
    return value


def _parent(value: str) -> str | None:
    if value == "GENESIS":
        return None
    return _sha(value)


def _add_manifest_context(command: argparse.ArgumentParser) -> None:
    command.add_argument("--manifest-public-key", type=Path, required=True)
    command.add_argument("--registry", type=Path, required=True)
    command.add_argument("--expected-genesis-seal", type=_sha, required=True)
    command.add_argument("--expected-head-seal", type=_sha, required=True)
    command.add_argument("--expected-head-commit-seal", type=_sha, required=True)


def _add_rebuild_context(command: argparse.ArgumentParser) -> None:
    _add_manifest_context(command)
    command.add_argument("--commit-anchor-ledger", type=Path, required=True)
    command.add_argument(
        "--expected-commit-anchor-ledger-sha256",
        type=_sha,
        required=True,
    )
    command.add_argument("--tool-commit-sha", required=True)
    command.add_argument("--dependency-lock", type=Path, required=True)
    command.add_argument(
        "--expected-dependency-lock-sha256",
        type=_sha,
        required=True,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    init_backup = commands.add_parser("init-backup")
    init_backup.add_argument("--backup-root", type=Path, required=True)
    init_receipts = commands.add_parser("init-receipts")
    init_receipts.add_argument("--receipt-root", type=Path, required=True)

    backup = commands.add_parser("backup")
    backup.add_argument("--source-root", type=Path, required=True)
    backup.add_argument("--source-derived-root", type=Path, required=True)
    backup.add_argument("--backup-root", type=Path, required=True)
    _add_rebuild_context(backup)
    backup.add_argument(
        "--expected-parent-backup-anchor",
        type=_parent,
        required=True,
        help="GENESIS or externally pinned current anchor SHA256",
    )
    backup.add_argument("--backup-signer-key-id", required=True)
    backup.add_argument("--backup-private-key", type=Path, required=True)
    backup.add_argument("--backup-public-key", type=Path, required=True)
    backup.add_argument(
        "--expected-backup-public-key-sha256",
        type=_sha,
        required=True,
    )
    backup.add_argument("--minimum-free-bytes-after", type=int, default=0)
    backup.add_argument("--trusted-now", required=True)

    restore = commands.add_parser("restore")
    restore.add_argument("--backup-root", type=Path, required=True)
    restore.add_argument("--expected-backup-anchor", type=_sha, required=True)
    restore.add_argument("--backup-public-key", type=Path, required=True)
    restore.add_argument(
        "--expected-backup-public-key-sha256",
        type=_sha,
        required=True,
    )
    restore.add_argument("--restore-root", type=Path, required=True)
    restore.add_argument("--restore-derived-root", type=Path, required=True)
    _add_rebuild_context(restore)
    restore.add_argument("--minimum-free-bytes-after", type=int, default=0)

    migrate = commands.add_parser("migrate")
    migrate.add_argument("--source-root", type=Path, required=True)
    migrate.add_argument("--destination-root", type=Path, required=True)
    migrate.add_argument("--receipt-root", type=Path, required=True)
    _add_manifest_context(migrate)
    migrate.add_argument("--migration-signer-key-id", required=True)
    migrate.add_argument("--migration-private-key", type=Path, required=True)
    migrate.add_argument("--migration-public-key", type=Path, required=True)
    migrate.add_argument(
        "--expected-migration-public-key-sha256",
        type=_sha,
        required=True,
    )
    migrate.add_argument("--minimum-free-bytes-after", type=int, default=0)
    migrate.add_argument("--trusted-now", required=True)

    verify = commands.add_parser("verify-migration")
    verify.add_argument("--source-root", type=Path, required=True)
    verify.add_argument("--destination-root", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--expected-receipt-sha256", type=_sha, required=True)
    verify.add_argument("--manifest-public-key", type=Path, required=True)
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--migration-public-key", type=Path, required=True)
    verify.add_argument(
        "--expected-migration-public-key-sha256",
        type=_sha,
        required=True,
    )
    return result


def _rebuild_values(args):
    registry = load_registry(args.registry)
    ledger = load_commit_anchor_ledger(
        args.commit_anchor_ledger,
        expected_raw_sha256=args.expected_commit_anchor_ledger_sha256,
    )
    binding = load_normalization_binding(
        tool_commit_sha=args.tool_commit_sha,
        dependency_lock_path=args.dependency_lock,
        expected_dependency_lock_sha256=(
            args.expected_dependency_lock_sha256
        ),
        registry_raw_sha256=registry.raw_sha256,
    )
    return registry, ledger, binding


def run(args: argparse.Namespace) -> dict:
    if args.command == "init-backup":
        paths = BackupPaths.initialize(args.backup_root)
        return {"backup_root": str(paths.root), "status": "BACKUP_ROOT_INITIALIZED"}
    if args.command == "init-receipts":
        paths = MigrationReceiptPaths.initialize(args.receipt_root)
        return {
            "receipt_root": str(paths.root),
            "status": "MIGRATION_RECEIPT_ROOT_INITIALIZED",
        }
    if args.command == "backup":
        registry, ledger, binding = _rebuild_values(args)
        anchor = create_append_only_backup(
            source=WarehousePaths.open(args.source_root),
            source_derived=DerivedPaths.open(args.source_derived_root),
            backup=BackupPaths.open(args.backup_root),
            public_key_path=args.manifest_public_key,
            registry=registry,
            expected_genesis_seal_sha256=args.expected_genesis_seal,
            expected_head_seal_sha256=args.expected_head_seal,
            expected_head_commit_seal_sha256=args.expected_head_commit_seal,
            ledger=ledger,
            binding=binding,
            expected_parent_anchor_raw_sha256=(
                args.expected_parent_backup_anchor
            ),
            backup_signer_key_id=args.backup_signer_key_id,
            backup_private_key_path=args.backup_private_key,
            backup_public_key_path=args.backup_public_key,
            expected_backup_public_key_sha256=(
                args.expected_backup_public_key_sha256
            ),
            minimum_free_bytes_after=args.minimum_free_bytes_after,
            now=parse_utc(args.trusted_now, "trusted backup time"),
        )
        return {
            "anchor": str(anchor.path),
            "anchor_raw_sha256": anchor.raw_sha256,
            "snapshot_root_sha256": anchor.snapshot.root_sha256,
            "status": "APPEND_ONLY_BACKUP_VERIFIED",
        }
    if args.command == "restore":
        registry, ledger, binding = _rebuild_values(args)
        restored = restore_and_verify(
            backup=BackupPaths.open(args.backup_root),
            expected_backup_anchor_raw_sha256=args.expected_backup_anchor,
            backup_public_key_path=args.backup_public_key,
            expected_backup_public_key_sha256=(
                args.expected_backup_public_key_sha256
            ),
            restore_root=args.restore_root,
            restore_derived_root=args.restore_derived_root,
            manifest_public_key_path=args.manifest_public_key,
            registry=registry,
            ledger=ledger,
            binding=binding,
            minimum_free_bytes_after=args.minimum_free_bytes_after,
        )
        return {
            "restored_root": str(restored.evidence.root),
            "restored_derived_root": str(restored.derived.root),
            "snapshot_root_sha256": restored.backup_anchor.snapshot.root_sha256,
            "status": "RESTORE_REBUILD_VERIFIED",
        }
    if args.command == "migrate":
        migrated = migrate_warehouse(
            source=WarehousePaths.open(args.source_root),
            destination_root=args.destination_root,
            receipt_paths=MigrationReceiptPaths.open(args.receipt_root),
            manifest_public_key_path=args.manifest_public_key,
            registry=load_registry(args.registry),
            expected_genesis_seal_sha256=args.expected_genesis_seal,
            expected_head_seal_sha256=args.expected_head_seal,
            expected_head_commit_seal_sha256=args.expected_head_commit_seal,
            migration_signer_key_id=args.migration_signer_key_id,
            migration_private_key_path=args.migration_private_key,
            migration_public_key_path=args.migration_public_key,
            expected_migration_public_key_sha256=(
                args.expected_migration_public_key_sha256
            ),
            minimum_free_bytes_after=args.minimum_free_bytes_after,
            now=parse_utc(args.trusted_now, "trusted migration time"),
        )
        return {
            "destination_root": str(migrated.destination.root),
            "receipt": str(migrated.receipt.path),
            "receipt_raw_sha256": migrated.receipt.raw_sha256,
            "status": "MIGRATION_RECEIPT_VERIFIED",
        }
    if args.command == "verify-migration":
        receipt = verify_completed_migration(
            source=WarehousePaths.open(args.source_root),
            destination=WarehousePaths.open(args.destination_root),
            receipt_path=args.receipt,
            expected_receipt_raw_sha256=args.expected_receipt_sha256,
            manifest_public_key_path=args.manifest_public_key,
            registry=load_registry(args.registry),
            migration_public_key_path=args.migration_public_key,
            expected_migration_public_key_sha256=(
                args.expected_migration_public_key_sha256
            ),
        )
        return {
            "migration_id": receipt.migration_id,
            "lineage_root_sha256": receipt.lineage.root_sha256,
            "status": "MIGRATION_REPLAY_VERIFIED",
        }
    raise RegistryError("unknown backup/migration command")


def main() -> int:
    try:
        print(json.dumps(run(parser().parse_args()), sort_keys=True))
    except RegistryError as exc:
        print(f"ERROR: {exc}")
        return 1
    return 0
