"""High-level append-only backup orchestration over layered primitives."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .backup_anchor import (
    VerifiedBackupAnchor,
    _create_backup_anchor,
    _create_backup_anchor_with_private_key,
)
from .backup_chain_binding import require_complete_chain_snapshot
from .backup_custody import BackupPaths
from .commit_anchors import CommitAnchorLedger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .filesystem import WarehousePaths
from .held_custody import (
    hold_custody_root,
    materialize_held_snapshot,
    scan_held_snapshot,
)
from .manifests import verify_manifest_chain
from .models import SourceRegistry
from .normalization_models import NormalizationBinding
from .rebuild_fingerprint import capture_rebuild_fingerprint


def create_append_only_backup(
    *,
    source: WarehousePaths,
    source_derived: DerivedPaths,
    backup: BackupPaths,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    expected_head_commit_seal_sha256: str,
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
    expected_parent_anchor_raw_sha256: str | None,
    backup_signer_key_id: str,
    backup_private_key_path: Path,
    backup_public_key_path: Path,
    expected_backup_public_key_sha256: str,
    minimum_free_bytes_after: int,
    now: datetime,
) -> VerifiedBackupAnchor:
    return _create_append_only_backup(
        source=source,
        source_derived=source_derived,
        backup=backup,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        ledger=ledger,
        binding=binding,
        expected_parent_anchor_raw_sha256=expected_parent_anchor_raw_sha256,
        backup_signer_key_id=backup_signer_key_id,
        backup_private_key_path=backup_private_key_path,
        backup_private_key=None,
        backup_public_key_path=backup_public_key_path,
        expected_backup_public_key_sha256=expected_backup_public_key_sha256,
        minimum_free_bytes_after=minimum_free_bytes_after,
        now=now,
    )


def create_append_only_backup_with_private_key(
    *,
    source: WarehousePaths,
    source_derived: DerivedPaths,
    backup: BackupPaths,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    expected_head_commit_seal_sha256: str,
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
    expected_parent_anchor_raw_sha256: str | None,
    backup_signer_key_id: str,
    backup_private_key: Ed25519PrivateKey,
    backup_public_key_path: Path,
    expected_backup_public_key_sha256: str,
    minimum_free_bytes_after: int,
    now: datetime,
) -> VerifiedBackupAnchor:
    """Create a backup using key material preloaded before privilege drop."""
    return _create_append_only_backup(
        source=source,
        source_derived=source_derived,
        backup=backup,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        ledger=ledger,
        binding=binding,
        expected_parent_anchor_raw_sha256=expected_parent_anchor_raw_sha256,
        backup_signer_key_id=backup_signer_key_id,
        backup_private_key_path=None,
        backup_private_key=backup_private_key,
        backup_public_key_path=backup_public_key_path,
        expected_backup_public_key_sha256=expected_backup_public_key_sha256,
        minimum_free_bytes_after=minimum_free_bytes_after,
        now=now,
    )


def _create_append_only_backup(
    *,
    source: WarehousePaths,
    source_derived: DerivedPaths,
    backup: BackupPaths,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    expected_head_commit_seal_sha256: str,
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
    expected_parent_anchor_raw_sha256: str | None,
    backup_signer_key_id: str,
    backup_private_key_path: Path | None,
    backup_private_key: Ed25519PrivateKey | None,
    backup_public_key_path: Path,
    expected_backup_public_key_sha256: str,
    minimum_free_bytes_after: int,
    now: datetime,
) -> VerifiedBackupAnchor:
    if (backup_private_key_path is None) == (backup_private_key is None):
        raise RegistryError("exactly one backup signer key source is required")
    with (
        hold_custody_root(source.root) as source_held,
        hold_custody_root(backup.root) as backup_held,
    ):
        first_rebuild = capture_rebuild_fingerprint(
            evidence=source,
            derived=source_derived,
            public_key_path=public_key_path,
            registry=registry,
            expected_genesis_seal_sha256=expected_genesis_seal_sha256,
            expected_head_seal_sha256=expected_head_seal_sha256,
            expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
            ledger=ledger,
            binding=binding,
        )
        snapshot = scan_held_snapshot(
            source_held,
            raw_prefix="raw",
            manifests_prefix="manifests",
        )
        chain = verify_manifest_chain(
            paths=source,
            public_key_path=public_key_path,
            registry=registry,
            expected_genesis_seal_sha256=expected_genesis_seal_sha256,
            expected_head_seal_sha256=expected_head_seal_sha256,
            expected_head_commit_seal_sha256=(
                expected_head_commit_seal_sha256
            ),
            offline=True,
        )
        require_complete_chain_snapshot(snapshot, chain)
        second_rebuild = capture_rebuild_fingerprint(
            evidence=source,
            derived=source_derived,
            public_key_path=public_key_path,
            registry=registry,
            expected_genesis_seal_sha256=expected_genesis_seal_sha256,
            expected_head_seal_sha256=expected_head_seal_sha256,
            expected_head_commit_seal_sha256=(
                expected_head_commit_seal_sha256
            ),
            ledger=ledger,
            binding=binding,
        )
        if first_rebuild != second_rebuild:
            raise RegistryError("warehouse rebuild evidence changed during backup")
        source_held.revalidate()
        materialize_held_snapshot(
            source=source_held,
            destination=backup_held,
            source_prefix="",
            destination_prefix="objects",
            snapshot=snapshot,
            minimum_free_bytes_after=minimum_free_bytes_after,
        )
        if scan_held_snapshot(
            backup_held,
            raw_prefix="objects/raw",
            manifests_prefix="objects/manifests",
            strip_prefix="objects",
        ) != snapshot:
            raise RegistryError("backup destination differs from source snapshot")
        arguments = {
            "paths": backup,
            "source_held": source_held,
            "backup_held": backup_held,
            "snapshot": snapshot,
            "rebuild": first_rebuild,
            "expected_parent_anchor_raw_sha256": (
                expected_parent_anchor_raw_sha256
            ),
            "signer_key_id": backup_signer_key_id,
            "public_key_path": backup_public_key_path,
            "expected_public_key_sha256": expected_backup_public_key_sha256,
            "now": now,
        }
        if backup_private_key is not None:
            return _create_backup_anchor_with_private_key(
                **arguments,
                private_key=backup_private_key,
            )
        assert backup_private_key_path is not None
        return _create_backup_anchor(
            **arguments,
            private_key_path=backup_private_key_path,
        )
