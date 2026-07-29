"""High-level append-only backup orchestration over layered primitives."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .backup_anchor import VerifiedBackupAnchor, _create_backup_anchor
from .backup_chain_binding import require_complete_chain_snapshot
from .backup_custody import BackupPaths, custody_identity, materialize_snapshot
from .backup_inventory import scan_warehouse_snapshot
from .commit_anchors import CommitAnchorLedger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .filesystem import WarehousePaths
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
    snapshot = scan_warehouse_snapshot(source)
    chain = verify_manifest_chain(
        paths=source,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
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
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        ledger=ledger,
        binding=binding,
    )
    if first_rebuild != second_rebuild:
        raise RegistryError("warehouse rebuild evidence changed during backup")
    materialize_snapshot(
        source_root=source.root,
        destination_root=backup.objects,
        temporary_dir=backup.temporary,
        snapshot=snapshot,
        minimum_free_bytes_after=minimum_free_bytes_after,
        destination_parent=backup.private_object_parent,
    )
    return _create_backup_anchor(
        paths=backup,
        snapshot=snapshot,
        rebuild=first_rebuild,
        source_custody_identity=custody_identity(
            source.root,
            domain="vnpy-research-source-custody-v1",
        ),
        backup_custody_identity=custody_identity(
            backup.root,
            domain="vnpy-research-backup-custody-v1",
        ),
        expected_parent_anchor_raw_sha256=expected_parent_anchor_raw_sha256,
        signer_key_id=backup_signer_key_id,
        private_key_path=backup_private_key_path,
        public_key_path=backup_public_key_path,
        expected_public_key_sha256=expected_backup_public_key_sha256,
        now=now,
    )
