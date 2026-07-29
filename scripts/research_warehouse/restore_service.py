"""Empty-root restore drill with manifest, catalog, and Parquet replay checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .backup_anchor import VerifiedBackupAnchor, verify_backup_anchor
from .backup_custody import BackupPaths, materialize_snapshot
from .backup_inventory import scan_warehouse_snapshot
from .commit_anchors import CommitAnchorLedger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .filesystem import WarehousePaths
from .models import SourceRegistry
from .normalization_models import NormalizationBinding
from .rebuild import rebuild_empty_catalog
from .rebuild_fingerprint import require_rebuild_result


@dataclass(frozen=True)
class VerifiedRestore:
    evidence: WarehousePaths
    derived: DerivedPaths
    backup_anchor: VerifiedBackupAnchor
    rebuild_result: dict[str, Any]


def _restore_parent(paths: WarehousePaths, relative_path: str) -> Path:
    parts = Path(relative_path).parts
    if parts[0] == "raw":
        base = paths.raw
    elif parts[0] == "manifests":
        base = paths.manifests
    else:
        raise RegistryError("restore object path is outside warehouse custody")
    components = parts[1:-1]
    return paths.private_subdir(base, *components) if components else base


def restore_and_verify(
    *,
    backup: BackupPaths,
    expected_backup_anchor_raw_sha256: str,
    backup_public_key_path: Path,
    expected_backup_public_key_sha256: str,
    restore_root: Path,
    restore_derived_root: Path,
    manifest_public_key_path: Path,
    registry: SourceRegistry,
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
    minimum_free_bytes_after: int,
) -> VerifiedRestore:
    anchor = verify_backup_anchor(
        paths=backup,
        public_key_path=backup_public_key_path,
        expected_public_key_sha256=expected_backup_public_key_sha256,
        expected_head_anchor_raw_sha256=expected_backup_anchor_raw_sha256,
    )
    expected = anchor.rebuild
    if (
        registry.raw_sha256 != expected.registry_raw_sha256
        or ledger.raw_sha256 != expected.commit_anchor_ledger_sha256
        or binding.registry_raw_sha256 != expected.registry_raw_sha256
        or binding.tool_commit_sha != expected.tool_commit_sha
        or binding.dependency_lock_sha256 != expected.dependency_lock_sha256
    ):
        raise RegistryError("restore external rebuild pins do not match backup anchor")
    evidence = WarehousePaths.initialize(restore_root)
    materialize_snapshot(
        source_root=backup.objects,
        destination_root=evidence.root,
        temporary_dir=evidence.temporary,
        snapshot=anchor.snapshot,
        minimum_free_bytes_after=minimum_free_bytes_after,
        destination_parent=lambda relative: _restore_parent(evidence, relative),
    )
    if scan_warehouse_snapshot(evidence) != anchor.snapshot:
        raise RegistryError("restored warehouse differs from backup snapshot")
    result = rebuild_empty_catalog(
        evidence=evidence,
        derived_root=restore_derived_root,
        public_key_path=manifest_public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected.genesis_batch_seal_sha256,
        expected_head_seal_sha256=expected.head_batch_seal_sha256,
        expected_head_commit_seal_sha256=expected.head_commit_seal_sha256,
        ledger=ledger,
        binding=binding,
    )
    require_rebuild_result(expected=expected, result=result)
    return VerifiedRestore(
        evidence=evidence,
        derived=DerivedPaths.open(restore_derived_root),
        backup_anchor=anchor,
        rebuild_result=result,
    )
