"""Empty-root restore drill with manifest, catalog, and Parquet replay checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .backup_anchor import VerifiedBackupAnchor, _verify_backup_anchor_held
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
from .rebuild import rebuild_empty_catalog
from .rebuild_fingerprint import require_rebuild_result


@dataclass(frozen=True)
class VerifiedRestore:
    evidence: WarehousePaths
    derived: DerivedPaths
    backup_anchor: VerifiedBackupAnchor
    rebuild_result: dict[str, Any]


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
    with hold_custody_root(backup.root) as backup_held:
        anchor = _verify_backup_anchor_held(
            paths=backup,
            held=backup_held,
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
            or binding.dependency_lock_sha256
            != expected.dependency_lock_sha256
        ):
            raise RegistryError(
                "restore external rebuild pins do not match backup anchor"
            )
        evidence = WarehousePaths.initialize(restore_root)
        with hold_custody_root(evidence.root) as restore_held:
            materialize_held_snapshot(
                source=backup_held,
                destination=restore_held,
                source_prefix="objects",
                destination_prefix="",
                snapshot=anchor.snapshot,
                minimum_free_bytes_after=minimum_free_bytes_after,
            )
            if (
                scan_held_snapshot(
                    restore_held,
                    raw_prefix="raw",
                    manifests_prefix="manifests",
                )
                != anchor.snapshot
            ):
                raise RegistryError(
                    "restored warehouse differs from backup snapshot"
                )
            result = rebuild_empty_catalog(
                evidence=evidence,
                derived_root=restore_derived_root,
                public_key_path=manifest_public_key_path,
                registry=registry,
                expected_genesis_seal_sha256=(
                    expected.genesis_batch_seal_sha256
                ),
                expected_head_seal_sha256=(
                    expected.head_batch_seal_sha256
                ),
                expected_head_commit_seal_sha256=(
                    expected.head_commit_seal_sha256
                ),
                ledger=ledger,
                binding=binding,
            )
            chain = verify_manifest_chain(
                paths=evidence,
                public_key_path=manifest_public_key_path,
                registry=registry,
                expected_genesis_seal_sha256=(
                    expected.genesis_batch_seal_sha256
                ),
                expected_head_seal_sha256=(
                    expected.head_batch_seal_sha256
                ),
                expected_head_commit_seal_sha256=(
                    expected.head_commit_seal_sha256
                ),
                offline=True,
            )
            require_complete_chain_snapshot(anchor.snapshot, chain)
            restore_held.revalidate()
        derived = DerivedPaths.open(restore_derived_root)
        require_rebuild_result(expected=expected, derived=derived)
        backup_held.revalidate()
        return VerifiedRestore(
            evidence=evidence,
            derived=derived,
            backup_anchor=anchor,
            rebuild_result=result,
        )
