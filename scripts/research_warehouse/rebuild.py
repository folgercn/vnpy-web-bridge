"""Empty-root rebuild of deterministic Parquet and metadata-only catalog."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import sha256
from .catalog_builder import build_catalog
from .catalog_lock import single_writer_lock
from .catalog_validation import validate_catalog
from .commit_anchors import CommitAnchorLedger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .filesystem import WarehousePaths
from .manifests import verify_manifest_chain
from .models import SourceRegistry
from .normalization_models import NormalizationBinding
from .normalization_replay import (
    normalize_chain,
    replay_expected_artifacts,
)


def _verified_chain(
    *,
    evidence: WarehousePaths,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    expected_head_commit_seal_sha256: str,
    ledger: CommitAnchorLedger,
) -> list[dict[str, Any]]:
    chain = verify_manifest_chain(
        paths=evidence,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        offline=True,
    )
    if not chain:
        raise RegistryError("cannot rebuild from an empty signed chain")
    ledger.require_chain(chain)
    return chain


def _require_registry_binding(
    registry: SourceRegistry,
    binding: NormalizationBinding,
) -> None:
    if binding.registry_raw_sha256 != registry.raw_sha256:
        raise RegistryError("normalization registry provenance mismatch")


def rebuild_empty_catalog(
    *,
    evidence: WarehousePaths,
    derived_root: Path,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    expected_head_commit_seal_sha256: str,
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
) -> dict[str, Any]:
    _require_registry_binding(registry, binding)
    derived = DerivedPaths.initialize(derived_root)
    with single_writer_lock(derived):
        chain = _verified_chain(
            evidence=evidence,
            public_key_path=public_key_path,
            registry=registry,
            expected_genesis_seal_sha256=expected_genesis_seal_sha256,
            expected_head_seal_sha256=expected_head_seal_sha256,
            expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
            ledger=ledger,
        )
        artifacts = normalize_chain(
            evidence=evidence,
            derived=derived,
            chain=chain,
            registry=registry,
            binding=binding,
        )
        catalog_path, catalog_hash = build_catalog(
            paths=derived,
            chain=chain,
            ledger=ledger,
            artifacts=artifacts,
            binding=binding,
        )
        validated = validate_catalog(
            paths=derived,
            chain=chain,
            ledger=ledger,
            binding=binding,
            expected_artifacts=artifacts,
        )
    return {
        **validated,
        "catalog_sha256": catalog_hash,
        "catalog": str(catalog_path),
        "partition_hashes": {
            artifact.parquet_relative_path: artifact.parquet_sha256
            for artifact in sorted(
                artifacts,
                key=lambda item: item.parquet_relative_path,
            )
        },
        "status": "EMPTY_ROOT_REBUILD_VALID",
    }


def verify_rebuilt_catalog(
    *,
    evidence: WarehousePaths,
    derived: DerivedPaths,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str,
    expected_head_seal_sha256: str,
    expected_head_commit_seal_sha256: str,
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
) -> dict[str, Any]:
    _require_registry_binding(registry, binding)
    chain = _verified_chain(
        evidence=evidence,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        ledger=ledger,
    )
    expected_artifacts = replay_expected_artifacts(
        evidence=evidence,
        chain=chain,
        registry=registry,
        binding=binding,
    )
    validated = validate_catalog(
        paths=derived,
        chain=chain,
        ledger=ledger,
        binding=binding,
        expected_artifacts=expected_artifacts,
    )
    catalog_raw = read_regular_strict(
        Path(validated["catalog"]),
        "verified DuckDB catalog",
        limit=512 * 1024 * 1024,
    )
    return {
        **validated,
        "catalog_sha256": sha256(catalog_raw),
        "status": "REBUILT_CATALOG_VALID",
    }
