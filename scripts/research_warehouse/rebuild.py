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
from .normalization_models import NormalizationBinding, NormalizedArtifact
from .normalizer import normalize_revision


def _unique_revisions(
    chain: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for manifest in chain:
        for revision in manifest["revisions"]:
            existing = values.setdefault(revision["revision_id"], revision)
            if existing != revision:
                raise RegistryError("signed revision changed across manifest chain")
    return sorted(
        values.values(),
        key=lambda item: (
            item["source_id"],
            item["trade_day"],
            item["revision_sequence"],
            item["revision_id"],
        ),
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


def _normalize_all(
    *,
    evidence: WarehousePaths,
    derived: DerivedPaths,
    chain: list[dict[str, Any]],
    registry: SourceRegistry,
    binding: NormalizationBinding,
) -> list[NormalizedArtifact]:
    artifacts = []
    for revision in _unique_revisions(chain):
        try:
            source = registry.source(revision["source_id"])
        except KeyError as exc:
            raise RegistryError("signed revision source is not trusted") from exc
        artifacts.append(
            normalize_revision(
                evidence_root=evidence.root,
                derived=derived,
                revision=revision,
                source=source,
                binding=binding,
            )
        )
    return artifacts


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
        artifacts = _normalize_all(
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
    chain = _verified_chain(
        evidence=evidence,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        ledger=ledger,
    )
    validated = validate_catalog(
        paths=derived,
        chain=chain,
        ledger=ledger,
        binding=binding,
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
