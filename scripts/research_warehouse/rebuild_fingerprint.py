"""Capture and compare deterministic catalog/Parquet rebuild evidence."""

from __future__ import annotations

import os
import tempfile
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import duckdb

from .backup_contracts import RebuildFingerprint
from .canonical import canonical_json, sha256
from .catalog_schema import CATALOG_FILENAME
from .commit_anchors import CommitAnchorLedger
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .file_integrity import write_all
from .filesystem import WarehousePaths
from .held_custody import HeldCustodyRoot, hash_held_tree, hold_custody_root
from .models import SourceRegistry
from .normalization_models import NormalizationBinding
from .rebuild import verify_rebuilt_catalog


def _partition_hashes(held: HeldCustodyRoot) -> tuple[tuple[str, str], ...]:
    return hash_held_tree(
        held,
        prefix="parquet",
        suffix=".parquet",
        limit=512 * 1024 * 1024,
    )


def _canonical_cell(value):
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    raise RegistryError("DuckDB catalog contains a non-canonical value type")


def _catalog_logical_sha256(held: HeldCustodyRoot) -> str:
    raw = held.read_file(
        f"catalog/{CATALOG_FILENAME}",
        label="logical-fingerprint DuckDB catalog",
        limit=512 * 1024 * 1024,
    )
    descriptor, name = tempfile.mkstemp(suffix=".duckdb")
    os.fchmod(descriptor, 0o600)
    try:
        write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    orders = {
        "catalog_meta": "key",
        "batches": "batch_sequence",
        "revisions": "revision_id",
        "normalized_partitions": "revision_id",
    }
    try:
        connection = duckdb.connect(name, read_only=True)
        try:
            tables = {}
            for table, order in orders.items():
                columns = [
                    item[1]
                    for item in connection.execute(
                        f"PRAGMA table_info('{table}')"
                    ).fetchall()
                ]
                rows = connection.execute(
                    f'SELECT * FROM "{table}" ORDER BY "{order}"'
                ).fetchall()
                tables[table] = {
                    "columns": columns,
                    "rows": [
                        [_canonical_cell(value) for value in row]
                        for row in rows
                    ],
                }
        except duckdb.Error as exc:
            raise RegistryError(
                "cannot fingerprint DuckDB catalog logically"
            ) from exc
        finally:
            connection.close()
    finally:
        Path(name).unlink(missing_ok=True)
    held.revalidate()
    return sha256(
        canonical_json(
            {"domain": "vnpy-research-catalog-logical-v1", "tables": tables}
        )
    )


def capture_rebuild_fingerprint(
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
) -> RebuildFingerprint:
    verify_rebuilt_catalog(
        evidence=evidence,
        derived=derived,
        public_key_path=public_key_path,
        registry=registry,
        expected_genesis_seal_sha256=expected_genesis_seal_sha256,
        expected_head_seal_sha256=expected_head_seal_sha256,
        expected_head_commit_seal_sha256=expected_head_commit_seal_sha256,
        ledger=ledger,
        binding=binding,
    )
    with hold_custody_root(derived.root) as held:
        return RebuildFingerprint(
            registry_raw_sha256=registry.raw_sha256,
            commit_anchor_ledger_sha256=ledger.raw_sha256,
            genesis_batch_seal_sha256=expected_genesis_seal_sha256,
            head_batch_seal_sha256=expected_head_seal_sha256,
            head_commit_seal_sha256=expected_head_commit_seal_sha256,
            tool_commit_sha=binding.tool_commit_sha,
            dependency_lock_sha256=binding.dependency_lock_sha256,
            catalog_logical_sha256=_catalog_logical_sha256(held),
            partition_hashes=_partition_hashes(held),
        )


def require_rebuild_result(
    *,
    expected: RebuildFingerprint,
    derived: DerivedPaths,
) -> None:
    with hold_custody_root(derived.root) as held:
        if _catalog_logical_sha256(held) != expected.catalog_logical_sha256:
            raise RegistryError("restored DuckDB catalog logical content changed")
        if _partition_hashes(held) != expected.partition_hashes:
            raise RegistryError("restored actual Parquet lineage hashes changed")
