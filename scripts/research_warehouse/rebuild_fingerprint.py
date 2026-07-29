"""Capture and compare deterministic catalog/Parquet rebuild evidence."""

from __future__ import annotations

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
from .file_integrity import read_regular_strict
from .filesystem import WarehousePaths
from .models import SourceRegistry
from .normalization_models import NormalizationBinding
from .rebuild import verify_rebuilt_catalog


def _partition_hashes(derived: DerivedPaths) -> tuple[tuple[str, str], ...]:
    values = []
    for path in sorted(derived.parquet.rglob("*.parquet"), key=str):
        raw = read_regular_strict(
            path,
            "rebuild fingerprint Parquet",
            limit=512 * 1024 * 1024,
        )
        values.append((path.relative_to(derived.root).as_posix(), sha256(raw)))
    if not values:
        raise RegistryError("rebuild fingerprint found no Parquet partitions")
    return tuple(values)


def _canonical_cell(value):
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    raise RegistryError("DuckDB catalog contains a non-canonical value type")


def _catalog_logical_sha256(derived: DerivedPaths) -> str:
    path = derived.catalog / CATALOG_FILENAME
    before = read_regular_strict(
        path,
        "logical-fingerprint DuckDB catalog",
        limit=512 * 1024 * 1024,
    )
    orders = {
        "catalog_meta": "key",
        "batches": "batch_sequence",
        "revisions": "revision_id",
        "normalized_partitions": "revision_id",
    }
    connection = duckdb.connect(str(path), read_only=True)
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
                    [_canonical_cell(value) for value in row] for row in rows
                ],
            }
    except duckdb.Error as exc:
        raise RegistryError("cannot fingerprint DuckDB catalog logically") from exc
    finally:
        connection.close()
    after = read_regular_strict(
        path,
        "post-fingerprint DuckDB catalog",
        limit=512 * 1024 * 1024,
    )
    if after != before:
        raise RegistryError("DuckDB catalog changed during logical fingerprint")
    return sha256(
        canonical_json(
            {
                "domain": "vnpy-research-catalog-logical-v1",
                "tables": tables,
            }
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
    return RebuildFingerprint(
        registry_raw_sha256=registry.raw_sha256,
        commit_anchor_ledger_sha256=ledger.raw_sha256,
        genesis_batch_seal_sha256=expected_genesis_seal_sha256,
        head_batch_seal_sha256=expected_head_seal_sha256,
        head_commit_seal_sha256=expected_head_commit_seal_sha256,
        tool_commit_sha=binding.tool_commit_sha,
        dependency_lock_sha256=binding.dependency_lock_sha256,
        catalog_logical_sha256=_catalog_logical_sha256(derived),
        partition_hashes=_partition_hashes(derived),
    )


def require_rebuild_result(
    *,
    expected: RebuildFingerprint,
    result: dict,
) -> None:
    restored_root = result.get("catalog")
    if not isinstance(restored_root, str):
        raise RegistryError("restored DuckDB catalog path is unavailable")
    catalog_path = Path(restored_root)
    actual_logical = _catalog_logical_sha256(
        DerivedPaths.open(catalog_path.parent.parent)
    )
    if actual_logical != expected.catalog_logical_sha256:
        raise RegistryError("restored DuckDB catalog logical content changed")
    partition_hashes = result.get("partition_hashes")
    if (
        not isinstance(partition_hashes, dict)
        or tuple(sorted(partition_hashes.items())) != expected.partition_hashes
    ):
        raise RegistryError("restored Parquet lineage hashes changed")
