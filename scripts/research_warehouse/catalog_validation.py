"""Fail-closed validation for DuckDB catalog and Parquet derivatives."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

import duckdb

from .canonical import sha256
from .catalog_schema import CATALOG_FILENAME, CATALOG_SCHEMA_VERSION, TABLE_COLUMNS
from .commit_anchors import CommitAnchorLedger
from .custody_paths import require_private_dir
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict, write_all
from .normalization_contracts import (
    DUCKDB_VERSION,
    NORMALIZED_COLUMNS,
    NORMALIZED_SCHEMA_VERSION,
    NORMALIZER_VERSION,
    PARQUET_COMPRESSION,
    SORT_KEYS,
    TIMEZONE,
    schema_sha256,
    sort_sha256,
)
from .normalization_models import NormalizationBinding, NormalizedArtifact
from .revision_snapshots import latest_revision_snapshots
from .timeutil import format_utc


def _require_schema(connection: duckdb.DuckDBPyConnection) -> None:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
    }
    if tables != set(TABLE_COLUMNS):
        raise RegistryError("DuckDB catalog table set drifted")
    for table, expected in TABLE_COLUMNS.items():
        actual = tuple(
            (row[1], row[2])
            for row in connection.execute(f"PRAGMA table_info('{table}')").fetchall()
        )
        if actual != expected:
            raise RegistryError(f"DuckDB catalog schema drifted: {table}")


def _safe_partition(paths: DerivedPaths, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or not pure.parts
        or pure.parts[0] != "parquet"
    ):
        raise RegistryError("catalog Parquet path escapes derived root")
    candidate = paths.root.joinpath(*pure.parts)
    current = paths.root
    for component in pure.parts[:-1]:
        current /= component
        require_private_dir(current, "catalog Parquet parent")
    return candidate


def _sql_path(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _read_descriptor(descriptor: int, size: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = size + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _descriptor_identity(descriptor: int) -> tuple[int, int]:
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino


def _descriptor_matches(
    descriptor: int,
    expected: tuple[int, int],
) -> bool:
    try:
        return _descriptor_identity(descriptor) == expected
    except OSError:
        return False


def _open_descriptor_identities() -> dict[int, tuple[int, int]]:
    directory = (
        Path("/proc/self/fd")
        if Path("/proc/self/fd").is_dir()
        else Path("/dev/fd")
    )
    values = {}
    for name in os.listdir(directory):
        if not name.isdigit():
            continue
        descriptor = int(name)
        try:
            values[descriptor] = _descriptor_identity(descriptor)
        except OSError:
            pass
    return values


def _write_verified_temporary(
    paths: DerivedPaths,
    raw: bytes,
    *,
    suffix: str,
) -> tuple[int, Path]:
    descriptor, name = tempfile.mkstemp(
        prefix=".verify-",
        suffix=suffix,
        dir=paths.temporary,
    )
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        write_all(descriptor, raw)
        os.fsync(descriptor)
        if _read_descriptor(descriptor, len(raw)) != raw:
            raise RegistryError("private verifier copy changed")
        fsync_dir(paths.temporary)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    return descriptor, temporary


@contextmanager
def _private_verified_copy(
    paths: DerivedPaths,
    raw: bytes,
) -> Iterator[Path]:
    descriptor, temporary = _write_verified_temporary(
        paths,
        raw,
        suffix=".parquet",
    )
    try:
        temporary.unlink()
        fsync_dir(paths.temporary)
        yield Path("/dev/fd") / str(descriptor)
        if _read_descriptor(descriptor, len(raw)) != raw:
            raise RegistryError("private verified Parquet copy changed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
            fsync_dir(paths.temporary)
        except FileNotFoundError:
            pass


@contextmanager
def _private_catalog_connection(
    paths: DerivedPaths,
    raw: bytes,
) -> Iterator[duckdb.DuckDBPyConnection]:
    descriptor, temporary = _write_verified_temporary(
        paths,
        raw,
        suffix=".duckdb",
    )
    connection = None
    duckdb_descriptors: set[int] = set()
    try:
        verified_identity = _descriptor_identity(descriptor)
        before = _open_descriptor_identities()
        connection = duckdb.connect(
            str(temporary),
            read_only=True,
            config={"threads": "1"},
        )
        after = _open_descriptor_identities()
        duckdb_descriptors = {
            candidate
            for candidate, identity in after.items()
            if identity == verified_identity and before.get(candidate) != identity
        }
        if not duckdb_descriptors:
            raise RegistryError("DuckDB catalog connection inode mismatch")
        temporary.unlink()
        fsync_dir(paths.temporary)
        yield connection
        if not any(
            _descriptor_matches(candidate, verified_identity)
            for candidate in duckdb_descriptors
        ):
            raise RegistryError("DuckDB catalog connection inode changed")
        if _read_descriptor(descriptor, len(raw)) != raw:
            raise RegistryError("private verified catalog copy changed")
    finally:
        if connection is not None:
            connection.close()
        os.close(descriptor)
        try:
            temporary.unlink()
            fsync_dir(paths.temporary)
        except FileNotFoundError:
            pass


def _validate_partition(
    connection: duckdb.DuckDBPyConnection,
    paths: DerivedPaths,
    row: tuple[Any, ...],
    binding: NormalizationBinding,
    revision: dict[str, Any],
) -> None:
    (
        normalization_id,
        revision_id,
        source_id,
        exchange,
        trade_day,
        raw_sha256,
        row_count,
        parquet_sha256,
        parquet_bytes,
        relative,
        claimed_schema,
        claimed_sort,
        tool_commit,
        dependency_lock,
        duckdb_version,
        timezone,
    ) = row
    path = _safe_partition(paths, relative)
    raw = read_regular_strict(
        path,
        "catalog normalized Parquet",
        limit=512 * 1024 * 1024,
    )
    if len(raw) != parquet_bytes or sha256(raw) != parquet_sha256:
        raise RegistryError("catalog Parquet hash/size mismatch")
    if (
        claimed_schema != schema_sha256()
        or claimed_sort != sort_sha256()
        or tool_commit != binding.tool_commit_sha
        or dependency_lock != binding.dependency_lock_sha256
        or duckdb_version != DUCKDB_VERSION
        or timezone != TIMEZONE
    ):
        raise RegistryError("catalog normalization binding mismatch")
    with _private_verified_copy(paths, raw) as verified:
        literal = _sql_path(verified)
        try:
            actual_count = connection.execute(
                f"SELECT count(*) FROM read_parquet({literal})"
            ).fetchone()[0]
            described = tuple(
                (item[0], item[1])
                for item in connection.execute(
                    f"DESCRIBE SELECT * FROM read_parquet({literal})"
                ).fetchall()
            )
            metadata = connection.execute(
                f"SELECT num_rows, format_version, created_by "
                f"FROM parquet_file_metadata({literal})"
            ).fetchone()
            compressions = {
                value[0]
                for value in connection.execute(
                    f"SELECT DISTINCT compression FROM parquet_metadata({literal})"
                ).fetchall()
            }
            mismatch_count = connection.execute(
                f"SELECT count(*) FROM read_parquet({literal}) WHERE "
                "normalization_id IS DISTINCT FROM ? "
                "OR normalizer_version IS DISTINCT FROM ? "
                "OR registry_raw_sha256 IS DISTINCT FROM ? "
                "OR revision_id IS DISTINCT FROM ? "
                "OR object_id IS DISTINCT FROM ? "
                "OR source_id IS DISTINCT FROM ? "
                "OR exchange IS DISTINCT FROM ? "
                "OR trade_day IS DISTINCT FROM ? "
                "OR raw_sha256 IS DISTINCT FROM ? "
                "OR schema_version IS DISTINCT FROM ? "
                "OR tool_commit_sha IS DISTINCT FROM ? "
                "OR dependency_lock_sha256 IS DISTINCT FROM ? "
                "OR duckdb_version IS DISTINCT FROM ? "
                "OR timezone IS DISTINCT FROM ?",
                (
                    normalization_id,
                    NORMALIZER_VERSION,
                    binding.registry_raw_sha256,
                    revision_id,
                    revision["object_id"],
                    source_id,
                    exchange,
                    trade_day,
                    raw_sha256,
                    NORMALIZED_SCHEMA_VERSION,
                    binding.tool_commit_sha,
                    binding.dependency_lock_sha256,
                    DUCKDB_VERSION,
                    TIMEZONE,
                ),
            ).fetchone()[0]
            sort_rows = connection.execute(
                "SELECT "
                + ", ".join(f'"{key}"' for key in SORT_KEYS)
                + f" FROM read_parquet({literal})"
            ).fetchall()
        except duckdb.Error as exc:
            raise RegistryError(f"catalog Parquet validation failed: {exc}") from exc
    if (
        read_regular_strict(
            path,
            "catalog normalized Parquet post-validation",
            limit=512 * 1024 * 1024,
        )
        != raw
    ):
        raise RegistryError("catalog Parquet changed during validation")
    if actual_count != row_count or metadata[0] != row_count:
        raise RegistryError("catalog Parquet row count mismatch")
    if described != NORMALIZED_COLUMNS:
        raise RegistryError("catalog Parquet schema mismatch")
    if metadata[1] != 2 or DUCKDB_VERSION not in metadata[2]:
        raise RegistryError("catalog Parquet writer/version mismatch")
    if compressions != {PARQUET_COMPRESSION.upper()}:
        raise RegistryError("catalog Parquet compression mismatch")
    if mismatch_count:
        raise RegistryError("catalog Parquet lineage columns mismatch")
    if sort_rows != sorted(sort_rows):
        raise RegistryError("catalog Parquet row order mismatch")


def validate_catalog(
    *,
    paths: DerivedPaths,
    chain: list[dict[str, Any]],
    ledger: CommitAnchorLedger,
    binding: NormalizationBinding,
    expected_artifacts: list[NormalizedArtifact],
) -> dict[str, Any]:
    ledger.require_chain(chain)
    if any(
        manifest["registry_raw_sha256"] != binding.registry_raw_sha256
        for manifest in chain
    ):
        raise RegistryError("catalog registry provenance mismatch")
    catalog_path = paths.catalog / CATALOG_FILENAME
    catalog_raw = read_regular_strict(
        catalog_path,
        "DuckDB catalog",
        limit=512 * 1024 * 1024,
    )
    try:
        with _private_catalog_connection(
            paths,
            catalog_raw,
        ) as connection:
            _require_schema(connection)
            meta = dict(
                connection.execute("SELECT key, value FROM catalog_meta").fetchall()
            )
            snapshots = latest_revision_snapshots(chain)
            revisions = {item.revision["revision_id"]: item for item in snapshots}
            expected_by_revision = {
                item.revision_id: item for item in expected_artifacts
            }
            if len(expected_by_revision) != len(expected_artifacts) or set(
                expected_by_revision
            ) != set(revisions):
                raise RegistryError("catalog replay revision set mismatch")
            expected_meta = {
                "catalog_schema_version": CATALOG_SCHEMA_VERSION,
                "commit_anchor_ledger_sha256": ledger.raw_sha256,
                "dependency_lock_sha256": binding.dependency_lock_sha256,
                "duckdb_version": DUCKDB_VERSION,
                "genesis_batch_seal_sha256": chain[0]["batch_seal_sha256"],
                "head_batch_seal_sha256": chain[-1]["batch_seal_sha256"],
                "head_commit_seal_sha256": chain[-1]["commit_seal_sha256"],
                "manifest_count": str(len(chain)),
                "normalization_count": str(len(revisions)),
                "normalized_schema_version": NORMALIZED_SCHEMA_VERSION,
                "normalizer_version": NORMALIZER_VERSION,
                "registry_raw_sha256": binding.registry_raw_sha256,
                "revision_count": str(len(revisions)),
                "timezone": TIMEZONE,
                "tool_commit_sha": binding.tool_commit_sha,
            }
            if meta != expected_meta:
                raise RegistryError("DuckDB catalog metadata mismatch")
            batch_rows = connection.execute(
                "SELECT batch_sequence, batch_id, batch_seal_sha256, "
                "commit_seal_sha256, parent_batch_seal_sha256, "
                "parent_commit_seal_sha256, trade_day::VARCHAR, "
                "sealed_at, available_at, registry_raw_sha256 "
                "FROM batches ORDER BY batch_sequence"
            ).fetchall()
            expected_batches = [
                (
                    sequence,
                    manifest["batch_id"],
                    manifest["batch_seal_sha256"],
                    manifest["commit_seal_sha256"],
                    manifest["parent_batch_seal_sha256"],
                    manifest["parent_commit_seal_sha256"],
                    manifest["trade_day"],
                    manifest["sealed_at"],
                    format_utc(ledger.entries[sequence - 1].available_at),
                    manifest["registry_raw_sha256"],
                )
                for sequence, manifest in enumerate(chain, start=1)
            ]
            if batch_rows != expected_batches:
                raise RegistryError("DuckDB catalog batch lineage mismatch")
            revision_rows = connection.execute(
                "SELECT revision_id, revision_sequence, source_id, exchange, "
                "trade_day::VARCHAR, object_id, raw_sha256, raw_bytes, "
                "raw_relative_path, first_seen_at, last_seen_at, "
                "supersedes_revision_id, supersedes_object_id, first_batch_sequence "
                "FROM revisions ORDER BY revision_id"
            ).fetchall()
            expected_revision_rows = sorted(
                (
                    revision["revision_id"],
                    revision["revision_sequence"],
                    revision["source_id"],
                    revision["exchange"],
                    revision["trade_day"],
                    revision["object_id"],
                    revision["raw_sha256"],
                    revision["raw_bytes"],
                    revision["raw_relative_path"],
                    revision["first_seen_at"],
                    revision["last_seen_at"],
                    revision["supersedes_revision_id"],
                    revision["supersedes_object_id"],
                    sequence,
                )
                for snapshot in snapshots
                for sequence, revision in [
                    (snapshot.first_batch_sequence, snapshot.revision)
                ]
            )
            if revision_rows != expected_revision_rows:
                raise RegistryError("DuckDB catalog revision lineage mismatch")
            partition_rows = connection.execute(
                "SELECT normalization_id, revision_id, source_id, exchange, "
                "trade_day::VARCHAR, raw_sha256, row_count, parquet_sha256, "
                "parquet_bytes, parquet_relative_path, schema_sha256, sort_sha256, "
                "tool_commit_sha, dependency_lock_sha256, duckdb_version, timezone "
                "FROM normalized_partitions ORDER BY revision_id"
            ).fetchall()
            if len(partition_rows) != len(revisions):
                raise RegistryError("DuckDB catalog partition count mismatch")
            for row in partition_rows:
                try:
                    revision = revisions[row[1]].revision
                    artifact = expected_by_revision[row[1]]
                except KeyError as exc:
                    raise RegistryError(
                        "catalog partition references an unknown revision"
                    ) from exc
                expected_row = (
                    artifact.normalization_id,
                    artifact.revision_id,
                    artifact.source_id,
                    artifact.exchange,
                    artifact.trade_day,
                    artifact.raw_sha256,
                    artifact.row_count,
                    artifact.parquet_sha256,
                    artifact.parquet_bytes,
                    artifact.parquet_relative_path,
                    artifact.schema_sha256,
                    artifact.sort_sha256,
                    binding.tool_commit_sha,
                    binding.dependency_lock_sha256,
                    DUCKDB_VERSION,
                    TIMEZONE,
                )
                if row != expected_row:
                    raise RegistryError("catalog partition replay mismatch")
                if (
                    row[2] != revision["source_id"]
                    or row[3] != revision["exchange"]
                    or row[4] != revision["trade_day"]
                    or row[5] != revision["raw_sha256"]
                ):
                    raise RegistryError("catalog partition/revision lineage mismatch")
                _validate_partition(connection, paths, row, binding, revision)
    except (duckdb.Error, KeyError, TypeError) as exc:
        raise RegistryError(f"DuckDB catalog validation failed: {exc}") from exc
    if (
        read_regular_strict(
            catalog_path,
            "DuckDB catalog post-validation",
            limit=512 * 1024 * 1024,
        )
        != catalog_raw
    ):
        raise RegistryError("DuckDB catalog changed during validation")
    return {
        "catalog": str(catalog_path),
        "catalog_sha256": sha256(catalog_raw),
        "manifest_count": len(chain),
        "partition_count": len(revisions),
        "revision_count": len(revisions),
        "status": "CATALOG_VALID",
    }
