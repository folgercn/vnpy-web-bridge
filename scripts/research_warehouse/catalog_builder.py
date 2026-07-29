"""Build and publish a metadata-only DuckDB Research catalog."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import duckdb

from .canonical import sha256
from .catalog_schema import CATALOG_FILENAME, CATALOG_SCHEMA_VERSION, DDL
from .commit_anchors import CommitAnchorLedger
from .derived_paths import DerivedPaths, private_file_mode
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict
from .normalization_contracts import (
    DUCKDB_VERSION,
    NORMALIZED_SCHEMA_VERSION,
    NORMALIZER_VERSION,
    TIMEZONE,
)
from .normalization_models import NormalizationBinding, NormalizedArtifact
from .publication import publish_temp_create_only
from .timeutil import format_utc


def _deduplicate_revisions(
    chain: list[dict[str, Any]],
) -> list[tuple[int, dict[str, Any]]]:
    values: dict[str, tuple[int, dict[str, Any]]] = {}
    for batch_sequence, manifest in enumerate(chain, start=1):
        for revision in manifest["revisions"]:
            existing = values.get(revision["revision_id"])
            if existing is None:
                values[revision["revision_id"]] = (batch_sequence, revision)
            elif existing[1] != revision:
                raise RegistryError("signed revision changed across manifest chain")
    return sorted(
        values.values(),
        key=lambda item: (
            item[1]["source_id"],
            item[1]["trade_day"],
            item[1]["revision_sequence"],
            item[1]["revision_id"],
        ),
    )


def _catalog_meta(
    chain: list[dict[str, Any]],
    ledger: CommitAnchorLedger,
    artifacts: list[NormalizedArtifact],
    binding: NormalizationBinding,
) -> dict[str, str]:
    return {
        "catalog_schema_version": CATALOG_SCHEMA_VERSION,
        "commit_anchor_ledger_sha256": ledger.raw_sha256,
        "dependency_lock_sha256": binding.dependency_lock_sha256,
        "duckdb_version": DUCKDB_VERSION,
        "genesis_batch_seal_sha256": chain[0]["batch_seal_sha256"],
        "head_batch_seal_sha256": chain[-1]["batch_seal_sha256"],
        "head_commit_seal_sha256": chain[-1]["commit_seal_sha256"],
        "manifest_count": str(len(chain)),
        "normalization_count": str(len(artifacts)),
        "normalized_schema_version": NORMALIZED_SCHEMA_VERSION,
        "normalizer_version": NORMALIZER_VERSION,
        "registry_raw_sha256": binding.registry_raw_sha256,
        "revision_count": str(len(artifacts)),
        "timezone": TIMEZONE,
        "tool_commit_sha": binding.tool_commit_sha,
    }


def _write_catalog(
    path: Path,
    *,
    chain: list[dict[str, Any]],
    ledger: CommitAnchorLedger,
    artifacts: list[NormalizedArtifact],
    binding: NormalizationBinding,
) -> None:
    if duckdb.__version__ != DUCKDB_VERSION:
        raise RegistryError("DuckDB dependency version drift")
    revisions = _deduplicate_revisions(chain)
    if len(revisions) != len(artifacts):
        raise RegistryError("normalization artifact/revision count mismatch")
    by_revision = {item.revision_id: item for item in artifacts}
    connection = duckdb.connect(str(path))
    try:
        connection.execute("SET threads = 1")
        connection.execute(DDL)
        connection.executemany(
            "INSERT INTO catalog_meta VALUES (?, ?)",
            sorted(_catalog_meta(chain, ledger, artifacts, binding).items()),
        )
        anchors = {item.batch_seal_sha256: item for item in ledger.entries}
        connection.executemany(
            "INSERT INTO batches VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    sequence,
                    manifest["batch_id"],
                    manifest["batch_seal_sha256"],
                    manifest["commit_seal_sha256"],
                    manifest["parent_batch_seal_sha256"],
                    manifest["parent_commit_seal_sha256"],
                    manifest["trade_day"],
                    manifest["sealed_at"],
                    format_utc(
                        anchors[manifest["batch_seal_sha256"]].available_at
                    ),
                    manifest["registry_raw_sha256"],
                )
                for sequence, manifest in enumerate(chain, start=1)
            ],
        )
        connection.executemany(
            "INSERT INTO revisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
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
                    first_batch,
                )
                for first_batch, revision in revisions
            ],
        )
        connection.executemany(
            "INSERT INTO normalized_partitions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    artifact.normalization_id,
                    revision_id,
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
                for revision_id, artifact in sorted(by_revision.items())
            ],
        )
        connection.execute("CHECKPOINT")
    except (duckdb.Error, KeyError) as exc:
        raise RegistryError(f"catalog build failed: {exc}") from exc
    finally:
        connection.close()
    private_file_mode(path)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_dir(path.parent)


def build_catalog(
    *,
    paths: DerivedPaths,
    chain: list[dict[str, Any]],
    ledger: CommitAnchorLedger,
    artifacts: list[NormalizedArtifact],
    binding: NormalizationBinding,
) -> tuple[Path, str]:
    descriptor, name = tempfile.mkstemp(
        prefix=".catalog-",
        suffix=".duckdb.partial",
        dir=paths.temporary,
    )
    os.close(descriptor)
    temporary = Path(name)
    temporary.unlink()
    try:
        _write_catalog(
            temporary,
            chain=chain,
            ledger=ledger,
            artifacts=artifacts,
            binding=binding,
        )
        raw = read_regular_strict(
            temporary,
            "temporary DuckDB catalog",
            limit=512 * 1024 * 1024,
        )
        digest = sha256(raw)
        output, _idempotent = publish_temp_create_only(
            temporary,
            paths.catalog / CATALOG_FILENAME,
            expected_sha256=digest,
        )
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return output, digest
