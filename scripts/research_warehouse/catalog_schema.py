"""Frozen DuckDB catalog schema for rebuildable Research metadata."""

from __future__ import annotations

CATALOG_SCHEMA_VERSION = "vnpy_research_catalog_v1"
CATALOG_FILENAME = "research-catalog-v1.duckdb"

TABLE_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "catalog_meta": (
        ("key", "VARCHAR"),
        ("value", "VARCHAR"),
    ),
    "batches": (
        ("batch_sequence", "INTEGER"),
        ("batch_id", "VARCHAR"),
        ("batch_seal_sha256", "VARCHAR"),
        ("commit_seal_sha256", "VARCHAR"),
        ("parent_batch_seal_sha256", "VARCHAR"),
        ("parent_commit_seal_sha256", "VARCHAR"),
        ("trade_day", "DATE"),
        ("sealed_at", "VARCHAR"),
        ("available_at", "VARCHAR"),
        ("registry_raw_sha256", "VARCHAR"),
    ),
    "revisions": (
        ("revision_id", "VARCHAR"),
        ("revision_sequence", "INTEGER"),
        ("source_id", "VARCHAR"),
        ("exchange", "VARCHAR"),
        ("trade_day", "DATE"),
        ("object_id", "VARCHAR"),
        ("raw_sha256", "VARCHAR"),
        ("raw_bytes", "BIGINT"),
        ("raw_relative_path", "VARCHAR"),
        ("first_seen_at", "VARCHAR"),
        ("last_seen_at", "VARCHAR"),
        ("supersedes_revision_id", "VARCHAR"),
        ("supersedes_object_id", "VARCHAR"),
        ("first_batch_sequence", "INTEGER"),
    ),
    "normalized_partitions": (
        ("normalization_id", "VARCHAR"),
        ("revision_id", "VARCHAR"),
        ("source_id", "VARCHAR"),
        ("exchange", "VARCHAR"),
        ("trade_day", "DATE"),
        ("raw_sha256", "VARCHAR"),
        ("row_count", "BIGINT"),
        ("parquet_sha256", "VARCHAR"),
        ("parquet_bytes", "BIGINT"),
        ("parquet_relative_path", "VARCHAR"),
        ("schema_sha256", "VARCHAR"),
        ("sort_sha256", "VARCHAR"),
        ("tool_commit_sha", "VARCHAR"),
        ("dependency_lock_sha256", "VARCHAR"),
        ("duckdb_version", "VARCHAR"),
        ("timezone", "VARCHAR"),
    ),
}

DDL = """
CREATE TABLE catalog_meta (
    key VARCHAR PRIMARY KEY,
    value VARCHAR NOT NULL
);
CREATE TABLE batches (
    batch_sequence INTEGER PRIMARY KEY,
    batch_id VARCHAR UNIQUE NOT NULL,
    batch_seal_sha256 VARCHAR UNIQUE NOT NULL,
    commit_seal_sha256 VARCHAR UNIQUE NOT NULL,
    parent_batch_seal_sha256 VARCHAR,
    parent_commit_seal_sha256 VARCHAR,
    trade_day DATE NOT NULL,
    sealed_at VARCHAR NOT NULL,
    available_at VARCHAR NOT NULL,
    registry_raw_sha256 VARCHAR NOT NULL
);
CREATE TABLE revisions (
    revision_id VARCHAR PRIMARY KEY,
    revision_sequence INTEGER NOT NULL,
    source_id VARCHAR NOT NULL,
    exchange VARCHAR NOT NULL,
    trade_day DATE NOT NULL,
    object_id VARCHAR NOT NULL,
    raw_sha256 VARCHAR NOT NULL,
    raw_bytes BIGINT NOT NULL CHECK (raw_bytes > 0),
    raw_relative_path VARCHAR NOT NULL,
    first_seen_at VARCHAR NOT NULL,
    last_seen_at VARCHAR NOT NULL,
    supersedes_revision_id VARCHAR,
    supersedes_object_id VARCHAR,
    first_batch_sequence INTEGER NOT NULL REFERENCES batches(batch_sequence)
);
CREATE TABLE normalized_partitions (
    normalization_id VARCHAR PRIMARY KEY,
    revision_id VARCHAR UNIQUE NOT NULL REFERENCES revisions(revision_id),
    source_id VARCHAR NOT NULL,
    exchange VARCHAR NOT NULL,
    trade_day DATE NOT NULL,
    raw_sha256 VARCHAR NOT NULL,
    row_count BIGINT NOT NULL CHECK (row_count > 0),
    parquet_sha256 VARCHAR UNIQUE NOT NULL,
    parquet_bytes BIGINT NOT NULL CHECK (parquet_bytes > 0),
    parquet_relative_path VARCHAR UNIQUE NOT NULL,
    schema_sha256 VARCHAR NOT NULL,
    sort_sha256 VARCHAR NOT NULL,
    tool_commit_sha VARCHAR NOT NULL,
    dependency_lock_sha256 VARCHAR NOT NULL,
    duckdb_version VARCHAR NOT NULL,
    timezone VARCHAR NOT NULL
);
"""
