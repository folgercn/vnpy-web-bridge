"""Frozen deterministic normalization and Parquet writer contract."""

from __future__ import annotations

from typing import Final

from .canonical import canonical_json, sha256

NORMALIZER_VERSION: Final = "vnpy-research-normalizer-v1"
NORMALIZED_SCHEMA_VERSION: Final = "vnpy_research_daily_rows_v1"
DUCKDB_VERSION: Final = "1.5.5"
TIMEZONE: Final = "UTC"
PARQUET_VERSION: Final = "V2"
PARQUET_COMPRESSION: Final = "zstd"
PARQUET_COMPRESSION_LEVEL: Final = 3
PARQUET_ROW_GROUP_SIZE: Final = 122_880
PARQUET_DICTIONARY_PAGE_SIZE: Final = 1_000_000

NORMALIZED_COLUMNS: Final[tuple[tuple[str, str], ...]] = (
    ("normalization_id", "VARCHAR"),
    ("normalizer_version", "VARCHAR"),
    ("schema_version", "VARCHAR"),
    ("tool_commit_sha", "VARCHAR"),
    ("dependency_lock_sha256", "VARCHAR"),
    ("duckdb_version", "VARCHAR"),
    ("timezone", "VARCHAR"),
    ("registry_raw_sha256", "VARCHAR"),
    ("source_id", "VARCHAR"),
    ("exchange", "VARCHAR"),
    ("trade_day", "DATE"),
    ("revision_id", "VARCHAR"),
    ("object_id", "VARCHAR"),
    ("raw_sha256", "VARCHAR"),
    ("source_row_number", "UINTEGER"),
    ("product_id", "VARCHAR"),
    ("delivery_month", "VARCHAR"),
    ("open_price", "DECIMAL(38,10)"),
    ("highest_price", "DECIMAL(38,10)"),
    ("lowest_price", "DECIMAL(38,10)"),
    ("close_price", "DECIMAL(38,10)"),
    ("settlement_price", "DECIMAL(38,10)"),
    ("volume", "BIGINT"),
    ("open_interest", "BIGINT"),
)

SORT_KEYS: Final[tuple[str, ...]] = (
    "source_id",
    "trade_day",
    "revision_id",
    "product_id",
    "delivery_month",
    "source_row_number",
)

PRICE_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("OPENPRICE", "open_price"),
    ("HIGHESTPRICE", "highest_price"),
    ("LOWESTPRICE", "lowest_price"),
    ("CLOSEPRICE", "close_price"),
    ("SETTLEMENTPRICE", "settlement_price"),
)

INTEGER_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("VOLUME", "volume"),
    ("OPENINTEREST", "open_interest"),
)


def schema_sha256() -> str:
    return sha256(
        canonical_json(
            {
                "columns": [
                    {"name": name, "type": value}
                    for name, value in NORMALIZED_COLUMNS
                ],
                "schema_version": NORMALIZED_SCHEMA_VERSION,
            }
        )
    )


def sort_sha256() -> str:
    return sha256(canonical_json({"sort_keys": list(SORT_KEYS)}))


def parquet_contract() -> dict[str, object]:
    return {
        "compression": PARQUET_COMPRESSION,
        "compression_level": PARQUET_COMPRESSION_LEVEL,
        "dictionary_page_size": PARQUET_DICTIONARY_PAGE_SIZE,
        "duckdb_version": DUCKDB_VERSION,
        "parquet_version": PARQUET_VERSION,
        "row_group_size": PARQUET_ROW_GROUP_SIZE,
        "schema_sha256": schema_sha256(),
        "sort_sha256": sort_sha256(),
        "timezone": TIMEZONE,
    }


def contract_document() -> dict[str, object]:
    return {
        "schema_version": "vnpy_research_normalization_contract_v1",
        "normalizer_version": NORMALIZER_VERSION,
        "normalized_schema_version": NORMALIZED_SCHEMA_VERSION,
        "columns": [
            {"name": name, "type": sql_type}
            for name, sql_type in NORMALIZED_COLUMNS
        ],
        "sort_keys": list(SORT_KEYS),
        "parquet": parquet_contract(),
    }
