"""Exact raw JSON to deterministic versioned Parquet normalization."""

from __future__ import annotations

import os
import re
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import duckdb

from .canonical import canonical_json, parse_json_strict, sha256
from .derived_paths import DerivedPaths, private_file_mode
from .derived_publication import cleanup_failed_temporary
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict
from .models import SourceEndpoint
from .normalization_contracts import (
    DUCKDB_VERSION,
    INTEGER_FIELDS,
    NORMALIZED_COLUMNS,
    NORMALIZED_SCHEMA_VERSION,
    NORMALIZER_VERSION,
    PARQUET_COMPRESSION,
    PARQUET_COMPRESSION_LEVEL,
    PARQUET_DICTIONARY_PAGE_SIZE,
    PARQUET_ROW_GROUP_SIZE,
    PARQUET_VERSION,
    PRICE_FIELDS,
    SORT_KEYS,
    TIMEZONE,
    parquet_contract,
    schema_sha256,
    sort_sha256,
)
from .normalization_models import NormalizationBinding, NormalizedArtifact
from .publication import publish_temp_create_only
from .validation import validate_source_bytes

GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _decimal(value: object, label: str) -> Decimal | None:
    if value in ("", None):
        return None
    if not isinstance(value, (str, int)):
        raise RegistryError(f"{label} must be a decimal string or integer")
    text = str(value)
    if text != text.strip() or not text:
        raise RegistryError(f"{label} is not canonical")
    try:
        parsed = Decimal(text)
    except InvalidOperation as exc:
        raise RegistryError(f"{label} is not decimal") from exc
    if not parsed.is_finite():
        raise RegistryError(f"{label} must be finite")
    sign, digits, exponent = parsed.as_tuple()
    del sign
    integer_digits = max(len(digits) + exponent, 0)
    fractional_digits = max(-exponent, 0)
    if integer_digits + fractional_digits > 38 or fractional_digits > 10:
        raise RegistryError(f"{label} exceeds DECIMAL(38,10)")
    return parsed


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise RegistryError(f"{label} must be an integer")
    text = str(value)
    if text != text.strip() or not text or not text.isascii() or not text.isdigit():
        raise RegistryError(f"{label} is not a canonical non-negative integer")
    parsed = int(text)
    if parsed > 9_223_372_036_854_775_807:
        raise RegistryError(f"{label} exceeds BIGINT")
    return parsed


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise RegistryError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized or normalized != value:
        raise RegistryError(f"{label} is not canonical")
    return normalized


def _normalization_id(
    revision: dict[str, Any],
    source: SourceEndpoint,
    binding: NormalizationBinding,
) -> str:
    payload = {
        "dependency_lock_sha256": binding.dependency_lock_sha256,
        "endpoint_schema_version": source.endpoint_schema_version,
        "normalizer_version": NORMALIZER_VERSION,
        "parquet": parquet_contract(),
        "raw_sha256": revision["raw_sha256"],
        "registry_raw_sha256": binding.registry_raw_sha256,
        "revision_id": revision["revision_id"],
        "source_id": revision["source_id"],
        "tool_commit_sha": binding.tool_commit_sha,
    }
    return "normalization-" + sha256(canonical_json(payload))


def _rows(
    raw: bytes,
    revision: dict[str, Any],
    source: SourceEndpoint,
    binding: NormalizationBinding,
    normalization_id: str,
) -> list[tuple[object, ...]]:
    validate_source_bytes(raw, source, revision["trade_day"])
    payload = parse_json_strict(
        raw,
        "normalizer raw source",
        decimal_numbers_as_strings=True,
    )
    values = payload[source.required_top_level_fields[0]]
    rows: list[tuple[object, ...]] = []
    for index, item in enumerate(values, start=1):
        prices = [
            _decimal(item[source_name], f"row {index} {source_name}")
            for source_name, _target_name in PRICE_FIELDS
        ]
        integers = [
            _integer(item[source_name], f"row {index} {source_name}")
            for source_name, _target_name in INTEGER_FIELDS
        ]
        rows.append(
            (
                normalization_id,
                NORMALIZER_VERSION,
                NORMALIZED_SCHEMA_VERSION,
                binding.tool_commit_sha,
                binding.dependency_lock_sha256,
                DUCKDB_VERSION,
                TIMEZONE,
                binding.registry_raw_sha256,
                revision["source_id"],
                revision["exchange"],
                revision["trade_day"],
                revision["revision_id"],
                revision["object_id"],
                revision["raw_sha256"],
                index,
                _identifier(item["PRODUCTID"], f"row {index} PRODUCTID"),
                _identifier(item["DELIVERYMONTH"], f"row {index} DELIVERYMONTH"),
                *prices,
                *integers,
            )
        )
    return rows


def _sql_path(path: Path) -> str:
    value = str(path)
    if "\x00" in value:
        raise RegistryError("Parquet path contains NUL")
    return "'" + value.replace("'", "''") + "'"


def _write_parquet(path: Path, rows: list[tuple[object, ...]]) -> None:
    if duckdb.__version__ != DUCKDB_VERSION:
        raise RegistryError(
            f"DuckDB version drift: expected {DUCKDB_VERSION}, got "
            f"{duckdb.__version__}"
        )
    connection = duckdb.connect(":memory:")
    try:
        connection.execute("SET threads = 1")
        definitions = ", ".join(
            f'"{name}" {sql_type}' for name, sql_type in NORMALIZED_COLUMNS
        )
        connection.execute(f"CREATE TABLE normalized_rows ({definitions})")
        placeholders = ", ".join("?" for _ in NORMALIZED_COLUMNS)
        connection.executemany(
            f"INSERT INTO normalized_rows VALUES ({placeholders})",
            rows,
        )
        order = ", ".join(f'"{key}" ASC NULLS FIRST' for key in SORT_KEYS)
        connection.execute(
            "COPY (SELECT * FROM normalized_rows ORDER BY "
            + order
            + ") TO "
            + _sql_path(path)
            + " (FORMAT parquet, COMPRESSION "
            + PARQUET_COMPRESSION
            + f", COMPRESSION_LEVEL {PARQUET_COMPRESSION_LEVEL}"
            + f", ROW_GROUP_SIZE {PARQUET_ROW_GROUP_SIZE}"
            + f", PARQUET_VERSION '{PARQUET_VERSION}'"
            + ", STRING_DICTIONARY_PAGE_SIZE_LIMIT "
            + str(PARQUET_DICTIONARY_PAGE_SIZE)
            + ")"
        )
    except duckdb.Error as exc:
        raise RegistryError(f"deterministic Parquet write failed: {exc}") from exc
    finally:
        connection.close()
    private_file_mode(path)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_dir(path.parent)


def normalize_revision(
    *,
    evidence_root: Path,
    derived: DerivedPaths,
    revision: dict[str, Any],
    source: SourceEndpoint,
    binding: NormalizationBinding,
) -> NormalizedArtifact:
    if GIT_SHA_PATTERN.fullmatch(binding.tool_commit_sha) is None:
        raise RegistryError("normalizer tool commit must be a lowercase Git SHA")
    for label, value in (
        ("dependency lock", binding.dependency_lock_sha256),
        ("registry", binding.registry_raw_sha256),
        ("raw", revision["raw_sha256"]),
    ):
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise RegistryError(f"normalizer {label} SHA256 is invalid")
    raw_path = evidence_root / revision["raw_relative_path"]
    raw = read_regular_strict(raw_path, "normalizer raw evidence")
    if len(raw) != revision["raw_bytes"] or sha256(raw) != revision["raw_sha256"]:
        raise RegistryError("normalizer raw evidence binding mismatch")
    normalization_id = _normalization_id(revision, source, binding)
    rows = _rows(raw, revision, source, binding, normalization_id)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".normalize-",
        suffix=".parquet.partial",
        dir=derived.temporary,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    try:
        _write_parquet(temporary, rows)
        parquet_raw = read_regular_strict(
            temporary,
            "normalized Parquet temporary file",
        )
        parquet_hash = sha256(parquet_raw)
        parent = derived.private_subdir(
            derived.parquet,
            NORMALIZED_SCHEMA_VERSION,
            revision["exchange"].lower(),
            revision["trade_day"],
            revision["source_id"],
            revision["revision_id"],
        )
        destination = parent / f"part-{normalization_id}.parquet"
        destination, _idempotent = publish_temp_create_only(
            temporary,
            destination,
            expected_sha256=parquet_hash,
        )
    except BaseException as exc:
        cleanup_failed_temporary(temporary)
        if isinstance(exc, OSError):
            raise RegistryError(
                f"Parquet publication filesystem failure: {exc}"
            ) from exc
        raise
    relative = destination.relative_to(derived.root).as_posix()
    return NormalizedArtifact(
        normalization_id=normalization_id,
        revision_id=revision["revision_id"],
        source_id=revision["source_id"],
        exchange=revision["exchange"],
        trade_day=revision["trade_day"],
        raw_sha256=revision["raw_sha256"],
        row_count=len(rows),
        parquet_sha256=parquet_hash,
        parquet_bytes=len(parquet_raw),
        parquet_path=destination,
        parquet_relative_path=relative,
        schema_sha256=schema_sha256(),
        sort_sha256=sort_sha256(),
    )
