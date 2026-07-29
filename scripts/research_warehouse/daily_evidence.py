"""Extract PIT-bound product coverage from one verified daily manifest."""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from .canonical import parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .filesystem import WarehousePaths
from .models import SourceRegistry
from .quality_contracts import PRODUCT_EXCHANGES, TARGET_PRODUCTS
from .timeutil import parse_utc
from .validation import validate_source_bytes


def _safe_raw_path(paths: WarehousePaths, relative: object):
    if not isinstance(relative, str):
        raise RegistryError("daily evidence raw path must be a string")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise RegistryError("daily evidence raw path is unsafe")
    return paths.root.joinpath(*pure.parts)


def _product_id(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("_f"):
        raise RegistryError("official daily row PRODUCTID is not canonical")
    product = value[:-2].lower()
    if not product.isascii() or not product.isalpha():
        raise RegistryError("official daily row PRODUCTID is invalid")
    return product


def _latest_revision(
    revisions: list[dict[str, Any]],
    *,
    source_id: str,
    cutoff_at: datetime,
) -> dict[str, Any]:
    candidates = []
    for revision in revisions:
        if revision["source_id"] != source_id:
            continue
        first_seen = parse_utc(revision["first_seen_at"], "first_seen_at")
        if first_seen > cutoff_at:
            raise RegistryError("anchored daily revision first_seen_at is in the future")
        candidates.append(revision)
    if not candidates:
        raise RegistryError(f"daily manifest has no revision for {source_id}")
    return max(
        candidates,
        key=lambda item: (item["revision_sequence"], item["revision_id"]),
    )


def product_coverage_for_manifest(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    manifest: dict[str, Any],
    cutoff_at: datetime,
) -> dict[str, dict[str, object]]:
    trade_day = manifest["trade_day"]
    coverage: dict[str, dict[str, object]] = {}
    for source in registry.sources:
        revision = _latest_revision(
            manifest["revisions"],
            source_id=source.source_id,
            cutoff_at=cutoff_at,
        )
        raw_path = _safe_raw_path(paths, revision["raw_relative_path"])
        raw = read_regular_strict(raw_path, "quality-gate raw evidence")
        if len(raw) != revision["raw_bytes"] or sha256(raw) != revision["raw_sha256"]:
            raise RegistryError("quality-gate raw evidence binding mismatch")
        validate_source_bytes(raw, source, trade_day)
        payload = parse_json_strict(raw, "quality-gate official daily raw")
        product_counts: dict[str, int] = {}
        for row in payload[source.required_top_level_fields[0]]:
            product = _product_id(row["PRODUCTID"])
            if product in TARGET_PRODUCTS:
                product_counts[product] = product_counts.get(product, 0) + 1
        for product, count in product_counts.items():
            if PRODUCT_EXCHANGES[product] != source.exchange:
                raise RegistryError("target product appeared under wrong exchange")
            coverage[product] = {
                "exchange": source.exchange,
                "revision_id": revision["revision_id"],
                "raw_sha256": revision["raw_sha256"],
                "row_count": count,
            }
    missing = set(TARGET_PRODUCTS) - set(coverage)
    if missing:
        raise RegistryError(
            "official daily evidence is missing target products: "
            + ", ".join(sorted(missing))
        )
    return coverage
