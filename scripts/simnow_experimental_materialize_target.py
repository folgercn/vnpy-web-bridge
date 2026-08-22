"""Materialize the small, unsigned SIMNOW_EXPERIMENTAL target contract.

This adapter deliberately consumes content only.  It does not load a catalog,
manifest, signer, custody receipt, or historical predecessor.  Monthly lots
remain exactly as produced; the current DAILY PIT input contributes only the
exact contract route.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "simnow-experimental-target-v1"
STRATEGY_ID = "STATIC_CORE_EQUAL"
PLANNER_BUNDLE_SCHEMA_VERSION = "simnow-experimental-monthly-planner-bundle-v1"
STATIC_CORE_EQUAL_MONTHLY = "STATIC_CORE_EQUAL_MONTHLY"
PRODUCT_EXCHANGES = {
    "ag": "SHFE", "al": "SHFE", "au": "SHFE", "bu": "SHFE",
    "cu": "SHFE", "rb": "SHFE", "ru": "SHFE", "sc": "INE",
    "sp": "SHFE", "zn": "SHFE",
}
PRODUCTS = tuple(PRODUCT_EXCHANGES)
MAX_INPUT_BYTES = 1024 * 1024
_SHA = re.compile(r"^[0-9a-f]{64}$")
_MONTH = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")
_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_CONTRACT = re.compile(r"^(SHFE|INE)\.([a-z]{2})([0-9]{4})$")


class ExperimentalTargetError(ValueError):
    """Content is not a safe experimental target input."""


def canonical_json_line(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json_stable(path: Path, *, label: str, limit: int = MAX_INPUT_BYTES) -> tuple[dict[str, Any], bytes]:
    """Read one regular JSON file twice-bound to its stat identity."""

    try:
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > limit:
            raise ExperimentalTargetError(f"{label} must be one bounded regular file")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
                raise ExperimentalTargetError(f"{label} changed before read")
            raw = handle.read(limit + 1)
        after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ExperimentalTargetError(f"{label} cannot be read") from exc
    if len(raw) != before.st_size or len(raw) > limit or (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
        raise ExperimentalTargetError(f"{label} changed during read")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExperimentalTargetError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ExperimentalTargetError(f"{label} must be an object")
    return value, raw


def _rows_by_product(rows: Any, *, quantity_fields: tuple[str, ...] = ()) -> dict[str, Mapping[str, Any]]:
    if not isinstance(rows, list) or len(rows) != len(PRODUCTS):
        raise ExperimentalTargetError("target rows must contain exactly the fixed ten products")
    result: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("product"), str):
            raise ExperimentalTargetError("target row is invalid")
        product = row["product"].lower()
        if product not in PRODUCT_EXCHANGES or product in result:
            raise ExperimentalTargetError("target products are invalid or duplicated")
        if quantity_fields and sum(field in row for field in quantity_fields) != 1:
            raise ExperimentalTargetError("monthly row must contain exactly one quantity field")
        result[product] = row
    if tuple(result) != PRODUCTS:
        raise ExperimentalTargetError("target products must use frozen order")
    return result


def validate_planner_bundle(value: Any) -> dict[str, Any]:
    """Validate content needed by the existing mature full-portfolio planner.

    This intentionally validates only the supplied monthly result bundle.  It
    neither obtains nor requires a catalog, signature, custody receipt, or
    physical provenance identity.
    """

    fields = {
        "schema_version", "strategy_id", "source_mode", "source_month",
        "static_core_equal_projection", "static_core_equal_freeze_contract",
        "static_core_equal_target_evidence", "position_manager_snapshot",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ExperimentalTargetError("monthly planner bundle fields are invalid")
    if (
        value["schema_version"] != PLANNER_BUNDLE_SCHEMA_VERSION
        or value["strategy_id"] != STRATEGY_ID
        or value["source_mode"] != STATIC_CORE_EQUAL_MONTHLY
    ):
        raise ExperimentalTargetError("monthly planner bundle identity is invalid")
    source_month = value.get("source_month")
    if not isinstance(source_month, str) or _MONTH.fullmatch(source_month) is None:
        raise ExperimentalTargetError("monthly planner bundle source_month is invalid")
    projection = value["static_core_equal_projection"]
    freeze = value["static_core_equal_freeze_contract"]
    evidence = value["static_core_equal_target_evidence"]
    snapshot = value["position_manager_snapshot"]
    if not all(isinstance(item, Mapping) for item in (projection, freeze, evidence, snapshot)):
        raise ExperimentalTargetError("monthly planner bundle artifacts are invalid")
    if evidence.get("scheduler_id") != STRATEGY_ID or snapshot.get("source_month") != source_month:
        raise ExperimentalTargetError("monthly planner bundle strategy/month mismatch")
    evidence_rows = _rows_by_product(evidence.get("targets"))
    rows = _rows_by_product(snapshot.get("targets"))
    quantities: dict[str, int] = {}
    for product, row in rows.items():
        quantity = row.get("shadow_target_quantity")
        if isinstance(quantity, bool) or not isinstance(quantity, int) or abs(quantity) > 500:
            raise ExperimentalTargetError("monthly target quantity is invalid")
        if row.get("exact_contract") != evidence_rows[product].get("exact_contract"):
            raise ExperimentalTargetError("monthly planner bundle route is cross-spliced")
        quantities[product] = quantity
    return value


def _daily_routes(value: Mapping[str, Any]) -> dict[str, str]:
    rows = value.get("mains", value.get("targets"))
    by_product = _rows_by_product(rows)
    routes: dict[str, str] = {}
    for product, row in by_product.items():
        exact = row.get("exact_contract")
        exchange = row.get("exchange")
        match = _CONTRACT.fullmatch(exact) if isinstance(exact, str) else None
        if match is None or match.group(1) != PRODUCT_EXCHANGES[product] or exchange != PRODUCT_EXCHANGES[product] or match.group(2) != product:
            raise ExperimentalTargetError("daily PIT exact contract/exchange mapping is invalid")
        routes[product] = exact
    return routes


def _target_id(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("target_id", None)
    return _sha256(canonical_json_line(body))


def validate_target(value: Any, *, raw: bytes | None = None) -> dict[str, Any]:
    fields = {
        "schema_version", "strategy_id", "source_month", "generated_at", "targets", "target_id",
        "monthly_quantity_sha256", "daily_route_sha256", "production", "live_trading_authorized",
        "countable_forward", "official_forward_claimed",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ExperimentalTargetError("experimental target fields are invalid")
    if raw is not None and raw != canonical_json_line(value):
        raise ExperimentalTargetError("experimental target must be canonical JSON")
    if value["schema_version"] != SCHEMA_VERSION or value["strategy_id"] != STRATEGY_ID:
        raise ExperimentalTargetError("experimental target identity is invalid")
    if not isinstance(value["source_month"], str) or _MONTH.fullmatch(value["source_month"]) is None:
        raise ExperimentalTargetError("experimental target source_month is invalid")
    if not isinstance(value["generated_at"], str) or _UTC.fullmatch(value["generated_at"]) is None:
        raise ExperimentalTargetError("experimental target generated_at is invalid")
    if any(value[field] is not False for field in ("production", "live_trading_authorized", "countable_forward", "official_forward_claimed")):
        raise ExperimentalTargetError("experimental target authority must remain false")
    if any(not isinstance(value[field], str) or _SHA.fullmatch(value[field]) is None for field in ("target_id", "monthly_quantity_sha256", "daily_route_sha256")):
        raise ExperimentalTargetError("experimental target hash is invalid")
    rows = _rows_by_product(value["targets"], quantity_fields=("quantity",))
    for product, row in rows.items():
        if set(row) != {"product", "exact_contract", "quantity"}:
            raise ExperimentalTargetError("experimental target row fields are invalid")
        exact = row["exact_contract"]
        match = _CONTRACT.fullmatch(exact) if isinstance(exact, str) else None
        if match is None or match.group(1) != PRODUCT_EXCHANGES[product] or match.group(2) != product:
            raise ExperimentalTargetError("experimental target exact contract is invalid")
        if isinstance(row["quantity"], bool) or not isinstance(row["quantity"], int) or abs(row["quantity"]) > 500:
            raise ExperimentalTargetError("experimental target quantity is invalid")
    if value["target_id"] != _target_id(value):
        raise ExperimentalTargetError("experimental target_id is invalid")
    return value


def materialize_target(*, planner_bundle: Mapping[str, Any], planner_bundle_raw: bytes, daily_route: Mapping[str, Any], daily_route_raw: bytes, generated_at: str) -> dict[str, Any]:
    if not isinstance(generated_at, str) or _UTC.fullmatch(generated_at) is None:
        raise ExperimentalTargetError("generated_at must be UTC seconds")
    bundle = validate_planner_bundle(dict(planner_bundle))
    source_month = str(bundle["source_month"])
    snapshot_rows = _rows_by_product(bundle["position_manager_snapshot"]["targets"])
    quantities = {product: int(snapshot_rows[product]["shadow_target_quantity"]) for product in PRODUCTS}
    routes = _daily_routes(daily_route)
    target: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "strategy_id": STRATEGY_ID,
        "source_month": source_month, "generated_at": generated_at,
        "targets": [{"product": product, "exact_contract": routes[product], "quantity": quantities[product]} for product in PRODUCTS],
        "monthly_quantity_sha256": _sha256(planner_bundle_raw), "daily_route_sha256": _sha256(daily_route_raw),
        "production": False, "live_trading_authorized": False, "countable_forward": False, "official_forward_claimed": False,
    }
    target["target_id"] = _target_id(target)
    return validate_target(target)


def write_target_atomic(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_json_line(validate_target(dict(value)))
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="materialize one SIMNOW_EXPERIMENTAL target")
    parser.add_argument("--monthly-planner-bundle", required=True, type=Path)
    parser.add_argument("--daily-pit-route", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--generated-at", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        bundle, bundle_raw = read_json_stable(args.monthly_planner_bundle, label="monthly planner bundle")
        route, route_raw = read_json_stable(args.daily_pit_route, label="daily PIT route")
        generated_at = args.generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        target = materialize_target(planner_bundle=bundle, planner_bundle_raw=bundle_raw, daily_route=route, daily_route_raw=route_raw, generated_at=generated_at)
        write_target_atomic(args.output, target)
    except ExperimentalTargetError as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "MATERIALIZED", "target_id": target["target_id"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
