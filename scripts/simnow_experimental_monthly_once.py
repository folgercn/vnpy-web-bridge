#!/usr/bin/env python3
"""Create one unsigned monthly planner bundle, then bind the latest PIT route.

This is deliberately a thin SIMNOW_EXPERIMENTAL adapter.  It invokes the two
existing pure producers only when the create-only monthly bundle for
``source_month`` does not already exist.  The stored monthly bytes are never
rewritten; the current DAILY PIT route is the only source of a later target
update.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import commodity_relative_vol_snapshot_producer as thermostat_producer
import commodity_static_core_equal_pure_producer as static_producer
from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    _static_core_equal_outputs,
)
from research_warehouse.verified_monthly_final_target import _final_projection
from simnow_experimental_materialize_target import (
    PLANNER_BUNDLE_SCHEMA_VERSION,
    ExperimentalTargetError,
    canonical_json_line,
    materialize_target,
    read_json_stable,
    validate_planner_bundle,
    validate_target,
    write_target_atomic,
)

_MONTH = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")
_MAX_PRODUCER_SOURCE_BYTES = 4 * 1024 * 1024


class ExperimentalMonthlyError(ValueError):
    """The unsigned monthly bridge cannot safely proceed."""


def _bundle_path(bundle_directory: Path, source_month: str) -> Path:
    if _MONTH.fullmatch(source_month) is None:
        raise ExperimentalMonthlyError("source_month is invalid")
    return bundle_directory / f"{source_month}.json"


def _json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExperimentalMonthlyError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ExperimentalMonthlyError(f"{label} is not an object")
    return value


def validate_monthly_bundle(value: Any, *, expected_source_month: str) -> dict[str, Any]:
    """Validate the PR1 bundle plus the exact static/thermostat splice.

    ``_final_projection`` is the existing pure structural comparison used by
    the audited reader.  Calling it here imports no catalog, root, signature,
    custody, or historical replay gate; it only rejects mismatched producer
    rows before this experimental adapter consumes them.
    """

    try:
        bundle = validate_planner_bundle(value)
        if bundle["source_month"] != expected_source_month:
            raise ExperimentalMonthlyError("monthly planner bundle source_month differs")
        _static_core_equal_outputs(
            producer_projection=bundle["static_core_equal_projection"],
            freeze_contract=bundle["static_core_equal_freeze_contract"],
            target_evidence=bundle["static_core_equal_target_evidence"],
        )
        projection = _final_projection(
            target_evidence=dict(bundle["static_core_equal_target_evidence"]),
            snapshot=dict(bundle["position_manager_snapshot"]),
        )
    except ExperimentalMonthlyError:
        raise
    except (
        ExecutableTargetAdapterError,
        KeyError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        raise ExperimentalMonthlyError("monthly producer outputs are cross-spliced") from exc
    if projection.get("source_month") != expected_source_month:
        raise ExperimentalMonthlyError("monthly producer source_month differs")
    return bundle


def _read_existing_bundle(path: Path, *, source_month: str) -> tuple[dict[str, Any], bytes] | None:
    if not path.exists():
        return None
    try:
        bundle, raw = read_json_stable(path, label="monthly planner bundle")
        if raw != canonical_json_line(bundle):
            raise ExperimentalMonthlyError("monthly planner bundle must be canonical JSON")
        return validate_monthly_bundle(bundle, expected_source_month=source_month), raw
    except ExperimentalMonthlyError:
        raise
    except ExperimentalTargetError as exc:
        raise ExperimentalMonthlyError(str(exc)) from exc


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_only_bundle(path: Path, value: Mapping[str, Any], *, source_month: str) -> tuple[dict[str, Any], bytes, bool]:
    bundle = validate_monthly_bundle(dict(value), expected_source_month=source_month)
    raw = canonical_json_line(bundle)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        _fsync_directory(path.parent)
        return bundle, raw, True
    except FileExistsError:
        existing = _read_existing_bundle(path, source_month=source_month)
        if existing is None or existing[1] != raw:
            raise ExperimentalMonthlyError("monthly planner bundle already exists with different bytes")
        return existing[0], existing[1], False
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@contextmanager
def _bundle_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path.parent / f".{path.name}.lock", os.O_RDWR | os.O_CREAT, 0o600
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _produce_bundle(*, static_source_raw: bytes, thermostat_source_raw: bytes, source_month: str) -> dict[str, Any]:
    try:
        static_result = static_producer.produce_research_artifacts(static_source_raw)
        thermostat_result = thermostat_producer.produce_snapshot(thermostat_source_raw)
        bundle = {
            "schema_version": PLANNER_BUNDLE_SCHEMA_VERSION,
            "strategy_id": "STATIC_CORE_EQUAL",
            "source_mode": "STATIC_CORE_EQUAL_MONTHLY",
            "source_month": source_month,
            "static_core_equal_projection": dict(static_result.producer_projection),
            "static_core_equal_freeze_contract": _json_object(
                static_result.artifacts["freeze_contract"],
                label="STATIC_CORE_EQUAL freeze contract",
            ),
            "static_core_equal_target_evidence": _json_object(
                static_result.artifacts["target_evidence"],
                label="STATIC_CORE_EQUAL target evidence",
            ),
            "position_manager_snapshot": _json_object(
                thermostat_result.snapshot_draft,
                label="monthly thermostat snapshot",
            ),
        }
        return validate_monthly_bundle(bundle, expected_source_month=source_month)
    except ExperimentalMonthlyError:
        raise
    except (KeyError, RuntimeError, TypeError, ValueError) as exc:
        raise ExperimentalMonthlyError("monthly producer replay failed closed") from exc


def _read_producer_source(path: Path, *, label: str) -> bytes:
    try:
        _value, raw = read_json_stable(path, label=label, limit=_MAX_PRODUCER_SOURCE_BYTES)
    except ExperimentalTargetError as exc:
        raise ExperimentalMonthlyError(str(exc)) from exc
    return raw


def _generated_at(value: str | None) -> str:
    return value or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_current_target(path: Path) -> tuple[dict[str, Any], bytes] | None:
    if not path.exists():
        return None
    try:
        current, raw = read_json_stable(path, label="experimental target")
        return validate_target(current, raw=raw), raw
    except ExperimentalTargetError as exc:
        raise ExperimentalMonthlyError(str(exc)) from exc


def _require_target_month_advances(current: Mapping[str, Any] | None, source_month: str) -> None:
    if (
        current is not None
        and current["source_month"] != source_month
        and current["source_month"] >= source_month
    ):
        raise ExperimentalMonthlyError(
            "experimental target source_month must strictly advance"
        )


def _target_rows_by_product(target: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Return the already-validated target rows keyed by product."""

    return {str(row["product"]): row for row in target["targets"]}


@contextmanager
def _target_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path.parent / f".{path.name}.lock", os.O_RDWR | os.O_CREAT, 0o600
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def materialize_monthly_once(
    *,
    source_month: str,
    static_source_path: Path,
    thermostat_source_path: Path,
    monthly_bundle_directory: Path,
    daily_pit_route_path: Path,
    target_path: Path,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Reuse/create one monthly bundle and atomically update its route target."""

    bundle_path = _bundle_path(monthly_bundle_directory, source_month)
    current = _read_current_target(target_path)
    _require_target_month_advances(
        None if current is None else current[0], source_month
    )

    with _bundle_lock(bundle_path):
        existing = _read_existing_bundle(bundle_path, source_month=source_month)
        created_bundle = False
        if existing is None:
            bundle = _produce_bundle(
                static_source_raw=_read_producer_source(
                    static_source_path, label="STATIC_CORE_EQUAL source"
                ),
                thermostat_source_raw=_read_producer_source(
                    thermostat_source_path, label="thermostat source"
                ),
                source_month=source_month,
            )
            bundle, bundle_raw, created_bundle = _create_only_bundle(
                bundle_path, bundle, source_month=source_month
            )
        else:
            bundle, bundle_raw = existing

    with _target_lock(target_path):
        current = _read_current_target(target_path)
        current_value = None if current is None else current[0]
        _require_target_month_advances(current_value, source_month)
        try:
            daily_route, daily_route_raw = read_json_stable(
                daily_pit_route_path, label="daily PIT route"
            )
        except ExperimentalTargetError as exc:
            raise ExperimentalMonthlyError(str(exc)) from exc
        if (
            current_value is not None
            and current_value["source_month"] == source_month
            and current_value["monthly_quantity_sha256"]
            != hashlib.sha256(bundle_raw).hexdigest()
        ):
            raise ExperimentalMonthlyError(
                "existing experimental target monthly bundle differs"
            )
        if current_value is not None and current_value["source_month"] == source_month:
            try:
                expected = materialize_target(
                    planner_bundle=bundle,
                    planner_bundle_raw=bundle_raw,
                    daily_route=daily_route,
                    daily_route_raw=daily_route_raw,
                    generated_at=current_value["generated_at"],
                )
            except ExperimentalTargetError as exc:
                raise ExperimentalMonthlyError(str(exc)) from exc

            current_rows = _target_rows_by_product(current_value)
            expected_rows = _target_rows_by_product(expected)
            if any(
                current_rows[product]["quantity"] != expected_rows[product]["quantity"]
                for product in expected_rows
            ):
                raise ExperimentalMonthlyError(
                    "existing experimental target quantity vector differs"
                )
            if all(
                current_rows[product]["exact_contract"]
                == expected_rows[product]["exact_contract"]
                for product in expected_rows
            ):
                return {
                    "status": "NO_NEW_TARGET",
                    "target_id": current_value["target_id"],
                    "monthly_bundle_created": created_bundle,
                }

        try:
            target = materialize_target(
                planner_bundle=bundle,
                planner_bundle_raw=bundle_raw,
                daily_route=daily_route,
                daily_route_raw=daily_route_raw,
                generated_at=_generated_at(generated_at),
            )
        except ExperimentalTargetError as exc:
            raise ExperimentalMonthlyError(str(exc)) from exc
        write_target_atomic(target_path, target)
        return {
            "status": "MATERIALIZED",
            "target_id": target["target_id"],
            "monthly_bundle_created": created_bundle,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-month", required=True)
    parser.add_argument("--static-source", required=True, type=Path)
    parser.add_argument("--thermostat-source", required=True, type=Path)
    parser.add_argument("--monthly-bundle-directory", required=True, type=Path)
    parser.add_argument("--daily-pit-route", required=True, type=Path)
    parser.add_argument("--target-output", required=True, type=Path)
    parser.add_argument("--generated-at", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = materialize_monthly_once(
            source_month=args.source_month,
            static_source_path=args.static_source,
            thermostat_source_path=args.thermostat_source,
            monthly_bundle_directory=args.monthly_bundle_directory,
            daily_pit_route_path=args.daily_pit_route,
            target_path=args.target_output,
            generated_at=args.generated_at,
        )
    except ExperimentalMonthlyError as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
