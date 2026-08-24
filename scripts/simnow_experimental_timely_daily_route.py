"""Materialize an experimental-only DAILY PIT route from timely raw receipts.

This is deliberately not a Warehouse v1/v2 artifact, catalog entry, or
official strategy output.  It reuses the frozen PIT exact-contract kernel
against one completed receipt that was available before its next-official-day
cutoff, and emits route *content* for the existing SIMNOW_EXPERIMENTAL target
adapter only.  It never writes the formal catalog or relaxes its cutoff gate.

On M2 it is invoked through the root-managed Research release entrypoint as
``vnpyresearch`` with ``--output -``; the existing caller identity owns the
0600 temporary route file used by the materializer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.daily_roll_predecessor_catalog import (
    _read_private_protected_evidence,
)
from research_warehouse.errors import RegistryError
from research_warehouse.file_integrity import read_regular_strict
from research_warehouse.daily_pit_main_roll_source import (
    _following_official_days,
)
from research_warehouse.m2_genesis_predecessor_cli import (
    _config_raw,
    _projection_from_config,
)
from research_warehouse.m2_monitor_facts import verify_daily_run_receipt
from research_warehouse.m2_receipts import load_run_receipt
from research_warehouse.m2_runtime_input import DEFAULT_RUNTIME_INPUT
from research_warehouse.m2_runtime_loader import RuntimeContext, load_runtime_context_readonly
from research_warehouse.shfe_contract_parameters import evidence_from_pinned_raw
from research_warehouse.static_core_baseline import _registry
from research_warehouse.timeutil import format_utc
from research_warehouse.verified_daily_pit_main_roll_source import _mains as verified_mains
from simnow_experimental_materialize_target import (
    NOT_OFFICIAL_STRATEGY_OUTPUT,
    PRODUCTS,
    ExperimentalTargetError,
)

SHANGHAI = ZoneInfo("Asia/Shanghai")
ROUTE_MODE = "SIMNOW_EXPERIMENTAL_TIMELY_COMPLETED_RECEIPT_ONLY"


class ExperimentalTimelyRouteError(ValueError):
    """Timely receipt content cannot produce an experimental route."""


def _execution_days(context: RuntimeContext, official_day: str) -> tuple[str, str]:
    try:
        day = datetime.fromisoformat(official_day).date()
    except ValueError as exc:
        raise ExperimentalTimelyRouteError("official day is invalid") from exc
    try:
        execution_day, following_day = _following_official_days(context.calendar, day)
    except RegistryError as exc:
        raise ExperimentalTimelyRouteError(str(exc)) from exc
    return execution_day.isoformat(), following_day.isoformat()


def _timely_cutoff(execution_day: str) -> datetime:
    return datetime.combine(
        datetime.fromisoformat(execution_day).date(),
        time(0, 0),
        tzinfo=SHANGHAI,
    ).astimezone(timezone.utc)


def _service_context(runtime_input: Path) -> RuntimeContext:
    context = load_runtime_context_readonly(runtime_input)
    if os.geteuid() != context.policy.uid:
        raise ExperimentalTimelyRouteError(
            "experimental timely route requires the isolated service identity"
        )
    return context


def _write_route_atomic(path: Path, route: dict[str, Any]) -> None:
    raw = canonical_json_line(route)
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


def build_timely_experimental_route(
    *,
    context: RuntimeContext,
    official_day: str,
    contract_registry_path: Path,
    expected_contract_registry_raw_sha256: str,
    shfe_contract_parameters_path: Path,
    expected_shfe_contract_parameters_raw_sha256: str,
    shfe_contract_parameters_observed_at: str,
) -> dict[str, Any]:
    """Use the frozen exact-contract kernel with one verified timely receipt."""

    try:
        official_date = date.fromisoformat(official_day)
        execution_day, following_day = _execution_days(context, official_day)
        receipt_path = context.runtime.run_receipts / f"{official_day}.json"
        receipt_raw = read_regular_strict(
            receipt_path,
            "experimental timely DAILY PIT run receipt",
            limit=1024 * 1024,
        )
        receipt = load_run_receipt(receipt_path)
        if receipt_raw != canonical_json_line(receipt) or receipt["trade_day"] != official_day:
            raise ExperimentalTimelyRouteError("timely DAILY PIT receipt bytes drifted")
        completed_at = verify_daily_run_receipt(
            receipt,
            paths=context.paths,
            registry=context.registry,
            calendar=context.calendar,
            calendar_availability_raw_sha256=context.availability.raw_sha256,
            readonly_observation_loader=True,
        )
        context.availability.require_available(context.calendar, cutoff_at=completed_at)
        cutoff = _timely_cutoff(execution_day)
        if completed_at >= cutoff:
            raise ExperimentalTimelyRouteError(
                "timely DAILY PIT receipt was unavailable at experimental execution cutoff"
            )
        registry_raw = _read_private_protected_evidence(
            contract_registry_path,
            "experimental timely contract registry",
            uid=context.policy.uid,
            limit=1024 * 1024,
        )
        registry_raw_sha256 = hashlib.sha256(registry_raw).hexdigest()
        if registry_raw_sha256 != expected_contract_registry_raw_sha256:
            raise ExperimentalTimelyRouteError("experimental contract registry pin drifted")
        contract_registry, _ = _registry(registry_raw)
        shfe_contract_parameters_raw = _read_private_protected_evidence(
            shfe_contract_parameters_path,
            "experimental timely SHFE contract parameters",
            uid=context.policy.uid,
            limit=4 * 1024 * 1024,
        )
        shfe_contract_parameters = evidence_from_pinned_raw(
            observed_at=shfe_contract_parameters_observed_at,
            raw=shfe_contract_parameters_raw,
            expected_raw_sha256=expected_shfe_contract_parameters_raw_sha256,
        )
        raws: dict[str, bytes] = {}
        for source in receipt["sources"]:
            exchange = source["exchange"]
            if exchange in raws or exchange not in {"SHFE", "INE"}:
                raise ExperimentalTimelyRouteError("timely DAILY PIT source set is invalid")
            raw = read_regular_strict(
                context.paths.root / source["raw_relative_path"],
                "experimental timely DAILY PIT source raw",
                limit=16 * 1024 * 1024,
            )
            if len(raw) != source["raw_bytes"] or sha256(raw) != source["raw_sha256"]:
                raise ExperimentalTimelyRouteError("timely DAILY PIT source bytes drifted")
            raws[exchange] = raw
        if set(raws) != {"SHFE", "INE"}:
            raise ExperimentalTimelyRouteError("timely DAILY PIT source set is incomplete")
        mains, _expiry_lineage = verified_mains(
            context=context,
            official_day=official_date,
            execution_day=date.fromisoformat(execution_day),
            following_day=date.fromisoformat(following_day),
            daily_source_raw=raws,
            contract_registry=contract_registry,
            predecessor={product: "" for product in PRODUCTS},
            shfe_contract_parameters=shfe_contract_parameters,
        )
        return {
            "schema_version": "daily-pit-route-v1",
            "mains": [
                {
                    "product": row["product"],
                    "exchange": row["exchange"],
                    "exact_contract": row["exact_contract"],
                }
                for row in mains
            ],
            "metadata": {
                "route_mode": ROUTE_MODE,
                "strategy_output_claim": NOT_OFFICIAL_STRATEGY_OUTPUT,
                "official_day": official_day,
                "execution_day": execution_day,
                "execution_cutoff_utc": format_utc(cutoff, "experimental cutoff"),
                "run_receipt_id": receipt["receipt_id"],
                "run_receipt_raw_sha256": sha256(receipt_raw),
                "contract_registry_raw_sha256": registry_raw_sha256,
                "shfe_contract_parameters_raw_sha256": shfe_contract_parameters.raw_sha256,
                "shfe_contract_parameters_observed_at": format_utc(
                    shfe_contract_parameters.observed_at,
                    "experimental timely SHFE contract parameters observed_at",
                ),
                "production": False,
                "live_trading_authorized": False,
                "countable_forward": False,
                "official_forward_claimed": False,
            },
        }
    except (OSError, RegistryError, ExperimentalTargetError, ValueError) as exc:
        if isinstance(exc, ExperimentalTimelyRouteError):
            raise
        raise ExperimentalTimelyRouteError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    parser.add_argument("--continuous-config", type=Path, required=True)
    parser.add_argument("--official-day", required=True)
    parser.add_argument(
        "--output",
        required=True,
        help="route file path, or '-' for canonical route bytes on stdout",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        context = _service_context(args.runtime_input)
        projection = _projection_from_config(
            _config_raw(args.continuous_config, uid=context.policy.uid)
        )
        route = build_timely_experimental_route(
            context=context,
            official_day=args.official_day,
            contract_registry_path=projection.contract_registry_path,
            expected_contract_registry_raw_sha256=(
                projection.contract_registry_raw_sha256
            ),
            shfe_contract_parameters_path=projection.shfe_contract_parameters_path,
            expected_shfe_contract_parameters_raw_sha256=(
                projection.shfe_contract_parameters_raw_sha256
            ),
            shfe_contract_parameters_observed_at=(
                projection.shfe_contract_parameters_observed_at
            ),
        )
        if args.output == "-":
            sys.stdout.buffer.write(canonical_json_line(route))
            print(
                json.dumps(
                    {
                        "status": "EXPERIMENTAL_ROUTE_MATERIALIZED",
                        "route_mode": ROUTE_MODE,
                        "production": False,
                        "run_receipt_raw_sha256": route["metadata"][
                            "run_receipt_raw_sha256"
                        ],
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 0
        _write_route_atomic(Path(args.output), route)
    except (ExperimentalTimelyRouteError, RegistryError, OSError, ValueError) as exc:
        print(
            json.dumps({"status": "STOP", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"status": "EXPERIMENTAL_ROUTE_MATERIALIZED", "route_mode": ROUTE_MODE}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
