"""Produce the fixed SIMNOW_LAB target, then reuse its existing run-once."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
for path in (WORKSPACE_ROOT / "backend", WORKSPACE_ROOT / "scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

materializer = importlib.import_module("scripts.simnow_experimental_materialize_target")
monthly_once = importlib.import_module("scripts.simnow_experimental_monthly_once")
lab_cli = importlib.import_module("scripts.windows_simnow_lab.cli_v1")
preopen = importlib.import_module("research_warehouse.simnow_lab_monthly_preopen")
preopen_join = importlib.import_module("scripts.simnow_lab_monthly_preopen_join")

SERVICE_ROOT = Path("/Users/fujun/services/vnpy-web-bridge")
EVIDENCE = SERVICE_ROOT / "simnow_lab_evidence"
RESEARCH_INPUTS = Path("/Users/Shared/vnpy-simnow-lab-inputs")
STATIC_SOURCE = RESEARCH_INPUTS / "static-core-equal-monthly-source.json"
THERMOSTAT_SOURCE = RESEARCH_INPUTS / "monthly-relative-vol-thermostat-source.json"
DAILY_ROUTE = RESEARCH_INPUTS / "daily-pit-route.json"
MONTHLY_BUNDLES = EVIDENCE / "monthly-bundles"
TARGET = EVIDENCE / "experimental-target.json"
LAB_TARGET = SERVICE_ROOT / "runtime/simnow-lab/target.json"
RESEARCH_PYTHON = Path("/usr/local/libexec/vnpyresearch/release/runtime/bin/python3.12")
RESEARCH_VENDOR = Path("/usr/local/libexec/vnpyresearch/release/vendor")
_MONTH = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")
SHANGHAI = ZoneInfo("Asia/Shanghai")


class SimNowLabM5Error(ValueError):
    """M5 must stop before calling CURRENT/apply."""


def _preopen_inputs(static_source: Path, thermostat_source: Path) -> tuple[bytes, bytes] | None:
    """Return the verified new source pair, or preserve the legacy source path."""

    try:
        thermostat, thermostat_raw = materializer.read_json_stable(
            thermostat_source, label="monthly thermostat source", limit=4 * 1024 * 1024
        )
        static, static_raw = materializer.read_json_stable(
            static_source, label="monthly static source", limit=4 * 1024 * 1024
        )
    except materializer.ExperimentalTargetError as exc:
        raise SimNowLabM5Error("monthly source pair is invalid") from exc
    thermostat_preopen = thermostat.get("schema_version") == preopen.THERMOSTAT_SCHEMA
    static_preopen = static.get("schema_version") == preopen.STATIC_SCHEMA
    if thermostat_preopen != static_preopen:
        raise SimNowLabM5Error("monthly preopen pair is mixed")
    if not thermostat_preopen:
        return None
    try:
        preopen.validate_preopen_pair(static_raw, thermostat_raw)
    except (
        materializer.ExperimentalTargetError,
        preopen.PitSourceViewError,
        ValueError,
    ) as exc:
        raise SimNowLabM5Error("monthly preopen pair is invalid") from exc
    return static_raw, thermostat_raw


def _expected_legacy_source_month(execution_day: date) -> str:
    """Return the prior calendar month owned by an execution TradingDay."""

    if execution_day.month == 1:
        return f"{execution_day.year - 1:04d}-12"
    return f"{execution_day.year:04d}-{execution_day.month - 1:02d}"


def _market_snapshot(
    *, request_address: str, publish_address: str, timeout_ms: int,
    vt_symbols: list[str],
) -> object:
    try:
        return lab_cli.rpc_call(
            method=lab_cli.RPC_GET,
            args=("MARKET", vt_symbols),
            request_address=request_address,
            publish_address=publish_address,
            timeout_ms=timeout_ms,
        )
    except Exception as exc:
        raise SimNowLabM5Error("MARKET_RPC_UNAVAILABLE") from exc


def require_fresh_daily_route(path: Path, *, now: datetime | None = None) -> date:
    try:
        route, _raw = materializer.read_json_stable(path, label="daily PIT route")
        execution_day = date.fromisoformat(route["metadata"]["execution_day"])
    except (
        KeyError,
        TypeError,
        ValueError,
        materializer.ExperimentalTargetError,
    ) as exc:
        raise SimNowLabM5Error("daily PIT route freshness is invalid") from exc
    local = (now or datetime.now(SHANGHAI)).astimezone(SHANGHAI)
    fresh = (
        execution_day > local.date()
        if local.hour >= 18
        else execution_day == local.date()
    )
    if not fresh:
        raise SimNowLabM5Error("daily PIT route is stale for this Lab window")
    return execution_day


def source_month_from_input(path: Path) -> str:
    try:
        value, _raw = materializer.read_json_stable(path, label="monthly thermostat source")
    except materializer.ExperimentalTargetError as exc:
        raise SimNowLabM5Error(str(exc)) from exc
    baseline = value.get("baseline_batch")
    if not isinstance(baseline, dict):
        raise SimNowLabM5Error("monthly thermostat baseline_batch is invalid")
    month = baseline.get("source_month")
    if not isinstance(month, str) or _MONTH.fullmatch(month) is None:
        raise SimNowLabM5Error("monthly thermostat source_month is invalid")
    top_level = value.get("source_month")
    if top_level is not None and top_level != month:
        raise SimNowLabM5Error("monthly thermostat source_month differs")
    return month


def run_monthly_once(
    *, source_month: str, static_source: Path, thermostat_source: Path,
    daily_route: Path, monthly_bundles: Path, target: Path,
) -> dict[str, object]:
    env = os.environ.copy()
    env["PYTHONPATH"] = ".:backend:scripts:" + str(RESEARCH_VENDOR)
    command = [
        str(RESEARCH_PYTHON), "-B", "-m", "scripts.simnow_experimental_monthly_once",
        "--source-month", source_month, "--static-source", str(static_source),
        "--thermostat-source", str(thermostat_source), "--monthly-bundle-directory",
        str(monthly_bundles), "--daily-pit-route", str(daily_route), "--target-output", str(target),
    ]
    try:
        completed = subprocess.run(command, cwd=WORKSPACE_ROOT, env=env, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise SimNowLabM5Error("MONTHLY_PRODUCER_UNAVAILABLE") from exc
    if completed.returncode:
        raise SimNowLabM5Error("MONTHLY_PRODUCER_FAILED")
    try:
        value = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise SimNowLabM5Error("MONTHLY_PRODUCER_RESULT_INVALID") from exc
    if not isinstance(value, dict) or value.get("status") not in {"MATERIALIZED", "NO_NEW_TARGET"}:
        raise SimNowLabM5Error("MONTHLY_PRODUCER_RESULT_INVALID")
    return value


def require_candidate_bindings(
    *, source_month: str, monthly_bundles: Path, daily_route: Path, target: Path
) -> None:
    """Reject a candidate whose recorded input bytes are no longer current."""

    try:
        candidate, candidate_raw = materializer.read_json_stable(
            target, label="candidate experimental target"
        )
        candidate = materializer.validate_target(candidate, raw=candidate_raw)
        bundle, bundle_raw = materializer.read_json_stable(
            monthly_bundles / f"{source_month}.json", label="monthly planner bundle"
        )
        if bundle_raw != materializer.canonical_json_line(bundle):
            raise SimNowLabM5Error("monthly planner bundle is not canonical")
        bundle = materializer.validate_planner_bundle(bundle)
        route, route_raw = materializer.read_json_stable(
            daily_route, label="daily PIT route"
        )
        if route_raw != materializer.canonical_json_line(route):
            raise SimNowLabM5Error("daily PIT route is not canonical")
        materializer._daily_routes(route)
    except SimNowLabM5Error:
        raise
    except (KeyError, TypeError, ValueError, materializer.ExperimentalTargetError) as exc:
        raise SimNowLabM5Error("candidate target binding is invalid") from exc
    if (
        candidate["source_month"] != source_month
        or bundle["source_month"] != source_month
        or candidate["monthly_quantity_sha256"] != materializer._sha256(bundle_raw)
        or candidate["daily_route_sha256"] != materializer._sha256(route_raw)
    ):
        raise SimNowLabM5Error("candidate target does not bind current inputs")


def run_once(
    *,
    static_source: Path = STATIC_SOURCE,
    thermostat_source: Path = THERMOSTAT_SOURCE,
    daily_route: Path = DAILY_ROUTE,
    monthly_bundles: Path = MONTHLY_BUNDLES,
    target: Path = TARGET,
    lab_target: Path = LAB_TARGET,
    request_address: str = lab_cli.DEFAULT_REQUEST_ADDRESS,
    publish_address: str = lab_cli.DEFAULT_PUBLISH_ADDRESS,
    timeout_ms: int = 30_000,
    now: datetime | None = None,
) -> int:
    local_now = (now or datetime.now(SHANGHAI)).astimezone(SHANGHAI)
    route_execution_day = require_fresh_daily_route(daily_route, now=local_now)
    preopen_inputs = _preopen_inputs(static_source, thermostat_source)
    if preopen_inputs is None:
        source_month = source_month_from_input(thermostat_source)
        if source_month != _expected_legacy_source_month(route_execution_day):
            raise SimNowLabM5Error("LEGACY_SOURCE_MONTH_STALE")
        produced = run_monthly_once(
            source_month=source_month, static_source=static_source,
            thermostat_source=thermostat_source, daily_route=daily_route,
            monthly_bundles=monthly_bundles, target=target,
        )
    else:
        static_preopen = json.loads(preopen_inputs[0])
        source_month = static_preopen["source_month"]
        preopen_execution_day = date.fromisoformat(static_preopen["execution_day"])
        if route_execution_day < preopen_execution_day:
            raise SimNowLabM5Error("PREOPEN_ROUTE_MISMATCH")
        if route_execution_day > preopen_execution_day:
            # After the one execution-open join, the shared pair remains as the
            # source-month identity.  Reuse only its already-created bundle on
            # the route's civil execution day; the preceding night window must
            # stop rather than interpreting stale preopen content as a new join.
            if local_now.date() != route_execution_day:
                raise SimNowLabM5Error("PREOPEN_EXECUTION_WINDOW_MISMATCH")
            try:
                produced = monthly_once.materialize_monthly_once(
                    source_month=source_month,
                    monthly_bundle_directory=monthly_bundles,
                    daily_pit_route_path=daily_route,
                    target_path=target,
                )
            except monthly_once.ExperimentalMonthlyError as exc:
                raise SimNowLabM5Error("MONTHLY_BUNDLE_REUSE_FAILED") from exc
        else:
            market = _market_snapshot(
                request_address=request_address,
                publish_address=publish_address,
                timeout_ms=timeout_ms,
                vt_symbols=[
                    f"{row['pit_main']['exact_contract'].split('.', 1)[1]}."
                    f"{row['pit_main']['exact_contract'].split('.', 1)[0]}"
                    for row in static_preopen["products"]
                ],
            )
            try:
                produced = preopen_join.complete_and_materialize(
                    static_preopen_raw=preopen_inputs[0],
                    thermostat_preopen_raw=preopen_inputs[1],
                    daily_route_path=daily_route,
                    market_snapshot=market,
                    monthly_bundle_directory=monthly_bundles,
                    target_path=target,
                    now=now,
                )
            except preopen_join.MonthlyPreopenJoinError as exc:
                raise SimNowLabM5Error(str(exc)) from exc
    require_candidate_bindings(
        source_month=source_month,
        monthly_bundles=monthly_bundles,
        daily_route=daily_route,
        target=target,
    )
    print(json.dumps(produced, sort_keys=True))
    return lab_cli.main(
        [
            "run-once",
            "--input",
            str(target),
            "--output",
            str(lab_target),
            "--request-address",
            request_address,
            "--publish-address",
            publish_address,
            "--timeout-ms",
            str(timeout_ms),
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-source", type=Path, default=STATIC_SOURCE)
    parser.add_argument("--thermostat-source", type=Path, default=THERMOSTAT_SOURCE)
    parser.add_argument("--daily-route", type=Path, default=DAILY_ROUTE)
    parser.add_argument("--monthly-bundles", type=Path, default=MONTHLY_BUNDLES)
    parser.add_argument("--target", type=Path, default=TARGET)
    parser.add_argument("--lab-target", type=Path, default=LAB_TARGET)
    parser.add_argument("--request-address", default=lab_cli.DEFAULT_REQUEST_ADDRESS)
    parser.add_argument("--publish-address", default=lab_cli.DEFAULT_PUBLISH_ADDRESS)
    parser.add_argument("--timeout-ms", type=int, default=30_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_once(
            static_source=args.static_source,
            thermostat_source=args.thermostat_source,
            daily_route=args.daily_route,
            monthly_bundles=args.monthly_bundles,
            target=args.target,
            lab_target=args.lab_target,
            request_address=args.request_address,
            publish_address=args.publish_address,
            timeout_ms=args.timeout_ms,
        )
    except SimNowLabM5Error as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
