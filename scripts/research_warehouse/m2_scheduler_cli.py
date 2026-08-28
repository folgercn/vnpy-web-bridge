"""No-authority M2 official-day scheduler entrypoint."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tempfile
from datetime import date, datetime, timezone
from functools import partial
from pathlib import Path

import commodity_relative_vol_snapshot_producer as thermostat_producer
import commodity_static_core_equal_pure_producer as static_producer
from simnow_experimental_timely_daily_route import (
    build_timely_experimental_route,
)

from .acquisition import acquire_daily
from .canonical import canonical_json_line, parse_json_strict
from .daily_roll_predecessor_catalog import _read_private_protected_evidence
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict, write_all
from .m2_acl_custody import require_acl_free_path
from .m2_daily_scheduler import run_daily
from .m2_genesis_predecessor_cli import _config_raw, _projection_from_config
from .m2_history_backfill import (
    DEFAULT_HISTORY_DAYS,
    RequestGate,
    retrying_acquirer,
    run_history_backfill,
)
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_ntp import query_trusted_clock
from .m2_operator_defaults import (
    DEFAULT_MANIFEST_PUBLIC_KEY,
    DEFAULT_OPERATOR_STATE,
)
from .m2_operator_state import load_operator_state, operator_state_lock
from .m2_request_gate import PersistentRequestGate
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT, require_root_managed
from .m2_runtime_loader import load_runtime_context

SIMNOW_LAB_EXPORT_INPUT = Path(
    "/usr/local/etc/vnpyresearch/simnow-lab-export-input-v1.json"
)
SIMNOW_LAB_INPUT_DIRECTORY = Path("/Users/Shared/vnpy-simnow-lab-inputs")
SIMNOW_LAB_EXPORT_SCHEMA = "simnow_lab_research_export_input_v1"
SIMNOW_LAB_EXPORT_MAX_BYTES = 16 * 1024
SIMNOW_LAB_SOURCE_MAX_BYTES = 4 * 1024 * 1024
SIMNOW_LAB_EXPORT_NAMES = (
    "static-core-equal-monthly-source.json",
    "monthly-relative-vol-thermostat-source.json",
    "daily-pit-route.json",
)
_CONFIG_KEYS = {
    "schema_version",
    "monthly_static_source_path",
    "monthly_thermostat_source_path",
    "daily_pit_continuous_config_path",
}


def _export_config() -> dict[str, Path]:
    require_root_managed(SIMNOW_LAB_EXPORT_INPUT)
    info = SIMNOW_LAB_EXPORT_INPUT.lstat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o444:
        raise RegistryError("SIMNOW_LAB export input must be root-managed")
    raw = read_regular_strict(
        SIMNOW_LAB_EXPORT_INPUT,
        "SIMNOW_LAB export input",
        private=False,
        limit=SIMNOW_LAB_EXPORT_MAX_BYTES,
    )
    value = parse_json_strict(raw, "SIMNOW_LAB export input")
    if (
        not isinstance(value, dict)
        or set(value) != _CONFIG_KEYS
        or value.get("schema_version") != SIMNOW_LAB_EXPORT_SCHEMA
        or canonical_json_line(value) != raw
    ):
        raise RegistryError("SIMNOW_LAB export input contract is invalid")
    paths = {key: Path(value[key]) for key in _CONFIG_KEYS - {"schema_version"}}
    if any(not path.is_absolute() for path in paths.values()):
        raise RegistryError("SIMNOW_LAB export input path is invalid")
    return paths


def _source_month(static_result, thermostat_result) -> str:
    target = parse_json_strict(
        static_result.artifacts["target_evidence"], "STATIC_CORE_EQUAL target"
    )
    snapshot = parse_json_strict(
        thermostat_result.snapshot_draft, "monthly thermostat snapshot"
    )
    execution = date.fromisoformat(target["execution_day"])
    prior = execution.replace(day=1).toordinal() - 1
    static_month = date.fromordinal(prior).strftime("%Y-%m")
    thermostat_month = snapshot.get("source_month")
    if thermostat_month != static_month:
        raise RegistryError("monthly source_month values differ")
    return static_month


def _precompute_exports(context, trade_day: str) -> tuple[bytes, bytes, bytes]:
    config = _export_config()
    try:
        static_raw = _read_private_protected_evidence(
            config["monthly_static_source_path"],
            "monthly static source",
            uid=context.policy.uid,
            limit=SIMNOW_LAB_SOURCE_MAX_BYTES,
        )
        thermostat_raw = _read_private_protected_evidence(
            config["monthly_thermostat_source_path"],
            "monthly thermostat source",
            uid=context.policy.uid,
            limit=SIMNOW_LAB_SOURCE_MAX_BYTES,
        )
        static_result = static_producer.produce_research_artifacts(static_raw)
        thermostat_result = thermostat_producer.produce_snapshot(thermostat_raw)
        _source_month(static_result, thermostat_result)
        static_output = static_result.source_view_canonical
        thermostat_output = thermostat_producer.canonical_json(
            parse_json_strict(thermostat_raw, "monthly thermostat source")
        )
        if (
            hashlib.sha256(thermostat_output).hexdigest()
            != thermostat_result.source_view_canonical_sha256
        ):
            raise RegistryError("monthly thermostat source replay drifted")
        projection = _projection_from_config(
            _config_raw(
                config["daily_pit_continuous_config_path"], uid=context.policy.uid
            )
        )
        route = build_timely_experimental_route(
            context=context,
            official_day=trade_day,
            contract_registry_path=projection.contract_registry_path,
            expected_contract_registry_raw_sha256=projection.contract_registry_raw_sha256,
            shfe_contract_parameters_path=projection.shfe_contract_parameters_path,
            expected_shfe_contract_parameters_raw_sha256=(
                projection.shfe_contract_parameters_raw_sha256
            ),
            shfe_contract_parameters_observed_at=(
                projection.shfe_contract_parameters_observed_at
            ),
        )
        return static_output, thermostat_output, canonical_json_line(route)
    except RegistryError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise RegistryError("SIMNOW_LAB export precompute failed") from exc


def _export_root() -> Path:
    root = SIMNOW_LAB_INPUT_DIRECTORY
    created = not root.exists()
    root.mkdir(mode=0o755, parents=False, exist_ok=True)
    if created:
        os.chmod(root, 0o755, follow_symlinks=False)
        fsync_dir(root.parent)
    info = root.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        raise RegistryError("SIMNOW_LAB export directory is unsafe")
    require_acl_free_path(root, "SIMNOW_LAB export directory")
    return root


def _existing(path: Path) -> bytes | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o644
        or info.st_nlink != 1
    ):
        raise RegistryError("existing SIMNOW_LAB export custody mismatch")
    require_acl_free_path(path, "existing SIMNOW_LAB export")
    return read_regular_strict(
        path,
        "existing SIMNOW_LAB export",
        private=False,
        limit=SIMNOW_LAB_SOURCE_MAX_BYTES,
    )


def _replace(path: Path, raw: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        write_all(descriptor, raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def export_simnow_lab_inputs(*, context, daily_result: dict) -> None:
    if daily_result.get("status") not in {"OFFICIAL_DAY_COMPLETE", "ALREADY_COMPLETE"}:
        return
    trade_day = daily_result.get("trade_day")
    if not isinstance(trade_day, str):
        raise RegistryError("completed official day is invalid")
    outputs = _precompute_exports(context, trade_day)
    root = _export_root()
    paths = tuple(root / name for name in SIMNOW_LAB_EXPORT_NAMES)
    current = tuple(_existing(path) for path in paths)
    for path, before, raw in zip(paths, current, outputs, strict=True):
        if before != raw:
            _replace(path, raw)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--runtime-input",
        type=Path,
        default=DEFAULT_RUNTIME_INPUT,
    )
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--history-through")
    mode.add_argument("--verify-history-receipt", type=Path)
    result.add_argument("--expected-history-receipt-sha256")
    result.add_argument(
        "--history-days",
        type=int,
        default=DEFAULT_HISTORY_DAYS,
    )
    result.add_argument(
        "--minimum-request-interval-seconds",
        type=float,
        default=2.0,
    )
    result.add_argument("--maximum-attempts", type=int, default=4)
    result.add_argument("--initial-backoff-seconds", type=float, default=5.0)
    result.add_argument(
        "--operator-state",
        type=Path,
        default=DEFAULT_OPERATOR_STATE,
    )
    result.add_argument(
        "--manifest-public-key",
        type=Path,
        default=DEFAULT_MANIFEST_PUBLIC_KEY,
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        context = load_runtime_context(args.runtime_input)
        if args.verify_history_receipt is not None:
            from .m2_history_verifier import verify_history_backfill

            if args.expected_history_receipt_sha256 is None:
                raise RegistryError(
                    "history verifier requires expected receipt SHA256"
                )
            with operator_state_lock(args.operator_state, exclusive=False):
                state = load_operator_state(args.operator_state)
                result = verify_history_backfill(
                    context=context,
                    operator_state=state,
                    history_receipt_path=args.verify_history_receipt,
                    expected_history_receipt_raw_sha256=(
                        args.expected_history_receipt_sha256
                    ),
                    manifest_public_key_path=args.manifest_public_key,
                    clock_sample=query_trusted_clock(),
                )
        elif args.expected_history_receipt_sha256 is not None:
            raise RegistryError(
                "expected history receipt SHA256 requires verifier mode"
            )
        elif args.history_through is None:
            request_gate = PersistentRequestGate(
                context.runtime.root,
                minimum_interval_seconds=args.minimum_request_interval_seconds,
                clock_provider=query_trusted_clock,
            )
            gated_acquire = partial(
                acquire_daily,
                request_gate=request_gate.request,
            )
            clock_sample = query_trusted_clock()
            result = run_daily(
                paths=context.paths,
                runtime=context.runtime,
                registry=context.registry,
                calendar=context.calendar,
                availability=context.availability,
                clock_sample=clock_sample,
                collector_version=context.runtime_input.payload[
                    "collector_version"
                ],
                verify_receipt=lambda receipt: verify_daily_run_receipt(
                    receipt,
                    paths=context.paths,
                    registry=context.registry,
                    calendar=context.calendar,
                    calendar_availability_raw_sha256=(
                        context.availability.raw_sha256
                    ),
                ),
                acquire=gated_acquire,
                utc_clock=lambda: datetime.now(timezone.utc),
                clock_provider=query_trusted_clock,
            )
            export_simnow_lab_inputs(context=context, daily_result=result)
        else:
            request_gate = PersistentRequestGate(
                context.runtime.root,
                minimum_interval_seconds=args.minimum_request_interval_seconds,
                clock_provider=query_trusted_clock,
            )
            gated_acquire = partial(
                acquire_daily,
                request_gate=request_gate.request,
            )
            through = date.fromisoformat(args.history_through)
            if through.isoformat() != args.history_through:
                raise RegistryError(
                    "history through day must be canonical YYYY-MM-DD"
                )
            gate = RequestGate(args.minimum_request_interval_seconds)
            acquire = retrying_acquirer(
                gated_acquire,
                clock_provider=query_trusted_clock,
                request_gate=gate,
                maximum_attempts=args.maximum_attempts,
                initial_backoff_seconds=args.initial_backoff_seconds,
            )
            with operator_state_lock(args.operator_state, exclusive=False):
                state = load_operator_state(args.operator_state)
                result = run_history_backfill(
                    paths=context.paths,
                    runtime=context.runtime,
                    registry=context.registry,
                    calendar=context.calendar,
                    availability=context.availability,
                    through_trade_day=through,
                    required_official_days=args.history_days,
                    collector_version=context.runtime_input.payload[
                        "collector_version"
                    ],
                    operator_state=state,
                    clock_provider=query_trusted_clock,
                    acquire=acquire,
                    utc_clock=lambda: datetime.now(timezone.utc),
                )
    except (OSError, RegistryError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(result))
    return 0
