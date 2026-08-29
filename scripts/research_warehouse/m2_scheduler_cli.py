"""No-authority M2 official-day scheduler entrypoint."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
from datetime import date, datetime, timezone
from functools import partial
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from simnow_experimental_materialize_target import NOT_OFFICIAL_STRATEGY_OUTPUT
from simnow_experimental_timely_daily_route import ROUTE_MODE, _timely_cutoff

from .acquisition import acquire_daily
from .canonical import canonical_json_line, sha256
from .daily_pit_main_roll_source import _following_official_days
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict, write_all
from .history_backfill_receipts import load_backfill_receipt
from .m2_acl_custody import require_acl_free_path
from .m2_daily_scheduler import run_daily
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
from .m2_receipts import load_run_receipt
from .m2_request_gate import PersistentRequestGate
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .pit_source_view import (
    _official_month_boundary,
    _safe_relative_path,
    build_source_view,
)
from .shfe_contract_parameters import evidence_from_pinned_raw
from .static_core_baseline import _registry, build_historical_baseline
from .timeutil import format_utc
from .verified_daily_pit_main_roll_source import _mains

SIMNOW_LAB_INPUT_DIRECTORY = Path("/Users/Shared/vnpy-simnow-lab-inputs")
SIMNOW_LAB_SOURCE_MAX_BYTES = 4 * 1024 * 1024
SIMNOW_LAB_EXPORT_NAMES = (
    "static-core-equal-monthly-source.json",
    "monthly-relative-vol-thermostat-source.json",
    "daily-pit-route.json",
)
SIMNOW_LAB_CONTRACT_PARAMETERS = Path(
    "/Users/Shared/vnpy-research/custody/raw/shfe/2026-08-28/"
    "shfe-contract-parameters-v1/"
    "b46f8fcb29cae52997017aa80c58f274abb7e6028c67b0f9647e45a4ede4d57b.raw"
)
SIMNOW_LAB_CONTRACT_PARAMETERS_SHA256 = (
    "b46f8fcb29cae52997017aa80c58f274abb7e6028c67b0f9647e45a4ede4d57b"
)
SIMNOW_LAB_CONTRACT_PARAMETERS_BYTES = 80997
SIMNOW_LAB_CONTRACT_PARAMETERS_OBSERVED_AT = "2026-08-29T04:55:44.297413Z"


def _source_month_for_completed_day(context, trade_day: str) -> str:
    try:
        current = date.fromisoformat(trade_day)
    except ValueError as exc:
        raise RegistryError("completed official day is invalid") from exc
    if current.isoformat() != trade_day:
        raise RegistryError("completed official day is invalid")
    months = sorted(
        {
            f"{day.year:04d}-{day.month:02d}"
            for day in context.calendar.days
            if day < current.replace(day=1)
        }
    )
    eligible = []
    for source_month in months:
        _research, execution_day, _cutoff = _official_month_boundary(
            context.calendar, source_month=source_month
        )
        if execution_day <= current:
            eligible.append(source_month)
    if not eligible:
        raise RegistryError("SIMNOW_LAB has no completed monthly source")
    return eligible[-1]


def _frozen_contract_registry_raw() -> bytes:
    """Use the immutable PRODUCT_SPECS facts; this creates no registry file."""

    from commodity_c_fast_pure_producer_kernel import PRODUCT_SPECS, PRODUCTS

    from .m2_isolation_contracts import false_authority

    products = []
    for product in PRODUCTS:
        spec = PRODUCT_SPECS[product]
        products.append(
            {
                "product": product,
                "exchange": spec["exchange"],
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
                "last_trading_day_rule": (
                    "INE_SC_PREVIOUS_MONTH_LAST_OFFICIAL_V1"
                    if product == "sc"
                    else "SHFE_DELIVERY_MONTH_15TH_NEXT_OFFICIAL_V1"
                ),
                "source_id": "frozen-product-specs-v1",
            }
        )
    return canonical_json_line(
        {
            "schema_version": "vnpy_research_static_core_contract_registry_v1",
            "registry_id": "frozen-product-specs-v1",
            "generated_at": "2026-08-29T00:00:00Z",
            "sources": [{"source_id": "frozen-product-specs-v1"}],
            "products": products,
            "authority": false_authority(),
        }
    )


def _simnow_replay_state(history_raw: bytes) -> SimpleNamespace:
    names = (
        "operator_state_raw_sha256",
        "manifest_genesis_seal_sha256",
        "manifest_head_seal_sha256",
        "manifest_head_commit_seal_sha256",
        "commit_anchor_ledger_raw_sha256",
    )
    payload = {
        name: sha256(canonical_json_line({"name": name, "history": sha256(history_raw)}))
        for name in names
    }
    return SimpleNamespace(
        raw_sha256=payload["operator_state_raw_sha256"], payload=payload
    )


def _one_186_day_backfill(context, path: Path):
    receipt = load_backfill_receipt(path, expected_owner_uid=context.policy.uid)
    if (
        receipt["required_official_days"] != DEFAULT_HISTORY_DAYS
        or receipt["calendar_raw_sha256"] != context.calendar.raw_sha256
        or receipt["calendar_availability_anchor_raw_sha256"]
        != context.availability.raw_sha256
        or receipt["registry_raw_sha256"] != context.registry.raw_sha256
    ):
        raise RegistryError("SIMNOW_LAB 186-day backfill receipt does not match runtime")
    return receipt, read_regular_strict(path, "M2 history backfill receipt")


def _completed_daily_raw(context, trade_day: str) -> tuple[dict, bytes, dict[str, bytes]]:
    receipt_path = context.runtime.run_receipts / f"{trade_day}.json"
    receipt_raw = read_regular_strict(receipt_path, "SIMNOW_LAB daily run receipt")
    receipt = load_run_receipt(receipt_path)
    if receipt["trade_day"] != trade_day:
        raise RegistryError("SIMNOW_LAB daily run receipt day differs")
    raws: dict[str, bytes] = {}
    for source in receipt["sources"]:
        raw = read_regular_strict(
            context.paths.root / source["raw_relative_path"],
            "SIMNOW_LAB daily raw",
            limit=16 * 1024 * 1024,
        )
        if len(raw) != source["raw_bytes"] or sha256(raw) != source["raw_sha256"]:
            raise RegistryError("SIMNOW_LAB daily raw binding drifted")
        raws[source["exchange"]] = raw
    if set(raws) != {"SHFE", "INE"}:
        raise RegistryError("SIMNOW_LAB daily raw exchange set is invalid")
    return receipt, receipt_raw, raws


def _backfill_daily_raw(context, history: dict) -> dict[str, dict[str, bytes]]:
    result: dict[str, dict[str, bytes]] = {}
    for expected in history["daily_receipts"]:
        receipt_path = _safe_relative_path(
            context.runtime.root,
            expected["run_receipt_relative_path"],
            "SIMNOW_LAB history receipt",
        )
        receipt_raw = read_regular_strict(receipt_path, "SIMNOW_LAB history receipt")
        if sha256(receipt_raw) != expected["run_receipt_raw_sha256"]:
            raise RegistryError("SIMNOW_LAB history receipt SHA256 drifted")
        receipt = load_run_receipt(receipt_path)
        if receipt["trade_day"] != expected["trade_day"]:
            raise RegistryError("SIMNOW_LAB history receipt day differs")
        sources: dict[str, bytes] = {}
        for index, source in enumerate(receipt["sources"]):
            raw = read_regular_strict(
                _safe_relative_path(
                    context.paths.root, source["raw_relative_path"], "SIMNOW_LAB history raw"
                ),
                "SIMNOW_LAB history raw",
                limit=16 * 1024 * 1024,
            )
            if (
                len(raw) != expected["source_raw_bytes"][index]
                or sha256(raw) != expected["source_raw_sha256"][index]
                or len(raw) != source["raw_bytes"]
                or sha256(raw) != source["raw_sha256"]
            ):
                raise RegistryError("SIMNOW_LAB history raw binding drifted")
            sources[source["exchange"]] = raw
        if set(sources) != {"SHFE", "INE"}:
            raise RegistryError("SIMNOW_LAB history raw exchange set is invalid")
        result[receipt["trade_day"]] = sources
    if set(result) != set(history["official_days"]):
        raise RegistryError("SIMNOW_LAB history raw days are incomplete")
    return result


def _daily_route(*, context, trade_day: str, receipt: dict, receipt_raw: bytes,
                 daily_raw: dict[str, bytes], registry_raw: bytes, parameters) -> dict:
    day = date.fromisoformat(trade_day)
    execution_day, following_day = _following_official_days(context.calendar, day)
    registry, registry_sha = _registry(registry_raw)
    mains, _lineage = _mains(
        context=context,
        official_day=day,
        execution_day=execution_day,
        following_day=following_day,
        daily_source_raw=daily_raw,
        contract_registry=registry,
        predecessor={product: "" for product in registry},
        shfe_contract_parameters=parameters,
    )
    cutoff = _timely_cutoff(execution_day.isoformat())
    return {
        "schema_version": "daily-pit-route-v1",
        "mains": [
            {key: row[key] for key in ("product", "exchange", "exact_contract")}
            for row in mains
        ],
        "metadata": {
            "route_mode": ROUTE_MODE,
            "strategy_output_claim": NOT_OFFICIAL_STRATEGY_OUTPUT,
            "official_day": trade_day,
            "execution_day": execution_day.isoformat(),
            "execution_cutoff_utc": format_utc(cutoff, "SIMNOW route cutoff"),
            "run_receipt_id": receipt["receipt_id"],
            "run_receipt_raw_sha256": sha256(receipt_raw),
            "contract_registry_raw_sha256": registry_sha,
            "shfe_contract_parameters_raw_sha256": parameters.raw_sha256,
            "shfe_contract_parameters_observed_at": format_utc(
                parameters.observed_at, "SIMNOW ContractBaseInfo observed_at"
            ),
            "production": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "official_forward_claimed": False,
        },
    }


def _precompute_exports(
    context, trade_day: str, history_receipt_path: Path
) -> tuple[bytes, bytes, bytes]:
    try:
        history, history_raw = _one_186_day_backfill(context, history_receipt_path)
        source_month = _source_month_for_completed_day(context, trade_day)
        daily_raw = _backfill_daily_raw(context, history)
        state = _simnow_replay_state(history_raw)
        operator_pins = {
            "operator_state_raw_sha256": state.raw_sha256,
            **{
                field: state.payload[field]
                for field in (
                    "manifest_genesis_seal_sha256",
                    "manifest_head_seal_sha256",
                    "manifest_head_commit_seal_sha256",
                    "commit_anchor_ledger_raw_sha256",
                )
            },
        }
        registry_raw = _frozen_contract_registry_raw()
        static = build_historical_baseline(
            calendar=context.calendar,
            calendar_anchor_raw_sha256=context.availability.raw_sha256,
            warehouse_registry_raw_sha256=context.registry.raw_sha256,
            history_receipt=history,
            history_receipt_raw_sha256=sha256(history_raw),
            operator_pins=operator_pins,
            daily_source_raw=daily_raw,
            contract_registry_raw=registry_raw,
            source_month=source_month,
            signer_key_id="simnow-lab-placeholder",
            execution_lane="simnow_shakedown",
        )
        thermostat = build_source_view(
            calendar=context.calendar,
            calendar_anchor=context.availability,
            history_receipt=history,
            history_receipt_sha256=sha256(history_raw),
            operator_state=state,
            daily_source_raw=daily_raw,
            baseline_batch=__import__("json").loads(static.unsigned_batch_raw),
            business_public_key=Ed25519PublicKey.from_public_bytes(bytes(32)),
            expected_business_signer_key_id="simnow-lab-placeholder",
            source_month=source_month,
            previous_snapshot=None,
            allow_simnow_placeholder_baseline=True,
        )
        daily_receipt, daily_receipt_raw, current_daily_raw = _completed_daily_raw(
            context, trade_day
        )
        parameters_raw = read_regular_strict(
            SIMNOW_LAB_CONTRACT_PARAMETERS,
            "SIMNOW_LAB ContractBaseInfo evidence",
            private=False,
            limit=SIMNOW_LAB_SOURCE_MAX_BYTES,
        )
        if len(parameters_raw) != SIMNOW_LAB_CONTRACT_PARAMETERS_BYTES:
            raise RegistryError("SIMNOW_LAB ContractBaseInfo byte count drifted")
        parameters = evidence_from_pinned_raw(
            observed_at=SIMNOW_LAB_CONTRACT_PARAMETERS_OBSERVED_AT,
            raw=parameters_raw,
            expected_raw_sha256=SIMNOW_LAB_CONTRACT_PARAMETERS_SHA256,
        )
        route = _daily_route(
            context=context, trade_day=trade_day, receipt=daily_receipt,
            receipt_raw=daily_receipt_raw, daily_raw=current_daily_raw,
            registry_raw=registry_raw, parameters=parameters,
        )
        return static.source_view_raw, thermostat.source_view_raw, canonical_json_line(route)
    except RegistryError:
        raise
    except (KeyError, TypeError, ValueError, OSError) as exc:
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


def export_simnow_lab_inputs(
    *, context, daily_result: dict, history_receipt_path: Path
) -> None:
    if daily_result.get("status") not in {"OFFICIAL_DAY_COMPLETE", "ALREADY_COMPLETE"}:
        return
    trade_day = daily_result.get("trade_day")
    if not isinstance(trade_day, str):
        raise RegistryError("completed official day is invalid")
    outputs = _precompute_exports(context, trade_day, history_receipt_path)
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
            with operator_state_lock(args.operator_state, exclusive=False):
                state = load_operator_state(args.operator_state)
                history_result = run_history_backfill(
                    paths=context.paths,
                    runtime=context.runtime,
                    registry=context.registry,
                    calendar=context.calendar,
                    availability=context.availability,
                    through_trade_day=date.fromisoformat(result["trade_day"]),
                    required_official_days=DEFAULT_HISTORY_DAYS,
                    collector_version=context.runtime_input.payload[
                        "collector_version"
                    ],
                    operator_state=state,
                    clock_provider=query_trusted_clock,
                    acquire=gated_acquire,
                    utc_clock=lambda: datetime.now(timezone.utc),
                )
            export_simnow_lab_inputs(
                context=context,
                daily_result=result,
                history_receipt_path=Path(history_result["backfill_receipt"]),
            )
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
