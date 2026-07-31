"""No-authority M2 official-day scheduler entrypoint."""

from __future__ import annotations

import argparse
import sys
from datetime import date, datetime, timezone
from functools import partial
from pathlib import Path

from .acquisition import acquire_daily
from .canonical import canonical_json_line
from .errors import RegistryError
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
from .m2_request_gate import PersistentRequestGate
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context


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
