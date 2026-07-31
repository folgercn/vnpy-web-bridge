"""Privileged manifest signer entrypoint with irreversible UID handoff."""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .canonical import canonical_json_line
from .errors import RegistryError
from .history_backfill_receipts import load_backfill_receipt
from .m2_daily_scheduler import due_trade_day
from .m2_history_signer import (
    remaining_history_days,
    sign_manifest_day,
    verify_history_base,
)
from .m2_isolation_contracts import load_isolation_policy
from .m2_ntp import query_trusted_clock
from .m2_operator_defaults import (
    DEFAULT_MANIFEST_PRIVATE_KEY,
    DEFAULT_OPERATOR_STATE,
    MANIFEST_SIGNER_KEY_ID,
)
from .m2_operator_state import (
    load_operator_state,
    operator_state_lock,
    record_manifest_result,
)
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .m2_signer_handoff import run_with_preloaded_private_key
from .quality_contracts import REQUIRED_HISTORY_OFFICIAL_DAYS


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    result.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_MANIFEST_PRIVATE_KEY,
    )
    result.add_argument(
        "--operator-state",
        type=Path,
        default=DEFAULT_OPERATOR_STATE,
    )
    result.add_argument("--signer-key-id", default=MANIFEST_SIGNER_KEY_ID)
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--trade-day")
    mode.add_argument("--history-receipt", type=Path)
    result.add_argument("--expected-history-receipt-sha256")
    return result


def _bounded_history_clock():
    failure = None
    for _attempt in range(3):
        try:
            return query_trusted_clock()
        except RegistryError as exc:
            failure = exc
    assert failure is not None
    raise failure


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if (args.history_receipt is None) != (
            args.expected_history_receipt_sha256 is None
        ):
            raise RegistryError(
                "history receipt and expected SHA256 must be provided together"
            )
        policy = load_isolation_policy(
            args.runtime_input.parent / "isolation-policy-v1.json"
        )
        with operator_state_lock(args.operator_state, exclusive=True):
            state = load_operator_state(args.operator_state)
            if args.history_receipt is not None:
                expected_parent = (
                    Path(policy.payload["runtime_root"])
                    / "backfill-receipts"
                )
                if args.history_receipt.parent != expected_parent:
                    raise RegistryError(
                        "M2 history receipt is outside frozen runtime custody"
                    )
            history = (
                load_backfill_receipt(
                    args.history_receipt,
                    expected_raw_sha256=(
                        args.expected_history_receipt_sha256
                    ),
                    private=False,
                    expected_owner_uid=policy.payload["service_uid"],
                )
                if args.history_receipt is not None
                else None
            )
            if history is not None:
                verify_history_base(state, history)
                trade_days = remaining_history_days(state, history)
            else:
                trade_days = [args.trade_day] if args.trade_day else [None]

            def execute_day(
                requested_day,
                parent_trade_day,
                parent_seal,
                parent_commit,
            ):
                def sign(private_key):
                    context = load_runtime_context(args.runtime_input)
                    if history is not None and (
                        history["registry_raw_sha256"]
                        != context.registry.raw_sha256
                        or history["calendar_raw_sha256"]
                        != context.calendar.raw_sha256
                        or history[
                            "calendar_availability_anchor_raw_sha256"
                        ]
                        != context.availability.raw_sha256
                    ):
                        raise RegistryError(
                            "M2 history receipt runtime pins diverged"
                        )
                    if history is not None:
                        through = date.fromisoformat(
                            history["through_trade_day"]
                        )
                        expected_days = [
                            day.isoformat()
                            for day in context.calendar.official_days_through(
                                through,
                                count=REQUIRED_HISTORY_OFFICIAL_DAYS,
                            )
                        ]
                        if (
                            history["required_official_days"]
                            != REQUIRED_HISTORY_OFFICIAL_DAYS
                            or history["official_days"] != expected_days
                        ):
                            raise RegistryError(
                                "M2 history signer plan is not exact 186 days"
                            )
                    clock_provider = (
                        _bounded_history_clock
                        if history is not None
                        else query_trusted_clock
                    )
                    clock = clock_provider()
                    trade_day = requested_day or due_trade_day(
                        context.calendar,
                        now=clock.trusted_now,
                    )
                    if trade_day is None:
                        raise RegistryError(
                            "M2 manifest signer has no official day due"
                        )
                    history_receipt_path = None
                    if history is not None:
                        daily_entry = next(
                            item
                            for item in history["daily_receipts"]
                            if item["trade_day"] == trade_day
                        )
                        history_receipt_path = (
                            context.runtime.root
                            / daily_entry["run_receipt_relative_path"]
                        )
                    return sign_manifest_day(
                        context=context,
                        private_key=private_key,
                        trade_day=trade_day,
                        signer_key_id=args.signer_key_id,
                        parent_trade_day=parent_trade_day,
                        parent_seal=parent_seal,
                        parent_commit=parent_commit,
                        clock=clock,
                        run_receipt_path=history_receipt_path,
                        clock_provider=clock_provider,
                    )
                return run_with_preloaded_private_key(
                    private_key_path=args.private_key,
                    service_uid=policy.payload["service_uid"],
                    service_gid=policy.payload["service_gid"],
                    operation=sign,
                )

            results = []
            for requested_day in trade_days:
                attempts = 0
                while True:
                    attempts += 1
                    if attempts > 3:
                        raise RegistryError(
                            "M2 history signer did not converge on current fingerprint"
                        )
                    item = execute_day(
                        requested_day,
                        state.payload["last_trade_day"],
                        state.payload["manifest_head_seal_sha256"],
                        state.payload["manifest_head_commit_seal_sha256"],
                    )
                    results.append(item)
                    if item["status"] == "DAILY_BATCH_ALREADY_COMMITTED":
                        break
                    state = record_manifest_result(state, result=item)
                    if history is None:
                        break
            output = (
                {
                    "status": "M2_HISTORY_MANIFEST_CHAIN_COMPLETE",
                    "history_receipt_id": history["receipt_id"],
                    "required_official_days": history[
                        "required_official_days"
                    ],
                    "processed_days_this_run": len(trade_days),
                    "signed_days": sum(
                        item["status"]
                        == "DAILY_BATCH_COMMITTED_AWAITING_EXTERNAL_ANCHOR"
                        for item in results
                    ),
                    "already_signed_days": sum(
                        item["status"] == "DAILY_BATCH_ALREADY_COMMITTED"
                        for item in results
                    ),
                    "manifest_sequence": state.payload["manifest_sequence"],
                    "manifest_head_seal_sha256": state.payload[
                        "manifest_head_seal_sha256"
                    ],
                    "manifest_head_commit_seal_sha256": state.payload[
                        "manifest_head_commit_seal_sha256"
                    ],
                    "commit_anchor_ledger_raw_sha256": state.payload[
                        "commit_anchor_ledger_raw_sha256"
                    ],
                    "days": results,
                }
                if history is not None
                else results[0]
            )
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
