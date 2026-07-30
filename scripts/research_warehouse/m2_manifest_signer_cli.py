"""Privileged manifest signer entrypoint with irreversible UID handoff."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_daily_scheduler import due_trade_day
from .m2_isolation_contracts import load_isolation_policy
from .m2_monitor_facts import verify_daily_run_receipt
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
from .m2_receipts import load_run_receipt
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .m2_signer_handoff import run_with_preloaded_private_key
from .manifest_commits import commit_receipt_path
from .manifests import seal_daily_batch_with_private_key


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
    result.add_argument("--trade-day")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy = load_isolation_policy(
            args.runtime_input.parent / "isolation-policy-v1.json"
        )
        with operator_state_lock(args.operator_state, exclusive=True):
            state = load_operator_state(args.operator_state)
            parent_seal = state.payload["manifest_head_seal_sha256"]
            parent_commit = state.payload["manifest_head_commit_seal_sha256"]

            def sign(private_key):
                context = load_runtime_context(args.runtime_input)
                clock = query_trusted_clock()
                trade_day = args.trade_day or due_trade_day(
                    context.calendar,
                    now=clock.trusted_now,
                )
                if trade_day is None:
                    raise RegistryError("M2 manifest signer has no official day due")
                receipt = load_run_receipt(
                    context.runtime.run_receipts / f"{trade_day}.json"
                )
                verify_daily_run_receipt(
                    receipt,
                    paths=context.paths,
                    registry=context.registry,
                    calendar=context.calendar,
                    calendar_availability_raw_sha256=(
                        context.availability.raw_sha256
                    ),
                )
                manifest_path = seal_daily_batch_with_private_key(
                    paths=context.paths,
                    registry=context.registry,
                    trade_day=trade_day,
                    private_key=private_key,
                    signer_key_id=args.signer_key_id,
                    expected_parent_batch_seal_sha256=parent_seal,
                    expected_parent_commit_seal_sha256=parent_commit,
                    trusted_clock=lambda: clock.trusted_now,
                )
                manifest_raw = read_regular_strict(
                    manifest_path,
                    "M2 signed manifest",
                    limit=16 * 1024 * 1024,
                )
                manifest = parse_json_strict(manifest_raw, "M2 signed manifest")
                receipt_path = commit_receipt_path(
                    manifest_path,
                    manifest["batch_id"],
                )
                receipt_raw = read_regular_strict(
                    receipt_path,
                    "M2 signed manifest commit receipt",
                    limit=2 * 1024 * 1024,
                )
                receipt = parse_json_strict(
                    receipt_raw,
                    "M2 signed manifest commit receipt",
                )
                return {
                    "batch_id": manifest["batch_id"],
                    "batch_seal_sha256": manifest["batch_seal_sha256"],
                    "commit_seal_sha256": sha256(receipt_raw),
                    "committed_at": receipt["committed_at"],
                    "manifest_relative_path": str(
                        manifest_path.relative_to(context.paths.root)
                    ),
                    "manifest_raw_sha256": sha256(manifest_raw),
                    "parent_batch_seal_sha256": manifest[
                        "parent_batch_seal_sha256"
                    ],
                    "parent_commit_seal_sha256": manifest[
                        "parent_commit_seal_sha256"
                    ],
                    "status": (
                        "DAILY_BATCH_COMMITTED_AWAITING_EXTERNAL_ANCHOR"
                    ),
                    "trade_day": trade_day,
                }

            output = run_with_preloaded_private_key(
                private_key_path=args.private_key,
                service_uid=policy.payload["service_uid"],
                service_gid=policy.payload["service_gid"],
                operation=sign,
            )
            record_manifest_result(
                state,
                result=output,
            )
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
