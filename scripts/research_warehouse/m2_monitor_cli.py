"""M2 monitor entrypoint with real-fact and legacy pure-evaluator modes."""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import load_isolation_policy
from .m2_monitor import evaluate_monitor
from .m2_monitor_facts import derive_monitor_facts
from .m2_ntp import query_trusted_clock
from .m2_receipts import publish_monitor_receipt
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .timeutil import parse_utc


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--policy", type=Path)
    result.add_argument("--input", type=Path)
    result.add_argument("--now")
    result.add_argument(
        "--runtime-input",
        type=Path,
        default=DEFAULT_RUNTIME_INPUT,
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        legacy = any(value is not None for value in (args.policy, args.input, args.now))
        if legacy:
            if None in (args.policy, args.input, args.now):
                raise RegistryError(
                    "legacy monitor mode requires --policy, --input, and --now"
                )
            policy = load_isolation_policy(args.policy)
            monitor_input = parse_json_strict(
                read_regular_strict(args.input, "M2 monitor input"),
                "M2 monitor input",
            )
            now = parse_utc(args.now, "M2 monitor now")
            result = evaluate_monitor(monitor_input, policy=policy, now=now)
            output = result
        else:
            context = load_runtime_context(args.runtime_input)
            clock_sample = query_trusted_clock()
            value = context.runtime_input.payload
            facts = derive_monitor_facts(
                paths=context.paths,
                runtime=context.runtime,
                registry=context.registry,
                calendar=context.calendar,
                calendar_availability_raw_sha256=(context.availability.raw_sha256),
                monitor_from_day=date.fromisoformat(value["monitor_from_day"]),
                backup_root=Path(context.policy.payload["backup_root"]),
                backup_public_key_path=Path(value["backup_public_key_path"]),
                expected_backup_public_key_sha256=(
                    value["expected_backup_public_key_sha256"]
                ),
                expected_backup_head_anchor_raw_sha256=(
                    value["expected_backup_head_anchor_raw_sha256"]
                ),
                now=clock_sample.trusted_now,
            )
            result = evaluate_monitor(
                facts,
                policy=context.policy,
                now=clock_sample.trusted_now,
            )
            receipt_path, receipt = publish_monitor_receipt(
                context.runtime,
                checked_at=clock_sample.trusted_now.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z"),
                runtime_input_raw_sha256=context.runtime_input.raw_sha256,
                facts=facts,
                result=result,
            )
            output = {
                **result,
                "receipt": str(receipt_path),
                "receipt_raw_sha256": sha256(receipt_path.read_bytes()),
                "receipt_id": receipt["receipt_id"],
            }
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0 if result["status"] == "HEALTHY" else 1
