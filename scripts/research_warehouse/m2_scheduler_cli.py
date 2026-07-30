"""No-authority M2 official-day scheduler entrypoint."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .canonical import canonical_json_line
from .errors import RegistryError
from .m2_daily_scheduler import run_daily
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_ntp import query_trusted_clock
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--runtime-input",
        type=Path,
        default=DEFAULT_RUNTIME_INPUT,
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        context = load_runtime_context(args.runtime_input)
        clock_sample = query_trusted_clock()
        result = run_daily(
            paths=context.paths,
            runtime=context.runtime,
            registry=context.registry,
            calendar=context.calendar,
            availability=context.availability,
            clock_sample=clock_sample,
            collector_version=context.runtime_input.payload["collector_version"],
            verify_receipt=lambda receipt: verify_daily_run_receipt(
                receipt,
                paths=context.paths,
                registry=context.registry,
                calendar=context.calendar,
                calendar_availability_raw_sha256=(context.availability.raw_sha256),
            ),
            utc_clock=lambda: datetime.now(timezone.utc),
            clock_provider=query_trusted_clock,
        )
    except (OSError, RegistryError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(result))
    return 0
