"""Extend the M2 signed official calendar with retained 2025 notice bytes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .calendar_extension import NewCalendarEvidence, issue_extended_calendar
from .canonical import canonical_json_line
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_calendar_rotation import activate_calendar_rotation
from .m2_isolation_contracts import load_isolation_policy
from .m2_ntp import query_trusted_clock
from .m2_operator_defaults import DEFAULT_CALENDAR_PRIVATE_KEY
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT, load_runtime_input
from .m2_runtime_loader import load_runtime_context
from .m2_signer_handoff import run_with_preloaded_private_key

SOURCE_URLS = {
    "INE": "https://www.ine.cn/publicnotice/notice/202412/t20241223_824108.html",
    "SHFE": "https://www.shfe.com.cn/publicnotice/notice/202412/t20241223_824109.html",
}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    result.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_CALENDAR_PRIVATE_KEY,
    )
    result.add_argument("--ine-capture", type=Path, required=True)
    result.add_argument("--shfe-capture", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy = load_isolation_policy(
            args.runtime_input.parent / "isolation-policy-v1.json"
        )
        current = load_runtime_input(args.runtime_input, policy=policy)

        def child(private_key):
            captures = {
                "INE": args.ine_capture,
                "SHFE": args.shfe_capture,
            }
            for exchange, path in captures.items():
                read_regular_strict(path, f"{exchange} staged 2025 capture")
            observed = query_trusted_clock().trusted_now
            issued = query_trusted_clock().trusted_now
            return issue_extended_calendar(
                context=load_runtime_context(args.runtime_input),
                private_key=private_key,
                new_evidence=tuple(
                    NewCalendarEvidence(
                        exchange=exchange,
                        source_url=SOURCE_URLS[exchange],
                        capture_path=captures[exchange],
                    )
                    for exchange in ("INE", "SHFE")
                ),
                observed_at=observed,
                issued_at=issued,
            )

        issued = run_with_preloaded_private_key(
            private_key_path=args.private_key,
            service_uid=policy.payload["service_uid"],
            service_gid=policy.payload["service_gid"],
            operation=child,
        )
        output = activate_calendar_rotation(
            current=current,
            policy=policy,
            issued=issued,
        )
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
