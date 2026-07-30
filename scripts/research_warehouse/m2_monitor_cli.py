"""CLI plumbing for the pure M2 monitor evaluator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .canonical import canonical_json_line, parse_json_strict
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import load_isolation_policy
from .m2_monitor import evaluate_monitor
from .timeutil import parse_utc


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--policy", type=Path, required=True)
    result.add_argument("--input", type=Path, required=True)
    result.add_argument("--now", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy = load_isolation_policy(args.policy)
        monitor_input = parse_json_strict(
            read_regular_strict(args.input, "M2 monitor input"),
            "M2 monitor input",
        )
        result = evaluate_monitor(
            monitor_input,
            policy=policy,
            now=parse_utc(args.now, "M2 monitor now"),
        )
    except RegistryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(result))
    return 0 if result["status"] == "HEALTHY" else 1
