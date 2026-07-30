"""Initialize or inspect root-managed M2 operator pins."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .canonical import canonical_json_line
from .errors import RegistryError
from .m2_operator_defaults import DEFAULT_OPERATOR_STATE
from .m2_operator_state import (
    initialize_operator_state,
    load_operator_state,
    operator_state_lock,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("initialize", "show"):
        command = commands.add_parser(name)
        command.add_argument(
            "--operator-state",
            type=Path,
            default=DEFAULT_OPERATOR_STATE,
        )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "initialize":
            state = initialize_operator_state(args.operator_state)
        else:
            with operator_state_lock(args.operator_state, exclusive=False):
                state = load_operator_state(args.operator_state)
        output = {
            **state.payload,
            "operator_state_raw_sha256": state.raw_sha256,
        }
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
