"""Command-line policy checks for source-registry changes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .authority import assert_research_source_boundary
from .errors import RegistryError
from .registry import load_registry


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    registry = commands.add_parser("verify-registry")
    registry.add_argument("--registry", type=Path, required=True)
    boundary = commands.add_parser("verify-boundary")
    boundary.add_argument("--source-root", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "verify-registry":
            registry = load_registry(args.registry)
            output = {
                "authority": registry.authority.authority_class,
                "registry_id": registry.registry_id,
                "registry_raw_sha256": registry.raw_sha256,
                "sources": [source.source_id for source in registry.sources],
                "status": "VALID",
            }
        else:
            paths = list(args.source_root.rglob("*.py"))
            if not paths:
                raise RegistryError("Research source root contains no Python modules")
            assert_research_source_boundary(paths)
            output = {
                "checked_file_count": len(paths),
                "status": "RESEARCH_BOUNDARY_VALID",
            }
    except RegistryError as exc:
        print(f"Research source policy failed closed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0
