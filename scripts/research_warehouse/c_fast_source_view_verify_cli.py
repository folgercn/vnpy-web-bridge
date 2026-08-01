"""Independently replay a published C_FAST Warehouse source directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .c_fast_source_view import (
    read_built_c_fast_source_view,
    verify_built_c_fast_source_view,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.input
    built = read_built_c_fast_source_view(root)
    verify_built_c_fast_source_view(built)
    print(
        json.dumps(
            {
                "status": "C_FAST_WAREHOUSE_SOURCE_VIEW_VERIFIED",
                "input": str(root),
                "authority_granted": False,
            },
            sort_keys=True,
        )
    )
    return 0
