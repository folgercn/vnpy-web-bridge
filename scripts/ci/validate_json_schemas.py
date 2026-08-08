#!/usr/bin/env python3
"""Validate repository JSON schemas against Draft 2020-12."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIRECTORIES = (
    ROOT / "docs/schemas",
    ROOT / "scripts/phase_b_workers/schemas",
)


def main() -> int:
    schemas = sorted(
        path
        for directory in SCHEMA_DIRECTORIES
        for path in directory.glob("*.schema.json")
    )
    if not schemas:
        raise SystemExit("no JSON schemas found")
    for path in schemas:
        with path.open(encoding="utf-8") as source:
            schema = json.load(source)
        Draft202012Validator.check_schema(schema)
    print(
        f"validated {len(schemas)} Draft 2020-12 schemas "
        f"from {len(SCHEMA_DIRECTORIES)} schema directories"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
