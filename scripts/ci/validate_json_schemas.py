#!/usr/bin/env python3
"""Validate repository JSON schemas against Draft 2020-12."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    schemas = sorted((ROOT / "docs/schemas").glob("*.schema.json"))
    if not schemas:
        raise SystemExit("no JSON schemas found")
    for path in schemas:
        with path.open(encoding="utf-8") as source:
            schema = json.load(source)
        Draft202012Validator.check_schema(schema)
    print(f"validated {len(schemas)} Draft 2020-12 schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
