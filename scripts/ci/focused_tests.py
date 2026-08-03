#!/usr/bin/env python3
"""Select a small deterministic smoke set from changed implementation paths."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[2]
UNIT_ROOT = ROOT / "backend/tests/unit"
ALWAYS = (
    "backend/tests/unit/test_ci_backend_test_shards.py",
    "backend/tests/unit/test_ci_change_classifier.py",
    "backend/tests/unit/test_ci_workflow_contract.py",
)


def select(paths: list[str]) -> list[str]:
    selected = {path for path in ALWAYS if (ROOT / path).is_file()}
    tests = sorted(UNIT_ROOT.glob("test_*.py"))
    for raw_path in paths:
        path = PurePosixPath(raw_path)
        if path.suffix != ".py":
            continue
        stem = path.stem.removeprefix("test_")
        tokens = {token for token in stem.split("_") if len(token) >= 4}
        if not tokens:
            continue
        candidates = []
        for test in tests:
            test_tokens = set(test.stem.removeprefix("test_").split("_"))
            overlap = len(tokens & test_tokens)
            if overlap >= min(3, len(tokens)):
                candidates.append((-overlap, test.name, test))
        for _, _, test in sorted(candidates)[:2]:
            selected.add(test.relative_to(ROOT).as_posix())
    return sorted(selected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--paths-file", required=True)
    args = parser.parse_args()
    with open(args.paths_file, encoding="utf-8") as source:
        paths = [line.rstrip("\n") for line in source]
    for path in select(paths):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
