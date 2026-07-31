"""Independently replay a historical STATIC_CORE_EQUAL baseline bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import commodity_static_core_equal_pure_producer as producer

from .canonical import parse_json_strict, sha256
from .file_integrity import read_regular_strict
from .static_core_baseline import BuiltBaseline, verify_built_baseline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.input
    built = BuiltBaseline(
        source_view_raw=read_regular_strict(root / "source-view.json", "source view"),
        artifacts={
            role: read_regular_strict(root / f"{role}.json", f"{role} evidence")
            for role in producer.ARTIFACT_ROLES
        },
        unsigned_batch_raw=read_regular_strict(
            root / "unsigned-target-batch.json",
            "unsigned target batch",
        ),
        evidence_raw=read_regular_strict(
            root / "baseline-evidence.json",
            "baseline evidence",
        ),
    )
    verify_built_baseline(built)
    batch = parse_json_strict(built.unsigned_batch_raw, "unsigned target batch")
    print(
        json.dumps(
            {
                "status": "INDEPENDENT_EXACT_REPLAY_VERIFIED",
                "source_view_raw_sha256": sha256(built.source_view_raw),
                "unsigned_batch_raw_sha256": sha256(built.unsigned_batch_raw),
                "contracts": {
                    row["product"]: row["exact_contract"]
                    for row in batch["targets"]
                },
            },
            sort_keys=True,
        )
    )
    return 0
