"""Independent read-only verifier for a sealed PIT source-view directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pit_source_view import verify_built_source_view
from .pit_source_view_custody import read_source_view


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Independently verify a sealed relative-vol PIT source view",
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-receipt-sha256", required=True)
    args = parser.parse_args(argv)
    source_raw, receipt_raw = read_source_view(args.input)
    receipt = verify_built_source_view(
        source_raw,
        receipt_raw,
        expected_receipt_raw_sha256=args.expected_receipt_sha256,
    )
    print(
        json.dumps(
            {
                "status": "SEALED_PIT_SOURCE_VIEW_VERIFIED_READ_ONLY",
                "source_view_id": receipt["source_view_id"],
                "receipt_id": receipt["receipt_id"],
                "authority": receipt["authority"],
            },
            sort_keys=True,
        )
    )
    return 0
