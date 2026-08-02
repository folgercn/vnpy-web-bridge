#!/usr/bin/env python3
"""Verify and bind one authoritative fee statement without external I/O."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from app.core.config import Settings
from app.schemas.commodity_c_fast_fee_statement import canonical_json_bytes
from app.services.commodity_c_fast_fee_statement import (
    load_and_verify_late_fee_correction_from_settings,
    load_settled_archive_replay_facts,
)
from app.services.commodity_c_fast_pnl_ledger import (
    build_actual_simnow_fee_bound_source_facts,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-facts", type=Path, required=True)
    parser.add_argument("--archive-facts-raw-sha256", required=True)
    parser.add_argument("--fee-statement", type=Path, required=True)
    parser.add_argument("--fee-statement-raw-sha256", required=True)
    parser.add_argument("--fee-source-document", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _write_create_only(path: Path, raw: bytes) -> None:
    if not path.is_absolute() or not path.parent.is_dir():
        raise ValueError("output must be absolute with an existing parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _lexical_absolute(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        raise ValueError("artifact paths must be absolute")
    return path


def main() -> int:
    args = parse_args()
    archive = load_settled_archive_replay_facts(
        path=_lexical_absolute(args.archive_facts),
        expected_raw_sha256=args.archive_facts_raw_sha256,
    )
    archive, evidence, trust_context = (
        load_and_verify_late_fee_correction_from_settings(
            settings=Settings(),
            statement_path=_lexical_absolute(args.fee_statement),
            source_document_path=_lexical_absolute(
                args.fee_source_document
            ),
            expected_statement_raw_sha256=args.fee_statement_raw_sha256,
            archive_replay=archive,
        )
    )
    actual = build_actual_simnow_fee_bound_source_facts(
        archive_replay=archive,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=trust_context,
    )
    _write_create_only(
        _lexical_absolute(args.output),
        canonical_json_bytes(actual.model_dump(mode="json")),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
