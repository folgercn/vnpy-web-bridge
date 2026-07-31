"""CLI for root-pinned create-only relative-vol PIT source views."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .canonical import parse_json_strict, sha256
from .m2_operator_state import load_operator_state, operator_state_lock
from .m2_runtime_loader import load_runtime_context
from .pit_source_view import (
    SourcePins,
    _official_month_boundary,
    _read_signed_payload,
    build_source_view,
    require_separate_paths,
    validate_business_key,
    verified_daily_raw,
    verified_supplemental_daily_raw,
    verify_root_pins,
)
from .pit_source_view_custody import publish_source_view


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a root-pinned sealed relative-vol PIT source view",
    )
    parser.add_argument("--runtime-input", type=Path, required=True)
    parser.add_argument("--operator-state", type=Path, required=True)
    parser.add_argument("--operator-state-sha256", required=True)
    parser.add_argument("--history-receipt", type=Path, required=True)
    parser.add_argument("--history-receipt-sha256", required=True)
    parser.add_argument("--manifest-public-key", type=Path, required=True)
    parser.add_argument("--manifest-public-key-sha256", required=True)
    parser.add_argument("--business-public-key", type=Path, required=True)
    parser.add_argument("--business-public-key-sha256", required=True)
    parser.add_argument("--business-signer-key-id", required=True)
    parser.add_argument("--baseline-batch", type=Path, required=True)
    parser.add_argument("--previous-snapshot", type=Path)
    parser.add_argument("--source-month", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    pins = SourcePins(
        history_receipt_raw_sha256=args.history_receipt_sha256,
        operator_state_raw_sha256=args.operator_state_sha256,
        manifest_public_key_raw_sha256=args.manifest_public_key_sha256,
        baseline_public_key_raw_sha256=args.business_public_key_sha256,
    )
    context = load_runtime_context(args.runtime_input)
    protected = (
        args.runtime_input,
        args.operator_state,
        args.history_receipt,
        args.manifest_public_key,
        args.business_public_key,
        args.baseline_batch,
        *((args.previous_snapshot,) if args.previous_snapshot is not None else ()),
    )
    require_separate_paths(
        output_root=args.output_root,
        context=context,
        protected_inputs=protected,
    )
    with operator_state_lock(args.operator_state, exclusive=False):
        state = load_operator_state(args.operator_state)
        history, chain = verify_root_pins(
            context=context,
            operator_state=state,
            history_receipt_path=args.history_receipt,
            pins=pins,
            manifest_public_key_path=args.manifest_public_key,
        )
        research_as_of, _execution_day, _cutoff_day = _official_month_boundary(
            context.calendar,
            source_month=args.source_month,
        )
        daily_raw = verified_daily_raw(
            context=context,
            history=history,
            chain=chain,
            through_day=research_as_of,
        )
        daily_raw.update(
            verified_supplemental_daily_raw(
                context=context,
                history=history,
                chain=chain,
                source_month=args.source_month,
            )
        )
        business_key = validate_business_key(
            args.business_public_key,
            expected_raw_sha256=pins.baseline_public_key_raw_sha256,
        )
        baseline = _read_signed_payload(args.baseline_batch, "signed baseline batch")
        previous = (
            _read_signed_payload(args.previous_snapshot, "signed previous snapshot")
            if args.previous_snapshot is not None
            else None
        )
        built = build_source_view(
            calendar=context.calendar,
            calendar_anchor=context.availability,
            history_receipt=history,
            history_receipt_sha256=pins.history_receipt_raw_sha256,
            operator_state=state,
            daily_source_raw=daily_raw,
            baseline_batch=baseline,
            business_public_key=business_key,
            expected_business_signer_key_id=args.business_signer_key_id,
            source_month=args.source_month,
            previous_snapshot=previous,
        )
        output = publish_source_view(
            args.output_root,
            built.source_view_id,
            source_view_raw=built.source_view_raw,
            receipt_raw=built.receipt_raw,
        )
    receipt = parse_json_strict(built.receipt_raw, "published PIT receipt")
    print(
        json.dumps(
            {
                "status": "SEALED_PIT_SOURCE_VIEW_CREATED",
                "output": str(output),
                "source_view_id": built.source_view_id,
                "source_view_raw_sha256": sha256(built.source_view_raw),
                "receipt_id": receipt["receipt_id"],
                "receipt_raw_sha256": sha256(built.receipt_raw),
                "authority": receipt["authority"],
            },
            sort_keys=True,
        )
    )
    return 0
