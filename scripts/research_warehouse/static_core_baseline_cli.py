"""Create a root-pinned historical STATIC_CORE_EQUAL baseline evidence bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .file_integrity import read_regular_strict
from .m2_operator_state import load_operator_state, operator_state_lock
from .m2_runtime_loader import load_runtime_context
from .pit_source_view import (
    SourcePins,
    _official_month_boundary,
    verified_daily_raw,
    verify_root_pins,
)
from .static_core_baseline import build_historical_baseline, publish_built_baseline


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-input", type=Path, required=True)
    parser.add_argument("--operator-state", type=Path, required=True)
    parser.add_argument("--operator-state-sha256", required=True)
    parser.add_argument("--history-receipt", type=Path, required=True)
    parser.add_argument("--history-receipt-sha256", required=True)
    parser.add_argument("--manifest-public-key", type=Path, required=True)
    parser.add_argument("--manifest-public-key-sha256", required=True)
    parser.add_argument("--contract-registry", type=Path, required=True)
    parser.add_argument("--source-month", required=True)
    parser.add_argument("--signer-key-id", required=True)
    parser.add_argument(
        "--execution-lane",
        required=True,
        choices=("official_forward", "simnow_shakedown"),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    context = load_runtime_context(args.runtime_input)
    state = load_operator_state(args.operator_state)
    pins = SourcePins(
        history_receipt_raw_sha256=args.history_receipt_sha256,
        operator_state_raw_sha256=args.operator_state_sha256,
        manifest_public_key_raw_sha256=args.manifest_public_key_sha256,
        baseline_public_key_raw_sha256="0" * 64,
    )
    with operator_state_lock(args.operator_state, exclusive=False):
        history, chain = verify_root_pins(
            context=context,
            operator_state=state,
            history_receipt_path=args.history_receipt,
            pins=pins,
            manifest_public_key_path=args.manifest_public_key,
        )
        _research_day, execution_day, _cutoff_day = _official_month_boundary(
            context.calendar,
            source_month=args.source_month,
        )
        daily_raw = verified_daily_raw(
            context=context,
            history=history,
            chain=chain,
            through_day=execution_day,
        )
        built = build_historical_baseline(
            calendar=context.calendar,
            calendar_anchor_raw_sha256=context.availability.raw_sha256,
            warehouse_registry_raw_sha256=context.registry.raw_sha256,
            history_receipt=history,
            history_receipt_raw_sha256=args.history_receipt_sha256,
            operator_pins={
                "operator_state_raw_sha256": state.raw_sha256,
                "manifest_genesis_seal_sha256": state.payload[
                    "manifest_genesis_seal_sha256"
                ],
                "manifest_head_seal_sha256": state.payload[
                    "manifest_head_seal_sha256"
                ],
                "manifest_head_commit_seal_sha256": state.payload[
                    "manifest_head_commit_seal_sha256"
                ],
                "commit_anchor_ledger_raw_sha256": state.payload[
                    "commit_anchor_ledger_raw_sha256"
                ],
            },
            daily_source_raw=daily_raw,
            contract_registry_raw=read_regular_strict(
                args.contract_registry,
                "static-core contract registry",
                limit=1024 * 1024,
            ),
            source_month=args.source_month,
            signer_key_id=args.signer_key_id,
            execution_lane=args.execution_lane,
        )
        publish_built_baseline(args.output, built)
    print(
        json.dumps(
            {
                "status": "HISTORICAL_STATIC_CORE_BASELINE_EVIDENCE_CREATED",
                "output": str(args.output),
                "authority": history["authority"],
            },
            sort_keys=True,
        )
    )
    return 0
