"""Create a root-pinned C_FAST source view and nine Research artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .c_fast_source_view import (
    build_c_fast_source_view,
    load_execution_open_observation,
    publish_built_c_fast_source_view,
)
from .file_integrity import read_regular_strict
from .m2_operator_state import load_operator_state, operator_state_lock
from .m2_runtime_loader import load_runtime_context
from .pit_source_view import (
    SourcePins,
    _official_month_boundary,
    require_separate_paths,
    verified_daily_raw,
    verified_supplemental_daily_raw,
    verify_root_pins,
)


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
    parser.add_argument("--contract-registry-sha256", required=True)
    parser.add_argument("--execution-open-receipt", type=Path, required=True)
    parser.add_argument("--execution-open-capture", type=Path, required=True)
    parser.add_argument("--execution-open-ticks", type=Path, required=True)
    parser.add_argument("--source-month", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    context = load_runtime_context(args.runtime_input)
    require_separate_paths(
        output_root=args.output.parent,
        context=context,
        protected_inputs=(
            args.runtime_input,
            args.operator_state,
            args.history_receipt,
            args.manifest_public_key,
            args.contract_registry,
            args.execution_open_receipt,
            args.execution_open_capture,
            args.execution_open_ticks,
        ),
    )
    pins = SourcePins(
        history_receipt_raw_sha256=args.history_receipt_sha256,
        operator_state_raw_sha256=args.operator_state_sha256,
        manifest_public_key_raw_sha256=args.manifest_public_key_sha256,
        baseline_public_key_raw_sha256="0" * 64,
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
        research_day, execution_day, _cutoff_day = _official_month_boundary(
            context.calendar,
            source_month=args.source_month,
        )
        daily_raw = verified_daily_raw(
            context=context,
            history=history,
            chain=chain,
            through_day=research_day,
        )
        daily_raw.update(
            verified_supplemental_daily_raw(
                context=context,
                history=history,
                chain=chain,
                source_month=args.source_month,
            )
        )
        execution_source = load_execution_open_observation(
            receipt_path=args.execution_open_receipt,
            capture_path=args.execution_open_capture,
            tick_export_path=args.execution_open_ticks,
            official_day=execution_day,
        )
        contract_registry_raw = read_regular_strict(
            args.contract_registry,
            "C_FAST contract registry",
            limit=1024 * 1024,
        )
        built = build_c_fast_source_view(
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
                "manifest_head_seal_sha256": state.payload["manifest_head_seal_sha256"],
                "manifest_head_commit_seal_sha256": state.payload[
                    "manifest_head_commit_seal_sha256"
                ],
                "commit_anchor_ledger_raw_sha256": state.payload[
                    "commit_anchor_ledger_raw_sha256"
                ],
            },
            daily_source_raw=daily_raw,
            execution_day_source=execution_source,
            contract_registry_raw=contract_registry_raw,
            expected_contract_registry_raw_sha256=(args.contract_registry_sha256),
            source_month=args.source_month,
            observed_at_utc=datetime.now(timezone.utc),
        )
        publish_built_c_fast_source_view(args.output, built)
    print(
        json.dumps(
            {
                "status": "C_FAST_WAREHOUSE_SOURCE_VIEW_CREATED",
                "output": str(args.output),
                "source_month": args.source_month,
                "research_as_of_official_day": research_day.isoformat(),
                "execution_day": execution_day.isoformat(),
                "authority": history["authority"],
            },
            sort_keys=True,
        )
    )
    return 0
