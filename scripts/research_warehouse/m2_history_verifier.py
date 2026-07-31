"""Final read-only verification for an M2 historical backfill."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from .backup_anchor import verify_backup_anchor
from .backup_custody import BackupPaths
from .canonical import sha256
from .clock_quality import TrustedClockSample
from .commit_anchors import load_commit_anchor_ledger
from .daily_evidence import require_target_product_receipt_coverage
from .derived_paths import DerivedPaths
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .history_backfill_receipts import load_backfill_receipt
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_operator_defaults import release_binding
from .m2_operator_state import OperatorState
from .m2_receipts import load_run_receipt
from .m2_runtime_loader import RuntimeContext
from .quality_gate import evaluate_history_quality
from .quality_contracts import REQUIRED_HISTORY_OFFICIAL_DAYS
from .rebuild import verify_rebuilt_catalog
from .rebuild_binding import load_normalization_binding
from .manifests import verify_manifest_chain


def _next_official_day(context: RuntimeContext, through: date) -> date:
    candidates = sorted(
        day
        for day, item in context.calendar.days.items()
        if item.is_official and day > through
    )
    if not candidates:
        raise RegistryError("history verifier has no following official day")
    return candidates[0]


def verify_history_backfill(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    history_receipt_path: Path,
    expected_history_receipt_raw_sha256: str,
    manifest_public_key_path: Path,
    clock_sample: TrustedClockSample,
) -> dict[str, Any]:
    history = load_backfill_receipt(
        history_receipt_path,
        expected_raw_sha256=expected_history_receipt_raw_sha256,
    )
    if (
        history["registry_raw_sha256"] != context.registry.raw_sha256
        or history["calendar_raw_sha256"] != context.calendar.raw_sha256
        or history["calendar_availability_anchor_raw_sha256"]
        != context.availability.raw_sha256
    ):
        raise RegistryError("history verifier runtime pins diverged")
    through = date.fromisoformat(history["through_trade_day"])
    expected_days = [
        day.isoformat()
        for day in context.calendar.official_days_through(
            through,
            count=REQUIRED_HISTORY_OFFICIAL_DAYS,
        )
    ]
    if (
        history["required_official_days"]
        != REQUIRED_HISTORY_OFFICIAL_DAYS
        or history["official_days"] != expected_days
    ):
        raise RegistryError(
            "history verifier receipt is not the exact 186-day calendar plan"
        )
    for expected in history["daily_receipts"]:
        path = context.runtime.root / expected["run_receipt_relative_path"]
        raw = read_regular_strict(path, "history verifier daily receipt")
        if sha256(raw) != expected["run_receipt_raw_sha256"]:
            raise RegistryError("history verifier daily receipt hash mismatch")
        receipt = load_run_receipt(path)
        verify_daily_run_receipt(
            receipt,
            paths=context.paths,
            registry=context.registry,
            calendar=context.calendar,
            calendar_availability_raw_sha256=context.availability.raw_sha256,
        )
        require_target_product_receipt_coverage(
            paths=context.paths,
            registry=context.registry,
            receipt=receipt,
        )
        if (
            [item["raw_sha256"] for item in receipt["sources"]]
            != expected["source_raw_sha256"]
            or [item["raw_bytes"] for item in receipt["sources"]]
            != expected["source_raw_bytes"]
        ):
            raise RegistryError("history verifier exact source binding mismatch")
    state = operator_state.payload
    ledger = load_commit_anchor_ledger(
        Path(state["commit_anchor_ledger_path"]),
        expected_raw_sha256=state["commit_anchor_ledger_raw_sha256"],
        private=False,
    )
    chain = verify_manifest_chain(
        paths=context.paths,
        public_key_path=manifest_public_key_path,
        registry=context.registry,
        expected_genesis_seal_sha256=state[
            "manifest_genesis_seal_sha256"
        ],
        expected_head_seal_sha256=state["manifest_head_seal_sha256"],
        expected_head_commit_seal_sha256=state[
            "manifest_head_commit_seal_sha256"
        ],
        offline=True,
    )
    ledger.require_chain(chain)
    quality = evaluate_history_quality(
        paths=context.paths,
        registry=context.registry,
        chain=chain,
        ledger=ledger,
        calendar=context.calendar,
        calendar_anchor=context.availability,
        as_of_official_day=through,
        execution_trade_day=_next_official_day(context, through),
        cutoff_at=clock_sample.trusted_now,
        clock_sample=clock_sample,
    )
    if [item["trade_day"] for item in quality["days"]] != expected_days:
        raise RegistryError("history verifier quality days diverged from receipt")
    tool_commit, dependency_lock, dependency_lock_sha = release_binding()
    binding = load_normalization_binding(
        tool_commit_sha=tool_commit,
        dependency_lock_path=dependency_lock,
        expected_dependency_lock_sha256=dependency_lock_sha,
        registry_raw_sha256=context.registry.raw_sha256,
    )
    derived_root = (
        context.runtime.root / "derived" / state["manifest_head_seal_sha256"]
    )
    catalog = verify_rebuilt_catalog(
        evidence=context.paths,
        derived=DerivedPaths.open(derived_root),
        public_key_path=manifest_public_key_path,
        registry=context.registry,
        expected_genesis_seal_sha256=state[
            "manifest_genesis_seal_sha256"
        ],
        expected_head_seal_sha256=state["manifest_head_seal_sha256"],
        expected_head_commit_seal_sha256=state[
            "manifest_head_commit_seal_sha256"
        ],
        ledger=ledger,
        binding=binding,
    )
    backup = verify_backup_anchor(
        paths=BackupPaths.open(Path(context.policy.payload["backup_root"])),
        public_key_path=Path(
            context.runtime_input.payload["backup_public_key_path"]
        ),
        expected_public_key_sha256=context.runtime_input.payload[
            "expected_backup_public_key_sha256"
        ],
        expected_head_anchor_raw_sha256=state[
            "backup_head_anchor_raw_sha256"
        ],
    )
    if (
        backup.sequence != state["backup_sequence"]
        or backup.rebuild.registry_raw_sha256 != context.registry.raw_sha256
        or backup.rebuild.commit_anchor_ledger_sha256
        != state["commit_anchor_ledger_raw_sha256"]
        or backup.rebuild.genesis_batch_seal_sha256
        != state["manifest_genesis_seal_sha256"]
        or backup.rebuild.head_batch_seal_sha256
        != state["manifest_head_seal_sha256"]
        or backup.rebuild.head_commit_seal_sha256
        != state["manifest_head_commit_seal_sha256"]
        or backup.rebuild.tool_commit_sha != tool_commit
        or backup.rebuild.dependency_lock_sha256 != dependency_lock_sha
    ):
        raise RegistryError("history verifier backup/rebuild binding mismatch")
    return {
        "status": "M2_RESEARCH_HISTORY_BACKFILL_VERIFIED",
        "history_receipt_id": history["receipt_id"],
        "history_receipt_raw_sha256": expected_history_receipt_raw_sha256,
        "covered_official_days": history["required_official_days"],
        "first_trade_day": history["official_days"][0],
        "through_trade_day": history["official_days"][-1],
        "products": quality["products"],
        "product_day_counts": quality["product_day_counts"],
        "quality_status": quality["status"],
        "source_commit_sha": tool_commit,
        "dependency_lock_sha256": dependency_lock_sha,
        "registry_raw_sha256": context.registry.raw_sha256,
        "calendar_raw_sha256": context.calendar.raw_sha256,
        "calendar_availability_anchor_raw_sha256": (
            context.availability.raw_sha256
        ),
        "operator_state_raw_sha256": operator_state.raw_sha256,
        "manifest_sequence": state["manifest_sequence"],
        "manifest_genesis_seal_sha256": state[
            "manifest_genesis_seal_sha256"
        ],
        "manifest_head_seal_sha256": state["manifest_head_seal_sha256"],
        "manifest_head_commit_seal_sha256": state[
            "manifest_head_commit_seal_sha256"
        ],
        "commit_anchor_ledger_raw_sha256": state[
            "commit_anchor_ledger_raw_sha256"
        ],
        "catalog_sha256": catalog["catalog_sha256"],
        "backup_sequence": backup.sequence,
        "backup_head_anchor_raw_sha256": backup.raw_sha256,
    }
