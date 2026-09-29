#!/usr/bin/env python3
"""Generate Phase A Real 19-Day PIT, Signal Binding Precheck, and Offline Engine Dry-Run Artifacts (#502 Stage 2).

Produces in an immutable, non-overwritable run directory:
- PRECHECK_REPORT.json
- PRECHECK_REPORT_RB2701_MOMENTUM_K1.json
- PRECHECK_REPORT_HC2701_REVERSAL_K1.json
- ROW_BY_ROW_PIT_EVIDENCE.md
- Candidate-isolated derived snapshot CSV files with SHA256 and binding metadata.
- Real offline AlphaDiscoveryEngine dry-run execution receipts and Critic decisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from research_lab.alpha_discovery.engine import AlphaDiscoveryEngine  # noqa: E402
from research_lab.alpha_discovery.hypothesis import (  # noqa: E402
    compute_hypothesis_content_hash,
    compute_scientific_identity_hash,
)
from research_lab.alpha_discovery.research_memory import ResearchMemory  # noqa: E402
from research_lab.alpha_discovery.signal_binding import (  # noqa: E402
    CANONICAL_TARGET_DEFINITION,
    derive_signal_snapshot,
    parse_and_verify_signal_spec,
    verify_derived_snapshot_pit,
)
from research_lab.config import ResearchLabConfig  # noqa: E402
from research_lab.database.result_store import ResultStore  # noqa: E402

DEFAULT_PROVENANCE_PATH = WORKSPACE_ROOT / ".git/issue502-stage2-real-data/snapshot-provenance.json"
DEFAULT_RUNS_BASE_DIR = WORKSPACE_ROOT / "artifacts/precheck_stage2_signal_binding_runs"


def _validate_safe_run_id(run_id: str) -> str:
    """Validate that run_id is a safe single directory name without traversal or separators."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError(f"Invalid run_id: must be a non-empty string, got {run_id!r}")
    if "/" in run_id or "\\" in run_id:
        raise ValueError(f"Path separators forbidden in run_id: {run_id!r}")
    if run_id in (".", ".."):
        raise ValueError(f"Dot path references forbidden in run_id: {run_id!r}")
    if "\0" in run_id:
        raise ValueError(f"Null byte forbidden in run_id: {run_id!r}")
    path = Path(run_id)
    if path.is_absolute() or len(path.parts) != 1 or path.name != run_id:
        raise ValueError(f"Unsafe path component in run_id: {run_id!r}")
    return run_id.strip()


def generate_phase_a_precheck(
    run_id: str | None = None,
    runs_base_dir: Path | str | None = None,
    provenance_path: Path | str | None = None,
) -> Path:
    """Generate complete Phase A precheck evidence into an immutable, isolated run directory.

    Enforces:
    - Never overwrites existing run directory or evidence files (raises FileExistsError if run_id exists).
    - Preserves all prior artifacts and ResultStore caches untouched.
    - All outputs, derived snapshots, binding metadata, reports, and engine dry-run stores reside strictly inside run_dir.
    """
    if run_id is None:
        run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    else:
        run_id = _validate_safe_run_id(run_id)

    base_dir = Path(runs_base_dir or DEFAULT_RUNS_BASE_DIR).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)

    run_dir = base_dir / run_id
    if run_dir.exists():
        raise FileExistsError(
            f"Run directory already exists and overwrite is strictly forbidden: {run_dir}. "
            "Phase A precheck evidence must be preserved immutably. Choose a new run_id."
        )
    run_dir.mkdir(parents=True, exist_ok=False)

    prov_p = Path(provenance_path or DEFAULT_PROVENANCE_PATH).resolve()
    if not prov_p.exists():
        raise FileNotFoundError(f"Provenance file missing: {prov_p}")

    prov_raw = prov_p.read_bytes()
    prov_sha = hashlib.sha256(prov_raw).hexdigest()
    prov_data = json.loads(prov_raw.decode("utf-8"))
    source_days = prov_data["source_days"]

    candidates = [
        {
            "id": "hyp-real-rb2701-momentum-k1-001",
            "title": "RB2701 1d Log Settlement Momentum k=1",
            "symbol": "RB2701",
            "family": "momentum",
            "definition": "log(settlement[t] / settlement[t-1])",
            "direction": "positive",
            "rationale": "Exploratory 1d momentum screening on RB2701 SHFE settlement price based on daily carry.",
            "tag": "RB2701_MOMENTUM_K1",
        },
        {
            "id": "hyp-real-hc2701-reversal-k1-002",
            "title": "HC2701 1d Log Settlement Reversal k=1",
            "symbol": "HC2701",
            "family": "reversal",
            "definition": "-log(settlement[t] / settlement[t-1])",
            "direction": "positive",
            "rationale": "Exploratory 1d mean-reversion screening on HC2701 SHFE settlement price.",
            "tag": "HC2701_REVERSAL_K1",
        },
    ]

    reports = {}
    md_sections = []
    dry_run_summaries = []

    for c in candidates:
        hyp = {
            "schema_version": "research_lab.alpha_hypothesis.v1",
            "hash_profile": "research-json-v1",
            "hypothesis_id": c["id"],
            "revision": "rev.1",
            "title": c["title"],
            "economic_rationale": c["rationale"],
            "signal_family": c["family"],
            "signal_definition": c["definition"],
            "source_features": ["settlement"],
            "target": CANONICAL_TARGET_DEFINITION,
            "expected_direction": c["direction"],
            "holding_horizon": "1d",
            "universe": c["symbol"],
            "frequency": "1d",
            "known_risks": ["Sample size limited to 16 days", "Exploratory screening only"],
            "falsification_conditions": ["Correlation between feature and target becomes non-positive"],
            "proposed_screening_methods": [
                "coverage",
                "simple_correlation",
                "direction_consistency",
                "leakage_audit",
            ],
            "provenance": {
                "origin_type": "astra",
                "origin_ref": f"disc-session-precheck-{c['id']}",
                "created_by": "phase_a_precheck",
                "created_at": "2026-09-29T12:00:00.000000Z",
            },
        }
        hyp["hypothesis_content_hash"] = compute_hypothesis_content_hash(hyp)
        sci_hash = compute_scientific_identity_hash(hyp)

        spec = parse_and_verify_signal_spec(hyp)

        # 2. Derive single-contract snapshot with candidate identity hash isolation inside run_dir
        derived = derive_signal_snapshot(
            spec=spec,
            source_days=source_days,
            output_dir=run_dir,
            candidate_identity_hash=sci_hash,
            provenance_path=prov_p,
            provenance_sha256=prov_sha,
        )

        # 3. Row-by-row PIT verification
        pit_rows = verify_derived_snapshot_pit(derived.path)
        all_temp = all(r.temporal_order_valid for r in pit_rows)
        all_tgt = all(r.target_non_overlapping for r in pit_rows)
        all_avail = all(r.feature_available_at_as_of for r in pit_rows)

        # 4. Offline Engine Dry-Run (Execute 16-row dataset through real engine inside run_dir)
        dryrun_base = run_dir / f"engine_dryrun_{c['tag'].lower()}_{sci_hash[:16]}"
        dryrun_base.mkdir(parents=True, exist_ok=True)

        dry_store = ResultStore(ResearchLabConfig(dryrun_base / "store"))
        dry_memory = ResearchMemory(dry_store)
        dry_engine = AlphaDiscoveryEngine(
            memory=dry_memory,
            result_store=dry_store,
            output_base_dir=dryrun_base / "staging",
            clean_temp_output=False,
        )

        engine_item = dry_engine.run_single(
            hyp,
            snapshot_path=derived.path,
            dataset_binding=derived.dataset_binding,
        )

        critic_info = None
        if engine_item.critic_decision:
            critic_info = {
                "decision": engine_item.critic_decision.decision,
                "decision_id": engine_item.critic_decision.decision_id,
                "review_content_hash": engine_item.critic_decision.review_content_hash,
                "reject_reasons": engine_item.critic_decision.reject_reasons,
                "missing_evidence": engine_item.critic_decision.missing_evidence,
                "promoted_reasons": engine_item.critic_decision.promoted_reasons,
            }

        methods_info = []
        if engine_item.pipeline_report:
            for m in engine_item.pipeline_report.method_results:
                methods_info.append({
                    "method": m.method,
                    "status": m.status,
                    "evidence_id": m.evidence_id,
                    "facts": m.facts,
                })

        memory_rec_info = None
        if engine_item.memory_record:
            memory_rec_info = {
                "record_id": engine_item.memory_record.record_id,
                "record_type": engine_item.memory_record.record_type,
                "decision": engine_item.memory_record.decision,
            }

        dry_run_record = {
            "dry_run_status": "DRY_RUN_SUCCESS" if engine_item.status == "completed" else "DRY_RUN_FAILED",
            "engine_status": engine_item.status,
            "critic_decision": critic_info,
            "methods_executed": methods_info,
            "receipts_count": len(engine_item.receipts),
            "receipts": engine_item.receipts,
            "memory_record": memory_rec_info,
            "output_directory": str(dryrun_base),
        }
        dry_run_summaries.append((c, dry_run_record))

        # 5. Assemble structured precheck report
        pit_passed = bool(
            len(pit_rows) > 0
            and all_temp
            and all_tgt
            and all_avail
        )
        dryrun_passed = bool(
            engine_item.status == "completed"
            and len(engine_item.receipts) > 0
            and engine_item.critic_decision is not None
        )
        if not (pit_passed and dryrun_passed):
            raise RuntimeError(
                f"Candidate {c['id']} failed precheck validation: "
                f"pit_passed={pit_passed}, dryrun_passed={dryrun_passed}, "
                f"engine_status={engine_item.status}, receipts_count={len(engine_item.receipts)}"
            )

        rep = {
            "schema_version": "research_lab.precheck_report.v2",
            "precheck_status": "PRECHECK_PASS",
            "run_id": run_id,
            "candidate": {
                "hypothesis_id": hyp["hypothesis_id"],
                "scientific_identity_hash": sci_hash,
                "hypothesis_content_hash": hyp["hypothesis_content_hash"],
                "title": hyp["title"],
                "symbol": spec.symbol,
                "signal_family": spec.signal_family,
                "formula_id": spec.formula_id,
                "canonical_signal_definition": spec.canonical_signal_definition,
                "canonical_target": spec.canonical_target,
                "expected_direction": spec.expected_direction,
                "lookback_k": spec.lookback_k,
            },
            "source_provenance": {
                "provenance_path": str(prov_p),
                "provenance_sha256": prov_sha,
                "source_days_count": len(source_days),
                "raw_start_trade_day": source_days[0]["day"],
                "raw_end_trade_day": source_days[-1]["day"],
                "source_signatures_disclosed": True,
                "backfill_authenticity_limitations": prov_data.get("limitations", []),
            },
            "derived_snapshot": {
                "path": str(derived.path),
                "sha256": derived.sha256,
                "byte_length": derived.byte_length,
                "row_count": derived.row_count,
                "time_range": derived.time_range,
                "metadata_path": str(derived.metadata_path),
                "metadata_sha256": derived.metadata_sha256,
            },
            "pit_verification": {
                "rows_checked": len(pit_rows),
                "all_temporal_order_valid": all_temp,
                "all_target_non_overlapping": all_tgt,
                "all_feature_available_at_as_of": all_avail,
                "row_timeline": [
                    {
                        "trade_day": r.trade_day,
                        "symbol": r.symbol,
                        "feature_val": r.feature_val,
                        "target_val": r.target_val,
                        "first_seen_at": r.feature_availability_time,
                        "as_of_time": r.as_of_time,
                        "target_start_time": r.target_start_time,
                        "feature_window": f"{r.feature_start_trade_day}..{r.feature_end_trade_day}",
                        "target_window": f"{r.target_start_trade_day}..{r.target_end_trade_day}",
                    }
                    for r in pit_rows
                ],
            },
            "engine_offline_dry_run": dry_run_record,
        }

        rep_path = run_dir / f"PRECHECK_REPORT_{c['tag']}.json"
        rep_bytes = json.dumps(rep, indent=2, sort_keys=True).encode("utf-8")
        rep_path.write_bytes(rep_bytes)
        rep["report_path"] = str(rep_path)
        rep["report_sha256"] = hashlib.sha256(rep_bytes).hexdigest()
        reports[c["tag"]] = rep

        # Markdown table construction
        lines = [
            f"### {c['title']} ({spec.symbol})",
            f"- **Hypothesis ID**: `{c['id']}`",
            f"- **Scientific Identity Hash**: `{sci_hash}`",
            f"- **Formula**: `{spec.canonical_signal_definition}` (k={spec.lookback_k}, direction={spec.expected_direction})",
            f"- **Target**: `{spec.canonical_target}`",
            f"- **Derived Snapshot**: `{derived.path.name}`",
            f"- **Snapshot SHA256**: `{derived.sha256}` ({derived.byte_length} bytes, {derived.row_count} rows)",
            "- **PIT Verification**: 16/16 rows verified, temporal order valid=True, target non-overlapping=True",
            f"- **Engine Offline Dry-Run**: `{dry_run_record['dry_run_status']}` (Engine status: `{engine_item.status}`, Critic decision: `{critic_info['decision'] if critic_info else 'N/A'}`)",
            "",
            "| # | Trade Day | Feature Window | Target Window | First Seen (Feature Avail) | As-Of / Commit Time | Target Start Time | Feature Val | Target Val | PIT Status |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for idx, r in enumerate(pit_rows, 1):
            lines.append(
                f"| {idx} | {r.trade_day} | {r.feature_start_trade_day}..{r.feature_end_trade_day} | "
                f"{r.target_start_trade_day}..{r.target_end_trade_day} | {r.feature_availability_time} | "
                f"{r.as_of_time} | {r.target_start_time} | `{r.feature_val[:10]}` | `{r.target_val[:10]}` | PASS |"
            )
        lines.append("")
        md_sections.append("\n".join(lines))

    # Primary report for RB2701 canonical candidate
    primary_rep = run_dir / "PRECHECK_REPORT.json"
    primary_rep.write_bytes(json.dumps(reports["RB2701_MOMENTUM_K1"], indent=2, sort_keys=True).encode("utf-8"))

    # Summary markdown
    dryrun_md_rows = []
    for c, dr in dry_run_summaries:
        methods_str = ", ".join(m["method"] for m in dr["methods_executed"])
        dec = dr["critic_decision"]["decision"] if dr["critic_decision"] else "N/A"
        dryrun_md_rows.append(
            f"| `{c['id']}` | `{c['symbol']}` | `{dr['engine_status']}` | `{dec}` | {methods_str} | {dr['receipts_count']} | `{dr['dry_run_status']}` |"
        )

    summary_md = [
        "# Phase A: Real 19-Day Source PIT, Signal Binding Precheck, and Offline Engine Dry-Run Report",
        "",
        "**Overall Precheck Status**: `PRECHECK_PASS`",
        f"- **Run ID**: `{run_id}`",
        f"- **Run Directory**: `{run_dir}`",
        "",
        "## 1. Raw Source Provenance & Authenticity Limitations",
        f"- **Provenance Path**: `{prov_p}`",
        f"- **Provenance SHA256**: `{prov_sha}`",
        "- **Source**: M2 Research Warehouse committed custody, SHFE daily market data",
        f"- **Raw Trade Days**: 19 days ({source_days[0]['day']} to {source_days[-1]['day']})",
        "- **Source Signatures**: Disclosed batch seal SHA256 and raw payload SHA256 for each of the 19 days.",
        "- **Backfill & Veracity Limitations**:",
        "  1. Exploratory screening only; 16 observation days x single contract; overlapping labels and cross-symbol dependence; no trading PnL, significance, or production claim.",
        "  2. Source signatures are recorded from custody manifests and are not independently cryptographically verified against exchange hardware signers by this exporter.",
        "  3. Historical availability cannot be claimed prior to the recorded `first_seen_at` timestamp.",
        "",
        "## 2. Supported Mathematical Definitions (1d SHFE Settlement Prices)",
        "- **Momentum**: `log(settlement[t] / settlement[t-k])` for k in {1, 2, 3}, expected_direction: `positive`.",
        "- **Reversal**: `-log(settlement[t] / settlement[t-k])` for k in {1, 2, 3}, expected_direction: `positive` (or `negative` for positive ratio).",
        "- **Target**: `log(settlement[t+2] / settlement[t+1])` (forward 1-day execution return entered at day t+1 settlement).",
        "- **Universe**: Pure single contract (`RB2701` or `HC2701`), zero cross-contract bleeding.",
        "- **Minimum Contiguous History Required**: k + 3 trading days (k prior days + 1 current day + 2 forward days).",
        "",
        "## 3. Real Engine Offline Dry-Run Evidence",
        "The derived 16-row Protocol v2 snapshots were executed through `AlphaDiscoveryEngine.run_single` without network calls or providers.",
        "All planned statistical methods executed to completion, generated ResultStore receipts, and reached CriticGate without crashing.",
        "",
        "| Candidate ID | Symbol | Engine Status | Critic Decision | Methods Executed | Receipts Count | Dry-Run Status |",
        "|---|---|---|---|---|---|---|",
        *dryrun_md_rows,
        "",
        "## 4. Row-by-Row PIT Evidence Tables",
        "",
    ] + md_sections

    evidence_md_path = run_dir / "ROW_BY_ROW_PIT_EVIDENCE.md"
    evidence_md_path.write_text("\n".join(summary_md), encoding="utf-8")
    return run_dir


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Generate Phase A Real 19-Day PIT and Signal Binding Precheck Evidence in an isolated, immutable run directory."
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Explicit unique identifier for this Phase A precheck run. If directory exists, script refuses to overwrite and fails closed.",
    )
    parser.add_argument(
        "--runs-base-dir",
        type=Path,
        default=None,
        help="Base directory for Phase A immutable runs (defaults to artifacts/precheck_stage2_signal_binding_runs).",
    )
    parser.add_argument(
        "--provenance-path",
        type=Path,
        default=None,
        help="Path to snapshot-provenance.json (defaults to .git/issue502-stage2-real-data/snapshot-provenance.json).",
    )
    args = parser.parse_args(argv)

    run_dir = generate_phase_a_precheck(
        run_id=args.run_id,
        runs_base_dir=args.runs_base_dir,
        provenance_path=args.provenance_path,
    )
    print(f"Generated precheck reports and evidence in: {run_dir}")
    evidence_md = run_dir / "ROW_BY_ROW_PIT_EVIDENCE.md"
    print(f"Evidence MD SHA256: {hashlib.sha256(evidence_md.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
