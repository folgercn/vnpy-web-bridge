"""Offline, create-only #502 manual real-source PIT/Engine pilot (no Provider or trading)."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research_lab.agent_control.contracts import ProjectBinding
from research_lab.agent_control.discovery_integration import DiscoveryIntegrationOrchestrator
from research_lab.alpha_discovery import (
    AlphaDiscoveryEngine,
    AlphaHypothesis,
    CriticGate,
    ResearchMemory,
    ScreeningPipeline,
    ScreeningPlanner,
    compute_hypothesis_content_hash,
)
from research_lab.alpha_discovery.signal_binding import (
    CANONICAL_TARGET_DEFINITION,
    precheck_candidate_real_data,
)
from research_lab.config import ResearchLabConfig
from research_lab.database import ResultStore

EXPECTED_PROVENANCE_SHA256 = "e3d6b6b74d8b6617455bcccf7d6eeed3e4f5fbfe8eca1216f40ad03006725354"
CANDIDATES = (
    ("human-momentum-k1-rb", "RB2701", "momentum", "log(settlement[t] / settlement[t-1])", 1, "rb_f"),
    ("human-reversal-k2-hc", "HC2701", "reversal", "-log(settlement[t] / settlement[t-2])", 2, "hc_f"),
)


def _candidate(label: str, symbol: str, family: str, formula: str) -> dict:
    hypothesis = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": label,
        "revision": "rev.1",
        "title": f"Manual PIT precheck {label}",
        "economic_rationale": "Manual deterministic settlement binding pilot; no predictive claim.",
        "signal_family": family,
        "signal_definition": formula,
        "source_features": ["settlement"],
        "target": CANONICAL_TARGET_DEFINITION,
        "expected_direction": "positive",
        "holding_horizon": "1d",
        "universe": symbol,
        "frequency": "1d",
        "known_risks": ["small sample", "overlapping labels"],
        "falsification_conditions": ["direction consistency fails"],
        "proposed_screening_methods": ["coverage", "simple_correlation", "direction_consistency", "leakage_audit"],
        "provenance": {
            "origin_type": "human",
            "origin_ref": "issue-502-manual-pit-precheck",
            "created_by": "Codex manual precheck",
            "created_at": "2026-09-30T03:45:00.000000Z",
        },
    }
    hypothesis["hypothesis_content_hash"] = compute_hypothesis_content_hash(hypothesis)
    return hypothesis


def _audit_rows(snapshot: Path, evidence: dict, product: str, lookback: int, reversal: bool) -> list[dict]:
    days = evidence["days"]
    results = []
    with snapshot.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            start = days[row["feature_start_trade_day"]]
            end = days[row["feature_end_trade_day"]]
            target_start = days[row["target_start_trade_day"]]
            target_end = days[row["target_end_trade_day"]]
            feature = math.log(end["settlement"][product] / start["settlement"][product])
            if reversal:
                feature = -feature
            target = math.log(target_end["settlement"][product] / target_start["settlement"][product])
            if format(feature, ".17g") != row["feature_val"] or format(target, ".17g") != row["target_val"]:
                raise ValueError("independent feature/target recomputation failed")
            if row["target_start_time"] != target_start["settlement_not_before"] or row["as_of_time"] >= row["target_start_time"]:
                raise ValueError("independent target lower-bound check failed")
            results.append({
                "as_of_trade_day": row["feature_end_trade_day"],
                "symbol": row["symbol"],
                "lookback_k": lookback,
                "feature_input_days": [row["feature_start_trade_day"], row["feature_end_trade_day"]],
                "feature_input_prices": [start["settlement"][product], end["settlement"][product]],
                "feature_input_raw_sha256": [start["raw_sha256"], end["raw_sha256"]],
                "feature_input_first_seen_at": [start["first_seen_at"], end["first_seen_at"]],
                "feature_input_committed_at": [start["committed_at"], end["committed_at"]],
                "as_of_time": row["as_of_time"],
                "target_days": [row["target_start_trade_day"], row["target_end_trade_day"]],
                "target_prices": [target_start["settlement"][product], target_end["settlement"][product]],
                "target_raw_sha256": [target_start["raw_sha256"], target_end["raw_sha256"]],
                "target_not_before": [target_start["settlement_not_before"], target_end["settlement_not_before"]],
                "time_rule_sha256": target_start["rule_sha256"],
                "calendar_sha256": target_start["calendar_sha256"],
                "feature_val": row["feature_val"],
                "target_val": row["target_val"],
            })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--official-rules-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    provenance = args.provenance.resolve()
    if hashlib.sha256(provenance.read_bytes()).hexdigest() != EXPECTED_PROVENANCE_SHA256:
        raise ValueError("the reviewed pilot provenance SHA256 changed")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binding = ProjectBinding(project_id="vnpy-502-manual-precheck", workspace_identity="/Users/fujun/node/vnpy-web-bridge")
    summary = {"schema": "issue502.manual-real-source-pit-precheck.v1", "scope": "manual pilot; not Provider Round 1 or trading", "candidates": []}
    for label, symbol, family, formula, lookback, product in CANDIDATES:
        area = output / label
        area.mkdir()
        hypothesis = _candidate(label, symbol, family, formula)
        (area / "hypothesis.json").write_text(json.dumps(hypothesis, sort_keys=True, indent=2), encoding="utf-8")
        precheck = precheck_candidate_real_data(
            hypothesis, provenance, area / "precheck",
            provenance_sha256=EXPECTED_PROVENANCE_SHA256,
            real_source_bundle_root=args.bundle_root,
            official_rules_root=args.official_rules_root,
        )
        rows = _audit_rows(Path(precheck["derived_snapshot"]["path"]), precheck["real_source_evidence"], product, lookback, family == "reversal")
        store = ResultStore(ResearchLabConfig(area / "store"))
        memory = ResearchMemory(store)
        engine = AlphaDiscoveryEngine(
            memory=memory, planner=ScreeningPlanner(), critic=CriticGate(),
            result_store=store, pipeline=ScreeningPipeline(),
            output_base_dir=area / "engine", clean_temp_output=False,
        )
        result = DiscoveryIntegrationOrchestrator(engine, allow_synthetic_passthrough=False).integrate_candidate(
            AlphaHypothesis.model_validate(hypothesis), snapshot_path=Path(precheck["derived_snapshot"]["path"]),
            dataset_binding={
                "provenance_path": str(provenance),
                "provenance_sha256": EXPECTED_PROVENANCE_SHA256,
                "real_source_bundle_root": str(args.bundle_root.resolve()),
                "official_rules_root": str(args.official_rules_root.resolve()),
            },
            project_binding=binding, expected_binding=binding, auto_supplemental=False,
        )
        if result.engineering_status != "COMPLETED":
            raise RuntimeError(f"{label}: Engine did not complete: {result.error_code} {result.error_message}")
        engine_csv = next((area / "engine/derived_snapshots").glob("*.csv"))
        engine_sha = hashlib.sha256(engine_csv.read_bytes()).hexdigest()
        if engine_sha != precheck["derived_snapshot"]["sha256"]:
            raise ValueError(f"{label}: Engine snapshot differs from precheck")
        receipt_count = 0
        for ref in result.run_refs:
            receipt_count += len(store.query_v2_runs(run_id=ref["run_id"], verify=True))
        if receipt_count != len(result.run_refs) or len(memory.find_by_hypothesis_id(label)) != 1:
            raise ValueError(f"{label}: verified ResultStore/Memory reread mismatch")
        summary["candidates"].append({
            "label": label, "origin_type": "human", "hypothesis_content_hash": hypothesis["hypothesis_content_hash"],
            "symbol": symbol, "formula": formula, "target": CANONICAL_TARGET_DEFINITION,
            "source_day_count": len(precheck["real_source_evidence"]["days"]),
            "warmup_days": lookback, "target_tail_days": 2, "effective_rows": len(rows),
            "snapshot_sha256": engine_sha, "snapshot_bytes": engine_csv.stat().st_size,
            "engineering_status": result.engineering_status, "scientific_decision": result.scientific_decision,
            "verified_resultstore_receipts": receipt_count, "run_refs": result.run_refs,
            "rows": rows,
        })
    (output / "manual-precheck-summary.json").write_text(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
    print(json.dumps({"candidates": [{k: c[k] for k in ("label", "effective_rows", "engineering_status", "scientific_decision", "verified_resultstore_receipts")} for c in summary["candidates"]]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
