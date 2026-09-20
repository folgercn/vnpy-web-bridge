"""Comprehensive End-to-End Acceptance Tests for Alpha Discovery MVP (#562, #565, #566).

Covers all 25 Final Acceptance criteria from Section 30:
- Case A: controlled synthetic hypothesis with complete evidence triggering falsification -> REJECT
- Case B: initial screening produces NEED_MORE_EVIDENCE -> supplemental screening runs only missing methods -> PROMOTE
- Case C: initial screening NME -> supplemental reveals leakage/cost violation -> REJECT
- Case D: engineering / execution failure -> NEED_MORE_EVIDENCE / honest failure record, NEVER scientific REJECT
- Case E: Memory skip semantics: NME + new methods MUST execute; exact same plan/coverage MAY skip
- Case F: deleting staging directory completely retains 100% resolvable research chain via ResultStore and Memory refs
- Critic mandatory dimensions cannot be reduced (fail-closed)
- Review content hash sealing and tamper detection
- Evidence facts purity (zero score/rank/promote/reject)
"""

from __future__ import annotations

import csv
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from research_lab.alpha_discovery import (
    AlphaDiscoveryEngine,
    AlphaHypothesis,
    CriticGate,
    ResearchMemory,
    ScreeningPipeline,
    ScreeningPlanner,
    compute_hypothesis_content_hash,
    validate_critic_decision,
    validate_hypothesis,
)
from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.database import ResultStore
from research_lab.runners.v2_statistical_screening import run_statistical_screening


def _create_synthetic_csv(
    file_path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> tuple[str, int]:
    """Helper to write CSV and return its canonical sha256 and byte length."""
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    raw = file_path.read_bytes()
    return v2.sha(raw), len(raw)


@pytest.fixture
def test_env(tmp_path: Path):
    """Sets up an isolated ResultStore, ResearchMemory, and synthetic dataset fixtures."""
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    planner = ScreeningPlanner()
    critic = CriticGate()
    pipeline = ScreeningPipeline(planner=planner)
    staging_dir = tmp_path / "staging"

    engine = AlphaDiscoveryEngine(
        memory=memory,
        planner=planner,
        critic=critic,
        result_store=store,
        pipeline=pipeline,
        output_base_dir=staging_dir,
        clean_temp_output=False,  # Keep staging for chain inspection before explicit deletion test
    )

    # 1. Clean comprehensive fixture with temporal metadata
    clean_csv = tmp_path / "clean_data.csv"
    clean_rows = []
    for i in range(1, 41):
        ts = f"2026-01-01T{i:02d}:00:00.000000Z"
        avail = f"2026-01-01T{i:02d}:00:00.000000Z"
        as_of = f"2026-01-01T{i:02d}:00:01.000000Z"
        tgt_start = f"2026-01-01T{i:02d}:00:02.000000Z"
        fv = float(i)
        tv = float(i) * 1.5 + 0.1  # Strong positive correlation
        clean_rows.append({
            "timestamp": ts,
            "symbol": "RB2405",
            "feature_val": str(fv),
            "target_val": str(tv),
            "feature_availability_time": avail,
            "as_of_time": as_of,
            "target_start_time": tgt_start,
        })
    fields_clean = ["timestamp", "symbol", "feature_val", "target_val", "feature_availability_time", "as_of_time", "target_start_time"]
    c_sha, c_len = _create_synthetic_csv(clean_csv, clean_rows, fields_clean)
    clean_binding = {
        "snapshot_locator": str(clean_csv),
        "snapshot_sha256": c_sha,
        "snapshot_byte_length": c_len,
        "required_fields": fields_clean,
        "available_fields": fields_clean,
        "provenance": "synthetic_clean_audit",
    }

    # 2. Falsified fixture (negative correlation for positive hypothesis)
    falsified_csv = tmp_path / "falsified_data.csv"
    falsified_rows = []
    for i in range(1, 41):
        ts = f"2026-01-01T{i:02d}:00:00.000000Z"
        avail = f"2026-01-01T{i:02d}:00:00.000000Z"
        as_of = f"2026-01-01T{i:02d}:00:01.000000Z"
        tgt_start = f"2026-01-01T{i:02d}:00:02.000000Z"
        fv = float(i)
        tv = -float(i) * 2.0  # Directly contradicts positive direction
        falsified_rows.append({
            "timestamp": ts,
            "symbol": "RB2405",
            "feature_val": str(fv),
            "target_val": str(tv),
            "feature_availability_time": avail,
            "as_of_time": as_of,
            "target_start_time": tgt_start,
        })
    f_sha, f_len = _create_synthetic_csv(falsified_csv, falsified_rows, fields_clean)
    falsified_binding = {
        "snapshot_locator": str(falsified_csv),
        "snapshot_sha256": f_sha,
        "snapshot_byte_length": f_len,
        "required_fields": fields_clean,
        "available_fields": fields_clean,
        "provenance": "synthetic_falsified_fixture",
    }

    # 3. Leakage violation fixture (availability after as_of time)
    leakage_csv = tmp_path / "leakage_violation.csv"
    leakage_rows = []
    for i in range(1, 41):
        ts = f"2026-01-01T{i:02d}:00:00.000000Z"
        # VIOLATION: feature available AFTER as_of decision time
        avail = f"2026-01-01T{i:02d}:05:00.000000Z"
        as_of = f"2026-01-01T{i:02d}:00:00.000000Z"
        tgt_start = f"2026-01-01T{i:02d}:10:00.000000Z"
        fv = float(i)
        tv = float(i)
        leakage_rows.append({
            "timestamp": ts,
            "symbol": "RB2405",
            "feature_val": str(fv),
            "target_val": str(tv),
            "feature_availability_time": avail,
            "as_of_time": as_of,
            "target_start_time": tgt_start,
        })
    l_sha, l_len = _create_synthetic_csv(leakage_csv, leakage_rows, fields_clean)
    leakage_binding = {
        "snapshot_locator": str(leakage_csv),
        "snapshot_sha256": l_sha,
        "snapshot_byte_length": l_len,
        "required_fields": fields_clean,
        "available_fields": fields_clean,
        "provenance": "synthetic_leakage_violation",
    }

    return {
        "store": store,
        "memory": memory,
        "engine": engine,
        "planner": planner,
        "critic": critic,
        "clean_csv": clean_csv,
        "clean_binding": clean_binding,
        "falsified_csv": falsified_csv,
        "falsified_binding": falsified_binding,
        "leakage_csv": leakage_csv,
        "leakage_binding": leakage_binding,
        "staging_dir": staging_dir,
    }


def _make_hypothesis(
    hyp_id: str = "hypo-momentum-rb",
    revision: str = "rev.1",
    direction: str = "positive",
    methods: list[str] | None = None,
    falsification: list[str] | None = None,
    signal_def: str | None = None,
    signal_type: str | None = None,
    source_features: list[str] | None = None,
) -> dict[str, Any]:
    """Helper to generate valid AlphaHypothesis dict."""
    methods_list = methods or ["coverage", "simple_correlation", "direction_consistency", "stability_split"]
    falsif = falsification or ["ic < 0.05", "negative_ic"]

    if signal_def is not None:
        effective_sig_def = signal_def
        effective_src = source_features or ["feature_val"]
    elif "cost_sensitivity" in methods_list:
        effective_sig_def = "feature_val"
        effective_src = source_features or ["feature_val"]
    else:
        effective_sig_def = "rolling_mean(close, 5) - close"
        effective_src = source_features or ["close"]

    raw: dict[str, Any] = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": hyp_id,
        "revision": revision,
        "title": f"Momentum Factor on RB for {hyp_id}",
        "economic_rationale": "Informed trader flow causes short-term price continuation in commodity futures.",
        "signal_family": "momentum",
        "signal_definition": effective_sig_def,
        "source_features": effective_src,
        "target": "future_return_1h",
        "expected_direction": direction,
        "holding_horizon": "1h",
        "universe": "commodity_active",
        "frequency": "1h",
        "known_risks": ["whipsaw in choppy market"],
        "falsification_conditions": falsif,
        "proposed_screening_methods": methods_list,
        "provenance": {
            "origin_type": "human",
            "origin_ref": "researcher_notebook_01",
            "created_by": "quantitative_researcher",
            "created_at": "2026-09-20T00:00:00.000000Z",
        },
    }
    if signal_type:
        raw["signal_type"] = signal_type
    raw["hypothesis_content_hash"] = compute_hypothesis_content_hash(raw)
    return validate_hypothesis(raw)


def test_case_a_controlled_falsification_reject(test_env):
    """Case A: Complete evidence triggers falsification conditions -> REJECT."""
    engine = test_env["engine"]
    falsified_binding = test_env["falsified_binding"]
    falsified_csv = test_env["falsified_csv"]

    # All methods including leakage, outlier, cost requested
    all_methods = [
        "coverage", "simple_correlation", "direction_consistency", "stability_split",
        "leakage_audit", "outlier_sensitivity", "cost_sensitivity"
    ]
    raw_hyp = _make_hypothesis("hypo-case-a", methods=all_methods, falsification=["ic < 0.05", "negative_ic"])

    result = engine.run_single(
        hypothesis_input=raw_hyp,
        snapshot_path=falsified_csv,
        dataset_binding=falsified_binding,
    )

    assert result.status == "completed"
    assert result.critic_decision is not None
    decision = result.critic_decision
    assert decision.decision == "REJECT"
    assert len(decision.reject_reasons) > 0
    # Must explicitly state why it was rejected
    assert any("Falsification triggered" in r or "Direction consistency" in r for r in decision.reject_reasons)

    # Verify ResearchMemory recorded the REJECT
    mem_records = test_env["memory"].find_by_hypothesis_id("hypo-case-a")
    assert len(mem_records) == 1
    assert mem_records[0].decision == "REJECT"
    assert mem_records[0].reject_reasons == decision.reject_reasons


def test_case_b_initial_nme_supplemental_promotes(test_env):
    """Case B: Initial screening lacks evidence (NME) -> Supplemental runs ONLY missing methods -> PROMOTE."""
    engine = test_env["engine"]
    clean_binding = test_env["clean_binding"]
    clean_csv = test_env["clean_csv"]

    # Step 1: Initial screening only requests first 4 cheap methods (lacks leakage, outlier, cost)
    initial_methods = ["coverage", "simple_correlation", "direction_consistency", "stability_split"]
    raw_hyp = _make_hypothesis("hypo-case-b", methods=initial_methods, signal_def="feature_val", source_features=["feature_val", "close"])

    initial_result = engine.run_single(
        hypothesis_input=raw_hyp,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        auto_supplemental=False,
    )

    assert initial_result.status == "completed"
    assert initial_result.critic_decision is not None
    assert initial_result.critic_decision.decision == "NEED_MORE_EVIDENCE"
    missing = initial_result.critic_decision.missing_evidence
    assert "leakage_audit" in missing
    assert "outlier_sensitivity" in missing
    assert "cost_sensitivity" in missing

    # Verify first memory record is NEED_MORE_EVIDENCE
    mem_history = test_env["memory"].find_by_hypothesis_id("hypo-case-b")
    assert len(mem_history) == 1
    assert mem_history[0].decision == "NEED_MORE_EVIDENCE"

    # Step 2: Trigger Supplemental Screening Loop (Section 15 & 16)
    supp_result = engine.execute_supplemental_cycle(
        prior_item=initial_result,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
    )

    assert supp_result.status == "completed"
    assert supp_result.plan is not None
    # Crucial acceptance check: Supplemental plan ONLY ran missing methods!
    supp_methods = [m.method for m in supp_result.plan.methods]
    assert "coverage" not in supp_methods
    assert "simple_correlation" not in supp_methods
    assert set(supp_methods) == {"leakage_audit", "outlier_sensitivity", "cost_sensitivity"}

    # Step 3: Re-evaluated decision with aggregated evidence must be PROMOTE
    assert supp_result.critic_decision is not None
    final_dec = supp_result.critic_decision
    assert final_dec.decision == "PROMOTE"
    assert len(final_dec.promoted_reasons) >= 3
    assert len(final_dec.reject_reasons) == 0

    # Step 4: Verify Research Memory append-only preservation (Section 18)
    all_mem = test_env["memory"].find_by_hypothesis_id("hypo-case-b")
    assert len(all_mem) == 2
    assert all_mem[0].decision == "NEED_MORE_EVIDENCE"
    assert all_mem[1].decision == "PROMOTE"
    assert all_mem[0].record_id != all_mem[1].record_id


def test_case_c_initial_nme_supplemental_reveals_leakage_rejects(test_env):
    """Case C: Initial screening NME -> Supplemental reveals critical leakage -> REJECT."""
    engine = test_env["engine"]
    leakage_binding = test_env["leakage_binding"]
    leakage_csv = test_env["leakage_csv"]

    # Initial partial run
    initial_methods = ["coverage", "simple_correlation", "direction_consistency", "stability_split"]
    raw_hyp = _make_hypothesis("hypo-case-c", methods=initial_methods)

    initial_result = engine.run_single(
        raw_hyp,
        snapshot_path=leakage_csv,
        dataset_binding=leakage_binding,
        auto_supplemental=False,
    )
    assert initial_result.critic_decision.decision == "NEED_MORE_EVIDENCE"

    # Supplemental run on leakage dataset
    supp_result = engine.execute_supplemental_cycle(
        prior_item=initial_result,
        snapshot_path=leakage_csv,
        dataset_binding=leakage_binding,
    )

    # Re-evaluation must REJECT due to temporal causality violation
    assert supp_result.critic_decision.decision == "REJECT"
    assert any("leakage violation" in r.lower() for r in supp_result.critic_decision.reject_reasons)

    all_mem = test_env["memory"].find_by_hypothesis_id("hypo-case-c")
    assert len(all_mem) == 2
    assert all_mem[0].decision == "NEED_MORE_EVIDENCE"
    assert all_mem[1].decision == "REJECT"


def test_case_d_engineering_failure_not_scientific_reject(test_env, tmp_path):
    """Case D: Engineering / execution failure produces NEED_MORE_EVIDENCE, NEVER scientific REJECT (P1-B)."""
    engine = test_env["engine"]
    clean_csv = test_env["clean_csv"]

    # Create dataset binding declaring missing fields to force INSUFFICIENT_DATA
    bad_binding = {
        "snapshot_locator": str(clean_csv),
        "snapshot_sha256": v2.sha(clean_csv.read_bytes()),
        "snapshot_byte_length": len(clean_csv.read_bytes()),
        "required_fields": ["non_existent_column"],
        "available_fields": ["timestamp", "symbol"],
        "provenance": "bad_binding",
    }
    raw_hyp = _make_hypothesis("hypo-case-d", methods=["coverage"])

    result = engine.run_single(
        raw_hyp,
        snapshot_path=clean_csv,
        dataset_binding=bad_binding,
    )

    assert result.status == "completed"
    assert result.critic_decision is not None
    # Crucial P1-B check: Must be NEED_MORE_EVIDENCE, NEVER REJECT!
    assert result.critic_decision.decision == "NEED_MORE_EVIDENCE"
    assert len(result.critic_decision.reject_reasons) == 0


def test_case_e_memory_skip_vs_duplicate_semantics(test_env):
    """Case E: P1-C Duplicate detection vs Execution skip.

    - NME + new methods MUST execute.
    - Exact same plan + coverage MAY skip.
    """
    memory = test_env["memory"]
    engine = test_env["engine"]
    clean_binding = test_env["clean_binding"]
    clean_csv = test_env["clean_csv"]

    raw_hyp = _make_hypothesis("hypo-case-e", methods=["coverage", "simple_correlation"])
    res1 = engine.run_single(raw_hyp, clean_csv, dataset_binding=clean_binding)
    assert res1.status == "completed"
    assert res1.critic_decision.decision == "NEED_MORE_EVIDENCE"

    # Check 1: is_duplicate_hypothesis is True (scientifically seen before)
    assert memory.is_duplicate_hypothesis(raw_hyp) is True

    # Check 2: Same hypothesis with NEW methods MUST execute
    new_methods_hyp = _make_hypothesis(
        "hypo-case-e",
        methods=["coverage", "simple_correlation", "direction_consistency", "outlier_sensitivity"],
    )
    res2 = engine.run_single(new_methods_hyp, clean_csv, dataset_binding=clean_binding)
    assert res2.status == "completed"  # Did NOT skip!

    # Check 3: Exact same hypothesis and plan with no new methods MAY skip
    res3 = engine.run_single(new_methods_hyp, clean_csv, dataset_binding=clean_binding)
    assert res3.status == "skipped_duplicate"
    assert res3.prior_record is not None


def test_case_f_staging_deletion_retains_full_chain_in_result_store(test_env):
    """Case F: Deleting staging directory completely retains 100% resolvable research chain (Section 17 & 30)."""
    engine = test_env["engine"]
    store = test_env["store"]
    memory = test_env["memory"]
    clean_binding = test_env["clean_binding"]
    clean_csv = test_env["clean_csv"]
    staging_dir = test_env["staging_dir"]

    raw_hyp = _make_hypothesis("hypo-case-f", methods=["coverage", "simple_correlation"])
    res = engine.run_single(raw_hyp, clean_csv, dataset_binding=clean_binding)
    assert res.status == "completed"
    assert len(res.receipts) >= 2

    # Step 1: Nuclear delete of staging directory
    shutil.rmtree(staging_dir, ignore_errors=True)
    assert not staging_dir.exists()

    # Step 2: Retrieve Research Memory record
    records = memory.find_by_hypothesis_id("hypo-case-f")
    assert len(records) == 1
    rec = records[0]

    # Step 3: Verify complete research chain can be fully resolved from ResultStore
    for ev_ref in rec.evidence_refs:
        ev_id = ev_ref["evidence_id"]
        runs = store.query_v2_runs(evidence_id=ev_id, verify=True)
        assert len(runs) == 1
        receipt = runs[0]

        # Stored snapshot in ResultStore remains 100% intact and verified
        bundle_facts = store.load_v2_bundle_facts(receipt["run"]["object_id"])
        assert bundle_facts["task"]["task_id"] == receipt["task"]["object_id"]
        assert bundle_facts["spec"]["spec_id"] == receipt["spec"]["object_id"]
        assert bundle_facts["run"]["run_id"] == receipt["run"]["object_id"]
        assert bundle_facts["manifest"]["manifest_id"] == receipt["manifest"]["object_id"]
        assert bundle_facts["evidence"]["evidence_id"] == ev_id


def test_critic_mandatory_dimensions_cannot_be_reduced():
    """Section 10: Mandatory dimensions can only be augmented, reducing fail-closed."""
    with pytest.raises(ValueError, match="Cannot reduce mandatory evidence dimensions"):
        CriticGate(required_evidence_dimensions={"signal_coverage", "sample_size"})


def test_critic_tampered_decision_hash_fails_closed():
    """Section 12: Tampering with review decision or criteria causes fail-closed verification."""
    critic = CriticGate()
    hyp_dict = _make_hypothesis("hypo-tamper")
    ev_dict = {
        "evidence_id": "ev-test-1",
        "revision": "rev.1",
        "evidence_content_hash": "a" * 64,
        "execution_status": "COMPLETED",
        "typed_metrics": {
            "methods_applied": ["coverage"],
            "facts": {"coverage": {"total_rows": 100, "valid_rows": 98, "missing_rows": 2, "coverage_ratio": "0.98"}},
        },
    }
    decision = critic.evaluate(hyp_dict, ev_dict)

    # Valid decision validates cleanly
    validated = validate_critic_decision(decision, hyp_dict, ev_dict)
    assert validated["decision_id"] == decision.decision_id

    # Tampered decision (e.g. attempting to change NEED_MORE_EVIDENCE to PROMOTE)
    tampered = decision.model_dump()
    tampered["decision"] = "PROMOTE"
    with pytest.raises(ValueError, match="review_content_hash mismatch"):
        validate_critic_decision(tampered, hyp_dict, ev_dict)


def test_evidence_facts_contain_zero_decision_words(test_env):
    """Section 23: Evidence facts contain zero decision, score, rank, or recommendation words."""
    pipeline = test_env["engine"].pipeline
    clean_csv = test_env["clean_csv"]
    clean_binding = test_env["clean_binding"]

    planner = ScreeningPlanner()
    hyp_obj = AlphaHypothesis.model_validate(_make_hypothesis("hypo-facts-only"))
    plan = planner.plan(hyp_obj, dataset_requirements=clean_binding)

    with tempfile.TemporaryDirectory() as td:
        report = pipeline.execute_plan(plan, clean_csv, td)
        for m_res in report.method_results:
            if m_res.facts:
                for forbidden in ("score", "rank", "decision", "promote", "reject", "recommendation"):
                    assert forbidden not in m_res.facts


def test_p1_1_leakage_audit_missing_metadata_cannot_be_completed(tmp_path: Path):
    """P1-1: leakage_audit with missing temporal metadata outputs INSUFFICIENT_DATA and Critic NME."""
    csv_path = tmp_path / "missing_meta.csv"
    # Rows with empty temporal fields represent unrecorded or missing metadata
    rows = [
        {
            "timestamp": f"2026-01-01T{i:02d}:00:00.000000Z",
            "symbol": "RB2405",
            "feature_val": str(i),
            "target_val": str(i * 0.1),
            "feature_availability_time": "",
            "as_of_time": "",
            "target_start_time": "",
        }
        for i in range(1, 25)
    ]
    all_fields = ["timestamp", "symbol", "feature_val", "target_val", "feature_availability_time", "as_of_time", "target_start_time"]
    c_sha, c_len = _create_synthetic_csv(csv_path, rows, all_fields)
    binding = {
        "snapshot_locator": str(csv_path),
        "snapshot_sha256": c_sha,
        "snapshot_byte_length": c_len,
        "required_fields": all_fields,
        "provenance": "test",
    }
    planner = ScreeningPlanner()
    hyp = _make_hypothesis("hypo-p1-1-meta", methods=["leakage_audit"])
    plan = planner.plan(hyp, dataset_requirements=binding)
    pipeline = ScreeningPipeline(planner=planner)

    with tempfile.TemporaryDirectory() as td:
        report = pipeline.execute_plan(plan, csv_path, Path(td) / "staging")
        m_res = report.method_results[0]
        assert m_res.method == "leakage_audit"
        assert m_res.status == "INSUFFICIENT_DATA"
        assert report.overall_status == "INSUFFICIENT_DATA"

        bundle_p = Path(m_res.bundle_dir)
        assert not (bundle_p / "statistical_summary.json").exists()
        assert (bundle_p / "failure_diagnostics.json").exists()

        run_dict = json.loads((bundle_p / "run.json").read_text("utf-8"))
        assert run_dict["run_status"] == "INSUFFICIENT_DATA"

        evidence_dict = json.loads((bundle_p / "evidence.json").read_text("utf-8"))
        assert evidence_dict["execution_status"] == "INSUFFICIENT_DATA"
        assert evidence_dict["run_status_snapshot"] == "INSUFFICIENT_DATA"

        # Critic evaluation must yield NEED_MORE_EVIDENCE, never pass or REJECT
        critic = CriticGate()
        dec = critic.evaluate(hyp, evidence_dict)
        assert dec.decision == "NEED_MORE_EVIDENCE"
        assert "leakage_audit" in dec.missing_evidence


def test_p1_1_leakage_audit_partial_unverifiable_rows(tmp_path: Path):
    """P1-1: Partial unverifiable rows in leakage_audit output INSUFFICIENT_DATA."""
    csv_path = tmp_path / "partial_meta.csv"
    rows = []
    for i in range(1, 25):
        # Even rows have missing target_start_time
        tgt_start = f"2026-01-01T{i:02d}:00:02.000000Z" if i % 2 != 0 else ""
        rows.append({
            "timestamp": f"2026-01-01T{i:02d}:00:00.000000Z",
            "symbol": "RB2405",
            "feature_val": str(i),
            "target_val": str(i * 0.1),
            "feature_availability_time": f"2026-01-01T{i:02d}:00:00.000000Z",
            "as_of_time": f"2026-01-01T{i:02d}:00:01.000000Z",
            "target_start_time": tgt_start,
        })
    fields = ["timestamp", "symbol", "feature_val", "target_val", "feature_availability_time", "as_of_time", "target_start_time"]
    c_sha, c_len = _create_synthetic_csv(csv_path, rows, fields)
    binding = {
        "snapshot_locator": str(csv_path),
        "snapshot_sha256": c_sha,
        "snapshot_byte_length": c_len,
        "required_fields": fields,
        "provenance": "test",
    }
    planner = ScreeningPlanner()
    hyp = _make_hypothesis("hypo-p1-1-partial", methods=["leakage_audit"])
    plan = planner.plan(hyp, dataset_requirements=binding)
    pipeline = ScreeningPipeline(planner=planner)

    with tempfile.TemporaryDirectory() as td:
        report = pipeline.execute_plan(plan, csv_path, Path(td) / "staging")
        m_res = report.method_results[0]
        assert m_res.status == "INSUFFICIENT_DATA"
        assert report.overall_status == "INSUFFICIENT_DATA"

        bundle_p = Path(m_res.bundle_dir)
        assert not (bundle_p / "statistical_summary.json").exists()
        assert (bundle_p / "failure_diagnostics.json").exists()

        run_dict = json.loads((bundle_p / "run.json").read_text("utf-8"))
        assert run_dict["run_status"] == "INSUFFICIENT_DATA"

        evidence_dict = json.loads((bundle_p / "evidence.json").read_text("utf-8"))
        assert evidence_dict["execution_status"] == "INSUFFICIENT_DATA"
        assert evidence_dict["run_status_snapshot"] == "INSUFFICIENT_DATA"


def test_p1_2_negative_alpha_cost_sensitivity_proxy_binding(tmp_path: Path):
    """P1-2: Negative Alpha binds -sign(feature_val) proxy deterministically into Spec and executes inverse position."""
    csv_path = tmp_path / "negative_alpha.csv"
    rows = []
    for i in range(1, 31):
        fv = float(i)
        tv = -0.05 * fv  # Negative target return
        rows.append({
            "timestamp": f"2026-01-01T{i:02d}:00:00.000000Z",
            "symbol": "RB2405",
            "feature_val": str(fv),
            "target_val": str(tv),
        })
    fields = ["timestamp", "symbol", "feature_val", "target_val"]
    c_sha, c_len = _create_synthetic_csv(csv_path, rows, fields)
    binding = {
        "snapshot_locator": str(csv_path),
        "snapshot_sha256": c_sha,
        "snapshot_byte_length": c_len,
        "required_fields": fields,
        "provenance": "test",
    }
    planner = ScreeningPlanner()
    hyp = _make_hypothesis("hypo-p1-2-neg", direction="negative", methods=["cost_sensitivity"])
    plan = planner.plan(hyp, dataset_requirements=binding)

    # 1. Planner sealed -sign(feature_val) in parameters
    cost_req = next(m for m in plan.methods if m.method == "cost_sensitivity")
    assert cost_req.parameters == {
        "position_proxy": "-sign(feature_val)",
        "expected_direction": "negative",
    }

    # 2. Pipeline executes with inverse position proxy
    pipeline = ScreeningPipeline(planner=planner)
    with tempfile.TemporaryDirectory() as td:
        report = pipeline.execute_plan(plan, csv_path, Path(td) / "staging")
        m_res = report.method_results[0]
        assert m_res.status == "COMPLETED"
        facts = m_res.facts
        assert facts["position_rule"] == "-sign(feature_val)"
        assert facts["expected_direction"] == "negative"
        # Since feature > 0, pos = -1, ret < 0, product pos * ret > 0 (positive screening return)
        assert float(facts["gross_screening_return"]) > 0


def test_p1_2_unmappable_cost_proxy_insufficient_data(tmp_path: Path):
    """P1-2: Missing or unmappable cost proxy outputs INSUFFICIENT_DATA in runner, planner and pipeline."""
    csv_path = tmp_path / "data.csv"
    rows = [{"timestamp": "2026-01-01T00:00:00.000000Z", "symbol": "RB", "feature_val": "1.0", "target_val": "0.1"}]
    c_sha, c_len = _create_synthetic_csv(csv_path, rows, ["timestamp", "symbol", "feature_val", "target_val"])

    data_req = {
        "snapshot_sha256": c_sha,
        "snapshot_locator": str(csv_path),
        "snapshot_byte_length": c_len,
        "required_fields": ["timestamp", "symbol", "feature_val", "target_val"],
        "provenance": "test",
    }
    task = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": "task-test-p12-insufficient",
        "revision": "rev.1",
        "research_type": "statistical_factor",
        "task_profile": "research_lab.statistical_screening.v1",
        "objective": "test",
        "data_requirements": data_req,
        "methods": ["cost_sensitivity"],
    }
    task["task_content_hash"] = v2.digest(task)

    # 1. Direct Runner execution with missing parameters -> INSUFFICIENT_DATA
    spec_missing = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": "spec-test-missing",
        "revision": "rev.1",
        "task_id": task["task_id"],
        "task_revision": task["revision"],
        "task_content_hash": task["task_content_hash"],
        "experiment_type": "statistical_factor",
        "research_stage": "validation",
        "screening_profile": "research_lab.statistical_screening.v1",
        "dataset_requirements": data_req,
        "methods": ["cost_sensitivity"],
    }
    spec_missing["spec_content_hash"] = v2.digest(spec_missing)

    with tempfile.TemporaryDirectory() as td:
        out1 = Path(td) / "run1"
        res_dir = run_statistical_screening(task=task, spec=spec_missing, snapshot_path=csv_path, output_dir=out1)
        run_record = json.loads((res_dir / "run.json").read_text("utf-8"))
        assert run_record["run_status"] == "INSUFFICIENT_DATA"
        ev_record = json.loads((res_dir / "evidence.json").read_text("utf-8"))
        assert ev_record["execution_status"] == "INSUFFICIENT_DATA"
        assert ev_record["run_status_snapshot"] == "INSUFFICIENT_DATA"
        assert not (res_dir / "statistical_summary.json").exists()
        assert (res_dir / "failure_diagnostics.json").exists()

    # 2. Pipeline executing plan with missing proxy -> INSUFFICIENT_DATA
    planner = ScreeningPlanner()
    hyp = _make_hypothesis("hypo-unmappable", direction="positive", methods=["cost_sensitivity"])
    plan_dict = planner.plan(hyp, dataset_requirements=data_req).model_dump()
    plan_dict["methods"][0]["parameters"] = {}
    from research_lab.alpha_discovery.screening_plan import compute_plan_content_hash
    plan_dict["plan_content_hash"] = compute_plan_content_hash(plan_dict)

    pipeline = ScreeningPipeline(planner=planner)
    with tempfile.TemporaryDirectory() as td:
        report = pipeline.execute_plan(plan_dict, csv_path, Path(td) / "staging_unmappable")
        assert report.method_results[0].status == "INSUFFICIENT_DATA"


def test_p1_2_cost_sensitivity_tampered_sealed_proxy_failclosed(tmp_path: Path):
    """P1-2: Tampered sealed proxy fails closed with NO pseudo-evidence in runner and pipeline."""
    csv_path = tmp_path / "data.csv"
    rows = [{"timestamp": "2026-01-01T00:00:00.000000Z", "symbol": "RB", "feature_val": "1.0", "target_val": "0.1"}]
    c_sha, c_len = _create_synthetic_csv(csv_path, rows, ["timestamp", "symbol", "feature_val", "target_val"])

    data_req = {
        "snapshot_sha256": c_sha,
        "snapshot_locator": str(csv_path),
        "snapshot_byte_length": c_len,
        "required_fields": ["timestamp", "symbol", "feature_val", "target_val"],
        "provenance": "test",
    }
    task = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": "task-test-p12-tampered",
        "revision": "rev.1",
        "research_type": "statistical_factor",
        "task_profile": "research_lab.statistical_screening.v1",
        "objective": "test",
        "data_requirements": data_req,
        "methods": ["cost_sensitivity"],
    }
    task["task_content_hash"] = v2.digest(task)

    # 1. Direct Runner execution with conflicting/tampered direction & proxy -> raises ValueError fail-closed
    spec_conflict = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": "spec-test-conflict",
        "revision": "rev.1",
        "task_id": task["task_id"],
        "task_revision": task["revision"],
        "task_content_hash": task["task_content_hash"],
        "experiment_type": "statistical_factor",
        "research_stage": "validation",
        "screening_profile": "research_lab.statistical_screening.v1",
        "dataset_requirements": data_req,
        "methods": ["cost_sensitivity"],
        "parameters": {"position_proxy": "-sign(feature_val)", "expected_direction": "positive"},
    }
    spec_conflict["spec_content_hash"] = v2.digest(spec_conflict)

    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "run_tampered"
        with pytest.raises(ValueError, match="Tampered sealed proxy mismatch"):
            run_statistical_screening(task=task, spec=spec_conflict, snapshot_path=csv_path, output_dir=out)
        # Defense assertion: NO pseudo-evidence produced
        assert not (out / "evidence.json").exists()

    # 2. Pipeline execution with tampered plan parameters -> EXECUTION_FAILED with NO pseudo-evidence
    planner = ScreeningPlanner()
    hyp = _make_hypothesis("hypo-tamper-plan", direction="positive", methods=["cost_sensitivity"])
    plan_dict = planner.plan(hyp, dataset_requirements=data_req).model_dump()
    # Tamper the sealed proxy in method parameters and recompute hash
    plan_dict["methods"][0]["parameters"]["position_proxy"] = "-sign(feature_val)"
    from research_lab.alpha_discovery.screening_plan import compute_plan_content_hash
    plan_dict["plan_content_hash"] = compute_plan_content_hash(plan_dict)

    pipeline = ScreeningPipeline(planner=planner)
    with tempfile.TemporaryDirectory() as td:
        report = pipeline.execute_plan(plan_dict, csv_path, Path(td) / "staging_tampered")
        m_tampered = report.method_results[0]
        assert m_tampered.status == "EXECUTION_FAILED"
        assert "Tampered sealed proxy mismatch" in (m_tampered.error_message or "")
        # Defense assertion: NO pseudo-evidence produced
        assert m_tampered.evidence_id is None
        assert m_tampered.bundle_dir is None


def test_p1_3_critic_multi_evidence_exact_binding_attacks():
    """P1-3: Rigorous attack defense for multi-Evidence exact binding in validate_critic_decision."""
    critic = CriticGate()
    hyp_dict = _make_hypothesis("hypo-p1-3")

    ev1 = {
        "evidence_id": "evidence-run-1",
        "revision": "rev.1",
        "evidence_content_hash": "1" * 64,
        "execution_status": "COMPLETED",
        "typed_metrics": {
            "methods_applied": ["coverage"],
            "facts": {"coverage": {"total_rows": 100, "valid_rows": 98, "missing_rows": 2, "coverage_ratio": "0.98"}},
        },
    }
    ev2 = {
        "evidence_id": "evidence-run-2",
        "revision": "rev.1",
        "evidence_content_hash": "2" * 64,
        "execution_status": "COMPLETED",
        "typed_metrics": {
            "methods_applied": ["simple_correlation"],
            "facts": {"simple_correlation": {"sample_size": 100, "pearson_ic": "0.150000"}},
        },
    }

    # Legitimate multi-evidence decision
    decision = critic.evaluate(hyp_dict, [ev1, ev2])
    assert decision.evidence_count == 2
    assert len(decision.evidence_refs) == 2

    # Legitimate decision validates cleanly
    validated = validate_critic_decision(decision, hyp_dict, [ev1, ev2])
    assert validated["decision_id"] == decision.decision_id

    # Order normalization: passing [ev2, ev1] still validates cleanly because of deterministic sorting
    validated_reordered = validate_critic_decision(decision, hyp_dict, [ev2, ev1])
    assert validated_reordered["decision_id"] == decision.decision_id

    # Attack 1: Extra unreferenced evidence provided
    ev3_extra = dict(ev1, evidence_id="evidence-run-3", evidence_content_hash="3" * 64)
    with pytest.raises(ValueError, match="Evidence set cardinality mismatch"):
        validate_critic_decision(decision, hyp_dict, [ev1, ev2, ev3_extra])

    # Attack 2: Missing one of the declared evidences
    with pytest.raises(ValueError, match="Evidence set cardinality mismatch"):
        validate_critic_decision(decision, hyp_dict, [ev1])

    # Attack 3: Same evidence_id but revision tampered
    ev1_tampered_rev = dict(ev1, revision="rev.2")
    with pytest.raises(ValueError, match="Evidence revision mismatch"):
        validate_critic_decision(decision, hyp_dict, [ev1_tampered_rev, ev2])

    # Attack 4: Same evidence_id but content_hash tampered
    ev1_tampered_hash = dict(ev1, evidence_content_hash="f" * 64)
    with pytest.raises(ValueError, match="Evidence content_hash mismatch"):
        validate_critic_decision(decision, hyp_dict, [ev1_tampered_hash, ev2])

    # Attack 5: Same evidence_id but execution_status tampered
    ev1_tampered_status = dict(ev1, execution_status="FAILED")
    with pytest.raises(ValueError, match="Evidence execution_status mismatch"):
        validate_critic_decision(decision, hyp_dict, [ev1_tampered_status, ev2])

    # Attack 6: Duplicate evidence items in input
    with pytest.raises(ValueError, match="Duplicate evidence items"):
        validate_critic_decision(decision, hyp_dict, [ev1, ev1])


def test_p1_1_cost_proxy_complex_signal_insufficient_data_vs_signed_scalar(tmp_path: Path):
    """P1-1: Complex/unverifiable signals yield INSUFFICIENT_DATA for cost_sensitivity; signed scalars succeed."""
    planner = ScreeningPlanner()
    pipeline = ScreeningPipeline()

    csv_path = tmp_path / "test_data.csv"
    rows = [
        {
            "timestamp": f"2026-01-01T{i:02d}:00:00.000000Z",
            "symbol": "RB2405",
            "feature_val": str(i),
            "target_val": str(i * 0.05),
            "close": str(3500 + i),
        }
        for i in range(1, 25)
    ]
    fields = ["timestamp", "symbol", "feature_val", "target_val", "close"]
    c_sha, c_len = _create_synthetic_csv(csv_path, rows, fields)
    binding = {
        "snapshot_locator": str(csv_path),
        "snapshot_sha256": c_sha,
        "snapshot_byte_length": c_len,
        "required_fields": fields,
        "provenance": "test",
    }

    # Case 1: Complex derived signal with NO machine-verifiable signed scalar property
    hyp_complex = _make_hypothesis(
        hyp_id="hyp-complex-1",
        direction="positive",
        methods=["cost_sensitivity"],
        signal_def="rolling_mean(close, 5) - close",
        source_features=["close"],
    )
    plan_complex = planner.plan(hyp_complex, dataset_requirements=binding)
    req_complex = plan_complex.methods[0]
    assert req_complex.method == "cost_sensitivity"
    assert req_complex.status == "INSUFFICIENT_DATA"
    assert req_complex.reason == "unmappable_cost_proxy_not_signed_scalar"

    with tempfile.TemporaryDirectory() as td:
        rep_complex = pipeline.execute_plan(plan_complex, csv_path, Path(td) / "staging")
        assert rep_complex.overall_status == "INSUFFICIENT_DATA"
        m_res_complex = rep_complex.method_results[0]
        assert m_res_complex.status == "INSUFFICIENT_DATA"
        assert m_res_complex.error_message == "unmappable_cost_proxy_not_signed_scalar"
        # Defense assertion: NO bundle or pseudo-evidence produced
        assert m_res_complex.bundle_dir is None
        assert m_res_complex.evidence_id is None

    # Case 2: Canonical signed scalar feature signal succeeds
    hyp_scalar = _make_hypothesis(
        hyp_id="hyp-scalar-1",
        direction="positive",
        methods=["cost_sensitivity"],
        signal_def="feature_val",
        source_features=["feature_val"],
    )
    plan_scalar = planner.plan(hyp_scalar, dataset_requirements=binding)
    req_scalar = plan_scalar.methods[0]
    assert req_scalar.method == "cost_sensitivity"
    assert req_scalar.status == "PLANNED"
    assert req_scalar.parameters["position_proxy"] == "sign(feature_val)"

    with tempfile.TemporaryDirectory() as td:
        rep_scalar = pipeline.execute_plan(plan_scalar, csv_path, Path(td) / "staging")
        assert rep_scalar.overall_status == "COMPLETED"
        m_res_scalar = rep_scalar.method_results[0]
        assert m_res_scalar.status == "COMPLETED"
        assert m_res_scalar.bundle_dir is not None
        assert (Path(m_res_scalar.bundle_dir) / "evidence.json").exists()


def test_p1_2_critic_opposite_direction_falsification_symmetry_and_fail_closed():
    """P1-2: Symmetric falsification for positive and negative directions, and strict fail-closed."""
    critic = CriticGate()

    def _make_ev(ic_value: str) -> dict[str, Any]:
        return {
            "evidence_id": "evidence-run-ic",
            "revision": "rev.1",
            "evidence_content_hash": "a" * 64,
            "execution_status": "COMPLETED",
            "typed_metrics": {
                "methods_applied": ["simple_correlation"],
                "facts": {
                    "simple_correlation": {
                        "sample_size": 100,
                        "pearson_ic": ic_value,
                    }
                },
            },
        }

    # Case 1: Positive hypothesis
    hyp_pos = _make_hypothesis("hyp-pos", direction="positive", falsification=["opposite_direction"])
    # 1a. Positive IC (0.15) -> pass
    dec_pos_pass = critic.evaluate(hyp_pos, _make_ev("0.150000"))
    assert dec_pos_pass.decision in ("PASS", "NEED_MORE_EVIDENCE")  # Not falsified/rejected
    assert not any("Falsification triggered" in r for r in dec_pos_pass.reject_reasons)
    # 1b. Negative IC (-0.15) -> REJECT
    dec_pos_fail = critic.evaluate(hyp_pos, _make_ev("-0.150000"))
    assert dec_pos_fail.decision == "REJECT"
    assert any("contradicts expected direction (positive)" in r for r in dec_pos_fail.reject_reasons)

    # Case 2: Negative hypothesis
    hyp_neg = _make_hypothesis("hyp-neg", direction="negative", falsification=["opposite_direction"])
    # 2a. Negative IC (-0.15) -> pass (symmetric check: negative IC matches negative hypothesis)
    dec_neg_pass = critic.evaluate(hyp_neg, _make_ev("-0.150000"))
    assert dec_neg_pass.decision in ("PASS", "NEED_MORE_EVIDENCE")  # Not falsified/rejected
    assert not any("Falsification triggered" in r for r in dec_neg_pass.reject_reasons)
    # 2b. Positive IC (0.15) -> REJECT (symmetric check: positive IC contradicts negative hypothesis)
    dec_neg_fail = critic.evaluate(hyp_neg, _make_ev("0.150000"))
    assert dec_neg_fail.decision == "REJECT"
    assert any("contradicts expected direction (negative)" in r for r in dec_neg_fail.reject_reasons)

    # Case 3: Missing or invalid expected_direction fail-closed (no silent fallback to 'direction' or 'positive')
    hyp_bad = dict(hyp_pos)
    hyp_bad.pop("expected_direction", None)
    with pytest.raises(ValueError, match="Hypothesis missing valid expected_direction"):
        critic.evaluate(hyp_bad, _make_ev("0.150000"))

    hyp_invalid = dict(hyp_pos, expected_direction="neutral")
    with pytest.raises(ValueError, match="Hypothesis missing valid expected_direction"):
        critic.evaluate(hyp_invalid, _make_ev("0.150000"))

