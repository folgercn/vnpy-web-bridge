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
) -> dict[str, Any]:
    """Helper to generate valid AlphaHypothesis dict."""
    methods_list = methods or ["coverage", "simple_correlation", "direction_consistency", "stability_split"]
    falsif = falsification or ["ic < 0.05", "negative_ic"]
    raw = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": hyp_id,
        "revision": revision,
        "title": f"Momentum Factor on RB for {hyp_id}",
        "economic_rationale": "Informed trader flow causes short-term price continuation in commodity futures.",
        "signal_family": "momentum",
        "signal_definition": "rolling_mean(close, 5) - close",
        "source_features": ["close"],
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
    raw_hyp = _make_hypothesis("hypo-case-b", methods=initial_methods)

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
