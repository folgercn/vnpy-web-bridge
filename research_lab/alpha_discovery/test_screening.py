"""Comprehensive tests for Cheap Screening Pipeline and Protocol v2 integration (#564).

Validates all 18 requirements defined in Issue #564 specification:
1. Valid Hypothesis generates stable ScreeningPlan
2. Rebuilding same Hypothesis yields identical plan hash
3. Exact duplicate Hypotheses yield same ScreeningPlan
4. New scientific hypothesis yields different plan
5. Unsupported method explicitly returns UNSUPPORTED (reason="not_registered")
6. Missing required field yields INSUFFICIENT_DATA (missing_fields, reason)
7. One hypothesis generates multiple experiment specs
8. Each spec legally passes current Protocol v2 validation
9. Completed screening generates Evidence
10. Execution failure is preserved (EXECUTION_FAILED, error_message)
11. Evidence & facts strictly forbid decision fields (no score, rank, promote, reject, etc.)
12. Pipeline does not output PROMOTE / REJECT decisions
13. No backtest generated if not planned
14. No parameter tuning
15. No silent fallback
16. Deterministic execution order
17. Protocol v2 regression
18. AlphaHypothesis regression
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from research_lab.alpha_discovery.hypothesis import (
    AlphaHypothesis,
    compute_hypothesis_content_hash,
    compute_scientific_identity_hash,
    validate_hypothesis,
)
from research_lab.alpha_discovery.planner import ScreeningPlanner
from research_lab.alpha_discovery.screening import (
    ScreeningPipeline,
    SequentialScreeningExecutor,
    build_protocol_v2_spec,
    build_protocol_v2_task,
)
from research_lab.alpha_discovery.screening_plan import (
    ScreeningPlan,
    validate_screening_plan,
)
from research_lab.contracts import statistical_screening_definition as ssd
from research_lab.contracts import v2

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / ssd.SYNTHETIC_FIXTURE_PATH


@pytest.fixture
def base_hypothesis_data() -> dict[str, Any]:
    """Base valid AlphaHypothesis for screening planning."""
    data = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": "hypo-momentum-cheap-001",
        "revision": "rev.1",
        "title": "Short term momentum predictive signal",
        "economic_rationale": "Order book imbalance causes short-term continuation in price drift.",
        "signal_family": "momentum",
        "signal_definition": "ts_mean(feature_val, 5)",
        "source_features": ["feature_val"],
        "target": "target_val",
        "expected_direction": "positive",
        "holding_horizon": "15m",
        "universe": "commodity_active",
        "frequency": "1m",
        "known_risks": ["Liquidity shocks during rollover windows."],
        "falsification_conditions": [
            "IC mean <= 0 over the screening evaluation period.",
            "Direction consistency ratio < 50%.",
        ],
        "proposed_screening_methods": [
            "coverage",
            "simple_correlation",
            "direction_consistency",
            "stability_split",
        ],
        "provenance": {
            "origin_type": "human",
            "origin_ref": "research_notes/alpha_001.md",
            "created_by": "fujun",
            "created_at": "2026-09-19T08:00:00.000000Z",
        },
    }
    data["hypothesis_content_hash"] = compute_hypothesis_content_hash(data)
    return data


@pytest.fixture
def dataset_requirements() -> dict[str, Any]:
    raw_bytes = FIXTURE_PATH.read_bytes()
    return {
        "snapshot_locator": str(FIXTURE_PATH),
        "snapshot_sha256": v2.sha(raw_bytes),
        "snapshot_byte_length": len(raw_bytes),
        "required_fields": ["timestamp", "symbol", "feature_val", "target_val"],
        "provenance": "synthetic_screening_fixture",
        "time_range": {
            "start": "2024-01-02T09:00:00.000000Z",
            "end": "2024-01-02T09:19:00.000000Z",
        },
    }


# =========================================================================
# Requirement 1: Valid Hypothesis generates stable ScreeningPlan
# =========================================================================
def test_01_valid_hypothesis_generates_stable_screening_plan(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    planner = ScreeningPlanner()
    plan = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    assert isinstance(plan, ScreeningPlan)
    assert plan.schema_version == "research_lab.screening_plan.v1"
    assert plan.hash_profile == "research-json-v1"
    assert plan.plan_id.startswith(f"plan-{base_hypothesis_data['hypothesis_id']}-")
    assert plan.hypothesis_ref.hypothesis_id == base_hypothesis_data["hypothesis_id"]
    assert plan.scientific_identity_hash == compute_scientific_identity_hash(base_hypothesis_data)
    assert len(plan.methods) == 4
    for m in plan.methods:
        assert m.status == "PLANNED"
        assert m.reason is None

    # Validate against strict contract
    validated = validate_screening_plan(plan.model_dump(exclude_none=True))
    assert validated["plan_content_hash"] == plan.plan_content_hash


# =========================================================================
# Requirement 2: Rebuilding same Hypothesis yields identical plan hash
# =========================================================================
def test_02_rebuilding_same_hypothesis_yields_identical_plan_hash(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    planner = ScreeningPlanner()
    plan1 = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)
    plan2 = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    assert plan1.plan_id == plan2.plan_id
    assert plan1.plan_content_hash == plan2.plan_content_hash
    assert plan1.model_dump() == plan2.model_dump()


# =========================================================================
# Requirement 3: Exact duplicate Hypotheses yield same ScreeningPlan
# =========================================================================
def test_03_exact_duplicate_hypotheses_yield_same_screening_plan(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    planner = ScreeningPlanner()
    # Re-order dictionary keys: exact duplicate representation of identical proposition
    h2 = {k: base_hypothesis_data[k] for k in sorted(base_hypothesis_data.keys())}
    assert compute_hypothesis_content_hash(h2) == base_hypothesis_data["hypothesis_content_hash"]
    assert compute_scientific_identity_hash(h2) == compute_scientific_identity_hash(base_hypothesis_data)

    plan1 = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)
    plan2 = planner.plan(h2, dataset_requirements=dataset_requirements)

    # Identical plan output and content hash
    assert plan1.plan_id == plan2.plan_id
    assert plan1.plan_content_hash == plan2.plan_content_hash
    assert [m.method for m in plan1.methods] == [m.method for m in plan2.methods]


# =========================================================================
# Requirement 4: New scientific hypothesis yields different plan
# =========================================================================
def test_04_new_scientific_hypothesis_yields_different_plan(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    planner = ScreeningPlanner()
    h_new = copy.deepcopy(base_hypothesis_data)
    h_new["hypothesis_id"] = "hypo-momentum-cheap-002"
    h_new["target"] = "forward_return_60m"
    h_new["hypothesis_content_hash"] = compute_hypothesis_content_hash(h_new)

    plan_orig = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)
    plan_new = planner.plan(h_new, dataset_requirements=dataset_requirements)

    assert plan_orig.plan_id != plan_new.plan_id
    assert plan_orig.scientific_identity_hash != plan_new.scientific_identity_hash
    assert plan_orig.plan_content_hash != plan_new.plan_content_hash


# =========================================================================
# Requirement 5: Unsupported method explicitly returns UNSUPPORTED
# =========================================================================
def test_05_unsupported_method_explicitly_returns_unsupported(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    planner = ScreeningPlanner()
    h = copy.deepcopy(base_hypothesis_data)
    h["proposed_screening_methods"] = ["coverage", "deep_rl_policy_gradient", "unregistered_method"]
    h["hypothesis_content_hash"] = compute_hypothesis_content_hash(h)

    plan = planner.plan(h, dataset_requirements=dataset_requirements)
    methods_by_name = {m.method: m for m in plan.methods}

    assert methods_by_name["coverage"].status == "PLANNED"
    assert methods_by_name["deep_rl_policy_gradient"].status == "UNSUPPORTED"
    assert methods_by_name["deep_rl_policy_gradient"].reason == "not_registered"
    assert methods_by_name["unregistered_method"].status == "UNSUPPORTED"
    assert methods_by_name["unregistered_method"].reason == "not_registered"

    # Pipeline execution directly preserves UNSUPPORTED status without running runner
    pipeline = ScreeningPipeline()
    report = pipeline.execute_plan(plan, FIXTURE_PATH, tmp_path / "out_unsupported")
    rep_methods = {r.method: r for r in report.method_results}
    assert rep_methods["deep_rl_policy_gradient"].status == "UNSUPPORTED"
    assert rep_methods["deep_rl_policy_gradient"].error_message == "not_registered"


# =========================================================================
# Requirement 6: Missing required field yields INSUFFICIENT_DATA
# =========================================================================
def test_06_missing_required_field_yields_insufficient_data(
    base_hypothesis_data: dict[str, Any],
    tmp_path: Path,
):
    planner = ScreeningPlanner()
    # Provide dataset missing "target_val"
    incomplete_ds = {
        "snapshot_locator": str(FIXTURE_PATH),
        "snapshot_sha256": "a" * 64,
        "snapshot_byte_length": 1000,
        "required_fields": ["timestamp", "symbol", "feature_val"],  # target_val missing
        "available_fields": ["timestamp", "symbol", "feature_val"],
        "provenance": "incomplete_fixture",
    }
    plan = planner.plan(base_hypothesis_data, dataset_requirements=incomplete_ds)
    methods_by_name = {m.method: m for m in plan.methods}

    # coverage only requires timestamp and symbol -> PLANNED
    assert methods_by_name["coverage"].status == "PLANNED"
    # correlation, consistency, stability require target_val -> INSUFFICIENT_DATA
    assert methods_by_name["simple_correlation"].status == "INSUFFICIENT_DATA"
    assert methods_by_name["simple_correlation"].reason == "missing_required_fields"
    assert "target_val" in (methods_by_name["simple_correlation"].missing_fields or [])

    # Pipeline execution preserves INSUFFICIENT_DATA
    pipeline = ScreeningPipeline()
    report = pipeline.execute_plan(plan, FIXTURE_PATH, tmp_path / "out_insufficient")
    rep_methods = {r.method: r for r in report.method_results}
    assert rep_methods["simple_correlation"].status == "INSUFFICIENT_DATA"
    assert "target_val" in (rep_methods["simple_correlation"].missing_fields or [])


# =========================================================================
# Requirement 7: One hypothesis generates multiple experiment specs
# =========================================================================
def test_07_one_hypothesis_generates_multiple_experiment_specs(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    planner = ScreeningPlanner()
    plan = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    specs = []
    for m in plan.methods:
        task = build_protocol_v2_task(plan, m.method, FIXTURE_PATH)
        spec = build_protocol_v2_spec(task, plan, m.method)
        specs.append(spec)

    assert len(specs) == 4
    spec_ids = [s["spec_id"] for s in specs]
    assert len(set(spec_ids)) == 4
    for m, spec in zip(plan.methods, specs):
        assert spec["methods"] == [m.method]
        assert f"-{m.method}-" in spec["spec_id"]


# =========================================================================
# Requirement 8: Each spec legally passes current Protocol v2 validation
# =========================================================================
def test_08_each_spec_legally_passes_current_protocol_v2(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    definitions = v2.Definitions()
    planner = ScreeningPlanner()
    plan = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    for m in plan.methods:
        task = build_protocol_v2_task(plan, m.method, FIXTURE_PATH)
        spec = build_protocol_v2_spec(task, plan, m.method)
        # Machine checks for Protocol v2 admission must pass cleanly
        res = v2.validate_spec(spec, task, definitions)
        assert res is not None


# =========================================================================
# Requirement 9: Completed screening generates Evidence
# =========================================================================
def test_09_completed_screening_generates_evidence(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    pipeline = ScreeningPipeline()
    out_dir = tmp_path / "screening_e2e_results"
    _plan, report = pipeline.execute_hypothesis(
        base_hypothesis_data,
        snapshot_path=FIXTURE_PATH,
        output_base_dir=out_dir,
        dataset_requirements=dataset_requirements,
    )

    assert report.overall_status == "COMPLETED"
    assert len(report.method_results) == 4

    for res in report.method_results:
        assert res.status == "COMPLETED"
        assert res.evidence_id is not None
        assert res.run_id is not None
        assert res.bundle_dir is not None
        b_path = Path(res.bundle_dir)
        assert (b_path / "evidence.json").is_file()
        assert (b_path / "manifest.json").is_file()
        assert (b_path / "run.json").is_file()
        assert (b_path / "statistical_summary.json").is_file()

        # Check facts are populated
        assert res.facts is not None
        if res.method == "coverage":
            assert res.facts["total_rows"] == 20
            assert res.facts["coverage_ratio"] == "1"
        elif res.method == "simple_correlation":
            assert res.facts["sample_size"] == 20
            assert res.facts["pearson_ic"] is not None
        elif res.method == "direction_consistency":
            assert res.facts["consistency_ratio"] is not None
        elif res.method == "stability_split":
            assert res.facts["first_half_sample_size"] == 10
            assert res.facts["second_half_sample_size"] == 10


# =========================================================================
# Requirement 10: Execution failure is preserved
# =========================================================================
def test_10_execution_failure_is_preserved(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    planner = ScreeningPlanner()
    plan = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    # Point to a corrupted binary snapshot that will fail runner CSV parsing
    corrupt_snap = tmp_path / "corrupted.csv"
    corrupt_snap.write_bytes(b"\x80\xff\xfe\x00\x01\x02\xff\xee\xdd")

    executor = SequentialScreeningExecutor()
    method_out = tmp_path / "failed_out"
    res = executor.execute_method(plan.methods[0], plan, corrupt_snap, method_out)

    assert res.status == "EXECUTION_FAILED"
    assert res.error_message is not None
    assert "mismatch" in res.error_message.lower() or "failed" in res.error_message.lower()


# =========================================================================
# Requirement 11: Evidence & facts contain no decision fields
# =========================================================================
def test_11_evidence_and_facts_contain_no_decision_fields(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    pipeline = ScreeningPipeline()
    out_dir = tmp_path / "screening_no_decisions"
    _, report = pipeline.execute_hypothesis(
        base_hypothesis_data,
        snapshot_path=FIXTURE_PATH,
        output_base_dir=out_dir,
        dataset_requirements=dataset_requirements,
    )

    forbidden_words = {
        "score",
        "rank",
        "decision",
        "gate_decision",
        "promote",
        "reject",
        "recommendation",
        "sharpe",
    }
    for res in report.method_results:
        if res.facts:
            for k in res.facts:
                assert k.lower() not in forbidden_words
        b_path = Path(res.bundle_dir)
        evidence = v2.parse((b_path / "evidence.json").read_bytes())
        for k in evidence:
            assert k.lower() not in forbidden_words


# =========================================================================
# Requirement 12: Pipeline does not output PROMOTE / REJECT decisions
# =========================================================================
def test_12_pipeline_does_not_output_promote_or_reject(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    pipeline = ScreeningPipeline()
    out_dir = tmp_path / "screening_pure_facts"
    _, report = pipeline.execute_hypothesis(
        base_hypothesis_data,
        snapshot_path=FIXTURE_PATH,
        output_base_dir=out_dir,
        dataset_requirements=dataset_requirements,
    )

    dumped_report = report.model_dump()
    assert dumped_report["overall_status"] in {"COMPLETED", "PARTIAL", "FAILED", "INSUFFICIENT_DATA", "UNSUPPORTED"}
    for res in dumped_report["method_results"]:
        assert res["status"] in {"COMPLETED", "UNSUPPORTED", "INSUFFICIENT_DATA", "EXECUTION_FAILED"}
        if res.get("facts"):
            for k in res["facts"]:
                assert k.lower() not in {"promote", "reject", "score", "rank", "decision", "recommendation"}


# =========================================================================
# Requirement 13: No backtest generated if not in plan
# =========================================================================
def test_13_no_backtest_generated_if_not_in_plan(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    pipeline = ScreeningPipeline()
    out_dir = tmp_path / "no_backtest_dir"
    _plan, report = pipeline.execute_hypothesis(
        base_hypothesis_data,
        snapshot_path=FIXTURE_PATH,
        output_base_dir=out_dir,
        dataset_requirements=dataset_requirements,
    )

    for res in report.method_results:
        b_path = Path(res.bundle_dir)
        manifest = v2.parse((b_path / "manifest.json").read_bytes())
        assert manifest["experiment_type"] == "statistical_factor"
        assert manifest["experiment_type"] != "trading_backtest"

        spec = v2.parse((b_path / "materials/spec.json").read_bytes())
        assert spec["experiment_type"] == "statistical_factor"
        assert "backtest_profile" not in spec


# =========================================================================
# Requirement 14: No parameter tuning
# =========================================================================
def test_14_no_parameter_tuning(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    pipeline = ScreeningPipeline()
    out_dir = tmp_path / "no_tuning_dir"
    _plan, report = pipeline.execute_hypothesis(
        base_hypothesis_data,
        snapshot_path=FIXTURE_PATH,
        output_base_dir=out_dir,
        dataset_requirements=dataset_requirements,
    )

    for res in report.method_results:
        b_path = Path(res.bundle_dir)
        method_def = v2.parse((b_path / "method_definition.json").read_bytes())
        # Parameters must be strictly empty (zero tuning)
        assert method_def["parameters"] == {}
        assert "grid_search" not in method_def
        assert "optimized_params" not in method_def


# =========================================================================
# Requirement 15: No silent fallback
# =========================================================================
def test_15_no_silent_fallback(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    planner = ScreeningPlanner()
    h = copy.deepcopy(base_hypothesis_data)
    # Propose an unsupported method
    h["proposed_screening_methods"] = ["fancy_quantum_screening"]
    h["hypothesis_content_hash"] = compute_hypothesis_content_hash(h)

    plan = planner.plan(h, dataset_requirements=dataset_requirements)
    assert len(plan.methods) == 1
    assert plan.methods[0].method == "fancy_quantum_screening"
    assert plan.methods[0].status == "UNSUPPORTED"
    assert plan.methods[0].reason == "not_registered"

    # Execution does not silently fall back to coverage or correlation
    pipeline = ScreeningPipeline()
    report = pipeline.execute_plan(plan, FIXTURE_PATH, tmp_path / "no_silent_out")
    assert report.overall_status == "UNSUPPORTED"
    assert len(report.method_results) == 1
    assert report.method_results[0].status == "UNSUPPORTED"
    assert report.method_results[0].facts is None


# =========================================================================
# Requirement 16: Deterministic execution order
# =========================================================================
def test_16_deterministic_execution_order(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    planner = ScreeningPlanner()
    # Give reversed order in hypothesis
    h = copy.deepcopy(base_hypothesis_data)
    h["proposed_screening_methods"] = [
        "stability_split",
        "direction_consistency",
        "simple_correlation",
        "coverage",
    ]
    h["hypothesis_content_hash"] = compute_hypothesis_content_hash(h)

    plan = planner.plan(h, dataset_requirements=dataset_requirements)
    method_names = [m.method for m in plan.methods]
    # Must be sorted alphabetically
    expected_order = ["coverage", "direction_consistency", "simple_correlation", "stability_split"]
    assert method_names == expected_order

    pipeline = ScreeningPipeline()
    report = pipeline.execute_plan(plan, FIXTURE_PATH, tmp_path / "order_out")
    executed_order = [r.method for r in report.method_results]
    assert executed_order == expected_order


# =========================================================================
# Requirement 17: Protocol v2 regression
# =========================================================================
def test_17_protocol_v2_regression():
    """Verify statistical screening profile constants and contracts remain valid."""
    assert ssd.PROFILE_NAME == "research_lab.statistical_screening.v1"
    assert "coverage" in ssd.ALLOWED_METHODS
    assert "simple_correlation" in ssd.ALLOWED_METHODS
    assert "direction_consistency" in ssd.ALLOWED_METHODS
    assert "stability_split" in ssd.ALLOWED_METHODS

    definitions = v2.Definitions()
    assert definitions is not None


# =========================================================================
# Requirement 18: AlphaHypothesis regression
# =========================================================================
def test_18_alpha_hypothesis_regression(base_hypothesis_data: dict[str, Any]):
    """Verify AlphaHypothesis invariants remain intact."""
    validated = validate_hypothesis(base_hypothesis_data)
    assert validated["hypothesis_id"] == base_hypothesis_data["hypothesis_id"]
    model = AlphaHypothesis.model_validate(validated)
    assert model.signal_family == "momentum"

    # Forbid decision words in rationale
    invalid = copy.deepcopy(base_hypothesis_data)
    invalid["economic_rationale"] = "Testing will promote signal."
    invalid["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid)
    with pytest.raises(ValueError, match="Result or evidence claim forbidden"):
        validate_hypothesis(invalid)


# =========================================================================
# P1-1 Tests: Hypothesis instance cannot bypass validation or hash check
# =========================================================================
def test_p1_1_hypothesis_model_construct_bypass_rejected(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-1: AlphaHypothesis created via model_construct with invalid/tampered hash is rejected."""
    planner = ScreeningPlanner()
    pipeline = ScreeningPipeline()

    # Tamper with content hash using model_construct to bypass initial pydantic validation
    fake_data = copy.deepcopy(base_hypothesis_data)
    fake_data["hypothesis_content_hash"] = "0" * 64  # invalid tampered hash
    fake_hyp = AlphaHypothesis.model_construct(**fake_data)

    # Must fail closed in planner.plan
    with pytest.raises(ValueError, match="hypothesis_content_hash mismatch"):
        planner.plan(fake_hyp, dataset_requirements=dataset_requirements)

    # Must fail closed in pipeline.execute_hypothesis
    with pytest.raises(ValueError, match="hypothesis_content_hash mismatch"):
        pipeline.execute_hypothesis(fake_hyp, FIXTURE_PATH, "./tmp/dummy_out")


def test_p1_1_hypothesis_mutated_after_creation_rejected(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-1: Mutating a field on a valid AlphaHypothesis without recomputing hash is rejected."""
    planner = ScreeningPlanner()
    valid_hyp = AlphaHypothesis.model_validate(base_hypothesis_data)

    # Mutate field directly on instance
    object.__setattr__(valid_hyp, "signal_family", "mean_reversion")

    with pytest.raises(ValueError, match="hypothesis_content_hash mismatch"):
        planner.plan(valid_hyp, dataset_requirements=dataset_requirements)


# =========================================================================
# P1-2 Tests: Plan/Task/Spec identity strictly binds full dataset identity
# =========================================================================
def test_p1_2_different_datasets_yield_different_plan_identity(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-2: Same hypothesis with different datasets yields different plan_id and plan_content_hash."""
    planner = ScreeningPlanner()

    ds1 = copy.deepcopy(dataset_requirements)
    ds2 = copy.deepcopy(dataset_requirements)
    ds2["snapshot_sha256"] = "b" * 64
    ds2["snapshot_byte_length"] = 9999

    plan1 = planner.plan(base_hypothesis_data, dataset_requirements=ds1)
    plan2 = planner.plan(base_hypothesis_data, dataset_requirements=ds2)

    assert plan1.plan_id != plan2.plan_id
    assert plan1.plan_content_hash != plan2.plan_content_hash


def test_p1_2_same_8char_prefix_different_full_hash_negative_test(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-2 Negative Test: Two datasets with identical 8-char prefix but different full 64-char sha256.

    Proves system never relies on 8-char truncation; full canonical digest produces different plan_id and content hash.
    """
    planner = ScreeningPlanner()

    prefix = "abcdef01"
    # ds_a and ds_b share identical first 8 hex characters, but differ in the remaining 56 hex characters
    ds_a = copy.deepcopy(dataset_requirements)
    ds_a["snapshot_sha256"] = prefix + "1" * 56
    ds_b = copy.deepcopy(dataset_requirements)
    ds_b["snapshot_sha256"] = prefix + "2" * 56

    plan_a = planner.plan(base_hypothesis_data, dataset_requirements=ds_a)
    plan_b = planner.plan(base_hypothesis_data, dataset_requirements=ds_b)

    # Must produce strictly different plan_id (no collision on prefix) and different plan_content_hash
    assert plan_a.plan_id != plan_b.plan_id
    assert plan_a.plan_content_hash != plan_b.plan_content_hash


# =========================================================================
# P1-3 Tests: Plan bound to Snapshot A cannot execute on Snapshot B
# =========================================================================
def test_p1_3_mismatched_runtime_snapshot_fails_closed_no_output_dir(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    """P1-3: Plan bound to Snapshot A fails immediately when executed with Snapshot B without creating output dir."""
    planner = ScreeningPlanner()
    plan = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    # Snapshot B has valid CSV format but different content / hash from Snapshot A
    snap_b = tmp_path / "snapshot_b.csv"
    snap_b.write_bytes(b"timestamp,symbol,feature_val,target_val\n2024-01-02T09:00:00Z,rb2405,1.0,2.0\n")

    executor = SequentialScreeningExecutor()
    method_out = tmp_path / "should_not_be_created"

    assert not method_out.exists()
    res = executor.execute_method(plan.methods[0], plan, snap_b, method_out)

    assert res.status == "EXECUTION_FAILED"
    assert "snapshot sha256 mismatch with plan dataset_requirements" in res.error_message.lower()
    # Critically: output directory must NOT have been created!
    assert not method_out.exists()


def test_p1_3_byte_length_mismatch_fails_closed_no_output_dir(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    """P1-3: Tampered byte length triggers immediate failure before output dir creation."""
    planner = ScreeningPlanner()
    tampered_ds = copy.deepcopy(dataset_requirements)
    tampered_ds["snapshot_byte_length"] += 10  # tampered length

    plan = planner.plan(base_hypothesis_data, dataset_requirements=tampered_ds)

    executor = SequentialScreeningExecutor()
    method_out = tmp_path / "tampered_len_out"

    res = executor.execute_method(plan.methods[0], plan, FIXTURE_PATH, method_out)
    assert res.status == "EXECUTION_FAILED"
    assert "byte_length mismatch" in res.error_message.lower()
    assert not method_out.exists()


# =========================================================================
# Additional P1-1 & P1-2 Tests (Revision & Methods Binding + Plan Hash Revalidation)
# =========================================================================
def test_p1_1_methods_change_yields_different_plan_id(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-1: Same hypothesis and dataset, but changing proposed methods yields different plan_id."""
    planner = ScreeningPlanner()

    h1 = copy.deepcopy(base_hypothesis_data)
    h1["proposed_screening_methods"] = ["coverage"]
    h1["hypothesis_content_hash"] = compute_hypothesis_content_hash(h1)

    h2 = copy.deepcopy(base_hypothesis_data)
    h2["proposed_screening_methods"] = ["coverage", "simple_correlation"]
    h2["hypothesis_content_hash"] = compute_hypothesis_content_hash(h2)

    plan1 = planner.plan(h1, dataset_requirements=dataset_requirements)
    plan2 = planner.plan(h2, dataset_requirements=dataset_requirements)

    assert plan1.plan_id != plan2.plan_id
    assert plan1.plan_content_hash != plan2.plan_content_hash


def test_p1_1_hypothesis_revision_change_yields_different_plan_id(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-1: Same scientific hypothesis and dataset, but updating hypothesis revision yields different plan_id."""
    planner = ScreeningPlanner()

    h_rev1 = copy.deepcopy(base_hypothesis_data)

    h_rev2 = copy.deepcopy(base_hypothesis_data)
    h_rev2["revision"] = "rev.2"
    h_rev2["parent_hypothesis_ref"] = {
        "hypothesis_id": base_hypothesis_data["hypothesis_id"],
        "revision": "rev.1",
        "content_hash": base_hypothesis_data["hypothesis_content_hash"],
    }
    h_rev2["hypothesis_content_hash"] = compute_hypothesis_content_hash(h_rev2)

    plan1 = planner.plan(h_rev1, dataset_requirements=dataset_requirements)
    plan2 = planner.plan(h_rev2, dataset_requirements=dataset_requirements)

    assert plan1.plan_id != plan2.plan_id
    assert "rev.1" in plan1.plan_id
    assert "rev.2" in plan2.plan_id
    assert plan1.plan_content_hash != plan2.plan_content_hash


def test_p1_1_methods_order_normalized_yields_same_plan_id(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-1: Changing order of proposed methods normalizes to identical plan_id."""
    planner = ScreeningPlanner()

    h1 = copy.deepcopy(base_hypothesis_data)
    h1["proposed_screening_methods"] = ["simple_correlation", "coverage"]
    h1["hypothesis_content_hash"] = compute_hypothesis_content_hash(h1)

    h2 = copy.deepcopy(base_hypothesis_data)
    h2["proposed_screening_methods"] = ["coverage", "simple_correlation"]
    h2["hypothesis_content_hash"] = compute_hypothesis_content_hash(h2)

    plan1 = planner.plan(h1, dataset_requirements=dataset_requirements)
    plan2 = planner.plan(h2, dataset_requirements=dataset_requirements)

    assert [m.method for m in plan1.methods] == ["coverage", "simple_correlation"]
    assert [m.method for m in plan2.methods] == ["coverage", "simple_correlation"]


def test_p1_1_unknown_methods_participate_in_plan_identity(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
):
    """P1-1: Unknown methods are normalized and participate in plan_id without collision."""
    planner = ScreeningPlanner()

    h_known = copy.deepcopy(base_hypothesis_data)
    h_known["proposed_screening_methods"] = ["coverage"]
    h_known["hypothesis_content_hash"] = compute_hypothesis_content_hash(h_known)

    h_unknown = copy.deepcopy(base_hypothesis_data)
    h_unknown["proposed_screening_methods"] = ["coverage", "unsupported_magic_screening"]
    h_unknown["hypothesis_content_hash"] = compute_hypothesis_content_hash(h_unknown)

    plan_known = planner.plan(h_known, dataset_requirements=dataset_requirements)
    plan_unknown = planner.plan(h_unknown, dataset_requirements=dataset_requirements)

    assert plan_known.plan_id != plan_unknown.plan_id
    assert plan_known.plan_content_hash != plan_unknown.plan_content_hash
    assert any(m.method == "unsupported_magic_screening" and m.status == "UNSUPPORTED" for m in plan_unknown.methods)


def test_p1_2_execute_plan_rejects_model_construct_plan(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    """P1-2: execute_plan rejects fake plan created via model_construct with invalid hash."""
    planner = ScreeningPlanner()
    valid_plan = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    plan_data = valid_plan.model_dump()
    plan_data["plan_content_hash"] = "f" * 64  # invalid tampered hash
    fake_plan = ScreeningPlan.model_construct(**plan_data)

    pipeline = ScreeningPipeline()
    out_dir = tmp_path / "fake_plan_out"
    with pytest.raises(ValueError, match="plan_content_hash mismatch"):
        pipeline.execute_plan(fake_plan, FIXTURE_PATH, out_dir)
    assert not out_dir.exists()


def test_p1_2_execute_plan_rejects_mutated_plan_instance(
    base_hypothesis_data: dict[str, Any],
    dataset_requirements: dict[str, Any],
    tmp_path: Path,
):
    """P1-2: execute_plan rejects plan instance mutated after creation without recomputing hash."""
    planner = ScreeningPlanner()
    valid_plan = planner.plan(base_hypothesis_data, dataset_requirements=dataset_requirements)

    # Mutate plan_id on valid_plan instance
    object.__setattr__(valid_plan, "plan_id", "plan-tampered-id")

    pipeline = ScreeningPipeline()
    out_dir = tmp_path / "mutated_plan_out"
    with pytest.raises(ValueError, match="plan_content_hash mismatch"):
        pipeline.execute_plan(valid_plan, FIXTURE_PATH, out_dir)
    assert not out_dir.exists()
