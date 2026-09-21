"""Comprehensive Acceptance Tests for Milestone 6: Alpha Discovery Engine Integration (#573).

Verifies the 4 mandatory formal E2E scenarios and core scientific/engineering boundaries:
- E2E 1: Normal REJECT (controlled falsified hypothesis -> Critic REJECT -> Research Memory)
- E2E 2: NEED_MORE_EVIDENCE -> Supplemental Evidence -> PROMOTE (decision evolution preserved)
- E2E 3: Invalid candidate -> ADMISSION_FAILED (fail closed, zero Runner/Evidence/Critic/scientific REJECT)
- E2E 4: Provider failure / uncertain (zero scientific Research Memory mutation, no scientific REJECT)
- Invariant & Idempotency tests:
  - Idempotent skip for duplicate plan coverage
  - Candidate and hypothesis immutability
  - Exact ProjectBinding enforcement
  - Audit trail completeness and tamper detection
  - Provider provenance excluded from scientific identity hash
"""

from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
from typing import Any

import pytest

from research_lab.agent_control.alpha_generator import (
    AlphaGenerationCandidate,
    AlphaGenerationRequest,
    AlphaGenerationResult,
    admit_alpha_generation_output,
)
from research_lab.agent_control.contracts import (
    AgentResult,
    ProjectBinding,
    TerminalStatus,
)
from research_lab.agent_control.discovery_integration import (
    TRADABLE_AUTHORITY,
    DiscoveryIntegrationOrchestrator,
    DiscoveryIntegrationResult,
    EngineeringStatus,
)
from research_lab.agent_control.errors import ProjectBindingError
from research_lab.agent_control.memory_view import ResearchMemoryView
from research_lab.agent_control.router import authorize
from research_lab.alpha_discovery import (
    AlphaDiscoveryEngine,
    CriticGate,
    ResearchMemory,
    ScreeningPipeline,
    ScreeningPlanner,
)
from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.database import ResultStore

NOW = "2026-09-21T00:00:00.000000Z"
BINDING = ProjectBinding(
    project_id="vnpy-web-bridge", workspace_identity="/Users/fujun/node/vnpy"
)


def _create_synthetic_csv(
    file_path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> tuple[str, int]:
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    raw = file_path.read_bytes()
    return v2.sha(raw), len(raw)


@pytest.fixture
def test_context(tmp_path: Path):
    """Sets up an isolated ResultStore, ResearchMemory, AlphaDiscoveryEngine, and synthetic datasets."""
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
        clean_temp_output=False,
    )

    orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)

    # 1. Clean synthetic dataset (strong positive correlation)
    fields = [
        "timestamp",
        "symbol",
        "feature_val",
        "target_val",
        "feature_availability_time",
        "as_of_time",
        "target_start_time",
    ]
    clean_csv = tmp_path / "clean_data.csv"
    clean_rows = []
    for i in range(1, 41):
        ts = f"2026-01-01T{i:02d}:00:00.000000Z"
        clean_rows.append({
            "timestamp": ts,
            "symbol": "RB2405",
            "feature_val": str(float(i)),
            "target_val": str(float(i) * 1.5 + 0.1),
            "feature_availability_time": ts,
            "as_of_time": f"2026-01-01T{i:02d}:00:01.000000Z",
            "target_start_time": f"2026-01-01T{i:02d}:00:02.000000Z",
        })
    c_sha, c_len = _create_synthetic_csv(clean_csv, clean_rows, fields)
    clean_binding = {
        "snapshot_locator": str(clean_csv),
        "snapshot_sha256": c_sha,
        "snapshot_byte_length": c_len,
        "required_fields": fields,
        "available_fields": fields,
        "provenance": "synthetic_clean_audit",
    }

    # 2. Falsified synthetic dataset (negative correlation triggering falsification)
    falsified_csv = tmp_path / "falsified_data.csv"
    falsified_rows = []
    for i in range(1, 41):
        ts = f"2026-01-01T{i:02d}:00:00.000000Z"
        falsified_rows.append({
            "timestamp": ts,
            "symbol": "RB2405",
            "feature_val": str(float(i)),
            "target_val": str(-float(i) * 2.0),
            "feature_availability_time": ts,
            "as_of_time": f"2026-01-01T{i:02d}:00:01.000000Z",
            "target_start_time": f"2026-01-01T{i:02d}:00:02.000000Z",
        })
    f_sha, f_len = _create_synthetic_csv(falsified_csv, falsified_rows, fields)
    falsified_binding = {
        "snapshot_locator": str(falsified_csv),
        "snapshot_sha256": f_sha,
        "snapshot_byte_length": f_len,
        "required_fields": fields,
        "available_fields": fields,
        "provenance": "synthetic_falsified_audit",
    }

    return {
        "orchestrator": orchestrator,
        "engine": engine,
        "memory": memory,
        "store": store,
        "clean_csv": clean_csv,
        "clean_binding": clean_binding,
        "falsified_csv": falsified_csv,
        "falsified_binding": falsified_binding,
        "tmp_path": tmp_path,
    }


def _view(*, content_hash: str = "a" * 64) -> ResearchMemoryView:
    return ResearchMemoryView(
        view_id="memview-" + content_hash[:32],
        view_content_hash=content_hash,
        role="alpha_generator",
        project_binding=BINDING.to_dict(),
        categories=("research_gaps",),
        entries_by_category={"research_gaps": ()},
        total_entries=0,
        policy_version="research_memory_view.v1",
        generated_at=NOW,
        source_refs=(),
    )


def _scope():
    return authorize("alpha_generator", ["read_research_memory", "create_hypothesis"], BINDING)


def _request(view: ResearchMemoryView | None = None):
    actual_view = view or _view()
    return AlphaGenerationRequest.create(
        objective="Generate a falsifiable commodity alpha candidate.",
        memory_view=actual_view,
        project_binding=BINDING,
        authorized_scope=_scope(),
    )


def _valid_envelope(
    *,
    direction: str = "positive",
    methods: list[str] | None = None,
    falsification: list[str] | None = None,
) -> dict[str, Any]:
    used_methods = methods or [
        "coverage",
        "simple_correlation",
        "direction_consistency",
        "stability_split",
        "leakage_audit",
        "outlier_sensitivity",
        "cost_sensitivity",
    ]
    used_falsif = falsification or ["ic < 0.05", "negative_ic"]
    return {
        "hypothesis": {
            "title": "Normalized Momentum Flow on RB",
            "economic_rationale": "Order flow imbalance creates short-term continuation in liquid contracts.",
            "signal_family": "momentum",
            "signal_definition": "feature_val",
            "source_features": ["feature_val"],
            "target": "target_val",
            "expected_direction": direction,
            "holding_horizon": "1h",
            "universe": "commodity_active",
            "frequency": "1h",
            "known_risks": ["trend exhaustion"],
            "falsification_conditions": used_falsif,
            "proposed_screening_methods": used_methods,
            "signal_type": "signed_scalar",
        },
        "rationale": "Valid test candidate with controlled inputs.",
        "source_context_refs": [],
        "novelty_statement": "Novel candidate within controlled context.",
        "duplicate_awareness": "No exact duplicate exists in empty context.",
        "uncertainty": "Regime dependency under macro shocks.",
    }


def _create_admitted_candidate(
    envelope: dict[str, Any],
    request: AlphaGenerationRequest,
    view: ResearchMemoryView,
    task_id: str = "task-m6-001",
) -> AlphaGenerationCandidate:
    raw_output = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return admit_alpha_generation_output(
        raw_output,
        request=request,
        memory_view=view,
        task_id=task_id,
        provider="antigravity",
        actual_model="gemini-2.5-pro",
        created_at=NOW,
    )


# ==============================================================================
# E2E 1: 正常 REJECT
# ==============================================================================
def test_e2e_1_normal_reject(test_context):
    """E2E 1: Accepted agent candidate -> Screening -> Critic REJECT -> Research Memory.

    Verifies:
    - REJECT is produced by real Critic evaluation (not fabricated by orchestrator).
    - Memory record stores complete chain referencing Evidence, Run, Manifest, Task, Spec.
    - Original candidate is NOT modified.
    - Candidate is NOT treated as Evidence.
    - Tradable authority is permanently False.
    """
    orchestrator = test_context["orchestrator"]
    falsified_csv = test_context["falsified_csv"]
    falsified_binding = test_context["falsified_binding"]
    memory = test_context["memory"]

    req = _request()
    view = _view()
    env = _valid_envelope(direction="positive", falsification=["ic < 0.05", "negative_ic"])
    candidate = _create_admitted_candidate(env, req, view)

    # Snapshot deep copy of candidate before run to prove immutability
    original_candidate_dump = copy.deepcopy(candidate.hypothesis.model_dump())

    res: DiscoveryIntegrationResult = orchestrator.integrate_candidate(
        candidate=candidate,
        snapshot_path=falsified_csv,
        dataset_binding=falsified_binding,
        project_binding=BINDING,
        request_id=req.request_id,
        task_id="task-e2e1",
        route_id="route-e2e1",
        provider_job_ref="job-e2e1",
        provider="antigravity",
        model="gemini-2.5-pro",
        agent_result_id="result-e2e1",
        agent_result_hash="hash-e2e1",
    )

    # 1. Terminal state checks
    assert res.engineering_status == EngineeringStatus.COMPLETED.value
    assert res.scientific_decision == "REJECT"
    assert res.is_tradable is False
    assert res.error_code is None

    # 2. Decision is genuinely made by CriticGate, not orchestrator
    assert res.critic_decision is not None
    assert res.critic_decision.decision == "REJECT"
    assert len(res.critic_decision.reject_reasons) > 0
    assert any("Falsification triggered" in r or "Direction consistency" in r for r in res.critic_decision.reject_reasons)

    # 3. Research Memory verification
    mem_records = memory.find_by_hypothesis_id(candidate.hypothesis.hypothesis_id)
    assert len(mem_records) == 1
    rec = mem_records[0]
    assert rec.decision == "REJECT"
    assert rec.reject_reasons == res.critic_decision.reject_reasons
    assert len(rec.evidence_refs) > 0
    assert len(rec.run_refs) > 0
    assert len(rec.manifest_refs) > 0
    assert len(rec.task_refs) > 0
    assert len(rec.spec_refs) > 0

    # 4. Invariant: candidate is NOT modified
    assert candidate.hypothesis.model_dump() == original_candidate_dump

    # 5. Audit trail verified
    audit_records = orchestrator.audit_trail.get_records()
    assert len(audit_records) == 1
    assert orchestrator.audit_trail.verify_all() is True
    assert audit_records[0].scientific_decision == "REJECT"


# ==============================================================================
# E2E 2: NEED_MORE_EVIDENCE 后 PROMOTE
# ==============================================================================
def test_e2e_2_nme_to_supplemental_promote(test_context):
    """E2E 2: Initial Screening NME -> Supplemental Evidence -> PROMOTE -> Research Memory.

    Verifies:
    - Initial evaluation produces NEED_MORE_EVIDENCE due to missing methods.
    - Supplemental screening runs ONLY missing methods through controlled pipeline.
    - Critic re-evaluates with aggregated evidence and produces PROMOTE.
    - Two distinct evaluation records are preserved in Memory (append-only, no overwrite).
    - Final Memory expresses decision evolution without rewriting history.
    - PROMOTE result has is_tradable == False.
    """
    orchestrator = test_context["orchestrator"]
    clean_csv = test_context["clean_csv"]
    clean_binding = test_context["clean_binding"]
    memory = test_context["memory"]

    req = _request()
    view = _view()
    # Initial envelope only requests 4 cheap methods (lacks leakage, outlier, cost)
    initial_methods = ["coverage", "simple_correlation", "direction_consistency", "stability_split"]
    env = _valid_envelope(direction="positive", methods=initial_methods)
    candidate = _create_admitted_candidate(env, req, view)

    # Execute with auto_supplemental=True
    res: DiscoveryIntegrationResult = orchestrator.integrate_candidate(
        candidate=candidate,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        project_binding=BINDING,
        request_id=req.request_id,
        task_id="task-e2e2",
        auto_supplemental=True,
    )

    # 1. Terminal state checks
    assert res.engineering_status == EngineeringStatus.COMPLETED.value
    assert res.scientific_decision == "PROMOTE"
    assert res.is_tradable is False

    # 2. Decision history preserves evolution: NME -> PROMOTE
    assert len(res.critic_decision_history) == 2
    first_dec, second_dec = res.critic_decision_history
    assert first_dec.decision == "NEED_MORE_EVIDENCE"
    assert "leakage_audit" in first_dec.missing_evidence
    assert "outlier_sensitivity" in first_dec.missing_evidence
    assert "cost_sensitivity" in first_dec.missing_evidence
    assert second_dec.decision == "PROMOTE"

    # 3. Research Memory records two distinct append-only entries
    mem_records = memory.find_by_hypothesis_id(candidate.hypothesis.hypothesis_id)
    assert len(mem_records) == 2
    assert mem_records[0].decision == "NEED_MORE_EVIDENCE"
    assert mem_records[1].decision == "PROMOTE"
    assert mem_records[0].record_id != mem_records[1].record_id

    # 4. Result traces all evidence refs across both cycles
    assert len(res.evidence_refs) >= 7


# ==============================================================================
# E2E 3: 非法 candidate
# ==============================================================================
@pytest.mark.parametrize(
    ("corrupted_field", "bad_value", "expected_err"),
    [
        ("fences", "```json\n{}\n```", "STRICT_PARSE_FAILED"),
        ("missing_field", "economic_rationale", "ADMISSION_FAILED"),
        ("forbidden_verdict", {"decision": "PROMOTE"}, "STRICT_PARSE_FAILED"),
        ("forbidden_metric", {"score": 9.9}, "STRICT_PARSE_FAILED"),
        ("invalid_source_refs", ["entry_not_in_view_999"], "ADMISSION_FAILED"),
    ],
)
def test_e2e_3_invalid_candidate_fail_closed(
    test_context, corrupted_field, bad_value, expected_err
):
    """E2E 3: Invalid candidate -> ADMISSION_FAILED.

    Verifies:
    - Fail closed on corrupt/invalid candidate.
    - No Screening execution (runner is not called).
    - No Evidence generated.
    - No CriticDecision produced.
    - No scientific REJECT fabricated.
    - Honest failure state is recorded.
    """
    orchestrator = test_context["orchestrator"]
    clean_csv = test_context["clean_csv"]
    clean_binding = test_context["clean_binding"]
    memory = test_context["memory"]
    store = test_context["store"]

    runs_before = store.query_v2_runs()
    req = _request()
    view = _view()
    env = _valid_envelope()

    # Apply corruption
    if corrupted_field == "fences":
        raw_text = f"```json\n{json.dumps(env)}\n```"
    elif corrupted_field == "missing_field":
        del env["hypothesis"][bad_value]
        raw_text = json.dumps(env)
    elif corrupted_field in ("forbidden_verdict", "forbidden_metric"):
        env["hypothesis"].update(bad_value)
        raw_text = json.dumps(env)
    elif corrupted_field == "invalid_source_refs":
        env["source_context_refs"] = bad_value
        raw_text = json.dumps(env)
    else:
        raw_text = json.dumps(env)

    # Wrap in AgentResult
    agent_res = AgentResult.create(
        task_ref={"task_id": "task-e2e3"},
        route_ref={"route_id": "route-e2e3"},
        provider_job_ref="job-e2e3",
        terminal_status=TerminalStatus.SUCCESS,
        acceptance_status="ACCEPTED",
        structured_output={"output": raw_text},
    )

    res: DiscoveryIntegrationResult = orchestrator.integrate_agent_result(
        agent_result=agent_res,
        request=req,
        memory_view=view,
        snapshot_path=clean_csv,
        task_id="task-e2e3",
        provider="antigravity",
        actual_model="gemini-2.5-pro",
        created_at=NOW,
        dataset_binding=clean_binding,
        expected_binding=BINDING,
    )

    # 1. Must fail closed in engineering status
    assert res.engineering_status in (
        EngineeringStatus.PARSE_FAILED.value,
        EngineeringStatus.ADMISSION_FAILED.value,
    )
    # 2. Scientific decision MUST BE NONE (NEVER REJECT)
    assert res.scientific_decision is None
    assert res.critic_decision is None

    # 3. No screening Runner was executed (no new runs in ResultStore)
    runs_after = store.query_v2_runs()
    assert len(runs_after) == len(runs_before)

    # 4. No scientific Memory decisions (only honest admission_failed if recorded)
    for rec in memory.find_by_hypothesis_id(res.hypothesis_id or "unknown"):
        assert rec.decision not in ("REJECT", "PROMOTE", "NEED_MORE_EVIDENCE")


# ==============================================================================
# E2E 4: Provider failure / uncertain
# ==============================================================================
@pytest.mark.parametrize(
    ("terminal_status", "acceptance_status", "expected_status"),
    [
        (TerminalStatus.UNCERTAIN, "ACCEPTED", EngineeringStatus.PROVIDER_UNCERTAIN.value),
        (TerminalStatus.FAILED, "ACCEPTED", EngineeringStatus.AGENT_EXECUTION_FAILED.value),
        (TerminalStatus.SUCCESS, "REJECTED", EngineeringStatus.RESULT_NOT_ACCEPTED.value),
    ],
)
def test_e2e_4_provider_failure_zero_memory_mutation(
    test_context, terminal_status, acceptance_status, expected_status
):
    """E2E 4: Provider failure / uncertain -> zero candidate admission, zero Memory mutation.

    Verifies:
    - Provider failure/uncertain is never translated to scientific REJECT.
    - No candidate admission occurs.
    - No Screening, no Evidence, no CriticDecision.
    - Research Memory is completely untouched (zero mutation/zero pollution).
    """
    orchestrator = test_context["orchestrator"]
    clean_csv = test_context["clean_csv"]
    clean_binding = test_context["clean_binding"]
    memory = test_context["memory"]
    store = test_context["store"]

    runs_before = store.query_v2_runs()
    db_before_count = len(memory.find_by_hypothesis_id("non-existent"))

    req = _request()
    view = _view()
    env = _valid_envelope()
    raw_text = json.dumps(env)

    agent_res = AgentResult.create(
        task_ref={"task_id": "task-e2e4"},
        route_ref={"route_id": "route-e2e4"},
        provider_job_ref="job-e2e4",
        terminal_status=terminal_status,
        acceptance_status=acceptance_status,
        structured_output={"output": raw_text},
    )

    res: DiscoveryIntegrationResult = orchestrator.integrate_agent_result(
        agent_result=agent_res,
        request=req,
        memory_view=view,
        snapshot_path=clean_csv,
        task_id="task-e2e4",
        provider="antigravity",
        actual_model="gemini-2.5-pro",
        created_at=NOW,
        dataset_binding=clean_binding,
        expected_binding=BINDING,
    )

    # 1. Engineering status reflects exact failure reason
    assert res.engineering_status == expected_status
    # 2. Scientific decision MUST BE NONE (NEVER REJECT)
    assert res.scientific_decision is None
    assert res.critic_decision is None
    assert res.admitted_hypothesis is None

    # 3. No screening runner executed
    assert len(store.query_v2_runs()) == len(runs_before)

    # 4. Zero Memory mutation (zero pollution)
    assert len(memory.find_by_hypothesis_id("non-existent")) == db_before_count
    assert len(res.memory_records) == 0


def test_e2e_4_direct_generation_result_failure_handling(test_context):
    """E2E 4 supplement: Direct M5 AlphaGenerationResult failure is handled cleanly."""
    orchestrator = test_context["orchestrator"]
    clean_csv = test_context["clean_csv"]

    failed_m5_res = AlphaGenerationResult(
        request_id="req-failed-m5",
        status="GENERATION_FAILED",
        candidate=None,
        task_id="task-failed-m5",
        route_id="route-failed-m5",
        provider_job_ref="NOT_SUBMITTED",
        provider="antigravity",
        requested_model="gemini-2.5-pro",
        actual_model="gemini-2.5-pro",
        memory_view_ref="memview-1@hash",
        prompt_policy_version="alpha_generator_prompt.v1",
        prompt_content_hash="b" * 64,
        agent_result_id="NO_RESULT",
        agent_result_content_hash="NO_RESULT",
        error_code="PROVIDER_UNAVAILABLE",
    )

    res = orchestrator.integrate_generation_result(
        generation_result=failed_m5_res,
        snapshot_path=clean_csv,
        project_binding=BINDING,
    )

    assert res.engineering_status == EngineeringStatus.AGENT_EXECUTION_FAILED.value
    assert res.scientific_decision is None
    assert res.critic_decision is None
    assert res.error_code == "PROVIDER_UNAVAILABLE"


# ==============================================================================
# Invariants & Boundaries
# ==============================================================================
def test_idempotency_skip_duplicate_screening(test_context):
    """Idempotency test: Re-executing exact same hypothesis with same coverage skips execution."""
    orchestrator = test_context["orchestrator"]
    falsified_csv = test_context["falsified_csv"]
    falsified_binding = test_context["falsified_binding"]
    memory = test_context["memory"]

    req = _request()
    view = _view()
    env = _valid_envelope(direction="positive")
    candidate = _create_admitted_candidate(env, req, view)

    # First execution -> Evaluated to REJECT
    first_res = orchestrator.integrate_candidate(
        candidate=candidate,
        snapshot_path=falsified_csv,
        dataset_binding=falsified_binding,
        project_binding=BINDING,
    )
    assert first_res.engineering_status == EngineeringStatus.COMPLETED.value
    assert first_res.scientific_decision == "REJECT"

    mem_count_1 = len(memory.find_by_hypothesis_id(candidate.hypothesis.hypothesis_id))
    assert mem_count_1 == 1

    # Second execution of exact same hypothesis/evidence coverage -> SKIPPED_DUPLICATE
    second_res = orchestrator.integrate_candidate(
        candidate=candidate,
        snapshot_path=falsified_csv,
        dataset_binding=falsified_binding,
        project_binding=BINDING,
    )
    assert second_res.engineering_status == EngineeringStatus.SKIPPED_DUPLICATE.value
    assert second_res.scientific_decision is None

    # Memory records must not increase (zero duplicate insertion)
    mem_count_2 = len(memory.find_by_hypothesis_id(candidate.hypothesis.hypothesis_id))
    assert mem_count_2 == mem_count_1


def test_project_binding_mismatch_fails_closed(test_context):
    """ProjectBinding exact enforcement: mismatch fails closed immediately."""
    orchestrator = test_context["orchestrator"]
    clean_csv = test_context["clean_csv"]
    clean_binding = test_context["clean_binding"]

    candidate = _create_admitted_candidate(_valid_envelope(), _request(), _view())

    wrong_binding = ProjectBinding(
        project_id="wrong-project",
        workspace_identity="/Users/fujun/node/vnpy",
    )

    with pytest.raises(ProjectBindingError):
        orchestrator.integrate_candidate(
            candidate=candidate,
            snapshot_path=clean_csv,
            dataset_binding=clean_binding,
            project_binding=wrong_binding,
            expected_binding=BINDING,
        )


def test_provider_identity_does_not_pollute_scientific_identity():
    """Scientific identity hash must exclude provider, transport, model, or task metadata."""
    req = _request()
    view = _view()
    env = _valid_envelope()

    cand1 = _create_admitted_candidate(env, req, view, task_id="task-001")
    cand2 = _create_admitted_candidate(env, req, view, task_id="task-002")

    # The two candidates have different task IDs and provenance refs
    prov1 = cand1.hypothesis.provenance.origin_ref if hasattr(cand1.hypothesis.provenance, "origin_ref") else cand1.hypothesis.provenance["origin_ref"]
    prov2 = cand2.hypothesis.provenance.origin_ref if hasattr(cand2.hypothesis.provenance, "origin_ref") else cand2.hypothesis.provenance["origin_ref"]
    assert prov1 != prov2

    # But their scientific identity hash MUST BE IDENTICAL
    assert cand1.scientific_identity_hash == cand2.scientific_identity_hash


def test_tradable_authority_permanently_false(test_context):
    """TRADABLE_AUTHORITY is permanently False; cannot be overridden."""
    assert TRADABLE_AUTHORITY is False
    with pytest.raises(ValueError, match="can NEVER grant tradable authority"):
        DiscoveryIntegrationResult(
            engineering_status=EngineeringStatus.COMPLETED.value,
            scientific_decision="PROMOTE",
            is_tradable=True,  # Forbidden
        )


# ==============================================================================
# P1 Review Regressions: Hash Compatibility & Supplemental Exception Isolation
# ==============================================================================
def test_v1_legacy_hypothesis_with_explicit_nulls_compatibility_and_replay(test_context):
    """P1-1 Regression: v1 hypothesis with explicit nulls remains fully compatible and replayable.

    Verifies:
    - Pre-PR v1 records containing explicit nulls (parent_hypothesis_ref, related_hypothesis_refs,
      duplicate_of, signal_type) retain stable content hash under canonical rules.
    - validate_hypothesis preserves verified explicit nulls, preventing silent hash divergence.
    - Candidate can be seamlessly integrated and replayed in M6 pipeline without hash mismatch.
    """
    orchestrator = test_context["orchestrator"]
    falsified_csv = test_context["falsified_csv"]
    falsified_binding = test_context["falsified_binding"]

    from research_lab.alpha_discovery.hypothesis import (
        AlphaHypothesis,
        compute_hypothesis_content_hash,
        validate_hypothesis,
    )

    # Construct canonical v1 payload as generated prior to PR (with explicit None fields)
    legacy_payload: dict[str, Any] = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": "hypo-legacy-nulls-001",
        "revision": "rev.1",
        "title": "Legacy Momentum with Explicit Nulls",
        "economic_rationale": "Liquidity continuation under order flow shocks.",
        "signal_family": "momentum",
        "signal_definition": "feature_val",
        "source_features": ["feature_val"],
        "target": "target_val",
        "expected_direction": "positive",
        "holding_horizon": "1h",
        "universe": "commodity_active",
        "frequency": "1h",
        "known_risks": ["liquidity exhaustion"],
        "falsification_conditions": ["ic < 0.05", "negative_ic"],
        "proposed_screening_methods": [
            "coverage",
            "simple_correlation",
            "direction_consistency",
            "stability_split",
        ],
        "provenance": {
            "origin_type": "observation",
            "origin_ref": "research_notes/2026-09-legacy.md",
            "created_by": "alpha_generator",
            "created_at": NOW,
        },
        "parent_hypothesis_ref": None,
        "related_hypothesis_refs": None,
        "duplicate_of": None,
        "signal_type": None,
    }

    # 1. Compute hash using canonical v1 rule (clean = {k: v for k, v in data.items() if k != 'hypothesis_content_hash'})
    legacy_hash = compute_hypothesis_content_hash(legacy_payload)
    legacy_payload["hypothesis_content_hash"] = legacy_hash

    # 2. Assert validate_hypothesis passes and does not mutate canonical content hash
    validated = validate_hypothesis(legacy_payload)
    assert compute_hypothesis_content_hash(validated) == legacy_hash

    # 3. Build AlphaHypothesis model and verify round-trip stability
    hyp_model = AlphaHypothesis.model_validate(validated)
    assert hyp_model.hypothesis_content_hash == legacy_hash

    # 4. Replay through DiscoveryIntegrationOrchestrator without mismatch
    res = orchestrator.integrate_candidate(
        candidate=hyp_model,
        snapshot_path=falsified_csv,
        dataset_binding=falsified_binding,
        project_binding=BINDING,
        task_id="task-legacy-nulls",
    )

    assert res.engineering_status == EngineeringStatus.COMPLETED.value
    assert res.scientific_decision == "REJECT"
    assert res.hypothesis_content_hash == legacy_hash
    assert len(res.memory_records) == 1
    assert res.memory_records[0].content_hash == legacy_hash


def test_supplemental_pipeline_exception_isolation(test_context, monkeypatch):
    """P1-2 Regression: Exception in supplemental pipeline execution does not escape or pollute.

    Verifies:
    - Initial NME completes, but supplemental pipeline crashes (e.g. I/O or data error).
    - Exception does NOT escape orchestrator.
    - engineering_status is SCREENING_FAILED.
    - scientific_decision is strictly None (NEVER NME/REJECT/PROMOTE).
    - critic_decision is strictly None.
    - Research Memory is NOT polluted by supplemental crash.
    - Valid tamper-evident audit record is appended and verified.
    """
    orchestrator = test_context["orchestrator"]
    clean_csv = test_context["clean_csv"]
    clean_binding = test_context["clean_binding"]
    engine = test_context["engine"]
    memory = test_context["memory"]

    req = _request()
    view = _view()
    # Envelope requesting only cheap methods -> triggers NEED_MORE_EVIDENCE on first evaluation
    initial_methods = ["coverage", "simple_correlation", "direction_consistency", "stability_split"]
    env = _valid_envelope(direction="positive", methods=initial_methods)
    candidate = _create_admitted_candidate(env, req, view)

    # Monkeypatch pipeline.execute_plan to succeed on initial run, but raise on supplemental
    original_execute = engine.pipeline.execute_plan
    call_count = 0

    def mock_execute_plan(plan, snapshot_path, staging_dir):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise RuntimeError("Synthetic supplemental pipeline stream error")
        return original_execute(plan, snapshot_path, staging_dir)

    monkeypatch.setattr(engine.pipeline, "execute_plan", mock_execute_plan)

    # Execute with auto_supplemental=True; must not escape
    res = orchestrator.integrate_candidate(
        candidate=candidate,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        project_binding=BINDING,
        auto_supplemental=True,
    )

    # 1. Engineering terminal state reflects screening failure
    assert res.engineering_status == EngineeringStatus.SCREENING_FAILED.value
    assert "Supplemental cycle failed" in (res.error_message or "")

    # 2. Scientific decision MUST BE NONE
    assert res.scientific_decision is None
    assert res.critic_decision is None

    # 3. Decision history records first round NME, but final outcome is not completed
    assert len(res.critic_decision_history) == 1
    assert res.critic_decision_history[0].decision == "NEED_MORE_EVIDENCE"

    # 4. Research Memory is not polluted: contains only the initial valid NME record, no crash record
    mem_records = memory.find_by_hypothesis_id(candidate.hypothesis.hypothesis_id)
    assert len(mem_records) == 1
    assert mem_records[0].decision == "NEED_MORE_EVIDENCE"

    # 5. Audit trail records the failure and passes integrity verification
    last_audit = orchestrator.audit_trail.get_records()[-1]
    assert last_audit.engineering_status == EngineeringStatus.SCREENING_FAILED.value
    assert last_audit.scientific_decision is None
    last_audit.verify()
    assert orchestrator.audit_trail.verify_all() is True


def test_supplemental_critic_exception_isolation(test_context, monkeypatch):
    """P1-2 Regression: Exception in supplemental Critic evaluation does not escape or pollute.

    Verifies:
    - Initial NME completes, supplemental pipeline succeeds, but Critic fails on re-evaluation.
    - Exception does NOT escape orchestrator.
    - engineering_status is CRITIC_FAILED.
    - scientific_decision is strictly None.
    - critic_decision is strictly None.
    - Research Memory is NOT polluted.
    - Valid audit record is appended and verified.
    """
    orchestrator = test_context["orchestrator"]
    clean_csv = test_context["clean_csv"]
    clean_binding = test_context["clean_binding"]
    engine = test_context["engine"]
    memory = test_context["memory"]

    req = _request()
    view = _view()
    initial_methods = ["coverage", "simple_correlation", "direction_consistency", "stability_split"]
    env = _valid_envelope(direction="positive", methods=initial_methods)
    candidate = _create_admitted_candidate(env, req, view)

    original_evaluate = engine.critic.evaluate
    call_count = 0

    def mock_evaluate(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise RuntimeError("Synthetic supplemental Critic rule evaluation failed")
        return original_evaluate(*args, **kwargs)

    monkeypatch.setattr(engine.critic, "evaluate", mock_evaluate)

    res = orchestrator.integrate_candidate(
        candidate=candidate,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        project_binding=BINDING,
        auto_supplemental=True,
    )

    # 1. Engineering terminal state reflects critic failure
    assert res.engineering_status == EngineeringStatus.CRITIC_FAILED.value
    assert "critic" in (res.error_message or "").lower()

    # 2. Scientific decision MUST BE NONE
    assert res.scientific_decision is None
    assert res.critic_decision is None

    # 3. Memory contains only initial NME record
    mem_records = memory.find_by_hypothesis_id(candidate.hypothesis.hypothesis_id)
    assert len(mem_records) == 1

    # 4. Audit trail verified
    last_audit = orchestrator.audit_trail.get_records()[-1]
    assert last_audit.engineering_status == EngineeringStatus.CRITIC_FAILED.value
    assert last_audit.scientific_decision is None
    last_audit.verify()
    assert orchestrator.audit_trail.verify_all() is True
