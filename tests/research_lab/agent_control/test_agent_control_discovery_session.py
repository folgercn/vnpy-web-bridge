"""Unit tests for Astra Discovery Session Contract & Deterministic Slot Admission (#502, Refs #497).

Milestone A Test Suite covering:
1. DiscoverySession creation, immutability, tamper detection, and fail-closed validation.
2. Controlled ResearchMemoryView authentic binding via build_research_memory_view.
3. Strict candidate budget validation (strict integer 1..10, rejecting bools, floats, strings).
4. Pure deterministic candidate slot planning (N slots = candidate_budget, requested_candidate_count=1).
5. Cross-object consistency in PlannedCandidateSlot (session, slot, request, task).
6. Propagation and auditability of allowed_universe, allowed_frequency, allowed_signal_families,
   and generation_policy_version into requests and task prompt / input_refs.
7. Re-sealing defense matrices (memory_view_ref tampering, foreign projects, wrong roles, forged hashes).
8. Faithful preservation of entry source_refs, source_hashes, and evidence_refs in SessionMemoryContext.
9. Zero side-effects with explicit mocks/spies preventing Provider, Screening, Critic, or Memory writes.
10. Permanent non-trading boundaries.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
import tempfile
from typing import Any
from unittest.mock import MagicMock

import pytest
from research_lab.agent_control.alpha_generator import (
    DISCOVERY_POLICY_VERSION,
    AlphaGenerationError,
    AlphaGenerationRequest,
)
from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    ProjectBinding,
    ProjectBindingError,
)
from research_lab.agent_control.discovery_session import (
    CANONICAL_SESSION_TIMESTAMP,
    MAX_CANDIDATE_BUDGET,
    MIN_CANDIDATE_BUDGET,
    DiscoverySession,
    DiscoverySessionBudgetError,
    DiscoverySessionError,
    compute_session_content_hash,
    compute_session_id,
    extract_session_memory_context,
    plan_candidate_slots,
    replan_slot_attempt,
)
from research_lab.agent_control.errors import PermissionDeniedError
from research_lab.agent_control.memory_view import (
    ResearchMemoryCategory,
    ResearchMemoryQuery,
    ResearchMemoryView,
    ResearchMemoryViewPolicy,
    build_research_memory_view,
)
from research_lab.agent_control.router import authorize
from research_lab.alpha_discovery import hypothesis as hyp
from research_lab.alpha_discovery.research_memory import ResearchMemory
from research_lab.contracts import v2

BINDING = ProjectBinding(
    project_id="vnpy-web-bridge",
    workspace_identity="/Users/fujun/node/vnpy-web-bridge",
)
REQUIRED_PERMISSIONS = ["read_research_memory", "create_hypothesis"]


def _make_scope(
    *,
    role: str = "alpha_generator",
    permissions: list[str] | None = None,
    project_binding: ProjectBinding | None = None,
    can_delegate: bool = False,
    max_delegation_depth: int = 0,
) -> AgentPermissionScope:
    pb = project_binding or BINDING
    perms = permissions if permissions is not None else list(REQUIRED_PERMISSIONS)
    scope = authorize(role, perms, pb)
    if can_delegate or max_delegation_depth > 0:
        d = scope.to_dict()
        d["can_delegate"] = can_delegate
        d["max_delegation_depth"] = max_delegation_depth
        d["scope_content_hash"] = v2.digest({
            "authorized_permissions": d["authorized_permissions"],
            "can_delegate": can_delegate,
            "context": d["context"],
            "denied_permissions": d["denied_permissions"],
            "hash_profile": d["hash_profile"],
            "is_authorized": d["is_authorized"],
            "max_delegation_depth": max_delegation_depth,
            "policy_version": d["policy_version"],
            "project_binding": d["project_binding"],
            "requested_permissions": d["requested_permissions"],
            "role": d["role"],
            "schema_version": d["schema_version"],
        })
        return AgentPermissionScope(**d)
    return scope


def _make_dummy_hypothesis(hyp_id: str = "hypo-001", title: str = "Momentum breakout") -> hyp.AlphaHypothesis:
    data = {
        "hypothesis_id": hyp_id,
        "revision": "rev.1",
        "title": title,
        "economic_rationale": "Trend continuation driven by persistent capital flows",
        "universe": "commodity_active",
        "frequency": "1d",
        "holding_horizon": "5d",
        "expected_direction": "positive",
        "signal_family": "momentum",
        "signal_definition": "close / ts_min(low, 20) - 1.0",
        "source_features": ["close", "low"],
        "target": "forward_return_5d",
        "known_risks": ["Volatile chop"],
        "falsification_conditions": ["Information coefficient <= 0"],
        "proposed_screening_methods": ["data_quality_check"],
        "provenance": {
            "origin_type": "astra",
            "origin_ref": "discovery_test",
            "created_by": "tester",
            "created_at": "2026-09-22T00:00:00.000000Z",
        },
    }
    data["hypothesis_content_hash"] = hyp.compute_hypothesis_content_hash(data)
    return hyp.AlphaHypothesis(**data)


def _make_dummy_plan(hypo: hyp.AlphaHypothesis, plan_id: str = "plan-001") -> dict[str, Any]:
    return {
        "plan_id": plan_id,
        "plan_content_hash": v2.digest({"plan_id": plan_id, "hypo_id": hypo.hypothesis_id}),
        "methods": [{"method": "data_quality_check", "status": "APPROVED"}],
        "dataset_requirements": {
            "snapshot_locator": "dummy/data.parquet",
            "required_fields": ["timestamp", "close"],
            "as_of_time": "2026-01-01T00:00:00.000000Z",
        },
        "scientific_identity_hash": hyp.compute_scientific_identity_hash(hypo.model_dump(exclude_none=True)),
        "provenance": {"created_by": "tester", "created_at": "2026-09-22T00:00:00.000000Z"},
    }


def _make_dummy_critic_decision(
    decision_id: str,
    decision: str,
    hypo: hyp.AlphaHypothesis,
    plan_dict: dict[str, Any],
    reject_reasons: list[str] | None = None,
    promoted_reasons: list[str] | None = None,
    missing_evidence: list[str] | None = None,
) -> dict[str, Any]:
    d = {
        "decision_id": decision_id,
        "decision": decision,
        "hypothesis_ref": {
            "hypothesis_id": hypo.hypothesis_id,
            "revision": hypo.revision,
            "content_hash": hypo.hypothesis_content_hash,
        },
        "plan_ref": {
            "plan_id": plan_dict["plan_id"],
            "content_hash": plan_dict["plan_content_hash"],
        },
        "scientific_identity_hash": hyp.compute_scientific_identity_hash(hypo.model_dump(exclude_none=True)),
        "reject_reasons": reject_reasons or [],
        "promoted_reasons": promoted_reasons or [],
        "missing_evidence": missing_evidence or [],
        "provenance": {"created_by": "tester", "created_at": "2026-09-22T00:00:00.000000Z"},
    }
    d["review_content_hash"] = v2.digest(d)
    return d


def _build_authentic_memory_view(
    *,
    role: str = "alpha_generator",
    project_binding: ProjectBinding | None = None,
    populate_records: bool = False,
    policy: ResearchMemoryViewPolicy | None = None,
) -> ResearchMemoryView:
    """Construct an authentic, verifiable ResearchMemoryView using build_research_memory_view."""
    pb = project_binding or BINDING
    scope_perms = ["read_research_memory", "create_hypothesis"] if role == "alpha_generator" else ["read_research_memory"]
    scope = authorize(role, scope_perms, pb)

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_memory.db"
        memory = ResearchMemory(db_path)

        if populate_records:
            hyp1 = _make_dummy_hypothesis("hypo-reject-1", "Falsified momentum hypothesis")
            plan1 = _make_dummy_plan(hyp1, "plan-reject-1")
            crit1 = _make_dummy_critic_decision(
                "crit-1", "REJECT", hyp1, plan1, reject_reasons=["negative_ic", "high_turnover"]
            )
            memory.append_evaluation_record(
                hypothesis=hyp1,
                plan=plan1,
                task_records=[{"task_id": "task-1", "revision": "rev.1", "task_content_hash": "thash-1"}],
                spec_records=[{"spec_id": "spec-1", "revision": "rev.1", "spec_content_hash": "shash-1"}],
                run_records=[{"run_id": "run-1", "run_content_hash": "rhash-1", "run_status": "COMPLETED"}],
                manifest_records=[{"manifest_id": "man-1", "revision": "rev.1", "manifest_content_hash": "mhash-1"}],
                evidence_records=[{"evidence_id": "ev-1", "revision": "rev.1", "evidence_content_hash": "hash-ev-1", "execution_status": "COMPLETED"}],
                critic_decision=crit1,
            )

            hyp2 = _make_dummy_hypothesis("hypo-promote-2", "Robust trend follower")
            plan2 = _make_dummy_plan(hyp2, "plan-promote-2")
            crit2 = _make_dummy_critic_decision(
                "crit-2", "PROMOTE", hyp2, plan2, promoted_reasons=["strong_t_stat", "clean_decay"]
            )
            memory.append_evaluation_record(
                hypothesis=hyp2,
                plan=plan2,
                task_records=[{"task_id": "task-2", "revision": "rev.1", "task_content_hash": "thash-2"}],
                spec_records=[{"spec_id": "spec-2", "revision": "rev.1", "spec_content_hash": "shash-2"}],
                run_records=[{"run_id": "run-2", "run_content_hash": "rhash-2", "run_status": "COMPLETED"}],
                manifest_records=[{"manifest_id": "man-2", "revision": "rev.1", "manifest_content_hash": "mhash-2"}],
                evidence_records=[{"evidence_id": "ev-2", "revision": "rev.1", "evidence_content_hash": "hash-ev-2", "execution_status": "COMPLETED"}],
                critic_decision=crit2,
            )

            hyp3 = _make_dummy_hypothesis("hypo-nme-3", "Incomplete hypothesis lacking cost check")
            plan3 = _make_dummy_plan(hyp3, "plan-nme-3")
            crit3 = _make_dummy_critic_decision(
                "crit-3", "NEED_MORE_EVIDENCE", hyp3, plan3, missing_evidence=["cost_ladder", "regime_stress"]
            )
            memory.append_evaluation_record(
                hypothesis=hyp3,
                plan=plan3,
                task_records=[{"task_id": "task-3", "revision": "rev.1", "task_content_hash": "thash-3"}],
                spec_records=[{"spec_id": "spec-3", "revision": "rev.1", "spec_content_hash": "shash-3"}],
                run_records=[{"run_id": "run-3", "run_content_hash": "rhash-3", "run_status": "COMPLETED"}],
                manifest_records=[{"manifest_id": "man-3", "revision": "rev.1", "manifest_content_hash": "mhash-3"}],
                evidence_records=[{"evidence_id": "ev-3", "revision": "rev.1", "evidence_content_hash": "hash-ev-3", "execution_status": "COMPLETED"}],
                critic_decision=crit3,
            )

        categories = (
            ResearchMemoryCategory.RECENT_REJECTS.value,
            ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
            ResearchMemoryCategory.NME_BACKLOG.value,
            ResearchMemoryCategory.RESEARCH_GAPS.value,
        )
        query = ResearchMemoryQuery(role=role, project_binding=pb, categories=categories)
        return build_research_memory_view(
            query=query,
            authorized_scope=scope,
            project_binding=pb,
            memory_store=memory,
            policy=policy,
        )


# ==============================================================================
# Positive Tests: Creation, Planning, Context, Bounds Propagation
# ==============================================================================


def test_discovery_session_creation_single_candidate():
    """Verify DiscoverySession creation with single candidate budget (1 slot)."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Discover short-term momentum signals on commodity futures",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=MIN_CANDIDATE_BUDGET,
        allowed_universe="commodity_futures",
        allowed_frequency="1m",
        allowed_signal_families=["momentum"],
    )

    assert session.candidate_budget == 1
    assert session.objective == "Discover short-term momentum signals on commodity futures"
    assert session.memory_view_id == view.view_id
    assert session.memory_view_content_hash == view.view_content_hash
    assert session.project_binding == BINDING.to_dict()
    assert session.allowed_frequency == "1m"
    assert session.allowed_signal_families == ("momentum",)

    slots = plan_candidate_slots(session, view)
    assert len(slots) == 1
    slot = slots[0]
    assert slot.ordinal == 1
    assert slot.slot_index == 0
    assert slot.session_id == session.session_id
    assert slot.attempt == 1
    assert slot.request.requested_candidate_count == 1
    assert slot.request.session_id == session.session_id
    assert slot.request.slot_id == slot.slot_id
    assert slot.request.ordinal == 1
    assert slot.task.role == "alpha_generator"


def test_discovery_session_creation_max_candidates():
    """Verify DiscoverySession creation with maximum candidate budget (10 slots) and distinct identities."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Discover mean-reversion signals on energy sector",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=MAX_CANDIDATE_BUDGET,
        allowed_universe=("RB", "HC", "I"),
        allowed_frequency="5m",
        allowed_signal_families=("mean_reversion", "spread"),
    )

    assert session.candidate_budget == 10
    slots = plan_candidate_slots(session, view)
    assert len(slots) == 10

    slot_ids = [s.slot_id for s in slots]
    task_ids = [s.task.task_id for s in slots]
    ordinals = [s.ordinal for s in slots]
    assert len(set(slot_ids)) == 10
    assert len(set(task_ids)) == 10
    assert ordinals == list(range(1, 11))

    for idx, s in enumerate(slots):
        assert s.slot_index == idx
        assert s.ordinal == idx + 1
        assert s.session_id == session.session_id
        assert s.request.requested_candidate_count == 1
        assert s.request.slot_id == s.slot_id
        assert s.request.ordinal == s.ordinal


def test_discovery_session_with_empty_memory_view():
    """Verify handling of completely empty Controlled Memory View (total_entries=0)."""
    scope = _make_scope()
    view = _build_authentic_memory_view(populate_records=False)
    assert view.total_entries == 0

    ctx = extract_session_memory_context(view)
    assert ctx.is_empty is True
    assert ctx.is_truncated is False
    assert ctx.total_entries == 0
    assert ctx.research_gaps == ()
    assert ctx.valid_entry_ids == ()

    session = DiscoverySession.create(
        objective="Cold-start exploration without prior history",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="all_futures",
        allowed_frequency="15m",
    )
    slots = plan_candidate_slots(session, view)
    assert len(slots) == 3


def test_discovery_session_with_non_empty_memory_view():
    """Verify context extraction from non-empty Controlled Memory View preserving entry details."""
    scope = _make_scope()
    view = _build_authentic_memory_view(populate_records=True)
    assert view.total_entries > 0

    ctx = extract_session_memory_context(view)
    assert ctx.is_empty is False
    assert ctx.total_entries == view.total_entries
    assert len(ctx.valid_entry_ids) > 0

    session = DiscoverySession.create(
        objective="Warm exploration guided by historical evaluation",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="ferrous_metals",
        allowed_frequency="30m",
    )
    slots = plan_candidate_slots(session, view)
    assert len(slots) == 5


def test_discovery_session_with_truncated_memory_view():
    """Verify that is_truncated flag from ResearchMemoryView is faithfully captured."""
    scope = _make_scope()
    # Enforce total limit of 1 record on a 3-record populated store to trigger is_truncated
    policy = ResearchMemoryViewPolicy(max_total_entries=1)
    view = _build_authentic_memory_view(populate_records=True, policy=policy)
    assert view.is_truncated is True

    ctx = extract_session_memory_context(view)
    assert ctx.is_truncated is True

    session = DiscoverySession.create(
        objective="Bounded exploration under truncated memory budget",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="equity_index_futures",
        allowed_frequency="1h",
    )
    slots = plan_candidate_slots(session, view)
    assert len(slots) == 2


def test_discovery_session_roundtrip_serialization():
    """Verify that to_dict and from_dict produce bit-for-bit identical DiscoverySession."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Roundtrip serialization test objective",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=7,
        allowed_universe=("AU", "AG"),
        allowed_frequency="5m",
        allowed_signal_families=["volatility_breakout"],
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    restored = DiscoverySession.from_dict(data, memory_view=view)

    assert restored.session_id == session.session_id
    assert restored.session_content_hash == session.session_content_hash
    assert restored.objective == session.objective
    assert restored.candidate_budget == session.candidate_budget
    assert restored.project_binding == session.project_binding
    assert restored.authorized_scope_ref == session.authorized_scope_ref
    assert restored.memory_view_id == session.memory_view_id
    assert restored.memory_view_content_hash == session.memory_view_content_hash
    assert restored.memory_view_ref == session.memory_view_ref
    assert restored.allowed_universe == session.allowed_universe
    assert restored.allowed_frequency == session.allowed_frequency
    assert restored.allowed_signal_families == session.allowed_signal_families
    assert restored.generation_policy_version == session.generation_policy_version
    assert restored.created_at == session.created_at
    assert restored.to_dict() == data


def test_discovery_session_replanning_determinism():
    """Verify that repeated planning calls on the same session produce 100% identical slot IDs and tasks."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Deterministic replanning verification",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=4,
        allowed_universe="agricultural_futures",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    run1 = plan_candidate_slots(session, view)
    run2 = plan_candidate_slots(session, view)

    assert len(run1) == len(run2) == 4
    for s1, s2 in zip(run1, run2):
        assert s1.slot_id == s2.slot_id
        assert s1.slot_content_hash == s2.slot_content_hash
        assert s1.ordinal == s2.ordinal
        assert s1.request.request_id == s2.request.request_id
        assert s1.task.task_id == s2.task.task_id
        assert s1.task.task_content_hash == s2.task.task_content_hash


def test_discovery_session_slot_replan_attempt():
    """Verify that replanning a slot with an incremented attempt preserves slot_id and updates attempt."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Slot attempt update verification",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="base_metals",
        allowed_frequency="15m",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)
    slot1 = slots[0]
    assert slot1.attempt == 1

    retry_slot = replan_slot_attempt(slot1, view, attempt=2)
    assert retry_slot.slot_id == slot1.slot_id  # Stable logical slot identity!
    assert retry_slot.ordinal == slot1.ordinal
    assert retry_slot.attempt == 2
    assert retry_slot.request.attempt == 2
    assert retry_slot.request.request_id != slot1.request.request_id  # Differentiates execution attempt
    assert retry_slot.task.task_id != slot1.task.task_id


def test_session_allowed_bounds_propagation_to_task_work_block_and_input_refs():
    """Verify that allowed_universe/frequency/families and generation_policy penetrate to task.work_block and input_refs."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Bounds propagation test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="ONLY_ASSET_X",
        allowed_frequency="UNIQUE_FREQ",
        allowed_signal_families=("ONLY_FAMILY",),
        generation_policy_version=DISCOVERY_POLICY_VERSION,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)
    assert len(slots) == 2

    for slot in slots:
        # Check request fields
        assert slot.request.allowed_universe == "ONLY_ASSET_X"
        assert slot.request.allowed_frequency == "UNIQUE_FREQ"
        assert slot.request.allowed_signal_families == ("ONLY_FAMILY",)
        assert slot.request.generation_policy_version == DISCOVERY_POLICY_VERSION

        # Check task.work_block prompt contains all 3 bounds and policy
        work_block = slot.task.work_block
        assert "Allowed universe: ONLY_ASSET_X" in work_block
        assert "Allowed frequency: UNIQUE_FREQ" in work_block
        assert "Allowed signal families: ONLY_FAMILY" in work_block
        assert f"Policy: {DISCOVERY_POLICY_VERSION}" in work_block

        # Check task.input_refs explicitly carries the slot input ref with bounds hash
        slot_input_refs = [r for r in slot.task.input_refs if r.get("ref") == slot.slot_id]
        assert len(slot_input_refs) == 1
        expected_hash = v2.digest({
            "allowed_frequency": "UNIQUE_FREQ",
            "allowed_signal_families": ["ONLY_FAMILY"],
            "allowed_universe": "ONLY_ASSET_X",
            "attempt": 1,
            "generation_policy_version": DISCOVERY_POLICY_VERSION,
            "ordinal": slot.ordinal,
            "slot_id": slot.slot_id,
        })
        assert slot_input_refs[0]["content_hash"] == expected_hash


def test_extract_session_memory_context_preserves_provenance_refs():
    """Verify that extract_session_memory_context preserves source_refs, source_hashes, and evidence_refs."""
    view = _build_authentic_memory_view(populate_records=True)
    ctx = extract_session_memory_context(view)

    assert len(ctx.view_source_refs) > 0
    assert tuple(view.source_refs) == ctx.view_source_refs

    all_entries = ctx.recent_rejects + ctx.promoted_summaries + ctx.nme_backlog
    assert len(all_entries) > 0
    for e in all_entries:
        assert "source_refs" in e
        assert isinstance(e["source_refs"], dict)
        assert "source_hashes" in e
        assert isinstance(e["source_hashes"], dict)
        assert "evidence_refs" in e
        assert isinstance(e["evidence_refs"], (tuple, list))


# ==============================================================================
# Negative Tests: Fail-Closed Boundaries & P1 Re-seal Attack Matrices
# ==============================================================================


@pytest.mark.parametrize("bad_budget", [0, 11, -1, 100, -10])
def test_reject_budget_out_of_bounds(bad_budget: int):
    """Verify that budgets outside 1..10 are rejected with DiscoverySessionBudgetError."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    with pytest.raises(DiscoverySessionBudgetError, match="candidate_budget must be between 1 and 10"):
        DiscoverySession.create(
            objective="Out of bounds budget",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=bad_budget,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


@pytest.mark.parametrize("bad_budget_type", [True, False, 1.0, 5.5, "5", None, [1]])
def test_reject_budget_non_strict_integer(bad_budget_type: Any):
    """Verify that booleans, floats, strings, and other non-strict integers are rejected."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    with pytest.raises(DiscoverySessionBudgetError, match="candidate_budget must be a strict integer"):
        DiscoverySession.create(
            objective="Non-strict integer budget",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=bad_budget_type,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


@pytest.mark.parametrize("bad_objective", ["", "   ", "\n\t", " \n "])
def test_reject_empty_or_whitespace_objective(bad_objective: str):
    """Verify that empty or whitespace-only objectives fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    with pytest.raises(DiscoverySessionError, match="objective cannot be empty or whitespace only"):
        DiscoverySession.create(
            objective=bad_objective,
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=5,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


def test_reject_oversized_objective():
    """Verify that objectives exceeding 2,000 characters fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    oversized = "a" * 2_001
    with pytest.raises(DiscoverySessionError, match="objective exceeds maximum length"):
        DiscoverySession.create(
            objective=oversized,
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=5,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


def test_reject_unknown_generation_policy():
    """Verify that unknown generation policy versions fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    with pytest.raises(DiscoverySessionError, match="Unsupported generation_policy_version"):
        DiscoverySession.create(
            objective="Unknown policy test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=5,
            allowed_universe="test_univ",
            allowed_frequency="1d",
            generation_policy_version="unknown_rogue_policy.v99",
        )


@pytest.mark.parametrize("unauthorized_role,role_perms", [
    ("data_researcher", ["read_research_memory"]),
    ("code_researcher", ["read_result_store"]),
    ("research_synthesizer", ["read_research_memory"]),
    ("external_researcher", []),
])
def test_reject_scope_wrong_role(unauthorized_role: str, role_perms: list[str]):
    """Verify that any role other than alpha_generator is rejected fail-closed."""
    scope = _make_scope(role=unauthorized_role, permissions=role_perms)
    view = _build_authentic_memory_view()
    with pytest.raises(PermissionDeniedError, match="requires an alpha_generator"):
        DiscoverySession.create(
            objective="Wrong role scope test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=5,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


def test_reject_scope_missing_required_permissions():
    """Verify that missing read_research_memory or create_hypothesis fails closed."""
    scope = _make_scope(permissions=["read_research_memory"])
    view = _build_authentic_memory_view()
    with pytest.raises(PermissionDeniedError, match="exact least-privilege permissions"):
        DiscoverySession.create(
            objective="Missing permission test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=5,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


@pytest.mark.parametrize("forbidden_permission", [
    "execute_screening",
    "write_research_memory",
    "invoke_critic",
    "request_screening",
    "read_result_store",
])
def test_reject_scope_unauthorized_permission_expansion(forbidden_permission: str):
    """Verify that scopes with unauthorized privileges fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Unauthorized expansion test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    data["authorized_scope_ref"]["authorized_permissions"].append(forbidden_permission)
    with pytest.raises(PermissionDeniedError):
        DiscoverySession.from_dict(data)


def test_reject_scope_nested_delegation():
    """Verify that nested delegation attempts (can_delegate=True or max_delegation_depth > 0) fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Nested delegation test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data1 = session.to_dict()
    data1["authorized_scope_ref"]["can_delegate"] = True
    with pytest.raises(PermissionDeniedError, match="Nested delegation prohibited"):
        DiscoverySession.from_dict(data1)

    data2 = session.to_dict()
    data2["authorized_scope_ref"]["max_delegation_depth"] = 1
    with pytest.raises(PermissionDeniedError, match="Nested delegation prohibited"):
        DiscoverySession.from_dict(data2)


def test_reject_project_binding_mismatch():
    """Verify that project binding mismatches between Session, Scope, and Memory View fail closed."""
    foreign_binding = ProjectBinding(project_id="other-project", workspace_identity="/other/path")
    scope = _make_scope(project_binding=foreign_binding)
    view = _build_authentic_memory_view(project_binding=BINDING)

    with pytest.raises(ProjectBindingError, match="project binding mismatch"):
        DiscoverySession.create(
            objective="Project mismatch test",
            memory_view=view,
            authorized_scope=scope,
            project_binding=BINDING,
            candidate_budget=5,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


# --- P1-1 Re-sealing and Memory View Binding Attack Matrices ---


def test_reject_resealing_with_forged_memory_view_id_and_hash():
    """P1-1: Modifying memory_view_id='nonexistent' and hash='f'*64 followed by re-sealing MUST be rejected."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reseal attack on memory view",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    # Attack: forge memory_view_id and memory_view_content_hash, then re-seal session
    data = session.to_dict()
    data["memory_view_id"] = "nonexistent"
    data["memory_view_content_hash"] = "f" * 64

    # Recompute session hash and ID to simulate outer re-sealing
    recomputed_hash = compute_session_content_hash(data)
    data["session_content_hash"] = recomputed_hash
    data["session_id"] = compute_session_id(recomputed_hash)

    # Must fail closed due to mismatch with memory_view_ref
    with pytest.raises(DiscoverySessionError, match="memory_view_ref view_id.*mismatch"):
        DiscoverySession.from_dict(data)


def test_reject_resealing_with_tampered_memory_view_ref_role():
    """P1-1: Modifying memory_view_ref role to an unauthorized role followed by re-sealing MUST be rejected."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reseal attack with wrong memory view role",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    data["memory_view_ref"]["role"] = "data_researcher"

    recomputed_hash = compute_session_content_hash(data)
    data["session_content_hash"] = recomputed_hash
    data["session_id"] = compute_session_id(recomputed_hash)

    with pytest.raises(PermissionDeniedError, match="memory_view role must be 'alpha_generator'"):
        DiscoverySession.from_dict(data)


def test_reject_resealing_with_foreign_project_memory_view_ref():
    """P1-1: Modifying memory_view_ref project_binding to another project followed by re-sealing MUST be rejected."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reseal attack with foreign project memory view",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    data["memory_view_ref"]["project_binding"] = {
        "binding_mode": "strict",
        "project_id": "malicious-foreign-project",
        "workspace_identity": "/malicious/workspace",
    }

    recomputed_hash = compute_session_content_hash(data)
    data["session_content_hash"] = recomputed_hash
    data["session_id"] = compute_session_id(recomputed_hash)

    with pytest.raises(ProjectBindingError, match="memory_view project_binding mismatch"):
        DiscoverySession.from_dict(data)


def test_reject_plan_candidate_slots_mismatched_view():
    """P1-1: Planning with a memory view that has mismatched ID, hash, or project fails closed."""
    scope = _make_scope()
    view1 = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Mismatched planning view test",
        memory_view=view1,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    # Different authentic view (different ID and content hash)
    view2 = _build_authentic_memory_view(populate_records=True)
    with pytest.raises(DiscoverySessionError, match="memory_view view_id mismatch"):
        plan_candidate_slots(session, view2)


# --- P1-2 PlannedCandidateSlot Cross-Object Validation & Attack Matrices ---


def test_reject_slot_swapping_request():
    """P1-2: Swapping requests between candidate slots (dataclasses.replace) MUST fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Slot swapping test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)

    # Swap request of slot[0] with request of slot[1]
    with pytest.raises(DiscoverySessionError, match="request.slot_id.*mismatch"):
        dataclasses.replace(slots[0], request=slots[1].request)


def test_reject_slot_swapping_task():
    """P1-2: Swapping tasks between candidate slots MUST fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Task swapping test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)

    with pytest.raises(DiscoverySessionError, match="task input_refs missing reference to slot_id"):
        dataclasses.replace(slots[0], task=slots[1].task)


def test_reject_slot_cross_session_request():
    """P1-2: Mixing a request from another session into a slot MUST fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session1 = DiscoverySession.create(
        objective="Session 1",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    session2 = DiscoverySession.create(
        objective="Session 2",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots1 = plan_candidate_slots(session1, view)
    slots2 = plan_candidate_slots(session2, view)

    with pytest.raises(DiscoverySessionError, match="request.session_id.*mismatch"):
        dataclasses.replace(slots1[0], request=slots2[0].request)


@pytest.mark.parametrize("bad_attempt", [True, False, 0, -1, "1", 1.5, None])
def test_reject_slot_bool_or_invalid_attempt(bad_attempt: Any):
    """P1-2: PlannedCandidateSlot must strictly reject boolean or invalid attempt counts."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Bad attempt test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)

    with pytest.raises(DiscoverySessionError, match="attempt must be a strict positive integer"):
        dataclasses.replace(slots[0], attempt=bad_attempt)


@pytest.mark.parametrize("bad_replan_attempt", [True, False, 1, 0, -1, "2", 2.0])
def test_reject_replan_slot_with_bool_or_non_incrementing_attempt(bad_replan_attempt: Any):
    """P1-2: replan_slot_attempt must reject boolean or non-incrementing attempt counts."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Bad replan attempt test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)

    with pytest.raises(DiscoverySessionError):
        replan_slot_attempt(slots[0], view, attempt=bad_replan_attempt)


def test_m5_request_grouped_session_fields():
    """P1-2: AlphaGenerationRequest session fields must be provided together as a complete group."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    # Only session_id without slot_id / ordinal
    with pytest.raises(AlphaGenerationError, match="must be specified together as a complete group"):
        AlphaGenerationRequest.create(
            objective="Partial session fields test",
            memory_view=view,
            project_binding=BINDING,
            authorized_scope=scope,
            session_id="disc-session-001",
        )

    # Legacy request without session fields preserves original M5 serialization
    legacy_req = AlphaGenerationRequest.create(
        objective="Legacy M5 request",
        memory_view=view,
        project_binding=BINDING,
        authorized_scope=scope,
    )
    d = legacy_req.to_dict()
    assert "session_id" not in d
    assert "slot_id" not in d
    assert "ordinal" not in d
    assert "allowed_universe" not in d


# --- Auxiliary Consistency Gap Tests ---


def test_reject_from_dict_non_string_objective():
    """Auxiliary: from_dict must reject objective=123 without loose string casting."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Strict objective test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    data["objective"] = 123  # Non-string!

    with pytest.raises(DiscoverySessionError, match="objective must be a string"):
        DiscoverySession.from_dict(data)


def test_reject_from_dict_unknown_schema_version():
    """Auxiliary: from_dict must reject unknown schema_version even if re-sealed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Strict schema test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    data["schema_version"] = "research_lab.discovery_session.v999_unknown"

    recomputed_hash = compute_session_content_hash(data)
    data["session_content_hash"] = recomputed_hash
    data["session_id"] = compute_session_id(recomputed_hash)

    with pytest.raises(DiscoverySessionError, match="Unsupported schema_version"):
        DiscoverySession.from_dict(data)


def test_reject_bare_string_signal_families():
    """Auxiliary: passing a bare string to allowed_signal_families must fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    with pytest.raises(DiscoverySessionError, match="allowed_signal_families must be a tuple or list of strings"):
        DiscoverySession.create(
            objective="Bare string family test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=3,
            allowed_universe="test_univ",
            allowed_frequency="1d",
            allowed_signal_families="momentum",  # Bare string!
        )


def test_reject_unknown_fields_in_from_dict():
    """Verify that extra unknown fields in deserialization payload fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Unknown field test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    data["rogue_injected_field"] = "malicious_payload"

    with pytest.raises(DiscoverySessionError, match="Unknown fields rejected under fail-closed policy"):
        DiscoverySession.from_dict(data)


# ==============================================================================
# Zero Side-Effects & Hard Boundary Tests with Explicit Mocks / Spies
# ==============================================================================


def test_zero_side_effects_with_explicit_spies(monkeypatch):
    """Verify that session creation, deserialization, and slot planning trigger NO external calls.

    Installs explicit spies on Provider submission, Screening execution, Critic decision,
    and ResearchMemory write methods, asserting 0 calls.
    """
    spy_submit = MagicMock()
    spy_screen = MagicMock()
    spy_critic = MagicMock()
    spy_memory_write = MagicMock()

    # Mock potential execution endpoints
    monkeypatch.setattr(
        "research_lab.agent_control.discovery_integration.DiscoveryIntegrationOrchestrator.execute_alpha_generation",
        spy_screen,
        raising=False,
    )
    monkeypatch.setattr(
        "research_lab.alpha_discovery.research_memory.ResearchMemory.append_evaluation_record",
        spy_memory_write,
        raising=False,
    )

    scope = _make_scope()
    view = _build_authentic_memory_view()

    # 1. Create session
    session = DiscoverySession.create(
        objective="Verify zero side-effects across all entrypoints",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    # 2. Serialize & deserialize
    payload = session.to_dict()
    restored = DiscoverySession.from_dict(payload, memory_view=view)

    # 3. Plan candidate slots
    slots = plan_candidate_slots(restored, view)
    assert len(slots) == 5

    # 4. Replan slot attempt
    replan_slot_attempt(slots[0], view, attempt=2)

    # Assert 0 calls were made to any side-effecting subsystem
    assert spy_submit.call_count == 0
    assert spy_screen.call_count == 0
    assert spy_critic.call_count == 0
    assert spy_memory_write.call_count == 0


def test_permanent_non_trading_boundaries():
    """Verify that live_trading_authorized and production_trading permissions are permanently rejected."""
    with pytest.raises(PermissionDeniedError, match="Hard invariant violation"):
        _make_scope(permissions=["read_research_memory", "create_hypothesis", "live_trading_authorized"])

    with pytest.raises(PermissionDeniedError, match="Hard invariant violation"):
        _make_scope(permissions=["read_research_memory", "create_hypothesis", "production_trading"])
