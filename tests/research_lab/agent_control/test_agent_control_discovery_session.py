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
    PROMPT_POLICY_VERSION,
    AlphaGenerationError,
    AlphaGenerationRequest,
    create_alpha_generation_task,
)
from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentTask,
    ProjectBinding,
    ProjectBindingError,
    TamperDetectionError,
    compute_scope_content_hash,
    compute_scope_deterministic_id,
)
from research_lab.agent_control.discovery_session import (
    CANONICAL_SESSION_TIMESTAMP,
    DISCOVERY_SESSION_SCHEMA_VERSION,
    DiscoverySession,
    DiscoverySessionBudgetError,
    DiscoverySessionError,
    compute_memory_view_snapshot_hash,
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
    is_authorized: bool = True,
    policy_version: str = "2026-09-m1",
) -> AgentPermissionScope:
    pb = project_binding or BINDING
    perms = permissions if permissions is not None else list(REQUIRED_PERMISSIONS)
    scope = authorize(role, perms, pb)
    if not is_authorized or policy_version != "2026-09-m1":
        d = scope.to_dict()
        d["is_authorized"] = is_authorized
        d["policy_version"] = policy_version
        if not is_authorized:
            d["authorized_permissions"] = []
            d["denied_permissions"] = sorted(perms)
        d["scope_id"] = compute_scope_deterministic_id(d)
        d["scope_content_hash"] = compute_scope_content_hash(d)
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
        objective="Discover short-term momentum signals in liquid commodities",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=1,
        allowed_universe="commodity_active",
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "trend_following"),
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    assert session.candidate_budget == 1
    assert session.session_id.startswith("disc-session-")
    assert len(session.session_content_hash) == 64
    assert session.memory_view_id == view.view_id
    assert session.memory_view_content_hash == view.view_content_hash
    assert session.memory_view_snapshot_hash == compute_memory_view_snapshot_hash(view)
    assert session.allowed_universe == "commodity_active"
    assert session.allowed_frequency == "1d"
    assert session.allowed_signal_families == ("momentum", "trend_following")
    assert session.schema_version == DISCOVERY_SESSION_SCHEMA_VERSION

    # Test direct constructor with memory_view InitVar
    direct_session = DiscoverySession(
        session_id=session.session_id,
        session_content_hash=session.session_content_hash,
        objective=session.objective,
        project_binding=session.project_binding,
        authorized_scope_ref=session.authorized_scope_ref,
        memory_view_ref=session.memory_view_ref,
        memory_view_id=session.memory_view_id,
        memory_view_content_hash=session.memory_view_content_hash,
        memory_view_snapshot_hash=session.memory_view_snapshot_hash,
        candidate_budget=session.candidate_budget,
        allowed_universe=session.allowed_universe,
        allowed_frequency=session.allowed_frequency,
        memory_view=view,
        allowed_signal_families=session.allowed_signal_families,
        generation_policy_version=session.generation_policy_version,
        created_at=session.created_at,
        schema_version=session.schema_version,
    )
    assert direct_session.session_id == session.session_id


def test_discovery_session_creation_maximum_candidates():
    """Verify DiscoverySession creation with maximum candidate budget (10 slots)."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    session = DiscoverySession.create(
        objective="Broad exploration across diverse signal families",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=10,
        allowed_universe=("RB", "HC", "I", "J"),
        allowed_frequency="5m",
        allowed_signal_families=["mean_reversion", "order_flow"],
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    assert session.candidate_budget == 10
    assert session.allowed_universe == ("HC", "I", "J", "RB")
    assert session.allowed_signal_families == ("mean_reversion", "order_flow")

    slots = plan_candidate_slots(session, view)
    assert len(slots) == 10
    assert len({s.slot_id for s in slots}) == 10
    assert all(s.request.requested_candidate_count == 1 for s in slots)
    assert all(s.ordinal == idx + 1 for idx, s in enumerate(slots))


def test_discovery_session_with_empty_memory_view():
    """Verify handling of completely empty Controlled Memory View (total_entries=0)."""
    scope = _make_scope()
    view = _build_authentic_memory_view(populate_records=False)
    assert view.total_entries == 0

    session = DiscoverySession.create(
        objective="Cold-start exploration without prior history",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    ctx = extract_session_memory_context(view)
    assert ctx.is_empty is True
    assert ctx.total_entries == 0
    assert len(ctx.valid_entry_ids) == 0

    slots = plan_candidate_slots(session, view)
    assert len(slots) == 3


def test_discovery_session_with_non_empty_memory_view():
    """Verify mapping of populated memory view entries and preservation of refs/hashes."""
    scope = _make_scope()
    view = _build_authentic_memory_view(populate_records=True)
    assert view.total_entries > 0

    session = DiscoverySession.create(
        objective="Informed exploration leveraging prior rejects and nme backlog",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    assert session.memory_view_id == view.view_id
    assert session.memory_view_content_hash == view.view_content_hash

    ctx = extract_session_memory_context(view)
    assert ctx.is_empty is False
    assert ctx.total_entries == view.total_entries
    assert len(ctx.valid_entry_ids) > 0
    assert len(ctx.view_source_refs) > 0

    # Verify faithful preservation of entry source_refs, source_hashes, and evidence_refs
    for category_entries in (ctx.recent_rejects, ctx.promoted_summaries, ctx.nme_backlog):
        for entry in category_entries:
            assert "source_refs" in entry
            assert "source_hashes" in entry
            assert "evidence_refs" in entry


def test_discovery_session_with_truncated_memory_view():
    """Verify faithful propagation of is_truncated flag from ResearchMemoryView."""
    scope = _make_scope()
    view = _build_authentic_memory_view(populate_records=True)
    truncated_view = dataclasses.replace(view, is_truncated=True)

    session = DiscoverySession.create(
        objective="Exploration with truncated memory view",
        memory_view=truncated_view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    ctx = extract_session_memory_context(truncated_view)
    assert ctx.is_truncated is True

    slots = plan_candidate_slots(session, truncated_view)
    assert len(slots) == 2


def test_discovery_session_serialization_roundtrip():
    """Verify lossless serialization and deserialization via to_dict / from_dict."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    session = DiscoverySession.create(
        objective="Serialization roundtrip test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=4,
        allowed_universe=("IF", "IH"),
        allowed_frequency="15m",
        allowed_signal_families=("volatility", "mean_reversion"),
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    data = session.to_dict()
    assert isinstance(data, dict)
    assert data["candidate_budget"] == 4
    assert data["memory_view_snapshot_hash"] == session.memory_view_snapshot_hash

    restored = DiscoverySession.from_dict(data, memory_view=view)
    assert restored.session_id == session.session_id
    assert restored.session_content_hash == session.session_content_hash
    assert restored.objective == session.objective
    assert restored.candidate_budget == session.candidate_budget
    assert restored.allowed_universe == session.allowed_universe
    assert restored.allowed_frequency == session.allowed_frequency
    assert restored.allowed_signal_families == session.allowed_signal_families
    assert restored.memory_view_snapshot_hash == session.memory_view_snapshot_hash


def test_discovery_session_replanning_determinism():
    """Verify that replanning slots multiple times produces bit-for-bit identical results."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    session = DiscoverySession.create(
        objective="Determinism verification test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    slots_run1 = plan_candidate_slots(session, view)
    slots_run2 = plan_candidate_slots(session, view)

    assert len(slots_run1) == len(slots_run2) == 3
    for s1, s2 in zip(slots_run1, slots_run2):
        assert s1.slot_id == s2.slot_id
        assert s1.slot_content_hash == s2.slot_content_hash
        assert s1.request.request_id == s2.request.request_id
        assert s1.request.to_dict() == s2.request.to_dict()
        assert s1.task.task_id == s2.task.task_id
        assert s1.task.task_content_hash == s2.task.task_content_hash


def test_discovery_session_slot_replan_attempt():
    """Verify that replanning a slot for a retry attempt preserves slot_id but updates task/attempt."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    session = DiscoverySession.create(
        objective="Slot replanning retry test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    slots = plan_candidate_slots(session, view)
    slot1 = slots[0]
    assert slot1.attempt == 1

    replanned = replan_slot_attempt(slot1, view, attempt=2)
    assert replanned.slot_id == slot1.slot_id
    assert replanned.attempt == 2
    assert replanned.request.attempt == 2
    assert replanned.task.task_id != slot1.task.task_id


def test_discovery_session_bounds_and_policy_propagation():
    """P1-3: Verify propagation of allowed universe, frequency, families, and policy."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    session = DiscoverySession.create(
        objective="Propagation test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe=("AU", "AG"),
        allowed_frequency="30m",
        allowed_signal_families=("breakout", "stat_arb"),
        generation_policy_version=DISCOVERY_POLICY_VERSION,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    slots = plan_candidate_slots(session, view)
    for slot in slots:
        req = slot.request
        task = slot.task

        assert req.allowed_universe == ("AG", "AU")
        assert req.allowed_frequency == "30m"
        assert req.allowed_signal_families == ("breakout", "stat_arb")
        assert req.generation_policy_version == DISCOVERY_POLICY_VERSION

        assert "Allowed universe: AG, AU" in task.work_block
        assert "Allowed frequency: 30m" in task.work_block
        assert "Allowed signal families: breakout, stat_arb" in task.work_block

        slot_input_refs = [r for r in task.input_refs if r.get("ref") == slot.slot_id]
        assert len(slot_input_refs) == 1
        assert "content_hash" in slot_input_refs[0]


# ==============================================================================
# Negative Tests: Strict Fail-Closed Boundaries and Attack Defenses
# ==============================================================================


@pytest.mark.parametrize("bad_budget", [0, 11, -1, 100, -10])
def test_reject_budget_out_of_bounds(bad_budget: int):
    """Verify that candidate budgets outside 1..10 fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    with pytest.raises(DiscoverySessionBudgetError, match="candidate_budget must be between 1 and 10"):
        DiscoverySession.create(
            objective="Out of bounds budget test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=bad_budget,
            allowed_universe="test_univ",
            allowed_frequency="1d",
        )


@pytest.mark.parametrize("bad_budget", [True, False, 1.0, 5.5, "5", None, [1]])
def test_reject_budget_non_strict_integer(bad_budget: Any):
    """Verify that non-strict integers fail closed (rejecting booleans, floats, strings, None)."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    with pytest.raises(DiscoverySessionBudgetError, match="candidate_budget must be a strict integer"):
        DiscoverySession.create(
            objective="Non-strict int budget test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=bad_budget,
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
    with pytest.raises(PermissionDeniedError, match="requires exact least-privilege permissions"):
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
    """Verify that scopes containing permissions beyond minimal least-privilege fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Permission expansion test",
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
        DiscoverySession.from_dict(data, memory_view=view)


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
        DiscoverySession.from_dict(data1, memory_view=view)

    data2 = session.to_dict()
    data2["authorized_scope_ref"]["max_delegation_depth"] = 1
    with pytest.raises(PermissionDeniedError, match="Nested delegation prohibited"):
        DiscoverySession.from_dict(data2, memory_view=view)


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


# ==============================================================================
# Codex Review Reproduction Test Matrix: Closing Reported Findings 1, 2, 3, 4
# ==============================================================================


def test_reproduction_1_forged_memory_view_rejected():
    """Reproduction 1: Forging memory_view_id='memview-forged', hash='f'*64, and re-sealing MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction 1 test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    d = session.to_dict()
    d["memory_view_id"] = "memview-forged"
    d["memory_view_content_hash"] = "f" * 64
    d["memory_view_ref"]["view_id"] = "memview-forged"
    d["memory_view_ref"]["view_content_hash"] = "f" * 64
    recomputed = compute_session_content_hash(d)
    d["session_content_hash"] = recomputed
    d["session_id"] = compute_session_id(recomputed)

    # Must fail because authentic memory_view does not match the forged ID
    with pytest.raises((DiscoverySessionError, TamperDetectionError)):
        DiscoverySession.from_dict(d, memory_view=view)


def test_reproduction_1_tampered_view_content_rejected_in_planning():
    """Reproduction 1: Modifying view contents under old ID/hash MUST FAIL snapshot verification in planning."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction 1 badview test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    badview = dataclasses.replace(view, is_truncated=not view.is_truncated, total_entries=999)
    with pytest.raises(TamperDetectionError, match="memory_view snapshot digest tampering detected"):
        plan_candidate_slots(session, badview)


def test_reproduction_1_from_dict_missing_memory_view_rejected():
    """Reproduction 1: Calling from_dict without memory_view context MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Missing view context test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    with pytest.raises(TypeError):
        DiscoverySession.from_dict(session.to_dict())  # type: ignore[call-arg]


def test_reproduction_2_unauthorized_scope_rejected_even_resealed():
    """Reproduction 2: scope_ref.is_authorized=False followed by re-sealing MUST be rejected."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction 2 is_authorized=False test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    scope_ref = dict(session.authorized_scope_ref)
    scope_ref["is_authorized"] = False
    scope_ref["authorized_permissions"] = []
    scope_ref["denied_permissions"] = sorted(REQUIRED_PERMISSIONS)
    scope_ref["scope_id"] = compute_scope_deterministic_id(scope_ref)
    scope_ref["scope_content_hash"] = compute_scope_content_hash(scope_ref)

    d = session.to_dict()
    d["authorized_scope_ref"] = scope_ref
    recomputed = compute_session_content_hash(d)
    d["session_content_hash"] = recomputed
    d["session_id"] = compute_session_id(recomputed)

    with pytest.raises(PermissionDeniedError, match="authorized_scope is not authorized"):
        DiscoverySession.from_dict(d, memory_view=view)


def test_reproduction_2_unknown_scope_policy_rejected():
    """Reproduction 2: Scope with unknown policy_version MUST be rejected."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction 2 unknown policy test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    scope_ref = dict(session.authorized_scope_ref)
    scope_ref["policy_version"] = "unknown_rogue_policy.v999"
    scope_ref["scope_id"] = compute_scope_deterministic_id(scope_ref)
    scope_ref["scope_content_hash"] = compute_scope_content_hash(scope_ref)

    d = session.to_dict()
    d["authorized_scope_ref"] = scope_ref
    recomputed = compute_session_content_hash(d)
    d["session_content_hash"] = recomputed
    d["session_id"] = compute_session_id(recomputed)

    with pytest.raises(PermissionDeniedError, match="Unsupported or unknown scope policy_version"):
        DiscoverySession.from_dict(d, memory_view=view)


def test_reproduction_3_slot_tampered_request_bounds_rejected():
    """Reproduction 3: Tampering request bounds on a PlannedCandidateSlot MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction 3 slot bounds tampering test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    x = plan_candidate_slots(session, view)[0]
    r = dataclasses.replace(x.request, allowed_universe=("FORBIDDEN_ASSET",))
    t = create_alpha_generation_task(r, view, created_at=x.task.created_at)

    with pytest.raises(DiscoverySessionError, match="request.allowed_universe.*mismatch with session"):
        dataclasses.replace(x, request=r, task=t)


def test_reproduction_3_slot_tampered_task_audit_hash_rejected():
    """Reproduction 3: Tampering task slot audit hash or missing memory ref MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction 3 slot audit hash test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    x = plan_candidate_slots(session, view)[0]
    bad_task = AgentTask.create(
        role=x.task.role,
        requested_permissions=list(x.task.requested_permissions),
        authorized_permissions=list(x.task.authorized_permissions),
        objective=x.task.objective,
        work_block=x.task.work_block,
        input_refs=[
            {"ref": session.memory_view_id, "content_hash": session.memory_view_content_hash},
            {"ref": x.slot_id, "content_hash": "f" * 64},
        ],
        provider_policy_ref=x.task.provider_policy_ref,
        project_binding=dict(x.task.project_binding),
        created_by=x.task.created_by,
        created_at=x.task.created_at,
        authorized_scope=AgentPermissionScope(**session.authorized_scope_ref),
    )

    with pytest.raises(TamperDetectionError, match="task input_refs slot content_hash mismatch"):
        dataclasses.replace(x, task=bad_task)


def test_reproduction_3_slot_ordinal_exceeding_budget_rejected():
    """Reproduction 3: Slot ordinal exceeding session candidate_budget MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction 3 ordinal budget test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    x = plan_candidate_slots(session, view)[0]
    with pytest.raises(DiscoverySessionBudgetError, match="exceeds session candidate_budget"):
        dataclasses.replace(x, ordinal=session.candidate_budget + 1, slot_index=session.candidate_budget)


def test_reproduction_4_zero_side_effects_with_real_entrypoint_spies(monkeypatch):
    """Reproduction 4: Verify zero external side-effects with explicit spies on real entrypoints (raising=True)."""
    # 1. Build authentic domain fixtures first
    scope = _make_scope()
    view = _build_authentic_memory_view()

    # 2. Setup spies on REAL execution and storage entrypoints with raising=True
    spy_provider_contract = MagicMock()
    spy_provider_mcp = MagicMock()
    spy_router_route = MagicMock()
    spy_screening_exec = MagicMock()
    spy_critic_eval = MagicMock()
    spy_memory_write = MagicMock()

    monkeypatch.setattr(
        "research_lab.agent_control.providers.contract_test_provider.ContractTestProvider.submit",
        spy_provider_contract,
        raising=True,
    )
    monkeypatch.setattr(
        "research_lab.agent_control.providers.antigravity_local_mcp.AntigravityLocalMCPProvider.submit",
        spy_provider_mcp,
        raising=True,
    )
    monkeypatch.setattr(
        "research_lab.agent_control.router.select_agent",
        spy_router_route,
        raising=True,
    )
    monkeypatch.setattr(
        "research_lab.runners.v2_statistical_screening.run_statistical_screening",
        spy_screening_exec,
        raising=True,
    )
    monkeypatch.setattr(
        "research_lab.alpha_discovery.critic_gate.CriticGate.evaluate",
        spy_critic_eval,
        raising=True,
    )
    monkeypatch.setattr(
        "research_lab.alpha_discovery.research_memory.ResearchMemory.append_evaluation_record",
        spy_memory_write,
        raising=True,
    )

    # 3. Create session
    session = DiscoverySession.create(
        objective="Verify zero side-effects across all entrypoints",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    # 4. Serialize & deserialize
    payload = session.to_dict()
    restored = DiscoverySession.from_dict(payload, memory_view=view)

    # 5. Plan candidate slots
    slots = plan_candidate_slots(restored, view)
    assert len(slots) == 5

    # 6. Replan slot attempt
    replan_slot_attempt(slots[0], view, attempt=2)

    # 7. Assert 0 calls across all protected execution and persistence interfaces
    assert spy_provider_contract.call_count == 0
    assert spy_provider_mcp.call_count == 0
    assert spy_router_route.call_count == 0
    assert spy_screening_exec.call_count == 0
    assert spy_critic_eval.call_count == 0
    assert spy_memory_write.call_count == 0


def test_reproduction_A_slot_tampered_request_objective_rejected():
    """Reproduction A: Tampering request.objective while keeping old session MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Original authentic objective",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    x = plan_candidate_slots(session, view)[0]
    r = dataclasses.replace(x.request, objective="another objective")
    t = create_alpha_generation_task(r, view, created_at=x.task.created_at)
    with pytest.raises(DiscoverySessionError, match="request.objective mismatch with session"):
        dataclasses.replace(x, request=r, task=t)


def test_reproduction_A_slot_tampered_request_scope_rejected():
    """Reproduction A: Tampering request.authorized_scope_ref while keeping old session MUST FAIL."""
    scope = _make_scope(policy_version="2026-09-m1")
    other_scope = _make_scope(policy_version="2026-09-m4")
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Original authentic objective",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    x = plan_candidate_slots(session, view)[0]
    r = dataclasses.replace(x.request, authorized_scope_ref=other_scope.to_dict())
    t = create_alpha_generation_task(r, view, created_at=x.task.created_at)
    with pytest.raises(DiscoverySessionError, match="request.authorized_scope_ref mismatch with session"):
        dataclasses.replace(x, request=r, task=t)


def test_reproduction_B_slot_tampered_task_work_block_rejected():
    """Reproduction B: Valid task with tampered work_block MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Authentic session objective",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    x = plan_candidate_slots(session, view)[0]
    bad_task = AgentTask.create(
        role=x.task.role,
        requested_permissions=list(x.task.requested_permissions),
        authorized_permissions=list(x.task.authorized_permissions),
        objective=x.task.objective,
        work_block="unrelated rogue work block bypass attempt",
        input_refs=list(x.task.to_dict()["input_refs"]),
        provider_policy_ref=x.task.provider_policy_ref,
        project_binding=dict(x.task.project_binding),
        created_by=x.task.created_by,
        created_at=x.task.created_at,
        authorized_scope=scope,
    )
    with pytest.raises(TamperDetectionError, match="task.work_block mismatch with expected authentic task"):
        dataclasses.replace(x, task=bad_task)


def test_reproduction_B_slot_tampered_task_provider_policy_rejected():
    """Reproduction B: Valid task with tampered provider_policy_ref MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Authentic session objective",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    x = plan_candidate_slots(session, view)[0]
    bad_task = AgentTask.create(
        role=x.task.role,
        requested_permissions=list(x.task.requested_permissions),
        authorized_permissions=list(x.task.authorized_permissions),
        objective=x.task.objective,
        work_block=x.task.work_block,
        input_refs=list(x.task.to_dict()["input_refs"]),
        provider_policy_ref="rogue-provider-policy@v1",
        project_binding=dict(x.task.project_binding),
        created_by=x.task.created_by,
        created_at=x.task.created_at,
        authorized_scope=scope,
    )
    with pytest.raises(TamperDetectionError, match="task.provider_policy_ref mismatch with expected authentic task"):
        dataclasses.replace(x, task=bad_task)


def test_reproduction_C_memory_view_ref_tampered_policy_version_rejected():
    """Reproduction C: Modifying memory_view_ref.policy_version even with resealed hash MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction C policy tampering test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )
    d = session.to_dict()
    d["memory_view_ref"]["policy_version"] = "unknown"
    d["session_content_hash"] = compute_session_content_hash(d)
    d["session_id"] = compute_session_id(d["session_content_hash"])
    with pytest.raises(DiscoverySessionError, match="memory_view_ref mismatch with authentic ResearchMemoryView reference.*policy_version"):
        DiscoverySession.from_dict(d, memory_view=view)


def test_reproduction_C_memory_view_ref_tampered_source_refs_rejected():
    """Reproduction C: Modifying memory_view_ref.source_refs even with resealed hash MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction C source_refs tampering test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )
    d = session.to_dict()
    d["memory_view_ref"]["source_refs"] = ["forged-source-id"]
    d["session_content_hash"] = compute_session_content_hash(d)
    d["session_id"] = compute_session_id(d["session_content_hash"])
    with pytest.raises(DiscoverySessionError, match="memory_view_ref mismatch with authentic ResearchMemoryView reference.*source_refs"):
        DiscoverySession.from_dict(d, memory_view=view)


def test_reproduction_C_memory_view_ref_unknown_nested_field_rejected():
    """Reproduction C: Injecting unknown nested fields into memory_view_ref MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction C unknown nested field test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )
    d = session.to_dict()
    d["memory_view_ref"]["rogue_nested_key"] = "malicious_payload"
    d["session_content_hash"] = compute_session_content_hash(d)
    d["session_id"] = compute_session_id(d["session_content_hash"])
    with pytest.raises(DiscoverySessionError, match="memory_view_ref contains unknown or unauthorized fields"):
        DiscoverySession.from_dict(d, memory_view=view)


def test_reproduction_C_memory_view_ref_tampered_categories_rejected():
    """Reproduction C: Modifying categories in memory_view_ref MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction C categories test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )
    d = session.to_dict()
    d["memory_view_ref"]["categories"] = ["failed_approaches"]
    d["session_content_hash"] = compute_session_content_hash(d)
    d["session_id"] = compute_session_id(d["session_content_hash"])
    with pytest.raises(DiscoverySessionError, match="memory_view_ref mismatch with authentic ResearchMemoryView reference.*categories"):
        DiscoverySession.from_dict(d, memory_view=view)


def test_reproduction_C_memory_view_ref_tampered_total_entries_or_truncation_rejected():
    """Reproduction C: Modifying total_entries or is_truncated in memory_view_ref MUST FAIL."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Reproduction C count/truncation test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )
    d = session.to_dict()
    d["memory_view_ref"]["total_entries"] = 9999
    d["session_content_hash"] = compute_session_content_hash(d)
    d["session_id"] = compute_session_id(d["session_content_hash"])
    with pytest.raises(DiscoverySessionError, match="memory_view_ref mismatch with authentic ResearchMemoryView reference.*total_entries"):
        DiscoverySession.from_dict(d, memory_view=view)


def test_request_in_place_mutation_prevented_by_deep_freeze():
    """Verify that AlphaGenerationRequest project_binding and scope are frozen against in-place mutation."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="In-place mutation defense test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )
    x = plan_candidate_slots(session, view)[0]
    with pytest.raises(TypeError):
        x.request.project_binding["project_id"] = "tampered_in_place"  # type: ignore[index]
    with pytest.raises(TypeError):
        x.request.authorized_scope_ref["role"] = "tampered_role"  # type: ignore[index]
    d = x.request.to_dict()
    d["project_binding"]["project_id"] = "modified_copy"
    assert x.request.project_binding["project_id"] != "modified_copy"


def test_session_semantic_reconstruction_stability():
    """Verify that identical semantic inputs produce identical session_id and content hash regardless of clock."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    # Create session without specifying created_at twice
    s1 = DiscoverySession.create(
        objective="Identical semantic input",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )
    s2 = DiscoverySession.create(
        objective="Identical semantic input",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    assert s1.session_content_hash == s2.session_content_hash
    assert s1.session_id == s2.session_id


def test_reject_create_non_string_frequency():
    """Verify that create rejects non-string allowed_frequency without stringifying."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    with pytest.raises(DiscoverySessionError, match="allowed_frequency must be a non-empty string"):
        DiscoverySession.create(
            objective="Bad frequency test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=2,
            allowed_universe="test_univ",
            allowed_frequency=123,  # type: ignore[arg-type]
        )


def test_reject_create_generator_or_set_signal_families():
    """Verify that create rejects sets or generators for allowed_signal_families without loose casting."""
    scope = _make_scope()
    view = _build_authentic_memory_view()

    with pytest.raises(DiscoverySessionError, match="allowed_signal_families must be a tuple or list"):
        DiscoverySession.create(
            objective="Bad signal families type test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=2,
            allowed_universe="test_univ",
            allowed_frequency="1d",
            allowed_signal_families={"momentum", "mean_reversion"},  # Set instead of list/tuple!
        )


def test_reject_slot_swapping_request():
    """P1-2: Replacing a slot's request with one from another slot MUST fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Slot swapping request test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)

    with pytest.raises(DiscoverySessionError, match="request.slot_id.*mismatch with slot.slot_id"):
        dataclasses.replace(slots[0], request=slots[1].request)


def test_reject_slot_swapping_task():
    """P1-2: Replacing a slot's task with one referencing another slot_id MUST fail closed."""
    scope = _make_scope()
    view = _build_authentic_memory_view()
    session = DiscoverySession.create(
        objective="Slot swapping task test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)

    with pytest.raises(DiscoverySessionError, match="task input_refs missing reference to slot_id"):
        dataclasses.replace(slots[0], task=slots[1].task)


def test_reject_slot_cross_session_request():
    """P1-2: Injecting a request from another session into a slot MUST fail closed."""
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

    with pytest.raises(DiscoverySessionError):
        dataclasses.replace(slots1[0], request=slots2[0].request)


@pytest.mark.parametrize("bad_attempt", [True, False, 0, -1, "1", 1.5, None])
def test_reject_slot_bool_or_invalid_attempt(bad_attempt: Any):
    """P1-2: PlannedCandidateSlot must reject boolean or non-positive attempt counts."""
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
        DiscoverySession.from_dict(data, memory_view=view)


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
        DiscoverySession.from_dict(data, memory_view=view)


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
        DiscoverySession.from_dict(data, memory_view=view)


def test_permanent_non_trading_boundaries():
    """Verify that live_trading_authorized and production_trading permissions are permanently rejected."""
    with pytest.raises(PermissionDeniedError, match="Hard invariant violation"):
        _make_scope(permissions=["read_research_memory", "create_hypothesis", "live_trading_authorized"])

    with pytest.raises(PermissionDeniedError, match="Hard invariant violation"):
        _make_scope(permissions=["read_research_memory", "create_hypothesis", "production_trading"])


def test_p1_universe_and_families_permutation_planning_identity():
    """P1: Verify universe and signal families permutations yield identical session identity,
    identical normalized attributes, and identical PlannedCandidateSlot requests & tasks.
    """
    scope = _make_scope()
    view = _build_authentic_memory_view()

    s1 = DiscoverySession.create(
        objective="Permutation invariant exploration",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe=("rb", "cu"),
        allowed_frequency="1d",
        allowed_signal_families=("trend", "momentum"),
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    s2 = DiscoverySession.create(
        objective="Permutation invariant exploration",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe=("cu", "rb"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "trend"),
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    assert s1.session_id == s2.session_id
    assert s1.session_content_hash == s2.session_content_hash
    assert s1.allowed_universe == ("cu", "rb")
    assert s2.allowed_universe == ("cu", "rb")
    assert s1.allowed_signal_families == ("momentum", "trend")
    assert s2.allowed_signal_families == ("momentum", "trend")
    assert s1.to_dict() == s2.to_dict()

    slots1 = plan_candidate_slots(s1, view)
    slots2 = plan_candidate_slots(s2, view)

    assert len(slots1) == len(slots2) == 2
    for slot1, slot2 in zip(slots1, slots2):
        assert slot1.slot_id == slot2.slot_id
        assert slot1.slot_content_hash == slot2.slot_content_hash
        assert slot1.request.to_dict() == slot2.request.to_dict()
        assert slot1.task.task_id == slot2.task.task_id
        assert slot1.task.work_block == slot2.task.work_block
        assert slot1.task.to_dict() == slot2.task.to_dict()


def test_p1_whitespace_elements_and_direct_constructor_stability():
    """P1: Verify elements with whitespace and unstripped frequency/objective
    are canonicalized and plan identical tasks across direct constructor and create.
    """
    scope = _make_scope()
    view = _build_authentic_memory_view()

    s_create = DiscoverySession.create(
        objective="  Normalized objective with surrounding whitespace  ",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=1,
        allowed_universe=("  rb  ", "  cu  "),
        allowed_frequency=" 1d ",
        allowed_signal_families=(" trend ", " momentum "),
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    assert s_create.objective == "Normalized objective with surrounding whitespace"
    assert s_create.allowed_frequency == "1d"
    assert s_create.allowed_universe == ("cu", "rb")
    assert s_create.allowed_signal_families == ("momentum", "trend")

    # Direct constructor with raw whitespace/un-ordered parameters
    s_direct = DiscoverySession(
        session_id=s_create.session_id,
        session_content_hash=s_create.session_content_hash,
        objective="  Normalized objective with surrounding whitespace  ",
        project_binding=dict(s_create.project_binding),
        authorized_scope_ref=dict(s_create.authorized_scope_ref),
        memory_view_ref=dict(s_create.memory_view_ref),
        memory_view_id=s_create.memory_view_id,
        memory_view_content_hash=s_create.memory_view_content_hash,
        memory_view_snapshot_hash=s_create.memory_view_snapshot_hash,
        candidate_budget=1,
        allowed_universe=("rb", "cu"),
        allowed_frequency=" 1d ",
        memory_view=view,
        allowed_signal_families=("trend", "momentum"),
        generation_policy_version=s_create.generation_policy_version,
        created_at=s_create.created_at,
        schema_version=s_create.schema_version,
    )

    assert s_direct.objective == s_create.objective
    assert s_direct.allowed_frequency == s_create.allowed_frequency
    assert s_direct.allowed_universe == s_create.allowed_universe
    assert s_direct.allowed_signal_families == s_create.allowed_signal_families
    assert s_direct.to_dict() == s_create.to_dict()

    slot_create = plan_candidate_slots(s_create, view)[0]
    slot_direct = plan_candidate_slots(s_direct, view)[0]

    assert slot_create.slot_id == slot_direct.slot_id
    assert slot_create.request.to_dict() == slot_direct.request.to_dict()
    assert slot_create.task.task_id == slot_direct.task.task_id
    assert slot_create.task.work_block == slot_direct.task.work_block


def test_p1_unresealed_from_dict_reordered_universe_and_families_identity():
    """P1: Verify from_dict re-ordering without resealing produces canonical storage
    and exactly identical plan without creating a diverged task.
    """
    scope = _make_scope()
    view = _build_authentic_memory_view()

    s_orig = DiscoverySession.create(
        objective="Strict from_dict reorder stability",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=1,
        allowed_universe=("cu", "rb"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "trend"),
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    d_tampered = s_orig.to_dict()
    # Invert universe and families order, inject whitespace into objective & frequency
    d_tampered["allowed_universe"] = ["rb", "cu"]
    d_tampered["allowed_signal_families"] = ["trend", "momentum"]
    d_tampered["objective"] = "  Strict from_dict reorder stability  "
    d_tampered["allowed_frequency"] = " 1d "
    # Do NOT update session_content_hash or session_id

    s_restored = DiscoverySession.from_dict(d_tampered, memory_view=view)

    assert s_restored.session_id == s_orig.session_id
    assert s_restored.session_content_hash == s_orig.session_content_hash
    assert s_restored.allowed_universe == ("cu", "rb")
    assert s_restored.allowed_signal_families == ("momentum", "trend")
    assert s_restored.objective == "Strict from_dict reorder stability"
    assert s_restored.allowed_frequency == "1d"
    assert s_restored.to_dict() == s_orig.to_dict()

    orig_slot = plan_candidate_slots(s_orig, view)[0]
    restored_slot = plan_candidate_slots(s_restored, view)[0]

    assert restored_slot.slot_id == orig_slot.slot_id
    assert restored_slot.request.to_dict() == orig_slot.request.to_dict()
    assert restored_slot.task.task_id == orig_slot.task.task_id
    assert restored_slot.task.work_block == orig_slot.task.work_block


@pytest.mark.parametrize("policy_version", [DISCOVERY_POLICY_VERSION, PROMPT_POLICY_VERSION])
def test_p2_supported_policies_three_entries_through_to_plan(policy_version):
    """P2: Verify all genuinely supported policies succeed across all three entries
    (create, direct constructor, from_dict) and successfully generate valid candidate slots.
    """
    scope = _make_scope()
    view = _build_authentic_memory_view()

    # Entry 1: create factory
    s_create = DiscoverySession.create(
        objective=f"Testing supported policy {policy_version}",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=1,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        generation_policy_version=policy_version,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots_create = plan_candidate_slots(s_create, view)
    assert len(slots_create) == 1
    assert slots_create[0].request.generation_policy_version == policy_version
    assert slots_create[0].task.role == "alpha_generator"

    # Entry 2: direct constructor
    s_direct = DiscoverySession(
        session_id=s_create.session_id,
        session_content_hash=s_create.session_content_hash,
        objective=s_create.objective,
        project_binding=dict(s_create.project_binding),
        authorized_scope_ref=dict(s_create.authorized_scope_ref),
        memory_view_ref=dict(s_create.memory_view_ref),
        memory_view_id=s_create.memory_view_id,
        memory_view_content_hash=s_create.memory_view_content_hash,
        memory_view_snapshot_hash=s_create.memory_view_snapshot_hash,
        candidate_budget=1,
        allowed_universe=s_create.allowed_universe,
        allowed_frequency=s_create.allowed_frequency,
        memory_view=view,
        allowed_signal_families=s_create.allowed_signal_families,
        generation_policy_version=policy_version,
        created_at=s_create.created_at,
        schema_version=s_create.schema_version,
    )
    slots_direct = plan_candidate_slots(s_direct, view)
    assert len(slots_direct) == 1
    assert slots_direct[0].request.generation_policy_version == policy_version

    # Entry 3: from_dict
    s_from_dict = DiscoverySession.from_dict(s_create.to_dict(), memory_view=view)
    slots_from_dict = plan_candidate_slots(s_from_dict, view)
    assert len(slots_from_dict) == 1
    assert slots_from_dict[0].request.generation_policy_version == policy_version


@pytest.mark.parametrize("invalid_policy", ["discovery_session_policy.v1", "unknown_rogue_policy.v99"])
def test_p2_unsupported_policy_rejected_at_all_three_entries(invalid_policy):
    """P2: Verify unsupported policies (including unmapped discovery_session_policy.v1)
    are strictly rejected at create, direct constructor, and from_dict.
    """
    scope = _make_scope()
    view = _build_authentic_memory_view()

    # Entry 1: create
    with pytest.raises(DiscoverySessionError, match="Unsupported generation_policy_version"):
        DiscoverySession.create(
            objective="Reject invalid policy test",
            memory_view=view,
            authorized_scope=scope,
            candidate_budget=1,
            allowed_universe="test_univ",
            allowed_frequency="1d",
            generation_policy_version=invalid_policy,
        )

    # Valid session for template
    valid_session = DiscoverySession.create(
        objective="Template for invalid policy test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=1,
        allowed_universe="test_univ",
        allowed_frequency="1d",
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    # Entry 2: direct constructor
    with pytest.raises(DiscoverySessionError, match="Unsupported generation_policy_version"):
        DiscoverySession(
            session_id=valid_session.session_id,
            session_content_hash=valid_session.session_content_hash,
            objective=valid_session.objective,
            project_binding=dict(valid_session.project_binding),
            authorized_scope_ref=dict(valid_session.authorized_scope_ref),
            memory_view_ref=dict(valid_session.memory_view_ref),
            memory_view_id=valid_session.memory_view_id,
            memory_view_content_hash=valid_session.memory_view_content_hash,
            memory_view_snapshot_hash=valid_session.memory_view_snapshot_hash,
            candidate_budget=1,
            allowed_universe=valid_session.allowed_universe,
            allowed_frequency=valid_session.allowed_frequency,
            memory_view=view,
            allowed_signal_families=valid_session.allowed_signal_families,
            generation_policy_version=invalid_policy,
            created_at=valid_session.created_at,
            schema_version=valid_session.schema_version,
        )

    # Entry 3: from_dict
    d_invalid = valid_session.to_dict()
    d_invalid["generation_policy_version"] = invalid_policy
    with pytest.raises(DiscoverySessionError, match="Unsupported generation_policy_version"):
        DiscoverySession.from_dict(d_invalid, memory_view=view)
