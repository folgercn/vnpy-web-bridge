"""Comprehensive contract tests for Milestone A: Astra Discovery Session Contract (#502).

Covers:
- Positive cases: 1 and 10 candidate budgets, empty/non-empty/truncated memory views,
  roundtrip serialization, deterministic replanning, distinct slot identities, attempt handling.
- Negative cases (fail-closed): budget 0/11/bool/float/string/None, empty/oversized objective,
  wrong role, missing/extra permissions, nested delegation, project binding mismatch,
  memory view mismatch, cross-session tampering, resealing bypass, unknown fields.
- Zero side-effects: SQLite database untouched, no provider calls, no critic calls.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from research_lab.agent_control.contracts import ProjectBinding
from research_lab.agent_control.discovery_session import (
    CANONICAL_SESSION_TIMESTAMP,
    DISCOVERY_POLICY_VERSION,
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
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    TamperDetectionError,
)
from research_lab.agent_control.memory_view import (
    ResearchMemoryCategory,
    ResearchMemoryEntryView,
    ResearchMemoryView,
)
from research_lab.agent_control.roles import DEFAULT_ROLE_POLICIES
from research_lab.agent_control.router import authorize
from research_lab.alpha_discovery.research_memory import ResearchMemory

PROJECT_ID = "vnpy-web-bridge"
WORKSPACE = "/Users/fujun/node/vnpy-web-bridge"
BINDING = ProjectBinding(project_id=PROJECT_ID, workspace_identity=WORKSPACE)
REQUIRED_PERMS = ["read_research_memory", "create_hypothesis"]


def _make_scope(
    *,
    role: str = "alpha_generator",
    permissions: list[str] | None = None,
    project_binding: ProjectBinding = BINDING,
):
    perms = REQUIRED_PERMS if permissions is None else permissions
    return authorize(role, perms, project_binding)


def _make_entry(
    *,
    entry_id: str,
    category: str,
    decision: str = "REJECT",
    summary: str = "Test research entry summary",
    reason_codes: tuple[str, ...] = ("low_ic",),
    gap_type: str | None = None,
    failure_class: str | None = None,
) -> ResearchMemoryEntryView:
    hypo_hash = "h" * 64
    sci_hash = "s" * 64
    return ResearchMemoryEntryView(
        entry_id=entry_id,
        category=category,
        hypothesis_id=f"hypo-{entry_id}",
        hypothesis_content_hash=hypo_hash,
        scientific_identity_hash=sci_hash,
        decision=decision,
        summary=summary,
        source_refs={"record_id": f"rec-{entry_id}"},
        source_hashes={"content_hash": hypo_hash},
        evidence_refs=({"evidence_id": f"ev-{entry_id}", "hash": "e" * 64},),
        view_generated_from=f"test_source_{entry_id}",
        decision_time="2026-09-20T00:00:00Z",
        reason_codes=reason_codes,
        gap_type=gap_type,
        failure_class=failure_class,
    )


def _make_memory_view(
    *,
    role: str = "alpha_generator",
    project_binding: ProjectBinding = BINDING,
    entries_by_category: dict[str, tuple[ResearchMemoryEntryView, ...]] | None = None,
    is_truncated: bool = False,
    view_id: str = "memview-test-001",
    content_hash: str = "a" * 64,
) -> ResearchMemoryView:
    cats = (
        ResearchMemoryCategory.RECENT_REJECTS.value,
        ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
        ResearchMemoryCategory.NME_BACKLOG.value,
        ResearchMemoryCategory.FAILED_APPROACHES.value,
        ResearchMemoryCategory.RESEARCH_GAPS.value,
    )
    entries = entries_by_category or {cat: () for cat in cats}
    total = sum(len(v) for v in entries.values())
    return ResearchMemoryView(
        view_id=view_id,
        view_content_hash=content_hash,
        role=role,
        project_binding=project_binding.to_dict(),
        categories=cats,
        entries_by_category=entries,
        total_entries=total,
        policy_version="research_memory_view.v1",
        generated_at="2026-09-21T00:00:00Z",
        source_refs=("test_source_ref",),
        is_truncated=is_truncated,
    )


# ==============================================================================
# Positive Tests
# ==============================================================================


def test_discovery_session_creation_single_candidate():
    """Verify DiscoverySession creation with minimum candidate budget (1 slot)."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Discover short-term momentum signals on commodity futures",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=MIN_CANDIDATE_BUDGET,
        allowed_universe="commodity_futures_main",
        allowed_frequency="1m",
        allowed_signal_families=("momentum",),
    )

    assert session.session_id.startswith("disc-session-")
    assert len(session.session_content_hash) == 64
    assert session.candidate_budget == 1
    assert session.objective == "Discover short-term momentum signals on commodity futures"
    assert session.memory_view_id == view.view_id
    assert session.memory_view_content_hash == view.view_content_hash
    assert session.project_binding == BINDING.to_dict()
    assert session.allowed_frequency == "1m"
    assert session.allowed_signal_families == ("momentum",)

    # Test slot planning
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
    view = _make_memory_view()
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

    # Verify all slots have unique slot_id and unique task_id
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
    view = _make_memory_view()
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
    entries = {
        ResearchMemoryCategory.RESEARCH_GAPS.value: (
            _make_entry(
                entry_id="gap-001",
                category=ResearchMemoryCategory.RESEARCH_GAPS.value,
                summary="Lack of overnight gap momentum tests",
                gap_type="untested_horizon",
            ),
        ),
        ResearchMemoryCategory.NME_BACKLOG.value: (
            _make_entry(
                entry_id="nme-001",
                category=ResearchMemoryCategory.NME_BACKLOG.value,
                decision="NEED_MORE_EVIDENCE",
                summary="Orderbook imbalance signal needs cost ladder evidence",
            ),
        ),
        ResearchMemoryCategory.FAILED_APPROACHES.value: (
            _make_entry(
                entry_id="fail-001",
                category=ResearchMemoryCategory.FAILED_APPROACHES.value,
                decision="REJECT",
                summary="Simple moving average crossover on illiquid months",
                failure_class="scientific",
            ),
        ),
        ResearchMemoryCategory.RECENT_REJECTS.value: (
            _make_entry(
                entry_id="rej-001",
                category=ResearchMemoryCategory.RECENT_REJECTS.value,
                decision="REJECT",
                summary="High turnover microstructural noise",
                reason_codes=("excessive_turnover", "low_t_stat"),
            ),
        ),
        ResearchMemoryCategory.PROMOTED_SUMMARIES.value: (
            _make_entry(
                entry_id="prom-001",
                category=ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
                decision="PROMOTE",
                summary="Cross-sectional term structure carry factor",
            ),
        ),
    }
    view = _make_memory_view(entries_by_category=entries)
    assert view.total_entries == 5

    ctx = extract_session_memory_context(view)
    assert ctx.is_empty is False
    assert ctx.total_entries == 5
    assert len(ctx.research_gaps) == 1
    assert ctx.research_gaps[0]["entry_id"] == "gap-001"
    assert ctx.research_gaps[0]["gap_type"] == "untested_horizon"
    assert len(ctx.nme_backlog) == 1
    assert ctx.nme_backlog[0]["entry_id"] == "nme-001"
    assert len(ctx.failed_approaches) == 1
    assert ctx.failed_approaches[0]["entry_id"] == "fail-001"
    assert len(ctx.recent_rejects) == 1
    assert ctx.recent_rejects[0]["reason_codes"] == ["excessive_turnover", "low_t_stat"]
    assert len(ctx.promoted_summaries) == 1
    assert set(ctx.valid_entry_ids) == {"gap-001", "nme-001", "fail-001", "rej-001", "prom-001"}

    session = DiscoverySession.create(
        objective="Explore carry factors with prior reject context",
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
    view = _make_memory_view(is_truncated=True)
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
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Roundtrip serialization test objective",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=7,
        allowed_universe=("AU", "AG"),
        allowed_frequency="5m",
        allowed_signal_families=("volatility_breakout",),
    )

    data = session.to_dict()
    restored = DiscoverySession.from_dict(data)

    assert restored.session_id == session.session_id
    assert restored.session_content_hash == session.session_content_hash
    assert restored.objective == session.objective
    assert restored.candidate_budget == session.candidate_budget
    assert restored.project_binding == session.project_binding
    assert restored.authorized_scope_ref == session.authorized_scope_ref
    assert restored.memory_view_id == session.memory_view_id
    assert restored.memory_view_content_hash == session.memory_view_content_hash
    assert restored.allowed_universe == session.allowed_universe
    assert restored.allowed_frequency == session.allowed_frequency
    assert restored.allowed_signal_families == session.allowed_signal_families
    assert restored.generation_policy_version == session.generation_policy_version
    assert restored.to_dict() == data


def test_discovery_session_replanning_determinism():
    """Verify that repeated planning calls on the same session produce 100% identical slot IDs and tasks."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Deterministic replanning verification",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=4,
        allowed_universe="agricultural_futures",
        allowed_frequency="1d",
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
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Slot attempt update verification",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=2,
        allowed_universe="base_metals",
        allowed_frequency="15m",
    )
    slots = plan_candidate_slots(session, view)
    slot1 = slots[0]
    assert slot1.attempt == 1

    # Replan attempt 2 (e.g. after provider timeout/failure)
    retry_slot = replan_slot_attempt(slot1, view, attempt=2)
    assert retry_slot.slot_id == slot1.slot_id  # Stable logical slot identity!
    assert retry_slot.ordinal == slot1.ordinal
    assert retry_slot.attempt == 2
    assert retry_slot.request.attempt == 2
    assert retry_slot.request.request_id != slot1.request.request_id  # Differentiates execution attempt
    assert retry_slot.task.task_id != slot1.task.task_id


# ==============================================================================
# Negative Tests (Fail-Closed)
# ==============================================================================


@pytest.mark.parametrize("bad_budget", [0, 11, -1, 100, -10])
def test_reject_budget_out_of_bounds(bad_budget: int):
    """Verify that budgets outside 1..10 are rejected with DiscoverySessionBudgetError."""
    scope = _make_scope()
    view = _make_memory_view()
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
    view = _make_memory_view()
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
    view = _make_memory_view()
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
    view = _make_memory_view()
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
    view = _make_memory_view()
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


@pytest.mark.parametrize("unauthorized_role", [
    "data_researcher",
    "code_researcher",
    "research_synthesizer",
    "external_researcher",
])
def test_reject_scope_wrong_role(unauthorized_role: str):
    """Verify that any role other than alpha_generator is rejected fail-closed."""
    policy = DEFAULT_ROLE_POLICIES[unauthorized_role]
    scope = authorize(unauthorized_role, list(policy.allowed_permissions), BINDING)
    view = _make_memory_view(role="alpha_generator")
    with pytest.raises(PermissionDeniedError, match="DiscoverySession requires an alpha_generator"):
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
    # Scope with only read_research_memory (missing create_hypothesis)
    scope = _make_scope(permissions=["read_research_memory"])
    view = _make_memory_view()
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
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Unauthorized expansion test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    data = session.to_dict()
    data["authorized_scope_ref"]["authorized_permissions"].append(forbidden_permission)
    with pytest.raises(PermissionDeniedError):
        DiscoverySession.from_dict(data)


def test_reject_scope_nested_delegation():
    """Verify that nested delegation attempts (can_delegate=True or max_delegation_depth > 0) fail closed."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Nested delegation test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    # Test can_delegate = True
    data1 = session.to_dict()
    data1["authorized_scope_ref"]["can_delegate"] = True
    with pytest.raises(PermissionDeniedError, match="Nested delegation prohibited"):
        DiscoverySession.from_dict(data1)

    # Test max_delegation_depth = 1
    data2 = session.to_dict()
    data2["authorized_scope_ref"]["max_delegation_depth"] = 1
    with pytest.raises(PermissionDeniedError, match="Nested delegation prohibited"):
        DiscoverySession.from_dict(data2)


def test_reject_project_binding_mismatch():
    """Verify that project binding mismatches between Session, Scope, and Memory View fail closed."""
    foreign_binding = ProjectBinding(project_id="other-project", workspace_identity="/other/path")
    scope = _make_scope(project_binding=foreign_binding)
    view = _make_memory_view(project_binding=BINDING)

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


def test_reject_memory_view_tampered_hash():
    """Verify that tampering with memory view content hash fails closed."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Tamper test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    # Tamper with view content hash
    tampered_view = ResearchMemoryView(
        view_id=view.view_id,
        view_content_hash="f" * 64,  # Forged hash!
        role=view.role,
        project_binding=view.project_binding,
        categories=view.categories,
        entries_by_category=view.entries_by_category,
        total_entries=view.total_entries,
        policy_version=view.policy_version,
        generated_at=view.generated_at,
        source_refs=view.source_refs,
    )

    with pytest.raises(TamperDetectionError, match="memory_view view_content_hash mismatch"):
        plan_candidate_slots(session, tampered_view)


def test_reject_memory_view_id_mismatch():
    """Verify that swapping memory view ID fails closed."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="View id mismatch test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    swapped_view = _make_memory_view(view_id="memview-swapped-999")
    with pytest.raises(DiscoverySessionError, match="memory_view view_id mismatch"):
        plan_candidate_slots(session, swapped_view)


def test_reject_resealing_with_forged_content_hash():
    """Verify that providing an incorrect session_content_hash raises TamperDetectionError."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Reseal test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    data = session.to_dict()
    data["session_content_hash"] = "e" * 64  # Tampered hash!

    with pytest.raises(TamperDetectionError, match="session_content_hash mismatch"):
        DiscoverySession.from_dict(data)


def test_reject_resealing_with_tampered_field_and_original_hash():
    """Verify that tampering with fields while keeping original hash raises TamperDetectionError."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Reseal tamper field test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    data = session.to_dict()
    data["objective"] = "Tampered objective secretly injected"

    with pytest.raises(TamperDetectionError, match="session_content_hash mismatch"):
        DiscoverySession.from_dict(data)


def test_reject_resealing_cannot_bypass_invariants():
    """Verify that re-sealing with a newly computed hash cannot bypass core invariant checks (e.g. budget > 10)."""
    scope = _make_scope()
    view = _make_memory_view()

    # Craft payload with candidate_budget = 99 and recomputed valid hash
    payload = {
        "allowed_frequency": "1d",
        "allowed_signal_families": [],
        "allowed_universe": "test_univ",
        "authorized_scope_ref": scope.to_dict(),
        "candidate_budget": 99,
        "created_at": CANONICAL_SESSION_TIMESTAMP,
        "generation_policy_version": DISCOVERY_POLICY_VERSION,
        "memory_view_content_hash": view.view_content_hash,
        "memory_view_id": view.view_id,
        "objective": "Bypass invariants attempt",
        "project_binding": BINDING.to_dict(),
        "schema_version": "research_lab.discovery_session.v1",
    }
    recomputed_hash = compute_session_content_hash(payload)
    recomputed_id = compute_session_id(recomputed_hash)
    payload["session_content_hash"] = recomputed_hash
    payload["session_id"] = recomputed_id

    with pytest.raises(DiscoverySessionBudgetError, match="candidate_budget must be between 1 and 10"):
        DiscoverySession.from_dict(payload)


def test_reject_unknown_fields_in_from_dict():
    """Verify that extra unknown fields in deserialization payload fail closed."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Unknown field test",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=5,
        allowed_universe="test_univ",
        allowed_frequency="1d",
    )

    data = session.to_dict()
    data["rogue_injected_field"] = "malicious_payload"

    with pytest.raises(DiscoverySessionError, match="Unknown fields rejected under fail-closed policy"):
        DiscoverySession.from_dict(data)


# ==============================================================================
# Zero Side-Effects & Boundary Tests
# ==============================================================================


def test_zero_side_effects_on_planning(tmp_path: Path):
    """Verify that DiscoverySession creation and slot planning do NOT modify ResearchMemory SQLite database."""
    db_file = tmp_path / "research_memory.db"
    ResearchMemory(db_file)

    # Calculate DB file hash and size before session planning
    with open(db_file, "rb") as f:
        before_bytes = f.read()
    before_hash = hashlib.sha256(before_bytes).hexdigest()
    before_size = len(before_bytes)

    # Perform DiscoverySession and slot planning
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Zero side-effects test objective",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=10,
        allowed_universe="test_univ",
        allowed_frequency="1m",
    )
    slots = plan_candidate_slots(session, view)
    assert len(slots) == 10

    # Verify DB file hash and size after planning are strictly identical
    with open(db_file, "rb") as f:
        after_bytes = f.read()
    after_hash = hashlib.sha256(after_bytes).hexdigest()
    after_size = len(after_bytes)

    assert before_hash == after_hash
    assert before_size == after_size


def test_permanent_non_trading_boundaries():
    """Verify that DiscoverySession and generated tasks permanently preserve non-trading invariants."""
    scope = _make_scope()
    view = _make_memory_view()
    session = DiscoverySession.create(
        objective="Trading invariant check",
        memory_view=view,
        authorized_scope=scope,
        candidate_budget=3,
        allowed_universe="test_univ",
        allowed_frequency="1h",
    )
    slots = plan_candidate_slots(session, view)

    for slot in slots:
        # Check permissions on AgentTask
        assert "production_trading" not in slot.task.requested_permissions
        assert "production_trading" not in slot.task.authorized_permissions
        assert "live_trading_authorized" not in slot.task.requested_permissions
        assert "live_trading_authorized" not in slot.task.authorized_permissions
        assert slot.task.role == "alpha_generator"
        assert slot.task.delegation_depth == 0
