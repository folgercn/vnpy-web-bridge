"""Tests for Batch Discovery Execution, Funnel Metrics, and Memory Feedback Loop.

Covers Issue #502 Stage 2 (Milestones B, C, D):
1. Sequential batch execution over 1-10 PlannedCandidateSlots.
2. Execution-side scope admission (universe, frequency, signal_family).
3. Engineering failure isolation (provider error, parse failure, acceptance failure).
4. Attempt replay idempotency.
5. Deterministic intra-batch and historical deduplication.
6. DiscoveryBatchFunnel partition invariants and denominator clarity.
7. Two-round memory feedback loop with AlphaDiscoveryEngine and verifiable attribution.
"""

from __future__ import annotations

import csv
import dataclasses
import json
from pathlib import Path
import re
from collections.abc import Mapping
from typing import Any

from unittest import mock
import pytest

from research_lab.agent_control.alpha_generator import (
    AlphaGenerationError,
    _validate_universe_scope,
)
from research_lab.agent_control.batch_discovery import (
    DISCOVERY_BATCH_SCHEMA_VERSION,
    DiscoveryBatchFunnel,
    DiscoveryBatchOrchestrator,
    MemoryFeedbackAttributionRecord,
    MemoryFeedbackLoopResult,
    SlotEngineeringStatus,
    execute_memory_feedback_loop,
)
from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentResult,
    AgentUsageSnapshot,
    TerminalStatus,
)
from research_lab.agent_control.discovery_integration import (
    DiscoveryIntegrationOrchestrator,
)
from research_lab.agent_control.discovery_session import (
    CANONICAL_SESSION_TIMESTAMP,
    DiscoverySession,
    plan_candidate_slots,
    replan_slot_attempt,
)
from research_lab.agent_control.memory_view import (
    ResearchMemoryCategory,
    ResearchMemoryQuery,
    ResearchMemoryView,
    build_research_memory_view,
)
from research_lab.agent_control.providers.contract_test_provider import (
    CONTRACT_TEST_DEFAULT_MODEL,
    CONTRACT_TEST_PROVIDER_NAME,
    ContractTestProvider,
)
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.roles import AgentRole
from research_lab.agent_control.router import authorize
from research_lab.agent_control.routing_policy import RoutingPolicy
from research_lab.agent_control.transports.direct_sdk_test import (
    DirectSDKTestTransport,
)
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

WORKSPACE_IDENTITY = "/mock/workspace/vnpy"
PROJECT_ID = "vnpy"
STANDARD_PROJECT_BINDING = {
    "project_id": PROJECT_ID,
    "workspace_identity": WORKSPACE_IDENTITY,
}
NOW = "2026-09-21T00:00:00.000000Z"


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


def _build_candidate_envelope(
    *,
    title: str = "Short-term momentum continuation",
    signal_family: str = "momentum",
    universe: str = "RB2405",
    frequency: str = "1d",
    holding_horizon: str = "3d",
    target: str = "forward_return_3d",
    signal_definition: str | None = None,
    source_context_refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "hypothesis": {
            "title": title,
            "economic_rationale": "Trend continuation driven by structural inventory shifts.",
            "signal_family": signal_family,
            "signal_definition": signal_definition or f"positive rolling return over 5 bars on {universe}",
            "source_features": ["close", "high", "low"],
            "target": target,
            "expected_direction": "positive",
            "holding_horizon": holding_horizon,
            "universe": universe,
            "frequency": frequency,
            "known_risks": ["sudden inventory release or basis collapse"],
            "falsification_conditions": [
                "directional correlation is non-positive out-of-sample"
            ],
            "proposed_screening_methods": [
                "coverage and directional association checks"
            ],
            "signal_type": "signed_scalar",
        },
        "rationale": "Bounded falsifiable candidate for discovery test.",
        "source_context_refs": source_context_refs or [],
        "novelty_statement": "Novel hypothesis within current test iteration.",
        "duplicate_awareness": "Distinct parameterization and signal definition.",
        "uncertainty": "Regime shifts in commodity macro cycle.",
    }


def _build_test_memory_view(
    memory: ResearchMemory,
    authorized_scope: AgentPermissionScope,
    role: str = AgentRole.ALPHA_GENERATOR.value,
) -> ResearchMemoryView:
    categories = (
        ResearchMemoryCategory.RECENT_REJECTS.value,
        ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
        ResearchMemoryCategory.NME_BACKLOG.value,
        ResearchMemoryCategory.RESEARCH_GAPS.value,
    )
    query = ResearchMemoryQuery(
        role=role,
        project_binding=STANDARD_PROJECT_BINDING,
        categories=categories,
    )
    return build_research_memory_view(
        query=query,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        memory_store=memory,
    )


def configure_provider_output(
    test_provider: ContractTestProvider,
    output_map_or_fn_or_str: Any,
) -> None:
    """Helper to configure output returned by ContractTestProvider via transport invoker."""
    def _invoker(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if operation == "execute":
            task_id = payload.get("input", {}).get("task_id", "")
            if callable(output_map_or_fn_or_str):
                out = output_map_or_fn_or_str(payload)
            elif isinstance(output_map_or_fn_or_str, dict) and task_id in output_map_or_fn_or_str:
                out = output_map_or_fn_or_str[task_id]
            else:
                out = output_map_or_fn_or_str
            return {
                "operation": "execute",
                "status": "COMPLETED",
                "output": out,
            }
        return {"status": "HEALTHY"}

    test_provider.transport.set_custom_invoker(_invoker)


@pytest.fixture
def test_provider() -> ContractTestProvider:
    transport = DirectSDKTestTransport()
    return ContractTestProvider(transport=transport)


@pytest.fixture
def provider_registry(test_provider: ContractTestProvider) -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(test_provider)
    return registry


@pytest.fixture
def authorized_scope() -> AgentPermissionScope:
    return authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=["read_research_memory", "create_hypothesis"],
        project_binding=STANDARD_PROJECT_BINDING,
    )


@pytest.fixture
def routing_policy() -> RoutingPolicy:
    return RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=(CONTRACT_TEST_PROVIDER_NAME,),
    )


@pytest.fixture
def discovery_context(tmp_path: Path) -> dict[str, Any]:
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
    for i in range(1, 60):
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
    return {
        "clean_binding": clean_binding,
        "clean_csv": clean_csv,
        "engine": engine,
        "memory": memory,
        "orchestrator": orchestrator,
        "store": store,
        "tmp_path": tmp_path,
    }


# =====================================================================
# Milestone B Tests: Sequential Execution, Scope Admission, Isolations
# =====================================================================

def test_batch_discovery_sequential_execution_budget_1(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Sequential batch discovery with budget 1."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Discover short-term momentum signals in liquid commodities",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "trend_following"),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    assert session.candidate_budget == 1

    envelope = _build_candidate_envelope(
        title="Single slot momentum candidate",
        signal_family="momentum",
        universe="RB2405",
        frequency="1d",
    )
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    batch_result = orchestrator.execute_session(session=session, memory_view=view)

    assert batch_result.schema_version == DISCOVERY_BATCH_SCHEMA_VERSION
    assert batch_result.total_slots_planned == 1
    assert len(batch_result.successful_slots) == 1
    assert len(batch_result.failed_slots) == 0
    assert len(batch_result.admitted_candidates) == 1
    assert batch_result.funnel.admitted_candidates == 1
    assert batch_result.funnel.novel_candidates == 1
    assert batch_result.funnel.novelty_rate == 1.0
    assert batch_result.funnel.duplicate_rate == 0.0


def test_batch_discovery_sequential_execution_budget_10(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Sequential batch discovery across all 10 planned slots."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Discover short-term momentum signals in liquid commodities",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=10,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "reversal"),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    assert session.candidate_budget == 10

    # Dynamic provider response producing distinct novel candidates
    counter = {"val": 0}

    def _dynamic_output(payload: dict[str, Any]) -> str:
        idx = counter["val"]
        counter["val"] += 1
        fam = "momentum" if idx % 2 == 0 else "reversal"
        return json.dumps(
            _build_candidate_envelope(
                title=f"Slot Candidate {idx}",
                signal_family=fam,
                universe="RB2405",
                frequency="1d",
                holding_horizon=f"{idx + 1}d",
                target=f"forward_return_{idx + 1}d",
            )
        )

    configure_provider_output(test_provider, _dynamic_output)

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    batch_result = orchestrator.execute_session(session=session, memory_view=view)

    assert batch_result.total_slots_planned == 10
    assert len(batch_result.successful_slots) == 10
    assert len(batch_result.failed_slots) == 0
    assert len(batch_result.admitted_candidates) == 10

    funnel = batch_result.funnel
    assert funnel.total_slots_planned == 10
    assert funnel.successful_slots == 10
    assert funnel.failed_slots == 0
    assert funnel.admitted_candidates == 10
    assert funnel.novel_candidates == 10
    assert funnel.exact_duplicates == 0
    assert funnel.related_duplicates == 0
    assert funnel.novelty_rate == 1.0


def test_batch_discovery_funnel_partition_invariants() -> None:
    """Milestone B: Funnel partition identity and denominator validation."""
    funnel = DiscoveryBatchFunnel(
        requested=10,
        attempted=10,
        generated=9,
        admitted=7,
        invalid=2,
        provider_failed=1,
        exact_duplicate_count=1,
        related_count=1,
        novel_count=5,
        signal_families={"momentum": 4, "reversal": 3},
        not_attempted=0,
    )
    # Verification of partition identities:
    assert funnel.total_slots_planned == 10
    assert funnel.admitted_candidates == 7
    assert funnel.novel_candidates == 5
    assert funnel.exact_duplicates == 1
    assert funnel.related_duplicates == 1
    # Admitted = exact + related + novel
    assert funnel.admitted == funnel.exact_duplicate_count + funnel.related_count + funnel.novel_count
    # Total denominator rate check:
    assert abs(funnel.duplicate_rate - (2 / 7)) < 1e-9
    assert abs(funnel.novelty_rate - (5 / 7)) < 1e-9


def test_scope_admission_frequency_rejection(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Execution-side scope admission isolates frequency mismatch."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Daily commodity momentum signals",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    envelope = _build_candidate_envelope(
        title="High frequency attempt",
        signal_family="momentum",
        universe="RB2405",
        frequency="1m",  # Forbidden frequency
    )
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )
    batch_result = orchestrator.execute_session(session=session, memory_view=view)

    assert batch_result.total_slots_planned == 1
    assert len(batch_result.successful_slots) == 0
    assert len(batch_result.failed_slots) == 1
    failed_slot = batch_result.failed_slots[0]
    assert failed_slot.engineering_status == SlotEngineeringStatus.SCOPE_MISMATCH.value
    assert "frequency" in str(failed_slot.error_details).lower()
    assert batch_result.funnel.admitted_candidates == 0


def test_scope_admission_signal_family_rejection(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Execution-side scope admission isolates unallowed signal family."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Momentum signals only",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    envelope = _build_candidate_envelope(
        title="Arbitrary family attempt",
        signal_family="crypto_sentiment",  # Not in allowed families
        universe="RB2405",
        frequency="1d",
    )
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )
    batch_result = orchestrator.execute_session(session=session, memory_view=view)

    assert len(batch_result.failed_slots) == 1
    failed_slot = batch_result.failed_slots[0]
    assert failed_slot.engineering_status == SlotEngineeringStatus.SCOPE_MISMATCH.value
    assert "signal_family" in str(failed_slot.error_details).lower()


def test_scope_admission_universe_rejection(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Execution-side scope admission isolates non-futures universe."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Futures momentum signals",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    envelope = _build_candidate_envelope(
        title="US equity attempt",
        signal_family="momentum",
        universe="AAPL",  # Non-futures symbol
        frequency="1d",
    )
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )
    batch_result = orchestrator.execute_session(session=session, memory_view=view)

    assert len(batch_result.failed_slots) == 1
    failed_slot = batch_result.failed_slots[0]
    assert failed_slot.engineering_status == SlotEngineeringStatus.SCOPE_MISMATCH.value
    assert "universe" in str(failed_slot.error_details).lower()


def test_single_slot_engineering_failure_isolation(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Single-slot engineering failure is isolated; batch proceeds sequentially."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Three slot test with failure isolation",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=3,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "reversal"),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    planned_slots = plan_candidate_slots(session, view)
    assert len(planned_slots) == 3

    # Map outputs by task_id: slot 0 valid, slot 1 malformed, slot 2 valid
    s0_task_id = planned_slots[0].task.task_id
    s1_task_id = planned_slots[1].task.task_id
    s2_task_id = planned_slots[2].task.task_id

    output_map = {
        s0_task_id: json.dumps(_build_candidate_envelope(title="Valid Slot 0", universe="RB2405")),
        s1_task_id: "CORRUPTED_NON_JSON_DELIVERABLE",
        s2_task_id: json.dumps(_build_candidate_envelope(title="Valid Slot 2", universe="HC2405")),
    }
    configure_provider_output(test_provider, output_map)

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )
    batch_result = orchestrator.execute_session(session=session, memory_view=view)

    assert batch_result.total_slots_planned == 3
    assert len(batch_result.successful_slots) == 2
    assert len(batch_result.failed_slots) == 1
    assert batch_result.failed_slots[0].ordinal == 2
    assert batch_result.failed_slots[0].engineering_status == SlotEngineeringStatus.PARSE_FAILED.value
    assert len(batch_result.admitted_candidates) == 2


def test_attempt_replay_idempotency(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Replaying an already executed slot attempt returns cached result idempotently."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Idempotent slot execution",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slot = plan_candidate_slots(session, view)[0]

    envelope = _build_candidate_envelope(title="Idempotent candidate", universe="RB2405")
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )

    # First execution
    res1 = orchestrator.execute_slot(session=session, slot=slot, memory_view=view)
    assert res1.engineering_status == SlotEngineeringStatus.COMPLETED.value
    assert res1.is_replayed is False

    # Second execution of exact same attempt
    res2 = orchestrator.execute_slot(session=session, slot=slot, memory_view=view)
    assert res2.engineering_status == SlotEngineeringStatus.COMPLETED.value
    assert res2.is_replayed is True
    assert res2.candidate is not None
    assert res1.candidate is not None
    assert res2.candidate.candidate_id == res1.candidate.candidate_id


def test_intra_batch_and_historical_deduplication(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Intra-batch deduplication correctly identifies identical candidates."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Intra batch deduplication test",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=2,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    # Both slots generate the exact same hypothesis
    envelope = _build_candidate_envelope(
        title="Identical hypothesis across slots",
        signal_family="momentum",
        universe="RB2405",
    )
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    batch_result = orchestrator.execute_session(session=session, memory_view=view)

    assert batch_result.total_slots_planned == 2
    assert len(batch_result.admitted_candidates) == 2
    # First slot is novel, second slot is intra-batch duplicate
    c1 = batch_result.admitted_candidates[0]
    c2 = batch_result.admitted_candidates[1]
    assert c1.duplicate_status == "NOVEL_WITHIN_VIEW"
    assert c2.duplicate_status == "EXACT_DUPLICATE"

    funnel = batch_result.funnel
    assert funnel.novel_candidates == 1
    assert funnel.exact_duplicates == 1


# =====================================================================
# Milestone C Tests: Two-Round Memory Feedback Loop & Attribution
# =====================================================================

def test_memory_feedback_loop_two_rounds_with_attribution(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone C: Two-round memory feedback loop with AlphaDiscoveryEngine and verifiable attribution."""
    engine: AlphaDiscoveryEngine = discovery_context["engine"]
    memory: ResearchMemory = discovery_context["memory"]
    clean_csv: Path = discovery_context["clean_csv"]
    clean_binding: dict[str, Any] = discovery_context["clean_binding"]

    # Round 1 outputs: 10 distinct candidates
    r1_envelopes: dict[int, dict[str, Any]] = {}
    for i in range(10):
        r1_envelopes[i] = _build_candidate_envelope(
            title=f"Round 1 Basis Momentum Factor #{i}",
            signal_family="momentum" if i % 2 == 0 else "reversal",
            universe="RB2405",
            frequency="1d",
        )

    # Set provider output for Round 1
    round_state = {"current_round": 1, "cited_refs": []}

    def _stateful_provider(payload: dict[str, Any]) -> str:
        prompt = payload.get("input", {}).get("objective", "")
        if round_state["current_round"] == 1:
            # Pick by ordinal or hash
            h = abs(hash(prompt)) % 10
            return json.dumps(r1_envelopes[h])
        # Round 2: cite Round 1 memory entry
        refs = round_state["cited_refs"][:1]
        return json.dumps(
            _build_candidate_envelope(
                title=f"Round 2 Refined Factor citing {refs}",
                signal_family="momentum",
                universe="RB2405",
                frequency="1d",
                source_context_refs=refs,
            )
        )

    configure_provider_output(test_provider, _stateful_provider)

    view_a = _build_test_memory_view(memory, authorized_scope)
    session_r1 = DiscoverySession.create(
        objective="Round 1 Discovery",
        memory_view=view_a,
        authorized_scope=authorized_scope,
        candidate_budget=10,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "reversal"),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    batch_r1 = orchestrator.execute_session(session=session_r1, memory_view=view_a)
    assert len(batch_r1.admitted_candidates) == 10

    # Hand off Round 1 candidates to AlphaDiscoveryEngine
    integration_orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)
    created_memory_records = []
    for slot_res in batch_r1.slots:
        c = slot_res.candidate
        if not c:
            continue
        integration_orchestrator.integrate_candidate(
            candidate=c,
            snapshot_path=clean_csv,
            dataset_binding=clean_binding,
            project_binding=STANDARD_PROJECT_BINDING,
            request_id=f"req-r1-{c.hypothesis.hypothesis_id}",
            task_id=slot_res.task_id or f"task-{c.hypothesis.hypothesis_id}",
            route_id=slot_res.route_id or "route-test",
            provider_job_ref=slot_res.provider_job_ref or f"job-{c.hypothesis.hypothesis_id}",
            provider=slot_res.provider or CONTRACT_TEST_PROVIDER_NAME,
            model=slot_res.model or "test-model-standard",
        )
        records = memory.find_by_hypothesis_id(c.hypothesis.hypothesis_id)
        created_memory_records.extend(records)

    assert len(created_memory_records) > 0

    # Round 2: construct Memory B and execute
    round_state["current_round"] = 2
    view_b = _build_test_memory_view(memory, authorized_scope)
    b_entries = [e for entries in view_b.entries_by_category.values() for e in entries]
    assert len(b_entries) > 0
    target_entry = b_entries[0]
    round_state["cited_refs"] = [target_entry.entry_id]

    session_r2 = DiscoverySession.create(
        objective="Round 2 Discovery with Memory",
        memory_view=view_b,
        authorized_scope=authorized_scope,
        candidate_budget=10,
        allowed_universe=("RB", "HC"),
        allowed_frequency="1d",
        allowed_signal_families=("momentum", "reversal"),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at="2026-01-02T00:00:00.000000Z",
    )

    batch_r2 = orchestrator.execute_session(session=session_r2, memory_view=view_b)
    assert len(batch_r2.admitted_candidates) == 10

    # Build attribution records
    attributions: list[MemoryFeedbackAttributionRecord] = []
    for c in batch_r2.admitted_candidates:
        for ref in c.source_context_refs:
            if ref in round_state["cited_refs"]:
                attributions.append(
                    MemoryFeedbackAttributionRecord(
                        candidate_id=c.hypothesis.hypothesis_id,
                        signal_family=c.hypothesis.signal_family,
                        cited_memory_entry_id=ref,
                        cited_decision=target_entry.decision,
                        predecessor_hypothesis_id=target_entry.hypothesis_id,
                        predecessor_failure_or_gap="Directional correlation below acceptance threshold",
                        adaptation_description=f"Refined signal definition based on {ref}",
                    )
                )

    assert len(attributions) == 10

    feedback_result = MemoryFeedbackLoopResult(
        round_1_session=session_r1,
        round_1_batch=batch_r1,
        round_1_integration_results=(),
        round_2_session=session_r2,
        round_2_batch=batch_r2,
        round_2_integration_results=(),
        attribution_records=tuple(attributions),
        comparative_summary={
            "round1_admitted": len(batch_r1.admitted_candidates),
            "round2_admitted": len(batch_r2.admitted_candidates),
            "attributions_count": len(attributions),
        },
    )

    assert feedback_result.comparative_summary["round1_admitted"] == 10
    assert feedback_result.comparative_summary["round2_admitted"] == 10
    assert feedback_result.comparative_summary["attributions_count"] == 10


def test_cross_session_slot_execution_rejected(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: execute_slot strictly rejects foreign slot from another session."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session_a = DiscoverySession.create(
        objective="Session A",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    session_b = DiscoverySession.create(
        objective="Session B",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("HC",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slot_b = plan_candidate_slots(session_b, view)[0]

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )
    # Attempt to execute slot_b within session_a
    res = orchestrator.execute_slot(session=session_a, slot=slot_b, memory_view=view)
    assert res.engineering_status == SlotEngineeringStatus.ADMISSION_FAILED.value
    assert res.error_code == "SESSION_MISMATCH"
    assert (session_a.session_id, slot_b.slot_id, slot_b.attempt) not in orchestrator._execution_cache


def test_cross_view_slot_execution_rejected(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: execute_slot strictly rejects mismatched memory view."""
    memory: ResearchMemory = discovery_context["memory"]
    view_1 = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Session with View 1",
        memory_view=view_1,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slot = plan_candidate_slots(session, view_1)[0]

    # Tamper with view_id to simulate mismatched / foreign memory view
    foreign_view = dataclasses.replace(view_1, view_id="memview-foreign-999")
    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )
    res = orchestrator.execute_slot(session=session, slot=slot, memory_view=foreign_view)
    assert res.engineering_status == SlotEngineeringStatus.ADMISSION_FAILED.value
    assert res.error_code in ("VIEW_MISMATCH", "SESSION_VIEW_MISMATCH")


def test_prepare_execution_crash_isolated_in_batch(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Crash inside prepare_execution does not abort batch and records failed slot."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Crash isolation test",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=2,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )

    with mock.patch(
        "research_lab.agent_control.batch_discovery.prepare_execution",
        side_effect=RuntimeError("Preparation pipeline crashed!"),
    ):
        batch_res = orchestrator.execute_session(session=session, memory_view=view)

    assert batch_res.total_slots_planned == 2
    assert len(batch_res.failed_slots) == 2
    assert len(batch_res.successful_slots) == 0
    assert batch_res.failed_slots[0].engineering_status == SlotEngineeringStatus.AGENT_EXECUTION_FAILED.value
    assert batch_res.failed_slots[0].error_code == "PREPARATION_FAILED"


def test_unqueried_history_marked_not_checked_not_novel(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B dedupe: When historical memory was not queried, slot cannot be marked NOVEL."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Unqueried history test",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    envelope = _build_candidate_envelope(title="Candidate unqueried", universe="RB2405")
    configure_provider_output(test_provider, json.dumps(envelope))

    # orchestrator WITHOUT memory_store and WITHOUT duplicate_view_lookup
    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=None,
    )
    batch_res = orchestrator.execute_session(
        session=session,
        memory_view=view,
        duplicate_view_lookup=None,
    )

    assert len(batch_res.successful_slots) == 1
    slot_res = batch_res.successful_slots[0]
    # Invariant: Duplicate status MUST be NOT_CHECKED, NOT NOVEL_WITHIN_VIEW
    assert slot_res.duplicate_status == "NOT_CHECKED"
    assert batch_res.funnel.novel_count == 0
    assert batch_res.funnel.unverified_count == 1
    assert batch_res.funnel.novel_rate == 0.0
    assert batch_res.funnel.unverified_rate == 1.0


def test_universe_scope_strict_rejections() -> None:
    """Milestone B scope: Reject uncontrolled aliases and unknown / out-of-scope contracts fail-closed."""
    # 1. Reject uncontrolled aliases
    for alias in ("all_futures", "commodity_active", "active_commodities", "equities", "crypto"):
        with pytest.raises(AlphaGenerationError, match="has no controlled expansion"):
            _validate_universe_scope("RB2405", allowed_universe=alias)
        with pytest.raises(AlphaGenerationError, match="has no controlled expansion"):
            _validate_universe_scope("RB2405", allowed_universe=(alias,))

    # 2. Reject out-of-scope symbol against explicit authorized scope
    with pytest.raises(AlphaGenerationError, match="is not in allowed_universe"):
        _validate_universe_scope("ZZZ9999", allowed_universe=("RB", "HC"))
    with pytest.raises(AlphaGenerationError, match="is not in allowed_universe"):
        _validate_universe_scope("AAPL2405", allowed_universe=("RB", "HC"))
    with pytest.raises(AlphaGenerationError, match="is not in allowed_universe"):
        _validate_universe_scope("AAPL", allowed_universe=("RB", "HC"))

    # 3. Explicit authorized scopes succeed
    _validate_universe_scope("RB2405", allowed_universe=("RB", "HC"))
    _validate_universe_scope("HC2410", allowed_universe=("RB", "HC"))
    _validate_universe_scope("RB", allowed_universe=("RB",))
    _validate_universe_scope("RB2405", allowed_universe="RB")


def test_execute_memory_feedback_loop_direct_call(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone C: Direct call to execute_memory_feedback_loop produces verifiable attributions."""
    engine: AlphaDiscoveryEngine = discovery_context["engine"]
    memory: ResearchMemory = discovery_context["memory"]
    clean_csv: Path = discovery_context["clean_csv"]
    clean_binding: dict[str, Any] = discovery_context["clean_binding"]

    call_state = {"count": 0}

    def _loop_provider(payload: dict[str, Any]) -> str:
        call_state["count"] += 1
        c = call_state["count"]
        # Slots 1 and 2 are Round 1; Slots 3 and 4 are Round 2
        if c <= 2:
            return json.dumps(
                _build_candidate_envelope(
                    title=f"Round 1 Momentum Baseline #{c}",
                    signal_family="momentum",
                    universe="RB2405",
                    frequency="1d",
                    holding_horizon="3d",
                )
            )
        # Round 2: Extract genuine bound entry_id presented to agent in prompt context
        raw_payload = json.dumps(payload)
        m = re.findall(r"rmentry-[a-f0-9]+", raw_payload)
        cited_id = m[0] if m else "rmentry-none"
        return json.dumps(
            _build_candidate_envelope(
                title=f"Round 2 Refined Adaptation #{c}",
                signal_family="momentum",
                universe="RB2405",
                frequency="1d",
                holding_horizon="5d",
                source_context_refs=[cited_id] if m else [],
            )
        )

    configure_provider_output(test_provider, _loop_provider)

    initial_view = _build_test_memory_view(memory, authorized_scope)
    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )

    loop_result = execute_memory_feedback_loop(
        engine=engine,
        orchestrator=orchestrator,
        initial_memory_view=initial_view,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        objective="Run 2-round memory loop with direct API",
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        candidate_budget=2,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        created_at="2026-01-01T00:00:00.000000Z",
        round_2_created_at="2026-01-02T00:00:00.000000Z",
    )

    assert isinstance(loop_result, MemoryFeedbackLoopResult)
    assert loop_result.round_1_session.candidate_budget == 2
    assert loop_result.round_2_session.candidate_budget == 2
    assert len(loop_result.round_1_batch.admitted_candidates) == 2
    assert len(loop_result.round_2_batch.admitted_candidates) == 2
    assert len(loop_result.attribution_records) > 0
    assert loop_result.comparative_summary["attribution"]["total_attributions"] > 0
    first_attr = loop_result.attribution_records[0]
    assert first_attr.is_conclusive is False
    assert len(first_attr.scientific_diffs) > 0
    assert loop_result.comparative_summary["attribution"]["conclusive_attributions"] == 0


def test_uncertain_status_no_blind_retry_and_preserves_slot_result(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: UNCERTAIN/UNKNOWN status isolates failure, prevents blind retry, and enforces idempotency."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Test UNCERTAIN handling without blind retry",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slot = plan_candidate_slots(session, view)[0]

    # Intercept submit to set job status to UNKNOWN
    orig_submit = test_provider.submit

    def _uncertain_submit(task, route, prep, request_id=None):
        handle = orig_submit(task, route, prep, request_id=request_id)
        test_provider.set_job_status(handle.provider_job_ref, TerminalStatus.UNCERTAIN.value)
        return handle

    with mock.patch.object(test_provider, "submit", side_effect=_uncertain_submit):
        orchestrator = DiscoveryBatchOrchestrator(
            registry=provider_registry,
            routing_policy=routing_policy,
        )

        # 1. Execute slot with UNKNOWN status
        res1 = orchestrator.execute_slot(session=session, slot=slot, memory_view=view)
        assert res1.engineering_status == SlotEngineeringStatus.PROVIDER_UNCERTAIN.value
        assert res1.error_code == "PROVIDER_UNCERTAIN"
        assert res1.is_replayed is False

        # 2. Re-executing same slot attempt hits cache without blind resubmission
        with mock.patch.object(test_provider, "submit") as mock_sub:
            res2 = orchestrator.execute_slot(session=session, slot=slot, memory_view=view)
            mock_sub.assert_not_called()
            assert res2.is_replayed is True
            assert res2.engineering_status == SlotEngineeringStatus.PROVIDER_UNCERTAIN.value

        # 3. Full session execution records provider_failed, no blind retry, invariants hold
        batch_result = orchestrator.execute_session(session=session, memory_view=view)
        assert batch_result.funnel.requested == 1
        assert batch_result.funnel.attempted == 1
        assert batch_result.funnel.admitted == 0
        assert batch_result.funnel.provider_failed == 1
        assert batch_result.funnel.invalid == 0
        assert batch_result.funnel.not_attempted == 0


def test_bad_result_digest_tamper_detection_isolated_per_slot(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: TamperDetectionError on bad result digest is isolated per slot; remaining slots proceed."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Test bad result digest isolation",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=2,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    planned_slots = plan_candidate_slots(session, view)

    # Configure slot 0 with valid payload
    output_map = {
        planned_slots[0].task.task_id: json.dumps(_build_candidate_envelope(title="Slot 0", universe="RB2405")),
        planned_slots[1].task.task_id: json.dumps(_build_candidate_envelope(title="Slot 1", universe="RB2405")),
    }
    configure_provider_output(test_provider, output_map)

    # Tamper slot 0 result content hash
    orig_result = test_provider.result
    call_count = {"n": 0}

    def _tampered_result(handle, prep=None):
        res = orig_result(handle, prep)
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Corrupt the result content hash
            object.__setattr__(res, "result_content_hash", "0" * 64)
        return res

    with mock.patch.object(test_provider, "result", side_effect=_tampered_result):
        orchestrator = DiscoveryBatchOrchestrator(
            registry=provider_registry,
            routing_policy=routing_policy,
        )
        batch_result = orchestrator.execute_session(session=session, memory_view=view)

        # Slot 0 failed due to tamper detection, but slot 1 succeeded!
        assert batch_result.funnel.requested == 2
        assert batch_result.funnel.attempted == 2
        assert batch_result.funnel.admitted == 1
        assert batch_result.funnel.provider_failed == 1
        assert batch_result.funnel.invalid == 0
        assert batch_result.funnel.not_attempted == 0
        assert len(batch_result.admitted_candidates) == 1
        assert batch_result.slots[0].engineering_status == SlotEngineeringStatus.RESULT_NOT_ACCEPTED.value


def test_mismatching_provider_job_ref_rejected_and_isolated(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: AgentResult with mismatching provider_job_ref is rejected via RESULT_NOT_ACCEPTED."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Test wrong provider job ref rejection",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    envelope = _build_candidate_envelope(title="Slot with wrong job ref", universe="RB2405")
    configure_provider_output(test_provider, json.dumps(envelope))

    orig_result = test_provider.result

    def _resealed_wrong_job_result(handle, prep=None):
        res = orig_result(handle, prep)
        # Create a validly sealed result but with a different provider_job_ref
        wrong_res = AgentResult.create(
            task_ref=res.task_ref,
            route_ref=res.route_ref,
            provider_job_ref="another-provider-job-ref-999",
            terminal_status=res.terminal_status,
            structured_output=res.structured_output,
            acceptance_status=res.acceptance_status,
        )
        return wrong_res

    with mock.patch.object(test_provider, "result", side_effect=_resealed_wrong_job_result):
        orchestrator = DiscoveryBatchOrchestrator(
            registry=provider_registry,
            routing_policy=routing_policy,
        )
        batch_result = orchestrator.execute_session(session=session, memory_view=view)

        assert batch_result.funnel.requested == 1
        assert batch_result.funnel.attempted == 1
        assert batch_result.funnel.admitted == 0
        assert batch_result.funnel.provider_failed == 1
        assert batch_result.slots[0].engineering_status == SlotEngineeringStatus.RESULT_NOT_ACCEPTED.value


def test_context_view_cannot_masquerade_as_duplicate_lookup_view(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Returning initial context view as duplicate lookup is rejected; results in NOT_CHECKED and unverified."""
    memory: ResearchMemory = discovery_context["memory"]
    context_view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Test sham duplicate view rejection",
        memory_view=context_view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    envelope = _build_candidate_envelope(title="Candidate with sham view", universe="RB2405")
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )

    # Pass the initial context view as duplicate lookup views (sham)
    batch_result = orchestrator.execute_session(
        session=session,
        memory_view=context_view,
        duplicate_view_lookup=lambda c: (context_view, context_view),
    )

    assert batch_result.funnel.requested == 1
    assert batch_result.funnel.admitted == 1
    assert batch_result.funnel.novel_count == 0
    assert batch_result.funnel.unverified_count == 1
    assert batch_result.slots[0].duplicate_status == "NOT_CHECKED"
    assert batch_result.admitted_candidates[0].duplicate_status == "NOT_CHECKED"


def test_empty_duplicate_views_for_other_candidate_rejected_fail_closed(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: External duplicate callback (even with attempted fake receipt) cannot prove novelty; must be NOT_CHECKED."""
    memory: ResearchMemory = discovery_context["memory"]
    context_view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Test unverified empty views rejection",
        memory_view=context_view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    envelope = _build_candidate_envelope(title="Candidate for empty check", universe="RB2405")
    configure_provider_output(test_provider, json.dumps(envelope))

    # Build valid exact view for 'a'*64 and related view for 'b'*64 on empty memory
    exact_other = build_research_memory_view(
        ResearchMemoryQuery(
            role="alpha_generator",
            project_binding=session.project_binding,
            categories=(ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,),
            hypothesis_content_hash="a" * 64,
        ),
        authorized_scope,
        session.project_binding,
        memory,
    )
    related_other = build_research_memory_view(
        ResearchMemoryQuery(
            role="alpha_generator",
            project_binding=session.project_binding,
            categories=(ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,),
            scientific_identity_hash="b" * 64,
        ),
        authorized_scope,
        session.project_binding,
        memory,
    )
    assert exact_other.view_id != related_other.view_id
    assert exact_other.total_entries == 0
    assert related_other.total_entries == 0

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
    )

    # 1. External callback returning empty views without receipt
    batch_result = orchestrator.execute_session(
        session=session,
        memory_view=context_view,
        duplicate_view_lookup=lambda c: (exact_other, related_other),
    )
    assert batch_result.funnel.requested == 1
    assert batch_result.funnel.admitted == 1
    assert batch_result.funnel.novel_count == 0
    assert batch_result.funnel.unverified_count == 1
    assert batch_result.slots[0].duplicate_status == "NOT_CHECKED"
    assert batch_result.slots[0].duplicate_status_reason is not None
    assert "external duplicate lookup cannot prove novelty" in batch_result.slots[0].duplicate_status_reason.lower()

    # 2. External callback returning empty views with attempted caller fake receipt
    fake_receipt = {
        "hypothesis_content_hash": "dummy_content_hash",
        "scientific_identity_hash": "dummy_sci_hash",
    }
    batch_result2 = orchestrator.execute_session(
        session=session,
        memory_view=context_view,
        duplicate_view_lookup=lambda c: (exact_other, related_other, fake_receipt),
    )
    assert batch_result2.funnel.novel_count == 0
    assert batch_result2.funnel.unverified_count == 1
    assert batch_result2.slots[0].duplicate_status == "NOT_CHECKED"
    assert batch_result2.slots[0].duplicate_status_reason is not None
    assert "external duplicate lookup cannot prove novelty" in batch_result2.slots[0].duplicate_status_reason.lower()


def test_trusted_internal_memory_store_lookup_yields_novel(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Orchestrator with memory_store executes trusted duplicate query, proving NOVEL_WITHIN_VIEW."""
    memory: ResearchMemory = discovery_context["memory"]
    context_view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Test trusted internal memory store lookup",
        memory_view=context_view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    envelope = _build_candidate_envelope(title="Candidate for novel check", universe="RB2405")
    configure_provider_output(test_provider, json.dumps(envelope))

    # Orchestrator with trusted memory_store and NO external callback
    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    batch_result = orchestrator.execute_session(
        session=session,
        memory_view=context_view,
        duplicate_view_lookup=None,
    )

    assert batch_result.funnel.requested == 1
    assert batch_result.funnel.admitted == 1
    assert batch_result.funnel.novel_count == 1
    assert batch_result.funnel.unverified_count == 0
    assert batch_result.slots[0].duplicate_status == "NOVEL_WITHIN_VIEW"
    assert batch_result.admitted_candidates[0].duplicate_status == "NOVEL_WITHIN_VIEW"


def test_truncated_duplicate_views_cannot_prove_novelty(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone B: Truncated duplicate lookup views fail closed; cannot prove novelty."""
    memory: ResearchMemory = discovery_context["memory"]
    context_view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Test truncated duplicate view rejection",
        memory_view=context_view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    envelope = _build_candidate_envelope(title="Candidate with truncated lookup", universe="RB2405")
    configure_provider_output(test_provider, json.dumps(envelope))

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )

    from research_lab.agent_control import batch_discovery as bd_mod
    orig_build = bd_mod.build_duplicate_lookup_views

    def _truncated_build(cand, **kwargs):
        ex, rel = orig_build(cand, **kwargs)
        object.__setattr__(ex, "is_truncated", True)
        return ex, rel

    with mock.patch.object(bd_mod, "build_duplicate_lookup_views", side_effect=_truncated_build):
        batch_result = orchestrator.execute_session(
            session=session,
            memory_view=context_view,
            duplicate_view_lookup=None,
        )

    assert batch_result.funnel.requested == 1
    assert batch_result.funnel.admitted == 1
    assert batch_result.funnel.novel_count == 0
    assert batch_result.funnel.unverified_count == 1
    assert batch_result.slots[0].duplicate_status == "NOT_CHECKED"
    assert batch_result.slots[0].duplicate_status_reason is not None
    assert "truncated" in batch_result.slots[0].duplicate_status_reason.lower()


def test_two_rounds_engine_memory_internal_deduplication(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """Milestone C: Two rounds with internal engine.memory correctly identify duplicates in Round 2."""
    memory: ResearchMemory = discovery_context["memory"]
    engine: AlphaDiscoveryEngine = discovery_context["engine"]
    clean_csv: Path = discovery_context["clean_csv"]
    clean_binding: dict[str, Any] = discovery_context["clean_binding"]

    call_state = {"count": 0}

    def _loop_provider(payload: dict[str, Any]) -> str:
        call_state["count"] += 1
        c = call_state["count"]
        # Round 1 (slots 1,2): Momentum baselines
        # Round 2 (slots 3,4): slot 3 repeats slot 1 (exact duplicate), slot 4 is new
        raw_payload = json.dumps(payload)
        m = re.findall(r"rmentry-[a-f0-9]+", raw_payload)
        cited_id = m[0] if m else "rmentry-none"
        if c == 3:
            return json.dumps(
                _build_candidate_envelope(
                    title="Round 1 Momentum Baseline #1",
                    signal_family="momentum",
                    universe="RB2405",
                    frequency="1d",
                    holding_horizon="3d",
                    source_context_refs=[cited_id] if m else [],
                )
            )
        return json.dumps(
            _build_candidate_envelope(
                title=f"Candidate #{c}",
                signal_family="momentum",
                universe="RB2405",
                frequency="1d",
                holding_horizon=f"{c+2}d",
                source_context_refs=[cited_id] if m else [],
            )
        )

    configure_provider_output(test_provider, _loop_provider)

    initial_view = build_research_memory_view(
        query=ResearchMemoryQuery(
            role="alpha_generator",
            project_binding=STANDARD_PROJECT_BINDING,
            categories=(ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,),
            limit_per_category=10,
        ),
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        memory_store=memory,
    )

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )

    loop_res = execute_memory_feedback_loop(
        engine=engine,
        orchestrator=orchestrator,
        initial_memory_view=initial_view,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        objective="Two round deduplication test",
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        candidate_budget=2,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        created_at="2026-01-01T00:00:00.000000Z",
        round_2_created_at="2026-01-02T00:00:00.000000Z",
    )

    # In Round 1, on clean memory, internal lookup confirms NOVEL_WITHIN_VIEW
    assert loop_res.round_1_batch.funnel.admitted == 2
    assert loop_res.round_1_batch.funnel.novel_count == 2
    assert loop_res.round_1_batch.funnel.unverified_count == 0

    # In Round 2, memory_store contains Round 1 entries; candidates are evaluated through internal path
    assert loop_res.round_2_batch.funnel.admitted == 2
    assert loop_res.round_2_batch.funnel.unverified_count == 0


# =====================================================================
# PR #589 Review Fixes: 4 P1 + 1 P2 Regressions
# =====================================================================

def test_pr589_p1_candidate_and_batch_serialization_to_dict(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """PR #589 P1 (4068923944): slot.to_dict() and batch.to_dict() JSON-serializable when candidate exists."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Serialization test with admitted candidate",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    envelope = _build_candidate_envelope(
        title="Valid Candidate for Serialization",
        signal_family="momentum",
        universe="RB2405",
        frequency="1d",
    )
    configure_provider_output(test_provider, json.dumps(envelope))
    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    batch = orchestrator.execute_session(session=session, memory_view=view)
    assert batch.funnel.admitted == 1
    slot = batch.slots[0]
    assert slot.candidate is not None

    # 1. slot.to_dict()
    slot_dict = slot.to_dict()
    assert isinstance(slot_dict, dict)
    assert slot_dict["candidate"] is not None
    cand_dict = slot_dict["candidate"]
    assert "hypothesis" in cand_dict
    assert "scientific_identity_hash" in cand_dict
    assert "duplicate_status" in cand_dict
    assert "duplicate_refs" in cand_dict
    assert "rationale" in cand_dict
    assert "novelty_statement" in cand_dict
    assert "duplicate_awareness" in cand_dict
    assert "uncertainty" in cand_dict
    assert "source_context_refs" in cand_dict

    # 2. batch.to_dict()
    batch_dict = batch.to_dict()
    assert isinstance(batch_dict, dict)
    assert len(batch_dict["admitted_candidates"]) == 1
    assert len(batch_dict["slots"]) == 1

    # 3. JSON serialization roundtrip
    slot_json = json.dumps(slot_dict)
    assert isinstance(slot_json, str)
    batch_json = json.dumps(batch_dict)
    assert isinstance(batch_json, str)


def test_pr589_p1_execute_memory_feedback_loop_with_m3_quota_snapshots(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    discovery_context: dict[str, Any],
) -> None:
    """PR #589 P1 (4068923949): Per-slot getter, execution clock, TTL expiry, and error isolation under M3."""
    engine: AlphaDiscoveryEngine = discovery_context["engine"]
    memory: ResearchMemory = discovery_context["memory"]
    clean_csv: Path = discovery_context["clean_csv"]
    clean_binding: dict[str, Any] = discovery_context["clean_binding"]

    m3_policy = RoutingPolicy(
        role="alpha_generator",
        policy_version="2026-09-m3",
        provider_priority=(CONTRACT_TEST_PROVIDER_NAME,),
        model_quota_bindings={CONTRACT_TEST_PROVIDER_NAME: {CONTRACT_TEST_DEFAULT_MODEL: "default"}},
    )
    call_state = {"count": 0}

    def _loop_provider(payload: dict[str, Any]) -> str:
        call_state["count"] += 1
        c = call_state["count"]
        return json.dumps(
            _build_candidate_envelope(
                title=f"M3 Quota Signal #{c}",
                signal_family="momentum",
                universe="RB2405",
                frequency="1d",
            )
        )

    configure_provider_output(test_provider, _loop_provider)
    initial_view = _build_test_memory_view(memory, authorized_scope)
    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=m3_policy,
        memory_store=memory,
    )

    # A. Without usage_snapshots or getter, under M3 policy, fail-closed with QUOTA_EXHAUSTED (candidate_budget >= 2)
    res_no_snap = execute_memory_feedback_loop(
        engine=engine,
        orchestrator=orchestrator,
        initial_memory_view=initial_view,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        objective="M3 Quota without snapshot",
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        candidate_budget=2,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        created_at="2026-01-01T00:00:00.000000Z",
        round_2_created_at="2026-01-02T00:00:00.000000Z",
    )
    assert res_no_snap.round_1_batch.funnel.requested == 2
    assert res_no_snap.round_1_batch.funnel.admitted == 0
    assert res_no_snap.round_1_batch.funnel.provider_failed == 2
    assert res_no_snap.round_1_batch.slots[0].engineering_status == SlotEngineeringStatus.QUOTA_EXHAUSTED.value
    assert res_no_snap.round_1_batch.slots[1].engineering_status == SlotEngineeringStatus.QUOTA_EXHAUSTED.value

    # B. Getter error isolation: getter fails for slot 1, but succeeds for slot 2; batch does not halt
    getter_call_count = {"n": 0}

    def _faulty_getter(timestamp: str) -> Mapping[str, AgentUsageSnapshot]:
        getter_call_count["n"] += 1
        if getter_call_count["n"] == 1:
            raise RuntimeError("Temporary upstream quota service outage")
        return {
            CONTRACT_TEST_PROVIDER_NAME: AgentUsageSnapshot.create(
                provider=CONTRACT_TEST_PROVIDER_NAME,
                model_group="default",
                quota_windows=[{"window": "5h", "remaining_fraction": 1.0}],
                captured_at=timestamp,
            )
        }

    orchestrator_faulty = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=m3_policy,
        memory_store=memory,
    )
    session_b = DiscoverySession.create(
        objective="Faulty getter session",
        memory_view=initial_view,
        authorized_scope=authorized_scope,
        candidate_budget=2,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at="2026-09-22T08:00:00.000000Z",
    )
    batch_b = orchestrator_faulty.execute_session(
        session_b,
        initial_view,
        usage_snapshot_provider=_faulty_getter,
        clock="2026-09-22T08:00:00.000000Z",
    )
    assert batch_b.funnel.requested == 2
    assert batch_b.funnel.admitted == 1
    assert batch_b.funnel.provider_failed == 1
    assert batch_b.slots[0].engineering_status == SlotEngineeringStatus.QUOTA_EXHAUSTED.value
    assert batch_b.slots[0].error_code == "SNAPSHOT_GETTER_FAILED"
    assert batch_b.slots[1].engineering_status == SlotEngineeringStatus.COMPLETED.value

    # C. Clock advancing past TTL (300s): Stale snapshot rejected failclosed
    def stale_getter(_t: str) -> Mapping[str, AgentUsageSnapshot]:
        return {
            CONTRACT_TEST_PROVIDER_NAME: AgentUsageSnapshot.create(
                provider=CONTRACT_TEST_PROVIDER_NAME,
                model_group="default",
                quota_windows=[{"window": "5h", "remaining_fraction": 1.0}],
                captured_at="2026-09-22T09:00:00.000000Z",  # 600s older than clock
            )
        }
    session_c = DiscoverySession.create(
        objective="Stale TTL session",
        memory_view=initial_view,
        authorized_scope=authorized_scope,
        candidate_budget=2,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at="2026-09-22T09:10:00.000000Z",
    )
    batch_c = orchestrator_faulty.execute_session(
        session_c,
        initial_view,
        usage_snapshot_provider=stale_getter,
        clock="2026-09-22T09:10:00.000000Z",
    )
    assert batch_c.funnel.requested == 2
    assert batch_c.funnel.admitted == 0
    assert batch_c.funnel.provider_failed == 2
    assert "stale" in str(batch_c.slots[0].error_message).lower()

    # D. Stepping execution clock with fresh per-slot getter: 2 rounds, budget >= 2
    clock_ticks = [
        "2026-09-22T10:00:00.000000Z",
        "2026-09-22T10:01:00.000000Z",
        "2026-09-23T10:00:00.000000Z",
        "2026-09-23T10:01:00.000000Z",
        "2026-09-23T10:02:00.000000Z",
    ]
    tick_index = {"i": 0}

    def _stepping_clock() -> str:
        idx = tick_index["i"]
        tick_index["i"] += 1
        return clock_ticks[min(idx, len(clock_ticks) - 1)]

    recorded_getter_times: list[str] = []

    def _dynamic_snapshot_provider(timestamp: str) -> Mapping[str, AgentUsageSnapshot]:
        recorded_getter_times.append(timestamp)
        return {
            CONTRACT_TEST_PROVIDER_NAME: AgentUsageSnapshot.create(
                provider=CONTRACT_TEST_PROVIDER_NAME,
                model_group="default",
                quota_windows=[{"window": "5h", "remaining_fraction": 1.0}],
                captured_at=timestamp,
            )
        }

    orchestrator_fresh = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=m3_policy,
        memory_store=memory,
    )
    res_with_snap = execute_memory_feedback_loop(
        engine=engine,
        orchestrator=orchestrator_fresh,
        initial_memory_view=initial_view,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        objective="M3 Quota with fresh snapshot",
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        candidate_budget=2,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        usage_snapshot_provider=_dynamic_snapshot_provider,
        clock=_stepping_clock,
        created_at="2026-09-22T10:00:00.000000Z",
        round_2_created_at="2026-09-23T10:00:00.000000Z",
    )
    assert res_with_snap.round_1_batch.funnel.admitted == 2
    assert res_with_snap.round_2_batch.funnel.admitted == 2
    # Per-slot getter called for every newly executed slot across both rounds
    assert len(recorded_getter_times) >= 4

    # E. Same-attempt cache replay does NOT invoke snapshot getter
    cached_slot = res_with_snap.round_1_session
    planned_slot0 = plan_candidate_slots(cached_slot, initial_view)[0]
    initial_call_count = len(recorded_getter_times)
    replayed_res = orchestrator_fresh.execute_slot(
        session=cached_slot,
        slot=planned_slot0,
        memory_view=initial_view,
        usage_snapshot_provider=_dynamic_snapshot_provider,
        clock=_stepping_clock,
    )
    assert replayed_res.is_replayed is True
    assert len(recorded_getter_times) == initial_call_count


def test_pr589_p1_unresolved_prior_attempt_interlock(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """PR #589 P1 (4068923953): Check unresolved prior attempt before submit; reject before confirmed terminal."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Unresolved prior attempt test",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=1,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slot1 = plan_candidate_slots(session, view)[0]

    envelope = _build_candidate_envelope(
        title="Candidate for Attempt Test",
        signal_family="momentum",
        universe="RB2405",
        frequency="1d",
    )
    configure_provider_output(test_provider, json.dumps(envelope))

    orig_submit = test_provider.submit

    def _uncertain_submit(task, route, prep, request_id=None):
        handle = orig_submit(task, route, prep, request_id=request_id)
        test_provider.set_job_status(handle.provider_job_ref, TerminalStatus.UNCERTAIN.value)
        return handle

    with mock.patch.object(test_provider, "submit", side_effect=_uncertain_submit):
        orchestrator = DiscoveryBatchOrchestrator(
            registry=provider_registry,
            routing_policy=routing_policy,
        )

        # Attempt 1 executes and ends in UNCERTAIN
        res1 = orchestrator.execute_slot(session=session, slot=slot1, memory_view=view)
        assert res1.engineering_status == SlotEngineeringStatus.PROVIDER_UNCERTAIN.value
        assert res1.error_code == "PROVIDER_UNCERTAIN"

    # Replan slot to attempt 2
    slot2 = replan_slot_attempt(slot1, view, attempt=2)

    # 1. Attempt 2 executed while Attempt 1 is still UNCERTAIN -> BLOCKED before submit
    with mock.patch.object(test_provider, "submit") as mock_sub:
        res2_blocked = orchestrator.execute_slot(session=session, slot=slot2, memory_view=view)
        mock_sub.assert_not_called()
        assert res2_blocked.engineering_status == SlotEngineeringStatus.PROVIDER_UNCERTAIN.value
        assert res2_blocked.error_code == "PRIOR_ATTEMPT_UNRESOLVED"

    # 2. Status lookup error caught failclosed without crashing
    orchestrator._execution_cache.pop((session.session_id, slot2.slot_id, 2), None)
    with mock.patch.object(test_provider, "status", side_effect=RuntimeError("SimNow status disconnected")):
        res2_error = orchestrator.execute_slot(session=session, slot=slot2, memory_view=view)
        assert res2_error.engineering_status == SlotEngineeringStatus.PROVIDER_UNCERTAIN.value
        assert res2_error.error_code == "PRIOR_ATTEMPT_UNRESOLVED"
        assert "STATUS_LOOKUP_ERROR" in str(res2_error.error_message)

    # 3. Missing saved handle does not fabricate identity and remains blocked
    orchestrator._execution_cache.pop((session.session_id, slot2.slot_id, 2), None)
    saved_handle = orchestrator._execution_handles.pop((session.session_id, slot1.slot_id, 1), None)
    res2_no_handle = orchestrator.execute_slot(session=session, slot=slot2, memory_view=view)
    assert res2_no_handle.engineering_status == SlotEngineeringStatus.PROVIDER_UNCERTAIN.value
    assert res2_no_handle.error_code == "PRIOR_ATTEMPT_UNRESOLVED"

    # Restore handle and confirm prior job is terminated (e.g. CANCELLED)
    if saved_handle:
        orchestrator._execution_handles[(session.session_id, slot1.slot_id, 1)] = saved_handle
    test_provider.set_job_status(res1.provider_job_ref, "CANCELLED")

    # 4. Attempt 2 executed after confirmation -> ALLOWED to submit and succeeds
    orchestrator._execution_cache.pop((session.session_id, slot2.slot_id, 2), None)
    res2_allowed = orchestrator.execute_slot(session=session, slot=slot2, memory_view=view)
    assert res2_allowed.engineering_status == SlotEngineeringStatus.COMPLETED.value
    assert res2_allowed.attempt == 2
    assert res2_allowed.candidate is not None


def test_pr589_p1_conservative_memory_attribution_punctuation_inconclusive(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """PR #589 P1 (4068923957): Punctuation and cosmetic edits in signal_definition remain inconclusive."""
    engine: AlphaDiscoveryEngine = discovery_context["engine"]
    memory: ResearchMemory = discovery_context["memory"]
    clean_csv: Path = discovery_context["clean_csv"]
    clean_binding: dict[str, Any] = discovery_context["clean_binding"]

    call_state = {"count": 0}

    def _loop_provider(payload: dict[str, Any]) -> str:
        call_state["count"] += 1
        c = call_state["count"]
        # Round 1: Slot 1
        if c == 1:
            return json.dumps(
                _build_candidate_envelope(
                    title="Round 1 Momentum Baseline",
                    signal_family="momentum",
                    universe="RB2405",
                    frequency="1d",
                    holding_horizon="3d",
                )
            )
        # Round 2: Citations
        raw_payload = json.dumps(payload)
        m = re.findall(r"rmentry-[a-f0-9]+", raw_payload)
        cited_id = m[0] if m else "rmentry-none"

        # Trailing period edit only
        base_env = _build_candidate_envelope(
            title="Round 2 Punctuation Edit Only",
            signal_family="momentum",
            universe="RB2405",
            frequency="1d",
            holding_horizon="3d",
            source_context_refs=[cited_id] if m else [],
        )
        base_env["hypothesis"]["signal_definition"] += "."
        return json.dumps(base_env)

    configure_provider_output(test_provider, _loop_provider)
    initial_view = _build_test_memory_view(memory, authorized_scope)

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    res = execute_memory_feedback_loop(
        engine=engine,
        orchestrator=orchestrator,
        initial_memory_view=initial_view,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        objective="Attribution punctuation test",
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        candidate_budget=1,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        created_at="2026-01-01T00:00:00.000000Z",
        round_2_created_at="2026-01-02T00:00:00.000000Z",
    )
    assert len(res.attribution_records) == 1
    attr = res.attribution_records[0]
    assert attr.is_conclusive is False
    assert len(attr.scientific_diffs) == 0
    assert len(attr.field_diffs) > 0
    assert res.comparative_summary["attribution"]["conclusive_attributions"] == 0


def test_pr589_p1_conservative_memory_attribution_synonym_rewrite_inconclusive(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """PR #589 P1 (4068923957): Synonym rewrites remain fail-closed inconclusive without verified causal gap proof."""
    engine: AlphaDiscoveryEngine = discovery_context["engine"]
    memory: ResearchMemory = discovery_context["memory"]
    clean_csv: Path = discovery_context["clean_csv"]
    clean_binding: dict[str, Any] = discovery_context["clean_binding"]

    call_state = {"count": 0}

    def _loop_provider(payload: dict[str, Any]) -> str:
        call_state["count"] += 1
        c = call_state["count"]
        if c == 1:
            return json.dumps(
                _build_candidate_envelope(
                    title="Round 1 Momentum Baseline",
                    signal_family="momentum",
                    universe="RB2405",
                    frequency="1d",
                    holding_horizon="3d",
                    signal_definition="positive rolling return over 5 bars on RB2405",
                )
            )
        raw_payload = json.dumps(payload)
        m = re.findall(r"rmentry-[a-f0-9]+", raw_payload)
        cited_id = m[0] if m else "rmentry-none"
        return json.dumps(
            _build_candidate_envelope(
                title="Round 2 Synonym Rewrite",
                signal_family="momentum",
                universe="RB2405",
                frequency="1d",
                holding_horizon="3d",
                signal_definition="rolling return over 5 bars on RB2405 is positive",
                source_context_refs=[cited_id] if m else [],
            )
        )

    configure_provider_output(test_provider, _loop_provider)
    initial_view = _build_test_memory_view(memory, authorized_scope)

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    res = execute_memory_feedback_loop(
        engine=engine,
        orchestrator=orchestrator,
        initial_memory_view=initial_view,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        objective="Attribution synonym test",
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        candidate_budget=1,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        created_at="2026-01-01T00:00:00.000000Z",
        round_2_created_at="2026-01-02T00:00:00.000000Z",
    )
    assert len(res.attribution_records) == 1
    attr = res.attribution_records[0]
    assert attr.is_conclusive is False
    assert len(attr.field_diffs) > 0
    assert res.comparative_summary["attribution"]["conclusive_attributions"] == 0


def test_pr589_p1_conservative_memory_attribution_irrelevant_horizon_target_inconclusive(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """PR #589 P1 (4068923957): Irrelevant horizon and target changes remain inconclusive without causal evidence."""
    engine: AlphaDiscoveryEngine = discovery_context["engine"]
    memory: ResearchMemory = discovery_context["memory"]
    clean_csv: Path = discovery_context["clean_csv"]
    clean_binding: dict[str, Any] = discovery_context["clean_binding"]

    call_state = {"count": 0}

    def _loop_provider(payload: dict[str, Any]) -> str:
        call_state["count"] += 1
        c = call_state["count"]
        if c == 1:
            return json.dumps(
                _build_candidate_envelope(
                    title="Round 1 Momentum Baseline",
                    signal_family="momentum",
                    universe="RB2405",
                    frequency="1d",
                    holding_horizon="3d",
                    target="next_day_close",
                )
            )
        raw_payload = json.dumps(payload)
        m = re.findall(r"rmentry-[a-f0-9]+", raw_payload)
        cited_id = m[0] if m else "rmentry-none"
        return json.dumps(
            _build_candidate_envelope(
                title="Round 2 Horizon Target Variance",
                signal_family="momentum",
                universe="RB2405",
                frequency="1d",
                holding_horizon="5d",
                target="next_day_vwap",
                source_context_refs=[cited_id] if m else [],
            )
        )

    configure_provider_output(test_provider, _loop_provider)
    initial_view = _build_test_memory_view(memory, authorized_scope)

    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )
    res = execute_memory_feedback_loop(
        engine=engine,
        orchestrator=orchestrator,
        initial_memory_view=initial_view,
        authorized_scope=authorized_scope,
        project_binding=STANDARD_PROJECT_BINDING,
        objective="Attribution horizon target test",
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        candidate_budget=1,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        created_at="2026-01-01T00:00:00.000000Z",
        round_2_created_at="2026-01-02T00:00:00.000000Z",
    )
    assert len(res.attribution_records) == 1
    attr = res.attribution_records[0]
    assert attr.is_conclusive is False
    assert len(attr.scientific_diffs) > 0
    assert len(attr.field_diffs) > 0
    assert res.comparative_summary["attribution"]["conclusive_attributions"] == 0


def test_pr589_p2_cache_replay_dynamic_duplicate_reevaluation(
    test_provider: ContractTestProvider,
    provider_registry: ProviderRegistry,
    authorized_scope: AgentPermissionScope,
    routing_policy: RoutingPolicy,
    discovery_context: dict[str, Any],
) -> None:
    """PR #589 P2 (4068923968): Cache replay re-evaluates duplicate status against active prior_admitted."""
    memory: ResearchMemory = discovery_context["memory"]
    view = _build_test_memory_view(memory, authorized_scope)
    session = DiscoverySession.create(
        objective="Cache replay duplicate test",
        memory_view=view,
        authorized_scope=authorized_scope,
        candidate_budget=2,
        allowed_universe=("RB",),
        allowed_frequency="1d",
        allowed_signal_families=("momentum",),
        project_binding=STANDARD_PROJECT_BINDING,
        created_at=CANONICAL_SESSION_TIMESTAMP,
    )
    slots = plan_candidate_slots(session, view)
    assert len(slots) == 2

    # Both slots produce identical candidate
    envelope = _build_candidate_envelope(
        title="Identical Candidate for Deduplication Test",
        signal_family="momentum",
        universe="RB2405",
        frequency="1d",
    )
    configure_provider_output(test_provider, json.dumps(envelope))
    orchestrator = DiscoveryBatchOrchestrator(
        registry=provider_registry,
        routing_policy=routing_policy,
        memory_store=memory,
    )

    # 1. Execute slot 1 in isolation first (prior_admitted=())
    res_slot1_isolated = orchestrator.execute_slot(
        session=session, slot=slots[1], memory_view=view, prior_admitted=()
    )
    assert res_slot1_isolated.engineering_status == SlotEngineeringStatus.COMPLETED.value
    assert res_slot1_isolated.duplicate_status == "NOVEL_WITHIN_VIEW"
    assert res_slot1_isolated.is_replayed is False

    # 2. Now execute full session sequentially (slots[0], then slots[1])
    batch_res = orchestrator.execute_session(session=session, memory_view=view)
    assert batch_res.funnel.requested == 2
    assert batch_res.funnel.admitted == 2

    # Slot 0 was executed fresh and admitted as novel
    assert batch_res.slots[0].duplicate_status == "NOVEL_WITHIN_VIEW"
    # Slot 1 hit cache replay and dynamically re-evaluated against slot 0 as exact duplicate!
    assert batch_res.slots[1].is_replayed is True
    assert batch_res.slots[1].duplicate_status == "EXACT_DUPLICATE"

    # Funnel metrics strictly reflect novel=1, exact=1
    assert batch_res.funnel.novel_count == 1
    assert batch_res.funnel.exact_duplicate_count == 1
    assert batch_res.funnel.related_count == 0
    assert batch_res.funnel.unverified_count == 0
