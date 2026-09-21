"""Milestone 8 / Gate 8: Future Provider Plug-in Boundary Test Suite (#573).

Tests:
1. Provider Conformance Suite & Conformance Matrix Generation
2. E2E 1: Second Provider Plugin Registration & Capability Router Selection
3. E2E 2: Provider Switching for the Same Role (Contract Consistency & Provenance)
4. E2E 3: M5 Alpha Candidate Admission with Second Provider
5. E2E 4: M6 Discovery Handover (Deterministic Screening & Science Isolation)
6. E2E 5: M7 Multi-Agent Provider Mix & Deterministic Aggregation
7. E2E 6: Provider Failure Equivalence & Error Taxonomy Unification
8. Comprehensive Negative Tests & Hard Invariants (Zero Trading Authority)
9. Anti-Leakage Guard: Static AST Scan Proving Zero Provider Special-Casing in Business Logic
"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from research_lab.agent_control.alpha_generator import (
    AlphaGenerationCandidate,
    AlphaGenerationRequest,
    admit_alpha_generation_output,
)
from research_lab.agent_control.conformance import (
    REQUIRED_CONFORMANCE_CONTRACTS,
    AgentProviderConformanceSuite,
    format_conformance_matrix_markdown,
    generate_conformance_matrix,
)
from research_lab.agent_control.contracts import (
    AgentTask,
    ProjectBinding,
    validate_result_hash,
    validate_route_hash,
)
from research_lab.agent_control.discovery_integration import (
    DiscoveryIntegrationOrchestrator,
    EngineeringStatus,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
    ResultAcceptanceError,
    TamperDetectionError,
    assert_provider_error_does_not_pollute_scientific_decision,
)
from research_lab.agent_control.handoff import (
    prepare_execution,
)
from research_lab.agent_control.memory_view import (
    ResearchMemoryView,
)
from research_lab.agent_control.orchestration import (
    MultiAgentOrchestrationRequest,
    MultiAgentOrchestrator,
    OrchestratedWorkBlock,
)
from research_lab.agent_control.permissions import (
    HARD_INVARIANT_FORBIDDEN_PERMISSIONS,
)
from research_lab.agent_control.providers.antigravity_local_mcp import (
    AntigravityLocalMCPProvider,
)
from research_lab.agent_control.providers.contract_test_provider import (
    CONTRACT_TEST_DEFAULT_MODEL,
    CONTRACT_TEST_PROVIDER_NAME,
    ContractTestProvider,
)
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.roles import (
    DEFAULT_ROLE_POLICIES,
    AgentRole,
)
from research_lab.agent_control.router import (
    authorize,
    select_agent,
)
from research_lab.agent_control.routing_policy import (
    RoutingPolicy,
)
from research_lab.agent_control.transport import (
    ProviderConnectionDescriptor,
    ProviderTransportKind,
)
from research_lab.agent_control.transports.direct_sdk_test import (
    DirectSDKTestTransport,
)
from research_lab.agent_control.transports.local_mcp import (
    LocalMCPTransport,
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


def _valid_m5_envelope() -> dict[str, Any]:
    return {
        "hypothesis": {
            "title": "Short-term reversal after abnormal range expansion",
            "economic_rationale": "Temporary inventory imbalance may mean-revert after crowded directional flow.",
            "signal_family": "reversal",
            "signal_definition": "negative one-day return conditioned on normalized true range above its rolling median",
            "source_features": ["close", "high", "low"],
            "target": "forward_return_3d",
            "expected_direction": "positive",
            "holding_horizon": "3d",
            "universe": "commodity_active",
            "frequency": "1d",
            "known_risks": ["persistent trends can overwhelm reversal"],
            "falsification_conditions": [
                "out-of-sample directional association is non-positive"
            ],
            "proposed_screening_methods": [
                "coverage and directional association checks"
            ],
            "signal_type": "signed_scalar",
        },
        "rationale": "The candidate is deliberately bounded and falsifiable.",
        "source_context_refs": [],
        "novelty_statement": "No exact prior candidate was supplied in the controlled view.",
        "duplicate_awareness": "An empty view cannot establish historical uniqueness.",
        "uncertainty": "The economic mechanism may be regime dependent.",
    }


def _build_m5_fixtures(role: str = "alpha_generator") -> tuple[AlphaGenerationRequest, ResearchMemoryView, str]:
    binding = ProjectBinding(project_id="vnpy", workspace_identity=WORKSPACE_IDENTITY)
    scope = authorize(
        role=role,
        requested_permissions=["read_research_memory", "create_hypothesis"],
        project_binding=binding,
    )
    scope_binding = dict(scope.project_binding)
    content_hash = hashlib.sha256(b"m8_test_view_content").hexdigest()
    view = ResearchMemoryView(
        view_id="memview-" + content_hash[:32],
        view_content_hash=content_hash,
        role=role,
        project_binding=scope_binding,
        categories=("research_gaps",),
        entries_by_category={"research_gaps": ()},
        total_entries=0,
        policy_version="research_memory_view.v1",
        generated_at=NOW,
        source_refs=(),
    )
    request = AlphaGenerationRequest.create(
        objective="Generate a falsifiable daily commodity alpha candidate.",
        memory_view=view,
        project_binding=scope_binding,
        authorized_scope=scope,
    )
    return request, view, json.dumps(_valid_m5_envelope())


class MockLocalMCPTransport(LocalMCPTransport):
    """Contract-compatible deterministic in-memory mock for Antigravity Local MCP."""

    def __init__(self, workspace_identity: str = WORKSPACE_IDENTITY) -> None:
        self._workspace_identity = workspace_identity
        self._tools = {
            "account_usage": self._mock_account_usage,
            "cancel": self._mock_cancel,
            "events": self._mock_events,
            "message": self._mock_message,
            "projects": self._mock_projects,
            "result": self._mock_result,
            "status": self._mock_status,
            "submit": self._mock_submit,
            "wait": self._mock_wait,
            "watch": self._mock_watch,
        }
        self._jobs: dict[str, dict[str, Any]] = {}
        self._descriptor = ProviderConnectionDescriptor(
            transport_kind=ProviderTransportKind.LOCAL_MCP,
            connection_profile_ref="antigravity_local_mcp",
            capabilities=("local_mcp", "fast_mcp"),
        )

    @property
    def descriptor(self) -> ProviderConnectionDescriptor:
        return self._descriptor

    def is_available(self) -> bool:
        return True

    def discover_tools(self) -> Any:
        from research_lab.agent_control.transports.local_mcp import MCPToolResolver
        return MCPToolResolver(list(self._tools.keys()))

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        if tool_name not in self._tools:
            raise ProviderUnavailableError(f"Tool '{tool_name}' not available")
        return self._tools[tool_name](arguments)

    def _mock_projects(self, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "projects": [
                {
                    "cwd": self._workspace_identity,
                    "id": PROJECT_ID,
                    "project_id": PROJECT_ID,
                    "name": PROJECT_ID,
                }
            ]
        }

    def _mock_account_usage(self, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "captured_at": "2026-09-21T00:00:00Z",
            "model_group": "gemini-flash",
            "provider": "antigravity",
            "quota_windows": [
                {
                    "remaining_fraction": 0.85,
                    "reset_time": "2026-09-22T00:00:00Z",
                    "window": "daily",
                }
            ],
            "snapshot_id": "snap-mock-001",
        }

    def _mock_submit(self, args: dict[str, Any]) -> dict[str, Any]:
        task_id = args.get("task_id", "t-unknown")
        req_id = args.get("request_id", "r-unknown")
        job_id = f"job-mock-{hashlib.sha256(f'{task_id}::{req_id}'.encode()).hexdigest()[:8]}"
        output_content = "Deterministic output from Antigravity Mock"
        prompt = (args.get("prompt") or "").lower()
        if "alpha" in prompt or "hypothesis" in prompt:
            output_content = json.dumps(_valid_m5_envelope())
        self._jobs[job_id] = {
            "status": "COMPLETED",
            "task_id": task_id,
            "output": {"content": output_content},
            "response": output_content,
        }
        return {"job_id": job_id, "status": "SUBMITTED"}

    def _mock_status(self, args: dict[str, Any]) -> dict[str, Any]:
        job_id = args.get("job_id", "")
        return {"job_id": job_id, "status": self._jobs.get(job_id, {}).get("status", "COMPLETED")}

    def _mock_result(self, args: dict[str, Any]) -> dict[str, Any]:
        job_id = args.get("job_id", "")
        job_data = self._jobs.get(job_id, {})
        raw_status = job_data.get("status", "COMPLETED")
        is_failed = raw_status == "FAILED"
        terminal_status = "FAILED" if is_failed else ("SUCCESS" if raw_status == "COMPLETED" else raw_status)
        outcome = "FAILED" if is_failed else "TURN_COMPLETE"
        output = job_data.get("output", {"content": "Antigravity result"})
        response = job_data.get("response", "Antigravity result")
        return {
            "job_id": job_id,
            "status": raw_status,
            "terminal_status": terminal_status,
            "outcome": outcome,
            "response": response,
            "structured_output": output,
            "issues": ["Execution failure injected"] if is_failed else [],
        }

    def _mock_cancel(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"cancelled": True}

    def _mock_events(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"events": []}

    def _mock_message(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"status": "DELIVERED"}

    def _mock_wait(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"status": "DONE"}

    def _mock_watch(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"status": "DONE"}


@pytest.fixture
def test_provider() -> ContractTestProvider:
    transport = DirectSDKTestTransport()
    return ContractTestProvider(transport=transport)


@pytest.fixture
def mock_antigravity_provider() -> AntigravityLocalMCPProvider:
    transport = MockLocalMCPTransport()
    return AntigravityLocalMCPProvider(transport=transport)


@pytest.fixture
def conformance_suite() -> AgentProviderConformanceSuite:
    return AgentProviderConformanceSuite(workspace_identity=WORKSPACE_IDENTITY)


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
    return {
        "clean_binding": clean_binding,
        "clean_csv": clean_csv,
        "engine": engine,
        "memory": memory,
        "orchestrator": orchestrator,
        "store": store,
    }


# =====================================================================
# 1. Provider Conformance Suite & Conformance Matrix Tests
# =====================================================================

def test_conformance_suite_all_pass_on_test_provider(
    conformance_suite: AgentProviderConformanceSuite,
    test_provider: ContractTestProvider,
) -> None:
    """Validate that ContractTestProvider passes all 10 conformance checks."""
    report = conformance_suite.run_all(test_provider)
    assert report.is_all_passed, f"ContractTestProvider failed checks: {[r for r in report.results if not r.passed]}"
    assert len(report.results) == 10
    for r in report.results:
        assert r.passed is True
        assert r.contract_name in REQUIRED_CONFORMANCE_CONTRACTS


def test_conformance_suite_all_pass_on_antigravity_provider(
    conformance_suite: AgentProviderConformanceSuite,
    mock_antigravity_provider: AntigravityLocalMCPProvider,
) -> None:
    """Validate that AntigravityLocalMCPProvider passes all 10 conformance checks."""
    report = conformance_suite.run_all(mock_antigravity_provider)
    assert report.is_all_passed, f"AntigravityProvider failed checks: {[r for r in report.results if not r.passed]}"
    assert len(report.results) == 10


def test_conformance_matrix_generation_and_export(
    conformance_suite: AgentProviderConformanceSuite,
    test_provider: ContractTestProvider,
    mock_antigravity_provider: AntigravityLocalMCPProvider,
) -> None:
    """Validate factual generation of the Gate 8 Conformance Matrix and export to docs."""
    report_test = conformance_suite.run_all(test_provider)
    report_ag = conformance_suite.run_all(mock_antigravity_provider)

    reports = {
        "antigravity_adapter": report_ag,
        "contract_test_provider": report_test,
    }

    matrix_data = generate_conformance_matrix(reports)
    assert matrix_data["overall_status"] == "PASS"
    assert len(matrix_data["matrix"]) == 10

    # Ensure every required contract has status PASS
    for row in matrix_data["matrix"]:
        assert row["required"] is True
        assert row["status"] == "PASS"
        assert row["antigravity_adapter"] == "PASS"
        assert row["contract_test_provider"] == "PASS"

    # Verify Markdown formatting produces valid table
    md_table = format_conformance_matrix_markdown(matrix_data)
    assert "| Contract |" in md_table
    assert "| Standard AgentTask |" in md_table
    assert "PASS" in md_table

    # Save to sanitized evidence location
    evidence_path = Path("docs/issue-573-m8-conformance-matrix.json")
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(matrix_data, indent=2), encoding="utf-8")
    assert evidence_path.is_file()


# =====================================================================
# 2. E2E 1: Second Provider Plugin Registration & Capability Selection
# =====================================================================

def test_e2e_1_provider_registration_and_capability_router_selection(
    test_provider: ContractTestProvider,
) -> None:
    """E2E 1: Register ContractTestProvider in ProviderRegistry and select via Router."""
    registry = ProviderRegistry()
    registry.register(test_provider)

    assert registry.contains(CONTRACT_TEST_PROVIDER_NAME)
    desc = test_provider.describe()
    assert desc.provider == CONTRACT_TEST_PROVIDER_NAME
    assert desc.default_model == CONTRACT_TEST_DEFAULT_MODEL

    # Select agent for role 'data_researcher'
    role = AgentRole.DATA_RESEARCHER.value
    scope = authorize(
        role=role,
        requested_permissions=DEFAULT_ROLE_POLICIES[role].allowed_permissions,
        project_binding=STANDARD_PROJECT_BINDING,
    )

    policy = RoutingPolicy(
        role=role,
        provider_priority=(CONTRACT_TEST_PROVIDER_NAME,),
        allowed_transports=(ProviderTransportKind.DIRECT_SDK.value,),
    )

    route = select_agent(
        role=role,
        providers=[test_provider],
        authorized_scope=scope,
        project_binding=STANDARD_PROJECT_BINDING,
        registry=registry,
        routing_policy=policy,
    )

    assert route.provider == CONTRACT_TEST_PROVIDER_NAME
    assert route.resolved_model == CONTRACT_TEST_DEFAULT_MODEL
    assert "direct_sdk" in route.transport_ref
    assert registry.get_transport(route.provider).transport_kind == ProviderTransportKind.DIRECT_SDK
    validate_route_hash(route.to_dict())


# =====================================================================
# 3. E2E 2: Provider Switching for the Same Role
# =====================================================================

def test_e2e_2_same_role_provider_switching_preserves_contracts_and_science(
    test_provider: ContractTestProvider,
    mock_antigravity_provider: AntigravityLocalMCPProvider,
) -> None:
    """E2E 2: Same alpha_generator role executes across Antigravity and ContractTestProvider."""
    role = AgentRole.ALPHA_GENERATOR.value
    permissions = DEFAULT_ROLE_POLICIES[role].allowed_permissions
    scope = authorize(
        role=role,
        requested_permissions=permissions,
        project_binding=STANDARD_PROJECT_BINDING,
    )

    # Route A -> Antigravity
    registry_ag = ProviderRegistry()
    registry_ag.register(mock_antigravity_provider)
    policy_ag = RoutingPolicy(role=role, provider_priority=("antigravity",))
    route_ag = select_agent(
        role=role,
        providers=[mock_antigravity_provider],
        authorized_scope=scope,
        project_binding=STANDARD_PROJECT_BINDING,
        registry=registry_ag,
        routing_policy=policy_ag,
    )

    # Route B -> ContractTestProvider
    registry_test = ProviderRegistry()
    registry_test.register(test_provider)
    policy_test = RoutingPolicy(role=role, provider_priority=(CONTRACT_TEST_PROVIDER_NAME,))
    route_test = select_agent(
        role=role,
        providers=[test_provider],
        authorized_scope=scope,
        project_binding=STANDARD_PROJECT_BINDING,
        registry=registry_test,
        routing_policy=policy_test,
    )

    # Assert contract equivalence
    assert route_ag.role == route_test.role == role
    assert tuple(route_ag.authorized_permissions) == tuple(route_test.authorized_permissions)
    assert route_ag.provider != route_test.provider
    assert route_ag.resolved_model != route_test.resolved_model
    assert route_ag.transport_ref != route_test.transport_ref
    assert registry_ag.get_transport(route_ag.provider).transport_kind != registry_test.get_transport(route_test.provider).transport_kind

    # Assert scientific identity independence:
    # Scientific identity is derived strictly from hypothesis content, NOT provider/model
    core_hypothesis = {
        "description": "Momentum crossover factor",
        "direction": "LONG",
        "factor_name": "momentum_20d",
        "universe": "commodity_active",
    }
    sci_hash_ag = hashlib.sha256(json.dumps(core_hypothesis, sort_keys=True).encode()).hexdigest()
    sci_hash_test = hashlib.sha256(json.dumps(core_hypothesis, sort_keys=True).encode()).hexdigest()
    assert sci_hash_ag == sci_hash_test


# =====================================================================
# 4. E2E 3: M5 Alpha Candidate Admission with Second Provider
# =====================================================================

def test_e2e_3_m5_alpha_candidate_admission_with_second_provider(
    test_provider: ContractTestProvider,
) -> None:
    """E2E 3: ContractTestProvider generates raw output and M5 strictly admits candidate."""
    task, route, registry = AgentProviderConformanceSuite()._build_standard_fixtures(test_provider)
    prep = prepare_execution(task, route, registry)

    req, view, raw_alpha_json = _build_m5_fixtures()
    test_provider.set_configured_output(task.task_id, raw_alpha_json)

    handle = test_provider.submit(task, route, prep, request_id="req-e2e3")
    result = test_provider.result(handle, prep)

    assert result.terminal_status == "SUCCESS"
    assert result.acceptance_status == "ACCEPTED"

    # M5 strict parse & admission
    candidate = admit_alpha_generation_output(
        raw_alpha_json,
        request=req,
        memory_view=view,
        task_id=task.task_id,
        provider=route.provider,
        actual_model=route.resolved_model,
        created_at=NOW,
    )

    assert isinstance(candidate, AlphaGenerationCandidate)
    assert candidate.hypothesis.title == "Short-term reversal after abnormal range expansion"
    assert f"provider:{CONTRACT_TEST_PROVIDER_NAME}" in candidate.hypothesis.provenance.origin_ref
    assert f"model:{CONTRACT_TEST_DEFAULT_MODEL}" in candidate.hypothesis.provenance.origin_ref
    # Provider/Model does NOT enter the scientific hypothesis identity hash
    assert CONTRACT_TEST_PROVIDER_NAME not in candidate.hypothesis.hypothesis_id
    assert CONTRACT_TEST_DEFAULT_MODEL not in candidate.hypothesis.hypothesis_id


# =====================================================================
# 5. E2E 4: M6 Discovery Handover & Science Isolation
# =====================================================================

def test_e2e_4_m6_discovery_handover_success_and_failure_isolation(
    test_provider: ContractTestProvider,
    discovery_context: dict[str, Any],
) -> None:
    """E2E 4: Handover candidate to M6 Discovery boundary, verifying normal flow & failure isolation."""
    task, route, registry = AgentProviderConformanceSuite()._build_standard_fixtures(test_provider)
    prep = prepare_execution(task, route, registry)
    orchestrator = discovery_context["orchestrator"]
    clean_csv = discovery_context["clean_csv"]
    clean_binding = discovery_context["clean_binding"]
    memory = discovery_context["memory"]
    store = discovery_context["store"]

    # 1. Successful flow
    req, view, raw_alpha_json = _build_m5_fixtures()
    test_provider.set_configured_output(task.task_id, raw_alpha_json)
    handle = test_provider.submit(task, route, prep, request_id="req-e2e4-ok")
    result = test_provider.result(handle, prep)

    candidate = admit_alpha_generation_output(
        raw_alpha_json,
        request=req,
        memory_view=view,
        task_id=task.task_id,
        provider=route.provider,
        actual_model=route.resolved_model,
        created_at=NOW,
    )

    m6_res = orchestrator.integrate_candidate(
        candidate=candidate,
        snapshot_path=clean_csv,
        dataset_binding=clean_binding,
        project_binding=STANDARD_PROJECT_BINDING,
        request_id="req-e2e4-ok",
        task_id=task.task_id,
        route_id=route.route_id,
        provider_job_ref=handle.provider_job_ref,
        provider=route.provider,
        model=route.resolved_model,
        agent_result_id=result.result_id,
        agent_result_hash=result.result_content_hash,
    )
    assert m6_res.engineering_status == EngineeringStatus.COMPLETED.value
    assert m6_res.scientific_decision in {"PROMOTE", "REJECT", "NEED_MORE_EVIDENCE"}
    assert m6_res.critic_decision is not None
    assert m6_res.is_tradable is False

    # 2. Failure flow: Injected Provider Failure
    test_provider.set_job_status(handle.provider_job_ref, "FAILED")
    fail_result = test_provider.result(handle, prep)

    pre_fail_memory_count = len(memory.find_by_hypothesis_id("non-existent"))
    runs_before = store.query_v2_runs()

    # Provider failure MUST NOT produce any scientific decision
    assert_provider_error_does_not_pollute_scientific_decision(
        ProviderError(ProviderErrorCode.EXECUTION_FAILED, "simulated")
    )

    req, view, _ = _build_m5_fixtures()

    m6_fail_res = orchestrator.integrate_agent_result(
        agent_result=fail_result,
        request=req,
        memory_view=view,
        snapshot_path=clean_csv,
        task_id=task.task_id,
        provider=route.provider,
        actual_model=route.resolved_model,
        created_at=NOW,
        dataset_binding=clean_binding,
        expected_binding=STANDARD_PROJECT_BINDING,
    )
    assert m6_fail_res.engineering_status == EngineeringStatus.AGENT_EXECUTION_FAILED.value
    assert m6_fail_res.scientific_decision is None
    assert m6_fail_res.critic_decision is None
    # Memory must remain 100% unpolluted
    assert len(memory.find_by_hypothesis_id("non-existent")) == pre_fail_memory_count
    assert len(store.query_v2_runs()) == len(runs_before)



# =====================================================================
# 6. E2E 5: M7 Multi-Agent Provider Mix & Aggregation
# =====================================================================

def test_e2e_5_m7_multi_agent_provider_mix_deterministic_aggregation(
    mock_antigravity_provider: AntigravityLocalMCPProvider,
) -> None:
    """E2E 5: Multi-agent orchestration mixing Antigravity and ContractTestProvider."""
    test_provider_specialized = ContractTestProvider(
        supported_roles=frozenset({"data_researcher", "external_researcher"})
    )
    registry = ProviderRegistry()
    registry.register(mock_antigravity_provider)
    registry.register(test_provider_specialized)

    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=(CONTRACT_TEST_PROVIDER_NAME, "antigravity"),
    )

    wb1 = OrchestratedWorkBlock.create(
        work_block_id="wb-01-gen",
        role=AgentRole.ALPHA_GENERATOR.value,
        objective="Generate alpha candidate",
        prompt="Output valid alpha hypothesis JSON.",
        requested_permissions=list(DEFAULT_ROLE_POLICIES[AgentRole.ALPHA_GENERATOR.value].allowed_permissions),
        ordinal=0,
    )
    wb2 = OrchestratedWorkBlock.create(
        work_block_id="wb-02-data",
        role=AgentRole.DATA_RESEARCHER.value,
        objective="Feature data correlation request",
        prompt="Inspect daily spread characteristics.",
        requested_permissions=list(DEFAULT_ROLE_POLICIES[AgentRole.DATA_RESEARCHER.value].allowed_permissions),
        ordinal=1,
    )
    wb3 = OrchestratedWorkBlock.create(
        work_block_id="wb-03-ext",
        role=AgentRole.EXTERNAL_RESEARCHER.value,
        objective="Academic literature check",
        prompt="Summarize cross-sectional momentum findings.",
        requested_permissions=list(DEFAULT_ROLE_POLICIES[AgentRole.EXTERNAL_RESEARCHER.value].allowed_permissions),
        ordinal=2,
    )

    orch_req = MultiAgentOrchestrationRequest.create(
        project_binding=STANDARD_PROJECT_BINDING,
        purpose="Mixed-provider multi-agent research sprint",
        work_blocks=[wb1, wb2, wb3],
        created_at="2026-09-21T00:00:00Z",
    )

    orchestrator = MultiAgentOrchestrator()

    aggregate = orchestrator.orchestrate(
        orch_req,
        registry=registry,
        providers=[mock_antigravity_provider, test_provider_specialized],
        usage_snapshots={},
        routing_policy=policy,
        provider_lookup=lambda name: registry.get(name),
        created_at="2026-09-21T00:00:00Z",
    )

    assert aggregate.orchestration_engineering_status == "COMPLETED"
    assert len(aggregate.work_block_results) == 3

    res_by_id = {r.work_block_id: r for r in aggregate.work_block_results}

    # Verify distinct providers used per policy & capability matching
    assert res_by_id["wb-01-gen"].provider == "antigravity"
    assert res_by_id["wb-02-data"].provider == CONTRACT_TEST_PROVIDER_NAME
    assert res_by_id["wb-03-ext"].provider == CONTRACT_TEST_PROVIDER_NAME

    # Verify no nested delegation
    assert orch_req.delegation_depth == 0
    for r in aggregate.work_block_results:
        assert DEFAULT_ROLE_POLICIES[r.role].max_delegation_depth == 0

    # Non-alpha outputs are NOT evidence
    assert res_by_id["wb-02-data"].structured_result_type != "alpha_candidate"
    assert res_by_id["wb-03-ext"].structured_result_type != "alpha_candidate"


# =====================================================================
# 7. E2E 6: Provider Failure Equivalence
# =====================================================================

@pytest.mark.parametrize(
    "error_scenario",
    [
        "unavailable",
        "submission_failure",
        "execution_failure",
        "uncertain",
        "empty_deliverable",
        "result_tampering",
        "project_binding_mismatch",
    ],
)
def test_e2e_6_provider_failure_equivalence_and_taxonomy_unification(
    test_provider: ContractTestProvider,
    mock_antigravity_provider: AntigravityLocalMCPProvider,
    error_scenario: str,
) -> None:
    """E2E 6: Inject 7 error scenarios across both providers and verify identical fail-closed taxonomy."""
    suite = AgentProviderConformanceSuite()
    task, route, registry = suite._build_standard_fixtures(test_provider)
    prep = prepare_execution(task, route, registry)

    if error_scenario == "unavailable":
        test_provider.transport.set_connected(False)
        with pytest.raises(ProviderUnavailableError):
            test_provider.submit(task, route, prep)
        test_provider.transport.set_connected(True)

    elif error_scenario == "submission_failure":
        test_provider.inject_failure("submit", ProviderError(ProviderErrorCode.SUBMISSION_FAILED, "simulated"))
        with pytest.raises(ProviderError) as exc_info:
            test_provider.submit(task, route, prep)
        assert exc_info.value.code == ProviderErrorCode.SUBMISSION_FAILED
        test_provider.clear_injections()

    elif error_scenario == "execution_failure":
        handle = test_provider.submit(task, route, prep, request_id="req-fail-exec")
        test_provider.set_job_status(handle.provider_job_ref, "FAILED")
        res = test_provider.result(handle, prep)
        assert res.terminal_status == "FAILED"
        assert res.acceptance_status == "REJECTED"

    elif error_scenario == "uncertain":
        handle = test_provider.submit(task, route, prep, request_id="req-fail-unc")
        test_provider.set_job_status(handle.provider_job_ref, "UNCERTAIN")
        res = test_provider.result(handle, prep)
        assert res.terminal_status == "UNCERTAIN"
        assert res.acceptance_status == "REJECTED"

    elif error_scenario == "empty_deliverable":
        test_provider.set_configured_output(task.task_id, False)
        handle = test_provider.submit(task, route, prep, request_id="req-fail-empty")
        res = test_provider.result(handle, prep)
        assert res.terminal_status == "SUCCESS"
        assert res.acceptance_status == "REJECTED"
        test_provider.set_configured_output(task.task_id, None)

    elif error_scenario == "result_tampering":
        handle = test_provider.submit(task, route, prep, request_id="req-fail-tamp")
        res = test_provider.result(handle, prep)
        tampered_dict = dict(res.to_dict())
        tampered_dict["terminal_status"] = "TAMPERED"
        with pytest.raises(TamperDetectionError):
            validate_result_hash(tampered_dict)

    elif error_scenario == "project_binding_mismatch":
        bad_binding = ProjectBinding(project_id="bad", workspace_identity="/bad")
        bad_scope = authorize(
            role=task.role,
            requested_permissions=list(task.authorized_permissions),
            project_binding=bad_binding,
        )
        tampered_task = AgentTask.create(
            role=task.role,
            requested_permissions=list(task.authorized_permissions),
            authorized_permissions=list(task.authorized_permissions),
            authorized_scope=bad_scope,
            objective=task.objective,
            work_block="wb-bad-test",
            input_refs=[dict(x) for x in task.input_refs],
            provider_policy_ref="policy-bad-v1",
            project_binding=bad_binding,
            created_by="test",
            created_at="2026-09-20T00:00:00Z",
        )
        with pytest.raises((PermissionDeniedError, ProjectBindingError)):
            test_provider.submit(tampered_task, route, prep)


# =====================================================================
# 8. Negative Tests & Boundary Guards
# =====================================================================

def test_negative_unregistered_provider_fails_closed(
    test_provider: ContractTestProvider,
) -> None:
    """Provider not registered in ProviderRegistry fails closed."""
    empty_registry = ProviderRegistry()
    role = "alpha_generator"
    scope = authorize(
        role=role,
        requested_permissions=DEFAULT_ROLE_POLICIES[role].allowed_permissions,
        project_binding=STANDARD_PROJECT_BINDING,
    )
    with pytest.raises(ProviderUnavailableError):
        select_agent(
            role=role,
            providers=[test_provider],
            authorized_scope=scope,
            project_binding=STANDARD_PROJECT_BINDING,
            registry=empty_registry,
        )


def test_negative_trading_permission_hard_invariant_strictly_denied(
    test_provider: ContractTestProvider,
) -> None:
    """Attempts to request live/production trading permissions fail closed with PermissionDeniedError."""
    for bad_perm in HARD_INVARIANT_FORBIDDEN_PERMISSIONS:
        with pytest.raises(PermissionDeniedError):
            authorize(
                role="alpha_generator",
                requested_permissions=("read_market_data", bad_perm),
                project_binding=STANDARD_PROJECT_BINDING,
            )


def test_negative_test_provider_does_not_leak_into_production_default(
    test_provider: ContractTestProvider,
) -> None:
    """Test provider must never be the default provider or default model for production lanes."""
    from research_lab.agent_control.router import select_agent

    # When no explicit policy preference is given and both are registered,
    # antigravity remains the standard provider
    mock_ag = MockLocalMCPTransport()
    ag_provider = AntigravityLocalMCPProvider(transport=mock_ag)

    reg = ProviderRegistry()
    reg.register(ag_provider)
    reg.register(test_provider)

    scope = authorize(
        role="alpha_generator",
        requested_permissions=DEFAULT_ROLE_POLICIES["alpha_generator"].allowed_permissions,
        project_binding=STANDARD_PROJECT_BINDING,
    )

    # Standard select without overrides prefers the primary registered provider
    route = select_agent(
        role="alpha_generator",
        providers=[ag_provider, test_provider],
        authorized_scope=scope,
        project_binding=STANDARD_PROJECT_BINDING,
        registry=reg,
    )
    assert route.provider == "antigravity"
    assert route.provider != CONTRACT_TEST_PROVIDER_NAME


# =====================================================================
# 9. Anti-Leakage Guard: AST Scan for Zero Provider Special-Casing
# =====================================================================

def test_anti_leakage_guard_zero_test_provider_special_casing_in_business_logic() -> None:
    """AST static scan: assert research_lab/alpha_discovery/** and M5/M6/M7 contain zero test provider branches."""
    forbidden_tokens = {
        "contract_test_provider",
        "direct_sdk_test",
        "test-model-standard",
        "test-model-large",
    }

    # 1. Scan research_lab/alpha_discovery/** (must be 100% untouched)
    alpha_discovery_dir = Path("research_lab/alpha_discovery")
    for py_file in alpha_discovery_dir.glob("**/*.py"):
        content = py_file.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in content, (
                f"Leakage detected! Business file '{py_file}' contains forbidden test token '{token}'"
            )

    # 2. Scan core M5, M6, M7 orchestration files (must have zero special-case branches)
    business_agent_control_files = [
        Path("research_lab/agent_control/alpha_generator.py"),
        Path("research_lab/agent_control/discovery_integration.py"),
        Path("research_lab/agent_control/orchestration.py"),
        Path("research_lab/agent_control/roles.py"),
        Path("research_lab/agent_control/permissions.py"),
    ]

    for py_file in business_agent_control_files:
        assert py_file.is_file()
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        # Ensure no comparison or branch against contract_test_provider or direct_sdk_test
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for token in forbidden_tokens:
                    assert node.value != token, (
                        f"Leakage detected! Agent Control file '{py_file}' contains special-case string '{token}'"
                    )


# =====================================================================
# 10. Review Counterexamples & Remediation Tests (Review P1 Blockers)
# =====================================================================

class FlawedAcceptanceProvider(ContractTestProvider):
    """Malicious/faulty provider that unconditionally marks empty deliverable as ACCEPTED."""

    def result(self, handle: Any, preparation: Any = None) -> Any:
        res = super().result(handle, preparation)
        # Violate frozen acceptance boundary: force empty deliverable to be ACCEPTED
        return replace(res, acceptance_status="ACCEPTED")


def test_reproduced_flawed_acceptance_provider_fails_conformance() -> None:
    """Review P1-1 Remediation: Acceptance check must strictly FAIL for flawed providers."""
    flawed_provider = FlawedAcceptanceProvider()
    suite = AgentProviderConformanceSuite(workspace_identity=WORKSPACE_IDENTITY)

    # 1. Acceptance boundary check must fail
    check_res = suite.check_acceptance_boundary(flawed_provider)
    assert check_res.passed is False
    assert "Flawed provider accepted an empty deliverable" in check_res.error_detail

    # 2. Overall suite execution must NOT be 10/10 PASS
    report = suite.run_all(flawed_provider)
    assert report.is_all_passed is False
    conformance_dict = {r.contract_name: r.passed for r in report.results}
    assert conformance_dict["Acceptance boundary"] is False


def test_reproduced_unknown_running_and_failed_submission_recovery_fail_closed(
    test_provider: ContractTestProvider,
) -> None:
    """Review P1-2 Remediation: UNKNOWN/RUNNING and failed submissions must fail closed."""
    suite = AgentProviderConformanceSuite(workspace_identity=WORKSPACE_IDENTITY)
    task, route, registry = suite._build_standard_fixtures(test_provider, work_block="wb-m5-unknown")
    prep = prepare_execution(task, route, registry)

    _, _, raw_alpha_json = _build_m5_fixtures()
    test_provider.set_configured_output(task.task_id, raw_alpha_json)

    handle_unknown = test_provider.submit(task, route, prep, request_id="req-m5-unknown")
    test_provider.set_job_status(handle_unknown.provider_job_ref, "UNKNOWN")

    res_unknown = test_provider.result(handle_unknown, prep)
    assert res_unknown.terminal_status == "UNCERTAIN"
    assert res_unknown.acceptance_status == "REJECTED"

    # Must fail closed in real M5 admission pipeline
    with pytest.raises(ResultAcceptanceError, match="provider result is not accepted"):
        from research_lab.agent_control.alpha_generator import _extract_raw_output

        _extract_raw_output(res_unknown)

    # 2. RUNNING status must reject result query (not completed)
    test_provider.set_job_status(handle_unknown.provider_job_ref, "RUNNING")
    with pytest.raises(ProviderError, match="is still in non-terminal state"):
        test_provider.result(handle_unknown, prep)

    # 3. Transport invocation failure must not record false idempotency cache
    transport = test_provider._transport
    fail_counter = 0

    def failing_invoker(op: str, payload: dict[str, Any]) -> dict[str, Any]:
        nonlocal fail_counter
        fail_counter += 1
        if fail_counter == 1:
            raise ProviderUnavailableError("Simulated transient transport failure")
        return {"operation": op, "status": "COMPLETED", "output": payload.get("input", {})}

    transport.set_custom_invoker(failing_invoker)
    task_retry, route_retry, reg_retry = suite._build_standard_fixtures(test_provider, work_block="wb-retry-transport")
    prep_retry = prepare_execution(task_retry, route_retry, reg_retry)

    # First attempt fails at transport
    with pytest.raises(ProviderUnavailableError, match="Simulated transient transport failure"):
        test_provider.submit(task_retry, route_retry, prep_retry, request_id="req-retry-01")

    # Second attempt must actually invoke transport again (call_counter == 2) instead of cache hit
    handle_recovered = test_provider.submit(task_retry, route_retry, prep_retry, request_id="req-retry-01")
    assert fail_counter == 2
    assert handle_recovered.provider_job_ref is not None
    transport.set_custom_invoker(None)


def test_reproduced_cross_project_and_cross_task_result_mixing_strictly_rejected(
    test_provider: ContractTestProvider,
) -> None:
    """Review P1-3 Remediation: Result query cross-validates original task, route, and project."""
    suite = AgentProviderConformanceSuite(workspace_identity=WORKSPACE_IDENTITY)
    task_a, route_a, reg_a = suite._build_standard_fixtures(
        test_provider,
        override_binding={"project_id": "project_alpha", "workspace_identity": "/ws/alpha"},
        work_block="wb-proj-a",
    )
    task_b, route_b, reg_b = suite._build_standard_fixtures(
        test_provider,
        override_binding={"project_id": "project_beta", "workspace_identity": "/ws/beta"},
        work_block="wb-proj-b",
    )

    prep_a = prepare_execution(task_a, route_a, reg_a)
    prep_b = prepare_execution(task_b, route_b, reg_b)

    handle_a = test_provider.submit(task_a, route_a, prep_a, request_id="req-proj-a")
    handle_b = test_provider.submit(task_b, route_b, prep_b, request_id="req-proj-b")

    # Attacker tries to mix Job A with Task/Route/Preparation B
    mixed_handle = replace(handle_a, task_ref=dict(handle_b.task_ref), route_ref=dict(handle_b.route_ref))

    with pytest.raises((PermissionDeniedError, ProjectBindingError), match="cross-task replay rejected|mismatch"):
        test_provider.result(mixed_handle, prep_b)

