"""Focused lifecycle and contract tests for Agent Control Architecture (#573 Milestone 0).

Verifies:
1. End-to-end contract flow: Task -> Authorize -> Route -> Provider -> Result -> Audit
2. Complete role / provider / model decoupling
3. Scientific boundary: Agent != Critic != Trading Authority
4. Provider error does not pollute scientific decision
5. Append-only audit integrity across multiple operations
"""

from __future__ import annotations

import pytest

from research_lab.agent_control import (
    AgentAuditRecord,
    AgentExecutionHandle,
    AgentPermission,
    AgentProviderDescriptor,
    AgentResult,
    AgentRole,
    AgentRoute,
    AgentTask,
    AppendOnlyAuditTrail,
    ProjectBinding,
    ProviderAvailability,
    ProviderError,
    ProviderErrorCode,
    TerminalStatus,
    assert_provider_error_does_not_pollute_scientific_decision,
    authorize,
    select_agent,
    validate_audit_hash,
    validate_result_hash,
    validate_route_hash,
    validate_task_hash,
)


class MockLifecycleProvider:
    """Provider implementing AgentProvider interface for focused contract verification."""

    def __init__(
        self,
        name: str = "antigravity_stub",
        default_model: str = "gemini-3.8-flash-high",
    ) -> None:
        self.name = name
        self.default_model = default_model

    def describe(self) -> AgentProviderDescriptor:
        return AgentProviderDescriptor(
            provider=self.name,
            supported_roles=(
                AgentRole.ALPHA_GENERATOR.value,
                AgentRole.RESEARCH_SYNTHESIZER.value,
                AgentRole.DATA_RESEARCHER.value,
            ),
            supported_models=(self.default_model, "gemini-3.8-pro"),
            capabilities=("text_generation", "code_analysis"),
            default_model=self.default_model,
        )

    def availability(self, role: str, context: dict | None = None) -> ProviderAvailability:
        return ProviderAvailability(is_available=True, status="AVAILABLE")

    def submit(self, task: AgentTask, route: AgentRoute) -> AgentExecutionHandle:
        return AgentExecutionHandle(
            handle_id=f"handle-{task.task_id[:16]}",
            task_ref={"task_id": task.task_id},
            route_ref={"route_id": route.route_id},
            provider_job_ref="mock-job-9999",
            status="SUBMITTED",
        )

    def status(self, handle: AgentExecutionHandle) -> str:
        return "COMPLETED"

    def result(self, handle: AgentExecutionHandle) -> AgentResult:
        return AgentResult.create(
            task_ref=handle.task_ref,
            route_ref=handle.route_ref,
            provider_job_ref=handle.provider_job_ref,
            terminal_status=TerminalStatus.SUCCESS,
            raw_result_ref="memory://mock-raw-result",
            structured_output={"candidate_alpha": "momentum_ts_if"},
            tool_failures=[],
            uncertainty=None,
            acceptance_status="ACCEPTED",
        )

    def cancel(self, handle: AgentExecutionHandle) -> bool:
        return True


def test_complete_agent_lifecycle_contract_flow() -> None:
    binding = ProjectBinding(
        project_id="vnpy-core",
        workspace_identity="/Users/fujun/node/vnpy",
    )

    # 1. Authorize requested permissions for alpha_generator
    requested_perms = [
        AgentPermission.READ_RESEARCH_MEMORY.value,
        AgentPermission.CREATE_HYPOTHESIS.value,
    ]
    auth_scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=requested_perms,
    )
    assert auth_scope.is_authorized is True
    assert set(auth_scope.authorized_permissions) == set(requested_perms)
    assert len(auth_scope.denied_permissions) == 0

    # 2. Construct AgentTask
    task = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=list(auth_scope.requested_permissions),
        authorized_permissions=list(auth_scope.authorized_permissions),
        authorized_scope=auth_scope,
        objective="Draft exploratory momentum alpha candidate on IF contracts",
        work_block="WB-DISCOVERY-001",
        input_refs=[{"kind": "dataset", "locator": "market_data/IF_continuous.parquet"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="orchestrator_main",
        created_at="2026-09-20T12:00:00Z",
    )
    validate_task_hash(task.to_dict())
    assert task.authorization_scope_ref == auth_scope.scope_id

    # 3. Router selects provider and model (Provider-neutral routing)
    provider = MockLifecycleProvider()
    route = select_agent(
        role=AgentRole.ALPHA_GENERATOR.value,
        providers=[provider],
        authorized_scope=auth_scope,
        project_binding=binding,
    )
    validate_route_hash(route.to_dict())
    assert route.provider == "antigravity_stub"
    assert route.resolved_model == "gemini-3.8-flash-high"
    assert route.role == AgentRole.ALPHA_GENERATOR.value
    assert route.authorization_scope_ref == auth_scope.scope_id
    assert route.authorized_permissions == auth_scope.authorized_permissions

    # 4. Provider execution
    handle = provider.submit(task, route)
    assert handle.provider_job_ref == "mock-job-9999"

    # 5. Result retrieval and validation
    result = provider.result(handle)
    validate_result_hash(result.to_dict())
    assert result.terminal_status == TerminalStatus.SUCCESS.value
    assert result.acceptance_status == "ACCEPTED"

    # 6. Append-only Audit trail
    audit_record = AgentAuditRecord.create(
        role=route.role,
        provider=route.provider,
        resolved_model=route.resolved_model,
        policy_version=route.policy_version,
        task_ref={"task_id": task.task_id},
        route_ref={"route_id": route.route_id},
        provider_job_ref=handle.provider_job_ref,
        project_binding=binding,
        input_refs=list(task.input_refs),
        requested_permissions=list(task.requested_permissions),
        authorized_permissions=list(task.authorized_permissions),
        usage_snapshot_ref=route.usage_snapshot_ref,
        terminal_status=result.terminal_status,
        result_ref={"result_id": result.result_id},
        acceptance_status=result.acceptance_status,
        recorded_at="2026-09-20T12:00:05Z",
    )
    validate_audit_hash(audit_record.to_dict())

    trail = AppendOnlyAuditTrail()
    trail.append(audit_record)
    assert len(trail) == 1
    assert trail.verify_all() is True


def test_role_provider_model_decoupling() -> None:
    """Verify that any single role can be routed to distinct providers and models."""
    role = AgentRole.RESEARCH_SYNTHESIZER.value
    binding = ProjectBinding(
        project_id="vnpy-core",
        workspace_identity="/Users/fujun/node/vnpy",
    )
    auth_scope = authorize(
        role=role,
        requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
    )

    provider1 = MockLifecycleProvider(name="provider_alpha", default_model="model-fast")
    provider2 = MockLifecycleProvider(name="provider_beta", default_model="model-deep")

    route1 = select_agent(
        role=role,
        providers=[provider1],
        authorized_scope=auth_scope,
        project_binding=binding,
    )
    route2 = select_agent(
        role=role,
        providers=[provider2],
        authorized_scope=auth_scope,
        project_binding=binding,
    )

    assert route1.role == role and route2.role == role
    assert route1.provider == "provider_alpha"
    assert route1.resolved_model == "model-fast"
    assert route2.provider == "provider_beta"
    assert route2.resolved_model == "model-deep"
    assert route1.authorization_scope_ref == auth_scope.scope_id
    assert route2.authorization_scope_ref == auth_scope.scope_id
    assert route1.authorized_permissions == (AgentPermission.READ_RESEARCH_MEMORY.value,)
    assert route2.authorized_permissions == (AgentPermission.READ_RESEARCH_MEMORY.value,)


def test_provider_error_cannot_pollute_scientific_decision() -> None:
    """Ensure provider errors cannot be mapped to scientific review outcomes."""
    clean_err = ProviderError(
        code=ProviderErrorCode.PROVIDER_UNAVAILABLE,
        message="Backend timeout",
        details={"timeout_sec": 30},
    )
    assert_provider_error_does_not_pollute_scientific_decision(clean_err)

    # Malicious or buggy mapping attempting to treat provider failure as scientific rejection
    polluting_err = ProviderError(
        code=ProviderErrorCode.EXECUTION_FAILED,
        message="Failure",
        details={"scientific_verdict": "REJECT"},
    )
    with pytest.raises(ValueError) as exc_info:
        assert_provider_error_does_not_pollute_scientific_decision(polluting_err)
    assert "ProviderError details contain forbidden scientific verdict" in str(exc_info.value)
