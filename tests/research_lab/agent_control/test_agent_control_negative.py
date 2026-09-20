"""Comprehensive Negative Tests for Agent Access Control (#573 Milestone 0).

Covers all 14 baseline negative scenarios plus strict Contract Freeze tests:
1. unknown role
2. unknown permission
3. role 请求越权 (elevation attempt)
4. production_trading=true (hard invariant violation)
5. live_trading_authorized=true (hard invariant violation)
6. worker nested delegation (depth >= 1 & role policy can_delegate)
7. unknown provider
8. malformed provider result
9. result content hash tampering
10. audit hash tampering
11. unknown quota state preserved (never assumed 0% or 100%)
12. project binding mismatch
13. role/model hard-coupling regression
14. duplicate deterministic task identity (stable across time & instances)
15. [P1-1] Task direct construction / create elevation fails closed
16. [P1-1] Route direct construction / create elevation fails closed
17. [P1-1] Route least privilege (never expands to full role policy permissions)
18. [P1-1] Scope hash tampering and mismatch detection
19. [P1-1] Task and Route authorization_scope_ref tampering detection
20. [P1-1] Task unrequested permission elevation fails closed (authorized ⊆ requested)
21. [P1-2] Task parent/depth relationship validation (depth=0 cannot have parent, depth>0 must have parent)
22. [P1-3] select_agent() missing project_binding fails closed
23. [P1-3] ProjectBinding placeholder and empty values rejected
"""

from __future__ import annotations

import copy

import pytest

from research_lab.agent_control import (
    AgentAuditRecord,
    AgentPermission,
    AgentPermissionScope,
    AgentProviderDescriptor,
    AgentResult,
    AgentRole,
    AgentRolePolicy,
    AgentRoute,
    AgentTask,
    AgentUsageSnapshot,
    AppendOnlyAuditTrail,
    PermissionDeniedError,
    ProjectBinding,
    ProjectBindingError,
    ProviderAvailability,
    ProviderErrorCode,
    ProviderUnavailableError,
    ResultAcceptanceError,
    TamperDetectionError,
    TerminalStatus,
    authorize,
    compute_route_content_hash,
    compute_task_content_hash,
    enforce_no_nested_delegation,
    select_agent,
    validate_audit_hash,
    validate_permission,
    validate_project_binding,
    validate_result_hash,
    validate_role,
    validate_route_hash,
    validate_scope_hash,
    validate_task_hash,
)


class DummyMockProvider:
    """Minimal mock provider for negative routing and execution tests."""

    def __init__(
        self,
        name: str = "mock_provider",
        supported_roles: tuple[str, ...] = (AgentRole.ALPHA_GENERATOR.value,),
        supported_models: tuple[str, ...] = ("mock-model-v1",),
        is_available: bool = True,
    ) -> None:
        self.name = name
        self.supported_roles = supported_roles
        self.supported_models = supported_models
        self.is_available = is_available

    def describe(self) -> AgentProviderDescriptor:
        return AgentProviderDescriptor(
            provider=self.name,
            supported_roles=self.supported_roles,
            supported_models=self.supported_models,
            capabilities=("text_generation",),
            default_model=self.supported_models[0],
        )

    def availability(self, role: str, context: dict | None = None) -> ProviderAvailability:
        return ProviderAvailability(
            is_available=self.is_available,
            status="AVAILABLE" if self.is_available else "UNAVAILABLE",
        )

    def submit(self, task, route):
        raise NotImplementedError

    def status(self, handle):
        raise NotImplementedError

    def result(self, handle):
        raise NotImplementedError

    def cancel(self, handle):
        return True


# 1. Unknown role
def test_negative_1_unknown_role() -> None:
    binding = ProjectBinding(project_id="vnpy-core", workspace_identity="/workspace/vnpy")
    with pytest.raises(PermissionDeniedError) as exc_info:
        validate_role("super_autonomous_trader")
    assert "Unknown role" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PERMISSION_DENIED

    with pytest.raises(PermissionDeniedError):
        authorize(
            role="unregistered_agent_role",
            requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
            project_binding=binding,
        )


# 2. Unknown permission
def test_negative_2_unknown_permission() -> None:
    binding = ProjectBinding(project_id="vnpy-core", workspace_identity="/workspace/vnpy")
    with pytest.raises(PermissionDeniedError) as exc_info:
        validate_permission("arbitrary_system_root")
    assert "Unknown permission" in str(exc_info.value)

    with pytest.raises(PermissionDeniedError):
        authorize(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value, "grant_all_access"],
            project_binding=binding,
        )


# 3. Role permission elevation (越权请求)
def test_negative_3_role_permission_elevation() -> None:
    binding = ProjectBinding(project_id="vnpy-core", workspace_identity="/workspace/vnpy")
    # alpha_generator attempts to invoke critic or write research memory
    with pytest.raises(PermissionDeniedError) as exc_info:
        authorize(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[
                AgentPermission.READ_RESEARCH_MEMORY.value,
                AgentPermission.INVOKE_CRITIC.value,  # Forbidden for alpha_generator
            ],
            project_binding=binding,
        )
    assert "Permission denied" in str(exc_info.value)
    assert "invoke_critic" in str(exc_info.value)


# 4. production_trading = true (Hard Invariant Violation)
def test_negative_4_production_trading_hard_invariant() -> None:
    binding = ProjectBinding(project_id="vnpy-core", workspace_identity="/workspace/vnpy")
    # Even if someone constructs a policy or requests production_trading, fail-closed
    with pytest.raises(PermissionDeniedError) as exc_info:
        authorize(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.PRODUCTION_TRADING.value],
            project_binding=binding,
        )
    assert "Hard invariant violation" in str(exc_info.value)

    # Trying to configure a policy with production_trading fails immediately
    with pytest.raises(PermissionDeniedError) as exc_info2:
        AgentRolePolicy(
            role=AgentRole.ALPHA_GENERATOR.value,
            allowed_permissions=frozenset([AgentPermission.PRODUCTION_TRADING.value]),
        )
    assert "Hard invariant violation" in str(exc_info2.value)


# 5. live_trading_authorized = true (Hard Invariant Violation)
def test_negative_5_live_trading_authorized_hard_invariant() -> None:
    binding = ProjectBinding(project_id="vnpy-core", workspace_identity="/workspace/vnpy")
    with pytest.raises(PermissionDeniedError) as exc_info:
        authorize(
            role=AgentRole.CODE_RESEARCHER.value,
            requested_permissions=[AgentPermission.LIVE_TRADING_AUTHORIZED.value],
            project_binding=binding,
        )
    assert "Hard invariant violation" in str(exc_info.value)

    with pytest.raises(PermissionDeniedError) as exc_info2:
        AgentRolePolicy(
            role=AgentRole.CODE_RESEARCHER.value,
            allowed_permissions=frozenset([AgentPermission.LIVE_TRADING_AUTHORIZED.value]),
        )
    assert "Hard invariant violation" in str(exc_info2.value)


# 6. Worker nested delegation (depth >= 1 & role policy can_delegate)
def test_negative_6_worker_nested_delegation() -> None:
    # 1. Default worker role has can_delegate=False, so depth=0 is still prohibited
    with pytest.raises(PermissionDeniedError) as exc_info0:
        enforce_no_nested_delegation(role=AgentRole.ALPHA_GENERATOR.value, delegation_depth=0)
    assert "not permitted to delegate" in str(exc_info0.value)

    # 2. Worker at depth >= 1 is prohibited under all circumstances
    with pytest.raises(PermissionDeniedError) as exc_info1:
        enforce_no_nested_delegation(
            role=AgentRole.ALPHA_GENERATOR.value,
            delegation_depth=1,
            parent_task_ref={"task_id": "task-parent-123"},
        )
    assert "Nested agent delegation prohibited" in str(exc_info1.value)
    assert exc_info1.value.code == ProviderErrorCode.PERMISSION_DENIED

    # 3. Explicit can_delegate=True policy allows depth=0
    orchestrator_policy = AgentRolePolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        allowed_permissions=frozenset([AgentPermission.CREATE_HYPOTHESIS.value]),
        can_delegate=True,
    )
    enforce_no_nested_delegation(
        role=AgentRole.ALPHA_GENERATOR.value,
        delegation_depth=0,
        policy=orchestrator_policy,
    )

    # 4. Explicit can_delegate=True policy STILL rejects depth >= 1
    with pytest.raises(PermissionDeniedError) as exc_info2:
        enforce_no_nested_delegation(
            role=AgentRole.ALPHA_GENERATOR.value,
            delegation_depth=1,
            parent_task_ref={"task_id": "task-parent-123"},
            policy=orchestrator_policy,
        )
    assert "Nested agent delegation prohibited" in str(exc_info2.value)


# 7. Unknown provider
def test_negative_7_unknown_provider() -> None:
    binding = ProjectBinding(project_id="vnpy-core", workspace_identity="/workspace/vnpy")
    scope = authorize(
        role=AgentRole.DATA_RESEARCHER.value,
        requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
        project_binding=binding,
    )
    providers = [DummyMockProvider(supported_roles=(AgentRole.ALPHA_GENERATOR.value,))]
    with pytest.raises(ProviderUnavailableError) as exc_info:
        select_agent(
            role=AgentRole.DATA_RESEARCHER.value,
            providers=providers,
            authorized_scope=scope,
            project_binding=binding,
        )
    assert "No available provider supports role" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PROVIDER_UNAVAILABLE


# 8. Malformed provider result
def test_negative_8_malformed_provider_result() -> None:
    with pytest.raises(ResultAcceptanceError) as exc_info:
        AgentResult.create(
            task_ref={"task_id": "task-123"},
            route_ref={"route_id": "route-123"},
            provider_job_ref="job-123",
            terminal_status="ARBITRARY_UNKNOWN_STATUS",
        )
    assert "Invalid terminal_status" in str(exc_info.value)


# 9. Result content hash tampering
def test_negative_9_result_content_hash_tampering() -> None:
    result = AgentResult.create(
        task_ref={"task_id": "task-123"},
        route_ref={"route_id": "route-123"},
        provider_job_ref="job-123",
        terminal_status=TerminalStatus.SUCCESS,
        structured_output={"ideas": ["alpha1"]},
    )
    raw_dict = result.to_dict()
    validate_result_hash(raw_dict)

    tampered = copy.deepcopy(raw_dict)
    tampered["structured_output"] = {"ideas": ["alpha1_tampered_malicious"]}

    with pytest.raises(TamperDetectionError) as exc_info:
        validate_result_hash(tampered)
    assert "AgentResult content hash tampering detected" in str(exc_info.value)


# 10. Audit hash tampering
def test_negative_10_audit_hash_tampering() -> None:
    audit = AgentAuditRecord.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider="mock_provider",
        resolved_model="mock-model",
        policy_version="2026-09-m0",
        task_ref={"task_id": "task-123"},
        route_ref={"route_id": "route-123"},
        provider_job_ref="job-123",
        project_binding={"project_id": "vnpy-p1", "workspace_identity": "vnpy-w1", "binding_mode": "strict"},
        input_refs=[],
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        usage_snapshot_ref=None,
        terminal_status=TerminalStatus.SUCCESS.value,
        result_ref={"result_id": "res-123"},
        acceptance_status="ACCEPTED",
        recorded_at="2026-09-20T00:00:00Z",
    )
    raw_dict = audit.to_dict()
    validate_audit_hash(raw_dict)

    tampered = copy.deepcopy(raw_dict)
    tampered["acceptance_status"] = "FORGED_ACCEPTED"
    with pytest.raises(TamperDetectionError) as exc_info:
        validate_audit_hash(tampered)
    assert "AgentAuditRecord content hash tampering detected" in str(exc_info.value)

    trail = AppendOnlyAuditTrail()
    trail.append(audit)
    assert len(trail) == 1


# 11. Unknown quota state preserved
def test_negative_11_unknown_quota_state_preserved() -> None:
    snapshot = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="gemini-high",
        quota_windows=[
            {
                "window": "hourly",
                "remaining_fraction": None,
                "reset_time": None,
                "status": "unknown",
            }
        ],
        captured_at="2026-09-20T12:00:00Z",
    )
    data = snapshot.to_dict()
    window = data["quota_windows"][0]
    assert window["status"] == "unknown"
    assert window["remaining_fraction"] is None


# 12. Project binding mismatch
def test_negative_12_project_binding_mismatch() -> None:
    expected = ProjectBinding(
        project_id="vnpy-core",
        workspace_identity="/Users/fujun/node/vnpy",
    )
    mismatched_id = ProjectBinding(
        project_id="foreign-project-xyz",
        workspace_identity="/Users/fujun/node/vnpy",
    )
    with pytest.raises(ProjectBindingError) as exc_info:
        validate_project_binding(mismatched_id, expected)
    assert "Project ID mismatch" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PROJECT_BINDING_FAILED

    mismatched_ws = ProjectBinding(
        project_id="vnpy-core",
        workspace_identity="/Users/fujun/node/other_repo",
    )
    with pytest.raises(ProjectBindingError) as exc_info2:
        validate_project_binding(mismatched_ws, expected)
    assert "Workspace identity mismatch" in str(exc_info2.value)


# 13. Role/model hard-coupling regression
def test_negative_13_role_model_hard_coupling_prohibited() -> None:
    with pytest.raises(PermissionDeniedError):
        validate_role("GeminiAlphaGenerator")

    with pytest.raises(PermissionDeniedError):
        validate_role("GPTResearcher")

    with pytest.raises(PermissionDeniedError):
        validate_role("ClaudeSynthesizer")


# 14. Duplicate deterministic task identity
def test_negative_14_deterministic_task_identity_reproducible() -> None:
    binding = ProjectBinding(
        project_id="vnpy-test",
        workspace_identity="/workspace/test",
    )
    scope1 = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )
    task1 = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope1,
        objective="Analyze momentum factors on IF contracts",
        work_block="WB-001",
        input_refs=[{"type": "spec", "id": "spec-1"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_a",
        created_at="2026-09-20T00:00:00Z",
    )

    task2 = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope1,
        objective="Analyze momentum factors on IF contracts",
        work_block="WB-001",
        input_refs=[{"type": "spec", "id": "spec-1"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_b",
        created_at="2026-09-20T18:00:00Z",
    )

    assert task1.task_id == task2.task_id

    task_modified = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope1,
        objective="Analyze mean reversion factors on IC contracts",
        work_block="WB-001",
        input_refs=[{"type": "spec", "id": "spec-1"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_a",
        created_at="2026-09-20T00:00:00Z",
    )
    assert task1.task_id != task_modified.task_id


# 15. [P1-1] Task direct construction / create elevation fails closed
def test_negative_15_task_direct_construction_elevation_fails_closed() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    valid_scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )

    # alpha_generator attempts to construct a task with invoke_critic or execute_screening
    with pytest.raises(PermissionDeniedError) as exc_info1:
        AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.INVOKE_CRITIC.value],
            authorized_permissions=[AgentPermission.INVOKE_CRITIC.value],
            authorized_scope=valid_scope,
            objective="Malicious elevation",
            work_block="WB-001",
            input_refs=[],
            provider_policy_ref="policy-v1",
            project_binding=binding,
            created_by="attacker",
            created_at="2026-09-20T00:00:00Z",
        )
    assert "unauthorized permissions" in str(exc_info1.value)

    # Direct constructor bypass attempt with unauthorized permissions
    raw = {
        "authorization_scope_ref": valid_scope.to_dict(),
        "authorized_permissions": [AgentPermission.EXECUTE_SCREENING.value],
        "created_at": "2026-09-20T00:00:00Z",
        "created_by": "attacker",
        "delegation_depth": 0,
        "hash_profile": "research-json-v1",
        "input_refs": [],
        "objective": "Bypass constructor",
        "parent_task_ref": None,
        "project_binding": binding.to_dict(),
        "provider_policy_ref": "policy-v1",
        "requested_permissions": [AgentPermission.EXECUTE_SCREENING.value],
        "role": AgentRole.ALPHA_GENERATOR.value,
        "schema_version": "research_lab.agent_task.v1",
        "work_block": "WB-001",
    }
    raw["task_id"] = "task-mock-id"
    raw["task_content_hash"] = compute_task_content_hash(raw)

    with pytest.raises(PermissionDeniedError) as exc_info2:
        AgentTask(
            task_id=raw["task_id"],
            authorization_scope_ref=valid_scope.to_dict(),
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=(AgentPermission.EXECUTE_SCREENING.value,),
            authorized_permissions=(AgentPermission.EXECUTE_SCREENING.value,),
            objective="Bypass constructor",
            work_block="WB-001",
            input_refs=(),
            provider_policy_ref="policy-v1",
            project_binding=binding.to_dict(),
            created_by="attacker",
            created_at="2026-09-20T00:00:00Z",
            task_content_hash=raw["task_content_hash"],
        )
    assert "mismatch with authorization_scope_ref" in str(exc_info2.value)


# 16. [P1-1] Route direct construction / create elevation fails closed
def test_negative_16_route_direct_construction_elevation_fails_closed() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    valid_scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )

    with pytest.raises(PermissionDeniedError) as exc_info1:
        AgentRoute.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            provider="mock_p",
            resolved_model="m1",
            policy_version="v1",
            route_reason="reason",
            usage_snapshot_ref=None,
            project_binding=binding,
            authorized_permissions=[AgentPermission.INVOKE_CRITIC.value],
            authorized_scope=valid_scope,
        )
    assert "unauthorized permissions" in str(exc_info1.value)

    # Direct constructor bypass attempt
    raw = {
        "authorization_scope_ref": valid_scope.to_dict(),
        "authorized_permissions": [AgentPermission.INVOKE_CRITIC.value],
        "hash_profile": "research-json-v1",
        "policy_version": "v1",
        "project_binding": binding.to_dict(),
        "provider": "mock_p",
        "resolved_model": "m1",
        "role": AgentRole.ALPHA_GENERATOR.value,
        "route_reason": "reason",
        "schema_version": "research_lab.agent_route.v1",
        "usage_snapshot_ref": None,
    }
    raw["route_id"] = "route-mock-id"
    raw["route_content_hash"] = compute_route_content_hash(raw)

    with pytest.raises(PermissionDeniedError) as exc_info2:
        AgentRoute(
            route_id=raw["route_id"],
            authorization_scope_ref=valid_scope.to_dict(),
            role=AgentRole.ALPHA_GENERATOR.value,
            provider="mock_p",
            resolved_model="m1",
            policy_version="v1",
            route_reason="reason",
            usage_snapshot_ref=None,
            project_binding=binding.to_dict(),
            authorized_permissions=(AgentPermission.INVOKE_CRITIC.value,),
            route_content_hash=raw["route_content_hash"],
        )
    assert "mismatch with authorization_scope_ref" in str(exc_info2.value)


# 17. [P1-1] Route least privilege (never expands to full role policy permissions)
def test_negative_17_route_least_privilege_no_role_expansion() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    provider = DummyMockProvider(
        name="antigravity_stub",
        supported_roles=(AgentRole.ALPHA_GENERATOR.value,),
    )

    # Request ONLY create_hypothesis (even though alpha_generator can also have revise_hypothesis and read_research_memory)
    auth_scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )
    assert auth_scope.authorized_permissions == (AgentPermission.CREATE_HYPOTHESIS.value,)

    route = select_agent(
        role=AgentRole.ALPHA_GENERATOR.value,
        providers=[provider],
        authorized_scope=auth_scope,
        project_binding=binding,
    )

    # Route MUST ONLY carry create_hypothesis, strictly matching the scope!
    assert route.authorized_permissions == (AgentPermission.CREATE_HYPOTHESIS.value,)
    assert AgentPermission.REVISE_HYPOTHESIS.value not in route.authorized_permissions
    assert AgentPermission.READ_RESEARCH_MEMORY.value not in route.authorized_permissions


# 18. [P1-1] Scope hash tampering and mismatch detection
def test_negative_18_scope_hash_tampering_and_mismatch_detected() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    scope = AgentPermissionScope.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )
    raw = scope.to_dict()
    validate_scope_hash(raw)

    tampered = copy.deepcopy(raw)
    tampered["authorized_permissions"] = [AgentPermission.INVOKE_CRITIC.value]
    with pytest.raises(TamperDetectionError):
        validate_scope_hash(tampered)

    # Role mismatch between scope and select_agent
    provider = DummyMockProvider(supported_roles=(AgentRole.DATA_RESEARCHER.value,))
    with pytest.raises(PermissionDeniedError) as exc_info:
        select_agent(
            role=AgentRole.DATA_RESEARCHER.value,
            providers=[provider],
            authorized_scope=scope,  # role is alpha_generator
            project_binding=binding,
        )
    assert "role mismatch" in str(exc_info.value)

    # Project binding mismatch between scope and select_agent
    other_binding = ProjectBinding(project_id="vnpy-other", workspace_identity="/workspace/other")
    alpha_provider = DummyMockProvider(supported_roles=(AgentRole.ALPHA_GENERATOR.value,))
    with pytest.raises(ProjectBindingError) as exc_binding:
        select_agent(
            role=AgentRole.ALPHA_GENERATOR.value,
            providers=[alpha_provider],
            authorized_scope=scope,  # binding is vnpy-p1
            project_binding=other_binding,
        )
    assert "project_binding mismatch" in str(exc_binding.value)


# 19. [P1-1] Task and Route authorization_scope_ref tampering detection
def test_negative_19_task_and_route_scope_ref_tampering_detected() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )
    task = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope,
        objective="Analyze factors",
        work_block="WB-001",
        input_refs=[],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_a",
        created_at="2026-09-20T00:00:00Z",
    )
    raw_task = task.to_dict()
    validate_task_hash(raw_task)

    tampered_task = copy.deepcopy(raw_task)
    tampered_task["authorization_scope_ref"]["scope_id"] = "scope-forged-999"
    with pytest.raises(TamperDetectionError):
        validate_task_hash(tampered_task)

    route = AgentRoute.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider="mock_p",
        resolved_model="m1",
        policy_version="v1",
        route_reason="reason",
        usage_snapshot_ref=None,
        project_binding=binding,
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope,
    )
    raw_route = route.to_dict()
    validate_route_hash(raw_route)

    tampered_route = copy.deepcopy(raw_route)
    tampered_route["authorization_scope_ref"]["scope_id"] = "scope-forged-999"
    with pytest.raises(TamperDetectionError):
        validate_route_hash(tampered_route)


# 20. [P1-1] Task unrequested permission elevation fails closed
def test_negative_20_task_unrequested_permission_elevation_fails_closed() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    valid_scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )

    # authorized is NOT a subset of requested
    with pytest.raises(PermissionDeniedError) as exc_info:
        AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[
                AgentPermission.CREATE_HYPOTHESIS.value,
                AgentPermission.REVISE_HYPOTHESIS.value,  # unrequested!
            ],
            authorized_scope=valid_scope,
            objective="Analyze factors",
            work_block="WB-001",
            input_refs=[],
            provider_policy_ref="policy-v1",
            project_binding=binding,
            created_by="researcher_a",
            created_at="2026-09-20T00:00:00Z",
        )
    assert "unrequested permissions" in str(exc_info.value)


# 21. [P1-2] Task parent/depth relationship validation
def test_negative_21_task_parent_depth_relationship_validation() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    valid_scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )

    # depth=0 but specifies parent_task_ref -> FAIL (cannot forge worker-parent)
    with pytest.raises(PermissionDeniedError) as exc_info1:
        AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_scope=valid_scope,
            objective="Analyze factors",
            work_block="WB-001",
            input_refs=[],
            provider_policy_ref="policy-v1",
            project_binding=binding,
            created_by="researcher_a",
            created_at="2026-09-20T00:00:00Z",
            delegation_depth=0,
            parent_task_ref={"task_id": "forged-parent"},
        )
    assert "delegation_depth=0 cannot have parent_task_ref" in str(exc_info1.value)

    # depth=1 but lacks parent_task_ref -> FAIL
    with pytest.raises(PermissionDeniedError) as exc_info2:
        AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_scope=valid_scope,
            objective="Analyze factors",
            work_block="WB-001",
            input_refs=[],
            provider_policy_ref="policy-v1",
            project_binding=binding,
            created_by="researcher_a",
            created_at="2026-09-20T00:00:00Z",
            delegation_depth=1,
            parent_task_ref=None,
        )
    assert "must specify a valid parent_task_ref" in str(exc_info2.value)


# 22. [P1-3] select_agent() missing project_binding fails closed
def test_negative_22_select_agent_missing_project_binding_fails_closed() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    provider = DummyMockProvider(supported_roles=(AgentRole.ALPHA_GENERATOR.value,))
    scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )

    with pytest.raises(ProjectBindingError) as exc_info:
        select_agent(
            role=AgentRole.ALPHA_GENERATOR.value,
            providers=[provider],
            authorized_scope=scope,
            project_binding=None,  # Missing!
        )
    assert "ProjectBinding is required and cannot be None" in str(exc_info.value)


# 23. [P1-3] ProjectBinding placeholder and empty values rejected
def test_negative_23_project_binding_placeholder_and_empty_values_rejected() -> None:
    # 1. Unspecified or placeholder project_id
    with pytest.raises(ProjectBindingError) as exc1:
        ProjectBinding(project_id="unspecified", workspace_identity="/workspace/vnpy")
    assert "cannot be placeholder" in str(exc1.value)

    with pytest.raises(ProjectBindingError) as exc2:
        ProjectBinding(project_id="default", workspace_identity="/workspace/vnpy")
    assert "cannot be placeholder" in str(exc2.value)

    with pytest.raises(ProjectBindingError) as exc3:
        ProjectBinding(project_id="", workspace_identity="/workspace/vnpy")
    assert "non-empty string" in str(exc3.value)

    # 2. Unspecified or placeholder workspace_identity
    with pytest.raises(ProjectBindingError) as exc4:
        ProjectBinding(project_id="p1", workspace_identity="placeholder")
    assert "cannot be placeholder" in str(exc4.value)

    with pytest.raises(ProjectBindingError) as exc5:
        ProjectBinding(project_id="p1", workspace_identity="")
    assert "non-empty string" in str(exc5.value)

    # 3. Unsupported binding mode
    with pytest.raises(ProjectBindingError) as exc6:
        ProjectBinding(project_id="p1", workspace_identity="/workspace/vnpy", binding_mode="loose")
    assert "Unsupported binding_mode" in str(exc6.value)

    # 4. Dict with placeholder passed to select_agent
    provider = DummyMockProvider(supported_roles=(AgentRole.ALPHA_GENERATOR.value,))
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )
    with pytest.raises(ProjectBindingError):
        select_agent(
            role=AgentRole.ALPHA_GENERATOR.value,
            providers=[provider],
            authorized_scope=scope,
            project_binding={"project_id": "unspecified", "workspace_identity": "unspecified"},
        )


# 24. [P1-1] Scope mock string bypass strictly rejected with TamperDetectionError
def test_negative_24_scope_mock_string_bypass_strictly_rejected() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    fake_scope_str = "scope-mock-valid-ref-12345"

    # Attempting to pass a forged scope string to AgentTask.create
    with pytest.raises(TamperDetectionError) as exc_task_create:
        AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorization_scope_ref=fake_scope_str,  # Forged string!
            objective="Analyze factors",
            work_block="WB-001",
            input_refs=[],
            provider_policy_ref="policy-v1",
            project_binding=binding,
            created_by="attacker",
            created_at="2026-09-20T00:00:00Z",
        )
    assert "must be an exact verifiable scope dictionary" in str(exc_task_create.value)

    # Attempting to pass a forged scope string to AgentRoute.create
    with pytest.raises(TamperDetectionError) as exc_route_create:
        AgentRoute.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            provider="mock_p",
            resolved_model="m1",
            policy_version="v1",
            route_reason="reason",
            usage_snapshot_ref=None,
            project_binding=binding,
            authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorization_scope_ref=fake_scope_str,  # Forged string!
        )
    assert "must be an exact verifiable scope dictionary" in str(exc_route_create.value)


# Quota exhausted router rejection
def test_quota_exhausted_router_rejection() -> None:
    provider = DummyMockProvider(
        name="antigravity_limited",
        supported_roles=(AgentRole.ALPHA_GENERATOR.value,),
    )
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
    )
    exhausted_snapshot = AgentUsageSnapshot.create(
        provider="antigravity_limited",
        model_group="gemini-high",
        quota_windows=[
            {
                "window": "hourly",
                "remaining_fraction": 0,
                "reset_time": "2026-09-20T19:00:00Z",
                "status": "exhausted",
            },
        ],
        captured_at="2026-09-20T18:00:00Z",
    )
    with pytest.raises(ProviderUnavailableError) as exc_info:
        select_agent(
            role=AgentRole.ALPHA_GENERATOR.value,
            providers=[provider],
            authorized_scope=scope,
            project_binding=binding,
            usage_snapshots={"antigravity_limited": exhausted_snapshot},
        )
    assert "unavailable or quota exhausted" in str(exc_info.value)


# 25. [P1-1] Unauthorized scope (is_authorized=False) bypass strictly rejected
def test_negative_25_unauthorized_scope_bypass_strictly_rejected() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")

    # 1. AgentPermissionScope.create cannot carry authorized_permissions when is_authorized=False
    with pytest.raises(PermissionDeniedError) as exc_scope_create:
        AgentPermissionScope.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            project_binding=binding,
            is_authorized=False,
        )
    assert "is_authorized=False and non-empty authorized_permissions" in str(exc_scope_create.value)

    # 2. Direct constructor of AgentPermissionScope cannot carry authorized permissions when is_authorized=False
    with pytest.raises(PermissionDeniedError) as exc_scope_direct:
        AgentPermissionScope(
            scope_id="scope-mock-unauthorized",
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=(AgentPermission.CREATE_HYPOTHESIS.value,),
            authorized_permissions=(AgentPermission.CREATE_HYPOTHESIS.value,),
            denied_permissions=(),
            is_authorized=False,
            policy_version="2026-09-m0",
            project_binding=binding.to_dict(),
            scope_content_hash="mock-hash",
        )
    assert "cannot carry authorized permissions" in str(exc_scope_direct.value)

    # Create a legitimate unauthorized scope (all requested permissions denied)
    unauthorized_scope = AgentPermissionScope.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[],
        project_binding=binding,
        is_authorized=False,
    )
    assert unauthorized_scope.is_authorized is False
    assert len(unauthorized_scope.authorized_permissions) == 0

    # 3. AgentTask.create rejects unauthorized scope (both instance and dict)
    with pytest.raises(PermissionDeniedError) as exc_task_scope:
        AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[],
            authorized_scope=unauthorized_scope,
            objective="Analyze IC factors",
            work_block="WB-001",
            input_refs=[],
            provider_policy_ref="policy-v1",
            project_binding=binding,
            created_by="researcher_a",
            created_at="2026-09-20T00:00:00Z",
        )
    assert "unauthorized scope (is_authorized=False)" in str(exc_task_scope.value)

    with pytest.raises(PermissionDeniedError) as exc_task_ref:
        AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[],
            authorization_scope_ref=unauthorized_scope.to_dict(),
            objective="Analyze IC factors",
            work_block="WB-001",
            input_refs=[],
            provider_policy_ref="policy-v1",
            project_binding=binding,
            created_by="researcher_a",
            created_at="2026-09-20T00:00:00Z",
        )
    assert "unauthorized scope (is_authorized is not True)" in str(exc_task_ref.value)

    # 4. AgentRoute.create rejects unauthorized scope (both instance and dict)
    with pytest.raises(PermissionDeniedError) as exc_route_scope:
        AgentRoute.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            provider="mock_p",
            resolved_model="m1",
            policy_version="2026-09-m0",
            route_reason="reason",
            usage_snapshot_ref=None,
            project_binding=binding,
            authorized_permissions=[],
            authorized_scope=unauthorized_scope,
        )
    assert "unauthorized scope (is_authorized=False)" in str(exc_route_scope.value)

    with pytest.raises(PermissionDeniedError) as exc_route_ref:
        AgentRoute.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            provider="mock_p",
            resolved_model="m1",
            policy_version="2026-09-m0",
            route_reason="reason",
            usage_snapshot_ref=None,
            project_binding=binding,
            authorized_permissions=[],
            authorization_scope_ref=unauthorized_scope.to_dict(),
        )
    assert "unauthorized scope (is_authorized is not True)" in str(exc_route_ref.value)

    # 5. select_agent rejects unauthorized scope
    provider = DummyMockProvider(supported_roles=(AgentRole.ALPHA_GENERATOR.value,))
    with pytest.raises(PermissionDeniedError) as exc_select:
        select_agent(
            role=AgentRole.ALPHA_GENERATOR.value,
            providers=[provider],
            authorized_scope=unauthorized_scope,
            project_binding=binding,
        )
    assert "requires an authorized_scope with is_authorized=True" in str(exc_select.value)

    # 6. Direct constructor of AgentTask and AgentRoute enforces is_authorized=True
    with pytest.raises(PermissionDeniedError) as exc_task_direct:
        AgentTask(
            task_id="task-mock",
            authorization_scope_ref=unauthorized_scope.to_dict(),
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=(AgentPermission.CREATE_HYPOTHESIS.value,),
            authorized_permissions=(),
            objective="Analyze factors",
            work_block="WB-001",
            input_refs=(),
            provider_policy_ref="policy-v1",
            project_binding=binding.to_dict(),
            created_by="researcher_a",
            created_at="2026-09-20T00:00:00Z",
            task_content_hash="mock-hash",
        )
    assert "requires authorization_scope_ref with is_authorized=True" in str(exc_task_direct.value)

    with pytest.raises(PermissionDeniedError) as exc_route_direct:
        AgentRoute(
            route_id="route-mock",
            authorization_scope_ref=unauthorized_scope.to_dict(),
            role=AgentRole.ALPHA_GENERATOR.value,
            provider="mock_p",
            resolved_model="m1",
            policy_version="2026-09-m0",
            route_reason="reason",
            usage_snapshot_ref=None,
            project_binding=binding.to_dict(),
            authorized_permissions=(),
            route_content_hash="mock-hash",
        )
    assert "requires authorization_scope_ref with is_authorized=True" in str(exc_route_direct.value)


# 26. [P1-1] Deep immutability via MappingProxyType blocks in-place container mutation
def test_negative_26_deep_immutability_mapping_proxy_blocks_mutation() -> None:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    scope = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
        context={"experiment_tag": "exp-1"},
    )
    task = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope,
        objective="Analyze factors",
        work_block="WB-001",
        input_refs=[{"type": "spec", "id": "spec-1"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_a",
        created_at="2026-09-20T00:00:00Z",
    )
    provider = DummyMockProvider(supported_roles=(AgentRole.ALPHA_GENERATOR.value,))
    route = select_agent(
        role=AgentRole.ALPHA_GENERATOR.value,
        providers=[provider],
        authorized_scope=scope,
        project_binding=binding,
    )

    # 1. In-place modification of Scope internal containers raises TypeError
    with pytest.raises(TypeError):
        scope.project_binding["project_id"] = "hacked"  # type: ignore[index]
    with pytest.raises(TypeError):
        scope.context["experiment_tag"] = "hacked"  # type: ignore[index]

    # 2. In-place modification of Task internal containers raises TypeError
    with pytest.raises(TypeError):
        task.project_binding["project_id"] = "hacked"  # type: ignore[index]
    with pytest.raises(TypeError):
        task.authorization_scope_ref["role"] = "hacked"  # type: ignore[index]
    with pytest.raises(TypeError):
        task.input_refs[0]["id"] = "hacked"  # type: ignore[index]

    # 3. In-place modification of Route internal containers raises TypeError
    with pytest.raises(TypeError):
        route.project_binding["project_id"] = "hacked"  # type: ignore[index]
    with pytest.raises(TypeError):
        route.authorization_scope_ref["role"] = "hacked"  # type: ignore[index]

    # 4. Modifying the dictionary returned by to_dict() does not affect the contract instance
    scope_dict = scope.to_dict()
    scope_dict["project_binding"]["project_id"] = "tampered"
    assert scope.project_binding["project_id"] == "vnpy-p1"

    task_dict = task.to_dict()
    task_dict["project_binding"]["project_id"] = "tampered"
    task_dict["authorization_scope_ref"]["role"] = "tampered"
    assert task.project_binding["project_id"] == "vnpy-p1"
    assert task.authorization_scope_ref["role"] == AgentRole.ALPHA_GENERATOR.value

    route_dict = route.to_dict()
    route_dict["project_binding"]["project_id"] = "tampered"
    route_dict["authorization_scope_ref"]["role"] = "tampered"
    assert route.project_binding["project_id"] == "vnpy-p1"
    assert route.authorization_scope_ref["role"] == AgentRole.ALPHA_GENERATOR.value

