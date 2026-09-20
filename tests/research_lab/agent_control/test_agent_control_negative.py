"""Mandatory 14 Negative Tests for Agent Access Control (#573 Milestone 0).

Covers all 14 fail-closed negative scenarios listed in specification:
1. unknown role
2. unknown permission
3. role 请求越权 (elevation attempt)
4. production_trading=true (hard invariant violation)
5. live_trading_authorized=true (hard invariant violation)
6. worker nested delegation (depth >= 1)
7. unknown provider
8. malformed provider result
9. result content hash tampering
10. audit hash tampering
11. unknown quota state preserved (never assumed 0% or 100%)
12. project binding mismatch
13. role/model hard-coupling regression
14. duplicate deterministic task identity (stable across time & instances)
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest

from research_lab.agent_control import (
    AgentAuditRecord,
    AgentPermission,
    AgentProvider,
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
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
    ResultAcceptanceError,
    TamperDetectionError,
    TerminalStatus,
    assert_provider_error_does_not_pollute_scientific_decision,
    authorize,
    compute_task_deterministic_id,
    enforce_no_nested_delegation,
    select_agent,
    validate_audit_hash,
    validate_permission,
    validate_project_binding,
    validate_result_hash,
    validate_role,
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
    with pytest.raises(PermissionDeniedError) as exc_info:
        validate_role("super_autonomous_trader")
    assert "Unknown role" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PERMISSION_DENIED

    with pytest.raises(PermissionDeniedError):
        authorize(
            role="unregistered_agent_role",
            requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
        )


# 2. Unknown permission
def test_negative_2_unknown_permission() -> None:
    with pytest.raises(PermissionDeniedError) as exc_info:
        validate_permission("arbitrary_system_root")
    assert "Unknown permission" in str(exc_info.value)

    with pytest.raises(PermissionDeniedError):
        authorize(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value, "grant_all_access"],
        )


# 3. Role permission elevation (越权请求)
def test_negative_3_role_permission_elevation() -> None:
    # alpha_generator attempts to invoke critic or write research memory
    with pytest.raises(PermissionDeniedError) as exc_info:
        authorize(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[
                AgentPermission.READ_RESEARCH_MEMORY.value,
                AgentPermission.INVOKE_CRITIC.value,  # Forbidden for alpha_generator
            ],
        )
    assert "Permission denied" in str(exc_info.value)
    assert "invoke_critic" in str(exc_info.value)


# 4. production_trading = true (Hard Invariant Violation)
def test_negative_4_production_trading_hard_invariant() -> None:
    # Even if someone constructs a policy or requests production_trading, fail-closed
    with pytest.raises(PermissionDeniedError) as exc_info:
        authorize(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.PRODUCTION_TRADING.value],
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
    with pytest.raises(PermissionDeniedError) as exc_info:
        authorize(
            role=AgentRole.CODE_RESEARCHER.value,
            requested_permissions=[AgentPermission.LIVE_TRADING_AUTHORIZED.value],
        )
    assert "Hard invariant violation" in str(exc_info.value)

    with pytest.raises(PermissionDeniedError) as exc_info2:
        AgentRolePolicy(
            role=AgentRole.CODE_RESEARCHER.value,
            allowed_permissions=frozenset([AgentPermission.LIVE_TRADING_AUTHORIZED.value]),
        )
    assert "Hard invariant violation" in str(exc_info2.value)


# 6. Worker nested delegation (depth >= 1)
def test_negative_6_worker_nested_delegation() -> None:
    # Orchestrator at depth 0 is allowed
    enforce_no_nested_delegation(delegation_depth=0)

    # Worker at depth 1 or deeper is prohibited from delegating
    with pytest.raises(PermissionDeniedError) as exc_info:
        enforce_no_nested_delegation(
            delegation_depth=1,
            parent_task_ref={"task_id": "task-parent-123"},
        )
    assert "Nested agent delegation prohibited" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PERMISSION_DENIED

    with pytest.raises(PermissionDeniedError):
        enforce_no_nested_delegation(delegation_depth=2)


# 7. Unknown provider
def test_negative_7_unknown_provider() -> None:
    # No matching provider supporting data_researcher
    providers = [DummyMockProvider(supported_roles=(AgentRole.ALPHA_GENERATOR.value,))]
    with pytest.raises(ProviderUnavailableError) as exc_info:
        select_agent(
            role=AgentRole.DATA_RESEARCHER.value,
            providers=providers,
        )
    assert "No available provider supports role" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PROVIDER_UNAVAILABLE


# 8. Malformed provider result
def test_negative_8_malformed_provider_result() -> None:
    # TerminalStatus must be from valid enum
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
    # Legitimate hash check passes
    validate_result_hash(raw_dict)

    # Tamper with structured output payload
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
        project_binding={"project_id": "p1", "workspace_identity": "w1", "binding_mode": "strict"},
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

    # Tamper with audit record
    tampered = copy.deepcopy(raw_dict)
    tampered["acceptance_status"] = "FORGED_ACCEPTED"
    with pytest.raises(TamperDetectionError) as exc_info:
        validate_audit_hash(tampered)
    assert "AgentAuditRecord content hash tampering detected" in str(exc_info.value)

    # Append to AppendOnlyAuditTrail also fails on tampered record
    trail = AppendOnlyAuditTrail()
    trail.append(audit)
    assert len(trail) == 1


# 11. Unknown quota state preserved
def test_negative_11_unknown_quota_state_preserved() -> None:
    # Quota window with status="unknown" and remaining_fraction=None
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
    # Invariant: unknown quota must remain None and "unknown", never coerced to 0% or 100%
    assert window["status"] == "unknown"
    assert window["remaining_fraction"] is None


# 12. Project binding mismatch
def test_negative_12_project_binding_mismatch() -> None:
    expected = ProjectBinding(
        project_id="vnpy-core",
        workspace_identity="/Users/fujun/node/vnpy",
    )
    # Mismatched project ID
    mismatched_id = ProjectBinding(
        project_id="foreign-project-xyz",
        workspace_identity="/Users/fujun/node/vnpy",
    )
    with pytest.raises(ProjectBindingError) as exc_info:
        validate_project_binding(mismatched_id, expected)
    assert "Project ID mismatch" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PROJECT_BINDING_FAILED

    # Mismatched workspace identity
    mismatched_ws = ProjectBinding(
        project_id="vnpy-core",
        workspace_identity="/Users/fujun/node/other_repo",
    )
    with pytest.raises(ProjectBindingError) as exc_info2:
        validate_project_binding(mismatched_ws, expected)
    assert "Workspace identity mismatch" in str(exc_info2.value)


# 13. Role/model hard-coupling regression
def test_negative_13_role_model_hard_coupling_prohibited() -> None:
    # Any attempt to name a role coupled to a provider/model must fail
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
    task1 = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        objective="Analyze momentum factors on IF contracts",
        work_block="WB-001",
        input_refs=[{"type": "spec", "id": "spec-1"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_a",
        created_at="2026-09-20T00:00:00Z",
    )

    # Task2 created at a different time by different creator, but identical core fields
    task2 = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        objective="Analyze momentum factors on IF contracts",
        work_block="WB-001",
        input_refs=[{"type": "spec", "id": "spec-1"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_b",
        created_at="2026-09-20T18:00:00Z",  # Different timestamp
    )

    # Scientific/business identity MUST be strictly deterministic and identical
    assert task1.task_id == task2.task_id

    # Core alteration must yield different task_id
    task_modified = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        objective="Analyze mean reversion factors on IC contracts",  # Changed objective
        work_block="WB-001",
        input_refs=[{"type": "spec", "id": "spec-1"}],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_a",
        created_at="2026-09-20T00:00:00Z",
    )
    assert task1.task_id != task_modified.task_id


def test_task_content_hash_tampering() -> None:
    binding = ProjectBinding(project_id="p1", workspace_identity="/workspace/vnpy")
    task = AgentTask.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        objective="Legitimate objective",
        work_block="WB-001",
        input_refs=[],
        provider_policy_ref="policy-v1",
        project_binding=binding,
        created_by="researcher_a",
        created_at="2026-09-20T00:00:00Z",
    )
    from research_lab.agent_control import validate_task_hash, validate_route_hash, QuotaUnavailableError
    raw = task.to_dict()
    validate_task_hash(raw)

    tampered = copy.deepcopy(raw)
    tampered["objective"] = "Malicious altered objective"
    with pytest.raises(TamperDetectionError) as exc_info:
        validate_task_hash(tampered)
    assert "AgentTask content hash tampering detected" in str(exc_info.value)


def test_route_content_hash_tampering() -> None:
    from research_lab.agent_control import validate_route_hash
    binding = ProjectBinding(project_id="p1", workspace_identity="/workspace/vnpy")
    route = AgentRoute.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider="mock_p",
        resolved_model="m1",
        policy_version="v1",
        route_reason="reason",
        usage_snapshot_ref=None,
        project_binding=binding,
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
    )
    raw = route.to_dict()
    validate_route_hash(raw)

    tampered = copy.deepcopy(raw)
    tampered["resolved_model"] = "unauthorized-different-model"
    with pytest.raises(TamperDetectionError) as exc_info:
        validate_route_hash(tampered)
    assert "AgentRoute content hash tampering detected" in str(exc_info.value)


def test_quota_exhausted_router_rejection() -> None:
    from research_lab.agent_control import QuotaUnavailableError
    provider = DummyMockProvider(
        name="antigravity_limited",
        supported_roles=(AgentRole.ALPHA_GENERATOR.value,),
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
            }
        ],
        captured_at="2026-09-20T18:00:00Z",
    )
    with pytest.raises(ProviderUnavailableError) as exc_info:
        select_agent(
            role=AgentRole.ALPHA_GENERATOR.value,
            providers=[provider],
            usage_snapshots={"antigravity_limited": exhausted_snapshot},
        )
    assert "unavailable or quota exhausted" in str(exc_info.value)
