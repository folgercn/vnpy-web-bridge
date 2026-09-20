"""Comprehensive Milestone 1 Test Suite (#573 Milestone 1).

Covers all 35 minimum required verification test cases:
1. duplicate provider registration
2. malformed provider descriptor
3. default_model not in supported_models
4. unsupported role
5. unknown transport
6. transport not allowed by policy
7. required capability missing
8. primary unavailable -> secondary
9. primary quota exhausted -> secondary
10. all quota exhausted -> QUOTA_UNAVAILABLE
11. availability UNKNOWN fail closed
12. quota UNKNOWN conservative
13. missing usage policy path explicit
14. unsupported preferred model
15. preferred provider unavailable
16. override cannot bypass policy
17. exact usage ref tampering
18. authorization scope tampering
19. Task/Route scope mismatch
20. ProjectBinding mismatch
21. role mismatch
22. least privilege preserved
23. Provider cannot elevate permissions
24. route deterministic repeat
25. availability state change -> route identity change
26. transport change -> route identity change
27. model change -> route identity change
28. handoff rejects unsupported model
29. handoff rejects unregistered provider
30. handoff rejects transport mismatch
31. worker executes own task successfully
32. worker attempts child delegation -> denied
33. candidate trace complete
34. Provider/Transport/Model provenance complete
35. Alpha Discovery domain contains no transport-specific logic
"""

from __future__ import annotations

from typing import Any

import pytest

from research_lab.agent_control import (
    AgentPermission,
    AgentPermissionScope,
    AgentProviderDescriptor,
    AgentRole,
    AgentRoute,
    AgentTask,
    AgentUsageSnapshot,
    ExecutionPreparation,
    PermissionDeniedError,
    ProjectBinding,
    ProviderAvailability,
    ProviderConnectionDescriptor,
    ProviderError,
    ProviderErrorCode,
    ProviderRegistry,
    ProviderTransportKind,
    ProviderUnavailableError,
    QuotaUnavailableError,
    RouteReasonCode,
    RoutingContext,
    RoutingPolicy,
    TamperDetectionError,
    authorize,
    enforce_no_nested_delegation,
    prepare_execution,
    select_agent,
    validate_preparation_hash,
)


class MockProvider:
    """Configurable mock provider for Milestone 1 router tests."""

    def __init__(
        self,
        name: str = "mock_provider",
        supported_roles: tuple[str, ...] = (AgentRole.ALPHA_GENERATOR.value,),
        supported_models: tuple[str, ...] = ("mock-model-v1", "mock-model-v2"),
        capabilities: tuple[str, ...] = ("text_generation",),
        default_model: str = "mock-model-v1",
        is_available: bool = True,
        availability_status: str = "AVAILABLE",
        availability_reason: str = "",
        transport_descriptor: ProviderConnectionDescriptor | None = None,
    ) -> None:
        self.name = name
        self.supported_roles = supported_roles
        self.supported_models = supported_models
        self.capabilities = capabilities
        if default_model == "mock-model-v1" and "mock-model-v1" not in supported_models and supported_models:
            self.default_model = supported_models[0]
        else:
            self.default_model = default_model
        self.is_available = is_available
        self.availability_status = availability_status
        self.availability_reason = availability_reason
        self.transport_descriptor = transport_descriptor or ProviderConnectionDescriptor(
            transport_kind=ProviderTransportKind.LOCAL_MCP,
            connection_profile_ref=f"{name}-local-profile",
            capabilities=capabilities,
        )

    def describe(self) -> AgentProviderDescriptor:
        return AgentProviderDescriptor(
            provider=self.name,
            supported_roles=self.supported_roles,
            supported_models=self.supported_models,
            capabilities=self.capabilities,
            default_model=self.default_model,
        )

    def describe_transport(self) -> ProviderConnectionDescriptor:
        return self.transport_descriptor

    def availability(self, role: str, context: dict | None = None) -> ProviderAvailability:
        return ProviderAvailability(
            is_available=self.is_available,
            status=self.availability_status,
            reason=self.availability_reason,
        )

    def submit(self, task: AgentTask, route: AgentRoute) -> Any:
        raise NotImplementedError("Milestone 1 does NOT call provider.submit()")

    def status(self, handle: Any) -> str:
        return "UNKNOWN"

    def result(self, handle: Any) -> Any:
        raise NotImplementedError()

    def cancel(self, handle: Any) -> bool:
        return False


def _create_test_scope(
    role: str = AgentRole.ALPHA_GENERATOR.value,
    permissions: list[str] | None = None,
    project_id: str = "vnpy-p1",
) -> AgentPermissionScope:
    binding = ProjectBinding(project_id=project_id, workspace_identity="/workspace/vnpy")
    perms = permissions or [AgentPermission.CREATE_HYPOTHESIS.value]
    return authorize(role=role, requested_permissions=perms, project_binding=binding)


def _create_test_task(
    scope: AgentPermissionScope,
    role: str = AgentRole.ALPHA_GENERATOR.value,
    permissions: list[str] | None = None,
    delegation_depth: int = 0,
    parent_task_ref: dict[str, str] | None = None,
) -> AgentTask:
    binding = ProjectBinding(
        project_id=scope.project_binding["project_id"],
        workspace_identity=scope.project_binding["workspace_identity"],
    )
    perms = permissions or list(scope.authorized_permissions)
    return AgentTask.create(
        role=role,
        requested_permissions=perms,
        authorized_permissions=perms,
        authorized_scope=scope,
        objective="Analyze market alpha factors",
        work_block="wb-m1-001",
        input_refs=[{"type": "spec", "ref": "spec-01"}],
        provider_policy_ref="policy-m1-v1",
        project_binding=binding,
        delegation_depth=delegation_depth,
        parent_task_ref=parent_task_ref,
        created_by="researcher",
        created_at="2026-09-20T00:00:00Z",
    )


# 1. duplicate provider registration
def test_01_duplicate_provider_registration() -> None:
    registry = ProviderRegistry()
    prov1 = MockProvider(name="provider_a")
    registry.register(prov1)
    assert len(registry) == 1

    prov1_dup = MockProvider(name="provider_a")
    with pytest.raises(ProviderError) as exc_info:
        registry.register(prov1_dup)
    assert "Duplicate provider registration rejected" in str(exc_info.value)
    assert exc_info.value.code == ProviderErrorCode.PROVIDER_UNAVAILABLE


# 2. malformed provider descriptor
def test_02_malformed_provider_descriptor() -> None:
    registry = ProviderRegistry()

    # Provider name is empty
    class EmptyNameProvider(MockProvider):
        def describe(self) -> AgentProviderDescriptor:
            return AgentProviderDescriptor(
                provider="   ",
                supported_roles=(AgentRole.ALPHA_GENERATOR.value,),
                supported_models=("m1",),
                capabilities=("text_generation",),
                default_model="m1",
            )

    with pytest.raises(ProviderError) as exc1:
        registry.register(EmptyNameProvider())
    assert "Provider name must be a non-empty string" in str(exc1.value)

    # supported_models is empty
    class EmptyModelsProvider(MockProvider):
        def describe(self) -> AgentProviderDescriptor:
            return AgentProviderDescriptor(
                provider="no_models",
                supported_roles=(AgentRole.ALPHA_GENERATOR.value,),
                supported_models=(),
                capabilities=("text_generation",),
                default_model="",
            )

    with pytest.raises(ProviderError) as exc2:
        registry.register(EmptyModelsProvider())
    assert "empty supported_models" in str(exc2.value)


# 3. default_model not in supported_models
def test_03_default_model_not_in_supported_models() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(
        name="invalid_model_prov",
        supported_models=("model-a", "model-b"),
        default_model="model-c",  # Not in supported_models
    )
    with pytest.raises(ProviderError) as exc:
        registry.register(prov)
    assert "default_model 'model-c' is not in supported_models" in str(exc.value)


# 4. unsupported role
def test_04_unsupported_role() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(
        name="alien_role_prov",
        supported_roles=("unsupported_alien_role",),
    )
    with pytest.raises(PermissionDeniedError) as exc:
        registry.register(prov)
    assert "Unknown role" in str(exc.value)


# 5. unknown transport
def test_05_unknown_transport() -> None:
    # 1. Invalid transport kind
    with pytest.raises(ProviderError) as exc1:
        ProviderConnectionDescriptor(
            transport_kind="alien_socket",
            connection_profile_ref="prof-01",
        )
    assert "Unknown or unsupported transport kind" in str(exc1.value)

    # 2. Sensitive endpoint leakage rejected
    with pytest.raises(ProviderError) as exc2:
        ProviderConnectionDescriptor(
            transport_kind=ProviderTransportKind.REMOTE_MCP,
            connection_profile_ref="https://api.remote.com/endpoint?token=secret123",
        )
    assert "sensitive pattern" in str(exc2.value)


# 6. transport not allowed by policy
def test_06_transport_not_allowed_by_policy() -> None:
    registry = ProviderRegistry()
    remote_transport = ProviderConnectionDescriptor(
        transport_kind=ProviderTransportKind.REMOTE_MCP,
        connection_profile_ref="remote-alpha-profile",
    )
    prov = MockProvider(name="remote_prov", transport_descriptor=remote_transport)
    registry.register(prov, remote_transport)

    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("remote_prov",),
        allowed_transports=("local_mcp",),  # remote_mcp NOT allowed
    )

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
    )

    with pytest.raises(ProviderUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "unavailable or quota exhausted" in str(exc.value)


# 7. required capability missing
def test_07_required_capability_missing() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="simple_prov", capabilities=("text_generation",))
    registry.register(prov)

    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("simple_prov",),
        required_capabilities=("external_web_search",),  # missing!
    )

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
    )

    with pytest.raises(ProviderUnavailableError):
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)


# 8. primary unavailable -> secondary
def test_08_primary_unavailable_fallback_to_secondary() -> None:
    registry = ProviderRegistry()
    p1 = MockProvider(name="prov_primary", is_available=False, availability_status="UNAVAILABLE", availability_reason="service maintenance")
    p2 = MockProvider(name="prov_secondary", is_available=True, availability_status="AVAILABLE")
    registry.register(p1)
    registry.register(p2)

    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("prov_primary", "prov_secondary"),
    )
    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)

    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.provider == "prov_secondary"
    assert route.route_reason_code == RouteReasonCode.PRIMARY_UNAVAILABLE_FALLBACK.value


# 9. primary quota exhausted -> secondary
def test_09_primary_quota_exhausted_fallback_to_secondary() -> None:
    registry = ProviderRegistry()
    p1 = MockProvider(name="prov_quota_exhausted")
    p2 = MockProvider(name="prov_healthy")
    registry.register(p1)
    registry.register(p2)

    snap_exhausted = AgentUsageSnapshot.create(
        provider="prov_quota_exhausted",
        model_group="g1",
        quota_windows=[{"status": "exhausted", "remaining_fraction": 0}],
        captured_at="2026-09-20T00:00:00Z",
    )
    snap_healthy = AgentUsageSnapshot.create(
        provider="prov_healthy",
        model_group="g1",
        quota_windows=[{"status": "healthy", "remaining_fraction": 0.8}],
        captured_at="2026-09-20T00:00:00Z",
    )

    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("prov_quota_exhausted", "prov_healthy"),
    )
    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
        usage_snapshots={"prov_quota_exhausted": snap_exhausted, "prov_healthy": snap_healthy},
    )

    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.provider == "prov_healthy"
    assert route.route_reason_code == RouteReasonCode.PRIMARY_QUOTA_EXHAUSTED.value


# 10. all quota exhausted -> QUOTA_UNAVAILABLE
def test_10_all_quota_exhausted_raises_quota_unavailable() -> None:
    registry = ProviderRegistry()
    p1 = MockProvider(name="prov_a")
    p2 = MockProvider(name="prov_b")
    registry.register(p1)
    registry.register(p2)

    snap_a = AgentUsageSnapshot.create(
        provider="prov_a",
        model_group="g1",
        quota_windows=[{"status": "exhausted", "remaining_fraction": 0}],
        captured_at="2026-09-20T00:00:00Z",
    )
    snap_b = AgentUsageSnapshot.create(
        provider="prov_b",
        model_group="g1",
        quota_windows=[{"status": "exhausted", "remaining_fraction": 0}],
        captured_at="2026-09-20T00:00:00Z",
    )

    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("prov_a", "prov_b"),
    )
    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
        usage_snapshots={"prov_a": snap_a, "prov_b": snap_b},
    )

    with pytest.raises(QuotaUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert exc.value.code == ProviderErrorCode.QUOTA_UNAVAILABLE
    assert "quota exhausted" in str(exc.value)


# 11. availability UNKNOWN fail closed
def test_11_availability_unknown_fails_closed() -> None:
    # 1. Conflict in ProviderAvailability rejected
    with pytest.raises(ProviderError) as exc1:
        ProviderAvailability(is_available=True, status="UNKNOWN")
    assert "Inconsistent ProviderAvailability" in str(exc1.value)

    # 2. Conservative unknown status fails closed in router
    registry = ProviderRegistry()
    p = MockProvider(name="prov_unknown", is_available=False, availability_status="UNKNOWN")
    registry.register(p)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("prov_unknown",))
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)

    with pytest.raises(ProviderUnavailableError):
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)


# 12. quota UNKNOWN conservative
def test_12_quota_unknown_conservative() -> None:
    registry = ProviderRegistry()
    p = MockProvider(name="prov_unknown_quota")
    registry.register(p)

    snap = AgentUsageSnapshot.create(
        provider="prov_unknown_quota",
        model_group="g1",
        quota_windows=[{"status": "unknown", "remaining_fraction": None}],
        captured_at="2026-09-20T00:00:00Z",
    )

    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("prov_unknown_quota",),
        allow_unknown_quota_fallback=False,  # default conservative
    )
    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
        usage_snapshots={"prov_unknown_quota": snap},
    )

    with pytest.raises(ProviderUnavailableError):
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)


# 13. missing usage policy path explicit
def test_13_missing_usage_policy_path_explicit() -> None:
    registry = ProviderRegistry()
    p = MockProvider(name="prov_no_snap")
    registry.register(p)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding, usage_snapshots={})

    # Path 1: policy rejects missing usage
    strict_policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("prov_no_snap",), allow_missing_usage=False)
    with pytest.raises(ProviderUnavailableError):
        select_agent(registry=registry, routing_policy=strict_policy, routing_context=ctx)

    # Path 2: policy explicitly permits missing usage
    permissive_policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("prov_no_snap",), allow_missing_usage=True)
    route = select_agent(registry=registry, routing_policy=permissive_policy, routing_context=ctx)
    assert route.provider == "prov_no_snap"
    assert route.usage_snapshot_ref is None


# 14. unsupported preferred model
def test_14_unsupported_preferred_model() -> None:
    registry = ProviderRegistry()
    p = MockProvider(name="prov_m", supported_models=("model-1", "model-2"))
    registry.register(p)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("prov_m",))
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
        preferred_model="unsupported-model-999",  # Unsupported!
    )

    with pytest.raises(ProviderUnavailableError):
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)


# 15. preferred provider unavailable
def test_15_preferred_provider_unavailable() -> None:
    registry = ProviderRegistry()
    p1 = MockProvider(name="prov_primary", is_available=True)
    p2 = MockProvider(name="prov_pref", is_available=False, availability_status="UNAVAILABLE")
    registry.register(p1)
    registry.register(p2)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("prov_primary", "prov_pref"))
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
        preferred_provider="prov_pref",  # Offline
    )

    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    # Successfully falls back to prov_primary
    assert route.provider == "prov_primary"


# 16. override cannot bypass policy
def test_16_override_cannot_bypass_policy() -> None:
    registry = ProviderRegistry()
    remote_transport = ProviderConnectionDescriptor(
        transport_kind=ProviderTransportKind.REMOTE_MCP,
        connection_profile_ref="remote-profile",
    )
    p = MockProvider(name="prov_remote", transport_descriptor=remote_transport)
    registry.register(p, remote_transport)

    # Policy explicitly forbids remote_mcp
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("prov_remote",),
        allowed_transports=("local_mcp",),
    )
    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    # Caller attempts to force preferred_provider="prov_remote"
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
        preferred_provider="prov_remote",
    )

    with pytest.raises(ProviderUnavailableError):
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)


# 17. exact usage ref tampering
def test_17_exact_usage_ref_tampering() -> None:
    registry = ProviderRegistry()
    p = MockProvider(name="prov_tamper")
    registry.register(p)

    snap = AgentUsageSnapshot.create(
        provider="prov_tamper",
        model_group="g1",
        quota_windows=[{"status": "healthy", "remaining_fraction": 0.5}],
        captured_at="2026-09-20T00:00:00Z",
    )
    # Tamper with snapshot content without recalculating hash
    tampered_dict = snap.to_dict()
    tampered_dict["quota_windows"] = [{"status": "exhausted", "remaining_fraction": 0}]

    with pytest.raises(TamperDetectionError) as exc:
        AgentUsageSnapshot(
            snapshot_id=tampered_dict["snapshot_id"],
            provider=tampered_dict["provider"],
            model_group=tampered_dict["model_group"],
            quota_windows=tuple(tampered_dict["quota_windows"]),
            captured_at=tampered_dict["captured_at"],
            usage_content_hash=tampered_dict["usage_content_hash"],
        )
    assert "tampering detected" in str(exc.value)


# 18. authorization scope tampering
def test_18_authorization_scope_tampering() -> None:
    scope = _create_test_scope()
    scope_dict = scope.to_dict()
    # Tamper scope content hash
    scope_dict["scope_content_hash"] = "0" * 64

    with pytest.raises(TamperDetectionError):
        AgentPermissionScope(
            scope_id=scope_dict["scope_id"],
            role=scope_dict["role"],
            requested_permissions=tuple(scope_dict["requested_permissions"]),
            authorized_permissions=tuple(scope_dict["authorized_permissions"]),
            denied_permissions=tuple(scope_dict["denied_permissions"]),
            project_binding=scope_dict["project_binding"],
            is_authorized=scope_dict["is_authorized"],
            policy_version=scope_dict["policy_version"],
            context=scope_dict["context"],
            scope_content_hash=scope_dict["scope_content_hash"],
        )


# 19. Task/Route scope mismatch
def test_19_task_route_scope_mismatch() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_test")
    registry.register(prov)

    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    scope1 = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
        context={"instance": 1},
    )
    scope2 = authorize(
        role=AgentRole.ALPHA_GENERATOR.value,
        requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        project_binding=binding,
        context={"instance": 2},
    )
    task = _create_test_task(scope1)

    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope2, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)

    # Hand off task (bound to scope1) with route (bound to scope2)
    with pytest.raises(TamperDetectionError) as exc:
        prepare_execution(task=task, route=route, registry=registry)
    assert "Task and Route authorization_scope_ref mismatch" in str(exc.value)


# 20. ProjectBinding mismatch
def test_20_project_binding_mismatch() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_test")
    registry.register(prov)

    scope1 = _create_test_scope(project_id="vnpy-p1")
    task = _create_test_task(scope1)

    # Route created under a different project
    scope2 = _create_test_scope(project_id="vnpy-p2")
    binding2 = ProjectBinding(project_id="vnpy-p2", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope2, project_binding=binding2)
    route = select_agent(registry=registry, routing_context=ctx)

    with pytest.raises(TamperDetectionError):  # Scope mismatch first
        prepare_execution(task=task, route=route, registry=registry)


# 21. role mismatch
def test_21_role_mismatch() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(
        name="prov_test",
        supported_roles=(AgentRole.ALPHA_GENERATOR.value, AgentRole.DATA_RESEARCHER.value),
    )
    registry.register(prov)

    scope_alpha = _create_test_scope(role=AgentRole.ALPHA_GENERATOR.value, permissions=[AgentPermission.CREATE_HYPOTHESIS.value])
    task = _create_test_task(scope_alpha)

    scope_data = _create_test_scope(role=AgentRole.DATA_RESEARCHER.value, permissions=[AgentPermission.READ_RESEARCH_MEMORY.value])
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.DATA_RESEARCHER.value, authorized_scope=scope_data, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)

    with pytest.raises((PermissionDeniedError, TamperDetectionError)):
        prepare_execution(task=task, route=route, registry=registry)


# 22. least privilege preserved
def test_22_least_privilege_preserved() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_least")
    registry.register(prov)

    # Scope only requests CREATE_HYPOTHESIS
    scope = _create_test_scope(permissions=[AgentPermission.CREATE_HYPOTHESIS.value])
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)

    # Route must strictly carry ONLY CREATE_HYPOTHESIS, not full role policy
    assert route.authorized_permissions == (AgentPermission.CREATE_HYPOTHESIS.value,)

    task = _create_test_task(scope)
    prep = prepare_execution(task=task, route=route, registry=registry)
    assert prep.authorized_permissions == (AgentPermission.CREATE_HYPOTHESIS.value,)


# 23. Provider cannot elevate permissions
def test_23_provider_cannot_elevate_permissions() -> None:
    registry = ProviderRegistry()
    # Provider declares capabilities and claims
    prov = MockProvider(name="all_powerful_prov", capabilities=("admin", "root", "execute_trades"))
    registry.register(prov)

    scope = _create_test_scope(permissions=[AgentPermission.CREATE_HYPOTHESIS.value])
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)

    # No permission elevation occurred
    assert set(route.authorized_permissions) == {AgentPermission.CREATE_HYPOTHESIS.value}
    assert "execute_trades" not in route.authorized_permissions


# 24. route deterministic repeat
def test_24_route_deterministic_repeat() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_det")
    registry.register(prov)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)

    route1 = select_agent(registry=registry, routing_context=ctx)
    route2 = select_agent(registry=registry, routing_context=ctx)

    assert route1.route_id == route2.route_id
    assert route1.route_content_hash == route2.route_content_hash


# 25. availability state change -> route identity change
def test_25_availability_state_change_route_identity_change() -> None:
    registry = ProviderRegistry()
    p1 = MockProvider(name="p1", is_available=True)
    p2 = MockProvider(name="p2", is_available=True)
    registry.register(p1)
    registry.register(p2)

    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("p1", "p2"))
    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)

    # Run 1: p1 is available
    route1 = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route1.provider == "p1"

    # Run 2: p1 becomes unavailable -> route selects p2
    registry2 = ProviderRegistry()
    p1_down = MockProvider(name="p1", is_available=False, availability_status="UNAVAILABLE")
    registry2.register(p1_down)
    registry2.register(p2)

    route2 = select_agent(registry=registry2, routing_policy=policy, routing_context=ctx)
    assert route2.provider == "p2"
    assert route1.route_id != route2.route_id


# 26. transport change -> route identity change
def test_26_transport_change_route_identity_change() -> None:
    reg1 = ProviderRegistry()
    t1 = ProviderConnectionDescriptor(transport_kind=ProviderTransportKind.LOCAL_MCP, connection_profile_ref="prof-local")
    p1 = MockProvider(name="prov_t", transport_descriptor=t1)
    reg1.register(p1, t1)

    reg2 = ProviderRegistry()
    t2 = ProviderConnectionDescriptor(transport_kind=ProviderTransportKind.REMOTE_MCP, connection_profile_ref="prof-remote")
    p2 = MockProvider(name="prov_t", transport_descriptor=t2)
    reg2.register(p2, t2)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)

    route1 = select_agent(registry=reg1, routing_context=ctx)
    route2 = select_agent(registry=reg2, routing_context=ctx)

    assert route1.route_id != route2.route_id


# 27. model change -> route identity change
def test_27_model_change_route_identity_change() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_model", supported_models=("model-1", "model-2"))
    registry.register(prov)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")

    ctx1 = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding, preferred_model="model-1")
    ctx2 = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding, preferred_model="model-2")

    route1 = select_agent(registry=registry, routing_context=ctx1)
    route2 = select_agent(registry=registry, routing_context=ctx2)

    assert route1.resolved_model == "model-1"
    assert route2.resolved_model == "model-2"
    assert route1.route_id != route2.route_id


# 28. handoff rejects unsupported model
def test_28_handoff_rejects_unsupported_model() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_test", supported_models=("model-1",))
    registry.register(prov)

    scope = _create_test_scope()
    task = _create_test_task(scope)
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")

    # Construct route with illegal model
    route = AgentRoute.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider="prov_test",
        resolved_model="unsupported-alien-model",
        policy_version="v1",
        route_reason="manual test",
        usage_snapshot_ref=None,
        project_binding=binding,
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope,
    )

    with pytest.raises(ProviderUnavailableError) as exc:
        prepare_execution(task=task, route=route, registry=registry)
    assert "not in supported_models" in str(exc.value)


# 29. handoff rejects unregistered provider
def test_29_handoff_rejects_unregistered_provider() -> None:
    registry = ProviderRegistry()
    scope = _create_test_scope()
    task = _create_test_task(scope)
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")

    route = AgentRoute.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider="ghost_provider",
        resolved_model="mock-model",
        policy_version="v1",
        route_reason="test",
        usage_snapshot_ref=None,
        project_binding=binding,
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope,
    )

    with pytest.raises(ProviderUnavailableError) as exc:
        prepare_execution(task=task, route=route, registry=registry)
    assert "not registered in ProviderRegistry" in str(exc.value)


# 30. handoff rejects transport mismatch
def test_30_handoff_rejects_transport_mismatch() -> None:
    registry = ProviderRegistry()
    transport = ProviderConnectionDescriptor(transport_kind=ProviderTransportKind.LOCAL_MCP, connection_profile_ref="registered-profile")
    prov = MockProvider(name="prov_t", transport_descriptor=transport)
    registry.register(prov, transport)

    scope = _create_test_scope()
    task = _create_test_task(scope)
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")

    # Route created claiming a different transport profile
    route = AgentRoute.create(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider="prov_t",
        resolved_model="mock-model-v1",
        policy_version="v1",
        route_reason="test",
        usage_snapshot_ref=None,
        project_binding=binding,
        authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
        authorized_scope=scope,
        transport_ref="different-tampered-profile",
    )

    with pytest.raises(ProviderError) as exc:
        prepare_execution(task=task, route=route, registry=registry)
    assert "does not match registered transport" in str(exc.value)


# 31. worker executes own task successfully
def test_31_worker_executes_own_task_successfully() -> None:
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_worker")
    registry.register(prov)

    scope = _create_test_scope()
    task = _create_test_task(scope, delegation_depth=0)
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)

    # Worker executing own task passes handoff boundary without delegation error
    prep = prepare_execution(task=task, route=route, registry=registry)
    assert isinstance(prep, ExecutionPreparation)
    validate_preparation_hash(prep.to_dict())
    assert prep.task_id == task.task_id
    assert prep.route_id == route.route_id


# 32. worker attempts child delegation -> denied
def test_32_worker_attempts_child_delegation_denied() -> None:
    scope = _create_test_scope()
    parent_task = _create_test_task(scope, delegation_depth=0)

    # Worker role attempting to spawn a child task at depth >= 1
    with pytest.raises(PermissionDeniedError) as exc:
        enforce_no_nested_delegation(
            role=AgentRole.ALPHA_GENERATOR.value,
            delegation_depth=1,
            parent_task_ref={"task_id": parent_task.task_id},
        )
    assert "Nested agent delegation prohibited" in str(exc.value)


# 33. candidate trace complete
def test_33_candidate_trace_complete() -> None:
    registry = ProviderRegistry()
    p1 = MockProvider(name="candidate_1", is_available=False, availability_status="UNAVAILABLE", availability_reason="offline")
    p2 = MockProvider(name="candidate_2", is_available=True, availability_status="AVAILABLE")
    registry.register(p1)
    registry.register(p2)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)

    trace = route.candidate_trace
    assert len(trace) == 2
    # Candidate 1 trace
    assert trace[0]["provider"] == "candidate_1"
    assert trace[0]["decision"] == "skipped"
    assert trace[0]["availability"] == "UNAVAILABLE"
    # Candidate 2 trace
    assert trace[1]["provider"] == "candidate_2"
    assert trace[1]["decision"] == "selected"
    assert trace[1]["availability"] == "AVAILABLE"
    assert trace[1]["role_supported"] is True


# 34. Provider/Transport/Model provenance complete
def test_34_provider_transport_model_provenance_complete() -> None:
    registry = ProviderRegistry()
    transport = ProviderConnectionDescriptor(
        transport_kind=ProviderTransportKind.LOCAL_MCP,
        connection_profile_ref="auditable-local-profile",
        capabilities=("text_generation",),
    )
    prov = MockProvider(name="prov_provenance", transport_descriptor=transport)
    registry.register(prov, transport)

    scope = _create_test_scope()
    task = _create_test_task(scope)
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)

    prep = prepare_execution(task=task, route=route, registry=registry)

    # Full provenance verified
    assert prep.provider == "prov_provenance"
    assert prep.model == "mock-model-v1"
    assert prep.transport.transport_kind == ProviderTransportKind.LOCAL_MCP.value
    assert prep.transport.connection_profile_ref == "auditable-local-profile"
    assert prep.task_ref["task_id"] == task.task_id
    assert prep.route_ref["route_id"] == route.route_id
    assert prep.project_binding["project_id"] == "vnpy-p1"


# 35. Alpha Discovery domain contains no transport-specific logic
def test_35_alpha_discovery_domain_contains_no_transport_specific_logic() -> None:
    import inspect

    import research_lab.agent_control as ac

    # Ensure no transport specific concrete keywords leak into contracts / access control
    forbidden_tokens = ["mcp__antigravity__", "gemini-3.8-flash-high", "account_usage", "watch", "desktop session"]
    source = inspect.getsource(ac.contracts) + inspect.getsource(ac.permissions) + inspect.getsource(ac.roles)
    for token in forbidden_tokens:
        assert token not in source, f"Forbidden concrete transport token '{token}' leaked into core contracts"


# 36. [Review Remediation - ISSUE-01] RATE_LIMITED status triggers QuotaUnavailableError and PRIMARY_QUOTA_EXHAUSTED
def test_36_review_remediation_rate_limited_triggers_quota_unavailable() -> None:
    registry = ProviderRegistry()
    prov_primary = MockProvider(
        name="prov_primary",
        is_available=False,
        availability_status="RATE_LIMITED",
        availability_reason="TPM quota exceeded",
    )
    registry.register(prov_primary)

    scope = _create_test_scope()
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=binding,
    )
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("prov_primary",),
    )

    # All providers rate limited -> QuotaUnavailableError (NOT ProviderUnavailableError)
    with pytest.raises(QuotaUnavailableError) as exc_quota:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "quota exhausted or rate limited" in str(exc_quota.value)

    # Fallback to secondary provider when primary is RATE_LIMITED -> PRIMARY_QUOTA_EXHAUSTED reason code
    prov_secondary = MockProvider(name="prov_secondary", is_available=True)
    registry2 = ProviderRegistry()
    registry2.register(prov_primary)
    registry2.register(prov_secondary)
    policy2 = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("prov_primary", "prov_secondary"),
    )
    route = select_agent(registry=registry2, routing_policy=policy2, routing_context=ctx)
    assert route.provider == "prov_secondary"
    assert route.route_reason_code == RouteReasonCode.PRIMARY_QUOTA_EXHAUSTED


# 37. [Review Remediation - ISSUE-02] Deterministic ID tamper detection across Task, Route, and ExecutionPreparation
def test_37_review_remediation_deterministic_id_tamper_detection() -> None:
    from research_lab.agent_control.contracts import (
        compute_route_content_hash,
        compute_task_content_hash,
    )
    from research_lab.agent_control.handoff import compute_preparation_content_hash

    scope = _create_test_scope()
    task = _create_test_task(scope)
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    registry = ProviderRegistry()
    prov = MockProvider(name="prov_det_test")
    registry.register(prov)
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=binding)
    route = select_agent(registry=registry, routing_context=ctx)
    prep = prepare_execution(task=task, route=route, registry=registry)

    # 1. AgentTask forged task_id rejected
    raw_task = task.to_dict()
    raw_task["task_id"] = "task-forged000000000000000000000000"
    raw_task["task_content_hash"] = compute_task_content_hash(raw_task)
    with pytest.raises(TamperDetectionError) as exc_task:
        AgentTask(
            task_id=raw_task["task_id"],
            authorization_scope_ref=raw_task["authorization_scope_ref"],
            role=raw_task["role"],
            requested_permissions=tuple(raw_task["requested_permissions"]),
            authorized_permissions=tuple(raw_task["authorized_permissions"]),
            objective=raw_task["objective"],
            work_block=raw_task["work_block"],
            input_refs=tuple(raw_task["input_refs"]),
            provider_policy_ref=raw_task["provider_policy_ref"],
            project_binding=raw_task["project_binding"],
            created_by=raw_task["created_by"],
            created_at=raw_task["created_at"],
            task_content_hash=raw_task["task_content_hash"],
        )
    assert "AgentTask task_id mismatch" in str(exc_task.value)

    # 2. AgentRoute forged route_id rejected
    raw_route = route.to_dict()
    raw_route["route_id"] = "route-forged0000000000000000000000"
    raw_route["route_content_hash"] = compute_route_content_hash(raw_route)
    with pytest.raises(TamperDetectionError) as exc_route:
        AgentRoute(
            route_id=raw_route["route_id"],
            authorization_scope_ref=raw_route["authorization_scope_ref"],
            role=raw_route["role"],
            provider=raw_route["provider"],
            resolved_model=raw_route["resolved_model"],
            policy_version=raw_route["policy_version"],
            route_reason=raw_route["route_reason"],
            usage_snapshot_ref=raw_route["usage_snapshot_ref"],
            project_binding=raw_route["project_binding"],
            authorized_permissions=tuple(raw_route["authorized_permissions"]),
            route_reason_code=raw_route["route_reason_code"],
            transport_ref=raw_route["transport_ref"],
            candidate_trace=tuple(raw_route["candidate_trace"]),
            route_content_hash=raw_route["route_content_hash"],
        )
    assert "AgentRoute route_id mismatch" in str(exc_route.value)

    # 3. ExecutionPreparation forged preparation_id rejected
    raw_prep = prep.to_dict()
    raw_prep["preparation_id"] = "prep-forged0000000000000000000000"
    raw_prep["preparation_hash"] = compute_preparation_content_hash(raw_prep)
    with pytest.raises(TamperDetectionError) as exc_prep:
        ExecutionPreparation(
            preparation_id=raw_prep["preparation_id"],
            task_id=raw_prep["task_id"],
            route_id=raw_prep["route_id"],
            task_ref=raw_prep["task_ref"],
            route_ref=raw_prep["route_ref"],
            provider=raw_prep["provider"],
            model=raw_prep["model"],
            transport=prep.transport,
            authorized_permissions=prep.authorized_permissions,
            project_binding=raw_prep["project_binding"],
            preparation_hash=raw_prep["preparation_hash"],
        )
    assert "ExecutionPreparation preparation_id mismatch" in str(exc_prep.value)


# 38. [Review Remediation - ISSUE-03] AgentTask delegation_depth > 1 rejected in __post_init__
def test_38_review_remediation_task_delegation_depth_hard_bound() -> None:
    scope = _create_test_scope()
    task = _create_test_task(scope)
    raw_task = task.to_dict()
    raw_task["delegation_depth"] = 2  # Exceeds maximum allowable depth 1
    raw_task["parent_task_ref"] = {"task_id": "task-parent-123"}
    from research_lab.agent_control.contracts import (
        compute_task_content_hash,
        compute_task_deterministic_id,
    )
    raw_task["task_id"] = compute_task_deterministic_id(raw_task)
    raw_task["task_content_hash"] = compute_task_content_hash(raw_task)

    with pytest.raises(PermissionDeniedError) as exc_depth:
        AgentTask(
            task_id=raw_task["task_id"],
            authorization_scope_ref=raw_task["authorization_scope_ref"],
            role=raw_task["role"],
            requested_permissions=tuple(raw_task["requested_permissions"]),
            authorized_permissions=tuple(raw_task["authorized_permissions"]),
            objective=raw_task["objective"],
            work_block=raw_task["work_block"],
            input_refs=tuple(raw_task["input_refs"]),
            provider_policy_ref=raw_task["provider_policy_ref"],
            project_binding=raw_task["project_binding"],
            created_by=raw_task["created_by"],
            created_at=raw_task["created_at"],
            delegation_depth=raw_task["delegation_depth"],
            parent_task_ref=raw_task["parent_task_ref"],
            task_content_hash=raw_task["task_content_hash"],
        )
    assert "Nested agent delegation prohibited" in str(exc_depth.value)
    assert "exceeds maximum allowable depth 1" in str(exc_depth.value)
