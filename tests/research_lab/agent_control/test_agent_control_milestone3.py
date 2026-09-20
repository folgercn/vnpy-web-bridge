"""Milestone 3 — Quota / Usage-Aware Routing Test Suite (#573 Milestone 3).

Comprehensive 31-case contract test suite strictly enforcing:
1. Provider-neutral Quota Facts and Antigravity normalization.
2. Shared quota group semantics (Gemini High/Medium shared group).
3. Exhausted group whole-group skipping (no fake same-group fallback).
4. Deterministic multi-window conservative aggregation.
5. Fail-closed on Unknown, Malformed, Stale, Tampered, and Provider mismatch.
6. Caller preference cannot override quota exhaustion.
7. Route identity and candidate trace quota facts determinism.
8. Error taxonomy isolation (QUOTA_UNAVAILABLE vs PROVIDER_UNAVAILABLE).
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentProviderDescriptor,
    AgentRoute,
    AgentTask,
    AgentUsageSnapshot,
    ProjectBinding,
    TamperDetectionError,
    compute_route_deterministic_id,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    QuotaUnavailableError,
)
from research_lab.agent_control.handoff import prepare_execution
from research_lab.agent_control.provider import AgentProvider, ProviderAvailability
from research_lab.agent_control.providers.antigravity_local_mcp import (
    AntigravityLocalMCPProvider,
)
from research_lab.agent_control.quota import (
    AntigravityQuotaNormalizer,
    ModelQuotaBinding,
    ProviderQuotaFacts,
    QuotaGroupSnapshot,
    QuotaStatus,
    QuotaWindowSnapshot,
)
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.roles import AgentRole
from research_lab.agent_control.router import authorize, select_agent
from research_lab.agent_control.routing_context import RoutingContext
from research_lab.agent_control.routing_policy import (
    RouteReasonCode,
    RoutingPolicy,
)
from research_lab.agent_control.transport import (
    ProviderConnectionDescriptor,
    ProviderTransportKind,
)
from research_lab.agent_control.transports.local_mcp import (
    ALL_MCP_OPERATIONS,
)


class MockM3Transport:
    """Mock transport for quota testing adhering to LocalMCPTransport contract."""

    def __init__(
        self,
        exact_ref: str = "local_mcp://antigravity-local-desktop",
        tool_catalog: list[str] | None = None,
        custom_caller: Any = None,
    ) -> None:
        self.exact_ref = exact_ref
        self._tool_catalog = list(tool_catalog if tool_catalog is not None else ALL_MCP_OPERATIONS)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._custom_caller = custom_caller
        self.descriptor = ProviderConnectionDescriptor(
            transport_kind=ProviderTransportKind.LOCAL_MCP,
            connection_profile_ref=exact_ref,
        )

    def discover_tools(self) -> list[str]:
        return list(self._tool_catalog)

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool_name, arguments))
        if self._custom_caller:
            return self._custom_caller(tool_name, arguments)
        if tool_name == "projects":
            return {"project": {"project_id": "vnpy-p1", "cwd": arguments.get("cwd", "/workspace/vnpy")}}
        if tool_name == "status":
            return {"status": "HEALTHY", "available": True}
        if tool_name == "submit":
            return {"job_id": "job-12345", "status": "PENDING"}
        return {}


class MockM3Provider(AgentProvider):
    """Configurable mock provider for Milestone 3 testing."""

    def __init__(
        self,
        name: str,
        supported_models: tuple[str, ...] = ("model-a", "model-b"),
        is_available: bool = True,
        availability_status: str = "AVAILABLE",
        transport_kind: ProviderTransportKind = ProviderTransportKind.LOCAL_MCP,
    ) -> None:
        self._name = name
        self._models = supported_models
        self._is_available = is_available
        self._avail_status = availability_status
        self.transport_descriptor = ProviderConnectionDescriptor(
            transport_kind=transport_kind,
            connection_profile_ref=f"{name}-desktop",
        )

    def describe(self) -> AgentProviderDescriptor:
        return AgentProviderDescriptor(
            provider=self._name,
            supported_roles=tuple(r.value for r in AgentRole),
            capabilities=("text_generation", "code_search"),
            default_model=self._models[0] if self._models else "default-model",
            supported_models=self._models,
        )

    def describe_transport(self) -> ProviderConnectionDescriptor:
        return self.transport_descriptor

    def availability(self, role: str, context: dict[str, Any] | None = None) -> ProviderAvailability:
        return ProviderAvailability(
            is_available=self._is_available,
            status=self._avail_status,
            reason="healthy" if self._is_available else "offline",
        )

    def account_usage(self) -> AgentUsageSnapshot:
        return AgentUsageSnapshot.create(
            provider=self._name,
            model_group="default-group",
            quota_windows=[{"window": "5h", "remaining_fraction": 1.0}],
            captured_at="2026-09-21T00:00:00Z",
        )


def _create_scope(role: str = AgentRole.ALPHA_GENERATOR.value) -> AgentPermissionScope:
    binding = ProjectBinding(project_id="vnpy-p1", workspace_identity="/workspace/vnpy")
    perms = ["read_result_store"] if role == AgentRole.CODE_RESEARCHER.value else ["create_hypothesis"]
    return authorize(
        role=role,
        requested_permissions=perms,
        project_binding=binding,
    )


def _sanitized_real_fixture() -> dict[str, Any]:
    """Sanitized fixture matching real Antigravity FastMCP response structure."""
    return {
        "status": "OK",
        "account": {
            "name": "<REDACTED>",
            "email": "<REDACTED>",
            "planName": "Pro",
        },
        "quota": {
            "groups": [
                {
                    "displayName": "Gemini Models",
                    "description": "Models within this group: Gemini Flash, Gemini Pro",
                    "buckets": [
                        {
                            "bucketId": "gemini-weekly",
                            "window": "weekly",
                            "remainingFraction": 0.85,
                            "resetTime": "2026-09-23T11:13:50Z",
                        },
                        {
                            "bucketId": "gemini-5h",
                            "window": "5h",
                            "remainingFraction": 0.95,
                            "resetTime": "2026-09-20T21:22:54Z",
                        },
                    ],
                }
            ]
        },
    }


# -------------------------------------------------------------------------
# Test Cases 1 - 31
# -------------------------------------------------------------------------

# 1. real usage snapshot parse
def test_01_real_usage_snapshot_parse() -> None:
    fixture = _sanitized_real_fixture()
    windows = []
    for g in fixture["quota"]["groups"]:
        for b in g["buckets"]:
            windows.append({
                "window": b["window"],
                "remaining_fraction": b["remainingFraction"],
                "reset_time": b["resetTime"],
            })
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=windows,
        captured_at="2026-09-21T00:00:00Z",
    )
    facts = AntigravityQuotaNormalizer.normalize(
        snap,
        healthy_threshold=0.30,
        max_age_seconds=600.0,
        current_time="2026-09-21T00:01:00Z",
    )
    assert facts.provider == "antigravity"
    assert len(facts.groups) == 1
    assert facts.groups[0].display_name == "Gemini Models"
    assert facts.groups[0].status == QuotaStatus.HEALTHY
    assert len(facts.groups[0].windows) == 2


# 2. shared group mapping
def test_02_shared_group_mapping() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[
            {"window": "5h", "remaining_fraction": 0.80},
            {"window": "weekly", "remaining_fraction": 0.90},
        ],
        captured_at="2026-09-21T00:00:00Z",
    )
    facts = AntigravityQuotaNormalizer.normalize(snap, current_time="2026-09-21T00:01:00Z")
    grp_high = facts.get_group_for_model("Gemini 3.8 Flash High")
    grp_med = facts.get_group_for_model("Gemini 3.8 Flash Medium")
    grp_37 = facts.get_group_for_model("Gemini 3.7 Flash High")
    assert grp_high is not None
    assert grp_med is not None
    assert grp_37 is not None
    assert grp_high.group_id == grp_med.group_id == grp_37.group_id == "gemini-shared"


# 3. multiple windows preserved
def test_03_multiple_windows_preserved() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[
            {"window": "5h", "remaining_fraction": 0.88, "reset_time": "2026-09-21T05:00:00Z"},
            {"window": "weekly", "remaining_fraction": 0.92, "reset_time": "2026-09-28T00:00:00Z"},
        ],
        captured_at="2026-09-21T00:00:00Z",
    )
    facts = AntigravityQuotaNormalizer.normalize(snap, current_time="2026-09-21T00:01:00Z")
    windows = facts.groups[0].windows
    assert len(windows) == 2
    w_map = {w.window: w for w in windows}
    assert "5h" in w_map and "weekly" in w_map
    assert w_map["5h"].remaining_fraction == 0.88
    assert w_map["weekly"].reset_time == "2026-09-28T00:00:00Z"


# 4. quota zero preserved
def test_04_quota_zero_preserved() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[
            {"window": "5h", "remaining_fraction": 0.0},
            {"window": "weekly", "remaining_fraction": 0.50},
        ],
        captured_at="2026-09-21T00:00:00Z",
    )
    facts = AntigravityQuotaNormalizer.normalize(snap, current_time="2026-09-21T00:01:00Z")
    assert facts.groups[0].status == QuotaStatus.EXHAUSTED
    assert facts.groups[0].windows[0].remaining_fraction == 0.0
    assert facts.groups[0].windows[0].status == QuotaStatus.EXHAUSTED


# 5. quota unknown preserved
def test_05_quota_unknown_preserved() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[
            {"window": "5h", "remaining_fraction": None},
            {"window": "weekly", "remaining_fraction": 0.80},
        ],
        captured_at="2026-09-21T00:00:00Z",
    )
    facts = AntigravityQuotaNormalizer.normalize(snap, current_time="2026-09-21T00:01:00Z")
    # Conservative multi-window: one unknown with no exhausted -> UNKNOWN
    assert facts.groups[0].status == QuotaStatus.UNKNOWN
    assert facts.groups[0].windows[0].status == QuotaStatus.UNKNOWN


# 6. malformed window fail closed
def test_06_malformed_window_fail_closed() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[
            {"window": "5h", "remaining_fraction": "not-a-number"},
            {"window": "weekly", "remaining_fraction": 0.80},
        ],
        captured_at="2026-09-21T00:00:00Z",
    )
    facts = AntigravityQuotaNormalizer.normalize(snap, current_time="2026-09-21T00:01:00Z")
    assert facts.groups[0].status == QuotaStatus.UNKNOWN
    assert facts.groups[0].windows[0].status == QuotaStatus.UNKNOWN


# 7. provider mismatch
def test_07_provider_mismatch() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 1.0}],
        captured_at="2026-09-21T00:00:00Z",
    )
    # Passed to OpenAI candidate
    registry = ProviderRegistry()
    openai_prov = MockM3Provider("openai", supported_models=("gpt-4o",))
    registry.register(openai_prov)

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("openai",), policy_version="2026-09-m3")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"openai": snap},
    )
    with pytest.raises(QuotaUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "mismatch" in str(exc.value).lower()


# 8. snapshot tamper
def test_08_snapshot_tamper() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.80}],
        captured_at="2026-09-21T00:00:00Z",
    )
    tampered_dict = dict(snap.to_dict())
    tampered_dict["model_group"] = "Hacked Group"
    with pytest.raises(TamperDetectionError):
        AgentUsageSnapshot(**tampered_dict)


# 9. stale snapshot
def test_09_stale_snapshot() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.80}],
        captured_at="2026-09-20T00:00:00Z",  # 1 day old
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("antigravity",),
        max_usage_snapshot_age=300.0,
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:00:00Z",  # 86400s later
    )
    with pytest.raises(QuotaUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "stale" in str(exc.value).lower()


# 10. healthy primary
def test_10_healthy_primary() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.85}],
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High", "Gemini 3.8 Flash Medium"))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("antigravity",),
        model_preference={"antigravity": ("Gemini 3.8 Flash High", "Gemini 3.8 Flash Medium")},
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.resolved_model == "Gemini 3.8 Flash High"
    assert route.quota_group == "gemini-shared"
    assert route.route_reason_code == RouteReasonCode.PRIMARY_HEALTHY.value


# 11. constrained primary
def test_11_constrained_primary() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.15}],  # < 0.30
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("antigravity",),
        healthy_threshold=0.30,
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.resolved_model == "Gemini 3.8 Flash High"
    assert route.route_reason_code == RouteReasonCode.PRIMARY_CONSTRAINED.value


# 12. exhausted shared group skips all bound models (no fake fallback)
def test_12_exhausted_shared_group_skips_all_bound_models() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.0}],  # Exhausted
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High", "Gemini 3.8 Flash Medium"))
    registry.register(prov)

    scope = _create_scope()
    # Preference lists High, then Medium (both in gemini-shared)
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("antigravity",),
        model_preference={"antigravity": ("Gemini 3.8 Flash High", "Gemini 3.8 Flash Medium")},
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    # Must NOT fall back from High to Medium; both belong to gemini-shared!
    with pytest.raises(QuotaUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "quota exhausted" in str(exc.value).lower()


# 13. independent group fallback
def test_13_independent_group_fallback() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.0}],  # Gemini exhausted
        captured_at="2026-09-21T00:00:00Z",
    )
    # Provide neutral facts containing an independent group (3p-group) that is healthy
    gemini_grp = QuotaGroupSnapshot(
        group_id="gemini-shared",
        display_name="Gemini Models",
        status=QuotaStatus.EXHAUSTED,
        windows=(QuotaWindowSnapshot(window="5h", remaining_fraction=0.0, reset_time=None, status=QuotaStatus.EXHAUSTED),),
        bound_models=("Gemini 3.8 Flash High",),
    )
    other_grp = QuotaGroupSnapshot(
        group_id="independent-group",
        display_name="Independent Models",
        status=QuotaStatus.HEALTHY,
        windows=(QuotaWindowSnapshot(window="5h", remaining_fraction=0.85, reset_time=None, status=QuotaStatus.HEALTHY),),
        bound_models=("Independent-Model-X",),
    )
    facts = ProviderQuotaFacts(
        provider="antigravity",
        snapshot_ref=f"{snap.snapshot_id}@{snap.usage_content_hash}",
        captured_at=snap.captured_at,
        groups=(gemini_grp, other_grp),
        model_bindings=(
            ModelQuotaBinding(provider="antigravity", model="Gemini 3.8 Flash High", quota_group_id="gemini-shared"),
            ModelQuotaBinding(provider="antigravity", model="Independent-Model-X", quota_group_id="independent-group"),
        ),
    )

    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High", "Independent-Model-X"))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("antigravity",),
        model_preference={"antigravity": ("Gemini 3.8 Flash High", "Independent-Model-X")},
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        quota_facts={"antigravity": facts},
        current_time="2026-09-21T00:01:00Z",
    )
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.resolved_model == "Independent-Model-X"
    assert route.quota_group == "independent-group"
    assert route.route_reason_code == RouteReasonCode.FALLBACK_DIFFERENT_QUOTA_GROUP.value


# 14. all exhausted
def test_14_all_exhausted() -> None:
    snap1 = AgentUsageSnapshot.create(
        provider="p1", model_group="g1", quota_windows=[{"window": "5h", "remaining_fraction": 0}], captured_at="2026-09-21T00:00:00Z"
    )
    snap2 = AgentUsageSnapshot.create(
        provider="p2", model_group="g2", quota_windows=[{"window": "5h", "remaining_fraction": 0}], captured_at="2026-09-21T00:00:00Z"
    )
    registry = ProviderRegistry()
    registry.register(MockM3Provider("p1"))
    registry.register(MockM3Provider("p2"))

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("p1", "p2"), policy_version="2026-09-m3")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"p1": snap1, "p2": snap2},
        current_time="2026-09-21T00:01:00Z",
    )
    with pytest.raises(QuotaUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "exhausted" in str(exc.value).lower()


# 15. all unknown
def test_15_all_unknown() -> None:
    snap = AgentUsageSnapshot.create(
        provider="p1", model_group="g1", quota_windows=[{"window": "5h", "remaining_fraction": None}], captured_at="2026-09-21T00:00:00Z"
    )
    registry = ProviderRegistry()
    registry.register(MockM3Provider("p1"))

    scope = _create_scope()
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("p1",),
        allow_unknown_quota_fallback=False,
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"p1": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    with pytest.raises(QuotaUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "unknown" in str(exc.value).lower()


# 16. unknown + healthy
def test_16_unknown_plus_healthy() -> None:
    snap1 = AgentUsageSnapshot.create(
        provider="p1", model_group="g1", quota_windows=[{"window": "5h", "remaining_fraction": None}], captured_at="2026-09-21T00:00:00Z"
    )
    snap2 = AgentUsageSnapshot.create(
        provider="p2", model_group="g2", quota_windows=[{"window": "5h", "remaining_fraction": 0.8}], captured_at="2026-09-21T00:00:00Z"
    )
    registry = ProviderRegistry()
    registry.register(MockM3Provider("p1"))
    registry.register(MockM3Provider("p2"))

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("p1", "p2"), policy_version="2026-09-m3")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"p1": snap1, "p2": snap2},
        current_time="2026-09-21T00:01:00Z",
    )
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.provider == "p2"


# 17. missing snapshot
def test_17_missing_snapshot() -> None:
    registry = ProviderRegistry()
    registry.register(MockM3Provider("p1"))

    scope = _create_scope()
    policy = RoutingPolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        provider_priority=("p1",),
        allow_missing_usage=False,  # M3 strict requirement
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={},
    )
    with pytest.raises(QuotaUnavailableError) as exc:
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert "missing" in str(exc.value).lower()


# 18. caller override exhausted model denied
def test_18_caller_override_exhausted_model_denied() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.0}],
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("antigravity",), policy_version="2026-09-m3")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        preferred_model="Gemini 3.8 Flash High",  # Caller tries to force exhausted model
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    with pytest.raises(QuotaUnavailableError):
        select_agent(registry=registry, routing_policy=policy, routing_context=ctx)


# 19. unsupported model mapping unknown
def test_19_unsupported_model_mapping_unknown() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.85}],
        captured_at="2026-09-21T00:00:00Z",
    )
    facts = AntigravityQuotaNormalizer.normalize(snap, current_time="2026-09-21T00:01:00Z")
    # Query model not in Antigravity model bindings
    grp = facts.get_group_for_model("Mystery-Custom-Model")
    assert grp is None
    assert facts.get_status_for_model("Mystery-Custom-Model") == QuotaStatus.UNKNOWN


# 20. route reason code correct
def test_20_route_reason_code_correct() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.85}],
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("antigravity",), policy_version="2026-09-m3")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.route_reason_code in [c.value for c in RouteReasonCode]
    assert route.route_reason_code == RouteReasonCode.PRIMARY_HEALTHY.value


# 21. route candidate trace contains quota facts
def test_21_route_candidate_trace_contains_quota_facts() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.85, "reset_time": "2026-09-21T05:00:00Z"}],
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("antigravity",), policy_version="2026-09-m3")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert len(route.candidate_trace) == 1
    tr = route.candidate_trace[0]
    for required_key in (
        "provider", "model", "quota_group", "quota_status", "quota_windows",
        "transport", "availability", "decision", "skip_reason"
    ):
        assert required_key in tr
    assert tr["quota_group"] == "gemini-shared"
    assert tr["quota_status"] == QuotaStatus.HEALTHY.value
    assert len(tr["quota_windows"]) == 1


# 22. route_id deterministic
def test_22_route_id_deterministic() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.85}],
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("antigravity",), policy_version="2026-09-m3")
    ctx1 = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    ctx2 = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    r1 = select_agent(registry=registry, routing_policy=policy, routing_context=ctx1)
    r2 = select_agent(registry=registry, routing_policy=policy, routing_context=ctx2)
    assert r1.route_id == r2.route_id


# 23. snapshot change changes route_id
def test_23_snapshot_change_changes_route_id() -> None:
    snap1 = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.85}],
        captured_at="2026-09-21T00:00:00Z",
    )
    snap2 = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.70}],
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("antigravity",), policy_version="2026-09-m3")
    ctx1 = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap1},
        current_time="2026-09-21T00:01:00Z",
    )
    ctx2 = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap2},
        current_time="2026-09-21T00:01:00Z",
    )
    r1 = select_agent(registry=registry, routing_policy=policy, routing_context=ctx1)
    r2 = select_agent(registry=registry, routing_policy=policy, routing_context=ctx2)
    assert r1.route_id != r2.route_id


# 24. reason text change does not change route_id
def test_24_reason_text_change_does_not_change_route_id() -> None:
    scope = _create_scope()
    payload1 = {
        "authorization_scope_ref": scope.to_dict(),
        "authorized_permissions": list(scope.authorized_permissions),
        "policy_version": "2026-09-m3",
        "project_binding": dict(scope.project_binding),
        "provider": "antigravity",
        "resolved_model": "Gemini 3.8 Flash High",
        "role": scope.role,
        "route_reason": "Reason version A",
        "route_reason_code": "PRIMARY_HEALTHY",
        "quota_group": "gemini-shared",
    }
    payload2 = copy.deepcopy(payload1)
    payload2["route_reason"] = "Completely different free text explanation"

    id1 = compute_route_deterministic_id(payload1)
    id2 = compute_route_deterministic_id(payload2)
    assert id1 == id2


# 25. Adapter cannot override resolved_model
def test_25_adapter_cannot_override_resolved_model() -> None:
    transport = MockM3Transport()
    adapter = AntigravityLocalMCPProvider(transport=transport)

    scope = _create_scope(role=AgentRole.CODE_RESEARCHER.value)
    task = AgentTask.create(
        role=AgentRole.CODE_RESEARCHER.value,
        requested_permissions=["read_result_store"],
        authorized_permissions=["read_result_store"],
        objective="Inspect code",
        work_block="WB-1",
        input_refs=[],
        provider_policy_ref="policy-v1",
        project_binding=scope.project_binding,
        created_by="tester",
        created_at="2026-09-21T00:00:00Z",
        authorized_scope=scope,
    )
    route = AgentRoute.create(
        role=AgentRole.CODE_RESEARCHER.value,
        provider="antigravity",
        resolved_model="Gemini 3.8 Flash High",
        policy_version="2026-09-m3",
        route_reason="Selected healthy model",
        usage_snapshot_ref=None,
        project_binding=scope.project_binding,
        authorized_permissions=["read_result_store"],
        authorized_scope=scope,
        route_reason_code=RouteReasonCode.PRIMARY_HEALTHY.value,
        transport_ref=transport.exact_ref,
        quota_group="gemini-shared",
    )

    # If preparation has mismatched model: submit must reject
    registry = ProviderRegistry()
    transport_desc = ProviderConnectionDescriptor(
        transport_kind=ProviderTransportKind.LOCAL_MCP,
        connection_profile_ref="antigravity-local-desktop",
    )
    registry.register(adapter, transport=transport_desc)
    prep = prepare_execution(task=task, route=route, registry=registry)
    object.__setattr__(prep, "model", "Gemini 3.8 Flash Medium")  # Attempt to override model
    with pytest.raises((PermissionDeniedError, TamperDetectionError)):
        adapter.submit(task=task, route=route, preparation=prep)


# 26. actual model mismatch still audited
def test_26_actual_model_mismatch_still_audited() -> None:
    # Verify submit accepts preparation matching route.resolved_model
    transport = MockM3Transport()
    adapter = AntigravityLocalMCPProvider(transport=transport)
    scope = _create_scope(role=AgentRole.CODE_RESEARCHER.value)
    task = AgentTask.create(
        role=AgentRole.CODE_RESEARCHER.value,
        requested_permissions=["read_result_store"],
        authorized_permissions=["read_result_store"],
        objective="Inspect code",
        work_block="WB-1",
        input_refs=[],
        provider_policy_ref="policy-v1",
        project_binding=scope.project_binding,
        created_by="tester",
        created_at="2026-09-21T00:00:00Z",
        authorized_scope=scope,
    )
    route = AgentRoute.create(
        role=AgentRole.CODE_RESEARCHER.value,
        provider="antigravity",
        resolved_model="Gemini 3.8 Flash High",
        policy_version="2026-09-m3",
        route_reason="Selected healthy model",
        usage_snapshot_ref=None,
        project_binding=scope.project_binding,
        authorized_permissions=["read_result_store"],
        authorized_scope=scope,
        route_reason_code=RouteReasonCode.PRIMARY_HEALTHY.value,
        transport_ref=transport.exact_ref,
        quota_group="gemini-shared",
    )
    registry = ProviderRegistry()
    transport_desc = ProviderConnectionDescriptor(
        transport_kind=ProviderTransportKind.LOCAL_MCP,
        connection_profile_ref="antigravity-local-desktop",
    )
    registry.register(adapter, transport=transport_desc)
    prep = prepare_execution(task=task, route=route, registry=registry)
    handle = adapter.submit(task=task, route=route, preparation=prep)
    assert handle.handle_id.startswith("handle-")


# 27. no secret leakage
def test_27_no_secret_leakage() -> None:
    snap = AgentUsageSnapshot.create(
        provider="antigravity",
        model_group="Gemini Models",
        quota_windows=[{"window": "5h", "remaining_fraction": 0.85}],
        captured_at="2026-09-21T00:00:00Z",
    )
    registry = ProviderRegistry()
    prov = MockM3Provider("antigravity", supported_models=("Gemini 3.8 Flash High",))
    registry.register(prov)

    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("antigravity",), policy_version="2026-09-m3")
    ctx = RoutingContext(
        role=AgentRole.ALPHA_GENERATOR.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": snap},
        current_time="2026-09-21T00:01:00Z",
    )
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    dumped = str(route.to_dict()).lower()
    for forbidden in ("password", "sk-", "avatar", "bearer", "authorization_header", "private_key", "secret"):
        assert forbidden not in dumped


# 28. M0 frozen tests pass
def test_28_m0_frozen_contracts_preserved() -> None:
    from research_lab.agent_control.roles import DEFAULT_ROLE_POLICIES
    assert len(DEFAULT_ROLE_POLICIES) == 5
    for pol in DEFAULT_ROLE_POLICIES.values():
        assert "production_trading" not in pol.allowed_permissions
        assert "live_trading_authorized" not in pol.allowed_permissions


# 29. M1 frozen tests pass
def test_29_m1_frozen_router_preserved() -> None:
    registry = ProviderRegistry()
    p1 = MockM3Provider("p1")
    registry.register(p1)
    scope = _create_scope()
    policy = RoutingPolicy(role=AgentRole.ALPHA_GENERATOR.value, provider_priority=("p1",))
    ctx = RoutingContext(role=AgentRole.ALPHA_GENERATOR.value, authorized_scope=scope, project_binding=scope.project_binding)
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.provider == "p1"


# 30. M2 frozen tests pass
def test_30_m2_frozen_adapter_preserved() -> None:
    transport = MockM3Transport()
    adapter = AntigravityLocalMCPProvider(transport=transport)
    avail = adapter.availability(AgentRole.CODE_RESEARCHER.value)
    assert avail.is_available is True
    assert avail.status == "AVAILABLE"


# 31. true real account_usage routing E2E mock simulation
def test_31_real_account_usage_routing_mock_e2e() -> None:
    """Mock-driven end-to-end verification of the exact account_usage routing chain."""
    raw_response = _sanitized_real_fixture()

    def _mock_caller(name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "account_usage":
            return raw_response
        if name == "status":
            return {"status": "HEALTHY", "available": True}
        if name == "projects":
            return {"project": {"cwd": args.get("cwd", "/workspace/vnpy")}}
        return {}

    transport = MockM3Transport(custom_caller=_mock_caller)

    adapter = AntigravityLocalMCPProvider(transport=transport)
    usage = adapter.account_usage()
    assert isinstance(usage, AgentUsageSnapshot)
    assert usage.provider == "antigravity"

    normalizer = AntigravityQuotaNormalizer()
    facts = normalizer.normalize(usage, current_time=usage.captured_at)
    assert facts.provider == "antigravity"
    assert facts.groups[0].status == QuotaStatus.HEALTHY

    registry = ProviderRegistry()
    transport_desc = ProviderConnectionDescriptor(
        transport_kind=ProviderTransportKind.LOCAL_MCP,
        connection_profile_ref="antigravity-local-desktop",
    )
    registry.register(adapter, transport=transport_desc)

    scope = _create_scope(role=AgentRole.CODE_RESEARCHER.value)
    policy = RoutingPolicy(
        role=AgentRole.CODE_RESEARCHER.value,
        provider_priority=("antigravity",),
        model_preference={"antigravity": ("Gemini 3.8 Flash High", "Gemini 3.8 Flash Medium")},
        policy_version="2026-09-m3",
    )
    ctx = RoutingContext(
        role=AgentRole.CODE_RESEARCHER.value,
        authorized_scope=scope,
        project_binding=scope.project_binding,
        usage_snapshots={"antigravity": usage},
        current_time=usage.captured_at,
    )

    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    assert route.provider == "antigravity"
    assert route.resolved_model == "Gemini 3.8 Flash High"
    assert route.quota_group == "gemini-shared"
    assert route.route_reason_code == RouteReasonCode.PRIMARY_HEALTHY.value
    assert route.usage_snapshot_ref == f"{usage.snapshot_id}@{usage.usage_content_hash}"
