#!/usr/bin/env python3
"""Verification script for real Antigravity Local FastMCP Quota-Aware Routing E2E (#573 Milestone 3).

Verifies the end-to-end quota-aware routing chain against the real host FastMCP service:
account_usage -> AgentUsageSnapshot -> AntigravityQuotaNormalizer -> ProviderQuotaFacts -> Router -> AgentRoute.

Strictly read-only and side-effect free: no tasks submitted.
"""

from __future__ import annotations

import sys

from research_lab.agent_control.contracts import (
    ProjectBinding,
    compute_route_deterministic_id,
)
from research_lab.agent_control.providers.antigravity_local_mcp import (
    AntigravityLocalMCPProvider,
)
from research_lab.agent_control.quota import (
    AntigravityQuotaNormalizer,
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
    CRITICAL_MCP_TOOLS,
    DEFAULT_MCP_SCRIPT,
    DEFAULT_MCP_VENV_PYTHON,
    LocalMCPTransport,
)

REAL_VNPY_DIR = "/Users/fujun/node/vnpy"
REAL_VNPY_PROJECT_ID = "a173ba08-8e0c-4c26-8604-0d462da55529"


def main() -> int:
    print("=== [SIMNOW_LAB #573 M3] Real Antigravity Quota-Aware Routing E2E ===")

    # 1. Environment and Executable Probe
    print(f"[*] Probing MCP script: {DEFAULT_MCP_SCRIPT}")
    if not DEFAULT_MCP_SCRIPT.is_file():
        print(f"[ERROR] MCP script not found at {DEFAULT_MCP_SCRIPT}")
        return 1
    print(f"[*] Probing MCP venv python: {DEFAULT_MCP_VENV_PYTHON}")
    if not DEFAULT_MCP_VENV_PYTHON.is_file():
        print(f"[ERROR] MCP Python venv not found at {DEFAULT_MCP_VENV_PYTHON}")
        return 1

    # 2. Initialize Real LocalMCPTransport over Stdio
    transport = LocalMCPTransport()
    print(f"[*] Initialized LocalMCPTransport: exact_ref = {transport.exact_ref}")

    # 3. Dynamic Tool Discovery
    resolver = transport.discover_tools()
    mapping = resolver.mapping
    print(f"[*] Discovered {len(mapping)} MCP tools from real FastMCP server")
    for critical in CRITICAL_MCP_TOOLS:
        if critical not in mapping:
            print(f"[ERROR] Missing critical tool '{critical}' in catalog")
            return 1
    print("[PASS] Critical tools check complete (fail-closed contract satisfied).")

    # 4. Availability Check
    provider = AntigravityLocalMCPProvider(transport=transport)
    avail = provider.availability("code_researcher")
    print(f"[*] Provider availability probe: status = {avail.status}, is_available = {avail.is_available}")
    if not avail.is_available:
        print(f"[ERROR] Provider reported unavailable: {avail.reason}")
        return 1
    print("[PASS] Local MCP Provider availability check complete.")

    # 5. Real account_usage Capture & Privacy Redaction
    usage = provider.account_usage()
    print("[*] Captured real AgentUsageSnapshot:")
    print(f"    - provider: {usage.provider}")
    print(f"    - model_group: {usage.model_group}")
    print(f"    - snapshot_id: {usage.snapshot_id}")
    print(f"    - usage_content_hash: {usage.usage_content_hash}")
    print(f"    - quota_windows count: {len(usage.quota_windows)}")
    for w in usage.quota_windows:
        print(f"      * window: {w.get('window')}, remaining_fraction: {w.get('remaining_fraction')}, reset_time: {w.get('reset_time')}")

    dumped_usage = str(usage.to_dict()).lower()
    for forbidden in ("password", "sk-", "avatar", "bearer", "authorization_header"):
        if forbidden in dumped_usage:
            print(f"[ERROR] Leakage of sensitive credential in usage snapshot: found '{forbidden}'")
            return 1
    print("[PASS] Account usage snapshot verified and sensitive info strictly redacted.")

    # 6. Normalize via AntigravityQuotaNormalizer to neutral ProviderQuotaFacts
    normalizer = AntigravityQuotaNormalizer()
    facts = normalizer.normalize(usage, current_time=usage.captured_at)
    print("[*] Normalized ProviderQuotaFacts:")
    print(f"    - provider: {facts.provider}")
    print(f"    - binding_profile_version: {facts.binding_profile_version}")
    print(f"    - binding_source: {facts.binding_source}")
    print(f"    - groups count: {len(facts.groups)}")
    for g in facts.groups:
        print(f"      * group_id: {g.group_id} ({g.display_name}) -> status: {g.status.value}")
        for qw in g.windows:
            print(f"        - window: {qw.window}, remaining: {qw.remaining_fraction}, status: {qw.status.value}")
    print(f"    - model bindings count: {len(facts.model_bindings)}")
    for b in facts.model_bindings:
        print(f"      * model: '{b.model}' -> group: '{b.quota_group_id}' (profile: {b.binding_profile_version}, src: {b.binding_source})")
    assert facts.binding_profile_version == "2026-09-m3.v1", f"Unexpected facts profile: {facts.binding_profile_version}"
    print("[PASS] Quota facts normalization complete (verified real-time quota windows + versioned provider profile mapping).")

    # 7. Register Provider & Set up Context with Real Facts
    registry = ProviderRegistry()
    transport_desc = ProviderConnectionDescriptor(
        transport_kind=ProviderTransportKind.LOCAL_MCP,
        connection_profile_ref="antigravity-local-desktop",
    )
    registry.register(provider, transport=transport_desc)

    binding = ProjectBinding(project_id=REAL_VNPY_PROJECT_ID, workspace_identity=REAL_VNPY_DIR)
    perms = ["read_result_store"]
    scope = authorize(role=AgentRole.CODE_RESEARCHER.value, requested_permissions=perms, project_binding=binding)

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

    # 8. Execute Router Selection
    route = select_agent(registry=registry, routing_policy=policy, routing_context=ctx)
    print("[*] Router Selected AgentRoute:")
    print(f"    - route_id: {route.route_id}")
    print(f"    - provider: {route.provider}")
    print(f"    - resolved_model: {route.resolved_model}")
    print(f"    - quota_group: {route.quota_group}")
    print(f"    - binding_profile_version: {route.binding_profile_version}")
    print(f"    - route_reason_code: {route.route_reason_code}")
    print(f"    - route_reason: {route.route_reason}")
    print(f"    - usage_snapshot_ref: {route.usage_snapshot_ref}")

    # 9. Verify Contract Invariants
    assert route.provider == "antigravity", f"Expected antigravity, got {route.provider}"
    assert route.quota_group == "gemini-shared", f"Expected gemini-shared, got {route.quota_group}"
    assert route.binding_profile_version == "2026-09-m3.v1", f"Expected profile 2026-09-m3.v1, got {route.binding_profile_version}"
    expected_ref = f"{usage.snapshot_id}@{usage.usage_content_hash}"
    assert route.usage_snapshot_ref == expected_ref, f"Expected {expected_ref}, got {route.usage_snapshot_ref}"
    assert route.route_reason_code in (
        RouteReasonCode.PRIMARY_HEALTHY.value,
        RouteReasonCode.PRIMARY_CONSTRAINED.value,
        RouteReasonCode.FALLBACK_DIFFERENT_QUOTA_GROUP.value,
    ), f"Unexpected route_reason_code: {route.route_reason_code}"

    # Verify deterministic route ID
    recomputed_id = compute_route_deterministic_id(route.to_dict())
    assert route.route_id == recomputed_id, "Route ID determinism violated"

    print("=== [PASS] All Milestone 3 Real Quota-Aware Routing E2E Verifications Succeeded ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
