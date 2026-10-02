"""Installed envelope -> sealed snapshot -> normalizer -> actual routing gate."""
import copy

import pytest

from research_lab.agent_control.contracts import ProjectBinding
from research_lab.agent_control.errors import ProviderError
from research_lab.agent_control.providers.antigravity_local_mcp import AntigravityLocalMCPProvider
from research_lab.agent_control.quota import AntigravityQuotaNormalizer
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.router import authorize, select_agent
from research_lab.agent_control.routing_context import RoutingContext
from research_lab.agent_control.routing_policy import RoutingPolicy
from research_lab.agent_control.transports.local_mcp import ALL_MCP_OPERATIONS, LocalMCPTransport


def group(name="Gemini Models", pairs=(("5h", .8), ("weekly", .9))):
    return {"displayName": name, "buckets": [
        {"window": window, "remainingFraction": value} for window, value in pairs]}


def exercise(groups):
    raw = {"quota_windows": [{"window": "weekly", "remaining_fraction": 1}],
           "desktop": {"status": "OK", "quota": {"groups": groups}}}
    original = copy.deepcopy(raw)
    calls = []

    def call(op, args):
        calls.append(op)
        assert op in {"account_usage", "status"}
        return raw if op == "account_usage" else {"ready": True}

    provider = AntigravityLocalMCPProvider(transport=LocalMCPTransport(
        tool_catalog=list(ALL_MCP_OPERATIONS), tool_caller=call))
    snapshot = provider.account_usage()
    assert raw == original
    facts = AntigravityQuotaNormalizer.normalize(snapshot, current_time=snapshot.captured_at)
    registry = ProviderRegistry()
    registry.register(provider)
    binding = ProjectBinding(project_id="offline-quota-test", workspace_identity="/tmp/offline-quota-test")
    scope = authorize("code_researcher", ["read_result_store"], binding)
    context = RoutingContext(role="code_researcher", authorized_scope=scope,
                             project_binding=binding, usage_snapshots={"antigravity": snapshot},
                             current_time=snapshot.captured_at)
    policy = RoutingPolicy(role="code_researcher", provider_priority=("antigravity",),
                           policy_version="2026-09-m3")
    try:
        route = select_agent(registry=registry, routing_policy=policy, routing_context=context)
        reason = route.route_reason_code
        assert route.resolved_model == "Gemini 3.8 Flash High"
    except ProviderError as error:
        reason = error.code.value
    assert set(calls) <= {"account_usage", "status"}
    assert len(facts.groups) == 1
    assert facts.groups[0].group_id == "gemini-shared"
    assert len(snapshot.quota_windows) == 2
    return facts.groups[0].status.value, reason


@pytest.mark.parametrize("groups,status,reason", [
    ([group(), group("Claude and GPT models", (("5h", .8), ("weekly", 0)))], "HEALTHY", "PRIMARY_HEALTHY"),
    ([group("Claude and GPT models")], "UNKNOWN", "QUOTA_UNAVAILABLE"),
    ([group(pairs=(("5h", .8),))], "UNKNOWN", "QUOTA_UNAVAILABLE"),
    ([group(pairs=(("weekly", .9),))], "UNKNOWN", "QUOTA_UNAVAILABLE"),
    ([group()], "HEALTHY", "PRIMARY_HEALTHY"),
    ([group(pairs=(("5h", 0), ("weekly", .9))), group("Claude and GPT models")], "EXHAUSTED", "QUOTA_UNAVAILABLE"),
    ([], "UNKNOWN", "QUOTA_UNAVAILABLE"),
    ([group("Gemini and Claude")], "UNKNOWN", "QUOTA_UNAVAILABLE"),
])
def test_model_isolation_and_required_windows(groups, status, reason):
    assert exercise(groups) == (status, reason)


@pytest.mark.parametrize("value", [None, "unknown", True, False, float("nan"), float("inf"), -1, 1.01])
def test_invalid_required_fraction_rejects_route(value):
    assert exercise([group(pairs=(("5h", value), ("weekly", .9)))]) == ("UNKNOWN", "QUOTA_UNAVAILABLE")


@pytest.mark.parametrize("groups", [
    [group(), group()],
    [group(pairs=(("5h", .8), ("5h", 1), ("weekly", .9)))],
    [group(pairs=(("5h", .8), ("5-hour", 1), ("weekly", .9)))],
    [group(pairs=(("monthly", 1), ("weekly", .9)))],
])
def test_ambiguous_group_or_window_rejected(groups):
    with pytest.raises(ProviderError) as error:
        exercise(groups)
    assert error.value.code.value == "QUOTA_UNAVAILABLE"


def test_conflicting_fraction_aliases_remain_unknown():
    gemini = group()
    gemini["buckets"][0]["remaining_fraction"] = 1.0
    assert exercise([gemini]) == ("UNKNOWN", "QUOTA_UNAVAILABLE")


@pytest.mark.parametrize("buckets", [None, "unknown", {}])
def test_invalid_bucket_inventory_cannot_look_healthy(buckets):
    gemini = group()
    gemini["buckets"] = buckets
    assert exercise([gemini]) == ("UNKNOWN", "QUOTA_UNAVAILABLE")
