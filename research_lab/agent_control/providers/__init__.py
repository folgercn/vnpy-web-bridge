"""Provider implementations for Agent Control (#573 Milestone 2)."""

from __future__ import annotations

from research_lab.agent_control.providers.antigravity_local_mcp import (
    AntigravityLocalMCPProvider,
)
from research_lab.agent_control.providers.contract_test_provider import (
    CONTRACT_TEST_DEFAULT_MODEL,
    CONTRACT_TEST_PROVIDER_NAME,
    CONTRACT_TEST_SUPPORTED_MODELS,
    CONTRACT_TEST_SUPPORTED_ROLES,
    ContractTestProvider,
)

__all__ = [
    "CONTRACT_TEST_DEFAULT_MODEL",
    "CONTRACT_TEST_PROVIDER_NAME",
    "CONTRACT_TEST_SUPPORTED_MODELS",
    "CONTRACT_TEST_SUPPORTED_ROLES",
    "AntigravityLocalMCPProvider",
    "ContractTestProvider",
]
