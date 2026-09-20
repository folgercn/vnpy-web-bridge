"""Provider-neutral abstract interface for Agent execution backends (#573 Milestone 0).

Domain contracts and access control strictly decouple from concrete provider APIs
(such as Antigravity MCP, OpenAI, Gemini). Concrete providers implement this
adapter interface without polluting core scientific or access control domains.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from research_lab.agent_control.contracts import (
    AgentExecutionHandle,
    AgentProviderDescriptor,
    AgentResult,
    AgentRoute,
    AgentTask,
)


@dataclass(frozen=True)
class ProviderAvailability:
    """Availability status of a provider for a specific role and context."""

    is_available: bool
    status: str  # "AVAILABLE", "UNAVAILABLE", "RATE_LIMITED", "UNKNOWN"
    reason: str = ""
    details: dict[str, Any] | None = None


@runtime_checkable
class AgentProvider(Protocol):
    """Neutral interface protocol implemented by all execution providers."""

    def describe(self) -> AgentProviderDescriptor:
        """Return the static descriptor of this provider, supported roles, and models."""
        ...

    def availability(
        self,
        role: str,
        context: dict[str, Any] | None = None,
    ) -> ProviderAvailability:
        """Check whether the provider is currently available to serve the given role."""
        ...

    def submit(
        self,
        task: AgentTask,
        route: AgentRoute,
    ) -> AgentExecutionHandle:
        """Submit an authorized task along its determined route for execution."""
        ...

    def status(
        self,
        handle: AgentExecutionHandle,
    ) -> str:
        """Query the current execution status of an active handle."""
        ...

    def result(
        self,
        handle: AgentExecutionHandle,
    ) -> AgentResult:
        """Retrieve the terminal execution result for a completed handle."""
        ...

    def cancel(
        self,
        handle: AgentExecutionHandle,
    ) -> bool:
        """Request cancellation of an active handle. Returns True if cancellation accepted."""
        ...
