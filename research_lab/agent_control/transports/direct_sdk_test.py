"""Deterministic Direct SDK Test Transport (#573 Milestone 8).

Architecture Rule:
Role -> Access Control -> Agent Router -> Agent Provider -> Provider Transport (DirectSDKTestTransport)

Boundary Rules:
1. Pure in-memory, deterministic execution transport for contract verification only.
2. Distinct from local_mcp; represents an SDK/direct programmatic call mechanism.
3. NEVER expose secrets, credentials, tokens, passwords, sockets, or endpoints.
4. Transport CANNOT modify AgentTask, cannot change ProjectBinding, cannot alter permissions.
5. Fail-closed on missing profile or simulated connection error.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from research_lab.agent_control.errors import (
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
)
from research_lab.agent_control.transport import (
    ProviderConnectionDescriptor,
    ProviderTransportKind,
)

DEFAULT_DIRECT_SDK_PROFILE = "direct_sdk_test"
DEFAULT_DIRECT_SDK_CAPABILITIES = (
    "in_memory",
    "deterministic",
    "synchronous",
    "fast_execution",
)


class DirectSDKTestTransport:
    """Deterministic in-memory transport representing a direct SDK boundary."""

    def __init__(
        self,
        profile_ref: str = DEFAULT_DIRECT_SDK_PROFILE,
        capabilities: tuple[str, ...] = DEFAULT_DIRECT_SDK_CAPABILITIES,
    ) -> None:
        self._profile_ref = profile_ref
        self._capabilities = capabilities
        self._descriptor = ProviderConnectionDescriptor(
            transport_kind=ProviderTransportKind.DIRECT_SDK,
            connection_profile_ref=self._profile_ref,
            capabilities=self._capabilities,
        )
        self._is_connected: bool = True
        self._custom_invoker: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None
        self._call_history: list[dict[str, Any]] = []

    @property
    def descriptor(self) -> ProviderConnectionDescriptor:
        """Return the neutral immutable connection descriptor."""
        return self._descriptor

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    def set_connected(self, connected: bool) -> None:
        """Simulate connection drop or recovery for test harness."""
        self._is_connected = bool(connected)

    def set_custom_invoker(
        self,
        invoker: Callable[[str, dict[str, Any]], dict[str, Any]] | None,
    ) -> None:
        """Attach custom invocation handler for negative / failure injection tests."""
        self._custom_invoker = invoker

    @property
    def call_history(self) -> list[dict[str, Any]]:
        return list(self._call_history)

    def clear_history(self) -> None:
        self._call_history.clear()

    def invoke(
        self,
        operation: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a direct SDK call in memory fail-closed."""
        if not self._is_connected:
            raise ProviderUnavailableError(
                f"DirectSDKTestTransport '{self._profile_ref}' is disconnected or unavailable",
                details={"profile_ref": self._profile_ref, "operation": operation},
            )

        cloned_payload = copy.deepcopy(payload)
        self._call_history.append(
            {
                "operation": operation,
                "payload": cloned_payload,
            }
        )

        if self._custom_invoker is not None:
            return self._custom_invoker(operation, cloned_payload)

        # Default minimal deterministic handling
        if operation == "health":
            return {"status": "HEALTHY", "profile": self._profile_ref}

        if operation == "execute":
            # Return raw echo or success envelope
            return {
                "operation": "execute",
                "status": "COMPLETED",
                "output": cloned_payload.get("input", {}),
            }

        raise ProviderError(
            ProviderErrorCode.EXECUTION_FAILED,
            f"Unknown SDK operation '{operation}'",
            details={"operation": operation},
        )
