"""Explicit neutral Provider Registry (#573 Milestone 1).

Rules:
1. Explicit in-memory registration only.
2. NO dynamic plugin scanning, NO entry-point autoloading.
3. Duplicate registration fails closed.
4. Validates provider descriptor completeness:
   - provider name non-empty and unique
   - supported_models non-empty
   - default_model in supported_models
   - supported_roles strictly validated against known roles
   - transport descriptor validity
"""

from __future__ import annotations

from research_lab.agent_control.contracts import AgentProviderDescriptor
from research_lab.agent_control.errors import (
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
)
from research_lab.agent_control.provider import AgentProvider
from research_lab.agent_control.roles import validate_role
from research_lab.agent_control.transport import (
    ProviderConnectionDescriptor,
    ProviderTransportKind,
)


class ProviderRegistry:
    """Explicit, auditable registry for execution backends and their transport profiles."""

    def __init__(self) -> None:
        self._providers: dict[str, AgentProvider] = {}
        self._transports: dict[str, ProviderConnectionDescriptor] = {}

    def register(
        self,
        provider: AgentProvider,
        transport: ProviderConnectionDescriptor | None = None,
    ) -> None:
        """Register a provider and its associated transport descriptor fail-closed."""
        if not hasattr(provider, "describe") or not callable(provider.describe):
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Object {provider} does not implement describe()",
            )

        desc = provider.describe()
        if not isinstance(desc, AgentProviderDescriptor):
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"describe() must return AgentProviderDescriptor, got {type(desc).__name__}",
            )

        name = desc.provider
        if not isinstance(name, str) or not name.strip():
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                "Provider name must be a non-empty string",
            )
        name = name.strip()

        if name in self._providers:
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Duplicate provider registration rejected: '{name}' is already registered",
                details={"provider": name},
            )

        # Validate supported_models
        if not desc.supported_models:
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Provider '{name}' has empty supported_models",
                details={"provider": name},
            )

        if desc.default_model not in desc.supported_models:
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Provider '{name}' default_model '{desc.default_model}' is not in supported_models {desc.supported_models}",
                details={"provider": name, "default_model": desc.default_model},
            )

        # Validate supported_roles
        if not desc.supported_roles:
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Provider '{name}' must declare at least one supported role",
                details={"provider": name},
            )

        for role in desc.supported_roles:
            # validate_role will raise PermissionDeniedError on unknown roles
            validate_role(role)

        # Validate transport descriptor
        resolved_transport: ProviderConnectionDescriptor
        if transport is not None:
            if not isinstance(transport, ProviderConnectionDescriptor):
                raise ProviderError(
                    ProviderErrorCode.PROVIDER_UNAVAILABLE,
                    f"transport must be ProviderConnectionDescriptor, got {type(transport).__name__}",
                )
            resolved_transport = transport
        elif hasattr(provider, "describe_transport") and callable(provider.describe_transport):
            t = provider.describe_transport()
            if not isinstance(t, ProviderConnectionDescriptor):
                raise ProviderError(
                    ProviderErrorCode.PROVIDER_UNAVAILABLE,
                    f"describe_transport() must return ProviderConnectionDescriptor, got {type(t).__name__}",
                )
            resolved_transport = t
        else:
            # Default safe standard local_mcp profile reference if not explicitly declared
            resolved_transport = ProviderConnectionDescriptor(
                transport_kind=ProviderTransportKind.LOCAL_MCP,
                connection_profile_ref=f"{name}-default-profile",
                capabilities=desc.capabilities,
            )

        self._providers[name] = provider
        self._transports[name] = resolved_transport

    def get(self, name: str) -> AgentProvider:
        """Retrieve registered provider by name, failing closed if absent."""
        if name not in self._providers:
            raise ProviderUnavailableError(
                f"Provider '{name}' is not registered in ProviderRegistry",
                details={"provider": name, "registered": sorted(self._providers.keys())},
            )
        return self._providers[name]

    def get_transport(self, name: str) -> ProviderConnectionDescriptor:
        """Retrieve transport connection descriptor for provider."""
        if name not in self._transports:
            raise ProviderUnavailableError(
                f"Transport for provider '{name}' is not found in ProviderRegistry",
                details={"provider": name},
            )
        return self._transports[name]

    def list(self) -> list[AgentProvider]:
        """Return list of all registered providers in registration order."""
        return list(self._providers.values())

    def providers_for_role(self, role: str) -> list[AgentProvider]:
        """Return all registered providers declaring support for the given role."""
        validate_role(role)
        result = []
        for prov in self._providers.values():
            if role in prov.describe().supported_roles:
                result.append(prov)
        return result

    def contains(self, name: str) -> bool:
        """Check whether provider name is registered."""
        return name in self._providers

    def __len__(self) -> int:
        return len(self._providers)
