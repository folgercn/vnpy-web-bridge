"""Transport abstraction and connection descriptors (#573 Milestone 1).

Architecture Rule:
Role -> Access Control -> Agent Router -> Agent Provider -> Provider Transport -> Concrete transport runtime

Rules:
1. role != provider != transport != model.
2. Domain contracts only express transport capability, kind, and reference identity.
3. NEVER expose secrets, URLs, tokens, passwords, sockets, or session IDs in descriptors.
4. Milestone 1 ONLY defines contracts and identity. No real transports (MCP/SSE/HTTP/SDK) are implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from research_lab.agent_control.errors import ProviderError, ProviderErrorCode

# Sensitive substring patterns prohibited from appearing in connection descriptors
_SENSITIVE_PATTERNS = frozenset(
    {
        "http://",
        "https://",
        "ws://",
        "wss://",
        "token",
        "secret",
        "password",
        "bearer",
        "api_key",
        "apikey",
        ".sock",
        "session_id",
        "private_key",
    }
)


class ProviderTransportKind(str, Enum):
    """Supported transport categories for execution backends."""

    LOCAL_MCP = "local_mcp"
    REMOTE_MCP = "remote_mcp"
    DIRECT_SDK = "direct_sdk"


@dataclass(frozen=True)
class ProviderConnectionDescriptor:
    """Neutral descriptor defining the transport identity and capability of a provider."""

    transport_kind: ProviderTransportKind | str
    connection_profile_ref: str
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # 1. Validate transport_kind
        kind_val = (
            self.transport_kind.value
            if isinstance(self.transport_kind, ProviderTransportKind)
            else str(self.transport_kind)
        )
        valid_kinds = {k.value for k in ProviderTransportKind}
        if kind_val not in valid_kinds:
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Unknown or unsupported transport kind '{self.transport_kind}'. Valid kinds: {sorted(valid_kinds)}",
                details={"transport_kind": str(self.transport_kind)},
            )
        object.__setattr__(self, "transport_kind", kind_val)

        # 2. Validate connection_profile_ref
        if not isinstance(self.connection_profile_ref, str) or not self.connection_profile_ref.strip():
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                "connection_profile_ref must be a non-empty string reference",
            )
        ref = self.connection_profile_ref.strip()
        object.__setattr__(self, "connection_profile_ref", ref)

        # 3. Security audit: forbid runtime secrets/endpoints
        ref_lower = ref.lower()
        for pattern in _SENSITIVE_PATTERNS:
            if pattern in ref_lower:
                raise ProviderError(
                    ProviderErrorCode.PERMISSION_DENIED,
                    f"ProviderConnectionDescriptor cannot contain sensitive pattern '{pattern}' in profile ref",
                    details={"sensitive_pattern": pattern, "connection_profile_ref": ref},
                )

        # 4. Capabilities normalization
        caps = tuple(str(c).strip() for c in self.capabilities if str(c).strip())
        object.__setattr__(self, "capabilities", caps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": list(self.capabilities),
            "connection_profile_ref": self.connection_profile_ref,
            "transport_kind": (
                self.transport_kind.value
                if isinstance(self.transport_kind, ProviderTransportKind)
                else str(self.transport_kind)
            ),
        }
