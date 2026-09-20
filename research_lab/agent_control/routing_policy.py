"""Deterministic routing policy and auditable reason codes (#573 Milestone 1).

Rules:
1. Fixed-priority candidate matching.
2. NO ML router, NO bidding, NO latency/cost optimizers.
3. Separation of Role, Capability, and Transport.
4. Policy model preferences strictly checked against supported_models; no silent substitutions.
5. Missing / unknown quota decision paths are explicit and conservative by default.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from research_lab.agent_control.roles import validate_role
from research_lab.agent_control.transport import ProviderTransportKind


class RouteReasonCode(str, Enum):
    """Machine-readable stable route reason codes for deterministic route identity."""

    PRIMARY_AVAILABLE = "PRIMARY_AVAILABLE"
    PRIMARY_HEALTHY = "PRIMARY_HEALTHY"
    PRIMARY_CONSTRAINED = "PRIMARY_CONSTRAINED"
    PRIMARY_UNAVAILABLE_FALLBACK = "PRIMARY_UNAVAILABLE_FALLBACK"
    PRIMARY_QUOTA_EXHAUSTED = "PRIMARY_QUOTA_EXHAUSTED"
    PRIMARY_QUOTA_UNKNOWN = "PRIMARY_QUOTA_UNKNOWN"
    FALLBACK_DIFFERENT_QUOTA_GROUP = "FALLBACK_DIFFERENT_QUOTA_GROUP"
    FALLBACK_PROVIDER = "FALLBACK_PROVIDER"
    TRANSPORT_NOT_ALLOWED = "TRANSPORT_NOT_ALLOWED"
    CAPABILITY_MISSING = "CAPABILITY_MISSING"
    PREFERRED_PROVIDER_SELECTED = "PREFERRED_PROVIDER_SELECTED"
    PREFERRED_PROVIDER_REJECTED = "PREFERRED_PROVIDER_REJECTED"
    PREFERRED_MODEL_UNSUPPORTED = "PREFERRED_MODEL_UNSUPPORTED"
    DEFAULT_MODEL_SELECTED = "DEFAULT_MODEL_SELECTED"
    QUOTA_UNKNOWN_CONSERVATIVE = "QUOTA_UNKNOWN_CONSERVATIVE"
    ALL_PROVIDERS_EXHAUSTED = "ALL_PROVIDERS_EXHAUSTED"
    ALL_PROVIDERS_UNAVAILABLE = "ALL_PROVIDERS_UNAVAILABLE"
    ALL_QUOTA_EXHAUSTED = "ALL_QUOTA_EXHAUSTED"
    ALL_QUOTA_UNKNOWN = "ALL_QUOTA_UNKNOWN"
    USAGE_SNAPSHOT_STALE = "USAGE_SNAPSHOT_STALE"
    USAGE_SNAPSHOT_INVALID = "USAGE_SNAPSHOT_INVALID"


DEFAULT_ALLOWED_TRANSPORTS = tuple(k.value for k in ProviderTransportKind)


@dataclass(frozen=True)
class RoutingPolicy:
    """Explicit, deterministic routing policy for an abstract role."""

    role: str
    provider_priority: tuple[str, ...]
    model_preference: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    allowed_transports: tuple[str, ...] = DEFAULT_ALLOWED_TRANSPORTS
    required_capabilities: tuple[str, ...] = ()
    allow_missing_usage: bool = True
    allow_unknown_quota_fallback: bool = False
    healthy_threshold: float = 0.30
    max_usage_snapshot_age: float | None = None
    model_quota_bindings: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    policy_version: str = "2026-09-m1"

    def __post_init__(self) -> None:
        validate_role(self.role)

        object.__setattr__(
            self,
            "provider_priority",
            tuple(str(p).strip() for p in self.provider_priority if str(p).strip()),
        )
        object.__setattr__(
            self,
            "allowed_transports",
            tuple(str(t).strip() for t in self.allowed_transports if str(t).strip()),
        )
        object.__setattr__(
            self,
            "required_capabilities",
            tuple(str(c).strip() for c in self.required_capabilities if str(c).strip()),
        )

        frozen_model_pref: dict[str, tuple[str, ...]] = {}
        if isinstance(self.model_preference, Mapping):
            for k, v in self.model_preference.items():
                if isinstance(v, (list, tuple)):
                    frozen_model_pref[str(k)] = tuple(str(m).strip() for m in v)
                elif isinstance(v, str):
                    frozen_model_pref[str(k)] = (v.strip(),)
        object.__setattr__(self, "model_preference", MappingProxyType(frozen_model_pref))

        frozen_bindings: dict[str, Mapping[str, str]] = {}
        if isinstance(self.model_quota_bindings, Mapping):
            for prov_k, model_map in self.model_quota_bindings.items():
                if isinstance(model_map, Mapping):
                    frozen_sub = {str(m): str(grp) for m, grp in model_map.items()}
                    frozen_bindings[str(prov_k)] = MappingProxyType(frozen_sub)
        object.__setattr__(self, "model_quota_bindings", MappingProxyType(frozen_bindings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_missing_usage": self.allow_missing_usage,
            "allow_unknown_quota_fallback": self.allow_unknown_quota_fallback,
            "allowed_transports": list(self.allowed_transports),
            "healthy_threshold": self.healthy_threshold,
            "max_usage_snapshot_age": self.max_usage_snapshot_age,
            "model_preference": {k: list(v) for k, v in self.model_preference.items()},
            "model_quota_bindings": {
                k: dict(v) for k, v in self.model_quota_bindings.items()
            },
            "policy_version": self.policy_version,
            "provider_priority": list(self.provider_priority),
            "required_capabilities": list(self.required_capabilities),
            "role": self.role,
        }
