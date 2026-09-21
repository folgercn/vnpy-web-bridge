"""Routing execution context and caller preference specifications (#573 Milestone 1).

Rules:
1. RoutingContext encapsulates the role, scope, project binding, and snapshots for a single routing run.
2. Caller overrides (preferred_provider, preferred_model, caller_constraints) are preferences ONLY.
3. Overrides CANNOT bypass policy or authorization scope.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentUsageSnapshot,
    ProjectBinding,
    validate_project_binding,
    validate_scope_hash,
)
from research_lab.agent_control.errors import PermissionDeniedError, ProjectBindingError
from research_lab.agent_control.roles import validate_role


@dataclass(frozen=True)
class RoutingContext:
    """Context object specifying inputs, scopes, and caller preferences for routing."""

    role: str
    authorized_scope: AgentPermissionScope
    project_binding: ProjectBinding
    usage_snapshots: Mapping[str, AgentUsageSnapshot] = field(default_factory=dict)
    required_capabilities: tuple[str, ...] = ()
    preferred_provider: str | None = None
    preferred_model: str | None = None
    allowed_transports: tuple[str, ...] | None = None
    caller_constraints: Mapping[str, Any] = field(default_factory=dict)
    quota_facts: Mapping[str, Any] = field(default_factory=dict)
    current_time: str | None = None

    def __post_init__(self) -> None:
        validated_role = validate_role(self.role)

        # Validate authorized_scope
        if not isinstance(self.authorized_scope, AgentPermissionScope):
            raise PermissionDeniedError(
                f"authorized_scope must be an AgentPermissionScope, got {type(self.authorized_scope).__name__}"
            )
        if not self.authorized_scope.is_authorized:
            raise PermissionDeniedError(
                "authorized_scope must have is_authorized=True",
                details={"role": validated_role},
            )
        validate_scope_hash(self.authorized_scope.to_dict())

        if self.authorized_scope.role != validated_role:
            raise PermissionDeniedError(
                f"authorized_scope role mismatch: scope={self.authorized_scope.role}, context={validated_role}",
                details={"scope_role": self.authorized_scope.role, "context_role": validated_role},
            )

        # Validate project_binding
        validated_binding = validate_project_binding(self.project_binding)
        if dict(self.authorized_scope.project_binding) != validated_binding.to_dict():
            raise ProjectBindingError(
                "authorized_scope project_binding mismatch with RoutingContext project_binding",
                details={
                    "scope_binding": dict(self.authorized_scope.project_binding),
                    "context_binding": validated_binding.to_dict(),
                },
            )

        # Freeze containers
        object.__setattr__(
            self,
            "required_capabilities",
            tuple(str(c).strip() for c in self.required_capabilities if str(c).strip()),
        )
        if self.allowed_transports is not None:
            object.__setattr__(
                self,
                "allowed_transports",
                tuple(str(t).strip() for t in self.allowed_transports if str(t).strip()),
            )

        frozen_snapshots = {}
        if isinstance(self.usage_snapshots, Mapping):
            for k, v in self.usage_snapshots.items():
                if isinstance(v, AgentUsageSnapshot):
                    frozen_snapshots[str(k)] = v
        object.__setattr__(self, "usage_snapshots", MappingProxyType(frozen_snapshots))

        frozen_facts = {}
        if isinstance(self.quota_facts, Mapping):
            for k, v in self.quota_facts.items():
                frozen_facts[str(k)] = v
        object.__setattr__(self, "quota_facts", MappingProxyType(frozen_facts))

        frozen_constraints = {}
        if isinstance(self.caller_constraints, Mapping):
            for k, v in self.caller_constraints.items():
                frozen_constraints[str(k)] = v
        object.__setattr__(self, "caller_constraints", MappingProxyType(frozen_constraints))
