"""Role definitions and baseline role policies (#573 Milestone 0).

Roles represent business research responsibilities, strictly decoupled from
providers (e.g., Antigravity, OpenAI) and models (e.g., gemini-3.8-flash-high).
- Unknown role: DENY / raise PermissionDeniedError
- Worker roles: delegation_depth = 0 only (cannot delegate to nested subagents)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from research_lab.agent_control.errors import PermissionDeniedError
from research_lab.agent_control.permissions import (
    AgentPermission,
    enforce_hard_invariants,
    validate_permissions,
)


class AgentRole(str, Enum):
    """Initial set of business research roles."""

    ALPHA_GENERATOR = "alpha_generator"
    RESEARCH_SYNTHESIZER = "research_synthesizer"
    DATA_RESEARCHER = "data_researcher"
    CODE_RESEARCHER = "code_researcher"
    EXTERNAL_RESEARCHER = "external_researcher"


ALL_ROLES = frozenset(r.value for r in AgentRole)


@dataclass(frozen=True)
class AgentRolePolicy:
    """Immutable policy governing what a specific role is permitted to do."""

    role: str
    allowed_permissions: frozenset[str]
    max_delegation_depth: int = 0
    can_delegate: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        # Validate role
        if self.role not in ALL_ROLES:
            raise PermissionDeniedError(
                f"Unknown role '{self.role}' cannot be configured in role policy",
                details={"role": self.role, "known_roles": sorted(ALL_ROLES)},
            )
        # Validate permissions fail-closed
        validated = validate_permissions(self.allowed_permissions)
        # Enforce hard invariants: trading permissions can never be in allowed_permissions
        enforce_hard_invariants(validated)


def validate_role(role_name: str) -> str:
    """Validate a role string against the closed catalog.

    Raises PermissionDeniedError on unknown role (fail-closed).
    """
    if not isinstance(role_name, str):
        raise PermissionDeniedError(f"Role identifier must be a string, got {type(role_name).__name__}")
    if role_name not in ALL_ROLES:
        raise PermissionDeniedError(
            f"Unknown role '{role_name}' rejected under fail-closed policy",
            details={"requested_role": role_name, "known_roles": sorted(ALL_ROLES)},
        )
    return role_name


# Baseline default policies reflecting Section 5 of Milestone 0 specifications
DEFAULT_ROLE_POLICIES: dict[str, AgentRolePolicy] = {
    AgentRole.ALPHA_GENERATOR.value: AgentRolePolicy(
        role=AgentRole.ALPHA_GENERATOR.value,
        allowed_permissions=frozenset({
            AgentPermission.READ_RESEARCH_MEMORY.value,
            AgentPermission.CREATE_HYPOTHESIS.value,
            AgentPermission.REVISE_HYPOTHESIS.value,
        }),
        max_delegation_depth=0,
        can_delegate=False,
        description="Generates alpha hypothesis candidates; cannot execute screening or write decisions",
    ),
    AgentRole.RESEARCH_SYNTHESIZER.value: AgentRolePolicy(
        role=AgentRole.RESEARCH_SYNTHESIZER.value,
        allowed_permissions=frozenset({
            AgentPermission.READ_RESEARCH_MEMORY.value,
            AgentPermission.READ_RESULT_STORE.value,
        }),
        max_delegation_depth=0,
        can_delegate=False,
        description="Reads and organizes research materials; cannot generate scientific decisions",
    ),
    AgentRole.DATA_RESEARCHER.value: AgentRolePolicy(
        role=AgentRole.DATA_RESEARCHER.value,
        allowed_permissions=frozenset({
            AgentPermission.READ_RESEARCH_MEMORY.value,
            AgentPermission.READ_RESULT_STORE.value,
        }),
        max_delegation_depth=0,
        can_delegate=False,
        description="Explores datasets and features; cannot trigger scientific promotions/rejections",
    ),
    AgentRole.CODE_RESEARCHER.value: AgentRolePolicy(
        role=AgentRole.CODE_RESEARCHER.value,
        allowed_permissions=frozenset({
            AgentPermission.READ_RESULT_STORE.value,
        }),
        max_delegation_depth=0,
        can_delegate=False,
        description="Assists with code inspection and tools; strictly separated from trading authority",
    ),
    AgentRole.EXTERNAL_RESEARCHER.value: AgentRolePolicy(
        role=AgentRole.EXTERNAL_RESEARCHER.value,
        allowed_permissions=frozenset(),
        max_delegation_depth=0,
        can_delegate=False,
        description="Researches external papers and literature; cannot write scientific records or access private stores",
    ),
}
