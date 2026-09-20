"""Explicit permission model and hard invariant guards (#573 Milestone 0).

Strict fail-closed permission evaluation.
- Unknown permission: DENY / raise PermissionDeniedError
- production_trading: HARD INVARIANT FALSE FOR ALL ROLES
- live_trading_authorized: HARD INVARIANT FALSE FOR ALL ROLES
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable

from research_lab.agent_control.errors import PermissionDeniedError


class AgentPermission(str, Enum):
    """Explicit agent permissions for Research Lab access control."""

    READ_RESEARCH_MEMORY = "read_research_memory"
    READ_RESULT_STORE = "read_result_store"
    CREATE_HYPOTHESIS = "create_hypothesis"
    REVISE_HYPOTHESIS = "revise_hypothesis"
    REQUEST_SCREENING = "request_screening"
    EXECUTE_SCREENING = "execute_screening"
    WRITE_RESEARCH_MEMORY = "write_research_memory"
    INVOKE_CRITIC = "invoke_critic"
    PRODUCTION_TRADING = "production_trading"
    LIVE_TRADING_AUTHORIZED = "live_trading_authorized"


ALL_PERMISSIONS = frozenset(p.value for p in AgentPermission)

# Absolute hard invariant permissions: NO role may EVER be granted these under SIMNOW_LAB
HARD_INVARIANT_FORBIDDEN_PERMISSIONS = frozenset({
    AgentPermission.PRODUCTION_TRADING.value,
    AgentPermission.LIVE_TRADING_AUTHORIZED.value,
})


def validate_permission(name: str) -> str:
    """Validate a single permission string against the closed catalog.

    Raises PermissionDeniedError on unknown permission (fail-closed).
    """
    if not isinstance(name, str):
        raise PermissionDeniedError(f"Permission identifier must be a string, got {type(name).__name__}")
    if name not in ALL_PERMISSIONS:
        raise PermissionDeniedError(
            f"Unknown permission '{name}' rejected under fail-closed policy",
            details={"requested_permission": name, "known_permissions": sorted(ALL_PERMISSIONS)},
        )
    return name


def validate_permissions(names: Iterable[str]) -> list[str]:
    """Validate a collection of permission strings, deduplicating while preserving order.

    Fails closed on any unknown permission.
    """
    validated = []
    seen = set()
    for name in names:
        val = validate_permission(name)
        if val not in seen:
            seen.add(val)
            validated.append(val)
    return validated


def enforce_hard_invariants(requested_permissions: Iterable[str]) -> None:
    """Enforce the absolute production/trading boundary.

    Raises PermissionDeniedError immediately if production_trading or
    live_trading_authorized is requested or attempted to be granted.
    """
    violating = set(requested_permissions) & HARD_INVARIANT_FORBIDDEN_PERMISSIONS
    if violating:
        raise PermissionDeniedError(
            f"Hard invariant violation: permissions {sorted(violating)} are strictly prohibited "
            f"for all agents in SIMNOW_LAB",
            details={"violating_permissions": sorted(violating)},
        )
