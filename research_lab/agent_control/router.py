"""Access control authorization and provider-neutral routing skeleton (#573 Milestone 0).

Rules:
1. authorize():
   - Validates role & permissions against closed catalogs (fail-closed)
   - Hard invariant: production_trading and live_trading_authorized are DENIED with absolute prejudice
   - Unprivileged permission elevation rejected with PermissionDeniedError
2. enforce_no_nested_delegation():
   - depth == 0: orchestrator may submit worker
   - depth >= 1: worker CANNOT delegate; raises PermissionDeniedError
3. validate_project_binding():
   - project_id and workspace_identity must match strictly; raises ProjectBindingError
   - Never falls back to desktop default
4. select_agent():
   - Fixed-priority candidate matching (policy -> availability -> quota -> route)
   - No ML router, bidding, or complex cost optimizers
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentRoute,
    AgentUsageSnapshot,
    ProjectBinding,
    validate_project_binding,
    validate_scope_hash,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProviderUnavailableError,
)
from research_lab.agent_control.permissions import (
    enforce_hard_invariants,
    validate_permissions,
)
from research_lab.agent_control.provider import AgentProvider
from research_lab.agent_control.roles import (
    DEFAULT_ROLE_POLICIES,
    AgentRolePolicy,
    validate_role,
)

POLICY_VERSION = "2026-09-m0"


def authorize(
    role: str,
    requested_permissions: Iterable[str],
    context: dict[str, Any] | None = None,
    policy: AgentRolePolicy | None = None,
) -> AgentPermissionScope:
    """Authorize requested permissions for a given role under fail-closed semantics.

    Raises PermissionDeniedError on:
    - Unknown role
    - Unknown permission
    - Hard invariant violation (production_trading, live_trading_authorized)
    - Permission elevation beyond policy allowance
    """
    validated_role = validate_role(role)
    val_requested = validate_permissions(requested_permissions)

    # Hard invariant check: never allow trading permissions
    enforce_hard_invariants(val_requested)

    active_policy = policy or DEFAULT_ROLE_POLICIES.get(validated_role)
    if not active_policy:
        raise PermissionDeniedError(
            f"No policy configured for role '{validated_role}'",
            details={"role": validated_role},
        )

    allowed = set(active_policy.allowed_permissions)
    authorized = []
    denied = []

    for perm in val_requested:
        if perm in allowed:
            authorized.append(perm)
        else:
            denied.append(perm)

    if denied:
        raise PermissionDeniedError(
            f"Permission denied for role '{validated_role}': requested unauthorized permissions {sorted(denied)}",
            details={
                "role": validated_role,
                "denied_permissions": sorted(denied),
                "allowed_permissions": sorted(allowed),
            },
        )

    return AgentPermissionScope.create(
        role=validated_role,
        requested_permissions=val_requested,
        authorized_permissions=authorized,
        denied_permissions=denied,
        is_authorized=True,
        policy_version=POLICY_VERSION,
        context=context or {},
    )


def enforce_no_nested_delegation(
    role: str,
    delegation_depth: int,
    parent_task_ref: dict[str, str] | None = None,
    policy: AgentRolePolicy | None = None,
) -> None:
    """Enforce strict No Nested Agent rule and delegation authorization.

    Rules:
    1. depth >= 1: worker level; CANNOT delegate under any circumstances.
    2. role policy: must have can_delegate=True to delegate subagents.
       depth=0 is a necessary condition, but NOT a sufficient condition.
       Currently all default worker roles have can_delegate=False and cannot delegate.
    """
    # 1. Depth check
    if delegation_depth >= 1:
        raise PermissionDeniedError(
            f"Nested agent delegation prohibited: worker task at delegation_depth={delegation_depth} "
            f"cannot spawn or delegate subagents",
            details={
                "role": role,
                "delegation_depth": delegation_depth,
                "parent_task_ref": parent_task_ref,
            },
        )

    # 2. Role policy can_delegate check
    validated_role = validate_role(role)
    active_policy = policy or DEFAULT_ROLE_POLICIES.get(validated_role)
    if not active_policy or not active_policy.can_delegate:
        raise PermissionDeniedError(
            f"Role '{validated_role}' is not permitted to delegate subagents (can_delegate=False)",
            details={"role": validated_role, "delegation_depth": delegation_depth},
        )


def select_agent(
    role: str,
    providers: Sequence[AgentProvider],
    authorized_scope: AgentPermissionScope,
    project_binding: ProjectBinding | dict[str, str],
    usage_snapshots: dict[str, AgentUsageSnapshot] | None = None,
    policy: AgentRolePolicy | None = None,
    context: dict[str, Any] | None = None,
) -> AgentRoute:
    """Router skeleton: selects an execution backend according to fixed-priority criteria.

    Order:
    1. Validate role, policy, project_binding, and authorized_scope (fail-closed)
    2. Filter providers that declare support for this role
    3. Check provider availability
    4. Check quota window states (skip exhausted, preserve unknown)
    5. Choose candidate by fixed list order
    6. Construct auditable AgentRoute with LEAST PRIVILEGE authorized_permissions
    """
    validated_role = validate_role(role)
    active_policy = policy or DEFAULT_ROLE_POLICIES.get(validated_role)
    if not active_policy:
        raise PermissionDeniedError(f"No policy configured for role '{validated_role}'")

    # Validate project_binding fail-closed (strictly no placeholder/unspecified fallback)
    validated_binding = validate_project_binding(project_binding)

    # Validate authorized_scope provenance
    if not isinstance(authorized_scope, AgentPermissionScope):
        raise PermissionDeniedError("select_agent() requires an authorized_scope of type AgentPermissionScope")
    validate_scope_hash(authorized_scope.to_dict())
    if authorized_scope.role != validated_role:
        raise PermissionDeniedError(
            f"authorized_scope role mismatch: expected '{validated_role}', got '{authorized_scope.role}'",
            details={"role": validated_role, "scope_role": authorized_scope.role},
        )

    if not providers:
        raise ProviderUnavailableError("No providers registered with router")

    # 1. Filter by role support
    candidates: list[AgentProvider] = []
    for prov in providers:
        desc = prov.describe()
        if validated_role in desc.supported_roles:
            candidates.append(prov)

    if not candidates:
        raise ProviderUnavailableError(
            f"No available provider supports role '{validated_role}'",
            details={"role": validated_role},
        )

    # 2. Match first available provider with viable quota
    selected_provider: AgentProvider | None = None
    selected_model: str = ""
    selected_snapshot_ref: str | None = None
    route_reason: str = ""

    for prov in candidates:
        desc = prov.describe()
        avail = prov.availability(validated_role, context)
        if not avail.is_available:
            continue

        # Check quota if snapshot provided
        prov_name = desc.provider
        snapshot = (usage_snapshots or {}).get(prov_name)
        snapshot_ref = snapshot.snapshot_id if snapshot else None

        if snapshot:
            # Check for explicitly exhausted windows
            is_exhausted = any(
                w.get("status") == "exhausted" or w.get("remaining_fraction") == 0
                for w in snapshot.quota_windows
            )
            if is_exhausted:
                continue

        selected_provider = prov
        selected_model = desc.default_model
        selected_snapshot_ref = snapshot_ref
        route_reason = f"Selected first matching available provider '{prov_name}' for role '{validated_role}'"
        break

    if not selected_provider:
        raise ProviderUnavailableError(
            f"All providers supporting role '{validated_role}' are unavailable or quota exhausted",
            details={"role": validated_role},
        )

    # LEAST PRIVILEGE: Carry only the exact authorized_permissions from the scope,
    # NEVER expand to the entire role policy!
    return AgentRoute.create(
        role=validated_role,
        provider=selected_provider.describe().provider,
        resolved_model=selected_model,
        policy_version=POLICY_VERSION,
        route_reason=route_reason,
        usage_snapshot_ref=selected_snapshot_ref,
        project_binding=validated_binding,
        authorized_permissions=list(authorized_scope.authorized_permissions),
        authorized_scope=authorized_scope,
    )
