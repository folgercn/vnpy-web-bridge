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
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
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

    return AgentPermissionScope(
        role=validated_role,
        requested_permissions=tuple(val_requested),
        authorized_permissions=tuple(authorized),
        denied_permissions=tuple(denied),
        is_authorized=True,
        context=context or {},
    )


def enforce_no_nested_delegation(
    delegation_depth: int,
    parent_task_ref: dict[str, str] | None = None,
) -> None:
    """Enforce the strict No Nested Agent rule.

    depth = 0: orchestrator level; can submit worker tasks.
    depth >= 1: worker level; cannot delegate or invoke any further subagents.
    """
    if delegation_depth >= 1:
        raise PermissionDeniedError(
            f"Nested agent delegation prohibited: worker task at delegation_depth={delegation_depth} "
            f"cannot spawn or delegate subagents",
            details={
                "delegation_depth": delegation_depth,
                "parent_task_ref": parent_task_ref,
            },
        )


def validate_project_binding(
    task_binding: ProjectBinding | dict[str, str],
    expected_binding: ProjectBinding | dict[str, str],
) -> None:
    """Validate project and workspace binding fail-closed.

    Rejects any mismatched project_id or workspace_identity without silent fallback.
    """
    tb = task_binding.to_dict() if isinstance(task_binding, ProjectBinding) else dict(task_binding)
    eb = expected_binding.to_dict() if isinstance(expected_binding, ProjectBinding) else dict(expected_binding)

    if tb.get("project_id") != eb.get("project_id"):
        raise ProjectBindingError(
            f"Project ID mismatch: expected '{eb.get('project_id')}', got '{tb.get('project_id')}'",
            details={"expected_project_id": eb.get("project_id"), "actual_project_id": tb.get("project_id")},
        )

    if tb.get("workspace_identity") != eb.get("workspace_identity"):
        raise ProjectBindingError(
            f"Workspace identity mismatch: expected '{eb.get('workspace_identity')}', got '{tb.get('workspace_identity')}'",
            details={
                "expected_workspace_identity": eb.get("workspace_identity"),
                "actual_workspace_identity": tb.get("workspace_identity"),
            },
        )


def select_agent(
    role: str,
    providers: Sequence[AgentProvider],
    usage_snapshots: dict[str, AgentUsageSnapshot] | None = None,
    policy: AgentRolePolicy | None = None,
    project_binding: ProjectBinding | dict[str, str] | None = None,
    context: dict[str, Any] | None = None,
) -> AgentRoute:
    """Router skeleton: selects an execution backend according to fixed-priority criteria.

    Order:
    1. Validate role & policy
    2. Filter providers that declare support for this role
    3. Check provider availability
    4. Check quota window states (skip exhausted, preserve unknown)
    5. Choose candidate by fixed list order
    6. Construct auditable AgentRoute
    """
    validated_role = validate_role(role)
    active_policy = policy or DEFAULT_ROLE_POLICIES.get(validated_role)
    if not active_policy:
        raise PermissionDeniedError(f"No policy configured for role '{validated_role}'")

    if not providers:
        raise ProviderUnavailableError("No providers registered with router")

    binding = project_binding or {
        "project_id": "unspecified",
        "workspace_identity": "unspecified",
        "binding_mode": "strict",
    }

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

    return AgentRoute.create(
        role=validated_role,
        provider=selected_provider.describe().provider,
        resolved_model=selected_model,
        policy_version=POLICY_VERSION,
        route_reason=route_reason,
        usage_snapshot_ref=selected_snapshot_ref,
        project_binding=binding,
        authorized_permissions=sorted(active_policy.allowed_permissions),
    )
