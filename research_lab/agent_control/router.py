"""Access control authorization and provider-neutral routing core (#573 Milestone 1).

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
   - Fixed-priority candidate matching (policy -> availability -> transport -> quota -> model -> route)
   - Generates auditable facts-only Candidate Trace
   - Enforces least privilege (authorized_permissions strictly preserved from Scope)
   - Accurate error classification (QUOTA_UNAVAILABLE vs PROVIDER_UNAVAILABLE)
   - Usage exact ref binding with snapshot ID and content hash
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentRoute,
    AgentUsageSnapshot,
    ProjectBinding,
    validate_project_binding,
    validate_scope_hash,
    validate_usage_hash,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
    QuotaUnavailableError,
)
from research_lab.agent_control.permissions import (
    enforce_hard_invariants,
    validate_permissions,
)
from research_lab.agent_control.provider import AgentProvider
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.roles import (
    DEFAULT_ROLE_POLICIES,
    AgentRolePolicy,
    validate_role,
)
from research_lab.agent_control.routing_context import RoutingContext
from research_lab.agent_control.routing_policy import (
    RouteReasonCode,
    RoutingPolicy,
)
from research_lab.agent_control.transport import (
    ProviderConnectionDescriptor,
    ProviderTransportKind,
)

POLICY_VERSION = "2026-09-m1"


def authorize(
    role: str,
    requested_permissions: Iterable[str],
    project_binding: ProjectBinding | dict[str, str],
    context: dict[str, Any] | None = None,
    policy: AgentRolePolicy | None = None,
) -> AgentPermissionScope:
    """Authorize requested permissions for a given role under fail-closed semantics.

    Raises PermissionDeniedError on:
    - Unknown role
    - Unknown permission
    - Hard invariant violation (production_trading, live_trading_authorized)
    - Permission elevation beyond policy allowance
    Raises ProjectBindingError on:
    - Missing or invalid project_binding (strict fail-closed)
    """
    validated_role = validate_role(role)
    val_requested = validate_permissions(requested_permissions)
    validated_binding = validate_project_binding(project_binding)

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
        project_binding=validated_binding,
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
    role: str | None = None,
    providers: Sequence[AgentProvider] | None = None,
    authorized_scope: AgentPermissionScope | None = None,
    project_binding: ProjectBinding | dict[str, str] | None = None,
    usage_snapshots: Mapping[str, AgentUsageSnapshot] | None = None,
    policy: AgentRolePolicy | None = None,
    context: dict[str, Any] | None = None,
    *,
    registry: ProviderRegistry | None = None,
    routing_policy: RoutingPolicy | None = None,
    routing_context: RoutingContext | None = None,
) -> AgentRoute:
    """Provider-neutral deterministic Router Core (#573 Milestone 1).

    Evaluates candidates by fixed-priority policy, checks availability, transport compatibility,
    quota window states, and model preferences. Returns auditable AgentRoute with facts-only
    Candidate Trace.
    """
    # 1. Unpack routing context if provided
    if routing_context is not None:
        target_role = routing_context.role
        target_scope = routing_context.authorized_scope
        target_binding = routing_context.project_binding
        snapshots = dict(routing_context.usage_snapshots)
        preferred_provider = routing_context.preferred_provider
        preferred_model = routing_context.preferred_model
        req_caps = set(routing_context.required_capabilities)
        allowed_trans = (
            set(routing_context.allowed_transports)
            if routing_context.allowed_transports is not None
            else None
        )
        ctx_dict = dict(routing_context.caller_constraints)
    else:
        if role is None:
            raise PermissionDeniedError("select_agent requires 'role' or 'routing_context'")
        target_role = role
        if authorized_scope is None:
            raise PermissionDeniedError("select_agent() requires an authorized_scope of type AgentPermissionScope")
        target_scope = authorized_scope
        target_binding = project_binding
        snapshots = dict(usage_snapshots or {})
        preferred_provider = None
        preferred_model = None
        req_caps = set()
        allowed_trans = None
        ctx_dict = context or {}

    validated_role = validate_role(target_role)
    validated_binding = validate_project_binding(target_binding)

    # 2. Validate authorized_scope provenance
    if not isinstance(target_scope, AgentPermissionScope):
        raise PermissionDeniedError("select_agent() requires an authorized_scope of type AgentPermissionScope")
    if not target_scope.is_authorized:
        raise PermissionDeniedError(
            "select_agent() requires an authorized_scope with is_authorized=True",
            details={"role": validated_role, "is_authorized": target_scope.is_authorized},
        )
    validate_scope_hash(target_scope.to_dict())
    if target_scope.role != validated_role:
        raise PermissionDeniedError(
            f"authorized_scope role mismatch: expected '{validated_role}', got '{target_scope.role}'",
            details={"role": validated_role, "scope_role": target_scope.role},
        )
    if dict(target_scope.project_binding) != validated_binding.to_dict():
        raise ProjectBindingError(
            f"authorized_scope project_binding mismatch: scope={target_scope.project_binding}, router={validated_binding.to_dict()}",
            details={"scope_binding": target_scope.project_binding, "router_binding": validated_binding.to_dict()},
        )

    # Validate usage snapshots tamper-resistance fail-closed
    for snap in snapshots.values():
        validate_usage_hash(snap.to_dict())

    is_m1_mode = (
        routing_policy is not None
        or routing_context is not None
        or registry is not None
    )

    # 3. Resolve candidate providers and their transport descriptors
    prov_map: dict[str, AgentProvider] = {}
    trans_map: dict[str, ProviderConnectionDescriptor | None] = {}

    if registry is not None:
        for prov in registry.list():
            p_name = prov.describe().provider
            prov_map[p_name] = prov
            trans_map[p_name] = registry.get_transport(p_name)
    elif providers:
        for prov in providers:
            p_name = prov.describe().provider
            prov_map[p_name] = prov
            if hasattr(prov, "describe_transport") and callable(prov.describe_transport):
                t = prov.describe_transport()
                if not isinstance(t, ProviderConnectionDescriptor):
                    raise ProviderError(
                        ProviderErrorCode.PROVIDER_UNAVAILABLE,
                        f"describe_transport() must return ProviderConnectionDescriptor, got {type(t).__name__ if t is not None else 'None'}",
                    )
                trans_map[p_name] = t
            elif hasattr(prov, "transport_descriptor") and isinstance(prov.transport_descriptor, ProviderConnectionDescriptor):
                trans_map[p_name] = prov.transport_descriptor
            elif is_m1_mode:
                raise ProviderError(
                    ProviderErrorCode.PROVIDER_UNAVAILABLE,
                    f"Missing transport descriptor for provider '{p_name}' in Milestone 1 router mode (cannot assume or default to local_mcp)",
                    details={"provider": p_name},
                )
            else:
                trans_map[p_name] = None
    else:
        raise ProviderUnavailableError("No providers registered with router")

    # 4. Form ordered candidate list
    ordered_provider_names: list[str] = []

    # If routing policy has explicit priority
    if routing_policy is not None:
        for p in routing_policy.provider_priority:
            if p in prov_map and p not in ordered_provider_names:
                ordered_provider_names.append(p)
        # Any other registered providers not listed in priority
        for p in prov_map:
            if p not in ordered_provider_names:
                ordered_provider_names.append(p)
    else:
        # Default order from registry / sequence
        ordered_provider_names = list(prov_map.keys())

    # If preferred_provider is specified, elevate it to the first candidate position
    # (subject to exact full validation)
    if preferred_provider:
        if preferred_provider in ordered_provider_names:
            ordered_provider_names.remove(preferred_provider)
            ordered_provider_names.insert(0, preferred_provider)
        elif preferred_provider in prov_map:
            ordered_provider_names.insert(0, preferred_provider)
        else:
            # Preferred provider unknown/unregistered
            ordered_provider_names.insert(0, preferred_provider)

    # 5. Evaluate candidates with facts-only trace
    candidate_trace: list[dict[str, Any]] = []
    selected_provider: AgentProvider | None = None
    selected_model: str = ""
    selected_snapshot_ref: str | None = None
    selected_transport_ref: str = ""
    route_reason_code: RouteReasonCode = RouteReasonCode.PRIMARY_AVAILABLE
    route_reason: str = ""

    # Tracking reasons for fine-grained error taxonomy
    quota_exhausted_candidates: list[str] = []
    all_role_supporting_candidates: list[str] = []

    for prov_name in ordered_provider_names:
        if prov_name not in prov_map:
            candidate_trace.append(
                {
                    "availability": "UNAVAILABLE",
                    "capability_supported": False,
                    "decision": "skipped",
                    "provider": prov_name,
                    "quota": "unknown",
                    "role_supported": False,
                    "skip_reason": "unregistered provider",
                    "transport": "unknown",
                    "transport_allowed": False,
                }
            )
            continue

        prov = prov_map[prov_name]
        desc = prov.describe()
        transport_desc = trans_map.get(prov_name)
        if transport_desc is not None:
            transport_kind = (
                transport_desc.transport_kind.value
                if isinstance(transport_desc.transport_kind, ProviderTransportKind)
                else str(transport_desc.transport_kind)
            )
            transport_ref_candidate = transport_desc.exact_ref
        else:
            transport_kind = "none"
            transport_ref_candidate = ""

        role_supported = validated_role in desc.supported_roles
        if role_supported:
            all_role_supporting_candidates.append(prov_name)

        # Capabilities check: role capability + policy required capabilities + context capabilities
        policy_caps = set(routing_policy.required_capabilities) if routing_policy else set()
        total_req_caps = req_caps | policy_caps
        prov_caps = set(desc.capabilities)
        capability_supported = total_req_caps.issubset(prov_caps)

        # Transport allowed check
        policy_allowed_trans = (
            set(routing_policy.allowed_transports) if routing_policy else None
        )
        transport_allowed = True
        if transport_desc is not None:
            if policy_allowed_trans is not None and transport_kind not in policy_allowed_trans:
                transport_allowed = False
            if allowed_trans is not None and transport_kind not in allowed_trans:
                transport_allowed = False
        else:
            if is_m1_mode:
                transport_allowed = False

        # Availability check
        avail = prov.availability(validated_role, ctx_dict)
        avail_status = avail.status
        is_available = avail.is_available

        # Quota check
        snapshot = snapshots.get(prov_name)
        quota_status = "healthy"
        quota_viable = True

        if snapshot:
            # Check windows
            has_exhausted = any(
                w.get("status") == "exhausted" or w.get("remaining_fraction") == 0
                for w in snapshot.quota_windows
            )
            has_unknown = any(
                w.get("status") == "unknown" or w.get("remaining_fraction") is None
                for w in snapshot.quota_windows
            )

            if has_exhausted:
                quota_status = "exhausted"
                quota_viable = False
            elif has_unknown:
                allow_unknown = (
                    routing_policy.allow_unknown_quota_fallback
                    if routing_policy
                    else False
                )
                if not allow_unknown:
                    quota_status = "unknown"
                    quota_viable = False
                else:
                    quota_status = "unknown_fallback_allowed"
        else:
            allow_missing = (
                routing_policy.allow_missing_usage if routing_policy else True
            )
            if not allow_missing:
                quota_status = "missing"
                quota_viable = False
            else:
                quota_status = "missing_allowed"

        # Model resolution check
        resolved_model_candidate: str | None = None
        skip_reason: str | None = None

        if not role_supported:
            skip_reason = f"role '{validated_role}' not supported"
        elif not capability_supported:
            missing_caps = sorted(total_req_caps - prov_caps)
            skip_reason = f"missing required capabilities: {missing_caps}"
        elif not transport_allowed:
            skip_reason = f"transport '{transport_kind}' not allowed by policy"
        elif not is_available:
            if avail_status == "RATE_LIMITED":
                skip_reason = f"provider rate limited ({avail_status}: {avail.reason})"
                quota_exhausted_candidates.append(prov_name)
            else:
                skip_reason = f"provider unavailable ({avail_status}: {avail.reason})"
        elif not quota_viable:
            skip_reason = f"quota not viable ({quota_status})"
            if quota_status in ("exhausted", "rate_limited"):
                quota_exhausted_candidates.append(prov_name)
        else:
            # Model preference resolution
            pref_model = preferred_model
            policy_models = (
                routing_policy.model_preference.get(prov_name)
                if routing_policy
                else None
            )

            if pref_model:
                if pref_model in desc.supported_models:
                    resolved_model_candidate = pref_model
                else:
                    # Preferred model unsupported
                    skip_reason = f"preferred model '{pref_model}' unsupported by provider"
            elif policy_models:
                # Find first intersection
                for m in policy_models:
                    if m in desc.supported_models:
                        resolved_model_candidate = m
                        break
                if not resolved_model_candidate:
                    skip_reason = f"none of policy model preferences {policy_models} supported by provider"
            else:
                resolved_model_candidate = desc.default_model

        decision = "selected" if (skip_reason is None and resolved_model_candidate) else "skipped"

        candidate_trace.append(
            {
                "availability": avail_status,
                "capability_supported": capability_supported,
                "decision": decision,
                "provider": prov_name,
                "quota": quota_status,
                "role_supported": role_supported,
                "skip_reason": skip_reason,
                "transport": transport_kind,
                "transport_allowed": transport_allowed,
            }
        )

        if decision == "selected":
            selected_provider = prov
            selected_model = resolved_model_candidate or desc.default_model
            selected_transport_ref = transport_ref_candidate

            if snapshot:
                # Exact bind snapshot_id and usage_content_hash
                selected_snapshot_ref = f"{snapshot.snapshot_id}@{snapshot.usage_content_hash}"
            else:
                selected_snapshot_ref = None

            # Determine reason code
            if preferred_provider and prov_name == preferred_provider:
                route_reason_code = RouteReasonCode.PREFERRED_PROVIDER_SELECTED
                route_reason = f"Selected caller preferred provider '{prov_name}' for role '{validated_role}'"
            elif quota_exhausted_candidates:
                route_reason_code = RouteReasonCode.PRIMARY_QUOTA_EXHAUSTED
                route_reason = f"Selected fallback provider '{prov_name}' due to quota exhaustion of primary candidates"
            elif any(t["decision"] == "skipped" and t["role_supported"] for t in candidate_trace[:-1]):
                route_reason_code = RouteReasonCode.PRIMARY_UNAVAILABLE_FALLBACK
                route_reason = f"Selected fallback provider '{prov_name}' for role '{validated_role}'"
            else:
                route_reason_code = RouteReasonCode.PRIMARY_AVAILABLE
                route_reason = f"Selected primary provider '{prov_name}' for role '{validated_role}'"
            break

    # 6. Check if any provider was selected
    if not selected_provider:
        # Fine-grained error classification (#573 Milestone 1):
        # Under Milestone 1 invocation (routing_policy, routing_context, or registry):
        # If all candidates that support the role failed SOLELY because of quota exhaustion or rate limit,
        # raise QuotaUnavailableError (QUOTA_UNAVAILABLE), NOT ProviderUnavailableError!
        is_m1_mode = (
            routing_policy is not None
            or routing_context is not None
            or registry is not None
        )
        viable_role_candidates = [
            t["provider"]
            for t in candidate_trace
            if t["role_supported"] and t["capability_supported"] and t["transport_allowed"]
        ]
        if (
            is_m1_mode
            and viable_role_candidates
            and all(prov in quota_exhausted_candidates for prov in viable_role_candidates)
        ):
            raise QuotaUnavailableError(
                f"All providers supporting role '{validated_role}' are quota exhausted or rate limited",
                details={
                    "candidate_trace": candidate_trace,
                    "exhausted_providers": quota_exhausted_candidates,
                    "role": validated_role,
                },
            )

        if not all_role_supporting_candidates:
            raise ProviderUnavailableError(
                f"No available provider supports role '{validated_role}'",
                details={"candidate_trace": candidate_trace, "role": validated_role},
            )

        raise ProviderUnavailableError(
            f"All providers supporting role '{validated_role}' are unavailable or quota exhausted",
            details={"candidate_trace": candidate_trace, "role": validated_role},
        )

    # 7. Construct and return immutable AgentRoute preserving LEAST PRIVILEGE
    return AgentRoute.create(
        role=validated_role,
        provider=selected_provider.describe().provider,
        resolved_model=selected_model,
        policy_version=POLICY_VERSION,
        route_reason=route_reason,
        usage_snapshot_ref=selected_snapshot_ref,
        project_binding=validated_binding,
        authorized_permissions=list(target_scope.authorized_permissions),
        authorized_scope=target_scope,
        route_reason_code=route_reason_code.value,
        transport_ref=selected_transport_ref,
        candidate_trace=candidate_trace,
    )
