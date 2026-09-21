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
    TamperDetectionError,
)
from research_lab.agent_control.permissions import (
    enforce_hard_invariants,
    validate_permissions,
)
from research_lab.agent_control.provider import AgentProvider
from research_lab.agent_control.quota import (
    AntigravityQuotaNormalizer,
    ModelQuotaBinding,
    ProviderQuotaFacts,
    QuotaGroupSnapshot,
    QuotaStatus,
    QuotaWindowSnapshot,
    evaluate_group_status,
    evaluate_window_status,
)
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
    selected_quota_group: str = ""
    selected_binding_profile_version: str = ""
    route_reason_code: RouteReasonCode = RouteReasonCode.PRIMARY_AVAILABLE
    route_reason: str = ""

    # Quota policy parameters
    current_time = routing_context.current_time if routing_context else None
    context_quota_facts = routing_context.quota_facts if routing_context else {}
    healthy_threshold = routing_policy.healthy_threshold if routing_policy else 0.30
    active_policy_version = routing_policy.policy_version if routing_policy else POLICY_VERSION
    if routing_policy and routing_policy.max_usage_snapshot_age is not None:
        max_usage_snapshot_age = routing_policy.max_usage_snapshot_age
    elif active_policy_version.endswith("-m3") or active_policy_version == "2026-09-m3":
        max_usage_snapshot_age = 300.0
    else:
        max_usage_snapshot_age = None

    # Tracking reasons for fine-grained error taxonomy
    quota_exhausted_candidates: list[str] = []
    all_role_supporting_candidates: list[str] = []
    stale_snapshot_candidates: list[str] = []
    missing_snapshot_candidates: list[str] = []
    provider_mismatch_candidates: list[str] = []
    all_unknown_quota_candidates: list[str] = []
    exhausted_group_ids_by_provider: dict[str, set[str]] = {}

    for prov_name in ordered_provider_names:
        if prov_name not in prov_map:
            candidate_trace.append(
                {
                    "availability": "UNAVAILABLE",
                    "capability_supported": False,
                    "decision": "skipped",
                    "model": "unknown",
                    "provider": prov_name,
                    "quota": "unknown",
                    "quota_group": "unknown",
                    "quota_status": "unknown",
                    "quota_windows": [],
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

        # Pre-resolve candidate models
        candidate_models: list[str] = []
        if preferred_model:
            candidate_models = [preferred_model]
        elif routing_policy and routing_policy.model_preference.get(prov_name):
            candidate_models = list(routing_policy.model_preference.get(prov_name))
        elif desc.supported_models:
            candidate_models = [desc.default_model]
        else:
            candidate_models = ["default"]

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
        facts: ProviderQuotaFacts | None = None
        quota_status_str = "healthy"
        quota_viable = True
        skip_reason: str | None = None

        if snapshot is not None:
            if snapshot.provider != prov_name:
                quota_status_str = "provider_mismatch"
                quota_viable = False
                skip_reason = f"Usage snapshot provider '{snapshot.provider}' does not match candidate '{prov_name}'"
                provider_mismatch_candidates.append(prov_name)
            else:
                effective_max_age = max_usage_snapshot_age if max_usage_snapshot_age is not None else float("inf")
                if prov_name in context_quota_facts:
                    facts = context_quota_facts[prov_name]
                    # P1-2: Validate facts against snapshot ground truth
                    validate_usage_hash(snapshot.to_dict())
                    if facts.provider != prov_name or facts.provider != snapshot.provider:
                        raise TamperDetectionError(
                            f"quota_facts provider '{facts.provider}' mismatch with snapshot provider '{snapshot.provider}'"
                        )
                    if facts.captured_at != snapshot.captured_at:
                        raise TamperDetectionError(
                            f"quota_facts captured_at '{facts.captured_at}' mismatch with snapshot '{snapshot.captured_at}'"
                        )
                    expected_ref = f"{snapshot.snapshot_id}@{snapshot.usage_content_hash}"
                    if facts.snapshot_ref != expected_ref and facts.snapshot_ref != snapshot.snapshot_id:
                        raise TamperDetectionError(
                            f"quota_facts snapshot_ref '{facts.snapshot_ref}' mismatch with snapshot expected ref '{expected_ref}'"
                        )
                    # Anti-forgery: Check if ground truth snapshot windows contradict injected healthy facts
                    for raw_w in snapshot.quota_windows:
                        rem = raw_w.get("remaining_fraction")
                        if rem is not None:
                            try:
                                rem_val = float(rem)
                            except (ValueError, TypeError):
                                rem_val = None
                            if rem_val is not None and rem_val <= 0.0:
                                w_name = str(raw_w.get("window") or raw_w.get("bucketId") or "")
                                for g in facts.groups:
                                    group_matches = False
                                    if (
                                        snapshot.model_group
                                        and (
                                            g.display_name == snapshot.model_group
                                            or g.group_id == snapshot.model_group
                                        )
                                    ) or len(facts.groups) == 1:
                                        group_matches = True
                                    elif any(gw.window == w_name for gw in g.windows):
                                        if snapshot.model_group and g.display_name != snapshot.model_group:
                                            group_matches = False
                                        else:
                                            group_matches = True

                                    if group_matches and g.status == QuotaStatus.HEALTHY:
                                        raise TamperDetectionError(
                                            f"Injected quota_facts group '{g.group_id}' claims HEALTHY status while underlying snapshot window '{w_name}' is exhausted"
                                        )
                    if AntigravityQuotaNormalizer.is_snapshot_stale(
                        snapshot.captured_at,
                        max_age_seconds=effective_max_age,
                        current_time=current_time,
                    ):
                        try:
                            object.__setattr__(facts, "is_stale", True)
                        except (AttributeError, TypeError):
                            pass
                elif prov_name == "antigravity" or snapshot.provider == "antigravity":
                    custom_bindings = []
                    if routing_policy and prov_name in routing_policy.model_quota_bindings:
                        for m_k, g_v in routing_policy.model_quota_bindings[prov_name].items():
                            custom_bindings.append(
                                ModelQuotaBinding(provider=prov_name, model=m_k, quota_group_id=g_v)
                            )
                    facts = AntigravityQuotaNormalizer.normalize(
                        snapshot,
                        healthy_threshold=healthy_threshold,
                        max_age_seconds=effective_max_age,
                        current_time=current_time,
                        custom_model_bindings=custom_bindings,
                    )
                else:
                    is_stale = False
                    if max_usage_snapshot_age is not None:
                        is_stale = AntigravityQuotaNormalizer.is_snapshot_stale(
                            snapshot.captured_at,
                            max_age_seconds=max_usage_snapshot_age,
                            current_time=current_time,
                        )
                    parsed_windows = []
                    for w in snapshot.quota_windows:
                        rem = w.get("remaining_fraction")
                        rem_val = float(rem) if rem is not None else None
                        parsed_windows.append(
                            QuotaWindowSnapshot(
                                window=str(w.get("window", "unknown")),
                                remaining_fraction=rem_val,
                                reset_time=str(w.get("reset_time")) if w.get("reset_time") is not None else None,
                                status=evaluate_window_status(rem_val, healthy_threshold=healthy_threshold),
                            )
                        )
                    grp_status = evaluate_group_status(parsed_windows)
                    grp = QuotaGroupSnapshot(
                        group_id=snapshot.model_group or "default-group",
                        display_name=snapshot.model_group or "Default Group",
                        status=grp_status,
                        windows=tuple(parsed_windows),
                        bound_models=tuple(desc.supported_models),
                    )
                    bindings = [
                        ModelQuotaBinding(provider=prov_name, model=m, quota_group_id=grp.group_id)
                        for m in desc.supported_models
                    ]
                    snapshot_ref = f"{snapshot.snapshot_id}@{snapshot.usage_content_hash}"
                    facts = ProviderQuotaFacts(
                        provider=prov_name,
                        snapshot_ref=snapshot_ref,
                        captured_at=snapshot.captured_at,
                        groups=(grp,),
                        model_bindings=tuple(bindings),
                        is_stale=is_stale,
                    )

                if facts.is_stale:
                    quota_status_str = "stale"
                    quota_viable = False
                    skip_reason = "usage snapshot is stale"
                    stale_snapshot_candidates.append(prov_name)
        else:
            # P1-2: Facts without snapshot is strictly rejected (no bypass)
            if prov_name in context_quota_facts:
                raise QuotaUnavailableError(
                    f"Provider '{prov_name}' cannot use quota_facts without a corresponding verified AgentUsageSnapshot",
                    details={"provider": prov_name},
                )
            if routing_policy is None:
                allow_missing = True
            elif routing_policy.allow_missing_usage is not None:
                allow_missing = routing_policy.allow_missing_usage
            elif active_policy_version.endswith("-m3") or active_policy_version == "2026-09-m3":
                # M3 quota-aware mode strictly requires snapshots; missing fails closed
                allow_missing = False
            else:
                # Retaining legacy policy_version (e.g. 2026-09-m1) allows missing usage by default
                allow_missing = True

            if not allow_missing:
                quota_status_str = "missing"
                quota_viable = False
                skip_reason = "missing required usage snapshot"
                missing_snapshot_candidates.append(prov_name)
            else:
                quota_status_str = "missing_allowed"

        # Model evaluation & resolution
        resolved_model_candidate: str | None = None
        resolved_group_id: str = ""
        resolved_model_status: QuotaStatus | None = None

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
            # Skip reason already populated above (stale, missing, or provider_mismatch)
            pass
        else:
            exhausted_group_ids = exhausted_group_ids_by_provider.setdefault(prov_name, set())
            candidate_unknown_models: list[tuple[str, str]] = []

            for m in candidate_models:
                if m not in desc.supported_models:
                    if preferred_model and m == preferred_model:
                        skip_reason = f"preferred model '{preferred_model}' unsupported by provider"
                    continue

                if facts is None:
                    resolved_model_candidate = m
                    resolved_group_id = ""
                    resolved_model_status = QuotaStatus.HEALTHY
                    break

                grp = facts.get_group_for_model(m)
                if grp is None:
                    candidate_unknown_models.append((m, "unknown"))
                    continue

                if grp.group_id in exhausted_group_ids:
                    continue

                if grp.status == QuotaStatus.EXHAUSTED:
                    exhausted_group_ids.add(grp.group_id)
                    quota_exhausted_candidates.append(f"{prov_name}:{m}")
                    continue

                if grp.status == QuotaStatus.UNKNOWN:
                    candidate_unknown_models.append((m, grp.group_id))
                    continue

                if grp.status in (QuotaStatus.HEALTHY, QuotaStatus.CONSTRAINED):
                    resolved_model_candidate = m
                    resolved_group_id = grp.group_id
                    resolved_model_status = grp.status
                    break

            if not resolved_model_candidate and candidate_unknown_models:
                allow_unknown = (
                    routing_policy.allow_unknown_quota_fallback
                    if routing_policy
                    else False
                )
                if allow_unknown:
                    resolved_model_candidate, resolved_group_id = candidate_unknown_models[0]
                    resolved_model_status = QuotaStatus.UNKNOWN
                else:
                    all_unknown_quota_candidates.append(prov_name)
                    skip_reason = f"all candidate models for provider '{prov_name}' have unknown quota"

            if not resolved_model_candidate and skip_reason is None:
                if exhausted_group_ids:
                    skip_reason = f"all candidate models for provider '{prov_name}' quota exhausted"
                    quota_exhausted_candidates.append(prov_name)
                elif preferred_model:
                    skip_reason = f"preferred model '{preferred_model}' is not available due to quota or unsupported"
                else:
                    skip_reason = f"none of policy model preferences supported or viable for provider '{prov_name}'"

        decision = "selected" if (skip_reason is None and resolved_model_candidate) else "skipped"

        # P1-4: candidate trace 的 quota_group、quota_status、quota_windows 必须精确取自当前实际评估/选中或跳过的同一个 group
        evaluated_group = None
        if facts is not None:
            if resolved_group_id:
                evaluated_group = facts.get_group(resolved_group_id)
            else:
                target_m = resolved_model_candidate or (candidate_models[0] if candidate_models else None)
                if target_m:
                    evaluated_group = facts.get_group_for_model(target_m)

        if evaluated_group is not None:
            trace_group_id = evaluated_group.group_id
            trace_quota_windows = [w.to_dict() for w in evaluated_group.windows]
            trace_quota_status = (
                resolved_model_status.value
                if resolved_model_status
                else evaluated_group.status.value
            )
        else:
            trace_group_id = resolved_group_id or "unknown"
            trace_quota_windows = []
            trace_quota_status = (
                resolved_model_status.value
                if resolved_model_status
                else quota_status_str
            )

        candidate_trace.append(
            {
                "availability": avail_status,
                "capability_supported": capability_supported,
                "decision": decision,
                "model": resolved_model_candidate or (candidate_models[0] if candidate_models else "unknown"),
                "provider": prov_name,
                "quota": quota_status_str,
                "quota_group": trace_group_id,
                "quota_status": trace_quota_status,
                "quota_windows": trace_quota_windows,
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
            selected_quota_group = resolved_group_id
            selected_binding_profile_version = getattr(facts, "binding_profile_version", "") if facts else ""

            if snapshot:
                selected_snapshot_ref = f"{snapshot.snapshot_id}@{snapshot.usage_content_hash}"
            else:
                selected_snapshot_ref = None

            # Determine auditable route reason code
            if preferred_provider and prov_name == preferred_provider:
                route_reason_code = RouteReasonCode.PREFERRED_PROVIDER_SELECTED
                route_reason = f"Selected caller preferred provider '{prov_name}' for role '{validated_role}'"
            elif len(exhausted_group_ids) > 0 and resolved_model_status in (QuotaStatus.HEALTHY, QuotaStatus.CONSTRAINED):
                route_reason_code = RouteReasonCode.FALLBACK_DIFFERENT_QUOTA_GROUP
                route_reason = f"Selected fallback model '{selected_model}' in quota group '{selected_quota_group}' due to exhaustion of primary quota group"
            elif quota_exhausted_candidates:
                route_reason_code = RouteReasonCode.PRIMARY_QUOTA_EXHAUSTED
                route_reason = f"Selected fallback provider '{prov_name}' due to quota exhaustion of primary candidates"
            elif any(t["decision"] == "skipped" and t["role_supported"] for t in candidate_trace[:-1]):
                route_reason_code = RouteReasonCode.PRIMARY_UNAVAILABLE_FALLBACK
                route_reason = f"Selected fallback provider '{prov_name}' for role '{validated_role}'"
            elif resolved_model_status == QuotaStatus.CONSTRAINED:
                route_reason_code = RouteReasonCode.PRIMARY_CONSTRAINED
                route_reason = f"Selected primary provider '{prov_name}' model '{selected_model}' under CONSTRAINED quota"
            elif resolved_model_status == QuotaStatus.HEALTHY:
                route_reason_code = RouteReasonCode.PRIMARY_HEALTHY
                route_reason = f"Selected healthy primary provider '{prov_name}' model '{selected_model}'"
            else:
                route_reason_code = RouteReasonCode.PRIMARY_AVAILABLE
                route_reason = f"Selected primary provider '{prov_name}' for role '{validated_role}'"
            break

    # 6. Check if any provider was selected
    if not selected_provider:
        viable_role_candidates = [
            t["provider"]
            for t in candidate_trace
            if t["role_supported"] and t["capability_supported"] and t["transport_allowed"]
        ]

        is_m3_policy = active_policy_version.endswith("-m3") or active_policy_version == "2026-09-m3"

        if viable_role_candidates:
            if is_m3_policy:
                if all(p in stale_snapshot_candidates for p in viable_role_candidates):
                    raise QuotaUnavailableError(
                        f"All providers supporting role '{validated_role}' failed due to stale usage snapshots",
                        details={"candidate_trace": candidate_trace, "stale_providers": stale_snapshot_candidates, "role": validated_role},
                    )
                if all(p in missing_snapshot_candidates for p in viable_role_candidates):
                    raise QuotaUnavailableError(
                        f"All providers supporting role '{validated_role}' failed due to missing required usage snapshot",
                        details={"candidate_trace": candidate_trace, "missing_providers": missing_snapshot_candidates, "role": validated_role},
                    )
                if all(p in provider_mismatch_candidates for p in viable_role_candidates):
                    raise QuotaUnavailableError(
                        f"All providers supporting role '{validated_role}' failed due to snapshot provider mismatch",
                        details={"candidate_trace": candidate_trace, "mismatched_providers": provider_mismatch_candidates, "role": validated_role},
                    )
                if all(prov in all_unknown_quota_candidates for prov in viable_role_candidates):
                    raise QuotaUnavailableError(
                        f"All providers supporting role '{validated_role}' have unknown quota",
                        details={
                            "candidate_trace": candidate_trace,
                            "unknown_providers": all_unknown_quota_candidates,
                            "role": validated_role,
                        },
                    )
                if all(
                    prov in quota_exhausted_candidates
                    or any(prov == q.split(":")[0] for q in quota_exhausted_candidates)
                    for prov in viable_role_candidates
                ):
                    raise QuotaUnavailableError(
                        f"All providers supporting role '{validated_role}' are quota exhausted or rate limited",
                        details={
                            "candidate_trace": candidate_trace,
                            "exhausted_providers": quota_exhausted_candidates,
                            "role": validated_role,
                        },
                    )
            elif is_m1_mode:
                if all(
                    prov in quota_exhausted_candidates
                    or any(prov == q.split(":")[0] for q in quota_exhausted_candidates)
                    for prov in viable_role_candidates
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
        policy_version=active_policy_version,
        route_reason=route_reason,
        usage_snapshot_ref=selected_snapshot_ref,
        project_binding=validated_binding,
        authorized_permissions=list(target_scope.authorized_permissions),
        authorized_scope=target_scope,
        route_reason_code=route_reason_code.value,
        transport_ref=selected_transport_ref,
        candidate_trace=candidate_trace,
        quota_group=selected_quota_group,
        binding_profile_version=selected_binding_profile_version,
    )
