"""Core immutable contracts and deterministic identity hashing (#573 Milestone 0).

Provides deterministic identity and content hashes using canonical research-json-v1 SHA-256
via `research_lab.contracts.v2.digest`. Business/scientific identity NEVER depends on
timestamps (e.g. now()) or random UUIDs.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ResultAcceptanceError,
    TamperDetectionError,
)
from research_lab.agent_control.permissions import (
    enforce_hard_invariants,
    validate_permissions,
)
from research_lab.agent_control.roles import DEFAULT_ROLE_POLICIES, validate_role
from research_lab.contracts import v2

HASH_PROFILE = "research-json-v1"
SUPPORTED_BINDING_MODES = frozenset({"strict"})
FORBIDDEN_BINDING_VALUES = frozenset({"unspecified", "default", "placeholder", ""})


def _freeze_mapping(obj: Any) -> Any:
    """Recursively freeze mapping and collection containers into immutable types."""
    if isinstance(obj, Mapping):
        return MappingProxyType({k: _freeze_mapping(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze_mapping(x) for x in obj)
    return obj


def _deepcopy_mappingproxy(x: Any, memo: dict[int, Any] | None = None) -> MappingProxyType[Any, Any]:
    """Support copy.deepcopy for MappingProxyType without raising TypeError."""
    if memo is None:
        memo = {}
    d = id(x)
    if d in memo:
        return memo[d]
    copied_dict = copy.deepcopy(dict(x), memo)
    proxy = MappingProxyType(copied_dict)
    memo[d] = proxy
    return proxy


# Register MappingProxyType with copy.deepcopy dispatch table to enable deepcopy compatibility
copy._deepcopy_dispatch[MappingProxyType] = _deepcopy_mappingproxy


def _unfreeze_to_dict(obj: Any) -> Any:
    """Recursively convert mappingproxy and frozen containers to plain, independent mutable dicts/lists."""
    if isinstance(obj, Mapping):
        return {k: _unfreeze_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_unfreeze_to_dict(x) for x in obj]
    return copy.deepcopy(obj)


def _clean_for_canonical(obj: Any) -> Any:
    """Recursively clean and sanitize data structures for research-json-v1 canonical encoding."""
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        # Format floating numbers into clean strings or integers to comply with research-json-v1
        if obj.is_integer():
            return int(obj)
        return f"{obj:.6f}".rstrip("0").rstrip(".")
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (set, frozenset)):
        return sorted([_clean_for_canonical(x) for x in obj])
    if isinstance(obj, (list, tuple)):
        return [_clean_for_canonical(x) for x in obj]
    if isinstance(obj, (dict, Mapping)):
        return {str(k): _clean_for_canonical(v) for k, v in sorted(obj.items())}
    if hasattr(obj, "to_dict"):
        return _clean_for_canonical(obj.to_dict())
    if hasattr(obj, "__dict__"):
        return _clean_for_canonical(asdict(obj) if hasattr(obj, "__dataclass_fields__") else vars(obj))
    return str(obj)


@dataclass(frozen=True)
class ProjectBinding:
    """Binding specification for workspace and project identity."""

    project_id: str
    workspace_identity: str
    binding_mode: str = "strict"

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, str) or not self.project_id.strip():
            raise ProjectBindingError("project_id must be a non-empty string")
        if self.project_id.strip().lower() in FORBIDDEN_BINDING_VALUES:
            raise ProjectBindingError(
                f"project_id cannot be placeholder or unspecified value '{self.project_id}'",
                details={"project_id": self.project_id},
            )

        if not isinstance(self.workspace_identity, str) or not self.workspace_identity.strip():
            raise ProjectBindingError("workspace_identity must be a non-empty string")
        if self.workspace_identity.strip().lower() in FORBIDDEN_BINDING_VALUES:
            raise ProjectBindingError(
                f"workspace_identity cannot be placeholder or unspecified value '{self.workspace_identity}'",
                details={"workspace_identity": self.workspace_identity},
            )

        if self.binding_mode not in SUPPORTED_BINDING_MODES:
            raise ProjectBindingError(
                f"Unsupported binding_mode '{self.binding_mode}', supported: {sorted(SUPPORTED_BINDING_MODES)}",
                details={"binding_mode": self.binding_mode},
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "binding_mode": self.binding_mode,
            "project_id": self.project_id,
            "workspace_identity": self.workspace_identity,
        }


def validate_project_binding(
    task_binding: ProjectBinding | dict[str, Any] | None,
    expected_binding: ProjectBinding | dict[str, Any] | None = None,
) -> ProjectBinding:
    """Validate project and workspace binding fail-closed.

    Rejects None, placeholder, empty values, or mismatches without silent fallback.
    """
    if task_binding is None:
        raise ProjectBindingError("ProjectBinding is required and cannot be None")

    if isinstance(task_binding, ProjectBinding):
        tb = task_binding
    elif isinstance(task_binding, dict):
        tb = ProjectBinding(
            project_id=str(task_binding.get("project_id", "")),
            workspace_identity=str(task_binding.get("workspace_identity", "")),
            binding_mode=str(task_binding.get("binding_mode", "strict")),
        )
    else:
        raise ProjectBindingError(f"Invalid project_binding type: {type(task_binding).__name__}")

    if expected_binding is not None:
        eb = expected_binding if isinstance(expected_binding, ProjectBinding) else validate_project_binding(expected_binding)
        if tb.project_id != eb.project_id:
            raise ProjectBindingError(
                f"Project ID mismatch: expected '{eb.project_id}', got '{tb.project_id}'",
                details={"expected_project_id": eb.project_id, "actual_project_id": tb.project_id},
            )
        if tb.workspace_identity != eb.workspace_identity:
            raise ProjectBindingError(
                f"Workspace identity mismatch: expected '{eb.workspace_identity}', got '{tb.workspace_identity}'",
                details={
                    "expected_workspace_identity": eb.workspace_identity,
                    "actual_workspace_identity": tb.workspace_identity,
                },
            )
        if tb.binding_mode != eb.binding_mode:
            raise ProjectBindingError(
                f"Binding mode mismatch: expected '{eb.binding_mode}', got '{tb.binding_mode}'",
                details={"expected_binding_mode": eb.binding_mode, "actual_binding_mode": tb.binding_mode},
            )

    return tb


CORE_SCOPE_IDENTITY_FIELDS = (
    "role",
    "requested_permissions",
    "authorized_permissions",
    "denied_permissions",
    "policy_version",
    "project_binding",
)


def compute_scope_deterministic_id(payload: dict[str, Any]) -> str:
    """Compute stable, reproducible scope ID strictly based on core authorization fields."""
    clean_core = {
        field: _clean_for_canonical(payload.get(field))
        for field in CORE_SCOPE_IDENTITY_FIELDS
    }
    digest = v2.digest(clean_core)
    return f"scope-{digest[:32]}"


def compute_scope_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of AgentPermissionScope payload."""
    clean = {k: _clean_for_canonical(v) for k, v in payload.items() if k != "scope_content_hash"}
    return v2.digest(clean)


def validate_scope_hash(payload: dict[str, Any]) -> None:
    """Tamper-detection validation for AgentPermissionScope content hash."""
    expected = payload.get("scope_content_hash")
    if not expected:
        raise TamperDetectionError("Missing scope_content_hash in payload")
    actual = compute_scope_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"AgentPermissionScope content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class AgentPermissionScope:
    """Immutable result of access control authorization with exact cryptographic provenance."""

    scope_id: str
    role: str
    requested_permissions: tuple[str, ...]
    authorized_permissions: tuple[str, ...]
    denied_permissions: tuple[str, ...]
    is_authorized: bool
    policy_version: str
    project_binding: dict[str, str] | Mapping[str, str]
    scope_content_hash: str
    context: dict[str, Any] | Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = "research_lab.agent_scope.v1"
    hash_profile: str = HASH_PROFILE

    def __post_init__(self) -> None:
        validate_role(self.role)
        req = validate_permissions(self.requested_permissions)
        auth = validate_permissions(self.authorized_permissions)
        den = validate_permissions(self.denied_permissions)
        enforce_hard_invariants(req)
        enforce_hard_invariants(auth)

        # Validate is_authorized consistency: unauthorized scope cannot carry authorized permissions
        if not self.is_authorized and auth:
            raise PermissionDeniedError(
                f"AgentPermissionScope with is_authorized=False cannot carry authorized permissions: {auth}",
                details={"role": self.role, "authorized_permissions": auth},
            )

        # Validate project binding strictly (fail-closed)
        validate_project_binding(self.project_binding)

        active_policy = DEFAULT_ROLE_POLICIES.get(self.role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(auth).issubset(allowed):
                unauthorized = sorted(set(auth) - allowed)
                raise PermissionDeniedError(
                    f"AgentPermissionScope contains unauthorized permissions for role '{self.role}': {unauthorized}",
                    details={"role": self.role, "unauthorized_permissions": unauthorized},
                )

        if not set(auth).issubset(set(req)):
            elevation = sorted(set(auth) - set(req))
            raise PermissionDeniedError(
                f"AgentPermissionScope contains unrequested permissions (elevation attempt): {elevation}",
                details={"role": self.role, "unrequested_permissions": elevation},
            )

        expected_denied = set(req) - set(auth)
        if set(den) != expected_denied:
            raise PermissionDeniedError(
                f"AgentPermissionScope denied_permissions mismatch: expected {sorted(expected_denied)}, got {sorted(den)}",
                details={"expected_denied": sorted(expected_denied), "actual_denied": sorted(den)},
            )

        if not self.scope_id or not self.scope_id.startswith("scope-"):
            raise TamperDetectionError("Invalid or missing scope_id")

        expected_id = compute_scope_deterministic_id(self.to_dict())
        if self.scope_id != expected_id:
            raise TamperDetectionError(
                f"AgentPermissionScope scope_id mismatch: expected {expected_id}, got {self.scope_id}"
            )

        validate_scope_hash(self.to_dict())

        # Deep freeze internal mapping containers into immutable types (tamper prevention)
        object.__setattr__(self, "project_binding", _freeze_mapping(self.project_binding))
        object.__setattr__(self, "context", _freeze_mapping(self.context))

    @classmethod
    def create(
        cls,
        *,
        role: str,
        requested_permissions: list[str],
        authorized_permissions: list[str],
        project_binding: ProjectBinding | dict[str, str],
        denied_permissions: list[str] | None = None,
        is_authorized: bool = True,
        policy_version: str = "2026-09-m0",
        context: dict[str, Any] | None = None,
    ) -> AgentPermissionScope:
        validate_role(role)
        val_req = validate_permissions(requested_permissions)
        val_auth = validate_permissions(authorized_permissions)
        enforce_hard_invariants(val_req)
        enforce_hard_invariants(val_auth)

        if not is_authorized and val_auth:
            raise PermissionDeniedError(
                f"Cannot create AgentPermissionScope with is_authorized=False and non-empty authorized_permissions: {val_auth}",
                details={"role": role, "authorized_permissions": val_auth},
            )

        validated_binding = validate_project_binding(project_binding)
        binding_dict = validated_binding.to_dict()

        active_policy = DEFAULT_ROLE_POLICIES.get(role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(val_auth).issubset(allowed):
                unauthorized = sorted(set(val_auth) - allowed)
                raise PermissionDeniedError(
                    f"Cannot authorize permissions beyond role policy for '{role}': {unauthorized}",
                    details={"role": role, "unauthorized_permissions": unauthorized},
                )

        if not set(val_auth).issubset(set(val_req)):
            elevation = sorted(set(val_auth) - set(val_req))
            raise PermissionDeniedError(
                f"Cannot authorize unrequested permissions (elevation attempt): {elevation}",
                details={"role": role, "unrequested_permissions": elevation},
            )

        expected_denied = sorted(set(val_req) - set(val_auth))
        if denied_permissions is not None:
            val_den = validate_permissions(denied_permissions)
            if sorted(val_den) != expected_denied:
                raise PermissionDeniedError(
                    f"denied_permissions mismatch: expected {expected_denied}, got {sorted(val_den)}"
                )
        else:
            val_den = expected_denied

        raw = {
            "authorized_permissions": val_auth,
            "context": _clean_for_canonical(context or {}),
            "denied_permissions": val_den,
            "hash_profile": HASH_PROFILE,
            "is_authorized": is_authorized,
            "policy_version": policy_version,
            "project_binding": binding_dict,
            "requested_permissions": val_req,
            "role": role,
            "schema_version": "research_lab.agent_scope.v1",
        }
        scope_id = compute_scope_deterministic_id(raw)
        raw["scope_id"] = scope_id
        content_hash = compute_scope_content_hash(raw)

        return cls(
            scope_id=scope_id,
            role=role,
            requested_permissions=tuple(val_req),
            authorized_permissions=tuple(val_auth),
            denied_permissions=tuple(val_den),
            is_authorized=is_authorized,
            policy_version=policy_version,
            project_binding=binding_dict,
            scope_content_hash=content_hash,
            context=context or {},
            schema_version="research_lab.agent_scope.v1",
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized_permissions": list(self.authorized_permissions),
            "context": _unfreeze_to_dict(self.context),
            "denied_permissions": list(self.denied_permissions),
            "hash_profile": self.hash_profile,
            "is_authorized": self.is_authorized,
            "policy_version": self.policy_version,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "requested_permissions": list(self.requested_permissions),
            "role": self.role,
            "schema_version": self.schema_version,
            "scope_content_hash": self.scope_content_hash,
            "scope_id": self.scope_id,
        }


@dataclass(frozen=True)
class AgentProviderDescriptor:
    """Descriptor exposing capabilities and model catalog of a neutral Agent Provider."""

    provider: str
    supported_roles: tuple[str, ...]
    supported_models: tuple[str, ...]
    capabilities: tuple[str, ...]
    default_model: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": list(self.capabilities),
            "default_model": self.default_model,
            "provider": self.provider,
            "supported_models": list(self.supported_models),
            "supported_roles": list(self.supported_roles),
        }


# --- AgentTask Deterministic Identity & Contract ---

CORE_TASK_IDENTITY_FIELDS = (
    "authorization_scope_ref",
    "role",
    "requested_permissions",
    "authorized_permissions",
    "objective",
    "work_block",
    "input_refs",
    "provider_policy_ref",
    "project_binding",
    "delegation_depth",
    "parent_task_ref",
)


def compute_task_deterministic_id(payload: dict[str, Any]) -> str:
    """Compute stable, reproducible task ID strictly based on core business/scientific inputs.

    Never uses current timestamp or random UUIDs. Identical inputs yield identical task IDs.
    """
    clean_core = {
        field: _clean_for_canonical(payload.get(field))
        for field in CORE_TASK_IDENTITY_FIELDS
    }
    digest = v2.digest(clean_core)
    return f"task-{digest[:32]}"


def compute_task_content_hash(payload: dict[str, Any]) -> str:
    """Compute repository-pinned research-json-v1 SHA-256 digest of AgentTask."""
    clean = {k: _clean_for_canonical(v) for k, v in payload.items() if k != "task_content_hash"}
    return v2.digest(clean)


def validate_task_hash(payload: dict[str, Any]) -> None:
    """Tamper-detection validation for AgentTask content hash."""
    expected = payload.get("task_content_hash")
    if not expected:
        raise TamperDetectionError("Missing task_content_hash in payload")
    actual = compute_task_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"AgentTask content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class AgentTask:
    """Immutable Agent task definition with deterministic identity and tamper detection."""

    task_id: str
    authorization_scope_ref: dict[str, Any] | Mapping[str, Any]
    role: str
    requested_permissions: tuple[str, ...]
    authorized_permissions: tuple[str, ...]
    objective: str
    work_block: str
    input_refs: tuple[dict[str, str] | Mapping[str, str], ...]
    provider_policy_ref: str
    project_binding: dict[str, str] | Mapping[str, str]
    created_by: str
    created_at: str
    task_content_hash: str
    schema_version: str = "research_lab.agent_task.v1"
    hash_profile: str = HASH_PROFILE
    delegation_depth: int = 0
    parent_task_ref: dict[str, str] | Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        validate_role(self.role)
        req = validate_permissions(self.requested_permissions)
        auth = validate_permissions(self.authorized_permissions)
        enforce_hard_invariants(req)
        enforce_hard_invariants(auth)

        # Validate ProjectBinding fail-closed
        validate_project_binding(self.project_binding)

        # 1. Type validation: must be exact verifiable dictionary/mapping, string references or placeholders rejected
        if not isinstance(self.authorization_scope_ref, Mapping):
            raise TamperDetectionError(
                f"authorization_scope_ref must be an exact verifiable scope dictionary, got {type(self.authorization_scope_ref).__name__}; "
                f"string references and mock placeholders are rejected: '{self.authorization_scope_ref}'"
            )

        # 2. Tamper-detection validation on scope content hash itself
        validate_scope_hash(dict(self.authorization_scope_ref))

        # 3. Deterministic identity verification
        expected_scope_id = compute_scope_deterministic_id(dict(self.authorization_scope_ref))
        if self.authorization_scope_ref.get("scope_id") != expected_scope_id:
            raise TamperDetectionError(
                f"authorization_scope_ref scope_id mismatch: expected {expected_scope_id}, got {self.authorization_scope_ref.get('scope_id')}"
            )

        # 4. Enforce is_authorized is True (prevent is_authorized bypass)
        if self.authorization_scope_ref.get("is_authorized") is not True:
            raise PermissionDeniedError(
                f"AgentTask requires authorization_scope_ref with is_authorized=True, got {self.authorization_scope_ref.get('is_authorized')}",
                details={"is_authorized": self.authorization_scope_ref.get("is_authorized")},
            )

        # 5. Consistency: role
        if self.authorization_scope_ref.get("role") != self.role:
            raise PermissionDeniedError(
                f"authorization_scope_ref role mismatch: scope={self.authorization_scope_ref.get('role')}, task={self.role}",
                details={"scope_role": self.authorization_scope_ref.get("role"), "target_role": self.role},
            )

        # 6. Consistency: authorized_permissions exact match
        scope_auth = tuple(self.authorization_scope_ref.get("authorized_permissions") or ())
        if tuple(self.authorized_permissions) != scope_auth:
            raise PermissionDeniedError(
                f"AgentTask authorized_permissions mismatch with authorization_scope_ref: task={self.authorized_permissions}, scope={scope_auth}",
                details={"task_authorized": self.authorized_permissions, "scope_authorized": scope_auth},
            )

        # 7. Consistency: requested_permissions superset
        scope_req = set(self.authorization_scope_ref.get("requested_permissions") or ())
        if not set(self.authorized_permissions).issubset(scope_req):
            raise PermissionDeniedError(
                "AgentTask authorized_permissions contains unrequested permissions according to authorization_scope_ref"
            )

        # 8. Consistency: project_binding match
        scope_binding = self.authorization_scope_ref.get("project_binding")
        if not scope_binding or dict(scope_binding) != dict(self.project_binding):
            raise ProjectBindingError(
                f"ProjectBinding mismatch between AgentTask and authorization_scope_ref: "
                f"task={dict(self.project_binding)}, scope={scope_binding}",
                details={"task_binding": dict(self.project_binding), "scope_binding": scope_binding},
            )

        # Validate least privilege subset: authorized ⊆ requested
        if not set(auth).issubset(set(req)):
            elevation = sorted(set(auth) - set(req))
            raise PermissionDeniedError(
                f"AgentTask authorized_permissions contains unrequested permissions (elevation attempt): {elevation}",
                details={"role": self.role, "unrequested_permissions": elevation},
            )

        # Validate policy bounds: authorized ⊆ role_policy.allowed_permissions
        active_policy = DEFAULT_ROLE_POLICIES.get(self.role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(auth).issubset(allowed):
                unauthorized = sorted(set(auth) - allowed)
                raise PermissionDeniedError(
                    f"AgentTask authorized_permissions contains unauthorized permissions for role '{self.role}': {unauthorized}",
                    details={"role": self.role, "unauthorized_permissions": unauthorized},
                )

        # Validate parent / delegation depth rules
        if self.delegation_depth < 0:
            raise PermissionDeniedError(f"delegation_depth cannot be negative: {self.delegation_depth}")
        if self.delegation_depth > 0:
            if not self.parent_task_ref or not isinstance(self.parent_task_ref, (dict, Mapping)) or not self.parent_task_ref.get("task_id"):
                raise PermissionDeniedError(
                    f"AgentTask with delegation_depth={self.delegation_depth} must specify a valid parent_task_ref with non-empty 'task_id'",
                    details={"delegation_depth": self.delegation_depth, "parent_task_ref": self.parent_task_ref},
                )
        else:
            if self.parent_task_ref is not None:
                raise PermissionDeniedError(
                    "AgentTask with delegation_depth=0 cannot have parent_task_ref (cannot forge worker-parent relationship)",
                    details={"delegation_depth": self.delegation_depth, "parent_task_ref": self.parent_task_ref},
                )

        # Validate tamper detection
        validate_task_hash(self.to_dict())

        # Deep freeze internal mapping containers into immutable types (tamper prevention)
        object.__setattr__(self, "project_binding", _freeze_mapping(self.project_binding))
        object.__setattr__(self, "authorization_scope_ref", _freeze_mapping(self.authorization_scope_ref))
        object.__setattr__(self, "input_refs", _freeze_mapping(self.input_refs))
        if self.parent_task_ref is not None:
            object.__setattr__(self, "parent_task_ref", _freeze_mapping(self.parent_task_ref))

    @classmethod
    def create(
        cls,
        *,
        role: str,
        requested_permissions: list[str],
        authorized_permissions: list[str],
        objective: str,
        work_block: str,
        input_refs: list[dict[str, str]],
        provider_policy_ref: str,
        project_binding: ProjectBinding | dict[str, str],
        created_by: str,
        created_at: str,
        authorized_scope: AgentPermissionScope | None = None,
        authorization_scope_ref: dict[str, Any] | None = None,
        delegation_depth: int = 0,
        parent_task_ref: dict[str, str] | None = None,
    ) -> AgentTask:
        validate_role(role)
        val_req = validate_permissions(requested_permissions)
        val_auth = validate_permissions(authorized_permissions)
        enforce_hard_invariants(val_req)
        enforce_hard_invariants(val_auth)

        validated_binding = validate_project_binding(project_binding)
        binding_dict = validated_binding.to_dict()

        if authorized_scope is not None:
            if not isinstance(authorized_scope, AgentPermissionScope):
                raise PermissionDeniedError(
                    f"authorized_scope must be an instance of AgentPermissionScope, got {type(authorized_scope).__name__}"
                )
            if not authorized_scope.is_authorized:
                raise PermissionDeniedError(
                    "Cannot create AgentTask with an unauthorized scope (is_authorized=False)",
                    details={"role": role},
                )
            scope_ref = authorized_scope.to_dict()
        elif authorization_scope_ref is not None:
            if not isinstance(authorization_scope_ref, Mapping):
                raise TamperDetectionError(
                    f"authorization_scope_ref must be an exact verifiable scope dictionary, got {type(authorization_scope_ref).__name__}; "
                    f"string references and mock placeholders are rejected: '{authorization_scope_ref}'"
                )
            if authorization_scope_ref.get("is_authorized") is not True:
                raise PermissionDeniedError(
                    "Cannot create AgentTask with an unauthorized scope (is_authorized is not True)",
                    details={"role": role, "is_authorized": authorization_scope_ref.get("is_authorized")},
                )
            scope_ref = copy.deepcopy(dict(authorization_scope_ref))
        else:
            raise PermissionDeniedError(
                "AgentTask requires authorized_scope (AgentPermissionScope) or authorization_scope_ref (dict); cannot be empty"
            )

        active_policy = DEFAULT_ROLE_POLICIES.get(role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(val_auth).issubset(allowed):
                unauthorized = sorted(set(val_auth) - allowed)
                raise PermissionDeniedError(
                    f"Cannot create AgentTask with unauthorized permissions for '{role}': {unauthorized}",
                    details={"role": role, "unauthorized_permissions": unauthorized},
                )

        if not set(val_auth).issubset(set(val_req)):
            elevation = sorted(set(val_auth) - set(val_req))
            raise PermissionDeniedError(
                f"Cannot create AgentTask with unrequested permissions (elevation attempt): {elevation}",
                details={"role": role, "unrequested_permissions": elevation},
            )

        raw = {
            "authorization_scope_ref": _clean_for_canonical(scope_ref),
            "authorized_permissions": val_auth,
            "created_at": created_at,
            "created_by": created_by,
            "delegation_depth": delegation_depth,
            "hash_profile": HASH_PROFILE,
            "input_refs": input_refs,
            "objective": objective,
            "parent_task_ref": parent_task_ref,
            "project_binding": binding_dict,
            "provider_policy_ref": provider_policy_ref,
            "requested_permissions": val_req,
            "role": role,
            "schema_version": "research_lab.agent_task.v1",
            "work_block": work_block,
        }
        deterministic_id = compute_task_deterministic_id(raw)
        raw["task_id"] = deterministic_id
        content_hash = compute_task_content_hash(raw)

        return cls(
            task_id=deterministic_id,
            authorization_scope_ref=scope_ref,
            role=role,
            requested_permissions=tuple(val_req),
            authorized_permissions=tuple(val_auth),
            objective=objective,
            work_block=work_block,
            input_refs=tuple(copy.deepcopy(input_refs)),
            provider_policy_ref=provider_policy_ref,
            project_binding=binding_dict,
            created_by=created_by,
            created_at=created_at,
            task_content_hash=content_hash,
            schema_version="research_lab.agent_task.v1",
            hash_profile=HASH_PROFILE,
            delegation_depth=delegation_depth,
            parent_task_ref=parent_task_ref,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_scope_ref": _unfreeze_to_dict(self.authorization_scope_ref),
            "authorized_permissions": list(self.authorized_permissions),
            "created_at": self.created_at,
            "created_by": self.created_by,
            "delegation_depth": self.delegation_depth,
            "hash_profile": self.hash_profile,
            "input_refs": _unfreeze_to_dict(self.input_refs),
            "objective": self.objective,
            "parent_task_ref": _unfreeze_to_dict(self.parent_task_ref) if self.parent_task_ref else None,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "provider_policy_ref": self.provider_policy_ref,
            "requested_permissions": list(self.requested_permissions),
            "role": self.role,
            "schema_version": self.schema_version,
            "task_content_hash": self.task_content_hash,
            "task_id": self.task_id,
            "work_block": self.work_block,
        }


# --- AgentRoute Contract ---

def compute_route_deterministic_id(payload: dict[str, Any]) -> str:
    """Compute deterministic route ID from role, provider, resolved model, policy version, and scope ref."""
    core = {
        "authorization_scope_ref": payload.get("authorization_scope_ref"),
        "authorized_permissions": _clean_for_canonical(payload.get("authorized_permissions")),
        "policy_version": payload.get("policy_version"),
        "project_binding": _clean_for_canonical(payload.get("project_binding")),
        "provider": payload.get("provider"),
        "resolved_model": payload.get("resolved_model"),
        "role": payload.get("role"),
        "route_reason": payload.get("route_reason"),
    }
    digest = v2.digest(core)
    return f"route-{digest[:32]}"


def compute_route_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of AgentRoute payload."""
    clean = {k: _clean_for_canonical(v) for k, v in payload.items() if k != "route_content_hash"}
    return v2.digest(clean)


def validate_route_hash(payload: dict[str, Any]) -> None:
    """Tamper-detection validation for AgentRoute content hash."""
    expected = payload.get("route_content_hash")
    if not expected:
        raise TamperDetectionError("Missing route_content_hash in payload")
    actual = compute_route_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"AgentRoute content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class AgentRoute:
    """Auditable routing decision resolving an abstract role to a neutral provider and model."""

    route_id: str
    authorization_scope_ref: dict[str, Any] | Mapping[str, Any]
    role: str
    provider: str
    resolved_model: str
    policy_version: str
    route_reason: str
    usage_snapshot_ref: str | None
    project_binding: dict[str, str] | Mapping[str, str]
    authorized_permissions: tuple[str, ...]
    route_content_hash: str
    schema_version: str = "research_lab.agent_route.v1"
    hash_profile: str = HASH_PROFILE

    def __post_init__(self) -> None:
        validate_role(self.role)
        auth = validate_permissions(self.authorized_permissions)
        enforce_hard_invariants(auth)

        # Validate project binding fail-closed
        validate_project_binding(self.project_binding)

        # 1. Type validation: must be exact verifiable dictionary/mapping, string references or placeholders rejected
        if not isinstance(self.authorization_scope_ref, Mapping):
            raise TamperDetectionError(
                f"authorization_scope_ref must be an exact verifiable scope dictionary, got {type(self.authorization_scope_ref).__name__}; "
                f"string references and mock placeholders are rejected: '{self.authorization_scope_ref}'"
            )

        # 2. Tamper-detection validation on scope content hash itself
        validate_scope_hash(dict(self.authorization_scope_ref))

        # 3. Deterministic identity verification
        expected_scope_id = compute_scope_deterministic_id(dict(self.authorization_scope_ref))
        if self.authorization_scope_ref.get("scope_id") != expected_scope_id:
            raise TamperDetectionError(
                f"authorization_scope_ref scope_id mismatch: expected {expected_scope_id}, got {self.authorization_scope_ref.get('scope_id')}"
            )

        # 4. Enforce is_authorized is True (prevent is_authorized bypass)
        if self.authorization_scope_ref.get("is_authorized") is not True:
            raise PermissionDeniedError(
                f"AgentRoute requires authorization_scope_ref with is_authorized=True, got {self.authorization_scope_ref.get('is_authorized')}",
                details={"is_authorized": self.authorization_scope_ref.get("is_authorized")},
            )

        # 5. Consistency: role
        if self.authorization_scope_ref.get("role") != self.role:
            raise PermissionDeniedError(
                f"authorization_scope_ref role mismatch: scope={self.authorization_scope_ref.get('role')}, route={self.role}",
                details={"scope_role": self.authorization_scope_ref.get("role"), "target_role": self.role},
            )

        # 6. Consistency: authorized_permissions exact match
        scope_auth = tuple(self.authorization_scope_ref.get("authorized_permissions") or ())
        if tuple(self.authorized_permissions) != scope_auth:
            raise PermissionDeniedError(
                f"AgentRoute authorized_permissions mismatch with authorization_scope_ref: route={self.authorized_permissions}, scope={scope_auth}",
                details={"route_authorized": self.authorized_permissions, "scope_authorized": scope_auth},
            )

        # 7. Consistency: requested_permissions superset
        scope_req = set(self.authorization_scope_ref.get("requested_permissions") or ())
        if not set(self.authorized_permissions).issubset(scope_req):
            raise PermissionDeniedError(
                "AgentRoute authorized_permissions contains unrequested permissions according to authorization_scope_ref"
            )

        # 8. Consistency: project_binding match
        scope_binding = self.authorization_scope_ref.get("project_binding")
        if not scope_binding or dict(scope_binding) != dict(self.project_binding):
            raise ProjectBindingError(
                f"ProjectBinding mismatch between AgentRoute and authorization_scope_ref: "
                f"route={dict(self.project_binding)}, scope={scope_binding}",
                details={"route_binding": dict(self.project_binding), "scope_binding": scope_binding},
            )

        active_policy = DEFAULT_ROLE_POLICIES.get(self.role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(auth).issubset(allowed):
                unauthorized = sorted(set(auth) - allowed)
                raise PermissionDeniedError(
                    f"AgentRoute authorized_permissions contains unauthorized permissions for role '{self.role}': {unauthorized}",
                    details={"role": self.role, "unauthorized_permissions": unauthorized},
                )

        validate_route_hash(self.to_dict())

        # Deep freeze internal mapping containers into immutable types (tamper prevention)
        object.__setattr__(self, "project_binding", _freeze_mapping(self.project_binding))
        object.__setattr__(self, "authorization_scope_ref", _freeze_mapping(self.authorization_scope_ref))

    @classmethod
    def create(
        cls,
        *,
        role: str,
        provider: str,
        resolved_model: str,
        policy_version: str,
        route_reason: str,
        usage_snapshot_ref: str | None,
        project_binding: ProjectBinding | dict[str, str],
        authorized_permissions: list[str],
        authorized_scope: AgentPermissionScope | None = None,
        authorization_scope_ref: dict[str, Any] | None = None,
    ) -> AgentRoute:
        validate_role(role)
        val_auth = validate_permissions(authorized_permissions)
        enforce_hard_invariants(val_auth)

        validated_binding = validate_project_binding(project_binding)
        binding_dict = validated_binding.to_dict()

        if authorized_scope is not None:
            if not isinstance(authorized_scope, AgentPermissionScope):
                raise PermissionDeniedError(
                    f"authorized_scope must be an instance of AgentPermissionScope, got {type(authorized_scope).__name__}"
                )
            if not authorized_scope.is_authorized:
                raise PermissionDeniedError(
                    "Cannot create AgentRoute with an unauthorized scope (is_authorized=False)",
                    details={"role": role},
                )
            scope_dict = authorized_scope.to_dict()
        elif authorization_scope_ref is not None:
            if not isinstance(authorization_scope_ref, Mapping):
                raise TamperDetectionError(
                    f"authorization_scope_ref must be an exact verifiable scope dictionary, got {type(authorization_scope_ref).__name__}; "
                    f"string references and mock placeholders are rejected: '{authorization_scope_ref}'"
                )
            if authorization_scope_ref.get("is_authorized") is not True:
                raise PermissionDeniedError(
                    "Cannot create AgentRoute with an unauthorized scope (is_authorized is not True)",
                    details={"role": role, "is_authorized": authorization_scope_ref.get("is_authorized")},
                )
            scope_dict = copy.deepcopy(dict(authorization_scope_ref))
        else:
            raise PermissionDeniedError(
                "AgentRoute requires authorized_scope (AgentPermissionScope) or authorization_scope_ref (dict); cannot be empty"
            )

        active_policy = DEFAULT_ROLE_POLICIES.get(role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(val_auth).issubset(allowed):
                unauthorized = sorted(set(val_auth) - allowed)
                raise PermissionDeniedError(
                    f"Cannot create AgentRoute with unauthorized permissions for '{role}': {unauthorized}",
                    details={"role": role, "unauthorized_permissions": unauthorized},
                )

        raw = {
            "authorization_scope_ref": _clean_for_canonical(scope_dict),
            "authorized_permissions": val_auth,
            "hash_profile": HASH_PROFILE,
            "policy_version": policy_version,
            "project_binding": binding_dict,
            "provider": provider,
            "resolved_model": resolved_model,
            "role": role,
            "route_reason": route_reason,
            "schema_version": "research_lab.agent_route.v1",
            "usage_snapshot_ref": usage_snapshot_ref,
        }
        route_id = compute_route_deterministic_id(raw)
        raw["route_id"] = route_id
        content_hash = compute_route_content_hash(raw)

        return cls(
            route_id=route_id,
            authorization_scope_ref=scope_dict,
            role=role,
            provider=provider,
            resolved_model=resolved_model,
            policy_version=policy_version,
            route_reason=route_reason,
            usage_snapshot_ref=usage_snapshot_ref,
            project_binding=binding_dict,
            authorized_permissions=tuple(val_auth),
            route_content_hash=content_hash,
            schema_version="research_lab.agent_route.v1",
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_scope_ref": _unfreeze_to_dict(self.authorization_scope_ref),
            "authorized_permissions": list(self.authorized_permissions),
            "hash_profile": self.hash_profile,
            "policy_version": self.policy_version,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "provider": self.provider,
            "resolved_model": self.resolved_model,
            "role": self.role,
            "route_content_hash": self.route_content_hash,
            "route_id": self.route_id,
            "route_reason": self.route_reason,
            "schema_version": self.schema_version,
            "usage_snapshot_ref": self.usage_snapshot_ref,
        }


# --- AgentExecutionHandle Contract ---

@dataclass(frozen=True)
class AgentExecutionHandle:
    """Handle identifying an execution job initiated through an AgentProvider."""

    handle_id: str
    task_ref: dict[str, str]
    route_ref: dict[str, str]
    provider_job_ref: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle_id": self.handle_id,
            "provider_job_ref": self.provider_job_ref,
            "route_ref": dict(self.route_ref),
            "status": self.status,
            "task_ref": dict(self.task_ref),
        }


# --- TerminalStatus & AgentResult Contract ---

class TerminalStatus(str, Enum):
    """Explicit terminal execution status."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNCERTAIN = "UNCERTAIN"
    CANCELLED = "CANCELLED"
    REJECTED_BY_ACCEPTANCE = "REJECTED_BY_ACCEPTANCE"


def compute_result_deterministic_id(payload: dict[str, Any]) -> str:
    """Compute deterministic result ID."""
    core = {
        "provider_job_ref": payload.get("provider_job_ref"),
        "route_ref": _clean_for_canonical(payload.get("route_ref")),
        "task_ref": _clean_for_canonical(payload.get("task_ref")),
        "terminal_status": payload.get("terminal_status"),
    }
    digest = v2.digest(core)
    return f"result-{digest[:32]}"


def compute_result_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of AgentResult payload."""
    clean = {k: _clean_for_canonical(v) for k, v in payload.items() if k != "result_content_hash"}
    return v2.digest(clean)


def validate_result_hash(payload: dict[str, Any]) -> None:
    """Tamper-detection validation for AgentResult content hash."""
    expected = payload.get("result_content_hash")
    if not expected:
        raise TamperDetectionError("Missing result_content_hash in payload")
    actual = compute_result_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"AgentResult content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class AgentResult:
    """Contract capturing execution output, tool failures, and acceptance outcome."""

    result_id: str
    task_ref: dict[str, str]
    route_ref: dict[str, str]
    provider_job_ref: str
    terminal_status: str
    raw_result_ref: str | None
    structured_output: dict[str, Any] | None
    tool_failures: tuple[str, ...]
    uncertainty: str | None
    acceptance_status: str | None
    result_content_hash: str
    schema_version: str = "research_lab.agent_result.v1"
    hash_profile: str = HASH_PROFILE

    @classmethod
    def create(
        cls,
        *,
        task_ref: dict[str, str],
        route_ref: dict[str, str],
        provider_job_ref: str,
        terminal_status: TerminalStatus | str,
        raw_result_ref: str | None = None,
        structured_output: dict[str, Any] | None = None,
        tool_failures: list[str] | None = None,
        uncertainty: str | None = None,
        acceptance_status: str | None = None,
    ) -> AgentResult:
        status_val = terminal_status.value if isinstance(terminal_status, TerminalStatus) else str(terminal_status)
        if status_val not in {s.value for s in TerminalStatus}:
            raise ResultAcceptanceError(f"Invalid terminal_status: {status_val}")

        failures = tuple(tool_failures or [])
        clean_structured = _clean_for_canonical(structured_output)

        raw = {
            "acceptance_status": acceptance_status,
            "hash_profile": HASH_PROFILE,
            "provider_job_ref": provider_job_ref,
            "raw_result_ref": raw_result_ref,
            "route_ref": _clean_for_canonical(route_ref),
            "schema_version": "research_lab.agent_result.v1",
            "structured_output": clean_structured,
            "task_ref": _clean_for_canonical(task_ref),
            "terminal_status": status_val,
            "tool_failures": list(failures),
            "uncertainty": uncertainty,
        }
        result_id = compute_result_deterministic_id(raw)
        raw["result_id"] = result_id
        content_hash = compute_result_content_hash(raw)

        return cls(
            result_id=result_id,
            task_ref=copy.deepcopy(task_ref),
            route_ref=copy.deepcopy(route_ref),
            provider_job_ref=provider_job_ref,
            terminal_status=status_val,
            raw_result_ref=raw_result_ref,
            structured_output=clean_structured,
            tool_failures=failures,
            uncertainty=uncertainty,
            acceptance_status=acceptance_status,
            result_content_hash=content_hash,
            schema_version="research_lab.agent_result.v1",
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "acceptance_status": self.acceptance_status,
            "hash_profile": self.hash_profile,
            "provider_job_ref": self.provider_job_ref,
            "raw_result_ref": self.raw_result_ref,
            "result_content_hash": self.result_content_hash,
            "result_id": self.result_id,
            "route_ref": dict(self.route_ref),
            "schema_version": self.schema_version,
            "structured_output": copy.deepcopy(self.structured_output),
            "task_ref": dict(self.task_ref),
            "terminal_status": self.terminal_status,
            "tool_failures": list(self.tool_failures),
            "uncertainty": self.uncertainty,
        }


# --- AgentUsageSnapshot Contract ---

def compute_usage_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of AgentUsageSnapshot payload."""
    clean = {k: _clean_for_canonical(v) for k, v in payload.items() if k != "usage_content_hash"}
    return v2.digest(clean)


def compute_usage_deterministic_id(payload: dict[str, Any]) -> str:
    core = {
        "model_group": payload.get("model_group"),
        "provider": payload.get("provider"),
        "quota_windows": _clean_for_canonical(payload.get("quota_windows")),
    }
    digest = v2.digest(core)
    return f"usage-{digest[:32]}"


@dataclass(frozen=True)
class AgentUsageSnapshot:
    """Snapshot of provider quota windows. Explicitly preserves 'unknown' states."""

    snapshot_id: str
    provider: str
    model_group: str
    quota_windows: tuple[dict[str, Any], ...]
    captured_at: str
    usage_content_hash: str
    schema_version: str = "research_lab.agent_usage_snapshot.v1"
    hash_profile: str = HASH_PROFILE

    @classmethod
    def create(
        cls,
        *,
        provider: str,
        model_group: str,
        quota_windows: list[dict[str, Any]],
        captured_at: str,
    ) -> AgentUsageSnapshot:
        clean_windows = tuple(_clean_for_canonical(quota_windows))
        raw = {
            "captured_at": captured_at,
            "hash_profile": HASH_PROFILE,
            "model_group": model_group,
            "provider": provider,
            "quota_windows": list(clean_windows),
            "schema_version": "research_lab.agent_usage_snapshot.v1",
        }
        snapshot_id = compute_usage_deterministic_id(raw)
        raw["snapshot_id"] = snapshot_id
        content_hash = compute_usage_content_hash(raw)

        return cls(
            snapshot_id=snapshot_id,
            provider=provider,
            model_group=model_group,
            quota_windows=clean_windows,
            captured_at=captured_at,
            usage_content_hash=content_hash,
            schema_version="research_lab.agent_usage_snapshot.v1",
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "hash_profile": self.hash_profile,
            "model_group": self.model_group,
            "provider": self.provider,
            "quota_windows": list(self.quota_windows),
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "usage_content_hash": self.usage_content_hash,
        }


# --- AgentAuditRecord Contract ---

def compute_audit_deterministic_id(payload: dict[str, Any]) -> str:
    """Compute deterministic audit record ID."""
    core = {
        "authorized_permissions": _clean_for_canonical(payload.get("authorized_permissions")),
        "policy_version": payload.get("policy_version"),
        "project_binding": _clean_for_canonical(payload.get("project_binding")),
        "provider": payload.get("provider"),
        "provider_job_ref": payload.get("provider_job_ref"),
        "requested_permissions": _clean_for_canonical(payload.get("requested_permissions")),
        "resolved_model": payload.get("resolved_model"),
        "role": payload.get("role"),
        "route_ref": _clean_for_canonical(payload.get("route_ref")),
        "task_ref": _clean_for_canonical(payload.get("task_ref")),
    }
    digest = v2.digest(core)
    return f"audit-{digest[:32]}"


def compute_audit_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of AgentAuditRecord payload."""
    clean = {k: _clean_for_canonical(v) for k, v in payload.items() if k != "audit_content_hash"}
    return v2.digest(clean)


def validate_audit_hash(payload: dict[str, Any]) -> None:
    """Tamper-detection validation for AgentAuditRecord content hash."""
    expected = payload.get("audit_content_hash")
    if not expected:
        raise TamperDetectionError("Missing audit_content_hash in payload")
    actual = compute_audit_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"AgentAuditRecord content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class AgentAuditRecord:
    """Immutable audit record. Must be stored in append-only storage without in-place updates."""

    audit_id: str
    role: str
    provider: str
    resolved_model: str
    policy_version: str
    task_ref: dict[str, str]
    route_ref: dict[str, str]
    provider_job_ref: str
    project_binding: dict[str, str]
    input_refs: tuple[dict[str, str], ...]
    requested_permissions: tuple[str, ...]
    authorized_permissions: tuple[str, ...]
    usage_snapshot_ref: str | None
    terminal_status: str
    result_ref: dict[str, str] | None
    acceptance_status: str | None
    recorded_at: str
    audit_content_hash: str
    schema_version: str = "research_lab.agent_audit.v1"
    hash_profile: str = HASH_PROFILE

    @classmethod
    def create(
        cls,
        *,
        role: str,
        provider: str,
        resolved_model: str,
        policy_version: str,
        task_ref: dict[str, str],
        route_ref: dict[str, str],
        provider_job_ref: str,
        project_binding: ProjectBinding | dict[str, str],
        input_refs: list[dict[str, str]],
        requested_permissions: list[str],
        authorized_permissions: list[str],
        usage_snapshot_ref: str | None,
        terminal_status: str,
        result_ref: dict[str, str] | None,
        acceptance_status: str | None,
        recorded_at: str,
    ) -> AgentAuditRecord:
        validate_role(role)
        val_req = validate_permissions(requested_permissions)
        val_auth = validate_permissions(authorized_permissions)
        enforce_hard_invariants(val_req)
        enforce_hard_invariants(val_auth)

        binding_dict = project_binding.to_dict() if isinstance(project_binding, ProjectBinding) else dict(project_binding)

        raw = {
            "acceptance_status": acceptance_status,
            "authorized_permissions": val_auth,
            "hash_profile": HASH_PROFILE,
            "input_refs": _clean_for_canonical(input_refs),
            "policy_version": policy_version,
            "project_binding": binding_dict,
            "provider": provider,
            "provider_job_ref": provider_job_ref,
            "recorded_at": recorded_at,
            "requested_permissions": val_req,
            "result_ref": _clean_for_canonical(result_ref),
            "role": role,
            "resolved_model": resolved_model,
            "route_ref": _clean_for_canonical(route_ref),
            "schema_version": "research_lab.agent_audit.v1",
            "task_ref": _clean_for_canonical(task_ref),
            "terminal_status": terminal_status,
            "usage_snapshot_ref": usage_snapshot_ref,
        }
        audit_id = compute_audit_deterministic_id(raw)
        raw["audit_id"] = audit_id
        content_hash = compute_audit_content_hash(raw)

        return cls(
            audit_id=audit_id,
            role=role,
            provider=provider,
            resolved_model=resolved_model,
            policy_version=policy_version,
            task_ref=_unfreeze_to_dict(task_ref),
            route_ref=_unfreeze_to_dict(route_ref),
            provider_job_ref=provider_job_ref,
            project_binding=binding_dict,
            input_refs=tuple(_unfreeze_to_dict(input_refs)),
            requested_permissions=tuple(val_req),
            authorized_permissions=tuple(val_auth),
            usage_snapshot_ref=usage_snapshot_ref,
            terminal_status=terminal_status,
            result_ref=_unfreeze_to_dict(result_ref) if result_ref else None,
            acceptance_status=acceptance_status,
            recorded_at=recorded_at,
            audit_content_hash=content_hash,
            schema_version="research_lab.agent_audit.v1",
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "acceptance_status": self.acceptance_status,
            "audit_content_hash": self.audit_content_hash,
            "audit_id": self.audit_id,
            "authorized_permissions": list(self.authorized_permissions),
            "hash_profile": self.hash_profile,
            "input_refs": _unfreeze_to_dict(self.input_refs),
            "policy_version": self.policy_version,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "provider": self.provider,
            "provider_job_ref": self.provider_job_ref,
            "recorded_at": self.recorded_at,
            "requested_permissions": list(self.requested_permissions),
            "result_ref": _unfreeze_to_dict(self.result_ref) if self.result_ref else None,
            "role": self.role,
            "resolved_model": self.resolved_model,
            "route_ref": _unfreeze_to_dict(self.route_ref),
            "schema_version": self.schema_version,
            "task_ref": _unfreeze_to_dict(self.task_ref),
            "terminal_status": self.terminal_status,
            "usage_snapshot_ref": self.usage_snapshot_ref,
        }
