"""Formal execution preparation and handoff boundary (#573 Milestone 1).

Rules:
1. Scope / Task / Route exact consistency required before execution handoff.
2. Least privilege strictly preserved.
3. Provider, model, and transport strictly verified against ProviderRegistry.
4. Outputs an immutable, tamper-resistant ExecutionPreparation object.
5. MILESTONE 1 DOES NOT CALL provider.submit().
6. Delegation guard separates worker executing own task from child delegation.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from research_lab.agent_control.contracts import (
    HASH_PROFILE,
    AgentRoute,
    AgentTask,
    _clean_for_canonical,
    _freeze_mapping,
    _unfreeze_to_dict,
    validate_route_hash,
    validate_task_hash,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
    TamperDetectionError,
)
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.transport import (
    ProviderConnectionDescriptor,
    ProviderTransportKind,
)
from research_lab.contracts import v2


def compute_preparation_deterministic_id(payload: dict[str, Any]) -> str:
    """Compute deterministic preparation ID from task_id, route_id, provider, model, and transport."""
    core = {
        "authorized_permissions": _clean_for_canonical(payload.get("authorized_permissions")),
        "model": payload.get("model"),
        "project_binding": _clean_for_canonical(payload.get("project_binding")),
        "provider": payload.get("provider"),
        "route_id": payload.get("route_id"),
        "task_id": payload.get("task_id"),
        "transport": _clean_for_canonical(payload.get("transport")),
    }
    digest = v2.digest(core)
    return f"prep-{digest[:32]}"


def compute_preparation_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of ExecutionPreparation payload."""
    clean = {
        k: _clean_for_canonical(v)
        for k, v in payload.items()
        if k not in ("preparation_hash", "preparation_content_hash")
    }
    return v2.digest(clean)


def validate_preparation_hash(payload: dict[str, Any]) -> None:
    """Tamper-detection validation for ExecutionPreparation content hash."""
    expected = payload.get("preparation_hash")
    if not expected:
        raise TamperDetectionError("Missing preparation_hash in payload")
    actual = compute_preparation_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"ExecutionPreparation content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class ExecutionPreparation:
    """Immutable, validated execution preparation token ready for provider handoff."""

    preparation_id: str
    task_id: str
    route_id: str
    task_ref: dict[str, Any]
    route_ref: dict[str, Any]
    provider: str
    model: str
    transport: ProviderConnectionDescriptor
    authorized_permissions: tuple[str, ...]
    project_binding: dict[str, str]
    preparation_hash: str
    schema_version: str = "research_lab.execution_preparation.v1"
    hash_profile: str = HASH_PROFILE

    def __post_init__(self) -> None:
        if not self.preparation_id or not self.preparation_id.startswith("prep-"):
            raise TamperDetectionError("Invalid or missing preparation_id")

        expected_id = compute_preparation_deterministic_id(self.to_dict())
        if self.preparation_id != expected_id:
            raise TamperDetectionError(
                f"ExecutionPreparation preparation_id mismatch: expected {expected_id}, got {self.preparation_id}"
            )

        validate_preparation_hash(self.to_dict())
        object.__setattr__(self, "task_ref", _freeze_mapping(self.task_ref))
        object.__setattr__(self, "route_ref", _freeze_mapping(self.route_ref))
        object.__setattr__(self, "project_binding", _freeze_mapping(self.project_binding))

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized_permissions": list(self.authorized_permissions),
            "hash_profile": self.hash_profile,
            "model": self.model,
            "preparation_hash": self.preparation_hash,
            "preparation_id": self.preparation_id,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "provider": self.provider,
            "route_id": self.route_id,
            "route_ref": _unfreeze_to_dict(self.route_ref),
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_ref": _unfreeze_to_dict(self.task_ref),
            "transport": self.transport.to_dict(),
        }

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> ExecutionPreparation:
        if memo is None:
            memo = {}
        d = id(self)
        if d in memo:
            return memo[d]
        copied = copy.deepcopy(_unfreeze_to_dict(self.to_dict()), memo)
        trans_dict = copied["transport"]
        transport_obj = ProviderConnectionDescriptor(
            transport_kind=trans_dict["transport_kind"],
            connection_profile_ref=trans_dict["connection_profile_ref"],
            capabilities=tuple(trans_dict.get("capabilities", ())),
        )
        instance = self.__class__(
            preparation_id=copied["preparation_id"],
            task_id=copied["task_id"],
            route_id=copied["route_id"],
            task_ref=copied["task_ref"],
            route_ref=copied["route_ref"],
            provider=copied["provider"],
            model=copied["model"],
            transport=transport_obj,
            authorized_permissions=tuple(copied["authorized_permissions"]),
            project_binding=copied["project_binding"],
            preparation_hash=copied["preparation_hash"],
            schema_version=copied["schema_version"],
            hash_profile=copied["hash_profile"],
        )
        memo[d] = instance
        return instance


def prepare_execution(
    task: AgentTask,
    route: AgentRoute,
    registry: ProviderRegistry,
) -> ExecutionPreparation:
    """Validate formal execution handoff boundary between authorized task, route, and provider registry.

    Enforces:
    1. Tamper detection on Task and Route
    2. Scope exact reference consistency (task.authorization_scope_ref == route.authorization_scope_ref)
    3. Role exact consistency (task.role == route.role)
    4. Project binding exact consistency (task.project_binding == route.project_binding)
    5. Authorized permissions exact consistency (task.authorized_permissions == route.authorized_permissions)
    6. Provider registration and model support
    7. Transport compatibility and exact match with provider registration
    8. Least privilege verification

    Returns:
        Immutable ExecutionPreparation object.
    NOTE: Does NOT call provider.submit() (#573 Milestone 1 constraint).
    """
    # 1. Tamper verification
    validate_task_hash(task.to_dict())
    validate_route_hash(route.to_dict())

    # 2. Scope exact ref consistency (fail-closed)
    task_scope = dict(task.authorization_scope_ref)
    route_scope = dict(route.authorization_scope_ref)
    if task_scope != route_scope:
        raise TamperDetectionError(
            "Task and Route authorization_scope_ref mismatch: exact scope provenance broken",
            details={
                "route_scope_id": route_scope.get("scope_id"),
                "task_scope_id": task_scope.get("scope_id"),
            },
        )

    # 3. Role consistency
    if task.role != route.role:
        raise PermissionDeniedError(
            f"Role mismatch between Task ('{task.role}') and Route ('{route.role}')",
            details={"route_role": route.role, "task_role": task.role},
        )

    # 4. Project binding consistency
    task_binding = dict(task.project_binding)
    route_binding = dict(route.project_binding)
    if task_binding != route_binding:
        raise ProjectBindingError(
            f"ProjectBinding mismatch between Task and Route: task={task_binding}, route={route_binding}",
            details={"route_binding": route_binding, "task_binding": task_binding},
        )

    # 5. Authorized permissions consistency & least privilege
    if tuple(task.authorized_permissions) != tuple(route.authorized_permissions):
        raise PermissionDeniedError(
            f"Authorized permissions mismatch between Task and Route: "
            f"task={task.authorized_permissions}, route={route.authorized_permissions}",
            details={
                "route_permissions": route.authorized_permissions,
                "task_permissions": task.authorized_permissions,
            },
        )

    # 6. Provider registration check
    if not registry.contains(route.provider):
        raise ProviderUnavailableError(
            f"Route provider '{route.provider}' is not registered in ProviderRegistry",
            details={"provider": route.provider},
        )
    prov = registry.get(route.provider)
    prov_desc = prov.describe()

    # 7. Model support check
    if route.resolved_model not in prov_desc.supported_models:
        raise ProviderUnavailableError(
            f"Route resolved_model '{route.resolved_model}' is not in supported_models for provider '{route.provider}'",
            details={"provider": route.provider, "resolved_model": route.resolved_model},
        )

    # 8. Transport verification
    transport_desc = registry.get_transport(route.provider)
    if not isinstance(transport_desc, ProviderConnectionDescriptor):
        raise ProviderError(
            ProviderErrorCode.PROVIDER_UNAVAILABLE,
            f"Provider '{route.provider}' has invalid registered transport descriptor: expected ProviderConnectionDescriptor, got {type(transport_desc).__name__ if transport_desc is not None else 'None'}",
            details={"provider": route.provider},
        )
    if route.transport_ref:
        if (
            route.transport_ref != transport_desc.exact_ref
            and route.transport_ref != transport_desc.connection_profile_ref
        ):
            raise ProviderError(
                ProviderErrorCode.PROVIDER_UNAVAILABLE,
                f"Route transport_ref '{route.transport_ref}' does not match registered transport "
                f"exact ref '{transport_desc.exact_ref}' for provider '{route.provider}'",
                details={
                    "provider": route.provider,
                    "registered_exact_ref": transport_desc.exact_ref,
                    "route_transport_ref": route.transport_ref,
                },
            )
        if "://" in route.transport_ref:
            route_kind = route.transport_ref.split("://", 1)[0]
            expected_kind = (
                transport_desc.transport_kind.value
                if isinstance(transport_desc.transport_kind, ProviderTransportKind)
                else str(transport_desc.transport_kind)
            )
            if route_kind != expected_kind:
                raise ProviderError(
                    ProviderErrorCode.PROVIDER_UNAVAILABLE,
                    f"Route transport kind '{route_kind}' does not match registered transport kind '{expected_kind}' for provider '{route.provider}'",
                    details={
                        "provider": route.provider,
                        "registered_kind": expected_kind,
                        "route_kind": route_kind,
                    },
                )

    # 9. Build immutable execution preparation
    raw = {
        "authorized_permissions": list(route.authorized_permissions),
        "hash_profile": HASH_PROFILE,
        "model": route.resolved_model,
        "project_binding": route_binding,
        "provider": route.provider,
        "route_id": route.route_id,
        "route_ref": route.to_dict(),
        "schema_version": "research_lab.execution_preparation.v1",
        "task_id": task.task_id,
        "task_ref": task.to_dict(),
        "transport": transport_desc.to_dict(),
    }
    prep_id = compute_preparation_deterministic_id(raw)
    raw["preparation_id"] = prep_id
    prep_hash = compute_preparation_content_hash(raw)

    return ExecutionPreparation(
        preparation_id=prep_id,
        task_id=task.task_id,
        route_id=route.route_id,
        task_ref=task.to_dict(),
        route_ref=route.to_dict(),
        provider=route.provider,
        model=route.resolved_model,
        transport=transport_desc,
        authorized_permissions=tuple(route.authorized_permissions),
        project_binding=route_binding,
        preparation_hash=prep_hash,
        schema_version="research_lab.execution_preparation.v1",
        hash_profile=HASH_PROFILE,
    )
