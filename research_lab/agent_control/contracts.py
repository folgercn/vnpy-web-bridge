"""Core immutable contracts and deterministic identity hashing (#573 Milestone 0).

Provides deterministic identity and content hashes using canonical research-json-v1 SHA-256
via `research_lab.contracts.v2.digest`. Business/scientific identity NEVER depends on
timestamps (e.g. now()) or random UUIDs.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from research_lab.agent_control.errors import (
    ResultAcceptanceError,
    TamperDetectionError,
)
from research_lab.agent_control.permissions import (
    enforce_hard_invariants,
    validate_permissions,
)
from research_lab.agent_control.roles import validate_role
from research_lab.contracts import v2

HASH_PROFILE = "research-json-v1"


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
    if isinstance(obj, dict):
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

    def to_dict(self) -> dict[str, str]:
        return {
            "binding_mode": self.binding_mode,
            "project_id": self.project_id,
            "workspace_identity": self.workspace_identity,
        }


@dataclass(frozen=True)
class AgentPermissionScope:
    """Result of access control authorization evaluation."""

    role: str
    requested_permissions: tuple[str, ...]
    authorized_permissions: tuple[str, ...]
    denied_permissions: tuple[str, ...]
    is_authorized: bool
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized_permissions": list(self.authorized_permissions),
            "context": _clean_for_canonical(self.context),
            "denied_permissions": list(self.denied_permissions),
            "is_authorized": self.is_authorized,
            "requested_permissions": list(self.requested_permissions),
            "role": self.role,
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
    role: str
    requested_permissions: tuple[str, ...]
    authorized_permissions: tuple[str, ...]
    objective: str
    work_block: str
    input_refs: tuple[dict[str, str], ...]
    provider_policy_ref: str
    project_binding: dict[str, str]
    created_by: str
    created_at: str
    task_content_hash: str
    schema_version: str = "research_lab.agent_task.v1"
    hash_profile: str = HASH_PROFILE
    delegation_depth: int = 0
    parent_task_ref: dict[str, str] | None = None

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
        delegation_depth: int = 0,
        parent_task_ref: dict[str, str] | None = None,
    ) -> AgentTask:
        validate_role(role)
        val_req = validate_permissions(requested_permissions)
        val_auth = validate_permissions(authorized_permissions)
        enforce_hard_invariants(val_req)
        enforce_hard_invariants(val_auth)

        binding_dict = project_binding.to_dict() if isinstance(project_binding, ProjectBinding) else dict(project_binding)

        raw = {
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
            "authorized_permissions": list(self.authorized_permissions),
            "created_at": self.created_at,
            "created_by": self.created_by,
            "delegation_depth": self.delegation_depth,
            "hash_profile": self.hash_profile,
            "input_refs": list(self.input_refs),
            "objective": self.objective,
            "parent_task_ref": self.parent_task_ref,
            "project_binding": dict(self.project_binding),
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
    """Compute deterministic route ID from role, provider, resolved model, and policy version."""
    core = {
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
    role: str
    provider: str
    resolved_model: str
    policy_version: str
    route_reason: str
    usage_snapshot_ref: str | None
    project_binding: dict[str, str]
    authorized_permissions: tuple[str, ...]
    route_content_hash: str
    schema_version: str = "research_lab.agent_route.v1"
    hash_profile: str = HASH_PROFILE

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
    ) -> AgentRoute:
        validate_role(role)
        val_auth = validate_permissions(authorized_permissions)
        enforce_hard_invariants(val_auth)
        binding_dict = project_binding.to_dict() if isinstance(project_binding, ProjectBinding) else dict(project_binding)

        raw = {
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
            "authorized_permissions": list(self.authorized_permissions),
            "hash_profile": self.hash_profile,
            "policy_version": self.policy_version,
            "project_binding": dict(self.project_binding),
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
            task_ref=copy.deepcopy(task_ref),
            route_ref=copy.deepcopy(route_ref),
            provider_job_ref=provider_job_ref,
            project_binding=binding_dict,
            input_refs=tuple(copy.deepcopy(input_refs)),
            requested_permissions=tuple(val_req),
            authorized_permissions=tuple(val_auth),
            usage_snapshot_ref=usage_snapshot_ref,
            terminal_status=terminal_status,
            result_ref=copy.deepcopy(result_ref) if result_ref else None,
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
            "input_refs": list(self.input_refs),
            "policy_version": self.policy_version,
            "project_binding": dict(self.project_binding),
            "provider": self.provider,
            "provider_job_ref": self.provider_job_ref,
            "recorded_at": self.recorded_at,
            "requested_permissions": list(self.requested_permissions),
            "result_ref": dict(self.result_ref) if self.result_ref else None,
            "role": self.role,
            "resolved_model": self.resolved_model,
            "route_ref": dict(self.route_ref),
            "schema_version": self.schema_version,
            "task_ref": dict(self.task_ref),
            "terminal_status": self.terminal_status,
            "usage_snapshot_ref": self.usage_snapshot_ref,
        }
