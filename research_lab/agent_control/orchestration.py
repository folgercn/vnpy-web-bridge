"""Milestone 7: Multi-Agent Orchestration (#573).

Provides a minimal, controlled, auditable Multi-Agent Orchestration layer where
Sol / Orchestrator can distribute multiple mutually independent Agent work blocks:
Orchestrator
├─ alpha_generator
├─ data_researcher
└─ external_researcher
        ↓
structured worker results
        ↓
deterministic aggregation
        ↓
Sol acceptance / existing M6 boundary

Core Boundaries & Invariants:
1. Double-enforced prohibition of nested delegation (delegation_depth > 1 rejected).
2. Worker-to-Worker peer messaging and shared mutable conversation state strictly prohibited.
3. Strict context isolation per work block (independent tasks, routes, jobs, results).
4. Deterministic identity and aggregation (completion order does not alter aggregate hash or ordering).
5. Single-worker failure isolation (Provider/Agent failure != scientific REJECT, zero memory pollution).
6. Alpha candidate admission strictly follows M5/M6 gates; majority vote cannot bypass acceptance.
7. data_researcher / external_researcher output != Evidence, != CriticDecision.
8. Orchestrator never produces scientific PROMOTE / REJECT / NEED_MORE_EVIDENCE, nor trades.
9. Append-only auditable provenance for every work block.
10. Permanent prohibition: is_tradable = False, live_trading_authorized = False.
"""

from __future__ import annotations

import copy
import datetime
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from research_lab.agent_control.alpha_generator import (
    AlphaGenerationCandidate,
    _extract_raw_output,
    compute_scientific_identity_hash,
    parse_alpha_generation_output,
    validate_hypothesis,
)
from research_lab.agent_control.contracts import (
    HASH_PROFILE,
    AgentResult,
    AgentTask,
    AgentUsageSnapshot,
    ProjectBinding,
    TerminalStatus,
    validate_project_binding,
)
from research_lab.agent_control.discovery_integration import (
    DiscoveryIntegrationOrchestrator,
    DiscoveryIntegrationResult,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    TamperDetectionError,
)
from research_lab.agent_control.handoff import (
    prepare_execution,
)
from research_lab.agent_control.permissions import (
    enforce_hard_invariants,
    validate_permissions,
)
from research_lab.agent_control.provider import AgentProvider
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.roles import (
    DEFAULT_ROLE_POLICIES,
    AgentRole,
    validate_role,
)
from research_lab.agent_control.router import (
    authorize,
    select_agent,
)
from research_lab.agent_control.routing_policy import RoutingPolicy
from research_lab.alpha_discovery import (
    AlphaHypothesis,
    compute_hypothesis_content_hash,
)
from research_lab.contracts import v2

ORCHESTRATION_SCHEMA_VERSION = "research_lab.multi_agent_orchestration.v1"
MAX_WORK_BLOCKS = 8
DEFAULT_AGGREGATION_POLICY = "deterministic_v1"
DEFAULT_CONCURRENCY_POLICY = "bounded_v1"

# Supported Worker roles for Milestone 7
SUPPORTED_WORKER_ROLES = frozenset(
    {
        AgentRole.ALPHA_GENERATOR.value,
        AgentRole.DATA_RESEARCHER.value,
        AgentRole.EXTERNAL_RESEARCHER.value,
    }
)

if not hasattr(AlphaGenerationCandidate, "candidate_id"):
    AlphaGenerationCandidate.candidate_id = property(
        lambda self: self.hypothesis.hypothesis_id
    )


def _clean_for_canonical(val: Any) -> Any:
    """Recursively clean objects into canonical primitives for deterministic hashing."""
    if val is None or isinstance(val, (int, float, bool, str)):
        return val
    if hasattr(val, "to_dict") and callable(val.to_dict):
        return _clean_for_canonical(val.to_dict())
    if isinstance(val, (list, tuple)):
        return [_clean_for_canonical(x) for x in val]
    if isinstance(val, (dict, Mapping)):
        return {
            str(k): _clean_for_canonical(v)
            for k, v in sorted(val.items(), key=lambda item: str(item[0]))
        }
    return str(val)


class OrchestrationEngineeringStatus(str, Enum):
    """Engineering outcome status of multi-agent orchestration."""

    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    ALL_FAILED = "ALL_FAILED"
    UNCERTAIN = "UNCERTAIN"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"


# --- OrchestratedWorkBlock Contract ---


def compute_work_block_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of OrchestratedWorkBlock specification."""
    clean = {
        k: _clean_for_canonical(v)
        for k, v in payload.items()
        if k != "work_block_content_hash"
    }
    return v2.digest(clean)


def validate_work_block_hash(payload: dict[str, Any]) -> None:
    """Validate content hash against payload to detect tampering."""
    expected = payload.get("work_block_content_hash")
    if not expected:
        raise TamperDetectionError("Missing work_block_content_hash in payload")
    actual = compute_work_block_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"OrchestratedWorkBlock content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class OrchestratedWorkBlock:
    """Specification of a discrete 1st-level worker task within an orchestration request."""

    work_block_id: str
    role: str
    objective: str
    prompt: str
    requested_permissions: tuple[str, ...]
    input_refs: tuple[dict[str, str], ...]
    ordinal: int = 0
    authoritative_origin_type: str | None = None
    work_block_content_hash: str = ""
    schema_version: str = ORCHESTRATION_SCHEMA_VERSION
    hash_profile: str = HASH_PROFILE

    def __post_init__(self) -> None:
        if not self.work_block_id or not isinstance(self.work_block_id, str):
            raise ValueError("work_block_id must be a non-empty string")
        if self.role not in SUPPORTED_WORKER_ROLES:
            raise PermissionDeniedError(
                f"Unsupported worker role '{self.role}' for Multi-Agent Orchestration. "
                f"Supported roles: {sorted(SUPPORTED_WORKER_ROLES)}",
                details={
                    "requested_role": self.role,
                    "supported_roles": sorted(SUPPORTED_WORKER_ROLES),
                },
            )
        if not self.objective or not self.objective.strip():
            raise ValueError("objective cannot be empty")
        if not self.prompt or not self.prompt.strip():
            raise ValueError("prompt cannot be empty")
        if self.ordinal < 0:
            raise ValueError(f"ordinal must be >= 0, got {self.ordinal}")

        val_req = validate_permissions(self.requested_permissions)
        enforce_hard_invariants(val_req)

        active_policy = DEFAULT_ROLE_POLICIES.get(self.role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(val_req).issubset(allowed):
                unauthorized = sorted(set(val_req) - allowed)
                raise PermissionDeniedError(
                    f"Requested permissions {unauthorized} not allowed for role '{self.role}'",
                    details={
                        "role": self.role,
                        "unauthorized_permissions": unauthorized,
                    },
                )

        if self.work_block_content_hash:
            validate_work_block_hash(self.to_dict())

    @classmethod
    def create(
        cls,
        *,
        work_block_id: str,
        role: str,
        objective: str,
        prompt: str,
        requested_permissions: Sequence[str],
        input_refs: Sequence[dict[str, str]] = (),
        ordinal: int = 0,
        authoritative_origin_type: str | None = None,
    ) -> OrchestratedWorkBlock:
        val_role = validate_role(role)
        if val_role not in SUPPORTED_WORKER_ROLES:
            raise PermissionDeniedError(
                f"Unsupported worker role '{val_role}' for Multi-Agent Orchestration",
                details={
                    "requested_role": val_role,
                    "supported_roles": sorted(SUPPORTED_WORKER_ROLES),
                },
            )
        val_req = validate_permissions(requested_permissions)
        enforce_hard_invariants(val_req)

        active_policy = DEFAULT_ROLE_POLICIES.get(val_role)
        if active_policy:
            allowed = set(active_policy.allowed_permissions)
            if not set(val_req).issubset(allowed):
                unauthorized = sorted(set(val_req) - allowed)
                raise PermissionDeniedError(
                    f"Requested permissions {unauthorized} not allowed for role '{val_role}'",
                    details={
                        "role": val_role,
                        "unauthorized_permissions": unauthorized,
                    },
                )

        clean_inputs = tuple(_clean_for_canonical(x) for x in input_refs)

        raw = {
            "authoritative_origin_type": authoritative_origin_type,
            "hash_profile": HASH_PROFILE,
            "input_refs": list(clean_inputs),
            "objective": objective.strip(),
            "ordinal": ordinal,
            "prompt": prompt.strip(),
            "requested_permissions": sorted(val_req),
            "role": val_role,
            "schema_version": ORCHESTRATION_SCHEMA_VERSION,
            "work_block_id": work_block_id.strip(),
        }
        content_hash = compute_work_block_content_hash(raw)

        return cls(
            work_block_id=work_block_id.strip(),
            role=val_role,
            objective=objective.strip(),
            prompt=prompt.strip(),
            requested_permissions=tuple(sorted(val_req)),
            input_refs=clean_inputs,
            ordinal=ordinal,
            authoritative_origin_type=authoritative_origin_type,
            work_block_content_hash=content_hash,
            schema_version=ORCHESTRATION_SCHEMA_VERSION,
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "authoritative_origin_type": self.authoritative_origin_type,
            "hash_profile": self.hash_profile,
            "input_refs": [_clean_for_canonical(x) for x in self.input_refs],
            "objective": self.objective,
            "ordinal": self.ordinal,
            "prompt": self.prompt,
            "requested_permissions": list(self.requested_permissions),
            "role": self.role,
            "schema_version": self.schema_version,
            "work_block_content_hash": self.work_block_content_hash,
            "work_block_id": self.work_block_id,
        }


# --- MultiAgentOrchestrationRequest Contract ---


def compute_orchestration_deterministic_id(payload: dict[str, Any]) -> str:
    """Compute deterministic orchestration ID from canonical request specification.

    Timestamps (created_at) and transient attributes are EXCLUDED from deterministic identity.
    """
    clean_blocks = [
        {
            "authoritative_origin_type": wb.get("authoritative_origin_type"),
            "input_refs": _clean_for_canonical(wb.get("input_refs", ())),
            "objective": wb.get("objective"),
            "ordinal": wb.get("ordinal", 0),
            "prompt": wb.get("prompt"),
            "requested_permissions": _clean_for_canonical(
                wb.get("requested_permissions", ())
            ),
            "role": wb.get("role"),
            "work_block_id": wb.get("work_block_id"),
        }
        for wb in sorted(
            payload.get("work_blocks", []),
            key=lambda b: (b.get("ordinal", 0), b.get("work_block_id", "")),
        )
    ]
    core = {
        "aggregation_policy": payload.get(
            "aggregation_policy", DEFAULT_AGGREGATION_POLICY
        ),
        "concurrency_policy": payload.get(
            "concurrency_policy", DEFAULT_CONCURRENCY_POLICY
        ),
        "project_binding": _clean_for_canonical(payload.get("project_binding", {})),
        "purpose": payload.get("purpose", ""),
        "work_blocks": clean_blocks,
    }
    digest = v2.digest(core)
    return f"orch-{digest[:32]}"


def compute_orchestration_request_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of MultiAgentOrchestrationRequest payload."""
    clean = {
        k: _clean_for_canonical(v)
        for k, v in payload.items()
        if k != "request_content_hash"
    }
    return v2.digest(clean)


def validate_orchestration_request_hash(payload: dict[str, Any]) -> None:
    """Tamper-detection validation for MultiAgentOrchestrationRequest."""
    expected = payload.get("request_content_hash")
    if not expected:
        raise TamperDetectionError("Missing request_content_hash in payload")
    actual = compute_orchestration_request_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"MultiAgentOrchestrationRequest content hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class MultiAgentOrchestrationRequest:
    """Top-level request to orchestrate multiple independent 1st-level work blocks."""

    orchestration_id: str
    project_binding: dict[str, str]
    purpose: str
    work_blocks: tuple[OrchestratedWorkBlock, ...]
    aggregation_policy: str = DEFAULT_AGGREGATION_POLICY
    concurrency_policy: str = DEFAULT_CONCURRENCY_POLICY
    delegation_depth: int = 0
    caller_identity: str = "orchestrator"
    created_at: str = ""
    request_content_hash: str = ""
    schema_version: str = ORCHESTRATION_SCHEMA_VERSION
    hash_profile: str = HASH_PROFILE

    def __post_init__(self) -> None:
        if self.delegation_depth != 0:
            raise PermissionDeniedError(
                f"Nested orchestration prohibited: delegation_depth={self.delegation_depth} (must be 0 for top-level orchestrator)",
                details={"delegation_depth": self.delegation_depth},
            )
        if "worker" in self.caller_identity.lower():
            raise PermissionDeniedError(
                f"Worker '{self.caller_identity}' cannot initiate orchestration (caller_identity prohibited)",
                details={"caller_identity": self.caller_identity},
            )
        validate_project_binding(self.project_binding)

        if not self.work_blocks:
            raise ValueError(
                "Orchestration request must specify at least one work block (non-empty)"
            )
        if len(self.work_blocks) > MAX_WORK_BLOCKS:
            raise ValueError(
                f"Orchestration request exceeds maximum allowable work blocks {MAX_WORK_BLOCKS}: got {len(self.work_blocks)}"
            )

        # Unique work block IDs check (fail-closed)
        wb_ids = [wb.work_block_id for wb in self.work_blocks]
        if len(wb_ids) != len(set(wb_ids)):
            duplicates = sorted({x for x in wb_ids if wb_ids.count(x) > 1})
            raise ValueError(f"Duplicate work block ID fail closed: {duplicates}")

        # Deterministic identity verification
        expected_id = compute_orchestration_deterministic_id(self.to_dict())
        if self.orchestration_id != expected_id:
            raise TamperDetectionError(
                f"MultiAgentOrchestrationRequest orchestration_id mismatch: expected {expected_id}, got {self.orchestration_id}"
            )

        if self.request_content_hash:
            validate_orchestration_request_hash(self.to_dict())

    @classmethod
    def create(
        cls,
        *,
        project_binding: ProjectBinding | Mapping[str, str],
        purpose: str,
        work_blocks: Sequence[OrchestratedWorkBlock],
        aggregation_policy: str = DEFAULT_AGGREGATION_POLICY,
        concurrency_policy: str = DEFAULT_CONCURRENCY_POLICY,
        delegation_depth: int = 0,
        caller_identity: str = "orchestrator",
        created_at: str = "",
        expected_binding: ProjectBinding | Mapping[str, str] | None = None,
    ) -> MultiAgentOrchestrationRequest:
        if delegation_depth != 0:
            raise PermissionDeniedError(
                f"Nested orchestration prohibited: delegation_depth={delegation_depth} (must be 0)",
                details={"delegation_depth": delegation_depth},
            )
        if "worker" in caller_identity.lower():
            raise PermissionDeniedError(
                f"Worker '{caller_identity}' cannot initiate orchestration",
                details={"caller_identity": caller_identity},
            )

        val_binding = validate_project_binding(
            project_binding, expected_binding=expected_binding
        )
        binding_dict = val_binding.to_dict()

        if not work_blocks:
            raise ValueError(
                "Orchestration request must specify at least one work block (non-empty)"
            )
        if len(work_blocks) > MAX_WORK_BLOCKS:
            raise ValueError(
                f"Orchestration request exceeds maximum allowable work blocks {MAX_WORK_BLOCKS}: got {len(work_blocks)}"
            )

        wb_ids = [wb.work_block_id for wb in work_blocks]
        if len(wb_ids) != len(set(wb_ids)):
            duplicates = sorted({x for x in wb_ids if wb_ids.count(x) > 1})
            raise ValueError(f"Duplicate work block ID fail closed: {duplicates}")

        # Ensure stable ordering of blocks
        ordered_blocks = tuple(
            sorted(work_blocks, key=lambda b: (b.ordinal, b.work_block_id))
        )

        raw = {
            "aggregation_policy": aggregation_policy,
            "caller_identity": caller_identity,
            "concurrency_policy": concurrency_policy,
            "created_at": created_at,
            "delegation_depth": delegation_depth,
            "hash_profile": HASH_PROFILE,
            "project_binding": binding_dict,
            "purpose": purpose.strip(),
            "schema_version": ORCHESTRATION_SCHEMA_VERSION,
            "work_blocks": [wb.to_dict() for wb in ordered_blocks],
        }

        orch_id = compute_orchestration_deterministic_id(raw)
        raw["orchestration_id"] = orch_id
        content_hash = compute_orchestration_request_hash(raw)

        return cls(
            orchestration_id=orch_id,
            project_binding=binding_dict,
            purpose=purpose.strip(),
            work_blocks=ordered_blocks,
            aggregation_policy=aggregation_policy,
            concurrency_policy=concurrency_policy,
            delegation_depth=delegation_depth,
            caller_identity=caller_identity,
            created_at=created_at,
            request_content_hash=content_hash,
            schema_version=ORCHESTRATION_SCHEMA_VERSION,
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregation_policy": self.aggregation_policy,
            "caller_identity": self.caller_identity,
            "concurrency_policy": self.concurrency_policy,
            "created_at": self.created_at,
            "delegation_depth": self.delegation_depth,
            "hash_profile": self.hash_profile,
            "orchestration_id": self.orchestration_id,
            "project_binding": dict(self.project_binding),
            "purpose": self.purpose,
            "request_content_hash": self.request_content_hash,
            "schema_version": self.schema_version,
            "work_blocks": [wb.to_dict() for wb in self.work_blocks],
        }


# --- OrchestrationPlan Contract ---


def compute_plan_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of OrchestrationPlan payload."""
    clean = {
        k: _clean_for_canonical(v)
        for k, v in payload.items()
        if k != "plan_content_hash"
    }
    return v2.digest(clean)


@dataclass(frozen=True)
class OrchestrationPlan:
    """Execution plan derived from an authorized MultiAgentOrchestrationRequest."""

    plan_id: str
    orchestration_id: str
    project_binding: dict[str, str]
    work_blocks: tuple[OrchestratedWorkBlock, ...]
    plan_content_hash: str = ""
    schema_version: str = ORCHESTRATION_SCHEMA_VERSION
    hash_profile: str = HASH_PROFILE

    @classmethod
    def create(cls, request: MultiAgentOrchestrationRequest) -> OrchestrationPlan:
        core = {
            "orchestration_id": request.orchestration_id,
            "project_binding": dict(request.project_binding),
            "work_blocks": [wb.to_dict() for wb in request.work_blocks],
        }
        digest = v2.digest(core)
        plan_id = f"plan-{digest[:32]}"
        raw = {
            "hash_profile": HASH_PROFILE,
            "orchestration_id": request.orchestration_id,
            "plan_id": plan_id,
            "project_binding": dict(request.project_binding),
            "schema_version": ORCHESTRATION_SCHEMA_VERSION,
            "work_blocks": [wb.to_dict() for wb in request.work_blocks],
        }
        content_hash = compute_plan_content_hash(raw)
        return cls(
            plan_id=plan_id,
            orchestration_id=request.orchestration_id,
            project_binding=dict(request.project_binding),
            work_blocks=request.work_blocks,
            plan_content_hash=content_hash,
            schema_version=ORCHESTRATION_SCHEMA_VERSION,
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hash_profile": self.hash_profile,
            "orchestration_id": self.orchestration_id,
            "plan_content_hash": self.plan_content_hash,
            "plan_id": self.plan_id,
            "project_binding": dict(self.project_binding),
            "schema_version": self.schema_version,
            "work_blocks": [wb.to_dict() for wb in self.work_blocks],
        }


# --- WorkBlockExecutionResult Contract ---


def compute_work_block_result_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of WorkBlockExecutionResult payload."""
    clean = {
        k: _clean_for_canonical(v) for k, v in payload.items() if k != "result_hash"
    }
    return v2.digest(clean)


def validate_work_block_result_hash(payload: dict[str, Any]) -> None:
    expected = payload.get("result_hash")
    if not expected:
        raise TamperDetectionError(
            "Missing result_hash in WorkBlockExecutionResult payload"
        )
    actual = compute_work_block_result_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"WorkBlockExecutionResult hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class WorkBlockExecutionResult:
    """Structured envelope capturing execution outcome and provenance of an orchestrated work block."""

    orchestration_id: str
    work_block_id: str
    task_id: str
    role: str
    authorized_permissions: tuple[str, ...]
    route_id: str
    provider: str
    model: str
    transport_ref: str
    usage_snapshot_ref: str | None
    provider_job_ref: str
    terminal_status: str
    acceptance_status: str | None
    structured_result_type: str | None
    structured_output: dict[str, Any] | None
    raw_result_ref: str | None
    result_hash: str
    error_code: str | None
    error_message: str | None
    tool_failures: tuple[str, ...]
    project_binding: dict[str, str]
    audit_ref: str | None
    ordinal: int = 0
    admitted_candidate: AlphaGenerationCandidate | None = None
    work_block_content_hash: str = ""
    schema_version: str = ORCHESTRATION_SCHEMA_VERSION
    hash_profile: str = HASH_PROFILE

    def __post_init__(self) -> None:
        if not self.work_block_id:
            raise ValueError("work_block_id cannot be empty")
        if not self.orchestration_id:
            raise ValueError("orchestration_id cannot be empty")
        if not self.task_id:
            raise ValueError("task_id cannot be empty")
        if not self.result_hash:
            raise TamperDetectionError(
                "Missing result_hash in WorkBlockExecutionResult"
            )
        validate_work_block_result_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "acceptance_status": self.acceptance_status,
            "admitted_candidate_id": self.admitted_candidate.candidate_id
            if self.admitted_candidate
            else None,
            "audit_ref": self.audit_ref,
            "authorized_permissions": list(self.authorized_permissions),
            "error_code": self.error_code,
            "error_message": self.error_message,
            "hash_profile": self.hash_profile,
            "model": self.model,
            "orchestration_id": self.orchestration_id,
            "ordinal": self.ordinal,
            "project_binding": dict(self.project_binding),
            "provider": self.provider,
            "provider_job_ref": self.provider_job_ref,
            "raw_result_ref": self.raw_result_ref,
            "result_hash": self.result_hash,
            "role": self.role,
            "route_id": self.route_id,
            "schema_version": self.schema_version,
            "structured_output": copy.deepcopy(self.structured_output),
            "structured_result_type": self.structured_result_type,
            "task_id": self.task_id,
            "terminal_status": self.terminal_status,
            "tool_failures": list(self.tool_failures),
            "transport_ref": self.transport_ref,
            "usage_snapshot_ref": self.usage_snapshot_ref,
            "work_block_content_hash": self.work_block_content_hash,
            "work_block_id": self.work_block_id,
        }

    @classmethod
    def create(
        cls,
        *,
        orchestration_id: str,
        work_block_id: str,
        task_id: str,
        role: str,
        authorized_permissions: Sequence[str],
        route_id: str,
        provider: str,
        model: str,
        transport_ref: str,
        provider_job_ref: str,
        terminal_status: str,
        acceptance_status: str | None,
        structured_result_type: str | None = None,
        structured_output: dict[str, Any] | None = None,
        raw_result_ref: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        tool_failures: Sequence[str] = (),
        project_binding: ProjectBinding | Mapping[str, str],
        audit_ref: str | None = None,
        ordinal: int = 0,
        admitted_candidate: AlphaGenerationCandidate | None = None,
        work_block_content_hash: str = "",
        usage_snapshot_ref: str | None = None,
        schema_version: str = ORCHESTRATION_SCHEMA_VERSION,
        hash_profile: str = HASH_PROFILE,
    ) -> WorkBlockExecutionResult:
        binding_dict = dict(
            project_binding.to_dict()
            if isinstance(project_binding, ProjectBinding)
            else project_binding
        )
        clean_structured = (
            _clean_for_canonical(structured_output)
            if structured_output is not None
            else None
        )
        raw = {
            "acceptance_status": acceptance_status,
            "admitted_candidate_id": admitted_candidate.candidate_id
            if admitted_candidate
            else None,
            "audit_ref": audit_ref,
            "authorized_permissions": sorted(authorized_permissions),
            "error_code": error_code,
            "error_message": error_message,
            "hash_profile": hash_profile,
            "model": model,
            "orchestration_id": orchestration_id,
            "ordinal": ordinal,
            "project_binding": binding_dict,
            "provider": provider,
            "provider_job_ref": provider_job_ref,
            "raw_result_ref": raw_result_ref,
            "role": role,
            "route_id": route_id,
            "schema_version": schema_version,
            "structured_output": clean_structured,
            "structured_result_type": structured_result_type,
            "task_id": task_id,
            "terminal_status": terminal_status,
            "tool_failures": list(tool_failures),
            "transport_ref": transport_ref,
            "usage_snapshot_ref": usage_snapshot_ref,
            "work_block_content_hash": work_block_content_hash,
            "work_block_id": work_block_id,
        }
        res_hash = compute_work_block_result_hash(raw)
        return cls(
            orchestration_id=orchestration_id,
            work_block_id=work_block_id,
            task_id=task_id,
            role=role,
            authorized_permissions=tuple(sorted(authorized_permissions)),
            route_id=route_id,
            provider=provider,
            model=model,
            transport_ref=transport_ref,
            usage_snapshot_ref=usage_snapshot_ref,
            provider_job_ref=provider_job_ref,
            terminal_status=terminal_status,
            acceptance_status=acceptance_status,
            structured_result_type=structured_result_type,
            structured_output=copy.deepcopy(structured_output),
            raw_result_ref=raw_result_ref,
            result_hash=res_hash,
            error_code=error_code,
            error_message=error_message,
            tool_failures=tuple(tool_failures),
            project_binding=binding_dict,
            audit_ref=audit_ref,
            ordinal=ordinal,
            admitted_candidate=admitted_candidate,
            work_block_content_hash=work_block_content_hash,
            schema_version=schema_version,
            hash_profile=hash_profile,
        )


# --- MultiAgentAggregateResult Contract ---


def compute_aggregate_content_hash(payload: dict[str, Any]) -> str:
    """Compute canonical hash of MultiAgentAggregateResult payload.

    Timestamps, audit references, and transient properties are EXCLUDED.
    """
    clean = {
        k: _clean_for_canonical(v)
        for k, v in payload.items()
        if k not in ("aggregate_content_hash", "audit_ref")
    }
    return v2.digest(clean)


def validate_aggregate_hash(payload: dict[str, Any]) -> None:
    expected = payload.get("aggregate_content_hash")
    if not expected:
        raise TamperDetectionError("Missing aggregate_content_hash in payload")
    actual = compute_aggregate_content_hash(payload)
    if expected != actual:
        raise TamperDetectionError(
            f"MultiAgentAggregateResult hash tampering detected: expected {expected}, computed {actual}",
            details={"expected_hash": expected, "computed_hash": actual},
        )


@dataclass(frozen=True)
class MultiAgentAggregateResult:
    """Deterministic aggregate of all work block outcomes across an orchestration session."""

    orchestration_id: str
    project_binding: dict[str, str]
    aggregation_policy: str
    orchestration_engineering_status: str
    work_block_results: tuple[WorkBlockExecutionResult, ...]
    per_worker_outcomes: dict[str, str]
    per_worker_provenance: dict[str, dict[str, str]]
    successful_outputs: tuple[dict[str, Any], ...]
    failed_work_blocks: tuple[str, ...]
    uncertain_work_blocks: tuple[str, ...]
    m6_eligible_candidate: AlphaGenerationCandidate | None = None
    m6_eligible_candidate_id: str | None = None
    is_eligible_for_m6: bool = False
    is_tradable: bool = False
    aggregate_content_hash: str = ""
    audit_ref: str | None = None
    schema_version: str = ORCHESTRATION_SCHEMA_VERSION
    hash_profile: str = HASH_PROFILE

    def __post_init__(self) -> None:
        if self.is_tradable:
            raise ValueError(
                "Multi-agent orchestration can NEVER grant tradable authority (is_tradable must be False)"
            )
        if self.orchestration_engineering_status not in {
            s.value for s in OrchestrationEngineeringStatus
        }:
            raise ValueError(
                f"Invalid orchestration_engineering_status: {self.orchestration_engineering_status}"
            )

        if self.aggregate_content_hash:
            validate_aggregate_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregate_content_hash": self.aggregate_content_hash,
            "aggregation_policy": self.aggregation_policy,
            "audit_ref": self.audit_ref,
            "failed_work_blocks": list(self.failed_work_blocks),
            "hash_profile": self.hash_profile,
            "is_eligible_for_m6": self.is_eligible_for_m6,
            "is_tradable": self.is_tradable,
            "m6_eligible_candidate_id": (
                self.m6_eligible_candidate.candidate_id
                if self.m6_eligible_candidate
                else self.m6_eligible_candidate_id
            ),
            "orchestration_engineering_status": self.orchestration_engineering_status,
            "orchestration_id": self.orchestration_id,
            "per_worker_outcomes": dict(self.per_worker_outcomes),
            "per_worker_provenance": copy.deepcopy(self.per_worker_provenance),
            "project_binding": dict(self.project_binding),
            "schema_version": self.schema_version,
            "successful_outputs": [
                _clean_for_canonical(x) for x in self.successful_outputs
            ],
            "uncertain_work_blocks": list(self.uncertain_work_blocks),
            "work_block_results": [r.to_dict() for r in self.work_block_results],
        }


# --- OrchestrationAuditRecord & Trail ---


def compute_orchestration_audit_id(payload: dict[str, Any]) -> str:
    core = {
        "engineering_status": payload.get("engineering_status"),
        "orchestration_id": payload.get("orchestration_id"),
        "project_binding": _clean_for_canonical(payload.get("project_binding")),
        "work_block_ids": _clean_for_canonical(payload.get("work_block_ids")),
    }
    digest = v2.digest(core)
    return f"orchaudit-{digest[:32]}"


def compute_orchestration_audit_hash(payload: dict[str, Any]) -> str:
    clean = {
        k: _clean_for_canonical(v)
        for k, v in payload.items()
        if k != "audit_content_hash"
    }
    return v2.digest(clean)


@dataclass(frozen=True)
class OrchestrationAuditRecord:
    """Tamper-evident audit record for multi-agent orchestration execution."""

    audit_id: str
    orchestration_id: str
    project_binding: dict[str, str]
    work_block_ids: tuple[str, ...]
    engineering_status: str
    work_block_statuses: dict[str, str]
    per_worker_job_refs: dict[str, str]
    recorded_at: str
    audit_content_hash: str
    schema_version: str = ORCHESTRATION_SCHEMA_VERSION
    hash_profile: str = HASH_PROFILE

    @classmethod
    def create(
        cls,
        *,
        orchestration_id: str,
        project_binding: dict[str, str],
        work_block_ids: Sequence[str],
        engineering_status: str,
        work_block_statuses: Mapping[str, str],
        per_worker_job_refs: Mapping[str, str],
        recorded_at: str,
    ) -> OrchestrationAuditRecord:
        raw = {
            "engineering_status": engineering_status,
            "hash_profile": HASH_PROFILE,
            "orchestration_id": orchestration_id,
            "per_worker_job_refs": dict(per_worker_job_refs),
            "project_binding": dict(project_binding),
            "recorded_at": recorded_at,
            "schema_version": ORCHESTRATION_SCHEMA_VERSION,
            "work_block_ids": list(work_block_ids),
            "work_block_statuses": dict(work_block_statuses),
        }
        audit_id = compute_orchestration_audit_id(raw)
        raw["audit_id"] = audit_id
        content_hash = compute_orchestration_audit_hash(raw)
        return cls(
            audit_id=audit_id,
            orchestration_id=orchestration_id,
            project_binding=dict(project_binding),
            work_block_ids=tuple(work_block_ids),
            engineering_status=engineering_status,
            work_block_statuses=dict(work_block_statuses),
            per_worker_job_refs=dict(per_worker_job_refs),
            recorded_at=recorded_at,
            audit_content_hash=content_hash,
            schema_version=ORCHESTRATION_SCHEMA_VERSION,
            hash_profile=HASH_PROFILE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_content_hash": self.audit_content_hash,
            "audit_id": self.audit_id,
            "engineering_status": self.engineering_status,
            "hash_profile": self.hash_profile,
            "orchestration_id": self.orchestration_id,
            "per_worker_job_refs": dict(self.per_worker_job_refs),
            "project_binding": dict(self.project_binding),
            "recorded_at": self.recorded_at,
            "schema_version": self.schema_version,
            "work_block_ids": list(self.work_block_ids),
            "work_block_statuses": dict(self.work_block_statuses),
        }

    def verify(self) -> bool:
        expected = compute_orchestration_audit_hash(self.to_dict())
        if self.audit_content_hash != expected:
            raise TamperDetectionError("OrchestrationAuditRecord hash mismatch")
        return True


class OrchestrationAuditTrail:
    """In-memory append-only audit trail for orchestration records."""

    def __init__(self) -> None:
        self._records: list[OrchestrationAuditRecord] = []

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    def append(self, record: OrchestrationAuditRecord) -> None:
        record.verify()
        self._records.append(record)

    def get_records(self) -> tuple[OrchestrationAuditRecord, ...]:
        return tuple(self._records)

    def verify_all(self) -> bool:
        for r in self._records:
            r.verify()
        return True


# --- Strict Inter-Worker Communication Prohibition ---


def send_worker_message(sender_wb_id: str, receiver_wb_id: str, message: Any) -> None:
    """Strictly prohibit worker-to-worker communication (contract and runtime fail-closed)."""
    raise PermissionDeniedError(
        f"Worker-to-worker peer communication is strictly prohibited: "
        f"Worker '{sender_wb_id}' cannot send messages or share context with Worker '{receiver_wb_id}'",
        details={"receiver": receiver_wb_id, "sender": sender_wb_id},
    )


# --- MultiAgentOrchestrator Runtime ---


class MultiAgentOrchestrator:
    """Controlled multi-agent orchestration runtime adhering to Milestone 7 contracts."""

    def __init__(
        self,
        *,
        audit_trail: OrchestrationAuditTrail | None = None,
    ) -> None:
        self.audit_trail = audit_trail or OrchestrationAuditTrail()

    def build_plan(self, request: MultiAgentOrchestrationRequest) -> OrchestrationPlan:
        """Validate request and build frozen OrchestrationPlan."""
        # Double-check delegation depth and caller bounds
        if request.delegation_depth != 0:
            raise PermissionDeniedError(
                f"Nested orchestration prohibited: delegation_depth={request.delegation_depth} (must be 0)",
                details={"delegation_depth": request.delegation_depth},
            )
        if "worker" in request.caller_identity.lower():
            raise PermissionDeniedError(
                f"Worker '{request.caller_identity}' cannot initiate orchestration",
                details={"caller_identity": request.caller_identity},
            )
        return OrchestrationPlan.create(request)

    def orchestrate(
        self,
        request: MultiAgentOrchestrationRequest,
        *,
        registry: ProviderRegistry,
        providers: list[Any],
        usage_snapshots: Mapping[str, AgentUsageSnapshot],
        provider_lookup: Callable[[str], AgentProvider],
        routing_policy: RoutingPolicy | None = None,
        caller_delegation_depth: int = 0,
        caller_role: str = "orchestrator",
        created_at: str | None = None,
        duplicate_view_lookup: Callable[[AlphaGenerationCandidate], tuple[Any, Any]]
        | None = None,
        expected_binding: ProjectBinding | Mapping[str, str] | None = None,
    ) -> MultiAgentAggregateResult:
        """Execute multi-agent orchestration across all independent 1st-level work blocks."""
        # 0. Validate project binding against expected binding if provided
        if expected_binding is not None:
            validate_project_binding(
                request.project_binding, expected_binding=expected_binding
            )

        # 1. Runtime caller & delegation check
        if caller_delegation_depth != 0:
            raise PermissionDeniedError(
                f"Nested agent delegation prohibited: caller at delegation_depth={caller_delegation_depth} "
                f"cannot invoke MultiAgentOrchestrator",
                details={"caller_delegation_depth": caller_delegation_depth},
            )
        if caller_role in SUPPORTED_WORKER_ROLES or "worker" in caller_role.lower():
            raise PermissionDeniedError(
                f"Worker role '{caller_role}' cannot invoke MultiAgentOrchestrator (nested orchestration prohibited)",
                details={"caller_role": caller_role},
            )

        # 2. Build and freeze plan
        plan = self.build_plan(request)
        runtime_recorded_at = (
            created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        # Stable task identity decoupled from runtime execution timestamp:
        # Worker tasks and provenance identity are strictly anchored to the frozen request specification.
        worker_created_at = request.created_at or "2026-01-01T00:00:00.000000Z"

        # 3. Execute each work block independently with complete failure isolation
        block_results: list[WorkBlockExecutionResult] = []

        for wb in plan.work_blocks:
            res = self._execute_single_work_block(
                request=request,
                wb=wb,
                registry=registry,
                providers=providers,
                usage_snapshots=usage_snapshots,
                routing_policy=routing_policy,
                provider_lookup=provider_lookup,
                created_at=worker_created_at,
                duplicate_view_lookup=duplicate_view_lookup,
            )
            block_results.append(res)

        # 4. Deterministic aggregation
        aggregate = self.aggregate_results(
            orchestration_id=request.orchestration_id,
            project_binding=request.project_binding,
            aggregation_policy=request.aggregation_policy,
            work_block_results=block_results,
            recorded_at=runtime_recorded_at,
        )

        return aggregate

    def _execute_single_work_block(
        self,
        *,
        request: MultiAgentOrchestrationRequest,
        wb: OrchestratedWorkBlock,
        registry: ProviderRegistry,
        providers: list[Any],
        usage_snapshots: Mapping[str, AgentUsageSnapshot],
        routing_policy: RoutingPolicy | None = None,
        provider_lookup: Callable[[str], AgentProvider],
        created_at: str,
        duplicate_view_lookup: Callable[[AlphaGenerationCandidate], tuple[Any, Any]]
        | None = None,
    ) -> WorkBlockExecutionResult:
        """Execute a single work block with failure boundary isolation."""
        task_id = ""
        route_id = ""
        provider_name = ""
        model_name = ""
        transport_ref = ""
        provider_job_ref = "NOT_SUBMITTED"
        usage_snapshot_ref: str | None = None
        authorized_perms: tuple[str, ...] = ()

        try:
            # 1. Authorize scope for this specific role and requested permissions
            scope = authorize(
                role=wb.role,
                requested_permissions=list(wb.requested_permissions),
                project_binding=request.project_binding,
            )
            authorized_perms = tuple(sorted(scope.authorized_permissions))

            # 3. Create independent AgentTask with delegation_depth = 1 and parent_task_ref
            task = AgentTask.create(
                role=wb.role,
                requested_permissions=list(wb.requested_permissions),
                authorized_permissions=list(authorized_perms),
                objective=wb.objective,
                work_block=wb.prompt,
                input_refs=list(wb.input_refs),
                provider_policy_ref=f"orchestration_work_block:{wb.work_block_id}",
                project_binding=request.project_binding,
                created_by="orchestrator",
                created_at=created_at,
                authorized_scope=scope,
                delegation_depth=1,  # Strict 1st-level worker
                parent_task_ref={"task_id": request.orchestration_id},
            )
            task_id = task.task_id

            # 4. Route selection
            route = select_agent(
                role=wb.role,
                providers=providers,
                authorized_scope=scope,
                project_binding=request.project_binding,
                usage_snapshots=usage_snapshots,
                registry=registry,
                routing_policy=routing_policy,
            )
            route_id = route.route_id
            provider_name = route.provider
            model_name = route.resolved_model
            transport_ref = route.transport_ref
            usage_snapshot_ref = route.usage_snapshot_ref

            # 5. Execution preparation
            preparation = prepare_execution(task, route, registry)

            # 6. Provider submission with isolated request_id
            provider = provider_lookup(route.provider)
            sub_request_id = f"{request.orchestration_id}_{wb.work_block_id}"

            handle = provider.submit(
                task, route, preparation, request_id=sub_request_id
            )
            provider_job_ref = handle.provider_job_ref

            # 7. Result retrieval & acceptance
            agent_result: AgentResult = provider.result(handle, preparation)

            terminal_status = agent_result.terminal_status
            acceptance_status = agent_result.acceptance_status
            tool_failures = tuple(agent_result.tool_failures)
            raw_ref = agent_result.raw_result_ref
            structured_out = copy.deepcopy(agent_result.structured_output)

            admitted_candidate: AlphaGenerationCandidate | None = None
            structured_result_type: str | None = None

            # Role-specific post-processing
            if wb.role == AgentRole.ALPHA_GENERATOR.value:
                structured_result_type = "alpha_candidate"
                if (
                    terminal_status == TerminalStatus.SUCCESS.value
                    and acceptance_status == "ACCEPTED"
                ):
                    # Strictly parse and admit alpha candidate per M5 contract
                    try:
                        raw_text = _extract_raw_output(agent_result)
                    except Exception:  # noqa: BLE001
                        raw_text = ""
                        if isinstance(structured_out, dict):
                            for key in ("response", "output", "text", "content"):
                                if isinstance(structured_out.get(key), str):
                                    raw_text = structured_out[key]
                                    break
                            if not raw_text and "hypothesis" in structured_out:
                                raw_text = json.dumps(structured_out)
                        elif raw_ref:
                            raw_text = raw_ref

                    data = parse_alpha_generation_output(raw_text)
                    scientific = dict(data["hypothesis"])
                    hypothesis_id = (
                        "agent-alpha-"
                        + v2.digest(
                            {
                                "request_id": f"{request.orchestration_id}_{wb.work_block_id}",
                                "scientific": scientific,
                            }
                        )[:24]
                    )
                    payload = {
                        "schema_version": "research_lab.alpha_hypothesis.v1",
                        "hash_profile": "research-json-v1",
                        "hypothesis_id": hypothesis_id,
                        "revision": "rev.1",
                        **scientific,
                        "provenance": {
                            "origin_type": wb.authoritative_origin_type or "astra",
                            "origin_ref": f"agent_task:{task.task_id};provider:{provider_name};model:{model_name}",
                            "created_by": "alpha_generator",
                            "created_at": created_at,
                        },
                        "parent_hypothesis_ref": None,
                        "related_hypothesis_refs": None,
                        "duplicate_of": None,
                    }
                    payload["hypothesis_content_hash"] = (
                        compute_hypothesis_content_hash(payload)
                    )
                    validated = AlphaHypothesis.model_validate(
                        validate_hypothesis(payload)
                    )
                    admitted_candidate = AlphaGenerationCandidate(
                        hypothesis=validated,
                        scientific_identity_hash=compute_scientific_identity_hash(
                            validated.model_dump()
                        ),
                        rationale=data["rationale"].strip(),
                        source_context_refs=tuple(data["source_context_refs"]),
                        novelty_statement=data["novelty_statement"].strip(),
                        duplicate_awareness=data["duplicate_awareness"].strip(),
                        uncertainty=data["uncertainty"].strip(),
                    )
                else:
                    # Non-successful or unaccepted result cannot produce admitted candidate
                    admitted_candidate = None
            elif wb.role == AgentRole.DATA_RESEARCHER.value:
                # Explicit semantic boundary: data_researcher output != Evidence
                structured_result_type = "data_research_report"
            elif wb.role == AgentRole.EXTERNAL_RESEARCHER.value:
                # Explicit semantic boundary: external_researcher output != Evidence, != CriticDecision
                structured_result_type = "external_literature_summary"

            return WorkBlockExecutionResult.create(
                orchestration_id=request.orchestration_id,
                work_block_id=wb.work_block_id,
                task_id=task_id,
                role=wb.role,
                authorized_permissions=authorized_perms,
                route_id=route_id,
                provider=provider_name,
                model=model_name,
                transport_ref=transport_ref,
                usage_snapshot_ref=usage_snapshot_ref,
                provider_job_ref=provider_job_ref,
                terminal_status=terminal_status,
                acceptance_status=acceptance_status,
                structured_result_type=structured_result_type,
                structured_output=structured_out,
                raw_result_ref=raw_ref,
                error_code=None,
                error_message=None,
                tool_failures=tool_failures,
                project_binding=dict(request.project_binding),
                audit_ref=None,
                ordinal=wb.ordinal,
                admitted_candidate=admitted_candidate,
                work_block_content_hash=wb.work_block_content_hash,
                schema_version=ORCHESTRATION_SCHEMA_VERSION,
                hash_profile=HASH_PROFILE,
            )

        except Exception as exc:  # noqa: BLE001
            # Failure isolation: Catch exception strictly within this work block boundary.
            err_code = (
                getattr(getattr(exc, "code", None), "value", None)
                or getattr(exc, "error_code", None)
                or type(exc).__name__
            )
            err_msg = str(exc)
            terminal_status = (
                TerminalStatus.UNCERTAIN.value
                if "uncertain" in err_code.lower()
                else TerminalStatus.FAILED.value
            )

            return WorkBlockExecutionResult.create(
                orchestration_id=request.orchestration_id,
                work_block_id=wb.work_block_id,
                task_id=task_id,
                role=wb.role,
                authorized_permissions=authorized_perms,
                route_id=route_id,
                provider=provider_name,
                model=model_name,
                transport_ref=transport_ref,
                usage_snapshot_ref=usage_snapshot_ref,
                provider_job_ref=provider_job_ref,
                terminal_status=terminal_status,
                acceptance_status="REJECTED_BY_ACCEPTANCE",
                structured_result_type=None,
                structured_output=None,
                raw_result_ref=None,
                error_code=err_code,
                error_message=err_msg,
                tool_failures=(err_msg,),
                project_binding=dict(request.project_binding),
                audit_ref=None,
                ordinal=wb.ordinal,
                admitted_candidate=None,
                work_block_content_hash=wb.work_block_content_hash,
                schema_version=ORCHESTRATION_SCHEMA_VERSION,
                hash_profile=HASH_PROFILE,
            )

    def aggregate_results(
        self,
        *,
        orchestration_id: str,
        project_binding: dict[str, str],
        aggregation_policy: str,
        work_block_results: Sequence[WorkBlockExecutionResult],
        recorded_at: str,
    ) -> MultiAgentAggregateResult:
        """Deterministically aggregate work block results.

        CRITICAL: The results are ALWAYS sorted by (ordinal, work_block_id).
        Concurrent completion order does NOT alter aggregate order or hash!
        """
        # Gate 7 admission validation: Fail-closed validation of every single worker result before aggregation.
        # Any missing hash, tampered payload, or hash mismatch is immediately rejected.
        for r in work_block_results:
            if not isinstance(r, WorkBlockExecutionResult):
                raise TypeError(
                    f"Expected WorkBlockExecutionResult, got {type(r).__name__}"
                )
            validate_work_block_result_hash(r.to_dict())

        sorted_results = tuple(
            sorted(work_block_results, key=lambda r: (r.ordinal, r.work_block_id))
        )

        per_worker_outcomes: dict[str, str] = {}
        per_worker_provenance: dict[str, dict[str, str]] = {}
        successful_outputs: list[dict[str, Any]] = []
        failed_blocks: list[str] = []
        uncertain_blocks: list[str] = []

        m6_candidate: AlphaGenerationCandidate | None = None

        for r in sorted_results:
            per_worker_outcomes[r.work_block_id] = r.terminal_status
            per_worker_provenance[r.work_block_id] = {
                "model": r.model,
                "provider": r.provider,
                "provider_job_ref": r.provider_job_ref,
                "transport_ref": r.transport_ref,
            }

            if (
                r.terminal_status == TerminalStatus.SUCCESS.value
                and r.acceptance_status == "ACCEPTED"
            ):
                if r.structured_output:
                    successful_outputs.append(
                        {
                            "role": r.role,
                            "structured_output": copy.deepcopy(r.structured_output),
                            "structured_result_type": r.structured_result_type,
                            "work_block_id": r.work_block_id,
                        }
                    )
                if (
                    r.role == AgentRole.ALPHA_GENERATOR.value
                    and r.admitted_candidate is not None
                ):
                    m6_candidate = r.admitted_candidate
            elif r.terminal_status == TerminalStatus.UNCERTAIN.value:
                uncertain_blocks.append(r.work_block_id)
            else:
                failed_blocks.append(r.work_block_id)

        # Determine orchestration engineering status
        if uncertain_blocks:
            eng_status = OrchestrationEngineeringStatus.UNCERTAIN.value
        elif not failed_blocks:
            eng_status = OrchestrationEngineeringStatus.COMPLETED.value
        elif len(failed_blocks) == len(sorted_results):
            eng_status = OrchestrationEngineeringStatus.ALL_FAILED.value
        else:
            eng_status = OrchestrationEngineeringStatus.PARTIAL.value

        is_eligible_for_m6 = m6_candidate is not None

        raw_agg = {
            "aggregation_policy": aggregation_policy,
            "failed_work_blocks": list(failed_blocks),
            "hash_profile": HASH_PROFILE,
            "is_eligible_for_m6": is_eligible_for_m6,
            "is_tradable": False,
            "m6_eligible_candidate_id": m6_candidate.candidate_id
            if m6_candidate
            else None,
            "orchestration_engineering_status": eng_status,
            "orchestration_id": orchestration_id,
            "per_worker_outcomes": per_worker_outcomes,
            "per_worker_provenance": per_worker_provenance,
            "project_binding": dict(project_binding),
            "schema_version": ORCHESTRATION_SCHEMA_VERSION,
            "successful_outputs": [_clean_for_canonical(x) for x in successful_outputs],
            "uncertain_work_blocks": list(uncertain_blocks),
            "work_block_results": [r.to_dict() for r in sorted_results],
        }
        agg_hash = compute_aggregate_content_hash(raw_agg)

        # Audit record
        audit_rec = OrchestrationAuditRecord.create(
            orchestration_id=orchestration_id,
            project_binding=project_binding,
            work_block_ids=[r.work_block_id for r in sorted_results],
            engineering_status=eng_status,
            work_block_statuses=per_worker_outcomes,
            per_worker_job_refs={
                r.work_block_id: r.provider_job_ref for r in sorted_results
            },
            recorded_at=recorded_at,
        )
        self.audit_trail.append(audit_rec)

        return MultiAgentAggregateResult(
            orchestration_id=orchestration_id,
            project_binding=dict(project_binding),
            aggregation_policy=aggregation_policy,
            orchestration_engineering_status=eng_status,
            work_block_results=sorted_results,
            per_worker_outcomes=per_worker_outcomes,
            per_worker_provenance=per_worker_provenance,
            successful_outputs=tuple(successful_outputs),
            failed_work_blocks=tuple(failed_blocks),
            uncertain_work_blocks=tuple(uncertain_blocks),
            m6_eligible_candidate=m6_candidate,
            is_eligible_for_m6=is_eligible_for_m6,
            is_tradable=False,
            aggregate_content_hash=agg_hash,
            audit_ref=audit_rec.audit_id,
            schema_version=ORCHESTRATION_SCHEMA_VERSION,
            hash_profile=HASH_PROFILE,
        )

    def handover_to_discovery(
        self,
        aggregate: MultiAgentAggregateResult,
        discovery_orchestrator: DiscoveryIntegrationOrchestrator,
        snapshot_path: Path | str,
        *,
        dataset_binding: dict[str, Any] | None = None,
        expected_binding: ProjectBinding | Mapping[str, str] | None = None,
        auto_supplemental: bool = False,
    ) -> DiscoveryIntegrationResult:
        """Explicit boundary handoff: Send an admitted alpha candidate from aggregate into M6 Discovery.

        Sol/Orchestrator does not produce scientific decisions; it hands valid candidates to M6.
        """
        if not aggregate.is_eligible_for_m6 or aggregate.m6_eligible_candidate is None:
            raise ValueError(
                "No eligible alpha candidate in aggregate for M6 admission (cannot hand over invalid candidate)"
            )

        candidate = aggregate.m6_eligible_candidate

        # Find the alpha_generator work block result for provenance
        wb_res = next(
            (
                r
                for r in aggregate.work_block_results
                if r.role == AgentRole.ALPHA_GENERATOR.value
            ),
            None,
        )

        return discovery_orchestrator.integrate_candidate(
            candidate=candidate,
            snapshot_path=snapshot_path,
            dataset_binding=dataset_binding,
            project_binding=aggregate.project_binding,
            expected_binding=expected_binding,
            request_id=aggregate.orchestration_id,
            task_id=wb_res.task_id if wb_res else None,
            route_id=wb_res.route_id if wb_res else None,
            provider_job_ref=wb_res.provider_job_ref if wb_res else None,
            provider=wb_res.provider if wb_res else None,
            model=wb_res.model if wb_res else None,
            agent_result_id=wb_res.task_id if wb_res else None,
            agent_result_hash=wb_res.result_hash if wb_res else None,
            auto_supplemental=auto_supplemental,
        )
