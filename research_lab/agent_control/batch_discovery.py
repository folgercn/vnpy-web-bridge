"""Milestone B & C: Astra Batch Discovery & Memory Feedback Loop (#502).

Implements sequential batch execution over PlannedCandidateSlots with:
- Execution-side scope admission (universe, frequency, signal family, source refs)
- M8 result state gating (TerminalStatus.SUCCESS + ACCEPTED required)
- Engineering failure isolation (individual slot failure does not halt other slots)
- Deterministic intra-batch and historical deduplication
- Funnel metrics with strictly partitioned categories and rigorous denominators
- Attempt replay protection and write idempotency
- Two-round Memory feedback loop with traceable hypothesis-to-memory attribution
"""

from __future__ import annotations

import dataclasses
import time
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from research_lab.agent_control.alpha_generator import (
    DISCOVERY_POLICY_VERSION,
    AlphaGenerationCandidate,
    AlphaGenerationError,
    admit_alpha_generation_output,
    apply_duplicate_views,
    build_duplicate_lookup_views,
    parse_alpha_generation_output,
)
from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentResult,
    AgentUsageSnapshot,
    ProjectBinding,
    TerminalStatus,
    _clean_for_canonical,
    _freeze_mapping,
    validate_project_binding,
    validate_result_hash,
)
from research_lab.agent_control.discovery_integration import (
    DiscoveryIntegrationOrchestrator,
    DiscoveryIntegrationResult,
)
from research_lab.agent_control.discovery_session import (
    CANONICAL_SESSION_TIMESTAMP,
    DiscoverySession,
    DiscoverySessionError,
    PlannedCandidateSlot,
    plan_candidate_slots,
    validate_session_memory_view,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
    QuotaUnavailableError,
    ResultAcceptanceError,
    TamperDetectionError,
)
from research_lab.agent_control.handoff import prepare_execution
from research_lab.agent_control.memory_view import (
    ResearchMemoryCategory,
    ResearchMemoryEntryView,
    ResearchMemoryQuery,
    ResearchMemoryView,
    build_research_memory_view,
)
from research_lab.agent_control.registry import ProviderRegistry
from research_lab.agent_control.router import select_agent
from research_lab.agent_control.routing_policy import RoutingPolicy
from research_lab.alpha_discovery import (
    AlphaDiscoveryEngine,
    ResearchMemoryRecord,
)
from research_lab.alpha_discovery.hypothesis import compute_structured_key
from research_lab.contracts import v2

DISCOVERY_BATCH_SCHEMA_VERSION = "research_lab.discovery_batch.v1"


class SlotEngineeringStatus(str, Enum):
    """Discrete engineering outcomes for a candidate slot execution."""

    COMPLETED = "COMPLETED"
    ROUTING_FAILED = "ROUTING_FAILED"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    AGENT_EXECUTION_FAILED = "AGENT_EXECUTION_FAILED"
    PROVIDER_UNCERTAIN = "PROVIDER_UNCERTAIN"
    RESULT_NOT_ACCEPTED = "RESULT_NOT_ACCEPTED"
    PARSE_FAILED = "PARSE_FAILED"
    ADMISSION_FAILED = "ADMISSION_FAILED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


@dataclass(frozen=True)
class SlotExecutionResult:
    """Detailed execution and admission record for a single PlannedCandidateSlot."""

    session_id: str
    slot_id: str
    ordinal: int
    attempt: int
    engineering_status: str
    error_code: str | None = None
    error_message: str | None = None
    candidate: AlphaGenerationCandidate | None = None
    duplicate_status: str | None = None
    duplicate_refs: tuple[str, ...] = ()
    duplicate_status_reason: str | None = None
    task_id: str | None = None
    route_id: str | None = None
    provider_job_ref: str | None = None
    provider: str | None = None
    model: str | None = None
    agent_result_id: str | None = None
    agent_result_hash: str | None = None
    hypothesis_id: str | None = None
    hypothesis_content_hash: str | None = None
    scientific_identity_hash: str | None = None
    memory_view_id: str = ""
    memory_view_content_hash: str = ""
    slot_content_hash: str = ""
    is_replayed: bool = False

    @property
    def error_details(self) -> dict[str, Any]:
        return {
            "error_code": self.error_code,
            "error_message": self.error_message,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_result_hash": self.agent_result_hash,
            "agent_result_id": self.agent_result_id,
            "attempt": self.attempt,
            "candidate": self.candidate.to_dict() if self.candidate else None,
            "duplicate_refs": list(self.duplicate_refs),
            "duplicate_status": self.duplicate_status,
            "duplicate_status_reason": self.duplicate_status_reason,
            "engineering_status": self.engineering_status,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "hypothesis_content_hash": self.hypothesis_content_hash,
            "hypothesis_id": self.hypothesis_id,
            "is_replayed": self.is_replayed,
            "memory_view_content_hash": self.memory_view_content_hash,
            "memory_view_id": self.memory_view_id,
            "model": self.model,
            "ordinal": self.ordinal,
            "provider": self.provider,
            "provider_job_ref": self.provider_job_ref,
            "route_id": self.route_id,
            "scientific_identity_hash": self.scientific_identity_hash,
            "session_id": self.session_id,
            "slot_content_hash": self.slot_content_hash,
            "slot_id": self.slot_id,
            "task_id": self.task_id,
        }


@dataclass(frozen=True)
class DiscoveryBatchFunnel:
    """Strictly partitioned, auditable funnel metrics for an Astra discovery batch."""

    requested: int = 0
    attempted: int = 0
    generated: int = 0
    admitted: int = 0
    invalid: int = 0
    provider_failed: int = 0
    exact_duplicate_count: int = 0
    related_count: int = 0
    novel_count: int = 0
    unverified_count: int = 0
    signal_families: Mapping[str, int] = field(default_factory=dict)
    not_attempted: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "signal_families", _freeze_mapping(dict(self.signal_families))
        )

    @property
    def total_slots_planned(self) -> int:
        return self.requested

    @property
    def admitted_candidates(self) -> int:
        return self.admitted

    @property
    def novel_candidates(self) -> int:
        return self.novel_count

    @property
    def unverified_candidates(self) -> int:
        return self.unverified_count

    @property
    def exact_duplicates(self) -> int:
        return self.exact_duplicate_count

    @property
    def related_duplicates(self) -> int:
        return self.related_count

    @property
    def admitted_rate(self) -> float:
        return (self.admitted / self.requested) if self.requested > 0 else 0.0

    @property
    def exact_duplicate_rate(self) -> float:
        return (self.exact_duplicate_count / self.admitted) if self.admitted > 0 else 0.0

    @property
    def related_rate(self) -> float:
        return (self.related_count / self.admitted) if self.admitted > 0 else 0.0

    @property
    def novel_rate(self) -> float:
        return (self.novel_count / self.admitted) if self.admitted > 0 else 0.0

    @property
    def unverified_rate(self) -> float:
        return (self.unverified_count / self.admitted) if self.admitted > 0 else 0.0

    @property
    def duplicate_rate(self) -> float:
        return (self.exact_duplicate_count + self.related_count) / self.admitted if self.admitted > 0 else 0.0

    @property
    def novelty_rate(self) -> float:
        return self.novel_rate

    @property
    def successful_slots(self) -> int:
        return self.admitted

    @property
    def failed_slots(self) -> int:
        return self.provider_failed + self.invalid

    @property
    def rejected_candidates(self) -> int:
        return self.invalid

    @property
    def skipped_slots(self) -> int:
        return self.not_attempted

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted": self.admitted,
            "admitted_rate": round(self.admitted_rate, 4),
            "attempted": self.attempted,
            "exact_duplicate_count": self.exact_duplicate_count,
            "exact_duplicate_rate": round(self.exact_duplicate_rate, 4),
            "generated": self.generated,
            "invalid": self.invalid,
            "not_attempted": self.not_attempted,
            "novel_count": self.novel_count,
            "novel_rate": round(self.novel_rate, 4),
            "unverified_count": self.unverified_count,
            "unverified_rate": round(self.unverified_rate, 4),
            "provider_failed": self.provider_failed,
            "related_count": self.related_count,
            "related_rate": round(self.related_rate, 4),
            "requested": self.requested,
            "signal_families": dict(self.signal_families),
        }


@dataclass(frozen=True)
class DiscoveryBatchResult:
    """Enclosed outcome of an Astra Discovery Session batch execution."""

    batch_id: str
    session_id: str
    session_content_hash: str
    memory_view_id: str
    memory_view_snapshot_hash: str
    candidate_budget: int
    funnel: DiscoveryBatchFunnel
    slots: tuple[SlotExecutionResult, ...]
    admitted_candidates: tuple[AlphaGenerationCandidate, ...]
    created_at: str
    schema_version: str = DISCOVERY_BATCH_SCHEMA_VERSION

    @property
    def total_slots_planned(self) -> int:
        return len(self.slots)

    @property
    def successful_slots(self) -> tuple[SlotExecutionResult, ...]:
        return tuple(s for s in self.slots if s.engineering_status == SlotEngineeringStatus.COMPLETED.value)

    @property
    def failed_slots(self) -> tuple[SlotExecutionResult, ...]:
        return tuple(s for s in self.slots if s.engineering_status != SlotEngineeringStatus.COMPLETED.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted_candidates": [c.to_dict() for c in self.admitted_candidates],
            "batch_id": self.batch_id,
            "candidate_budget": self.candidate_budget,
            "created_at": self.created_at,
            "funnel": self.funnel.to_dict(),
            "memory_view_id": self.memory_view_id,
            "memory_view_snapshot_hash": self.memory_view_snapshot_hash,
            "schema_version": self.schema_version,
            "session_content_hash": self.session_content_hash,
            "session_id": self.session_id,
            "slots": [s.to_dict() for s in self.slots],
        }


@dataclass(frozen=True)
class DiscoveryBatchAuditRecord:
    """Tamper-evident audit record for batch execution."""

    batch_id: str
    session_id: str
    requested: int
    admitted: int
    audit_hash: str

    @classmethod
    def create(cls, result: DiscoveryBatchResult) -> DiscoveryBatchAuditRecord:
        raw = {
            "admitted": result.funnel.admitted,
            "batch_id": result.batch_id,
            "candidate_budget": result.candidate_budget,
            "requested": result.funnel.requested,
            "session_id": result.session_id,
            "slots": [
                {
                    "ordinal": s.ordinal,
                    "slot_id": s.slot_id,
                    "status": s.engineering_status,
                }
                for s in result.slots
            ],
        }
        return cls(
            batch_id=result.batch_id,
            session_id=result.session_id,
            requested=result.funnel.requested,
            admitted=result.funnel.admitted,
            audit_hash=v2.digest(_clean_for_canonical(raw)),
        )


class DiscoveryBatchAuditTrail:
    """Append-only audit trail for batch discovery runs."""

    def __init__(self) -> None:
        self._records: list[DiscoveryBatchAuditRecord] = []

    def append(self, record: DiscoveryBatchAuditRecord) -> None:
        self._records.append(record)

    def get_records(self) -> tuple[DiscoveryBatchAuditRecord, ...]:
        return tuple(self._records)

    def __len__(self) -> int:
        return len(self._records)


def _extract_raw_output_safe(result: AgentResult) -> str:
    """Safely extract model raw output text with strict validation."""
    validate_result_hash(result.to_dict())
    if (
        result.terminal_status != TerminalStatus.SUCCESS.value
        or result.acceptance_status != "ACCEPTED"
    ):
        raise ResultAcceptanceError(
            f"Provider result not accepted: terminal_status={result.terminal_status}, acceptance_status={result.acceptance_status}"
        )
    output = result.structured_output
    if not isinstance(output, dict):
        raise ResultAcceptanceError("Accepted provider result has no structured output dictionary")
    for key in ("output", "text", "content", "final_output", "response"):
        if isinstance(output.get(key), str):
            return output[key]
    from research_lab.agent_control.alpha_generator import ENVELOPE_FIELDS

    if set(output) == ENVELOPE_FIELDS:
        import json

        return json.dumps(output, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    raise ResultAcceptanceError("Accepted provider result has no extractable model output text")


@dataclass(frozen=True)
class DuplicateLookupReceipt:
    """Verifiable query receipt binding duplicate lookup views to candidate identities."""

    hypothesis_content_hash: str
    scientific_identity_hash: str
    exact_view_id: str
    related_view_id: str
    is_truncated: bool = False
    queried_source: str = "controlled_memory_store"

    def to_dict(self) -> dict[str, Any]:
        return {
            "exact_view_id": self.exact_view_id,
            "hypothesis_content_hash": self.hypothesis_content_hash,
            "is_truncated": self.is_truncated,
            "queried_source": self.queried_source,
            "related_view_id": self.related_view_id,
            "scientific_identity_hash": self.scientific_identity_hash,
        }


def create_duplicate_lookup_receipt(
    candidate: AlphaGenerationCandidate,
    exact_view: ResearchMemoryView,
    related_view: ResearchMemoryView,
    queried_source: str = "controlled_memory_store",
) -> DuplicateLookupReceipt:
    """Create an authentic query receipt binding exact and related lookup views to candidate."""
    return DuplicateLookupReceipt(
        hypothesis_content_hash=candidate.hypothesis.hypothesis_content_hash,
        scientific_identity_hash=candidate.scientific_identity_hash,
        exact_view_id=exact_view.view_id,
        related_view_id=related_view.view_id,
        is_truncated=(bool(exact_view.is_truncated) or bool(related_view.is_truncated)),
        queried_source=queried_source,
    )


def validate_duplicate_lookup_views(
    candidate: AlphaGenerationCandidate,
    exact_view: Any,
    related_view: Any,
    session: DiscoverySession,
    *,
    receipt: DuplicateLookupReceipt | Mapping[str, Any] | None = None,
    is_internal_lookup: bool = False,
) -> tuple[bool, str | None]:
    """Validate that exact and related views are genuine, untruncated duplicate lookup views for the candidate."""
    if not isinstance(exact_view, ResearchMemoryView) or not isinstance(related_view, ResearchMemoryView):
        return False, "Duplicate lookup views must be ResearchMemoryView instances"

    expected_role = getattr(session, "role", None) or (
        session.authorized_scope_ref.get("role", "alpha_generator")
        if isinstance(session.authorized_scope_ref, dict)
        else "alpha_generator"
    )
    if exact_view.role != expected_role or related_view.role != expected_role:
        return False, f"Duplicate views role ({exact_view.role}, {related_view.role}) does not match role '{expected_role}'"

    if dict(exact_view.project_binding) != dict(session.project_binding):
        return False, "exact_view project_binding does not match active session"

    if dict(related_view.project_binding) != dict(session.project_binding):
        return False, "related_view project_binding does not match active session"

    dup_cat = ResearchMemoryCategory.DUPLICATE_IDENTITIES.value
    if dup_cat not in exact_view.categories:
        return False, f"exact_view categories {exact_view.categories} missing '{dup_cat}'"

    if dup_cat not in related_view.categories:
        return False, f"related_view categories {related_view.categories} missing '{dup_cat}'"

    # Distinct query views required: content hash vs scientific identity hash
    if exact_view.view_id == related_view.view_id:
        return False, "exact_view and related_view have identical view_id; distinct query views required"

    # Fail-closed check: Truncated views cannot prove novelty due to incomplete historical coverage
    if exact_view.is_truncated or related_view.is_truncated:
        return False, "Duplicate lookup view is truncated; partial coverage cannot prove novelty"

    # Check entries in exact_view: must belong to DUPLICATE_IDENTITIES category
    # If exact duplicate, must match candidate hypothesis_content_hash
    for entry in exact_view.entries_by_category.get(dup_cat, ()):
        if entry.category != dup_cat:
            return False, f"exact_view contains unexpected category entry '{entry.category}'"
        if entry.duplicate_state == "exact" and entry.hypothesis_content_hash != candidate.hypothesis.hypothesis_content_hash:
            return False, "exact_view contains exact duplicate entry with mismatching hypothesis_content_hash"

    # Check entries in related_view: must belong to DUPLICATE_IDENTITIES category
    # If related duplicate, must match candidate scientific_identity_hash
    for entry in related_view.entries_by_category.get(dup_cat, ()):
        if entry.category != dup_cat:
            return False, f"related_view contains unexpected category entry '{entry.category}'"
        if entry.duplicate_state in ("exact", "related") and entry.scientific_identity_hash != candidate.scientific_identity_hash:
            return False, "related_view contains related duplicate entry with mismatching scientific_identity_hash"

    # Verifiable query binding:
    # ResearchMemoryView does not directly expose its query object.
    # Empty views or unverified external callbacks cannot prove they were queried for the current candidate.
    # If not an internal controlled query from orchestrator memory_store, a valid receipt is strictly required.
    if not is_internal_lookup:
        if receipt is None:
            return False, "External lookup views lack verifiable query receipt for current candidate (unverified query targets cannot prove novelty)"

        r_content_hash = receipt.get("hypothesis_content_hash") if isinstance(receipt, dict) else getattr(receipt, "hypothesis_content_hash", None)
        r_sci_hash = receipt.get("scientific_identity_hash") if isinstance(receipt, dict) else getattr(receipt, "scientific_identity_hash", None)
        r_exact_id = receipt.get("exact_view_id") if isinstance(receipt, dict) else getattr(receipt, "exact_view_id", None)
        r_related_id = receipt.get("related_view_id") if isinstance(receipt, dict) else getattr(receipt, "related_view_id", None)

        if r_content_hash != candidate.hypothesis.hypothesis_content_hash:
            return False, f"Duplicate receipt hypothesis_content_hash mismatch: '{r_content_hash}' != '{candidate.hypothesis.hypothesis_content_hash}'"
        if r_sci_hash != candidate.scientific_identity_hash:
            return False, f"Duplicate receipt scientific_identity_hash mismatch: '{r_sci_hash}' != '{candidate.scientific_identity_hash}'"
        if r_exact_id != exact_view.view_id:
            return False, f"Duplicate receipt exact_view_id mismatch: '{r_exact_id}' != '{exact_view.view_id}'"
        if r_related_id != related_view.view_id:
            return False, f"Duplicate receipt related_view_id mismatch: '{r_related_id}' != '{related_view.view_id}'"

    return True, None


class DiscoveryBatchOrchestrator:
    """Sequential batch discovery orchestrator executing PlannedCandidateSlots fail-closed."""

    def __init__(
        self,
        *,
        registry: ProviderRegistry,
        routing_policy: RoutingPolicy,
        provider_lookup: Callable[[str], Any] | None = None,
        memory_store: Any | None = None,
        audit_trail: DiscoveryBatchAuditTrail | None = None,
    ) -> None:
        self.registry = registry
        self.routing_policy = routing_policy
        self.provider_lookup = provider_lookup or (lambda name: registry.get(name))
        self.memory_store = memory_store
        self.audit_trail = audit_trail or DiscoveryBatchAuditTrail()
        # Key: (session_id, slot_id, attempt) -> SlotExecutionResult for replay idempotency
        self._execution_cache: dict[tuple[str, str, int], SlotExecutionResult] = {}

    def execute_slot(
        self,
        session: DiscoverySession,
        slot: PlannedCandidateSlot,
        memory_view: ResearchMemoryView,
        *,
        usage_snapshots: Mapping[str, AgentUsageSnapshot] | None = None,
        prior_admitted: tuple[AlphaGenerationCandidate, ...] = (),
        duplicate_view_lookup: Callable[
            [AlphaGenerationCandidate], tuple[ResearchMemoryView, ResearchMemoryView]
        ]
        | None = None,
        created_at: str = CANONICAL_SESSION_TIMESTAMP,
    ) -> SlotExecutionResult:
        """Execute or replay a single candidate slot with fail-closed engineering gates."""
        # Step 0: Cross-Session & Object Binding Integrity Verification (fail-closed)
        if slot.session_id != session.session_id or slot.session_content_hash != session.session_content_hash:
            return SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ADMISSION_FAILED.value,
                error_code="SESSION_MISMATCH",
                error_message=f"Slot session binding '{slot.session_id}' does not match active session '{session.session_id}'",
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )

        if (
            slot.memory_view.view_id != memory_view.view_id
            or slot.memory_view.view_content_hash != memory_view.view_content_hash
            or slot.session.memory_view_snapshot_hash != session.memory_view_snapshot_hash
        ):
            return SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ADMISSION_FAILED.value,
                error_code="VIEW_MISMATCH",
                error_message="Slot memory view binding does not match active session or memory view snapshot",
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )

        if slot.request.session_id != session.session_id or dict(slot.task.project_binding) != dict(session.project_binding):
            return SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ADMISSION_FAILED.value,
                error_code="REQUEST_TASK_SESSION_MISMATCH",
                error_message="Slot request session or task project binding does not match active session",
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )

        if slot.request.attempt != slot.attempt:
            return SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ADMISSION_FAILED.value,
                error_code="ATTEMPT_MISMATCH",
                error_message=f"Slot request attempt {slot.request.attempt} does not match slot attempt {slot.attempt}",
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )

        if (
            session.memory_view_id != memory_view.view_id
            or session.memory_view_content_hash != memory_view.view_content_hash
        ):
            return SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ADMISSION_FAILED.value,
                error_code="SESSION_VIEW_MISMATCH",
                error_message="Active session memory view reference does not match provided memory view",
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )

        if slot.slot_id not in [s.slot_id for s in plan_candidate_slots(session, memory_view)]:
            return SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ADMISSION_FAILED.value,
                error_code="SLOT_NOT_IN_SESSION_PLAN",
                error_message=f"Slot '{slot.slot_id}' does not belong to active planned slots for session '{session.session_id}'",
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )

        cache_key = (session.session_id, slot.slot_id, slot.attempt)

        # Idempotency / Replay Guard
        if cache_key in self._execution_cache:
            cached_res = self._execution_cache[cache_key]
            if (
                cached_res.slot_content_hash == slot.slot_content_hash
                and cached_res.session_id == session.session_id
                and cached_res.memory_view_id == memory_view.view_id
            ):
                return dataclasses.replace(cached_res, is_replayed=True)

        scope = AgentPermissionScope(**dict(session.authorized_scope_ref))
        snapshots = usage_snapshots or {}

        # Step A: Select route
        try:
            all_descs = [
                p.describe()
                for p in self.registry.list()
                if hasattr(p, "describe")
            ]
            route = select_agent(
                role="alpha_generator",
                providers=all_descs,
                authorized_scope=scope,
                project_binding=session.project_binding,
                usage_snapshots=snapshots,
                registry=self.registry,
                routing_policy=self.routing_policy,
            )
        except QuotaUnavailableError as exc:
            q_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.QUOTA_EXHAUSTED.value,
                error_code="QUOTA_EXHAUSTED",
                error_message=str(exc),
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = q_res
            return q_res
        except (ProviderUnavailableError, ProviderError, PermissionDeniedError, ProjectBindingError) as exc:
            r_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ROUTING_FAILED.value,
                error_code=getattr(getattr(exc, "code", None), "value", None) or type(exc).__name__,
                error_message=str(exc),
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = r_res
            return r_res
        except Exception as exc:  # noqa: BLE001
            gen_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.ROUTING_FAILED.value,
                error_code="ROUTE_SELECTION_FAILED",
                error_message=str(exc),
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = gen_res
            return gen_res

        # Step B: Prepare execution & Provider lookup (with failure isolation)
        try:
            prep = prepare_execution(slot.task, route, self.registry)
            provider = self.provider_lookup(route.provider)
            if provider is None:
                raise ProviderUnavailableError(f"Provider '{route.provider}' not found in registry")
        except Exception as exc:  # noqa: BLE001
            p_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.AGENT_EXECUTION_FAILED.value,
                error_code="PREPARATION_FAILED",
                error_message=f"Execution preparation crashed: {exc}",
                route_id=route.route_id,
                provider=route.provider,
                model=route.resolved_model,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = p_res
            return p_res

        # Step C: Submit task
        try:
            handle = provider.submit(
                slot.task,
                route,
                prep,
                request_id=slot.request.request_id,
            )
            if handle.task_ref.get("task_id") != slot.task.task_id:
                raise ProviderError(
                    f"Execution handle task_id '{handle.task_ref.get('task_id')}' does not match '{slot.task.task_id}'",
                    code=ProviderErrorCode.EXECUTION_FAILED,
                )
        except Exception as exc:  # noqa: BLE001
            s_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.AGENT_EXECUTION_FAILED.value,
                error_code="SUBMISSION_FAILED",
                error_message=f"Provider submit crashed: {exc}",
                route_id=route.route_id,
                provider=route.provider,
                model=route.resolved_model,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = s_res
            return s_res

        # Step D: Retrieve result with M8 status gate
        try:
            if hasattr(provider, "status"):
                max_wait = 90.0
                poll_int = 1.0
                elapsed = 0.0
                while elapsed < max_wait:
                    st = provider.status(handle)
                    if st not in ("SUBMITTED", "RUNNING"):
                        break
                    time.sleep(poll_int)
                    elapsed += poll_int

            agent_result = provider.result(handle, prep)

            # Cross-Task, Route & Provider Job verification on agent_result
            res_task_id = (
                agent_result.task_ref.get("task_id")
                if isinstance(agent_result.task_ref, dict)
                else getattr(agent_result, "task_id", None)
            )
            res_route_id = (
                agent_result.route_ref.get("route_id")
                if isinstance(agent_result.route_ref, dict)
                else getattr(agent_result, "route_id", None)
            )
            res_provider = (
                agent_result.route_ref.get("provider")
                if isinstance(agent_result.route_ref, dict)
                else getattr(agent_result, "provider", None)
            )
            res_job_ref = getattr(agent_result, "provider_job_ref", None)

            if (
                res_task_id != slot.task.task_id
                or res_route_id != route.route_id
                or res_provider != route.provider
                or res_job_ref != handle.provider_job_ref
            ):
                raise ResultAcceptanceError(
                    f"Result task/route/job ({res_task_id}, {res_route_id}, {res_provider}, {res_job_ref}) "
                    f"does not match expected ({slot.task.task_id}, {route.route_id}, {route.provider}, {handle.provider_job_ref})"
                )
        except (ResultAcceptanceError, TamperDetectionError) as exc:
            acc_err = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.RESULT_NOT_ACCEPTED.value,
                error_code="RESULT_NOT_ACCEPTED",
                error_message=str(exc),
                route_id=route.route_id,
                provider_job_ref=handle.provider_job_ref,
                provider=route.provider,
                model=route.resolved_model,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = acc_err
            return acc_err
        except Exception as exc:  # noqa: BLE001
            res_err = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.AGENT_EXECUTION_FAILED.value,
                error_code="RESULT_RETRIEVAL_FAILED",
                error_message=f"Provider result retrieval crashed: {exc}",
                route_id=route.route_id,
                provider_job_ref=handle.provider_job_ref,
                provider=route.provider,
                model=route.resolved_model,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = res_err
            return res_err

        # Check agent result status
        if agent_result.terminal_status == TerminalStatus.UNCERTAIN.value:
            unc_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.PROVIDER_UNCERTAIN.value,
                error_code="PROVIDER_UNCERTAIN",
                error_message="Provider execution resulted in UNCERTAIN status",
                route_id=route.route_id,
                provider_job_ref=handle.provider_job_ref,
                provider=route.provider,
                model=route.resolved_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = unc_res
            return unc_res

        if (
            agent_result.terminal_status != TerminalStatus.SUCCESS.value
            or agent_result.acceptance_status != "ACCEPTED"
        ):
            not_acc_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.RESULT_NOT_ACCEPTED.value,
                error_code="RESULT_NOT_ACCEPTED",
                error_message=f"Agent result acceptance check failed: status={agent_result.terminal_status}, acceptance={agent_result.acceptance_status}",
                route_id=route.route_id,
                provider_job_ref=handle.provider_job_ref,
                provider=route.provider,
                model=route.resolved_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = not_acc_res
            return not_acc_res

        # Step E: Parse model output strictly
        try:
            raw_text = _extract_raw_output_safe(agent_result)
            parse_alpha_generation_output(raw_text)
        except (ResultAcceptanceError, TamperDetectionError) as exc:
            acc_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.RESULT_NOT_ACCEPTED.value,
                error_code="RESULT_NOT_ACCEPTED",
                error_message=f"Agent result acceptance check failed: {exc}",
                route_id=route.route_id,
                provider_job_ref=handle.provider_job_ref,
                provider=route.provider,
                model=route.resolved_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = acc_res
            return acc_res
        except (AlphaGenerationError, Exception) as exc:
            p_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=SlotEngineeringStatus.PARSE_FAILED.value,
                error_code="STRICT_PARSE_FAILED",
                error_message=str(exc),
                route_id=route.route_id,
                provider_job_ref=handle.provider_job_ref,
                provider=route.provider,
                model=route.resolved_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = p_res
            return p_res

        # Step F: Admit candidate with execution-side scope admission
        try:
            candidate = admit_alpha_generation_output(
                raw_text,
                request=slot.request,
                memory_view=memory_view,
                task_id=slot.task.task_id,
                provider=route.provider,
                actual_model=route.resolved_model,
                created_at=created_at,
            )
        except (AlphaGenerationError, Exception) as exc:
            err_str = str(exc)
            is_scope = (
                "outside allowed" in err_str
                or "not in allowed" in err_str
                or "does not match" in err_str
                or "candidate universe" in err_str
                or "candidate frequency" in err_str
                or "candidate signal_family" in err_str
            )
            eng_status = (
                SlotEngineeringStatus.SCOPE_MISMATCH.value
                if is_scope
                else SlotEngineeringStatus.ADMISSION_FAILED.value
            )
            adm_res = SlotExecutionResult(
                session_id=session.session_id,
                slot_id=slot.slot_id,
                ordinal=slot.ordinal,
                attempt=slot.attempt,
                engineering_status=eng_status,
                error_code=eng_status,
                error_message=err_str,
                route_id=route.route_id,
                provider_job_ref=handle.provider_job_ref,
                provider=route.provider,
                model=route.resolved_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                memory_view_id=session.memory_view_id,
                memory_view_content_hash=session.memory_view_content_hash,
                slot_content_hash=slot.slot_content_hash,
            )
            self._execution_cache[cache_key] = adm_res
            return adm_res

        # Step G: Deterministic Deduplication (Intra-batch & Historical Memory)
        batch_exact = any(
            c.scientific_identity_hash == candidate.scientific_identity_hash
            or c.hypothesis.hypothesis_content_hash == candidate.hypothesis.hypothesis_content_hash
            for c in prior_admitted
        )
        batch_related = any(
            compute_structured_key(c.hypothesis.model_dump())
            == compute_structured_key(candidate.hypothesis.model_dump())
            for c in prior_admitted
        )

        hist_exact = False
        hist_related = False
        hist_refs: list[str] = []
        hist_queried = False
        dup_status_reason: str | None = None

        lookup_fn = duplicate_view_lookup
        is_internal_lookup = False
        if lookup_fn is None and self.memory_store is not None:
            def _mem_lookup(
                cand: AlphaGenerationCandidate,
            ) -> tuple[ResearchMemoryView, ResearchMemoryView, DuplicateLookupReceipt]:
                exact_v, related_v = build_duplicate_lookup_views(
                    cand,
                    memory_store=self.memory_store,
                    authorized_scope=scope,
                    project_binding=session.project_binding,
                    current_time=created_at,
                )
                rcpt = create_duplicate_lookup_receipt(
                    cand, exact_v, related_v, queried_source="orchestrator_memory_store"
                )
                return exact_v, related_v, rcpt

            lookup_fn = _mem_lookup
            is_internal_lookup = True

        if lookup_fn is not None:
            try:
                res = lookup_fn(candidate)
                receipt = None
                if isinstance(res, tuple) and len(res) == 3:
                    exact_v, related_v, receipt = res
                elif isinstance(res, tuple) and len(res) == 2:
                    exact_v, related_v = res
                else:
                    raise TypeError(f"duplicate_view_lookup returned invalid format: {type(res)}")

                is_valid, val_reason = validate_duplicate_lookup_views(
                    candidate,
                    exact_v,
                    related_v,
                    session,
                    receipt=receipt,
                    is_internal_lookup=is_internal_lookup,
                )
                if is_valid:
                    candidate_with_hist = apply_duplicate_views(
                        candidate, exact_view=exact_v, related_view=related_v
                    )
                    hist_exact = candidate_with_hist.duplicate_status == "EXACT_DUPLICATE"
                    hist_related = candidate_with_hist.duplicate_status == "RELATED_HISTORY"
                    hist_refs = list(candidate_with_hist.duplicate_refs)
                    hist_queried = True
                else:
                    hist_queried = False
                    dup_status_reason = val_reason
            except Exception as exc:  # noqa: BLE001
                hist_queried = False
                dup_status_reason = f"Duplicate lookup failed: {exc}"
        else:
            dup_status_reason = "No memory store or duplicate lookup configured"

        if batch_exact or hist_exact:
            dup_status = "EXACT_DUPLICATE"
        elif batch_related or hist_related:
            dup_status = "RELATED_HISTORY"
        elif hist_queried:
            dup_status = "NOVEL_WITHIN_VIEW"
        else:
            dup_status = "NOT_CHECKED"

        admitted_candidate = dataclasses.replace(
            candidate,
            duplicate_status=dup_status,
            duplicate_refs=tuple(sorted(set(hist_refs))),
        )

        slot_res = SlotExecutionResult(
            session_id=session.session_id,
            slot_id=slot.slot_id,
            ordinal=slot.ordinal,
            attempt=slot.attempt,
            engineering_status=SlotEngineeringStatus.COMPLETED.value,
            candidate=admitted_candidate,
            duplicate_status=dup_status,
            duplicate_refs=tuple(sorted(set(hist_refs))),
            duplicate_status_reason=dup_status_reason,
            task_id=slot.task.task_id,
            route_id=route.route_id,
            provider_job_ref=handle.provider_job_ref,
            provider=route.provider,
            model=route.resolved_model,
            agent_result_id=agent_result.result_id,
            agent_result_hash=agent_result.result_content_hash,
            hypothesis_id=admitted_candidate.hypothesis.hypothesis_id,
            hypothesis_content_hash=admitted_candidate.hypothesis.hypothesis_content_hash,
            scientific_identity_hash=admitted_candidate.scientific_identity_hash,
            memory_view_id=session.memory_view_id,
            memory_view_content_hash=session.memory_view_content_hash,
            slot_content_hash=slot.slot_content_hash,
        )
        self._execution_cache[cache_key] = slot_res
        return slot_res

    def execute_session(
        self,
        session: DiscoverySession,
        memory_view: ResearchMemoryView,
        *,
        usage_snapshots: Mapping[str, AgentUsageSnapshot] | None = None,
        duplicate_view_lookup: Callable[
            [AlphaGenerationCandidate], tuple[ResearchMemoryView, ResearchMemoryView]
        ]
        | None = None,
        created_at: str = CANONICAL_SESSION_TIMESTAMP,
        stop_on_quota: bool = False,
    ) -> DiscoveryBatchResult:
        """Execute all planned slots within a DiscoverySession sequentially."""
        # 1. Pre-validation of session and memory view binding
        validate_session_memory_view(session.to_dict(), memory_view)

        # 2. Plan slots deterministically from the session
        planned_slots = plan_candidate_slots(session, memory_view)

        slot_results: list[SlotExecutionResult] = []
        batch_admitted: list[AlphaGenerationCandidate] = []
        family_counts: Counter[str] = Counter()
        exact_duplicate_count = 0
        related_count = 0
        novel_count = 0
        unverified_count = 0
        invalid_count = 0
        provider_failed_count = 0
        attempted_count = 0
        generated_count = 0
        quota_blocked = False

        for slot in planned_slots:
            cache_key = (session.session_id, slot.slot_id, slot.attempt)

            if quota_blocked:
                not_att = SlotExecutionResult(
                    session_id=session.session_id,
                    slot_id=slot.slot_id,
                    ordinal=slot.ordinal,
                    attempt=slot.attempt,
                    engineering_status=SlotEngineeringStatus.NOT_ATTEMPTED.value,
                    error_code="BATCH_QUOTA_BLOCKED",
                    error_message="Execution skipped because prior slot encountered quota exhaustion",
                    memory_view_id=session.memory_view_id,
                    memory_view_content_hash=session.memory_view_content_hash,
                    slot_content_hash=slot.slot_content_hash,
                )
                slot_results.append(not_att)
                self._execution_cache[cache_key] = not_att
                continue

            slot_res = self.execute_slot(
                session=session,
                slot=slot,
                memory_view=memory_view,
                usage_snapshots=usage_snapshots,
                prior_admitted=tuple(batch_admitted),
                duplicate_view_lookup=duplicate_view_lookup,
                created_at=created_at,
            )
            slot_results.append(slot_res)

            if slot_res.engineering_status == SlotEngineeringStatus.COMPLETED.value and slot_res.candidate:
                attempted_count += 1
                generated_count += 1
                batch_admitted.append(slot_res.candidate)
                family_counts[slot_res.candidate.hypothesis.signal_family] += 1
                if slot_res.duplicate_status == "EXACT_DUPLICATE":
                    exact_duplicate_count += 1
                elif slot_res.duplicate_status == "RELATED_HISTORY":
                    related_count += 1
                elif slot_res.duplicate_status == "NOVEL_WITHIN_VIEW":
                    novel_count += 1
                else:
                    unverified_count += 1
            elif slot_res.engineering_status in (
                SlotEngineeringStatus.PARSE_FAILED.value,
                SlotEngineeringStatus.ADMISSION_FAILED.value,
                SlotEngineeringStatus.SCOPE_MISMATCH.value,
            ):
                attempted_count += 1
                generated_count += 1
                invalid_count += 1
            elif slot_res.engineering_status in (
                SlotEngineeringStatus.ROUTING_FAILED.value,
                SlotEngineeringStatus.QUOTA_EXHAUSTED.value,
                SlotEngineeringStatus.AGENT_EXECUTION_FAILED.value,
                SlotEngineeringStatus.PROVIDER_UNCERTAIN.value,
                SlotEngineeringStatus.RESULT_NOT_ACCEPTED.value,
            ):
                attempted_count += 1
                provider_failed_count += 1
                if slot_res.engineering_status == SlotEngineeringStatus.QUOTA_EXHAUSTED.value and stop_on_quota:
                    quota_blocked = True

        # Step 4: Construct Funnel
        not_attempted_count = session.candidate_budget - attempted_count
        funnel = DiscoveryBatchFunnel(
            requested=session.candidate_budget,
            attempted=attempted_count,
            generated=generated_count,
            admitted=len(batch_admitted),
            invalid=invalid_count,
            provider_failed=provider_failed_count,
            exact_duplicate_count=exact_duplicate_count,
            related_count=related_count,
            novel_count=novel_count,
            unverified_count=unverified_count,
            signal_families=dict(family_counts),
            not_attempted=not_attempted_count,
        )

        batch_id = f"batch-{session.session_id[:16]}-{v2.digest({'slots': [s.slot_id for s in slot_results]})[:12]}"
        batch_result = DiscoveryBatchResult(
            batch_id=batch_id,
            session_id=session.session_id,
            session_content_hash=session.session_content_hash,
            memory_view_id=session.memory_view_id,
            memory_view_snapshot_hash=session.memory_view_snapshot_hash,
            candidate_budget=session.candidate_budget,
            funnel=funnel,
            slots=tuple(slot_results),
            admitted_candidates=tuple(batch_admitted),
            created_at=created_at,
        )

        audit_rec = DiscoveryBatchAuditRecord.create(batch_result)
        self.audit_trail.append(audit_rec)
        return batch_result

    def execute_batch(
        self,
        session: DiscoverySession,
        memory_view: ResearchMemoryView,
        *,
        usage_snapshots: Mapping[str, AgentUsageSnapshot] | None = None,
        duplicate_view_lookup: Callable[
            [AlphaGenerationCandidate], tuple[ResearchMemoryView, ResearchMemoryView]
        ]
        | None = None,
        created_at: str = CANONICAL_SESSION_TIMESTAMP,
        stop_on_quota: bool = False,
    ) -> DiscoveryBatchResult:
        """Alias for execute_session."""
        return self.execute_session(
            session=session,
            memory_view=memory_view,
            usage_snapshots=usage_snapshots,
            duplicate_view_lookup=duplicate_view_lookup,
            created_at=created_at,
            stop_on_quota=stop_on_quota,
        )


@dataclass(frozen=True)
class MemoryFeedbackAttributionRecord:
    """Traceable attribution for a Round 2 candidate citing Round 1 Research Memory."""

    candidate_id: str
    signal_family: str
    cited_memory_entry_id: str
    cited_decision: str
    predecessor_hypothesis_id: str
    predecessor_failure_or_gap: str
    adaptation_description: str
    is_conclusive: bool = True
    scientific_diffs: tuple[str, ...] = ()


@dataclass(frozen=True)
class MemoryFeedbackLoopResult:
    """Consolidated outcome of the two-round Milestone C Memory feedback loop."""

    round_1_session: DiscoverySession
    round_1_batch: DiscoveryBatchResult
    round_1_integration_results: tuple[DiscoveryIntegrationResult, ...]
    round_2_session: DiscoverySession
    round_2_batch: DiscoveryBatchResult
    round_2_integration_results: tuple[DiscoveryIntegrationResult, ...]
    attribution_records: tuple[MemoryFeedbackAttributionRecord, ...]
    comparative_summary: dict[str, Any]


def execute_memory_feedback_loop(
    *,
    engine: AlphaDiscoveryEngine,
    orchestrator: DiscoveryBatchOrchestrator,
    initial_memory_view: ResearchMemoryView,
    authorized_scope: AgentPermissionScope,
    project_binding: ProjectBinding | Mapping[str, str],
    objective: str,
    allowed_universe: tuple[str, ...] | str,
    allowed_frequency: str,
    allowed_signal_families: tuple[str, ...],
    candidate_budget: int = 10,
    snapshot_path: Path | str,
    dataset_binding: dict[str, Any] | None = None,
    generation_policy_version: str = DISCOVERY_POLICY_VERSION,
    created_at: str = CANONICAL_SESSION_TIMESTAMP,
    round_2_created_at: str = "2026-01-02T00:00:00.000000Z",
) -> MemoryFeedbackLoopResult:
    """Execute complete Milestone C two-round memory feedback loop.

    Round 1: Initial view -> Session 1 -> Batch -> Engine -> Memory accumulation.
    Round 2: Re-query memory -> Session 2 -> Batch -> Memory attribution check.
    """
    pb = validate_project_binding(project_binding)
    orchestrator.memory_store = engine.memory

    # ==========================
    # ROUND 1
    # ==========================
    session_1 = DiscoverySession.create(
        objective=objective,
        memory_view=initial_memory_view,
        authorized_scope=authorized_scope,
        candidate_budget=candidate_budget,
        allowed_universe=allowed_universe,
        allowed_frequency=allowed_frequency,
        allowed_signal_families=allowed_signal_families,
        project_binding=pb,
        generation_policy_version=generation_policy_version,
        created_at=created_at,
    )

    def _r1_dup_lookup(
        cand: AlphaGenerationCandidate,
    ) -> tuple[ResearchMemoryView, ResearchMemoryView, DuplicateLookupReceipt]:
        exact_v, related_v = build_duplicate_lookup_views(
            cand,
            memory_store=engine.memory,
            authorized_scope=authorized_scope,
            project_binding=pb,
            current_time=created_at,
        )
        return (
            exact_v,
            related_v,
            create_duplicate_lookup_receipt(cand, exact_v, related_v, queried_source="engine_memory"),
        )

    batch_res_1 = orchestrator.execute_session(
        session_1,
        initial_memory_view,
        duplicate_view_lookup=_r1_dup_lookup,
        created_at=created_at,
    )

    # Integrate admitted candidates through existing AlphaDiscoveryEngine (Screening -> Critic -> Memory)
    int_orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)
    r1_integration_results: list[DiscoveryIntegrationResult] = []

    for cand in batch_res_1.admitted_candidates:
        int_res = int_orchestrator.integrate_candidate(
            cand,
            snapshot_path=snapshot_path,
            dataset_binding=dataset_binding,
            project_binding=pb,
            auto_supplemental=True,
        )
        r1_integration_results.append(int_res)

    # ==========================
    # RECONSTRUCT MEMORY B
    # ==========================
    # Build updated memory view reflecting Round 1 accumulation
    query_2 = ResearchMemoryQuery(
        role="alpha_generator",
        project_binding=pb,
        categories=(
            ResearchMemoryCategory.RESEARCH_GAPS.value,
            ResearchMemoryCategory.NME_BACKLOG.value,
            ResearchMemoryCategory.FAILED_APPROACHES.value,
            ResearchMemoryCategory.RECENT_REJECTS.value,
            ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
            ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,
        ),
        limit_per_category=10,
        total_limit=50,
    )
    memory_view_2 = build_research_memory_view(
        query=query_2,
        authorized_scope=authorized_scope,
        project_binding=pb,
        memory_store=engine.memory,
        current_time=round_2_created_at,
    )

    # ==========================
    # ROUND 2
    # ==========================
    session_2 = DiscoverySession.create(
        objective=objective,
        memory_view=memory_view_2,
        authorized_scope=authorized_scope,
        candidate_budget=candidate_budget,
        allowed_universe=allowed_universe,
        allowed_frequency=allowed_frequency,
        allowed_signal_families=allowed_signal_families,
        project_binding=pb,
        generation_policy_version=generation_policy_version,
        created_at=round_2_created_at,
    )

    # Verify session 2 has distinct identity and correctly binds memory view 2
    if session_2.session_id == session_1.session_id:
        raise DiscoverySessionError("Session 2 unexpectedly has identical ID to Session 1 despite updated memory")

    def _r2_dup_lookup(
        cand: AlphaGenerationCandidate,
    ) -> tuple[ResearchMemoryView, ResearchMemoryView, DuplicateLookupReceipt]:
        exact_v, related_v = build_duplicate_lookup_views(
            cand,
            memory_store=engine.memory,
            authorized_scope=authorized_scope,
            project_binding=pb,
            current_time=round_2_created_at,
        )
        return (
            exact_v,
            related_v,
            create_duplicate_lookup_receipt(cand, exact_v, related_v, queried_source="engine_memory"),
        )

    batch_res_2 = orchestrator.execute_session(
        session_2,
        memory_view_2,
        duplicate_view_lookup=_r2_dup_lookup,
        created_at=round_2_created_at,
    )

    # Integrate Round 2 candidates
    r2_integration_results: list[DiscoveryIntegrationResult] = []
    for cand in batch_res_2.admitted_candidates:
        int_res = int_orchestrator.integrate_candidate(
            cand,
            snapshot_path=snapshot_path,
            dataset_binding=dataset_binding,
            project_binding=pb,
            auto_supplemental=True,
        )
        r2_integration_results.append(int_res)

    # ==========================
    # TRACEABLE MEMORY ATTRIBUTION
    # ==========================
    attribution_records: list[MemoryFeedbackAttributionRecord] = []

    # Map strictly Round 1 records generated via engine/critic
    r1_records_by_id: dict[str, Any] = {}
    for r1_int in r1_integration_results:
        r1_hyp = r1_int.admitted_hypothesis
        if not r1_hyp:
            continue
        recs: list[ResearchMemoryRecord] = list(r1_int.memory_records)
        if not recs:
            found = engine.memory.find_by_hypothesis_id(r1_hyp.hypothesis_id)
            if found:
                recs.append(found)
        for rec in recs:
            r1_records_by_id[rec.record_id] = {"record": rec, "hypothesis": r1_hyp, "integration": r1_int}
            r1_records_by_id[rec.hypothesis_id] = {"record": rec, "hypothesis": r1_hyp, "integration": r1_int}

    # Map Memory View 2 entries
    view2_entries_by_id: dict[str, ResearchMemoryEntryView] = {}
    for cat_entries in memory_view_2.entries_by_category.values():
        for entry in cat_entries:
            view2_entries_by_id[entry.entry_id] = entry
            view2_entries_by_id[entry.hypothesis_id] = entry

    for cand in batch_res_2.admitted_candidates:
        for ref in cand.source_context_refs:
            # Must resolve within Memory View 2
            v_entry = view2_entries_by_id.get(ref)
            if not v_entry:
                continue

            # Must map strictly to a Round 1 generated entry
            r1_match = (
                r1_records_by_id.get(ref)
                or r1_records_by_id.get(v_entry.hypothesis_id)
                or r1_records_by_id.get(getattr(v_entry, "view_generated_from", ""))
            )
            if not r1_match and isinstance(v_entry.source_refs, dict):
                r1_match = r1_records_by_id.get(v_entry.source_refs.get("record_id", ""))

            if not r1_match:
                continue

            pre_rec = r1_match["record"]
            pre_hyp = r1_match["hypothesis"]

            diffs: list[str] = []
            cand_sig = getattr(cand.hypothesis, "signal_definition", "")
            pre_sig = getattr(pre_hyp, "signal_definition", "")
            if cand_sig != pre_sig:
                diffs.append(f"signal_definition updated: '{pre_sig}' -> '{cand_sig}'")

            cand_hh = getattr(cand.hypothesis, "holding_horizon", "")
            pre_hh = getattr(pre_hyp, "holding_horizon", "")
            if cand_hh != pre_hh:
                diffs.append(f"holding_horizon modified: {pre_hh} -> {cand_hh}")

            cand_target = getattr(cand.hypothesis, "target", "")
            pre_target = getattr(pre_hyp, "target", "")
            if cand_target != pre_target:
                diffs.append(f"target modified: {pre_target} -> {cand_target}")

            cand_features = set(getattr(cand.hypothesis, "source_features", ()) or ())
            pre_features = set(getattr(pre_hyp, "source_features", ()) or ())
            if cand_features != pre_features:
                diffs.append(f"source_features modified: {sorted(pre_features)} -> {sorted(cand_features)}")

            if cand.hypothesis.signal_family != pre_hyp.signal_family:
                diffs.append(f"family shifted: {pre_hyp.signal_family} -> {cand.hypothesis.signal_family}")

            cand_params = getattr(cand.hypothesis, "parameters", None) or {}
            pre_params = getattr(pre_hyp, "parameters", None) or {}
            if isinstance(cand_params, dict) and isinstance(pre_params, dict):
                for pk in sorted(set(cand_params.keys()) | set(pre_params.keys())):
                    if cand_params.get(pk) != pre_params.get(pk):
                        diffs.append(f"parameter '{pk}' modified: {pre_params.get(pk)} -> {cand_params.get(pk)}")

            fail_or_gap = (
                "; ".join(pre_rec.reject_reasons)
                if pre_rec.reject_reasons
                else (
                    "; ".join(pre_rec.missing_evidence)
                    if pre_rec.missing_evidence
                    else (v_entry.summary or "prior_evaluated")
                )
            )

            if diffs:
                desc = (
                    f"Adapted hypothesis to address predecessor ({pre_hyp.hypothesis_id}) outcome [{pre_rec.decision}]: "
                    f"gap='{fail_or_gap[:60]}', concrete diffs=[{'; '.join(diffs)}]"
                )
                is_conclusive = True
            else:
                desc = (
                    f"Inconclusive: cited predecessor ({pre_hyp.hypothesis_id}) [{pre_rec.decision}] "
                    "but exhibits no concrete scientific parameter/formula variance"
                )
                is_conclusive = False

            attribution_records.append(
                MemoryFeedbackAttributionRecord(
                    candidate_id=cand.hypothesis.hypothesis_id,
                    signal_family=cand.hypothesis.signal_family,
                    cited_memory_entry_id=ref,
                    cited_decision=pre_rec.decision,
                    predecessor_hypothesis_id=pre_hyp.hypothesis_id,
                    predecessor_failure_or_gap=fail_or_gap,
                    adaptation_description=desc,
                    is_conclusive=is_conclusive,
                    scientific_diffs=tuple(diffs),
                )
            )

    # Build Comparative Summary Table
    comparative_summary = {
        "round_1": {
            "admitted": batch_res_1.funnel.admitted,
            "admitted_rate": batch_res_1.funnel.admitted_rate,
            "exact_duplicate_rate": batch_res_1.funnel.exact_duplicate_rate,
            "family_diversity": len(batch_res_1.funnel.signal_families),
            "generated": batch_res_1.funnel.generated,
            "invalid": batch_res_1.funnel.invalid,
            "novel_rate": batch_res_1.funnel.novel_rate,
            "provider_failed": batch_res_1.funnel.provider_failed,
            "related_rate": batch_res_1.funnel.related_rate,
            "requested": batch_res_1.funnel.requested,
            "signal_families": dict(batch_res_1.funnel.signal_families),
        },
        "round_2": {
            "admitted": batch_res_2.funnel.admitted,
            "admitted_rate": batch_res_2.funnel.admitted_rate,
            "exact_duplicate_rate": batch_res_2.funnel.exact_duplicate_rate,
            "family_diversity": len(batch_res_2.funnel.signal_families),
            "generated": batch_res_2.funnel.generated,
            "invalid": batch_res_2.funnel.invalid,
            "novel_rate": batch_res_2.funnel.novel_rate,
            "provider_failed": batch_res_2.funnel.provider_failed,
            "related_rate": batch_res_2.funnel.related_rate,
            "requested": batch_res_2.funnel.requested,
            "signal_families": dict(batch_res_2.funnel.signal_families),
        },
        "attribution": {
            "attributed_candidates_count": len({a.candidate_id for a in attribution_records}),
            "total_attributions": len(attribution_records),
            "conclusive_attributions": len([a for a in attribution_records if a.is_conclusive]),
        },
    }

    return MemoryFeedbackLoopResult(
        round_1_session=session_1,
        round_1_batch=batch_res_1,
        round_1_integration_results=tuple(r1_integration_results),
        round_2_session=session_2,
        round_2_batch=batch_res_2,
        round_2_integration_results=tuple(r2_integration_results),
        attribution_records=tuple(attribution_records),
        comparative_summary=comparative_summary,
    )
