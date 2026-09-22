"""Milestone A: Astra Discovery Session Contract (#502, Refs #497 Stage 1).

Provides an immutable, tamper-evident, deterministic Discovery Session contract
and deterministic candidate slot planning for Astra autonomous alpha discovery.

Guarantees & Invariants:
1. Strict Fail-Closed Validation:
   - Objective: bounded string (1..2000 chars, non-empty after stripping).
   - Candidate Budget: strict integer 1..10 (rejects booleans, floats, strings, 0, 11).
   - Project Binding: strict non-empty binding matching Scope and Memory View.
   - Authorized Scope: verified least-privilege role 'alpha_generator' with exact
     permissions ('read_research_memory', 'create_hypothesis'), no delegation.
   - Memory View Reference: exact ID and content hash matching Controlled ResearchMemoryView.
   - Consistent validation across direct constructor, from_dict deserializer, and create factory.
   - Deserialization strictly rejects unknown fields.
2. Controlled Context Extraction:
   - Gaps, NME backlog, failed approaches, recent rejects, and promoted summaries are
     sourced exclusively from the bound Controlled ResearchMemoryView.
   - Explicit representation of empty views (total_entries == 0) and truncated views (is_truncated == True).
   - Zero raw Memory access; zero self-claimed model provenance.
3. Deterministic Slot Planning (Minimal Split):
   - Plans N candidate slots where N = candidate_budget (1..10).
   - Preserves M5 contract: one candidate = one AlphaGenerationRequest / AgentTask.
   - requested_candidate_count remains strictly 1.
   - Rebuilding slot produces 100% deterministic, stable identity.
   - Distinct slots within the same session have distinct identities and task IDs.
   - Slot identity is decoupled from execution retry attempt.
   - No Provider submit, no Screening execution, no Critic call, no Memory write.
   - Permanent isolation from trading and production authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from research_lab.agent_control.alpha_generator import (
    PROMPT_POLICY_VERSION,
    AlphaGenerationRequest,
    create_alpha_generation_task,
)
from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentTask,
    ProjectBinding,
    _clean_for_canonical,
    _freeze_mapping,
    _unfreeze_to_dict,
    validate_project_binding,
    validate_scope_hash,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    TamperDetectionError,
)
from research_lab.agent_control.memory_view import (
    ResearchMemoryCategory,
    ResearchMemoryView,
)
from research_lab.contracts import v2

DISCOVERY_SESSION_SCHEMA_VERSION = "research_lab.discovery_session.v1"
DISCOVERY_POLICY_VERSION = "discovery_session_policy.v1"
SUPPORTED_DISCOVERY_POLICIES = frozenset({
    DISCOVERY_POLICY_VERSION,
    PROMPT_POLICY_VERSION,
})

MIN_CANDIDATE_BUDGET = 1
MAX_CANDIDATE_BUDGET = 10
MAX_OBJECTIVE_CHARS = 2_000
CANONICAL_SESSION_TIMESTAMP = "2026-01-01T00:00:00.000000Z"
REQUIRED_PERMISSIONS = ("read_research_memory", "create_hypothesis")

ALLOWED_SESSION_FIELDS = frozenset({
    "session_id",
    "session_content_hash",
    "objective",
    "project_binding",
    "authorized_scope_ref",
    "memory_view_id",
    "memory_view_content_hash",
    "candidate_budget",
    "allowed_universe",
    "allowed_frequency",
    "allowed_signal_families",
    "generation_policy_version",
    "created_at",
    "schema_version",
})


class DiscoverySessionError(ValueError):
    """Base error for Discovery Session contract violations."""


class DiscoverySessionBudgetError(DiscoverySessionError):
    """Raised when candidate budget violates strict 1-10 integer invariants."""


def compute_session_content_hash(data: Mapping[str, Any]) -> str:
    """Compute canonical SHA-256 content hash of a DiscoverySession dictionary representation."""
    canonical_dict = {
        "allowed_frequency": str(data["allowed_frequency"]),
        "allowed_signal_families": sorted([str(x) for x in data.get("allowed_signal_families", ())]),
        "allowed_universe": (
            sorted([str(x) for x in data["allowed_universe"]])
            if isinstance(data["allowed_universe"], (list, tuple))
            else str(data["allowed_universe"])
        ),
        "authorized_scope_ref": _clean_for_canonical(data["authorized_scope_ref"]),
        "candidate_budget": data["candidate_budget"],
        "created_at": str(data.get("created_at", CANONICAL_SESSION_TIMESTAMP)),
        "generation_policy_version": str(data.get("generation_policy_version", DISCOVERY_POLICY_VERSION)),
        "memory_view_content_hash": str(data["memory_view_content_hash"]),
        "memory_view_id": str(data["memory_view_id"]),
        "objective": str(data["objective"]).strip(),
        "project_binding": _clean_for_canonical(data["project_binding"]),
        "schema_version": str(data.get("schema_version", DISCOVERY_SESSION_SCHEMA_VERSION)),
    }
    return v2.digest(canonical_dict)


def compute_session_id(content_hash: str) -> str:
    """Compute deterministic session identifier from content hash."""
    return f"disc-session-{content_hash[:32]}"


@dataclass(frozen=True)
class DiscoverySession:
    """Immutable, tamper-evident contract defining an Astra Discovery Session."""

    session_id: str
    session_content_hash: str
    objective: str
    project_binding: dict[str, str]
    authorized_scope_ref: dict[str, Any]
    memory_view_id: str
    memory_view_content_hash: str
    candidate_budget: int
    allowed_universe: tuple[str, ...] | str
    allowed_frequency: str
    allowed_signal_families: tuple[str, ...] = ()
    generation_policy_version: str = DISCOVERY_POLICY_VERSION
    created_at: str = CANONICAL_SESSION_TIMESTAMP
    schema_version: str = DISCOVERY_SESSION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        # 1. candidate_budget: strict integer 1..10 (reject booleans, floats, strings)
        if type(self.candidate_budget) is not int or isinstance(self.candidate_budget, bool):
            raise DiscoverySessionBudgetError(
                f"candidate_budget must be a strict integer, got {type(self.candidate_budget).__name__}"
            )
        if self.candidate_budget < MIN_CANDIDATE_BUDGET or self.candidate_budget > MAX_CANDIDATE_BUDGET:
            raise DiscoverySessionBudgetError(
                f"candidate_budget must be between {MIN_CANDIDATE_BUDGET} and {MAX_CANDIDATE_BUDGET}, "
                f"got {self.candidate_budget}"
            )

        # 2. objective: bounded non-empty string
        if not isinstance(self.objective, str):
            raise DiscoverySessionError(f"objective must be a string, got {type(self.objective).__name__}")
        clean_objective = self.objective.strip()
        if not clean_objective:
            raise DiscoverySessionError("objective cannot be empty or whitespace only")
        if len(self.objective) > MAX_OBJECTIVE_CHARS:
            raise DiscoverySessionError(
                f"objective exceeds maximum length of {MAX_OBJECTIVE_CHARS} characters ({len(self.objective)} chars)"
            )

        # 3. project_binding: strict validation
        if not isinstance(self.project_binding, Mapping):
            raise ProjectBindingError(
                f"project_binding must be a dictionary/mapping, got {type(self.project_binding).__name__}"
            )
        pb = validate_project_binding(self.project_binding)

        # 4. authorized_scope_ref: strict Access Control verification
        if not isinstance(self.authorized_scope_ref, Mapping):
            raise PermissionDeniedError(
                f"authorized_scope_ref must be a dictionary/mapping, got {type(self.authorized_scope_ref).__name__}"
            )
        scope_role = self.authorized_scope_ref.get("role")
        if scope_role != "alpha_generator":
            raise PermissionDeniedError(
                f"DiscoverySession requires role 'alpha_generator', got '{scope_role}'"
            )
        scope_perms = set(self.authorized_scope_ref.get("authorized_permissions") or ())
        if scope_perms != set(REQUIRED_PERMISSIONS):
            raise PermissionDeniedError(
                f"DiscoverySession requires exact least-privilege permissions {set(REQUIRED_PERMISSIONS)}, "
                f"got {scope_perms}"
            )
        if self.authorized_scope_ref.get("can_delegate") is True:
            raise PermissionDeniedError("Nested delegation prohibited: can_delegate must be False")
        if (self.authorized_scope_ref.get("max_delegation_depth") or 0) > 0:
            raise PermissionDeniedError("Nested delegation prohibited: max_delegation_depth must be 0")
        validate_scope_hash(dict(self.authorized_scope_ref))
        scope_binding = self.authorized_scope_ref.get("project_binding")
        if not scope_binding or dict(scope_binding) != pb.to_dict():
            raise ProjectBindingError(
                "authorized_scope_ref project_binding mismatch with session project_binding",
                details={"scope_binding": scope_binding, "session_binding": pb.to_dict()},
            )

        # 5. memory_view references
        if not isinstance(self.memory_view_id, str) or not self.memory_view_id.strip():
            raise DiscoverySessionError("memory_view_id must be a non-empty string")
        if not isinstance(self.memory_view_content_hash, str) or len(self.memory_view_content_hash.strip()) != 64:
            raise DiscoverySessionError("memory_view_content_hash must be a valid 64-character SHA-256 string")

        # 6. allowed_universe
        if isinstance(self.allowed_universe, str):
            if not self.allowed_universe.strip():
                raise DiscoverySessionError("allowed_universe cannot be empty")
        elif isinstance(self.allowed_universe, (tuple, list)):
            if not self.allowed_universe or not all(isinstance(x, str) and x.strip() for x in self.allowed_universe):
                raise DiscoverySessionError("allowed_universe cannot be empty or contain empty entries")
        else:
            raise DiscoverySessionError("allowed_universe must be a string or sequence of strings")

        # 7. allowed_frequency
        if not isinstance(self.allowed_frequency, str) or not self.allowed_frequency.strip():
            raise DiscoverySessionError("allowed_frequency must be a non-empty string")

        # 8. allowed_signal_families
        if not isinstance(self.allowed_signal_families, (tuple, list)):
            raise DiscoverySessionError("allowed_signal_families must be a tuple or list of strings")
        for fam in self.allowed_signal_families:
            if not isinstance(fam, str) or not fam.strip():
                raise DiscoverySessionError("signal family must be a non-empty string")

        # 9. generation_policy_version
        if self.generation_policy_version not in SUPPORTED_DISCOVERY_POLICIES:
            raise DiscoverySessionError(
                f"Unsupported generation_policy_version '{self.generation_policy_version}', "
                f"supported: {sorted(SUPPORTED_DISCOVERY_POLICIES)}"
            )

        # 10. Canonical digest and session identity verification (anti-tamper / reseal check)
        raw_dict = {
            "allowed_frequency": self.allowed_frequency,
            "allowed_signal_families": self.allowed_signal_families,
            "allowed_universe": self.allowed_universe,
            "authorized_scope_ref": self.authorized_scope_ref,
            "candidate_budget": self.candidate_budget,
            "created_at": self.created_at,
            "generation_policy_version": self.generation_policy_version,
            "memory_view_content_hash": self.memory_view_content_hash,
            "memory_view_id": self.memory_view_id,
            "objective": clean_objective,
            "project_binding": pb.to_dict(),
            "schema_version": self.schema_version,
        }
        expected_hash = compute_session_content_hash(raw_dict)
        expected_id = compute_session_id(expected_hash)
        if self.session_content_hash != expected_hash:
            raise TamperDetectionError(
                f"DiscoverySession session_content_hash mismatch: expected {expected_hash}, "
                f"got {self.session_content_hash}"
            )
        if self.session_id != expected_id:
            raise TamperDetectionError(
                f"DiscoverySession session_id mismatch: expected {expected_id}, got {self.session_id}"
            )

        # 11. Freeze internal mappings and sequences into immutable representations
        object.__setattr__(self, "project_binding", _freeze_mapping(pb.to_dict()))
        object.__setattr__(self, "authorized_scope_ref", _freeze_mapping(dict(self.authorized_scope_ref)))
        object.__setattr__(self, "allowed_signal_families", tuple(self.allowed_signal_families))
        if isinstance(self.allowed_universe, list):
            object.__setattr__(self, "allowed_universe", tuple(self.allowed_universe))

    @classmethod
    def create(
        cls,
        *,
        objective: str,
        memory_view: ResearchMemoryView,
        authorized_scope: AgentPermissionScope,
        candidate_budget: int,
        allowed_universe: tuple[str, ...] | str,
        allowed_frequency: str,
        allowed_signal_families: tuple[str, ...] | list[str] = (),
        project_binding: ProjectBinding | Mapping[str, str] | None = None,
        generation_policy_version: str = DISCOVERY_POLICY_VERSION,
        created_at: str = CANONICAL_SESSION_TIMESTAMP,
    ) -> DiscoverySession:
        """Create and validate a new DiscoverySession from trusted domain objects."""
        # Cross-validate memory_view role
        if memory_view.role != "alpha_generator":
            raise PermissionDeniedError(
                f"DiscoverySession requires an alpha_generator ResearchMemoryView, got '{memory_view.role}'"
            )

        # Cross-validate authorized_scope role
        if authorized_scope.role != "alpha_generator":
            raise PermissionDeniedError(
                f"DiscoverySession requires an alpha_generator AgentPermissionScope, got '{authorized_scope.role}'"
            )

        # Resolve and cross-validate ProjectBinding across all objects
        binding_obj = project_binding or authorized_scope.project_binding
        pb = validate_project_binding(binding_obj)
        if dict(memory_view.project_binding) != pb.to_dict():
            raise ProjectBindingError(
                "Memory View project binding mismatch with session project binding",
                details={"memory_view_binding": dict(memory_view.project_binding), "session_binding": pb.to_dict()},
            )
        if dict(authorized_scope.project_binding) != pb.to_dict():
            raise ProjectBindingError(
                "Authorized scope project binding mismatch with session project binding",
                details={"authorized_scope_binding": dict(authorized_scope.project_binding), "session_binding": pb.to_dict()},
            )

        # Clean objective
        if not isinstance(objective, str):
            raise DiscoverySessionError(f"objective must be a string, got {type(objective).__name__}")
        clean_obj = objective.strip()
        if not clean_obj:
            raise DiscoverySessionError("objective cannot be empty or whitespace only")

        # Validate candidate budget
        if type(candidate_budget) is not int or isinstance(candidate_budget, bool):
            raise DiscoverySessionBudgetError(
                f"candidate_budget must be a strict integer, got {type(candidate_budget).__name__}"
            )
        if candidate_budget < MIN_CANDIDATE_BUDGET or candidate_budget > MAX_CANDIDATE_BUDGET:
            raise DiscoverySessionBudgetError(
                f"candidate_budget must be between {MIN_CANDIDATE_BUDGET} and {MAX_CANDIDATE_BUDGET}, got {candidate_budget}"
            )

        # Normalize universe and signal families
        univ = tuple(allowed_universe) if isinstance(allowed_universe, (list, tuple)) else allowed_universe
        fams = tuple(allowed_signal_families)

        raw_dict = {
            "allowed_frequency": allowed_frequency,
            "allowed_signal_families": fams,
            "allowed_universe": univ,
            "authorized_scope_ref": authorized_scope.to_dict(),
            "candidate_budget": candidate_budget,
            "created_at": created_at,
            "generation_policy_version": generation_policy_version,
            "memory_view_content_hash": memory_view.view_content_hash,
            "memory_view_id": memory_view.view_id,
            "objective": clean_obj,
            "project_binding": pb.to_dict(),
            "schema_version": DISCOVERY_SESSION_SCHEMA_VERSION,
        }
        content_hash = compute_session_content_hash(raw_dict)
        session_id = compute_session_id(content_hash)

        return cls(
            session_id=session_id,
            session_content_hash=content_hash,
            objective=clean_obj,
            project_binding=pb.to_dict(),
            authorized_scope_ref=authorized_scope.to_dict(),
            memory_view_id=memory_view.view_id,
            memory_view_content_hash=memory_view.view_content_hash,
            candidate_budget=candidate_budget,
            allowed_universe=univ,
            allowed_frequency=allowed_frequency,
            allowed_signal_families=fams,
            generation_policy_version=generation_policy_version,
            created_at=created_at,
            schema_version=DISCOVERY_SESSION_SCHEMA_VERSION,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DiscoverySession:
        """Strict fail-closed deserialization rejecting unknown fields."""
        if not isinstance(data, Mapping):
            raise DiscoverySessionError(f"DiscoverySession data must be a Mapping, got {type(data).__name__}")

        # Check for unknown fields (fail-closed)
        unknown = set(data.keys()) - ALLOWED_SESSION_FIELDS
        if unknown:
            raise DiscoverySessionError(
                f"Unknown fields rejected under fail-closed policy: {sorted(unknown)}"
            )

        # Check required fields
        required_fields = {
            "session_id",
            "session_content_hash",
            "objective",
            "project_binding",
            "authorized_scope_ref",
            "memory_view_id",
            "memory_view_content_hash",
            "candidate_budget",
            "allowed_universe",
            "allowed_frequency",
        }
        missing = required_fields - set(data.keys())
        if missing:
            raise DiscoverySessionError(
                f"Missing required DiscoverySession fields: {sorted(missing)}"
            )

        univ = (
            tuple(data["allowed_universe"])
            if isinstance(data["allowed_universe"], list)
            else data["allowed_universe"]
        )
        fams = tuple(data.get("allowed_signal_families", ()))

        return cls(
            session_id=str(data["session_id"]),
            session_content_hash=str(data["session_content_hash"]),
            objective=str(data["objective"]),
            project_binding=dict(data["project_binding"]),
            authorized_scope_ref=dict(data["authorized_scope_ref"]),
            memory_view_id=str(data["memory_view_id"]),
            memory_view_content_hash=str(data["memory_view_content_hash"]),
            candidate_budget=data["candidate_budget"],
            allowed_universe=univ,
            allowed_frequency=str(data["allowed_frequency"]),
            allowed_signal_families=fams,
            generation_policy_version=str(data.get("generation_policy_version", DISCOVERY_POLICY_VERSION)),
            created_at=str(data.get("created_at", CANONICAL_SESSION_TIMESTAMP)),
            schema_version=str(data.get("schema_version", DISCOVERY_SESSION_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert session to serializable dictionary representation."""
        return {
            "allowed_frequency": self.allowed_frequency,
            "allowed_signal_families": list(self.allowed_signal_families),
            "allowed_universe": list(self.allowed_universe) if isinstance(self.allowed_universe, (tuple, list)) else self.allowed_universe,
            "authorized_scope_ref": _unfreeze_to_dict(self.authorized_scope_ref),
            "candidate_budget": self.candidate_budget,
            "created_at": self.created_at,
            "generation_policy_version": self.generation_policy_version,
            "memory_view_content_hash": self.memory_view_content_hash,
            "memory_view_id": self.memory_view_id,
            "objective": self.objective,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "schema_version": self.schema_version,
            "session_content_hash": self.session_content_hash,
            "session_id": self.session_id,
        }

    def _to_canonical_dict(self) -> dict[str, Any]:
        """Internal canonical representation for hashing."""
        return {
            "allowed_frequency": self.allowed_frequency,
            "allowed_signal_families": sorted([str(x) for x in self.allowed_signal_families]),
            "allowed_universe": (
                sorted([str(x) for x in self.allowed_universe])
                if isinstance(self.allowed_universe, (list, tuple))
                else str(self.allowed_universe)
            ),
            "authorized_scope_ref": _clean_for_canonical(self.authorized_scope_ref),
            "candidate_budget": self.candidate_budget,
            "created_at": self.created_at,
            "generation_policy_version": self.generation_policy_version,
            "memory_view_content_hash": self.memory_view_content_hash,
            "memory_view_id": self.memory_view_id,
            "objective": self.objective.strip(),
            "project_binding": _clean_for_canonical(self.project_binding),
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class SessionMemoryContext:
    """Explicit, controlled research context extracted from the bound ResearchMemoryView."""

    view_id: str
    view_content_hash: str
    total_entries: int
    is_empty: bool
    is_truncated: bool
    research_gaps: tuple[dict[str, Any], ...]
    nme_backlog: tuple[dict[str, Any], ...]
    failed_approaches: tuple[dict[str, Any], ...]
    recent_rejects: tuple[dict[str, Any], ...]
    promoted_summaries: tuple[dict[str, Any], ...]
    valid_entry_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "failed_approaches": list(self.failed_approaches),
            "is_empty": self.is_empty,
            "is_truncated": self.is_truncated,
            "nme_backlog": list(self.nme_backlog),
            "promoted_summaries": list(self.promoted_summaries),
            "recent_rejects": list(self.recent_rejects),
            "research_gaps": list(self.research_gaps),
            "total_entries": self.total_entries,
            "valid_entry_ids": list(self.valid_entry_ids),
            "view_content_hash": self.view_content_hash,
            "view_id": self.view_id,
        }


def extract_session_memory_context(memory_view: ResearchMemoryView) -> SessionMemoryContext:
    """Extract explicit, non-fabricated research context categories from Controlled ResearchMemoryView."""
    valid_ids: list[str] = []

    def _extract_category(cat: str) -> tuple[dict[str, Any], ...]:
        entries = memory_view.entries_by_category.get(cat, ())
        res: list[dict[str, Any]] = []
        for e in entries:
            valid_ids.append(e.entry_id)
            item = {
                "entry_id": e.entry_id,
                "hypothesis_id": e.hypothesis_id,
                "decision": e.decision,
                "summary": e.summary,
                "scientific_identity_hash": e.scientific_identity_hash,
                "source_ref": e.view_generated_from,
            }
            if e.reason_codes:
                item["reason_codes"] = list(e.reason_codes)
            if e.gap_type:
                item["gap_type"] = e.gap_type
            if e.failure_class:
                item["failure_class"] = e.failure_class
            res.append(item)
        return tuple(res)

    gaps = _extract_category(ResearchMemoryCategory.RESEARCH_GAPS.value)
    nme = _extract_category(ResearchMemoryCategory.NME_BACKLOG.value)
    failed = _extract_category(ResearchMemoryCategory.FAILED_APPROACHES.value)
    rejects = _extract_category(ResearchMemoryCategory.RECENT_REJECTS.value)
    promoted = _extract_category(ResearchMemoryCategory.PROMOTED_SUMMARIES.value)

    # Collect entry IDs from any other categories as well
    for cat, entries in memory_view.entries_by_category.items():
        for e in entries:
            if e.entry_id not in valid_ids:
                valid_ids.append(e.entry_id)

    return SessionMemoryContext(
        view_id=memory_view.view_id,
        view_content_hash=memory_view.view_content_hash,
        total_entries=memory_view.total_entries,
        is_empty=(memory_view.total_entries == 0),
        is_truncated=memory_view.is_truncated,
        research_gaps=gaps,
        nme_backlog=nme,
        failed_approaches=failed,
        recent_rejects=rejects,
        promoted_summaries=promoted,
        valid_entry_ids=tuple(sorted(set(valid_ids))),
    )


@dataclass(frozen=True)
class PlannedCandidateSlot:
    """A deterministic, independent candidate work block slot within a DiscoverySession."""

    session_id: str
    session_content_hash: str
    slot_index: int
    ordinal: int
    slot_id: str
    slot_content_hash: str
    attempt: int
    request: AlphaGenerationRequest
    task: AgentTask

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "ordinal": self.ordinal,
            "request": self.request.to_dict(),
            "session_content_hash": self.session_content_hash,
            "session_id": self.session_id,
            "slot_content_hash": self.slot_content_hash,
            "slot_id": self.slot_id,
            "slot_index": self.slot_index,
            "task_id": self.task.task_id,
        }


def plan_candidate_slots(
    session: DiscoverySession,
    memory_view: ResearchMemoryView,
    *,
    created_at: str | None = None,
) -> tuple[PlannedCandidateSlot, ...]:
    """Deterministically plan N independent candidate slots from a DiscoverySession.

    Zero Provider submit, zero Screening execution, zero Critic call, zero Memory write.
    """
    # Verify exact Memory View reference binding
    if session.memory_view_id != memory_view.view_id:
        raise DiscoverySessionError(
            f"memory_view view_id mismatch: session={session.memory_view_id}, view={memory_view.view_id}"
        )
    if session.memory_view_content_hash != memory_view.view_content_hash:
        raise TamperDetectionError(
            f"memory_view view_content_hash mismatch: session={session.memory_view_content_hash}, "
            f"view={memory_view.view_content_hash}"
        )
    if dict(session.project_binding) != dict(memory_view.project_binding):
        raise ProjectBindingError(
            f"project_binding mismatch: session={dict(session.project_binding)}, view={dict(memory_view.project_binding)}"
        )

    task_created_at = created_at or session.created_at
    slots: list[PlannedCandidateSlot] = []

    for slot_idx in range(session.candidate_budget):
        ordinal = slot_idx + 1

        # Deterministic slot token & ID
        slot_token = v2.digest({
            "ordinal": ordinal,
            "session_content_hash": session.session_content_hash,
            "session_id": session.session_id,
        })[:12]
        slot_id = f"slot-{session.session_id[:16]}-{ordinal:02d}-{slot_token}"
        slot_hash = v2.digest({
            "ordinal": ordinal,
            "session_id": session.session_id,
            "slot_id": slot_id,
        })

        # Milestone 5 AlphaGenerationRequest: requested_candidate_count remains strictly 1
        req = AlphaGenerationRequest(
            objective=session.objective,
            memory_view_id=session.memory_view_id,
            memory_view_content_hash=session.memory_view_content_hash,
            project_binding=dict(session.project_binding),
            authorized_scope_ref=dict(session.authorized_scope_ref),
            generation_policy_version=PROMPT_POLICY_VERSION,
            requested_candidate_count=1,
            attempt=1,
            session_id=session.session_id,
            slot_id=slot_id,
            ordinal=ordinal,
        )

        # Build task with deterministic provenance timestamp
        task = create_alpha_generation_task(req, memory_view, created_at=task_created_at)

        slots.append(
            PlannedCandidateSlot(
                session_id=session.session_id,
                session_content_hash=session.session_content_hash,
                slot_index=slot_idx,
                ordinal=ordinal,
                slot_id=slot_id,
                slot_content_hash=slot_hash,
                attempt=1,
                request=req,
                task=task,
            )
        )

    return tuple(slots)


def replan_slot_attempt(
    slot: PlannedCandidateSlot,
    memory_view: ResearchMemoryView,
    *,
    attempt: int,
    created_at: str | None = None,
) -> PlannedCandidateSlot:
    """Replan a candidate slot with an incremented attempt count.

    Preserves stable slot_id while updating attempt on the request and task.
    """
    if attempt < 1:
        raise DiscoverySessionError(f"attempt must be >= 1, got {attempt}")

    task_created_at = created_at or slot.task.created_at

    new_req = AlphaGenerationRequest(
        objective=slot.request.objective,
        memory_view_id=slot.request.memory_view_id,
        memory_view_content_hash=slot.request.memory_view_content_hash,
        project_binding=dict(slot.request.project_binding),
        authorized_scope_ref=dict(slot.request.authorized_scope_ref),
        generation_policy_version=slot.request.generation_policy_version,
        requested_candidate_count=1,
        attempt=attempt,
        session_id=slot.session_id,
        slot_id=slot.slot_id,
        ordinal=slot.ordinal,
    )
    new_task = create_alpha_generation_task(new_req, memory_view, created_at=task_created_at)

    return PlannedCandidateSlot(
        session_id=slot.session_id,
        session_content_hash=slot.session_content_hash,
        slot_index=slot.slot_index,
        ordinal=slot.ordinal,
        slot_id=slot.slot_id,
        slot_content_hash=slot.slot_content_hash,
        attempt=attempt,
        request=new_req,
        task=new_task,
    )
