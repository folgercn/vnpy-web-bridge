"""Milestone A: Astra Discovery Session Contract (#502, Refs #497 Stage 1).

Provides an immutable, tamper-evident, deterministic Discovery Session contract
and deterministic candidate slot planning for Astra autonomous alpha discovery.

Guarantees & Invariants:
1. Strict Fail-Closed Validation:
   - Objective: bounded string (1..2000 chars, non-empty after stripping).
   - Candidate Budget: strict integer 1..10 (rejects booleans, floats, strings, 0, 11).
   - Project Binding: strict non-empty binding matching Scope and Memory View.
   - Authorized Scope: verified least-privilege role 'alpha_generator' with exact
     permissions ('read_research_memory', 'create_hypothesis'), is_authorized is strictly True,
     supported policy version, no delegation.
   - Controlled Memory View Binding: exact ID, content hash, role, project_binding,
     policy, and full canonical snapshot digest matching real ResearchMemoryView.
   - Direct constructor, from_dict deserializer, and create factory all enforce
     identical strict validation and require authentic ResearchMemoryView context.
   - Deserialization strictly rejects unknown fields and loose type casting.
2. Controlled Context Extraction:
   - Gaps, NME backlog, failed approaches, recent rejects, and promoted summaries are
     sourced exclusively from the bound Controlled ResearchMemoryView.
   - Explicit representation of empty views (total_entries == 0) and truncated views (is_truncated == True).
   - Faithful preservation of entry source_refs, source_hashes, and evidence_refs.
   - Zero raw Memory access; zero self-claimed model provenance.
3. Deterministic Slot Planning:
   - Plans N candidate slots where N = candidate_budget (1..10).
   - Preserves M5 contract: one candidate = one AlphaGenerationRequest / AgentTask.
   - requested_candidate_count remains strictly 1.
   - Binds exact allowed_universe, allowed_frequency, allowed_signal_families,
     and generation_policy_version to each request and task work_block / input_refs.
   - Rebuilding slot produces 100% deterministic, stable identity.
   - Distinct slots within the same session have distinct identities and task IDs.
   - Slot identity is decoupled from execution retry attempt.
   - PlannedCandidateSlot holds verified Session context and enforces deep cross-object
     consistency (ordinal <= candidate_budget, recomputed request/task bounds and input_refs audit hashes).
   - No Provider submit, no Screening execution, no Critic call, no Memory write.
   - Permanent isolation from trading and production authority.
"""

from __future__ import annotations

from collections.abc import Mapping
import dataclasses
from dataclasses import InitVar, dataclass
from typing import Any

from research_lab.agent_control.alpha_generator import (
    DISCOVERY_POLICY_VERSION,
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
SUPPORTED_DISCOVERY_POLICIES = frozenset({
    DISCOVERY_POLICY_VERSION,
    PROMPT_POLICY_VERSION,
    "discovery_session_policy.v1",
    "discovery_generation_policy.v1",
})
SUPPORTED_SCOPE_POLICIES = frozenset({
    "2026-09-m1",
    "research_lab.agent_scope.v1",
    "2026-09-m4",
    "2026-09-m0",
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
    "memory_view_ref",
    "memory_view_id",
    "memory_view_content_hash",
    "memory_view_snapshot_hash",
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


def compute_memory_view_snapshot_hash(view: ResearchMemoryView) -> str:
    """Compute deterministic canonical digest of full Controlled ResearchMemoryView snapshot.

    Excludes non-semantic wall-clock `generated_at` to preserve deterministic identity stability
    across identical memory states.
    """
    if not isinstance(view, ResearchMemoryView):
        raise DiscoverySessionError(
            f"memory_view must be an instance of ResearchMemoryView, got {type(view).__name__}"
        )
    d = view.to_dict()
    d.pop("generated_at", None)
    return v2.digest(_clean_for_canonical(d))


def build_memory_view_ref(view: ResearchMemoryView) -> dict[str, Any]:
    """Extract verifiable metadata reference payload from a Controlled ResearchMemoryView."""
    return {
        "view_id": view.view_id,
        "view_content_hash": view.view_content_hash,
        "snapshot_hash": compute_memory_view_snapshot_hash(view),
        "role": view.role,
        "project_binding": (
            view.project_binding.to_dict()
            if isinstance(view.project_binding, ProjectBinding)
            else dict(view.project_binding)
        ),
        "policy_version": view.policy_version,
        "source_refs": list(view.source_refs),
        "total_entries": view.total_entries,
        "is_truncated": view.is_truncated,
        "categories": list(view.categories),
    }


def validate_session_memory_view(
    session_data: Mapping[str, Any],
    memory_view: ResearchMemoryView,
) -> None:
    """Deep verification of real Controlled ResearchMemoryView context against session bindings."""
    if not isinstance(memory_view, ResearchMemoryView):
        raise DiscoverySessionError(
            f"memory_view must be an instance of ResearchMemoryView, got {type(memory_view).__name__}"
        )
    if memory_view.role != "alpha_generator":
        raise PermissionDeniedError(
            f"memory_view role must be 'alpha_generator', got '{memory_view.role}'"
        )
    expected_pb = validate_project_binding(session_data["project_binding"])
    if dict(memory_view.project_binding) != expected_pb.to_dict():
        raise ProjectBindingError(
            "memory_view project_binding mismatch with session project_binding",
            details={"memory_view_binding": dict(memory_view.project_binding), "session_binding": expected_pb.to_dict()},
        )
    if memory_view.view_id != str(session_data["memory_view_id"]):
        raise DiscoverySessionError(
            f"memory_view.view_id '{memory_view.view_id}' mismatch with session.memory_view_id '{session_data['memory_view_id']}'"
        )
    if memory_view.view_content_hash != str(session_data["memory_view_content_hash"]):
        raise TamperDetectionError(
            f"memory_view.view_content_hash '{memory_view.view_content_hash}' mismatch with session '{session_data['memory_view_content_hash']}'"
        )
    actual_snapshot_hash = compute_memory_view_snapshot_hash(memory_view)
    expected_snapshot_hash = session_data.get("memory_view_snapshot_hash")
    if expected_snapshot_hash and actual_snapshot_hash != expected_snapshot_hash:
        raise TamperDetectionError(
            f"memory_view snapshot digest tampering detected: expected '{expected_snapshot_hash}', actual '{actual_snapshot_hash}'"
        )
    if "memory_view_ref" in session_data:
        validate_memory_view_ref(session_data["memory_view_ref"], memory_view)


def validate_memory_view_ref(
    memory_view_ref: Mapping[str, Any],
    memory_view: ResearchMemoryView,
) -> dict[str, Any]:
    """Strict validation of the controlled ResearchMemoryView reference structure against authentic view."""
    if not isinstance(memory_view_ref, Mapping):
        raise DiscoverySessionError(
            f"memory_view_ref must be a dictionary/mapping, got {type(memory_view_ref).__name__}"
        )
    if not isinstance(memory_view, ResearchMemoryView):
        raise DiscoverySessionError(
            f"memory_view must be a valid ResearchMemoryView instance, got {type(memory_view).__name__}"
        )
    expected_ref = build_memory_view_ref(memory_view)

    # 1. Reject unknown or extra fields in memory_view_ref fail-closed
    actual_keys = set(memory_view_ref.keys())
    expected_keys = set(expected_ref.keys())
    extra_keys = sorted(actual_keys - expected_keys)
    if extra_keys:
        raise DiscoverySessionError(
            f"memory_view_ref contains unknown or unauthorized fields: {extra_keys}"
        )
    missing_keys = sorted(expected_keys - actual_keys)
    if missing_keys:
        raise DiscoverySessionError(
            f"memory_view_ref is missing required fields: {missing_keys}"
        )

    # 2. Canonical exact comparison with build_memory_view_ref(memory_view)
    clean_actual = _clean_for_canonical(dict(memory_view_ref))
    clean_expected = _clean_for_canonical(expected_ref)
    if clean_actual != clean_expected:
        diffs = [
            f"{k} (expected {clean_expected.get(k)!r}, got {clean_actual.get(k)!r})"
            for k in sorted(expected_keys)
            if clean_actual.get(k) != clean_expected.get(k)
        ]
        raise DiscoverySessionError(
            f"memory_view_ref mismatch with authentic ResearchMemoryView reference: {'; '.join(diffs)}"
        )
    return clean_actual


def compute_session_content_hash(data: Mapping[str, Any]) -> str:
    """Compute canonical SHA-256 content hash of a DiscoverySession dictionary representation.

    Deterministic identity stability guarantee:
    Audit timestamp `created_at` is strictly excluded from canonical identity computation.
    """
    raw_budget = data.get("candidate_budget")
    if type(raw_budget) is not int or isinstance(raw_budget, bool):
        raise DiscoverySessionBudgetError(
            f"candidate_budget must be a strict integer, got {type(raw_budget).__name__}"
        )
    if raw_budget < MIN_CANDIDATE_BUDGET or raw_budget > MAX_CANDIDATE_BUDGET:
        raise DiscoverySessionBudgetError(
            f"candidate_budget must be between {MIN_CANDIDATE_BUDGET} and {MAX_CANDIDATE_BUDGET}, "
            f"got {raw_budget}"
        )

    raw_freq = data.get("allowed_frequency")
    if type(raw_freq) is not str or not raw_freq.strip():
        raise DiscoverySessionError(f"allowed_frequency must be a non-empty string, got {raw_freq!r}")

    raw_univ = data.get("allowed_universe")
    if isinstance(raw_univ, (list, tuple)):
        univ_clean: list[str] = []
        for u in raw_univ:
            if type(u) is not str or not u.strip():
                raise DiscoverySessionError(f"allowed_universe elements must be non-empty strings, got {u!r}")
            univ_clean.append(u.strip())
        canonical_univ: list[str] | str = sorted(univ_clean)
    elif type(raw_univ) is str and raw_univ.strip():
        canonical_univ = raw_univ.strip()
    else:
        raise DiscoverySessionError(f"allowed_universe must be a non-empty string or sequence of strings, got {raw_univ!r}")

    raw_families = data.get("allowed_signal_families", ())
    if not isinstance(raw_families, (list, tuple)) or isinstance(raw_families, (str, bytes)):
        raise DiscoverySessionError(f"allowed_signal_families must be a tuple or list, got {type(raw_families).__name__}")
    fams_clean: list[str] = []
    for f in raw_families:
        if type(f) is not str or not f.strip():
            raise DiscoverySessionError(f"allowed_signal_families elements must be non-empty strings, got {f!r}")
        fams_clean.append(f.strip())
    canonical_fams = sorted(fams_clean)

    raw_obj = data.get("objective")
    if type(raw_obj) is not str or not raw_obj.strip():
        raise DiscoverySessionError(f"objective must be a non-empty string, got {raw_obj!r}")

    raw_snapshot_hash = data.get("memory_view_snapshot_hash")
    if not isinstance(raw_snapshot_hash, str) or len(raw_snapshot_hash) != 64:
        raise DiscoverySessionError(
            "memory_view_snapshot_hash must be a valid 64-character SHA-256 string"
        )

    canonical_dict = {
        "allowed_frequency": raw_freq.strip(),
        "allowed_signal_families": canonical_fams,
        "allowed_universe": canonical_univ,
        "authorized_scope_ref": _clean_for_canonical(data["authorized_scope_ref"]),
        "candidate_budget": raw_budget,
        "generation_policy_version": str(data.get("generation_policy_version", DISCOVERY_POLICY_VERSION)),
        "memory_view_content_hash": str(data["memory_view_content_hash"]),
        "memory_view_id": str(data["memory_view_id"]),
        "memory_view_ref": _clean_for_canonical(data.get("memory_view_ref", {})),
        "memory_view_snapshot_hash": raw_snapshot_hash,
        "objective": raw_obj.strip(),
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
    memory_view_ref: dict[str, Any]
    memory_view_id: str
    memory_view_content_hash: str
    memory_view_snapshot_hash: str
    candidate_budget: int
    allowed_universe: tuple[str, ...] | str
    allowed_frequency: str
    memory_view: InitVar[ResearchMemoryView]
    allowed_signal_families: tuple[str, ...] = ()
    generation_policy_version: str = DISCOVERY_POLICY_VERSION
    created_at: str = CANONICAL_SESSION_TIMESTAMP
    schema_version: str = DISCOVERY_SESSION_SCHEMA_VERSION

    def __post_init__(self, memory_view: ResearchMemoryView) -> None:
        # 0. schema_version check (strict fail-closed)
        if self.schema_version != DISCOVERY_SESSION_SCHEMA_VERSION:
            raise DiscoverySessionError(
                f"Unsupported schema_version '{self.schema_version}', expected '{DISCOVERY_SESSION_SCHEMA_VERSION}'"
            )

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
        if type(self.objective) is not str:
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

        # 4. authorized_scope_ref: strict Access Control verification & semantic scope execution
        if not isinstance(self.authorized_scope_ref, Mapping):
            raise PermissionDeniedError(
                f"authorized_scope_ref must be a dictionary/mapping, got {type(self.authorized_scope_ref).__name__}"
            )
        if self.authorized_scope_ref.get("can_delegate") is True:
            raise PermissionDeniedError("Nested delegation prohibited: can_delegate must be False")
        if (self.authorized_scope_ref.get("max_delegation_depth") or 0) > 0:
            raise PermissionDeniedError("Nested delegation prohibited: max_delegation_depth must be 0")

        scope_dict = dict(self.authorized_scope_ref)
        scope_dict.pop("can_delegate", None)
        scope_dict.pop("max_delegation_depth", None)
        try:
            scope = AgentPermissionScope(**scope_dict)
        except Exception as exc:
            raise PermissionDeniedError(f"authorized_scope_ref failed AgentPermissionScope construction: {exc}") from exc

        if scope.is_authorized is not True:
            raise PermissionDeniedError(
                "authorized_scope is not authorized (is_authorized must be strictly True)"
            )
        if scope.role != "alpha_generator":
            raise PermissionDeniedError(
                f"DiscoverySession requires role 'alpha_generator', got '{scope.role}'"
            )
        if set(scope.authorized_permissions) != set(REQUIRED_PERMISSIONS):
            raise PermissionDeniedError(
                f"DiscoverySession requires exact least-privilege permissions {set(REQUIRED_PERMISSIONS)}, "
                f"got {set(scope.authorized_permissions)}"
            )
        if scope.policy_version not in SUPPORTED_SCOPE_POLICIES:
            raise PermissionDeniedError(
                f"Unsupported or unknown scope policy_version '{scope.policy_version}'"
            )
        validate_scope_hash(scope.to_dict())
        if dict(scope.project_binding) != pb.to_dict():
            raise ProjectBindingError(
                "authorized_scope_ref project_binding mismatch with session project_binding",
                details={"scope_binding": dict(scope.project_binding), "session_binding": pb.to_dict()},
            )

        # 5. Full Controlled ResearchMemoryView context verification
        if not isinstance(self.memory_view_snapshot_hash, str) or len(self.memory_view_snapshot_hash) != 64:
            raise DiscoverySessionError("memory_view_snapshot_hash must be a valid 64-character SHA-256 string")

        validate_session_memory_view(
            {
                "project_binding": pb.to_dict(),
                "memory_view_id": self.memory_view_id,
                "memory_view_content_hash": self.memory_view_content_hash,
                "memory_view_snapshot_hash": self.memory_view_snapshot_hash,
                "memory_view_ref": self.memory_view_ref,
            },
            memory_view,
        )

        # 6. allowed_universe
        if isinstance(self.allowed_universe, str):
            if not self.allowed_universe.strip():
                raise DiscoverySessionError("allowed_universe cannot be empty")
        elif isinstance(self.allowed_universe, (tuple, list)):
            if not self.allowed_universe or not all(isinstance(x, str) and x.strip() for x in self.allowed_universe):
                raise DiscoverySessionError("allowed_universe cannot be empty or contain empty entries")
            object.__setattr__(self, "allowed_universe", tuple(self.allowed_universe))
        else:
            raise DiscoverySessionError("allowed_universe must be a string or sequence of strings")

        # 7. allowed_frequency
        if type(self.allowed_frequency) is not str or not self.allowed_frequency.strip():
            raise DiscoverySessionError(f"allowed_frequency must be a non-empty string, got {self.allowed_frequency!r}")

        # 8. allowed_signal_families (reject bare strings or non-iterables)
        if not isinstance(self.allowed_signal_families, (tuple, list)) or isinstance(self.allowed_signal_families, (str, bytes)):
            raise DiscoverySessionError(
                "allowed_signal_families must be a tuple or list of strings, not a bare string"
            )
        for fam in self.allowed_signal_families:
            if not isinstance(fam, str) or not fam.strip():
                raise DiscoverySessionError("signal family must be a non-empty string")
        object.__setattr__(self, "allowed_signal_families", tuple(self.allowed_signal_families))

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
            "memory_view_ref": self.memory_view_ref,
            "memory_view_snapshot_hash": self.memory_view_snapshot_hash,
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

        # 11. Deep freeze mutable containers
        object.__setattr__(self, "project_binding", _freeze_mapping(pb.to_dict()))
        object.__setattr__(self, "authorized_scope_ref", _freeze_mapping(dict(self.authorized_scope_ref)))
        object.__setattr__(self, "memory_view_ref", _freeze_mapping(dict(self.memory_view_ref)))

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
        if not isinstance(memory_view, ResearchMemoryView):
            raise DiscoverySessionError(f"memory_view must be ResearchMemoryView, got {type(memory_view).__name__}")
        if memory_view.role != "alpha_generator":
            raise PermissionDeniedError(
                f"DiscoverySession requires an alpha_generator ResearchMemoryView, got '{memory_view.role}'"
            )

        if not isinstance(authorized_scope, AgentPermissionScope):
            raise PermissionDeniedError(
                f"DiscoverySession requires AgentPermissionScope, got {type(authorized_scope).__name__}"
            )
        if authorized_scope.role != "alpha_generator":
            raise PermissionDeniedError(
                f"DiscoverySession requires an alpha_generator AgentPermissionScope, got '{authorized_scope.role}'"
            )
        if authorized_scope.is_authorized is not True:
            raise PermissionDeniedError(
                "authorized_scope is not authorized (is_authorized must be strictly True)"
            )

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

        if type(objective) is not str:
            raise DiscoverySessionError(f"objective must be a string, got {type(objective).__name__}")
        clean_obj = objective.strip()
        if not clean_obj:
            raise DiscoverySessionError("objective cannot be empty or whitespace only")

        if type(candidate_budget) is not int or isinstance(candidate_budget, bool):
            raise DiscoverySessionBudgetError(
                f"candidate_budget must be a strict integer, got {type(candidate_budget).__name__}"
            )
        if candidate_budget < MIN_CANDIDATE_BUDGET or candidate_budget > MAX_CANDIDATE_BUDGET:
            raise DiscoverySessionBudgetError(
                f"candidate_budget must be between {MIN_CANDIDATE_BUDGET} and {MAX_CANDIDATE_BUDGET}, got {candidate_budget}"
            )

        if type(allowed_frequency) is not str or not allowed_frequency.strip():
            raise DiscoverySessionError(f"allowed_frequency must be a non-empty string, got {allowed_frequency!r}")

        if isinstance(allowed_signal_families, (str, bytes)):
            raise DiscoverySessionError(
                "allowed_signal_families must be a tuple or list of strings, not a bare string"
            )
        if not isinstance(allowed_signal_families, (tuple, list)):
            raise DiscoverySessionError(
                f"allowed_signal_families must be a tuple or list, got {type(allowed_signal_families).__name__}"
            )
        fams = tuple(allowed_signal_families)

        if isinstance(allowed_universe, (str, bytes)):
            if not allowed_universe.strip():
                raise DiscoverySessionError("allowed_universe cannot be empty")
            univ: tuple[str, ...] | str = allowed_universe.strip()
        elif isinstance(allowed_universe, (tuple, list)):
            if not allowed_universe:
                raise DiscoverySessionError("allowed_universe cannot be empty")
            univ = tuple(allowed_universe)
        else:
            raise DiscoverySessionError("allowed_universe must be a string or sequence of strings")

        view_ref = build_memory_view_ref(memory_view)
        snapshot_hash = compute_memory_view_snapshot_hash(memory_view)

        raw_dict = {
            "allowed_frequency": allowed_frequency.strip(),
            "allowed_signal_families": fams,
            "allowed_universe": univ,
            "authorized_scope_ref": authorized_scope.to_dict(),
            "candidate_budget": candidate_budget,
            "created_at": created_at,
            "generation_policy_version": generation_policy_version,
            "memory_view_content_hash": memory_view.view_content_hash,
            "memory_view_id": memory_view.view_id,
            "memory_view_ref": view_ref,
            "memory_view_snapshot_hash": snapshot_hash,
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
            memory_view_ref=view_ref,
            memory_view_id=memory_view.view_id,
            memory_view_content_hash=memory_view.view_content_hash,
            memory_view_snapshot_hash=snapshot_hash,
            candidate_budget=candidate_budget,
            allowed_universe=univ,
            allowed_frequency=allowed_frequency.strip(),
            memory_view=memory_view,
            allowed_signal_families=fams,
            generation_policy_version=generation_policy_version,
            created_at=created_at,
            schema_version=DISCOVERY_SESSION_SCHEMA_VERSION,
        )

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        memory_view: ResearchMemoryView,
    ) -> DiscoverySession:
        """Restore and validate a DiscoverySession from serialized payload with authentic MemoryView context."""
        if not isinstance(data, Mapping):
            raise DiscoverySessionError(f"payload must be a mapping, got {type(data).__name__}")
        if not isinstance(memory_view, ResearchMemoryView):
            raise DiscoverySessionError(
                f"memory_view must be a valid ResearchMemoryView instance, got {type(memory_view).__name__}"
            )

        # Check unknown fields
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
            "memory_view_ref",
            "memory_view_id",
            "memory_view_content_hash",
            "memory_view_snapshot_hash",
            "candidate_budget",
            "allowed_universe",
            "allowed_frequency",
        }
        missing = required_fields - set(data.keys())
        if missing:
            raise DiscoverySessionError(
                f"Missing required DiscoverySession fields: {sorted(missing)}"
            )

        # Strict type checks without loose conversion
        if type(data["objective"]) is not str:
            raise DiscoverySessionError(f"objective must be a string, got {type(data['objective']).__name__}")
        if type(data["candidate_budget"]) is not int or isinstance(data["candidate_budget"], bool):
            raise DiscoverySessionBudgetError(
                f"candidate_budget must be a strict integer, got {type(data['candidate_budget']).__name__}"
            )
        if type(data["allowed_frequency"]) is not str:
            raise DiscoverySessionError(
                f"allowed_frequency must be a string, got {type(data['allowed_frequency']).__name__}"
            )
        if not isinstance(data.get("allowed_signal_families", ()), (tuple, list)) or isinstance(data.get("allowed_signal_families"), (str, bytes)):
            raise DiscoverySessionError("allowed_signal_families must be a tuple or list of strings")

        if data.get("schema_version") and data["schema_version"] != DISCOVERY_SESSION_SCHEMA_VERSION:
            raise DiscoverySessionError(
                f"Unsupported schema_version '{data['schema_version']}', expected '{DISCOVERY_SESSION_SCHEMA_VERSION}'"
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
            objective=data["objective"],
            project_binding=dict(data["project_binding"]),
            authorized_scope_ref=dict(data["authorized_scope_ref"]),
            memory_view_ref=dict(data["memory_view_ref"]),
            memory_view_id=str(data["memory_view_id"]),
            memory_view_content_hash=str(data["memory_view_content_hash"]),
            memory_view_snapshot_hash=str(data["memory_view_snapshot_hash"]),
            candidate_budget=data["candidate_budget"],
            allowed_universe=univ,
            allowed_frequency=data["allowed_frequency"],
            memory_view=memory_view,
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
            "allowed_universe": (
                list(self.allowed_universe)
                if isinstance(self.allowed_universe, (list, tuple))
                else self.allowed_universe
            ),
            "authorized_scope_ref": _unfreeze_to_dict(self.authorized_scope_ref),
            "candidate_budget": self.candidate_budget,
            "created_at": self.created_at,
            "generation_policy_version": self.generation_policy_version,
            "memory_view_content_hash": self.memory_view_content_hash,
            "memory_view_id": self.memory_view_id,
            "memory_view_ref": _unfreeze_to_dict(self.memory_view_ref),
            "memory_view_snapshot_hash": self.memory_view_snapshot_hash,
            "objective": self.objective,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "schema_version": self.schema_version,
            "session_content_hash": self.session_content_hash,
            "session_id": self.session_id,
        }


@dataclass(frozen=True)
class SessionMemoryContext:
    """Safe, read-only projection extracted from a Controlled ResearchMemoryView."""

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
    view_source_refs: tuple[str, ...]
    schema_version: str = "research_lab.session_memory_context.v1"


def extract_session_memory_context(memory_view: ResearchMemoryView) -> SessionMemoryContext:
    """Project a Controlled ResearchMemoryView into immutable SessionMemoryContext."""
    if not isinstance(memory_view, ResearchMemoryView):
        raise DiscoverySessionError(
            f"Expected ResearchMemoryView instance, got {type(memory_view).__name__}"
        )

    valid_ids: list[str] = []

    def _extract_category(category_name: str) -> tuple[dict[str, Any], ...]:
        entries = memory_view.entries_by_category.get(category_name, ())
        res: list[dict[str, Any]] = []
        for e in entries:
            valid_ids.append(e.entry_id)
            res.append({
                "entry_id": e.entry_id,
                "hypothesis_id": e.hypothesis_id,
                "decision": e.decision,
                "summary": e.summary,
                "source_refs": _unfreeze_to_dict(e.source_refs),
                "source_hashes": _unfreeze_to_dict(e.source_hashes),
                "evidence_refs": _unfreeze_to_dict(e.evidence_refs),
            })
        return tuple(res)

    gaps = _extract_category(ResearchMemoryCategory.RESEARCH_GAPS.value)
    nme = _extract_category(ResearchMemoryCategory.NME_BACKLOG.value)
    failed = _extract_category(ResearchMemoryCategory.FAILED_APPROACHES.value)
    rejects = _extract_category(ResearchMemoryCategory.RECENT_REJECTS.value)
    promoted = _extract_category(ResearchMemoryCategory.PROMOTED_SUMMARIES.value)

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
        view_source_refs=tuple(memory_view.source_refs),
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
    session: DiscoverySession
    memory_view: ResearchMemoryView

    def __post_init__(self) -> None:
        # 0. Session context and memory view verification
        if not isinstance(self.session, DiscoverySession):
            raise DiscoverySessionError(
                f"session must be a valid DiscoverySession instance, got {type(self.session).__name__}"
            )
        if not isinstance(self.memory_view, ResearchMemoryView):
            raise DiscoverySessionError(
                f"memory_view must be a valid ResearchMemoryView instance, got {type(self.memory_view).__name__}"
            )
        validate_session_memory_view(self.session.to_dict(), self.memory_view)

        if self.session_id != self.session.session_id:
            raise DiscoverySessionError(
                f"slot session_id '{self.session_id}' mismatch with session '{self.session.session_id}'"
            )
        if self.session_content_hash != self.session.session_content_hash:
            raise TamperDetectionError(
                "slot session_content_hash mismatch with session"
            )

        # 1. Attempt validation: strict positive integer
        if type(self.attempt) is not int or isinstance(self.attempt, bool) or self.attempt < 1:
            raise DiscoverySessionError(f"attempt must be a strict positive integer, got {self.attempt}")

        # 2. Slot index and ordinal validation within session candidate budget
        if type(self.slot_index) is not int or isinstance(self.slot_index, bool) or self.slot_index < 0:
            raise DiscoverySessionError(f"slot_index must be a non-negative integer, got {self.slot_index}")
        if type(self.ordinal) is not int or isinstance(self.ordinal, bool) or self.ordinal < 1:
            raise DiscoverySessionError(f"ordinal must be a positive integer, got {self.ordinal}")
        if self.ordinal != self.slot_index + 1:
            raise DiscoverySessionError(
                f"ordinal mismatch with slot_index: expected {self.slot_index + 1}, got {self.ordinal}"
            )
        if self.ordinal > self.session.candidate_budget:
            raise DiscoverySessionBudgetError(
                f"ordinal {self.ordinal} exceeds session candidate_budget {self.session.candidate_budget}"
            )

        # 3. Deterministic slot identity verification
        expected_token = v2.digest({
            "ordinal": self.ordinal,
            "session_content_hash": self.session_content_hash,
            "session_id": self.session_id,
        })[:12]
        expected_slot_id = f"slot-{self.session_id[:16]}-{self.ordinal:02d}-{expected_token}"
        if self.slot_id != expected_slot_id:
            raise TamperDetectionError(
                f"PlannedCandidateSlot slot_id mismatch: expected '{expected_slot_id}', got '{self.slot_id}'"
            )

        expected_slot_hash = v2.digest({
            "ordinal": self.ordinal,
            "session_id": self.session_id,
            "slot_id": self.slot_id,
        })
        if self.slot_content_hash != expected_slot_hash:
            raise TamperDetectionError(
                f"PlannedCandidateSlot slot_content_hash mismatch: expected '{expected_slot_hash}', "
                f"got '{self.slot_content_hash}'"
            )

        # 4. Cross-object consistency with AlphaGenerationRequest (full expected request reconstruction)
        if not isinstance(self.request, AlphaGenerationRequest):
            raise DiscoverySessionError(
                f"request must be an AlphaGenerationRequest, got {type(self.request).__name__}"
            )
        if self.request.session_id != self.session_id:
            raise DiscoverySessionError(
                f"request.session_id '{self.request.session_id}' mismatch with slot.session_id '{self.session_id}'"
            )
        if self.request.slot_id != self.slot_id:
            raise DiscoverySessionError(
                f"request.slot_id '{self.request.slot_id}' mismatch with slot.slot_id '{self.slot_id}'"
            )
        if self.request.ordinal != self.ordinal:
            raise DiscoverySessionError(
                f"request.ordinal '{self.request.ordinal}' mismatch with slot.ordinal '{self.ordinal}'"
            )
        if self.request.attempt != self.attempt:
            raise DiscoverySessionError(
                f"request.attempt '{self.request.attempt}' mismatch with slot.attempt '{self.attempt}'"
            )
        if self.request.requested_candidate_count != 1:
            raise DiscoverySessionError("request.requested_candidate_count must be strictly 1")

        expected_request = AlphaGenerationRequest.create(
            objective=self.session.objective,
            memory_view=self.memory_view,
            project_binding=self.session.project_binding,
            authorized_scope=AgentPermissionScope(**dict(self.session.authorized_scope_ref)),
            allowed_universe=self.session.allowed_universe,
            allowed_frequency=self.session.allowed_frequency,
            allowed_signal_families=self.session.allowed_signal_families,
            generation_policy_version=self.session.generation_policy_version,
            session_id=self.session_id,
            slot_id=self.slot_id,
            ordinal=self.ordinal,
            attempt=self.attempt,
        )

        clean_actual_req = _clean_for_canonical(self.request.to_dict())
        clean_expected_req = _clean_for_canonical(expected_request.to_dict())
        if clean_actual_req != clean_expected_req:
            diff_keys = [
                k for k in set(clean_actual_req.keys()) | set(clean_expected_req.keys())
                if clean_actual_req.get(k) != clean_expected_req.get(k)
            ]
            diff_details = [
                f"request.{k} mismatch with session: expected {clean_expected_req.get(k)!r}, got {clean_actual_req.get(k)!r}"
                for k in sorted(diff_keys)
            ]
            raise DiscoverySessionError(
                f"PlannedCandidateSlot request mismatch with session: {'; '.join(diff_details)}"
            )

        # 5. Cross-object consistency with AgentTask (full expected task reconstruction)
        if not isinstance(self.task, AgentTask):
            raise DiscoverySessionError(f"task must be an AgentTask, got {type(self.task).__name__}")
        if self.task.role != "alpha_generator":
            raise PermissionDeniedError(f"task role must be 'alpha_generator', got '{self.task.role}'")

        # Verify task input_refs binds BOTH memory view and exact slot with valid hash
        mem_input_refs = [
            r for r in self.task.input_refs
            if isinstance(r, (dict, Mapping))
            and r.get("ref") == self.session.memory_view_id
            and r.get("content_hash") == self.session.memory_view_content_hash
        ]
        if not mem_input_refs:
            raise DiscoverySessionError(
                f"task input_refs missing valid reference to memory_view '{self.session.memory_view_id}'"
            )

        slot_input_refs = [
            r for r in self.task.input_refs
            if isinstance(r, (dict, Mapping)) and r.get("ref") == self.slot_id
        ]
        if not slot_input_refs:
            raise DiscoverySessionError(
                f"task input_refs missing reference to slot_id '{self.slot_id}'"
            )
        expected_slot_audit_hash = v2.digest({
            "allowed_frequency": self.request.allowed_frequency,
            "allowed_signal_families": (
                sorted(self.request.allowed_signal_families)
                if self.request.allowed_signal_families
                else []
            ),
            "allowed_universe": (
                sorted(self.request.allowed_universe)
                if isinstance(self.request.allowed_universe, (list, tuple))
                else self.request.allowed_universe
            ),
            "attempt": self.attempt,
            "generation_policy_version": self.request.generation_policy_version,
            "ordinal": self.ordinal,
            "slot_id": self.slot_id,
        })
        if slot_input_refs[0].get("content_hash") != expected_slot_audit_hash:
            raise TamperDetectionError(
                f"task input_refs slot content_hash mismatch: expected '{expected_slot_audit_hash}', "
                f"got '{slot_input_refs[0].get('content_hash')}'"
            )

        expected_task = create_alpha_generation_task(
            expected_request,
            self.memory_view,
            created_at=self.task.created_at,
        )
        clean_actual_task = _clean_for_canonical(self.task.to_dict())
        clean_expected_task = _clean_for_canonical(expected_task.to_dict())
        if clean_actual_task != clean_expected_task:
            diff_keys = [
                k for k in set(clean_actual_task.keys()) | set(clean_expected_task.keys())
                if clean_actual_task.get(k) != clean_expected_task.get(k)
            ]
            diff_details = [
                f"task.{k} mismatch with expected authentic task: expected {clean_expected_task.get(k)!r}, got {clean_actual_task.get(k)!r}"
                for k in sorted(diff_keys)
            ]
            raise TamperDetectionError(
                f"PlannedCandidateSlot task mismatch with expected authentic task: {'; '.join(diff_details)}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert planned slot to serializable dictionary representation."""
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
) -> tuple[PlannedCandidateSlot, ...]:
    """Plan pure deterministic candidate slots for a validated DiscoverySession."""
    if not isinstance(session, DiscoverySession):
        raise DiscoverySessionError(f"session must be a DiscoverySession instance, got {type(session).__name__}")
    validate_session_memory_view(session.to_dict(), memory_view)

    slots: list[PlannedCandidateSlot] = []
    task_created_at = session.created_at

    for ordinal in range(1, session.candidate_budget + 1):
        slot_index = ordinal - 1
        slot_token = v2.digest({
            "ordinal": ordinal,
            "session_content_hash": session.session_content_hash,
            "session_id": session.session_id,
        })[:12]
        slot_id = f"slot-{session.session_id[:16]}-{ordinal:02d}-{slot_token}"
        slot_content_hash = v2.digest({
            "ordinal": ordinal,
            "session_id": session.session_id,
            "slot_id": slot_id,
        })
        attempt = 1

        req = AlphaGenerationRequest.create(
            objective=session.objective,
            memory_view=memory_view,
            project_binding=session.project_binding,
            authorized_scope=AgentPermissionScope(**dict(session.authorized_scope_ref)),
            allowed_universe=session.allowed_universe,
            allowed_frequency=session.allowed_frequency,
            allowed_signal_families=session.allowed_signal_families,
            generation_policy_version=session.generation_policy_version,
            session_id=session.session_id,
            slot_id=slot_id,
            ordinal=ordinal,
            attempt=attempt,
        )
        task = create_alpha_generation_task(req, memory_view, created_at=task_created_at)

        slot = PlannedCandidateSlot(
            session_id=session.session_id,
            session_content_hash=session.session_content_hash,
            slot_index=slot_index,
            ordinal=ordinal,
            slot_id=slot_id,
            slot_content_hash=slot_content_hash,
            attempt=attempt,
            request=req,
            task=task,
            session=session,
            memory_view=memory_view,
        )
        slots.append(slot)

    return tuple(slots)


def replan_slot_attempt(
    slot: PlannedCandidateSlot,
    memory_view: ResearchMemoryView,
    *,
    attempt: int,
) -> PlannedCandidateSlot:
    """Replan a candidate slot for a subsequent retry attempt while preserving logical slot identity."""
    if not isinstance(slot, PlannedCandidateSlot):
        raise DiscoverySessionError(f"slot must be a PlannedCandidateSlot, got {type(slot).__name__}")
    if type(attempt) is not int or isinstance(attempt, bool) or attempt <= slot.attempt:
        raise DiscoverySessionError(
            f"attempt must be a strict integer strictly greater than current attempt {slot.attempt}, got {attempt}"
        )

    validate_session_memory_view(slot.session.to_dict(), memory_view)

    task_created_at = slot.session.created_at
    req = AlphaGenerationRequest.create(
        objective=slot.session.objective,
        memory_view=memory_view,
        project_binding=slot.session.project_binding,
        authorized_scope=AgentPermissionScope(**dict(slot.session.authorized_scope_ref)),
        allowed_universe=slot.session.allowed_universe,
        allowed_frequency=slot.session.allowed_frequency,
        allowed_signal_families=slot.session.allowed_signal_families,
        generation_policy_version=slot.session.generation_policy_version,
        session_id=slot.session_id,
        slot_id=slot.slot_id,
        ordinal=slot.ordinal,
        attempt=attempt,
    )
    task = create_alpha_generation_task(req, memory_view, created_at=task_created_at)

    return dataclasses.replace(
        slot,
        attempt=attempt,
        request=req,
        task=task,
        memory_view=memory_view,
    )
