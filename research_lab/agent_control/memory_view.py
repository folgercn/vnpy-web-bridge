"""Controlled Research Memory View and deterministic read adapter (#573 Milestone 4).

Strictly isolates:
raw memory != controlled view != agent prompt context

Provides read-only, bounded, deterministic, auditable, and unforgeable research memory
views for authorized agent roles under exact project bindings.
Zero LLM / MCP / provider dependency.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from research_lab.agent_control.audit import AppendOnlyAuditTrail
from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    ProjectBinding,
    _clean_for_canonical,
    _freeze_mapping,
    _unfreeze_to_dict,
    validate_project_binding,
    validate_scope_hash,
)
from research_lab.agent_control.errors import (
    ResearchMemoryCategoryError,
    ResearchMemoryLimitError,
    ResearchMemoryPermissionError,
    ResearchMemorySourceCorruptionError,
)
from research_lab.agent_control.permissions import AgentPermission
from research_lab.agent_control.roles import AgentRole, validate_role
from research_lab.alpha_discovery import hypothesis as hyp
from research_lab.alpha_discovery.research_memory import (
    ResearchMemory,
    ResearchMemoryRecord,
)
from research_lab.contracts import v2


class ResearchMemoryCategory(str, Enum):
    """Closed catalog of supported research memory query categories."""

    RECENT_REJECTS = "recent_rejects"
    PROMOTED_SUMMARIES = "promoted_summaries"
    NME_BACKLOG = "need_more_evidence_backlog"
    DUPLICATE_IDENTITIES = "duplicate_identities"
    FAILED_APPROACHES = "failed_approaches"
    RESEARCH_GAPS = "research_gaps"


ALL_CATEGORIES: frozenset[str] = frozenset(c.value for c in ResearchMemoryCategory)

ALLOWED_DECISION_TYPES: frozenset[str] = frozenset({
    "PROMOTE",
    "REJECT",
    "NEED_MORE_EVIDENCE",
    "ADMISSION_FAILED",
    "EXECUTION_CRASHED",
})

CATEGORY_ALLOWED_DECISIONS: dict[str, frozenset[str]] = {
    ResearchMemoryCategory.RECENT_REJECTS.value: frozenset({"REJECT"}),
    ResearchMemoryCategory.PROMOTED_SUMMARIES.value: frozenset({"PROMOTE"}),
    ResearchMemoryCategory.NME_BACKLOG.value: frozenset({"NEED_MORE_EVIDENCE"}),
    ResearchMemoryCategory.DUPLICATE_IDENTITIES.value: ALLOWED_DECISION_TYPES,
    ResearchMemoryCategory.FAILED_APPROACHES.value: frozenset({"REJECT", "ADMISSION_FAILED", "EXECUTION_CRASHED"}),
    ResearchMemoryCategory.RESEARCH_GAPS.value: ALLOWED_DECISION_TYPES,
}


class MemoryAccessReasonCode(str, Enum):
    """Reason codes for memory view access evaluation and audit trail."""

    MEMORY_VIEW_ALLOWED = "MEMORY_VIEW_ALLOWED"
    MEMORY_PERMISSION_DENIED = "MEMORY_PERMISSION_DENIED"
    MEMORY_CATEGORY_DENIED = "MEMORY_CATEGORY_DENIED"
    MEMORY_PROJECT_MISMATCH = "MEMORY_PROJECT_MISMATCH"
    MEMORY_LIMIT_EXCEEDED = "MEMORY_LIMIT_EXCEEDED"
    MEMORY_SOURCE_CORRUPT = "MEMORY_SOURCE_CORRUPT"


def validate_category(name: str) -> str:
    """Validate a category name against the closed catalog (fail-closed)."""
    if not isinstance(name, str):
        raise ResearchMemoryCategoryError(
            f"Category must be a string, got {type(name).__name__}",
            details={"requested_category": name},
        )
    normalized = name.strip().lower()
    if normalized not in ALL_CATEGORIES:
        raise ResearchMemoryCategoryError(
            f"Unknown research memory category '{name}' rejected under fail-closed policy",
            details={"requested_category": name, "known_categories": sorted(ALL_CATEGORIES)},
        )
    return normalized


# Default baseline category permissions per role (Milestone 4 least privilege)
DEFAULT_ROLE_ALLOWED_CATEGORIES: dict[str, frozenset[str]] = {
    AgentRole.ALPHA_GENERATOR.value: frozenset({
        ResearchMemoryCategory.RECENT_REJECTS.value,
        ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
        ResearchMemoryCategory.NME_BACKLOG.value,
        ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,
        ResearchMemoryCategory.FAILED_APPROACHES.value,
        ResearchMemoryCategory.RESEARCH_GAPS.value,
    }),
    AgentRole.RESEARCH_SYNTHESIZER.value: frozenset({
        ResearchMemoryCategory.RECENT_REJECTS.value,
        ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
        ResearchMemoryCategory.NME_BACKLOG.value,
        ResearchMemoryCategory.FAILED_APPROACHES.value,
        ResearchMemoryCategory.RESEARCH_GAPS.value,
    }),
    AgentRole.DATA_RESEARCHER.value: frozenset({
        ResearchMemoryCategory.RESEARCH_GAPS.value,
        ResearchMemoryCategory.FAILED_APPROACHES.value,
        ResearchMemoryCategory.RECENT_REJECTS.value,
    }),
    AgentRole.CODE_RESEARCHER.value: frozenset({
        ResearchMemoryCategory.FAILED_APPROACHES.value,
    }),
    AgentRole.EXTERNAL_RESEARCHER.value: frozenset({
        ResearchMemoryCategory.RESEARCH_GAPS.value,
        ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
        ResearchMemoryCategory.RECENT_REJECTS.value,
    }),
}


@dataclass(frozen=True)
class ResearchMemoryViewPolicy:
    """Immutable policy governing bounding, limits, and role access to research memory."""

    role_allowed_categories: dict[str, frozenset[str]] = field(
        default_factory=lambda: dict(DEFAULT_ROLE_ALLOWED_CATEGORIES)
    )
    max_entries_per_category: int = 10
    max_total_entries: int = 50
    max_summary_chars: int = 500
    max_chars: int = 20000
    policy_version: str = "2026-09-m4"
    enforce_source_integrity: bool = True

    def __post_init__(self) -> None:
        if self.max_entries_per_category <= 0:
            raise ValueError("max_entries_per_category must be positive")
        if self.max_total_entries <= 0:
            raise ValueError("max_total_entries must be positive")
        if self.max_summary_chars <= 0:
            raise ValueError("max_summary_chars must be positive")
        if self.max_chars <= 0:
            raise ValueError("max_chars must be positive")

    def get_allowed_categories(self, role: str) -> frozenset[str]:
        return self.role_allowed_categories.get(role, frozenset())


@dataclass(frozen=True)
class ResearchMemoryQuery:
    """Immutable, typed query contract for requesting a bounded research memory view.

    Strictly forbids raw SQL, cursor, where-clause, or arbitrary filter expressions.
    """

    role: str
    project_binding: ProjectBinding | dict[str, str]
    categories: tuple[str, ...]
    hypothesis_refs: tuple[str, ...] = ()
    hypothesis_content_hash: str | None = None
    scientific_identity_hash: str | None = None
    decision_types: tuple[str, ...] = ()
    time_window_since: str | None = None
    limit_per_category: int | None = None
    total_limit: int | None = None

    def __post_init__(self) -> None:
        validate_role(self.role)
        validate_project_binding(self.project_binding)
        if not self.categories:
            raise ResearchMemoryCategoryError("Query must request at least one memory category")
        validated_cats = []
        for cat in self.categories:
            validated_cats.append(validate_category(cat))
        object.__setattr__(self, "categories", tuple(validated_cats))
        if self.hypothesis_refs:
            object.__setattr__(self, "hypothesis_refs", tuple(self.hypothesis_refs))
        if self.decision_types:
            validated_decisions = []
            for dt in self.decision_types:
                if dt not in ALLOWED_DECISION_TYPES:
                    raise ResearchMemoryCategoryError(
                        f"Unknown decision_type '{dt}'; must be one of {sorted(ALLOWED_DECISION_TYPES)}",
                        details={"requested_decision": dt, "known_decisions": sorted(ALLOWED_DECISION_TYPES)},
                    )
                validated_decisions.append(dt)
            object.__setattr__(self, "decision_types", tuple(validated_decisions))

            # Validate compatibility between categories and decision_types (fail-closed on unsupported combinations)
            allowed_for_cats = set()
            for c in self.categories:
                allowed_for_cats.update(CATEGORY_ALLOWED_DECISIONS.get(c, ALLOWED_DECISION_TYPES))
            if not set(self.decision_types).intersection(allowed_for_cats):
                raise ResearchMemoryCategoryError(
                    f"Unsupported query combination: requested decision_types {sorted(self.decision_types)} "
                    f"cannot satisfy any requested categories {sorted(self.categories)}",
                    details={
                        "categories": sorted(self.categories),
                        "decision_types": sorted(self.decision_types),
                        "supported_decisions_for_categories": sorted(allowed_for_cats),
                    },
                )

        if self.limit_per_category is not None and self.limit_per_category <= 0:
            raise ResearchMemoryLimitError("limit_per_category must be positive if specified")
        if self.total_limit is not None and self.total_limit <= 0:
            raise ResearchMemoryLimitError("total_limit must be positive if specified")

    def to_dict(self) -> dict[str, Any]:
        return {
            "categories": list(self.categories),
            "decision_types": list(self.decision_types),
            "hypothesis_content_hash": self.hypothesis_content_hash,
            "hypothesis_refs": list(self.hypothesis_refs),
            "limit_per_category": self.limit_per_category,
            "project_binding": (
                self.project_binding.to_dict()
                if isinstance(self.project_binding, ProjectBinding)
                else dict(self.project_binding)
            ),
            "role": self.role,
            "scientific_identity_hash": self.scientific_identity_hash,
            "time_window_since": self.time_window_since,
            "total_limit": self.total_limit,
        }


def _sanitize_string(val: str) -> str:
    """Defensively sanitize strings against file paths and credentials."""
    if not isinstance(val, str):
        return str(val)
    # Redact absolute paths
    sanitized = re.sub(r"/(?:Users|home|var|tmp|private)/[^\s,;\"'\]\}]+", "[REDACTED_PATH]", val)
    # Redact potential keys, secrets, tokens
    sanitized = re.sub(r"(?i)(key|token|secret|password|credential|bearer)[\s:=]+[A-Za-z0-9_\-\.]{8,}", r"\1=[REDACTED]", sanitized)
    return sanitized


def _sanitize_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively sanitize mapping structures."""
    sanitized: dict[str, Any] = {}
    forbidden_keys = {"token", "secret", "password", "api_key", "email", "authorization", "auth"}
    for k, v in data.items():
        if k.lower() in forbidden_keys:
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, str):
            sanitized[k] = _sanitize_string(v)
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_dict(v)
        elif isinstance(v, (list, tuple)):
            sanitized[k] = [
                _sanitize_dict(x) if isinstance(x, dict)
                else _sanitize_string(x) if isinstance(x, str)
                else x
                for x in v
            ]
        else:
            sanitized[k] = v
    return sanitized


class ResearchMemoryReadAdapter:
    """Minimal domain read adapter decoupling View Builder from raw SQLite storage.

    Guarantees read-only connection mode (mode=ro and PRAGMA query_only=ON) at connection boundary.
    Yields immutable domain ResearchMemoryRecord objects without leaking SQLite connections,
    cursors, raw queries, or table schemas to the View Builder or calling Agent.
    """

    def __init__(self, source: ResearchMemory | Path | str) -> None:
        if isinstance(source, ResearchMemory):
            self._db_path = source.db_path
        elif isinstance(source, (Path, str)):
            self._db_path = Path(source).resolve()
        else:
            raise TypeError(f"Unsupported memory source type: {type(source).__name__}")

        if not self._db_path.exists():
            raise FileNotFoundError(f"Research Memory database does not exist: {self._db_path}")

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _get_readonly_connection(self) -> sqlite3.Connection:
        uri = f"file:{self._db_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON;")
        return conn

    def get_all_records(self) -> tuple[ResearchMemoryRecord, ...]:
        """Fetch all records safely using read-only domain mapping."""
        with self._get_readonly_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM research_memory_records ORDER BY rowid ASC"
            ).fetchall()
            return tuple(self._row_to_record(r) for r in rows)

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ResearchMemoryRecord:
        return ResearchMemoryRecord(
            record_id=row["record_id"],
            record_type=row["record_type"],
            hypothesis_id=row["hypothesis_id"],
            revision=row["revision"],
            content_hash=row["content_hash"],
            scientific_identity_hash=row["scientific_identity_hash"],
            semantic_hash=row["semantic_hash"],
            decision=row["decision"],
            created_at=row["created_at"],
            hypothesis_ref=json.loads(row["hypothesis_ref_json"]),
            plan_ref=json.loads(row["plan_ref_json"]) if row["plan_ref_json"] else None,
            task_refs=json.loads(row["task_refs_json"]),
            spec_refs=json.loads(row["spec_refs_json"]),
            run_refs=json.loads(row["run_refs_json"]),
            manifest_refs=json.loads(row["manifest_refs_json"]),
            evidence_refs=json.loads(row["evidence_refs_json"]),
            critic_ref=json.loads(row["critic_ref_json"]) if row["critic_ref_json"] else None,
            hypothesis_payload=json.loads(row["hypothesis_payload"]),
            plan_payload=json.loads(row["plan_payload"]) if row["plan_payload"] else None,
            critic_decision_payload=json.loads(row["critic_decision_payload"]) if row["critic_decision_payload"] else None,
            methods_applied=json.loads(row["methods_applied_json"]),
            missing_evidence=json.loads(row["missing_evidence_json"]),
            reject_reasons=json.loads(row["reject_reasons_json"]),
            promoted_reasons=json.loads(row["promoted_reasons_json"]),
            error_message=row["error_message"],
            provenance=json.loads(row["provenance_json"]),
        )


@dataclass(frozen=True)
class ResearchMemoryEntryView:
    """Controlled, bounded, and sanitized single entry in a ResearchMemoryView."""

    entry_id: str
    category: str
    hypothesis_id: str
    hypothesis_content_hash: str
    scientific_identity_hash: str
    decision: str
    summary: str
    source_refs: dict[str, Any]
    source_hashes: dict[str, str]
    evidence_refs: tuple[dict[str, str], ...]
    view_generated_from: str
    decision_time: str
    # Specific categorical fields
    reason_codes: tuple[str, ...] = ()
    strengths: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    missing_dimensions: tuple[str, ...] = ()
    suggested_evidence_types: tuple[str, ...] = ()
    failure_class: str | None = None  # "scientific" | "engineering"
    retry_condition: str | None = None
    duplicate_state: str | None = None  # "exact" | "related" | "none"
    gap_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_refs", _freeze_mapping(_sanitize_dict(self.source_refs)))
        object.__setattr__(self, "source_hashes", _freeze_mapping(self.source_hashes))
        object.__setattr__(
            self,
            "evidence_refs",
            tuple(_freeze_mapping(_sanitize_dict(e)) for e in self.evidence_refs),
        )
        object.__setattr__(self, "metadata", _freeze_mapping(_sanitize_dict(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "category": self.category,
            "decision": self.decision,
            "decision_time": self.decision_time,
            "entry_id": self.entry_id,
            "evidence_refs": _unfreeze_to_dict(self.evidence_refs),
            "hypothesis_content_hash": self.hypothesis_content_hash,
            "hypothesis_id": self.hypothesis_id,
            "metadata": _unfreeze_to_dict(self.metadata),
            "scientific_identity_hash": self.scientific_identity_hash,
            "source_hashes": _unfreeze_to_dict(self.source_hashes),
            "source_refs": _unfreeze_to_dict(self.source_refs),
            "summary": self.summary,
            "view_generated_from": self.view_generated_from,
        }
        if self.reason_codes:
            d["reason_codes"] = list(self.reason_codes)
        if self.strengths:
            d["strengths"] = list(self.strengths)
        if self.limitations:
            d["limitations"] = list(self.limitations)
        if self.missing_dimensions:
            d["missing_dimensions"] = list(self.missing_dimensions)
        if self.suggested_evidence_types:
            d["suggested_evidence_types"] = list(self.suggested_evidence_types)
        if self.failure_class:
            d["failure_class"] = self.failure_class
        if self.retry_condition:
            d["retry_condition"] = self.retry_condition
        if self.duplicate_state:
            d["duplicate_state"] = self.duplicate_state
        if self.gap_type:
            d["gap_type"] = self.gap_type
        return d

    def to_normalized_dict(self) -> dict[str, Any]:
        """Normalized representation for deterministic view content hash."""
        return _clean_for_canonical(self.to_dict())


@dataclass(frozen=True)
class ResearchMemoryView:
    """Immutable, bounded, deterministic view of research memory for an agent."""

    view_id: str
    view_content_hash: str
    role: str
    project_binding: dict[str, str]
    categories: tuple[str, ...]
    entries_by_category: dict[str, tuple[ResearchMemoryEntryView, ...]]
    total_entries: int
    policy_version: str
    generated_at: str  # Kept for provenance/audit, strictly excluded from view_id and view_content_hash
    source_refs: tuple[str, ...]
    is_truncated: bool = False
    reason_code: str = MemoryAccessReasonCode.MEMORY_VIEW_ALLOWED.value
    schema_version: str = "research_lab.memory_view.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_binding", _freeze_mapping(self.project_binding))
        frozen_entries: dict[str, tuple[ResearchMemoryEntryView, ...]] = {}
        for cat, entries in self.entries_by_category.items():
            frozen_entries[cat] = tuple(entries)
        object.__setattr__(self, "entries_by_category", MappingProxyType(frozen_entries))

    def to_dict(self) -> dict[str, Any]:
        return {
            "categories": list(self.categories),
            "entries_by_category": {
                cat: [e.to_dict() for e in entries]
                for cat, entries in self.entries_by_category.items()
            },
            "generated_at": self.generated_at,
            "is_truncated": self.is_truncated,
            "policy_version": self.policy_version,
            "project_binding": _unfreeze_to_dict(self.project_binding),
            "reason_code": self.reason_code,
            "role": self.role,
            "schema_version": self.schema_version,
            "source_refs": list(self.source_refs),
            "total_entries": self.total_entries,
            "view_content_hash": self.view_content_hash,
            "view_id": self.view_id,
        }

    def to_prompt_context(self) -> str:
        """Render bounded, clean structured markdown context for inclusion in prompt."""
        lines = [
            f"# Controlled Research Memory View [{self.view_id}]",
            f"- Role: {self.role}",
            f"- Categories: {', '.join(self.categories)}",
            f"- Total Entries: {self.total_entries}",
            f"- Content Hash: {self.view_content_hash}",
            "",
        ]
        for cat in self.categories:
            entries = self.entries_by_category.get(cat, ())
            lines.append(f"## Category: {cat} ({len(entries)} entries)")
            if not entries:
                lines.append("  (no entries)")
                continue
            for idx, e in enumerate(entries, start=1):
                lines.append(f"### {idx}. {e.hypothesis_id} [{e.decision}]")
                lines.append(f"  - Entry ID: {e.entry_id}")
                lines.append(f"  - Scientific Hash: {e.scientific_identity_hash}")
                lines.append(f"  - Summary: {e.summary}")
                if e.reason_codes:
                    lines.append(f"  - Reasons: {', '.join(e.reason_codes)}")
                if e.strengths:
                    lines.append(f"  - Strengths: {', '.join(e.strengths)}")
                if e.limitations:
                    lines.append(f"  - Limitations: {', '.join(e.limitations)}")
                if e.missing_dimensions:
                    lines.append(f"  - Missing: {', '.join(e.missing_dimensions)}")
                if e.failure_class:
                    lines.append(f"  - Failure Class: {e.failure_class}")
                if e.duplicate_state:
                    lines.append(f"  - Duplicate State: {e.duplicate_state}")
                if e.gap_type:
                    lines.append(f"  - Gap Type: {e.gap_type}")
                lines.append(f"  - Evidence Count: {len(e.evidence_refs)}")
                lines.append(f"  - Source Ref: {e.view_generated_from}")
            lines.append("")
        return "\n".join(lines)


@dataclass(frozen=True)
class MemoryViewAuditRecord:
    """Immutable audit record appended whenever a memory view is built."""

    role: str
    scope_ref: str
    project_binding: dict[str, str]
    requested_categories: tuple[str, ...]
    returned_counts: dict[str, int]
    source_refs: tuple[str, ...]
    view_id: str
    view_content_hash: str
    policy_version: str
    timestamp: str
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "project_binding": dict(self.project_binding),
            "reason_code": self.reason_code,
            "requested_categories": list(self.requested_categories),
            "returned_counts": dict(self.returned_counts),
            "role": self.role,
            "scope_ref": self.scope_ref,
            "source_refs": list(self.source_refs),
            "timestamp": self.timestamp,
            "view_content_hash": self.view_content_hash,
            "view_id": self.view_id,
        }


class MemoryViewAuditTrail:
    """In-memory append-only audit trail for memory view accesses."""

    def __init__(self) -> None:
        self._records: list[MemoryViewAuditRecord] = []

    def append(self, record: MemoryViewAuditRecord) -> None:
        self._records.append(record)

    def get_records(self) -> list[MemoryViewAuditRecord]:
        return list(self._records)

    @property
    def records(self) -> list[MemoryViewAuditRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)


def _verify_record_integrity(record: ResearchMemoryRecord) -> None:
    """Verify hashes and references of an existing ResearchMemoryRecord.

    Fails closed immediately if any corruption or tampering is detected.
    """
    # 1. Verify hypothesis content hash
    expected_hyp_hash = record.content_hash
    recomputed_hyp_hash = record.hypothesis_payload.get("hypothesis_content_hash") or v2.digest(record.hypothesis_payload)
    if expected_hyp_hash != recomputed_hyp_hash:
        raise ResearchMemorySourceCorruptionError(
            f"Record '{record.record_id}' hypothesis content hash mismatch: "
            f"expected {expected_hyp_hash}, found {recomputed_hyp_hash}",
            details={"record_id": record.record_id, "content_hash": expected_hyp_hash},
        )

    # 2. Verify scientific identity hash
    expected_sci_hash = record.scientific_identity_hash
    recomputed_sci_hash = hyp.compute_scientific_identity_hash(record.hypothesis_payload)
    if expected_sci_hash != recomputed_sci_hash:
        raise ResearchMemorySourceCorruptionError(
            f"Record '{record.record_id}' scientific identity hash mismatch: "
            f"expected {expected_sci_hash}, recomputed {recomputed_sci_hash}",
            details={"record_id": record.record_id, "scientific_identity_hash": expected_sci_hash},
        )

    # 3. Verify critic decision hash if evaluation record
    if record.critic_decision_payload is not None:
        dec_hash = record.critic_decision_payload.get("review_content_hash")
        if record.critic_ref and record.critic_ref.get("review_content_hash") != dec_hash:
            raise ResearchMemorySourceCorruptionError(
                f"Record '{record.record_id}' critic review content hash mismatch",
                details={"record_id": record.record_id},
            )


def _build_entry_summary(category: str, record: ResearchMemoryRecord, max_chars: int) -> str:
    """Deterministic template summarizer for research memory record."""
    hyp_id = record.hypothesis_id
    if category == ResearchMemoryCategory.RECENT_REJECTS.value:
        reasons = record.reject_reasons or ["unspecified_reasons"]
        summary = f"REJECT: Hypothesis '{hyp_id}' rejected by Critic. Reasons: {'; '.join(reasons)}"
    elif category == ResearchMemoryCategory.PROMOTED_SUMMARIES.value:
        strengths = record.promoted_reasons or ["screened_criteria_passed"]
        summary = (
            f"PROMOTE (Scientific screening passed; NOT tradable / production approved): "
            f"Hypothesis '{hyp_id}'. Key strengths: {'; '.join(strengths)}"
        )
    elif category == ResearchMemoryCategory.NME_BACKLOG.value:
        missing = record.missing_evidence or ["additional_evidence_needed"]
        summary = (
            f"NEED_MORE_EVIDENCE (Scientific evaluation incomplete; NOT a failure): "
            f"Hypothesis '{hyp_id}'. Pending dimensions: {'; '.join(missing)}"
        )
    elif category == ResearchMemoryCategory.DUPLICATE_IDENTITIES.value:
        summary = (
            f"DUPLICATE_IDENTITY: Hypothesis '{hyp_id}' scientific_hash='{record.scientific_identity_hash[:12]}'. "
            f"Duplicate detection provides prior context and does NOT mean unconditional execution skip."
        )
    elif category == ResearchMemoryCategory.FAILED_APPROACHES.value:
        if record.record_type in ("admission_failed", "execution_crashed") or record.decision in ("ADMISSION_FAILED", "EXECUTION_CRASHED"):
            summary = (
                f"ENGINEERING_FAILURE (Infrastructure error; NOT scientific REJECT): "
                f"Approach on '{hyp_id}' crashed: {record.error_message or 'runtime_crash'}. "
                f"Retry permissible after fixing runner environment."
            )
        else:
            reasons = record.reject_reasons or ["screening_falsified"]
            summary = (
                f"SCIENTIFIC_FAILURE: Approach on '{hyp_id}' falsified: {'; '.join(reasons)}."
            )
    elif category == ResearchMemoryCategory.RESEARCH_GAPS.value:
        if record.missing_evidence:
            summary = (
                f"RESEARCH_GAP (Unresolved NME Dimension): '{hyp_id}' is missing coverage on: "
                f"{'; '.join(record.missing_evidence)}."
            )
        else:
            summary = f"RESEARCH_GAP: Hypothesis '{hyp_id}' gap identified from historical screening coverage."
    else:
        summary = f"Research memory record for '{hyp_id}' [{record.decision}]."

    sanitized = _sanitize_string(summary)
    if len(sanitized) > max_chars:
        sanitized = sanitized[: max_chars - 3] + "..."
    return sanitized


def _create_entry_view(
    category: str,
    record: ResearchMemoryRecord,
    policy: ResearchMemoryViewPolicy,
    duplicate_state: str | None = None,
    gap_type: str | None = None,
) -> ResearchMemoryEntryView:
    """Construct an immutable ResearchMemoryEntryView from an authentic ResearchMemoryRecord."""
    summary = _build_entry_summary(category, record, policy.max_summary_chars)

    source_hashes = {
        "content_hash": record.content_hash,
        "scientific_identity_hash": record.scientific_identity_hash,
        "semantic_hash": record.semantic_hash,
    }
    if record.critic_ref and "review_content_hash" in record.critic_ref:
        source_hashes["critic_review_hash"] = record.critic_ref["review_content_hash"]

    # Entry ID depends strictly on scientific identity, source hashes, category, and record id
    entry_token = v2.digest({
        "category": category,
        "hypothesis_id": record.hypothesis_id,
        "record_id": record.record_id,
        "scientific_identity_hash": record.scientific_identity_hash,
        "source_hashes": source_hashes,
    })[:24]
    entry_id = f"rmentry-{entry_token}"

    failure_class = None
    retry_condition = None
    if category == ResearchMemoryCategory.FAILED_APPROACHES.value:
        if record.record_type in ("admission_failed", "execution_crashed") or record.decision in ("ADMISSION_FAILED", "EXECUTION_CRASHED"):
            failure_class = "engineering"
            retry_condition = "Fix runtime dependencies or input schema, then re-execute runner"
        else:
            failure_class = "scientific"
            retry_condition = "Do not re-execute unchanged hypothesis; require new falsification regime or supplemental evidence"

    # Evidence refs: strictly refs and hashes, no raw payload
    evidence_refs = tuple(
        {
            "content_hash": ev.get("content_hash", ""),
            "evidence_id": ev.get("evidence_id", ""),
            "execution_status": ev.get("execution_status", ""),
            "revision": ev.get("revision", "rev.1"),
        }
        for ev in record.evidence_refs
    )

    return ResearchMemoryEntryView(
        category=category,
        decision=record.decision,
        decision_time=record.created_at,
        duplicate_state=duplicate_state,
        entry_id=entry_id,
        evidence_refs=evidence_refs,
        failure_class=failure_class,
        gap_type=gap_type,
        hypothesis_content_hash=record.content_hash,
        hypothesis_id=record.hypothesis_id,
        limitations=tuple(record.hypothesis_payload.get("limitations", ())) if category == ResearchMemoryCategory.PROMOTED_SUMMARIES.value else (),
        metadata={"record_type": record.record_type},
        missing_dimensions=tuple(record.missing_evidence),
        reason_codes=tuple(record.reject_reasons),
        retry_condition=retry_condition,
        scientific_identity_hash=record.scientific_identity_hash,
        source_hashes=source_hashes,
        source_refs={
            "critic_ref": record.critic_ref,
            "hypothesis_ref": record.hypothesis_ref,
            "plan_ref": record.plan_ref,
            "record_id": record.record_id,
        },
        strengths=tuple(record.promoted_reasons),
        suggested_evidence_types=tuple(
            [f"supplemental_{m}" for m in record.missing_evidence]
        ) if record.missing_evidence else (),
        summary=summary,
        view_generated_from=record.record_id,
    )


def _canonical_policy_dict(policy: ResearchMemoryViewPolicy) -> dict[str, Any]:
    """Canonical serializable representation of complete view policy."""
    return {
        "enforce_source_integrity": policy.enforce_source_integrity,
        "max_chars": policy.max_chars,
        "max_entries_per_category": policy.max_entries_per_category,
        "max_summary_chars": policy.max_summary_chars,
        "max_total_entries": policy.max_total_entries,
        "policy_version": policy.policy_version,
        "role_allowed_categories": {
            role: sorted(cats)
            for role, cats in sorted(policy.role_allowed_categories.items())
        },
    }


def _canonical_query_dict(query: ResearchMemoryQuery) -> dict[str, Any]:
    """Canonical serializable representation of complete typed query contract."""
    pb = query.project_binding.to_dict() if isinstance(query.project_binding, ProjectBinding) else dict(query.project_binding)
    return {
        "categories": sorted(query.categories),
        "decision_types": sorted(query.decision_types),
        "hypothesis_content_hash": query.hypothesis_content_hash,
        "hypothesis_refs": sorted(query.hypothesis_refs),
        "limit_per_category": query.limit_per_category,
        "project_binding": _clean_for_canonical(pb),
        "role": query.role,
        "scientific_identity_hash": query.scientific_identity_hash,
        "time_window_since": query.time_window_since,
        "total_limit": query.total_limit,
    }


def _record_sort_key(r: ResearchMemoryRecord) -> tuple[float, str]:
    """Deterministic, full-precision sort key: decision_time DESC, record_id ASC."""
    try:
        clean_ts = r.created_at.replace("Z", "+00:00")
        ts = datetime.fromisoformat(clean_ts).timestamp()
        return (-1.0 * ts, r.record_id)
    except (ValueError, TypeError):
        return (0.0, r.record_id)


def build_research_memory_view(
    query: ResearchMemoryQuery,
    authorized_scope: AgentPermissionScope,
    project_binding: ProjectBinding | dict[str, str],
    memory_store: ResearchMemory | Any,
    policy: ResearchMemoryViewPolicy | None = None,
    audit_trail: MemoryViewAuditTrail | AppendOnlyAuditTrail | Any | None = None,
    current_time: str | None = None,
) -> ResearchMemoryView:
    """Build a controlled, bounded, deterministic research memory view.

    Authorization and Security Gates:
    1. Scope integrity validation (tamper detection).
    2. Permission check: scope must be authorized and contain 'read_research_memory'.
    3. ProjectBinding validation: query, scope, and requested binding must exactly match.
    4. Role validation and category least-privilege intersection.
    5. Query limit vs Policy limit validation.
    6. Source integrity validation on every read record (fails closed on corrupt hash).
    7. Strict bounded exposure and deterministic identity calculation.
    """
    active_policy = policy or ResearchMemoryViewPolicy()
    eval_time = current_time or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # 1. Scope integrity validation
    validate_scope_hash(authorized_scope.to_dict())

    # 2. Permission check
    if not authorized_scope.is_authorized:
        raise ResearchMemoryPermissionError(
            f"Authorization scope '{authorized_scope.scope_id}' is not authorized",
            details={"scope_id": authorized_scope.scope_id, "role": authorized_scope.role},
        )
    if AgentPermission.READ_RESEARCH_MEMORY.value not in authorized_scope.authorized_permissions:
        raise ResearchMemoryPermissionError(
            f"Role '{authorized_scope.role}' lacks required '{AgentPermission.READ_RESEARCH_MEMORY.value}' permission",
            details={
                "authorized_permissions": list(authorized_scope.authorized_permissions),
                "required_permission": AgentPermission.READ_RESEARCH_MEMORY.value,
                "role": authorized_scope.role,
            },
        )

    # 3. ProjectBinding validation (fail-closed on cross-project crossover)
    expected_binding = validate_project_binding(project_binding)
    validate_project_binding(query.project_binding, expected_binding=expected_binding)
    validate_project_binding(authorized_scope.project_binding, expected_binding=expected_binding)

    # 4. Role match & Least-privilege Category intersection
    if query.role != authorized_scope.role:
        raise ResearchMemoryPermissionError(
            f"Query role '{query.role}' does not match authorized scope role '{authorized_scope.role}'",
            details={"query_role": query.role, "scope_role": authorized_scope.role},
        )

    role_allowed = active_policy.get_allowed_categories(query.role)
    for req_cat in query.categories:
        if req_cat not in role_allowed:
            raise ResearchMemoryCategoryError(
                f"Category '{req_cat}' is not permitted for role '{query.role}' under policy",
                details={
                    "allowed_categories": sorted(role_allowed),
                    "requested_category": req_cat,
                    "role": query.role,
                },
            )

    effective_categories = tuple(sorted(set(query.categories)))

    # 5. Limit checking
    eff_per_category_limit = active_policy.max_entries_per_category
    if query.limit_per_category is not None:
        if query.limit_per_category > active_policy.max_entries_per_category:
            raise ResearchMemoryLimitError(
                f"Requested limit_per_category ({query.limit_per_category}) exceeds policy maximum ({active_policy.max_entries_per_category})",
                details={
                    "policy_max": active_policy.max_entries_per_category,
                    "requested": query.limit_per_category,
                },
            )
        eff_per_category_limit = query.limit_per_category

    eff_total_limit = active_policy.max_total_entries
    if query.total_limit is not None:
        if query.total_limit > active_policy.max_total_entries:
            raise ResearchMemoryLimitError(
                f"Requested total_limit ({query.total_limit}) exceeds policy maximum ({active_policy.max_total_entries})",
                details={
                    "policy_max": active_policy.max_total_entries,
                    "requested": query.total_limit,
                },
            )
        eff_total_limit = query.total_limit

    # 6. Read from underlying memory store safely via Read Adapter / domain get_all_records API
    # View Builder strictly avoids raw SQLite connections, cursors, raw queries, or internal schemas
    adapter_records: tuple[ResearchMemoryRecord, ...] | list[ResearchMemoryRecord]
    if hasattr(memory_store, "get_all_records"):
        adapter_records = memory_store.get_all_records()
    elif isinstance(memory_store, (Path, str, ResearchMemory)):
        adapter = ResearchMemoryReadAdapter(memory_store)
        adapter_records = adapter.get_all_records()
    else:
        raise TypeError(f"Unsupported memory_store type for memory view: {type(memory_store).__name__}")

    all_raw_records: list[ResearchMemoryRecord] = []
    for rec in adapter_records:
        if active_policy.enforce_source_integrity:
            _verify_record_integrity(rec)
        all_raw_records.append(rec)

    # Apply typed query deterministic filters (fail-closed)
    target_hypo_refs = set(query.hypothesis_refs) if query.hypothesis_refs else None
    target_decisions = set(query.decision_types) if query.decision_types else None

    filtered_records: list[ResearchMemoryRecord] = []
    for r in all_raw_records:
        # Time window filter
        if query.time_window_since and r.created_at < query.time_window_since:
            continue
        # Hypothesis refs filter
        if target_hypo_refs is not None and r.hypothesis_id not in target_hypo_refs:
            continue
        # Decision types filter
        if target_decisions is not None and r.decision not in target_decisions:
            continue
        # Hypothesis content hash / Scientific identity hash filter
        if query.hypothesis_content_hash and query.scientific_identity_hash:
            if r.content_hash != query.hypothesis_content_hash and r.scientific_identity_hash != query.scientific_identity_hash:
                continue
        elif query.hypothesis_content_hash and r.content_hash != query.hypothesis_content_hash or query.scientific_identity_hash and r.scientific_identity_hash != query.scientific_identity_hash:
            continue

        filtered_records.append(r)

    # Filter/group by category
    entries_by_category: dict[str, list[ResearchMemoryEntryView]] = {
        cat: [] for cat in effective_categories
    }

    # 7. Deterministic categorical extraction
    # 7a. RECENT_REJECTS
    if ResearchMemoryCategory.RECENT_REJECTS.value in entries_by_category:
        candidates = [r for r in filtered_records if r.decision == "REJECT"]
        # Stable sort: decision_time DESC, record_id ASC
        candidates.sort(key=_record_sort_key)
        for rec in candidates[:eff_per_category_limit]:
            entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value].append(
                _create_entry_view(ResearchMemoryCategory.RECENT_REJECTS.value, rec, active_policy)
            )

    # 7b. PROMOTED_SUMMARIES
    if ResearchMemoryCategory.PROMOTED_SUMMARIES.value in entries_by_category:
        candidates = [r for r in filtered_records if r.decision == "PROMOTE"]
        candidates.sort(key=_record_sort_key)
        for rec in candidates[:eff_per_category_limit]:
            entries_by_category[ResearchMemoryCategory.PROMOTED_SUMMARIES.value].append(
                _create_entry_view(ResearchMemoryCategory.PROMOTED_SUMMARIES.value, rec, active_policy)
            )

    # 7c. NME_BACKLOG
    if ResearchMemoryCategory.NME_BACKLOG.value in entries_by_category:
        candidates = [r for r in filtered_records if r.decision == "NEED_MORE_EVIDENCE"]
        candidates.sort(key=_record_sort_key)
        for rec in candidates[:eff_per_category_limit]:
            entries_by_category[ResearchMemoryCategory.NME_BACKLOG.value].append(
                _create_entry_view(ResearchMemoryCategory.NME_BACKLOG.value, rec, active_policy)
            )

    # 7d. DUPLICATE_IDENTITIES
    if ResearchMemoryCategory.DUPLICATE_IDENTITIES.value in entries_by_category:
        # Check if query provided exact content hash or scientific hash
        target_content_hash = query.hypothesis_content_hash
        target_sci_hash = query.scientific_identity_hash
        dup_candidates: list[tuple[ResearchMemoryRecord, str]] = []

        for rec in filtered_records:
            dup_state = "none"
            if target_content_hash and rec.content_hash == target_content_hash:
                dup_state = "exact"
            elif target_sci_hash and rec.scientific_identity_hash == target_sci_hash:
                dup_state = "related"
            elif not target_content_hash and not target_sci_hash:
                # General duplicate lookup: flag if multiple records share this scientific identity
                matching_sci = [r for r in filtered_records if r.scientific_identity_hash == rec.scientific_identity_hash]
                if len(matching_sci) > 1:
                    dup_state = "related"

            if dup_state in ("exact", "related"):
                dup_candidates.append((rec, dup_state))

        # Stable sort: decision_time DESC, record_id ASC (P1 fix: latest duplicates prioritized)
        dup_candidates.sort(key=lambda item: _record_sort_key(item[0]))
        for rec, dup_state in dup_candidates[:eff_per_category_limit]:
            entries_by_category[ResearchMemoryCategory.DUPLICATE_IDENTITIES.value].append(
                _create_entry_view(
                    ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,
                    rec,
                    active_policy,
                    duplicate_state=dup_state,
                )
            )

    # 7e. FAILED_APPROACHES
    if ResearchMemoryCategory.FAILED_APPROACHES.value in entries_by_category:
        # Both engineering failures and scientific falsifications
        candidates = [
            r for r in filtered_records
            if r.decision in ("REJECT", "ADMISSION_FAILED", "EXECUTION_CRASHED")
            or r.record_type in ("admission_failed", "execution_crashed")
        ]
        candidates.sort(key=_record_sort_key)
        for rec in candidates[:eff_per_category_limit]:
            entries_by_category[ResearchMemoryCategory.FAILED_APPROACHES.value].append(
                _create_entry_view(ResearchMemoryCategory.FAILED_APPROACHES.value, rec, active_policy)
            )

    # 7f. RESEARCH_GAPS
    if ResearchMemoryCategory.RESEARCH_GAPS.value in entries_by_category:
        # Derive gaps purely from structured facts: unresolved NME or unexecuted dimensions
        # NEVER invoke LLM to fabricate gaps
        candidates = [r for r in filtered_records if r.missing_evidence or r.decision == "NEED_MORE_EVIDENCE"]
        candidates.sort(key=_record_sort_key)
        for rec in candidates[:eff_per_category_limit]:
            gap_type = "unresolved_nme" if rec.decision == "NEED_MORE_EVIDENCE" else "missing_coverage"
            entries_by_category[ResearchMemoryCategory.RESEARCH_GAPS.value].append(
                _create_entry_view(
                    ResearchMemoryCategory.RESEARCH_GAPS.value,
                    rec,
                    active_policy,
                    gap_type=gap_type,
                )
            )

    # 8. Total limit and total character bound enforcement
    initial_total_available = sum(len(entries) for entries in entries_by_category.values())
    all_selected_entries: list[ResearchMemoryEntryView] = []
    final_entries_by_cat: dict[str, tuple[ResearchMemoryEntryView, ...]] = {}
    total_count = 0
    total_chars = 0
    is_truncated = False

    for cat in effective_categories:
        cat_entries = entries_by_category.get(cat, [])
        selected_for_cat: list[ResearchMemoryEntryView] = []
        for entry in cat_entries:
            if total_count >= eff_total_limit:
                is_truncated = True
                break
            entry_chars = len(entry.summary)
            if total_chars + entry_chars > active_policy.max_chars:
                is_truncated = True
                break
            selected_for_cat.append(entry)
            all_selected_entries.append(entry)
            total_count += 1
            total_chars += entry_chars
        final_entries_by_cat[cat] = tuple(selected_for_cat)
        if total_count >= eff_total_limit or total_chars >= active_policy.max_chars or is_truncated:
            for rem_cat in effective_categories:
                if rem_cat not in final_entries_by_cat:
                    final_entries_by_cat[rem_cat] = ()
            break

    if total_count < initial_total_available:
        is_truncated = True

    # 9. Source references collection (immutable and deduplicated)
    source_refs_set: set[str] = set()
    for e in all_selected_entries:
        source_refs_set.add(e.view_generated_from)
    sorted_source_refs = tuple(sorted(source_refs_set))

    # 10. Deterministic View Content Hash & View ID Calculation
    # Binds full typed query contract, canonical policy payload, entries, and source refs.
    # generated_at is strictly EXCLUDED from identity.
    canonical_policy = _canonical_policy_dict(active_policy)
    canonical_query = _canonical_query_dict(query)

    core_view_payload = {
        "categories": list(effective_categories),
        "entries": [e.to_normalized_dict() for e in all_selected_entries],
        "policy": canonical_policy,
        "policy_version": active_policy.policy_version,
        "project_binding": expected_binding.to_dict(),
        "query": canonical_query,
        "role": query.role,
        "source_refs": list(sorted_source_refs),
    }
    view_content_hash = v2.digest(core_view_payload)
    view_token = v2.digest({
        "categories": list(effective_categories),
        "policy": canonical_policy,
        "policy_version": active_policy.policy_version,
        "project_binding": expected_binding.to_dict(),
        "query": canonical_query,
        "role": query.role,
        "view_content_hash": view_content_hash,
    })[:32]
    view_id = f"memview-{view_token}"

    view = ResearchMemoryView(
        categories=effective_categories,
        entries_by_category=final_entries_by_cat,
        generated_at=eval_time,
        is_truncated=is_truncated,
        policy_version=active_policy.policy_version,
        project_binding=expected_binding.to_dict(),
        reason_code=MemoryAccessReasonCode.MEMORY_VIEW_ALLOWED.value,
        role=query.role,
        schema_version="research_lab.memory_view.v1",
        source_refs=sorted_source_refs,
        total_entries=total_count,
        view_content_hash=view_content_hash,
        view_id=view_id,
    )

    # 11. Append audit record
    audit_rec = MemoryViewAuditRecord(
        policy_version=active_policy.policy_version,
        project_binding=expected_binding.to_dict(),
        reason_code=MemoryAccessReasonCode.MEMORY_VIEW_ALLOWED.value,
        requested_categories=tuple(query.categories),
        returned_counts={cat: len(entries) for cat, entries in final_entries_by_cat.items()},
        role=query.role,
        scope_ref=f"{authorized_scope.scope_id}@{authorized_scope.scope_content_hash}",
        source_refs=sorted_source_refs,
        timestamp=eval_time,
        view_content_hash=view_content_hash,
        view_id=view_id,
    )
    if audit_trail is not None:
        if isinstance(audit_trail, MemoryViewAuditTrail):
            audit_trail.append(audit_rec)
        elif hasattr(audit_trail, "record"):
            audit_trail.record(
                action="build_research_memory_view",
                role=query.role,
                scope_ref=audit_rec.scope_ref,
                task_ref=None,
                route_ref=None,
                project_binding=expected_binding,
                details=audit_rec.to_dict(),
                current_time=eval_time,
            )
        elif hasattr(audit_trail, "append") and not hasattr(audit_trail, "verify_all"):
            audit_trail.append(audit_rec)

    return view
