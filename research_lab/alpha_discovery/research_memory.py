"""Append-only Research Memory for Alpha Discovery MVP (#566, #562).

Maintains an immutable, append-only record of studied hypotheses, experiment runs,
evidences, screening plans, and Critic evaluation decisions.
Reuses existing ResultStore SQLite database, preserves honest failure records,
and proves that deleting temporary execution output retains the complete resolvable
research chain: Task -> Spec -> Run -> Manifest -> Evidence -> Review -> Input.
Strictly enforces deterministic object identities (zero random UUIDs),
separates duplicate detection from execution skip decisions,
and supports dynamic NEED_MORE_EVIDENCE supplemental evidence resolution.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from research_lab.alpha_discovery import hypothesis as hyp
from research_lab.alpha_discovery.critic_gate import CriticDecision
from research_lab.alpha_discovery.screening_plan import ScreeningPlan
from research_lab.contracts import v2
from research_lab.database import ResultStore


@dataclass(frozen=True)
class ResearchMemoryRecord:
    """Immutable, append-only record of an evaluated hypothesis and its complete research chain."""

    record_id: str
    record_type: str  # "evaluation", "admission_failed", "execution_crashed"
    hypothesis_id: str
    revision: str
    content_hash: str
    scientific_identity_hash: str
    semantic_hash: str
    decision: str  # "PROMOTE", "REJECT", "NEED_MORE_EVIDENCE", "ADMISSION_FAILED", "EXECUTION_CRASHED"
    created_at: str

    # Reference dictionaries
    hypothesis_ref: dict[str, str]
    plan_ref: dict[str, str] | None
    task_refs: list[dict[str, str]]
    spec_refs: list[dict[str, str]]
    run_refs: list[dict[str, str]]
    manifest_refs: list[dict[str, str]]
    evidence_refs: list[dict[str, str]]
    critic_ref: dict[str, str] | None

    # Stored payloads
    hypothesis_payload: dict[str, Any]
    plan_payload: dict[str, Any] | None
    critic_decision_payload: dict[str, Any] | None

    # Diagnostic / coverage metadata
    methods_applied: list[str]
    missing_evidence: list[str]
    reject_reasons: list[str]
    promoted_reasons: list[str]
    error_message: str | None
    provenance: dict[str, Any]


class ResearchMemory:
    """Append-only research memory persisting exploration records in SQLite."""

    def __init__(self, db_path_or_store: Path | str | ResultStore) -> None:
        if isinstance(db_path_or_store, ResultStore):
            self.result_store: ResultStore | None = db_path_or_store
            self.db_path = Path(db_path_or_store.config.database_path).resolve()
        else:
            self.result_store = None
            self.db_path = Path(db_path_or_store).resolve()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS research_memory_records (
                    record_id TEXT PRIMARY KEY,
                    record_type TEXT NOT NULL,
                    hypothesis_id TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    scientific_identity_hash TEXT NOT NULL,
                    semantic_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    hypothesis_ref_json TEXT NOT NULL,
                    plan_ref_json TEXT,
                    task_refs_json TEXT NOT NULL,
                    spec_refs_json TEXT NOT NULL,
                    run_refs_json TEXT NOT NULL,
                    manifest_refs_json TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    critic_ref_json TEXT,
                    hypothesis_payload TEXT NOT NULL,
                    plan_payload TEXT,
                    critic_decision_payload TEXT,
                    methods_applied_json TEXT NOT NULL,
                    missing_evidence_json TEXT NOT NULL,
                    reject_reasons_json TEXT NOT NULL,
                    promoted_reasons_json TEXT NOT NULL,
                    error_message TEXT,
                    provenance_json TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rm_hyp_id ON research_memory_records(hypothesis_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rm_content_hash ON research_memory_records(content_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rm_scientific_hash ON research_memory_records(scientific_identity_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rm_decision ON research_memory_records(decision)")
            conn.commit()

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

    def append_evaluation_record(
        self,
        *,
        hypothesis: dict[str, Any] | hyp.AlphaHypothesis,
        plan: ScreeningPlan | dict[str, Any],
        task_records: list[dict[str, Any]],
        spec_records: list[dict[str, Any]],
        run_records: list[dict[str, Any]],
        manifest_records: list[dict[str, Any]],
        evidence_records: list[dict[str, Any]],
        critic_decision: CriticDecision | dict[str, Any],
        provenance: dict[str, Any] | None = None,
    ) -> ResearchMemoryRecord:
        """Append a completed evaluation research chain to append-only memory."""
        hyp_dict = (
            hypothesis.model_dump(exclude_none=True)
            if isinstance(hypothesis, hyp.AlphaHypothesis)
            else dict(hypothesis)
        )
        plan_dict = (
            plan.model_dump(exclude_none=True)
            if isinstance(plan, ScreeningPlan)
            else dict(plan)
        )
        dec_dict = (
            critic_decision.model_dump(exclude_none=True)
            if isinstance(critic_decision, CriticDecision)
            else dict(critic_decision)
        )

        hyp_id = hyp_dict["hypothesis_id"]
        hyp_rev = hyp_dict["revision"]
        hyp_hash = hyp_dict["hypothesis_content_hash"]
        scientific_hash = hyp.compute_scientific_identity_hash(hyp_dict)
        sem_hash = hyp.compute_semantic_hash(hyp_dict)

        plan_id = plan_dict["plan_id"]
        plan_hash = plan_dict["plan_content_hash"]

        # Extract refs
        hyp_ref = {
            "hypothesis_id": hyp_id,
            "revision": hyp_rev,
            "content_hash": hyp_hash,
        }
        plan_ref = {
            "plan_id": plan_id,
            "content_hash": plan_hash,
        }

        task_refs = [
            {"task_id": t["task_id"], "revision": t.get("revision", "rev.1"), "content_hash": t["task_content_hash"]}
            for t in task_records
        ]
        spec_refs = [
            {"spec_id": s["spec_id"], "revision": s.get("revision", "rev.1"), "content_hash": s["spec_content_hash"]}
            for s in spec_records
        ]
        run_refs = [
            {"run_id": r["run_id"], "content_hash": r["run_content_hash"], "run_status": r["run_status"]}
            for r in run_records
        ]
        manifest_refs = [
            {"manifest_id": m["manifest_id"], "revision": m.get("revision", "rev.1"), "content_hash": m["manifest_content_hash"]}
            for m in manifest_records
        ]
        evidence_refs = [
            {
                "evidence_id": e["evidence_id"],
                "revision": e.get("revision", "rev.1"),
                "content_hash": e["evidence_content_hash"],
                "execution_status": e.get("execution_status") or e.get("run_status_snapshot", ""),
            }
            for e in evidence_records
        ]
        critic_ref = {
            "decision_id": dec_dict["decision_id"],
            "review_content_hash": dec_dict["review_content_hash"],
        }

        methods_applied = sorted(
            {m.get("method", "") for m in plan_dict.get("methods", []) if m.get("method")}
        )

        created_at = dec_dict.get("criteria", {}).get("evaluated_at") or hyp_dict.get("provenance", {}).get("created_at") or "2026-09-20T00:00:00.000000Z"
        prov = provenance or {"component": "research_lab.research_memory", "action": "evaluation"}

        # P1-D: Deterministic record identity based on scientific identity, plan token, and count
        existing = self.find_by_scientific_identity(scientific_hash)
        attempt_idx = len(existing) + 1
        record_token = v2.digest({
            "scientific_hash": scientific_hash,
            "plan_hash": plan_hash,
            "critic_hash": dec_dict["review_content_hash"],
            "attempt": attempt_idx,
        })[:12]
        record_id = f"rmrec-{hyp_id}-{hyp_rev}-{attempt_idx}-{record_token}"

        record = ResearchMemoryRecord(
            record_id=record_id,
            record_type="evaluation",
            hypothesis_id=hyp_id,
            revision=hyp_rev,
            content_hash=hyp_hash,
            scientific_identity_hash=scientific_hash,
            semantic_hash=sem_hash,
            decision=dec_dict["decision"],
            created_at=created_at,
            hypothesis_ref=hyp_ref,
            plan_ref=plan_ref,
            task_refs=task_refs,
            spec_refs=spec_refs,
            run_refs=run_refs,
            manifest_refs=manifest_refs,
            evidence_refs=evidence_refs,
            critic_ref=critic_ref,
            hypothesis_payload=hyp_dict,
            plan_payload=plan_dict,
            critic_decision_payload=dec_dict,
            methods_applied=methods_applied,
            missing_evidence=dec_dict.get("missing_evidence", []),
            reject_reasons=dec_dict.get("reject_reasons", []),
            promoted_reasons=dec_dict.get("promoted_reasons", []),
            error_message=None,
            provenance=prov,
        )

        self._insert_record(record)
        return record

    def append_admission_failed_record(
        self,
        *,
        raw_hypothesis: dict[str, Any],
        error_message: str,
        provenance: dict[str, Any] | None = None,
    ) -> ResearchMemoryRecord:
        """Append an honest admission failure without fabricating Protocol v2 objects (Section 14)."""
        hyp_id = str(raw_hypothesis.get("hypothesis_id", "hypo-unknown"))
        hyp_rev = str(raw_hypothesis.get("revision", "rev.unknown"))
        hyp_hash = str(raw_hypothesis.get("hypothesis_content_hash", v2.digest(raw_hypothesis)))
        scientific_hash = str(raw_hypothesis.get("scientific_identity_hash", v2.digest({"raw": raw_hypothesis})))
        sem_hash = str(raw_hypothesis.get("semantic_hash", "none"))

        existing = self.find_by_hypothesis_id(hyp_id)
        attempt_idx = len(existing) + 1
        record_id = f"rmrec-fail-admit-{hyp_id}-{attempt_idx}-{v2.sha(error_message.encode())[:8]}"

        record = ResearchMemoryRecord(
            record_id=record_id,
            record_type="admission_failed",
            hypothesis_id=hyp_id,
            revision=hyp_rev,
            content_hash=hyp_hash,
            scientific_identity_hash=scientific_hash,
            semantic_hash=sem_hash,
            decision="ADMISSION_FAILED",
            created_at="2026-09-20T00:00:00.000000Z",
            hypothesis_ref={"hypothesis_id": hyp_id, "revision": hyp_rev, "content_hash": hyp_hash},
            plan_ref=None,
            task_refs=[],
            spec_refs=[],
            run_refs=[],
            manifest_refs=[],
            evidence_refs=[],
            critic_ref=None,
            hypothesis_payload=raw_hypothesis,
            plan_payload=None,
            critic_decision_payload=None,
            methods_applied=[],
            missing_evidence=[],
            reject_reasons=[],
            promoted_reasons=[],
            error_message=error_message,
            provenance=provenance or {"component": "research_lab.research_memory", "action": "admission_failed"},
        )
        self._insert_record(record)
        return record

    def append_execution_crashed_record(
        self,
        *,
        hypothesis: dict[str, Any] | hyp.AlphaHypothesis,
        plan: ScreeningPlan | dict[str, Any] | None,
        error_message: str,
        provenance: dict[str, Any] | None = None,
    ) -> ResearchMemoryRecord:
        """Append pre-admission runner crash without fabricating completed/failed Run (Section 14)."""
        hyp_dict = (
            hypothesis.model_dump(exclude_none=True)
            if isinstance(hypothesis, hyp.AlphaHypothesis)
            else dict(hypothesis)
        )
        hyp_id = hyp_dict["hypothesis_id"]
        hyp_rev = hyp_dict["revision"]
        hyp_hash = hyp_dict["hypothesis_content_hash"]
        scientific_hash = hyp.compute_scientific_identity_hash(hyp_dict)
        sem_hash = hyp.compute_semantic_hash(hyp_dict)

        plan_dict = plan.model_dump(exclude_none=True) if isinstance(plan, ScreeningPlan) else plan
        plan_ref = {"plan_id": plan_dict["plan_id"], "content_hash": plan_dict["plan_content_hash"]} if plan_dict else None

        existing = self.find_by_scientific_identity(scientific_hash)
        attempt_idx = len(existing) + 1
        record_id = f"rmrec-crash-{hyp_id}-{attempt_idx}-{v2.sha(error_message.encode())[:8]}"

        record = ResearchMemoryRecord(
            record_id=record_id,
            record_type="execution_crashed",
            hypothesis_id=hyp_id,
            revision=hyp_rev,
            content_hash=hyp_hash,
            scientific_identity_hash=scientific_hash,
            semantic_hash=sem_hash,
            decision="EXECUTION_CRASHED",
            created_at="2026-09-20T00:00:00.000000Z",
            hypothesis_ref={"hypothesis_id": hyp_id, "revision": hyp_rev, "content_hash": hyp_hash},
            plan_ref=plan_ref,
            task_refs=[],
            spec_refs=[],
            run_refs=[],
            manifest_refs=[],
            evidence_refs=[],
            critic_ref=None,
            hypothesis_payload=hyp_dict,
            plan_payload=plan_dict,
            critic_decision_payload=None,
            methods_applied=[],
            missing_evidence=["execution_crashed"],
            reject_reasons=[],
            promoted_reasons=[],
            error_message=error_message,
            provenance=provenance or {"component": "research_lab.research_memory", "action": "execution_crashed"},
        )
        self._insert_record(record)
        return record

    def _insert_record(self, record: ResearchMemoryRecord) -> None:
        """Strict append-only insert into research_memory_records."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO research_memory_records (
                    record_id, record_type, hypothesis_id, revision,
                    content_hash, scientific_identity_hash, semantic_hash,
                    decision, created_at, hypothesis_ref_json, plan_ref_json,
                    task_refs_json, spec_refs_json, run_refs_json,
                    manifest_refs_json, evidence_refs_json, critic_ref_json,
                    hypothesis_payload, plan_payload, critic_decision_payload,
                    methods_applied_json, missing_evidence_json,
                    reject_reasons_json, promoted_reasons_json,
                    error_message, provenance_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.record_id,
                    record.record_type,
                    record.hypothesis_id,
                    record.revision,
                    record.content_hash,
                    record.scientific_identity_hash,
                    record.semantic_hash,
                    record.decision,
                    record.created_at,
                    json.dumps(record.hypothesis_ref),
                    json.dumps(record.plan_ref) if record.plan_ref else None,
                    json.dumps(record.task_refs),
                    json.dumps(record.spec_refs),
                    json.dumps(record.run_refs),
                    json.dumps(record.manifest_refs),
                    json.dumps(record.evidence_refs),
                    json.dumps(record.critic_ref) if record.critic_ref else None,
                    json.dumps(record.hypothesis_payload),
                    json.dumps(record.plan_payload) if record.plan_payload else None,
                    json.dumps(record.critic_decision_payload) if record.critic_decision_payload else None,
                    json.dumps(record.methods_applied),
                    json.dumps(record.missing_evidence),
                    json.dumps(record.reject_reasons),
                    json.dumps(record.promoted_reasons),
                    record.error_message,
                    json.dumps(record.provenance),
                ),
            )
            conn.commit()

    # Query APIs
    def get_all_records(self) -> list[ResearchMemoryRecord]:
        """Domain read-only API returning all records via strict mode=ro connection."""
        uri = f"file:{self.db_path.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON;")
            rows = conn.execute(
                "SELECT * FROM research_memory_records ORDER BY rowid ASC"
            ).fetchall()
            return [self._row_to_record(r) for r in rows]

    def as_readonly_reader(self) -> ReadOnlyResearchMemoryReader:
        """Expose a dedicated read-only domain reader bound to this store."""
        return ReadOnlyResearchMemoryReader(self.db_path)

    @classmethod
    def open_readonly(cls, db_path: Path | str) -> ReadOnlyResearchMemoryReader:
        """Open an existing database file strictly as a read-only reader without schema mutation."""
        return ReadOnlyResearchMemoryReader(db_path)

    def find_by_hypothesis_id(self, hypothesis_id: str) -> list[ResearchMemoryRecord]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM research_memory_records WHERE hypothesis_id = ? ORDER BY rowid",
                (hypothesis_id,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def find_by_scientific_identity(self, scientific_identity_hash: str) -> list[ResearchMemoryRecord]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM research_memory_records WHERE scientific_identity_hash = ? ORDER BY rowid",
                (scientific_identity_hash,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def get_latest_record(self, scientific_identity_hash: str) -> ResearchMemoryRecord | None:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM research_memory_records WHERE scientific_identity_hash = ? ORDER BY rowid DESC LIMIT 1",
                (scientific_identity_hash,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def is_duplicate_hypothesis(self, hypothesis: dict[str, Any] | hyp.AlphaHypothesis) -> bool:
        """Determine if this hypothesis has already been evaluated scientifically (P1-C duplicate detection)."""
        hyp_dict = (
            hypothesis.model_dump(exclude_none=True)
            if isinstance(hypothesis, hyp.AlphaHypothesis)
            else dict(hypothesis)
        )
        sci_hash = hyp.compute_scientific_identity_hash(hyp_dict)
        history = self.find_by_scientific_identity(sci_hash)
        return len(history) > 0

    def should_execute(
        self,
        plan: ScreeningPlan | dict[str, Any],
        history: list[ResearchMemoryRecord] | None = None,
    ) -> tuple[bool, str]:
        """Determine whether screening plan should execute based on evidence coverage (P1-C execution skip).

        Rules (Section 3 P1-C & Section 17):
        - Prior PROMOTE + exact same plan/evidence coverage => skip
        - Prior terminal REJECT + exact same hypothesis/evidence plan => skip
        - Prior NEED_MORE_EVIDENCE + current plan produces NEW evidence => MUST execute
        - Prior NEED_MORE_EVIDENCE + exact same plan and zero new methods => skip
        - Revision change with new methods/dataset => MUST execute
        """
        plan_dict = plan.model_dump(exclude_none=True) if isinstance(plan, ScreeningPlan) else dict(plan)
        sci_hash = plan_dict.get("scientific_identity_hash")
        if not sci_hash:
            return True, "no_scientific_identity_hash_in_plan"

        records = history if history is not None else self.find_by_scientific_identity(sci_hash)
        if not records:
            return True, "no_prior_research_history"

        latest = records[-1]
        prior_decision = latest.decision

        # Aggregate all methods previously covered by successful evidence in this scientific line
        all_covered_methods: set[str] = set()
        for rec in records:
            if rec.decision in ("PROMOTE", "REJECT", "NEED_MORE_EVIDENCE"):
                all_covered_methods.update(rec.methods_applied)

        plan_methods = {
            m.get("method") for m in plan_dict.get("methods", [])
            if m.get("method") and m.get("status") != "UNSUPPORTED"
        }

        # Check for any new methods in current plan that are not yet covered
        new_methods = plan_methods - all_covered_methods

        if prior_decision == "NEED_MORE_EVIDENCE":
            if new_methods:
                return True, f"need_more_evidence_with_new_methods:{sorted(new_methods)}"
            else:
                return False, "skip_need_more_evidence_exact_same_coverage"

        if prior_decision == "PROMOTE":
            if new_methods:
                return True, f"promote_further_investigation_new_methods:{sorted(new_methods)}"
            else:
                return False, "skip_already_promoted_same_coverage"

        if prior_decision == "REJECT":
            if new_methods:
                return True, f"rerun_falsified_hypothesis_with_supplemental_evidence:{sorted(new_methods)}"
            else:
                return False, "skip_terminal_reject_same_coverage"

        return True, f"execute_unhandled_prior_state:{prior_decision}"
class ReadOnlyResearchMemoryReader:
    """Strict read-only domain reader bound to an existing Research Memory SQLite database.

    Guarantees SQLite connection mode is mode=ro and PRAGMA query_only=ON at the connection boundary.
    Does not create parent directories, does not initialize SQLite schema or tables, and strictly
    avoids read-write connection fallback. Yields only immutable domain ResearchMemoryRecord objects.
    """

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path).resolve()
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
        """Fetch all research memory records using strict read-only domain mapping."""
        with self._get_readonly_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM research_memory_records ORDER BY rowid ASC"
            ).fetchall()
            return tuple(ResearchMemory._row_to_record(r) for r in rows)
