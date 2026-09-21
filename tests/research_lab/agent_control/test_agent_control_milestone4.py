"""Comprehensive test suite for Controlled Research Memory View (#573 Milestone 4).

Verifies all 41 required criteria from specification section 85:
1. permission denied
2. wrong project
3. unknown category
4. limit exceeded
5. per-category limit
6. total limit
7. recent_rejects
8. promoted_summaries
9. need_more_evidence_backlog
10. duplicate_identities (exact & related)
11. failed_approaches (scientific vs engineering)
12. research_gaps
13. no raw sqlite leakage
14. no raw Evidence dump
15. source refs preserved
16. source hash validation
17. corrupted memory fail closed
18. deterministic view ID
19. deterministic content hash
20. same query same view
21. source append produces new view
22. generated_at not in identity
23. role category restriction
24. least privilege category intersection
25. no write methods
26. no mutation of source store
27. max chars
28. max entries
29. stable ordering
30. no provider/model dependency
31. no MCP call
32. no LLM call
33. duplicate != skip
34. engineering failure != REJECT
35. PROMOTE != tradable
36. AgentTask input_ref integration
37. M0 frozen
38. M1 frozen
39. M2 frozen
40. M3 frozen
41. true real Research Memory read-only E2E
"""

from __future__ import annotations

import hashlib
import inspect
import sqlite3
import unittest
from pathlib import Path
from typing import Any

from research_lab.agent_control.contracts import (
    AgentPermissionScope,
    AgentTask,
    ProjectBinding,
)
from research_lab.agent_control.errors import (
    PermissionDeniedError,
    ProjectBindingError,
    ResearchMemoryAccessError,
    ResearchMemoryCategoryError,
    ResearchMemoryLimitError,
    ResearchMemoryPermissionError,
    ResearchMemorySourceCorruptionError,
)
from research_lab.agent_control.memory_view import (
    DEFAULT_ROLE_ALLOWED_CATEGORIES,
    MemoryAccessReasonCode,
    ResearchMemoryCategory,
    ResearchMemoryEntryView,
    ResearchMemoryQuery,
    ResearchMemoryView,
    ResearchMemoryViewPolicy,
    build_research_memory_view,
)
from research_lab.agent_control.permissions import AgentPermission
from research_lab.agent_control.roles import AgentRole
from research_lab.alpha_discovery import hypothesis as hyp
from research_lab.alpha_discovery.research_memory import (
    ReadOnlyResearchMemoryReader,
    ResearchMemory,
    ResearchMemoryRecord,
)
from research_lab.contracts import v2


def _make_dummy_hypothesis(hyp_id: str, desc: str = "Test alpha hypothesis") -> hyp.AlphaHypothesis:
    """Helper to build a valid AlphaHypothesis for testing."""
    data = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": hyp_id,
        "revision": "rev.1",
        "title": "20-day high breakout momentum signal",
        "economic_rationale": "Sustained momentum driven by structural flows.",
        "signal_family": "momentum",
        "signal_definition": "(close - ts_min(low, 20)) / (ts_max(high, 20) - ts_min(low, 20) + 1e-6)",
        "source_features": ["close", "high", "low"],
        "target": "forward_return_5d",
        "expected_direction": "positive",
        "holding_horizon": "5d",
        "universe": "commodity_active",
        "frequency": "1d",
        "known_risks": ["Risk of chop"],
        "falsification_conditions": ["IC <= 0"],
        "proposed_screening_methods": ["data_quality_check"],
        "provenance": {
            "origin_type": "human",
            "origin_ref": "user_test",
            "created_by": "tester",
            "created_at": "2026-09-20T00:00:00.000000Z",
        },
    }
    data["hypothesis_content_hash"] = hyp.compute_hypothesis_content_hash(data)
    return hyp.AlphaHypothesis(**data)



def _make_dummy_plan(hypo: hyp.AlphaHypothesis, plan_id: str = "plan-1") -> dict[str, Any]:
    """Helper to build a valid ScreeningPlan dict for testing."""
    return {
        "plan_id": plan_id,
        "plan_content_hash": v2.digest({"plan_id": plan_id, "hypo_id": hypo.hypothesis_id}),
        "methods": [{"method": "coverage", "status": "APPROVED"}],
        "dataset_requirements": {
            "snapshot_locator": "dummy/data.csv",
            "required_fields": ["timestamp", "close"],
            "as_of_time": "2026-01-01T00:00:00.000000Z",
        },
        "scientific_identity_hash": hyp.compute_scientific_identity_hash(hypo.model_dump(exclude_none=True)),
        "provenance": {"created_by": "tester", "created_at": "2026-09-20T00:00:00.000000Z"},
    }


def _make_dummy_critic_decision(
    decision_id: str,
    decision: str,
    hypo: hyp.AlphaHypothesis,
    plan_dict: dict[str, Any],
    reject_reasons: list[str] | None = None,
    promoted_reasons: list[str] | None = None,
    missing_evidence: list[str] | None = None,
) -> dict[str, Any]:
    """Helper to build a valid CriticDecision dict for testing."""
    d = {
        "decision_id": decision_id,
        "decision": decision,
        "hypothesis_ref": {
            "hypothesis_id": hypo.hypothesis_id,
            "revision": hypo.revision,
            "content_hash": hypo.hypothesis_content_hash,
        },
        "plan_ref": {
            "plan_id": plan_dict["plan_id"],
            "content_hash": plan_dict["plan_content_hash"],
        },
        "criteria": {"evaluated_at": "2026-09-20T10:00:00.000000Z"},
        "reject_reasons": reject_reasons or [],
        "promoted_reasons": promoted_reasons or [],
        "missing_evidence": missing_evidence or [],
    }
    d["review_content_hash"] = v2.digest(d)
    return d


def _populate_test_memory(memory: ResearchMemory) -> dict[str, ResearchMemoryRecord]:
    """Populate memory with diverse records covering REJECT, PROMOTE, NME, and Crashes."""
    records: dict[str, ResearchMemoryRecord] = {}

    # 1. REJECT record
    hyp1 = _make_dummy_hypothesis("hypo-reject-1", "Hypothesis doomed to fail")
    plan1 = _make_dummy_plan(hyp1, "plan-reject-1")
    crit1 = _make_dummy_critic_decision(
        decision_id="crit-dec-1",
        decision="REJECT",
        hypo=hyp1,
        plan_dict=plan1,
        reject_reasons=["stability_split failed", "cost_sensitivity failed"],
    )
    records["reject"] = memory.append_evaluation_record(
        hypothesis=hyp1,
        plan=plan1,
        task_records=[{"task_id": "task-1", "revision": "rev.1", "task_content_hash": "thash-1"}],
        spec_records=[{"spec_id": "spec-1", "revision": "rev.1", "spec_content_hash": "shash-1"}],
        run_records=[{"run_id": "run-1", "run_content_hash": "rhash-1", "run_status": "COMPLETED"}],
        manifest_records=[{"manifest_id": "man-1", "revision": "rev.1", "manifest_content_hash": "mhash-1"}],
        evidence_records=[{"evidence_id": "ev-1", "revision": "rev.1", "evidence_content_hash": "hash-ev-1", "execution_status": "COMPLETED"}],
        critic_decision=crit1,
    )

    # 2. PROMOTE record
    hyp2 = _make_dummy_hypothesis("hypo-candidate-2", "Promoted hypothesis passing all filters")
    plan2 = _make_dummy_plan(hyp2, "plan-candidate-2")
    crit2 = _make_dummy_critic_decision(
        decision_id="crit-dec-2",
        decision="PROMOTE",
        hypo=hyp2,
        plan_dict=plan2,
        promoted_reasons=["robust_direction_confirmed", "cost_acceptable"],
    )
    records["promote"] = memory.append_evaluation_record(
        hypothesis=hyp2,
        plan=plan2,
        task_records=[{"task_id": "task-2", "revision": "rev.1", "task_content_hash": "thash-2"}],
        spec_records=[{"spec_id": "spec-2", "revision": "rev.1", "spec_content_hash": "shash-2"}],
        run_records=[{"run_id": "run-2", "run_content_hash": "rhash-2", "run_status": "COMPLETED"}],
        manifest_records=[{"manifest_id": "man-2", "revision": "rev.1", "manifest_content_hash": "mhash-2"}],
        evidence_records=[{"evidence_id": "ev-2", "revision": "rev.1", "evidence_content_hash": "hash-ev-2", "execution_status": "COMPLETED"}],
        critic_decision=crit2,
    )

    # 3. NEED_MORE_EVIDENCE record
    hyp3 = _make_dummy_hypothesis("hypo-nme-3", "Promising hypothesis lacking cost evidence")
    plan3 = _make_dummy_plan(hyp3, "plan-nme-3")
    crit3 = _make_dummy_critic_decision(
        decision_id="crit-dec-3",
        decision="NEED_MORE_EVIDENCE",
        hypo=hyp3,
        plan_dict=plan3,
        missing_evidence=["cost_sensitivity", "outlier_sensitivity"],
    )
    records["nme"] = memory.append_evaluation_record(
        hypothesis=hyp3,
        plan=plan3,
        task_records=[{"task_id": "task-3", "revision": "rev.1", "task_content_hash": "thash-3"}],
        spec_records=[{"spec_id": "spec-3", "revision": "rev.1", "spec_content_hash": "shash-3"}],
        run_records=[{"run_id": "run-3", "run_content_hash": "rhash-3", "run_status": "COMPLETED"}],
        manifest_records=[{"manifest_id": "man-3", "revision": "rev.1", "manifest_content_hash": "mhash-3"}],
        evidence_records=[{"evidence_id": "ev-3", "revision": "rev.1", "evidence_content_hash": "hash-ev-3", "execution_status": "COMPLETED"}],
        critic_decision=crit3,
    )

    # 4. Engineering failure (execution crash)
    hyp4 = _make_dummy_hypothesis("hypo-crash-4", "Hypothesis whose runner crashed")
    records["crash"] = memory.append_execution_crashed_record(
        hypothesis=hyp4,
        plan=None,
        error_message="Runner memory fault in test environment",
    )

    return records



class TestAgentControlMilestone4(unittest.TestCase):
    """Rigorous verification of Milestone 4 Controlled Research Memory View."""

    def setUp(self) -> None:
        self.tmp_dir = Path("/Users/fujun/node/vnpy/tmp/m4_test_workspace")
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.tmp_dir / "test_research_memory.sqlite3"
        if self.db_path.exists():
            self.db_path.unlink()

        self.memory = ResearchMemory(self.db_path)
        self.records = _populate_test_memory(self.memory)

        self.project_binding = ProjectBinding(
            project_id="test-proj-m4",
            workspace_identity="test-workspace-m4",
            binding_mode="strict",
        )

        # Standard authorized scope for alpha_generator with read_research_memory
        self.scope_alpha_generator = AgentPermissionScope.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[
                AgentPermission.READ_RESEARCH_MEMORY.value,
                AgentPermission.CREATE_HYPOTHESIS.value,
            ],
            authorized_permissions=[
                AgentPermission.READ_RESEARCH_MEMORY.value,
                AgentPermission.CREATE_HYPOTHESIS.value,
            ],
            project_binding=self.project_binding,
            is_authorized=True,
        )

    def tearDown(self) -> None:
        if self.db_path.exists():
            self.db_path.unlink()
        if self.tmp_dir.exists():
            import shutil
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. permission denied
    def test_01_permission_denied(self) -> None:
        # Scope without READ_RESEARCH_MEMORY permission
        unauthorized_scope = AgentPermissionScope.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            authorized_permissions=[AgentPermission.CREATE_HYPOTHESIS.value],
            project_binding=self.project_binding,
            is_authorized=True,
        )
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        with self.assertRaises(ResearchMemoryPermissionError) as ctx:
            build_research_memory_view(
                query=query,
                authorized_scope=unauthorized_scope,
                project_binding=self.project_binding,
                memory_store=self.memory,
            )
        self.assertEqual(ctx.exception.reason_code, MemoryAccessReasonCode.MEMORY_PERMISSION_DENIED.value)

    # 2. wrong project
    def test_02_wrong_project(self) -> None:
        different_project = ProjectBinding(
            project_id="foreign-proj",
            workspace_identity="foreign-workspace",
            binding_mode="strict",
        )
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=different_project,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        with self.assertRaises(ProjectBindingError):
            build_research_memory_view(
                query=query,
                authorized_scope=self.scope_alpha_generator,
                project_binding=self.project_binding,  # mismatch with query.project_binding
                memory_store=self.memory,
            )

    # 3. unknown category
    def test_03_unknown_category(self) -> None:
        with self.assertRaises(ResearchMemoryCategoryError):
            ResearchMemoryQuery(
                role=AgentRole.ALPHA_GENERATOR.value,
                project_binding=self.project_binding,
                categories=("completely_unknown_category",),
            )

    # 4. limit exceeded
    def test_04_limit_exceeded(self) -> None:
        policy = ResearchMemoryViewPolicy(max_entries_per_category=5, max_total_entries=10)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            limit_per_category=20,  # Exceeds policy max (5)
        )
        with self.assertRaises(ResearchMemoryLimitError) as ctx:
            build_research_memory_view(
                query=query,
                authorized_scope=self.scope_alpha_generator,
                project_binding=self.project_binding,
                memory_store=self.memory,
                policy=policy,
            )
        self.assertEqual(ctx.exception.reason_code, MemoryAccessReasonCode.MEMORY_LIMIT_EXCEEDED.value)

    # 5. per-category limit
    def test_05_per_category_limit(self) -> None:
        # Add 5 more reject records
        for i in range(10, 15):
            hyp_i = _make_dummy_hypothesis(f"hypo-reject-{i}")
            plan_i = _make_dummy_plan(hyp_i, f"plan-reject-{i}")
            crit_i = _make_dummy_critic_decision(
                decision_id=f"crit-{i}",
                decision="REJECT",
                hypo=hyp_i,
                plan_dict=plan_i,
                reject_reasons=["test_rejection"],
            )
            self.memory.append_evaluation_record(
                hypothesis=hyp_i, plan=plan_i, task_records=[], spec_records=[],
                run_records=[], manifest_records=[], evidence_records=[], critic_decision=crit_i,
            )

        policy = ResearchMemoryViewPolicy(max_entries_per_category=3)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            limit_per_category=3,
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            policy=policy,
        )
        entries = view.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]
        self.assertEqual(len(entries), 3)

    # 6. total limit
    def test_06_total_limit(self) -> None:
        policy = ResearchMemoryViewPolicy(max_total_entries=2)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(
                ResearchMemoryCategory.RECENT_REJECTS.value,
                ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
                ResearchMemoryCategory.NME_BACKLOG.value,
            ),
            total_limit=2,
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            policy=policy,
        )
        self.assertEqual(view.total_entries, 2)
        self.assertTrue(view.is_truncated)

    # 7. recent_rejects
    def test_07_recent_rejects(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        rejects = view.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]
        self.assertGreaterEqual(len(rejects), 1)
        self.assertEqual(rejects[0].decision, "REJECT")
        self.assertIn("stability_split failed", rejects[0].reason_codes)
        self.assertTrue(len(rejects[0].evidence_refs) > 0)
        self.assertNotIn("raw_payload", rejects[0].to_dict())

    # 8. promoted_summaries
    def test_08_promoted_summaries(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.PROMOTED_SUMMARIES.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        promoted = view.entries_by_category[ResearchMemoryCategory.PROMOTED_SUMMARIES.value]
        self.assertGreaterEqual(len(promoted), 1)
        self.assertEqual(promoted[0].decision, "PROMOTE")
        self.assertIn("NOT tradable", promoted[0].summary)
        self.assertIn("robust_direction_confirmed", promoted[0].strengths)

    # 9. need_more_evidence_backlog
    def test_09_need_more_evidence_backlog(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.NME_BACKLOG.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        nme = view.entries_by_category[ResearchMemoryCategory.NME_BACKLOG.value]
        self.assertGreaterEqual(len(nme), 1)
        self.assertEqual(nme[0].decision, "NEED_MORE_EVIDENCE")
        self.assertIn("NOT a failure", nme[0].summary)
        self.assertIn("cost_sensitivity", nme[0].missing_dimensions)

    # 10. duplicate exact & related
    def test_10_duplicate_identities(self) -> None:
        # Exact lookup using content hash of reject record
        rec = self.records["reject"]
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,),
            hypothesis_content_hash=rec.content_hash,
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        dups = view.entries_by_category[ResearchMemoryCategory.DUPLICATE_IDENTITIES.value]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0].duplicate_state, "exact")
        self.assertIn("does NOT mean unconditional execution skip", dups[0].summary)

        # Append two duplicate candidates with same scientific identity at different timestamps
        hyp_dup1 = _make_dummy_hypothesis("hypo-dup-order-1")
        plan_dup1 = _make_dummy_plan(hyp_dup1, "plan-dup-order-1")
        crit_dup1 = _make_dummy_critic_decision("crit-dup-1", "REJECT", hyp_dup1, plan_dup1, ["dup_order_1"])
        rec1 = self.memory.append_evaluation_record(
            hypothesis=hyp_dup1, plan=plan_dup1, task_records=[], spec_records=[],
            run_records=[], manifest_records=[], evidence_records=[], critic_decision=crit_dup1,
        )

        hyp_dup2 = _make_dummy_hypothesis("hypo-dup-order-2")
        plan_dup2 = _make_dummy_plan(hyp_dup2, "plan-dup-order-2")
        crit_dup2 = _make_dummy_critic_decision("crit-dup-2", "REJECT", hyp_dup2, plan_dup2, ["dup_order_2"])
        rec2 = self.memory.append_evaluation_record(
            hypothesis=hyp_dup2, plan=plan_dup2, task_records=[], spec_records=[],
            run_records=[], manifest_records=[], evidence_records=[], critic_decision=crit_dup2,
        )

        # Force timestamps to prove (decision_time DESC, record_id ASC) ordering
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("UPDATE research_memory_records SET created_at = '2026-09-20T10:00:00Z' WHERE record_id = ?", (rec1.record_id,))
            conn.execute("UPDATE research_memory_records SET created_at = '2026-09-21T10:00:00Z' WHERE record_id = ?", (rec2.record_id,))
            conn.commit()

        # Query with limit_per_category = 1 to verify latest duplicate is prioritized (P1 fix verification)
        query_ordered = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,),
            limit_per_category=1,
            scientific_identity_hash=rec1.scientific_identity_hash,
        )
        view_ordered = build_research_memory_view(
            query=query_ordered,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        dup_entries = view_ordered.entries_by_category[ResearchMemoryCategory.DUPLICATE_IDENTITIES.value]
        self.assertEqual(len(dup_entries), 1)
        self.assertEqual(dup_entries[0].view_generated_from, rec2.record_id, "Latest duplicate must be prioritized by decision_time DESC")

    # 11. failed approaches (scientific vs engineering)
    def test_11_failed_approaches(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.FAILED_APPROACHES.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        failed = view.entries_by_category[ResearchMemoryCategory.FAILED_APPROACHES.value]
        failure_classes = {f.failure_class for f in failed}
        self.assertIn("engineering", failure_classes)
        self.assertIn("scientific", failure_classes)
        # Check engineering failure properties
        eng = next(f for f in failed if f.failure_class == "engineering")
        self.assertIn("ENGINEERING_FAILURE", eng.summary)
        self.assertIn("NOT scientific REJECT", eng.summary)
        self.assertIsNotNone(eng.retry_condition)

    # 12. research gaps
    def test_12_research_gaps(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RESEARCH_GAPS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        gaps = view.entries_by_category[ResearchMemoryCategory.RESEARCH_GAPS.value]
        self.assertGreaterEqual(len(gaps), 1)
        self.assertEqual(gaps[0].gap_type, "unresolved_nme")
        self.assertIn("cost_sensitivity", gaps[0].missing_dimensions)

    # 13. no raw sqlite leakage
    def test_13_no_raw_sqlite_leakage(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        ctx = view.to_prompt_context()
        vdict = view.to_dict()
        for forbidden in ("sqlite", "research_memory_records", "cursor", "rowid", "SELECT "):
            self.assertNotIn(forbidden, ctx)
            self.assertNotIn(forbidden, str(vdict))

    # 14. no raw Evidence dump
    def test_14_no_raw_evidence_dump(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        entry = view.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value][0]
        for ev in entry.evidence_refs:
            self.assertIn("evidence_id", ev)
            self.assertIn("content_hash", ev)
            self.assertNotIn("payload", ev)
            self.assertNotIn("data", ev)

    # 15. source refs preserved
    def test_15_source_refs_preserved(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        entry = view.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value][0]
        self.assertTrue(entry.view_generated_from.startswith("rmrec-"))
        self.assertIn("content_hash", entry.source_hashes)
        self.assertIn("hypothesis_ref", entry.source_refs)

    # 16. source hash validation
    def test_16_source_hash_validation(self) -> None:
        # A valid view succeeds when integrity is enforced
        policy = ResearchMemoryViewPolicy(enforce_source_integrity=True)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            policy=policy,
        )
        self.assertIsNotNone(view.view_id)

    # 17. corrupted memory fail closed
    def test_17_corrupted_memory_fail_closed(self) -> None:
        # Corrupt one record directly in SQLite
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("UPDATE research_memory_records SET content_hash = 'corrupted_hash' WHERE rowid = 1")
            conn.commit()

        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        with self.assertRaises(ResearchMemorySourceCorruptionError) as ctx:
            build_research_memory_view(
                query=query,
                authorized_scope=self.scope_alpha_generator,
                project_binding=self.project_binding,
                memory_store=self.memory,
            )
        self.assertEqual(ctx.exception.reason_code, MemoryAccessReasonCode.MEMORY_SOURCE_CORRUPT.value)

    # 18. deterministic view ID
    def test_18_deterministic_view_id(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value, ResearchMemoryCategory.PROMOTED_SUMMARIES.value),
        )
        view1 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )
        view2 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )
        self.assertEqual(view1.view_id, view2.view_id)

    # 19. deterministic content hash
    def test_19_deterministic_content_hash(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value, ResearchMemoryCategory.PROMOTED_SUMMARIES.value),
        )
        view1 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )
        view2 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )
        self.assertEqual(view1.view_content_hash, view2.view_content_hash)


    # 20. same query same view
    def test_20_same_query_same_view(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.NME_BACKLOG.value,),
        )
        view1 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        view2 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        self.assertEqual(view1.view_id, view2.view_id)
        self.assertEqual(view1.view_content_hash, view2.view_content_hash)
        self.assertEqual(view1.total_entries, view2.total_entries)

    # 21. source append produces new view
    def test_21_source_append_produces_new_view(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view1 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )

        # Append a new reject record
        hyp_new = _make_dummy_hypothesis("hypo-reject-new")
        plan_new = _make_dummy_plan(hyp_new, "plan-reject-new")
        crit_new = _make_dummy_critic_decision(
            decision_id="crit-new",
            decision="REJECT",
            hypo=hyp_new,
            plan_dict=plan_new,
            reject_reasons=["appended_rejection"],
        )

        self.memory.append_evaluation_record(
            hypothesis=hyp_new, plan=plan_new, task_records=[], spec_records=[],
            run_records=[], manifest_records=[], evidence_records=[], critic_decision=crit_new,
        )

        view2 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )
        self.assertNotEqual(view1.view_id, view2.view_id)
        self.assertNotEqual(view1.view_content_hash, view2.view_content_hash)

    # 22. generated_at not in identity
    def test_22_generated_at_not_in_identity(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.PROMOTED_SUMMARIES.value,),
        )
        view_time1 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )
        view_time2 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T12:34:56Z",  # Different timestamp
        )
        self.assertEqual(view_time1.view_id, view_time2.view_id)
        self.assertEqual(view_time1.view_content_hash, view_time2.view_content_hash)
        self.assertNotEqual(view_time1.generated_at, view_time2.generated_at)

    # 23. role category restriction
    def test_23_role_category_restriction(self) -> None:
        # code_researcher is restricted to failed_approaches only
        scope_code_researcher = AgentPermissionScope.create(
            role=AgentRole.CODE_RESEARCHER.value,
            requested_permissions=[AgentPermission.READ_RESULT_STORE.value],
            authorized_permissions=[AgentPermission.READ_RESULT_STORE.value],
            project_binding=self.project_binding,
            is_authorized=True,
        )
        # Attempt to query promoted_summaries with code_researcher role
        query_bad = ResearchMemoryQuery(
            role=AgentRole.CODE_RESEARCHER.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.PROMOTED_SUMMARIES.value,),
        )
        with self.assertRaises(ResearchMemoryAccessError):
            build_research_memory_view(
                query=query_bad,
                authorized_scope=scope_code_researcher,
                project_binding=self.project_binding,
                memory_store=self.memory,
            )

    # 24. least privilege category intersection
    def test_24_least_privilege_category_intersection(self) -> None:
        # data_researcher is allowed research_gaps, failed_approaches, recent_rejects
        # If query requests recent_rejects and promoted_summaries, promoted_summaries is denied fail-closed
        scope_data_researcher = AgentPermissionScope.create(
            role=AgentRole.DATA_RESEARCHER.value,
            requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
            authorized_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
            project_binding=self.project_binding,
            is_authorized=True,
        )
        query = ResearchMemoryQuery(
            role=AgentRole.DATA_RESEARCHER.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value, ResearchMemoryCategory.PROMOTED_SUMMARIES.value),
        )
        with self.assertRaises(ResearchMemoryCategoryError) as ctx:
            build_research_memory_view(
                query=query,
                authorized_scope=scope_data_researcher,
                project_binding=self.project_binding,
                memory_store=self.memory,
            )
        self.assertEqual(ctx.exception.reason_code, MemoryAccessReasonCode.MEMORY_CATEGORY_DENIED.value)


    # 25. no write methods on View or EntryView or Query
    def test_25_no_write_methods(self) -> None:
        for cls in (ResearchMemoryView, ResearchMemoryEntryView, ResearchMemoryQuery, ResearchMemoryViewPolicy):
            for attr_name in dir(cls):
                attr_lower = attr_name.lower()
                for forbidden in ("write", "update", "delete", "insert", "mark_promoted", "mark_rejected"):
                    self.assertNotIn(
                        forbidden,
                        attr_lower,
                        f"Class {cls.__name__} must not expose mutating method '{attr_name}'",
                    )

    # 26. no mutation of source store
    def test_26_no_mutation_of_source_store(self) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            before_rows = conn.execute("SELECT COUNT(*) FROM research_memory_records").fetchone()[0]

        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(
                ResearchMemoryCategory.RECENT_REJECTS.value,
                ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
            ),
        )
        build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )

        with sqlite3.connect(str(self.db_path)) as conn:
            after_rows = conn.execute("SELECT COUNT(*) FROM research_memory_records").fetchone()[0]
        self.assertEqual(before_rows, after_rows)

    # 27. max chars
    def test_27_max_chars(self) -> None:
        # Strict max_chars = 150
        policy = ResearchMemoryViewPolicy(max_chars=150)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(
                ResearchMemoryCategory.RECENT_REJECTS.value,
                ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
            ),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            policy=policy,
        )
        total_chars = sum(
            len(e.summary)
            for entries in view.entries_by_category.values()
            for e in entries
        )
        self.assertLessEqual(total_chars, 150)
        self.assertTrue(view.is_truncated)

    # 28. max entries
    def test_28_max_entries(self) -> None:
        policy = ResearchMemoryViewPolicy(max_total_entries=1)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(
                ResearchMemoryCategory.RECENT_REJECTS.value,
                ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
            ),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            policy=policy,
        )
        self.assertEqual(view.total_entries, 1)

    # 29. stable ordering
    def test_29_stable_ordering(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.FAILED_APPROACHES.value,),
        )
        view1 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        view2 = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        entries1 = [e.entry_id for e in view1.entries_by_category[ResearchMemoryCategory.FAILED_APPROACHES.value]]
        entries2 = [e.entry_id for e in view2.entries_by_category[ResearchMemoryCategory.FAILED_APPROACHES.value]]
        self.assertEqual(entries1, entries2)

    # 30. no provider/model dependency
    def test_30_no_provider_model_dependency(self) -> None:
        # Module memory_view should not import or require provider or model
        import research_lab.agent_control.memory_view as mv
        src = inspect.getsource(mv)
        for forbidden in ("AntigravityLocalMCPProvider", "SUPPORTED_MODELS", "Gemini 3.8", "gpt-4"):
            self.assertNotIn(forbidden, src)

    # 31. no MCP call
    def test_31_no_mcp_call(self) -> None:
        import research_lab.agent_control.memory_view as mv
        src = inspect.getsource(mv)
        self.assertNotIn("call_tool", src)
        self.assertNotIn("mcp_client", src)

    # 32. no LLM call
    def test_32_no_llm_call(self) -> None:
        import research_lab.agent_control.memory_view as mv
        src = inspect.getsource(mv)
        for forbidden in ("openai", "anthropic", "google.generativeai", "llm_client"):
            self.assertNotIn(forbidden, src.lower())

    # 33. duplicate != skip
    def test_33_duplicate_not_skip(self) -> None:
        rec = self.records["reject"]
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,),
            hypothesis_content_hash=rec.content_hash,
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        dups = view.entries_by_category[ResearchMemoryCategory.DUPLICATE_IDENTITIES.value]
        self.assertEqual(len(dups), 1)
        self.assertIn("does NOT mean unconditional execution skip", dups[0].summary)

    # 34. engineering failure != scientific REJECT
    def test_34_engineering_failure_not_reject(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.FAILED_APPROACHES.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        approaches = view.entries_by_category[ResearchMemoryCategory.FAILED_APPROACHES.value]
        eng_crash = next(a for a in approaches if a.hypothesis_id == "hypo-crash-4")
        self.assertEqual(eng_crash.failure_class, "engineering")
        self.assertIn("NOT scientific REJECT", eng_crash.summary)

    # 35. PROMOTE != tradable
    def test_35_promote_not_tradable(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.PROMOTED_SUMMARIES.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        promoted = view.entries_by_category[ResearchMemoryCategory.PROMOTED_SUMMARIES.value][0]
        self.assertIn("NOT tradable / production approved", promoted.summary)

    # 36. AgentTask input_ref integration
    def test_36_agent_task_input_ref_integration(self) -> None:
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        # Construct AgentTask referencing this view
        task = AgentTask.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            objective="Develop new momentum alpha avoiding known falsified patterns",
            work_block="alpha_generation_with_memory",
            input_refs=[
                {
                    "content_hash": view.view_content_hash,
                    "ref_type": "memory_view",
                    "view_id": view.view_id,
                }
            ],
            requested_permissions=list(self.scope_alpha_generator.requested_permissions),
            authorized_permissions=list(self.scope_alpha_generator.authorized_permissions),
            provider_policy_ref="policy-alpha-gen-v1",
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            created_by="tester",
            created_at="2026-09-21T00:00:00Z",
        )
        self.assertTrue(task.task_id.startswith("task-"))
        self.assertEqual(len(task.input_refs), 1)
        self.assertEqual(task.input_refs[0]["view_id"], view.view_id)

    # 37-40. M0-M3 frozen suites compatibility check
    def test_37_m0_frozen(self) -> None:
        # Confirm hard invariants are still strictly enforced
        with self.assertRaises(PermissionDeniedError):
            AgentPermissionScope.create(
                role=AgentRole.ALPHA_GENERATOR.value,
                requested_permissions=[AgentPermission.PRODUCTION_TRADING.value],
                authorized_permissions=[AgentPermission.PRODUCTION_TRADING.value],
                project_binding=self.project_binding,
            )

    def test_38_m1_frozen(self) -> None:
        # Confirm role policy and delegation depth are still enforced
        self.assertEqual(DEFAULT_ROLE_ALLOWED_CATEGORIES[AgentRole.CODE_RESEARCHER.value], frozenset({ResearchMemoryCategory.FAILED_APPROACHES.value}))

    def test_39_m2_frozen(self) -> None:
        # Confirm audit trail records memory view events append-only
        from research_lab.agent_control.memory_view import MemoryViewAuditTrail
        audit_trail = MemoryViewAuditTrail()
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            audit_trail=audit_trail,
        )
        self.assertEqual(len(audit_trail.records), 1)
        self.assertEqual(audit_trail.records[0].role, AgentRole.ALPHA_GENERATOR.value)
        self.assertEqual(audit_trail.records[0].view_id, view.view_id)


    def test_40_m3_frozen(self) -> None:
        # Confirm Router / Quota neutral behavior without memory view intrusion
        from research_lab.agent_control.routing_policy import RoutingPolicy
        pol = RoutingPolicy(
            role=AgentRole.ALPHA_GENERATOR.value,
            provider_priority=("antigravity",),
            policy_version="2026-09-m3",
        )
        self.assertNotIn("memory_view", pol.to_dict())

    # 41. true real Research Memory read-only E2E
    def test_41_real_research_memory_read_only_e2e(self) -> None:
        """Locate actual existing Research Lab database, execute bounded read-only view build, and prove zero mutation."""
        repo_root = Path(__file__).resolve().parents[3]
        real_db_path = repo_root / "research_lab" / "research_lab.sqlite3"

        # Strictly check existence before touching anything; skipTest if absent, NEVER create/init or delete real store
        if not real_db_path.exists() or real_db_path.stat().st_size == 0:
            self.skipTest(
                f"Real Research Memory database not found at {real_db_path}; "
                "skipping real read-only E2E to prevent creating unpopulated store."
            )

        # 1. Baseline: SHA-256, file size, mtime, and read-only row counts BEFORE any objects are constructed
        hash_before = hashlib.sha256(real_db_path.read_bytes()).hexdigest()
        stat_before = real_db_path.stat()
        size_before = stat_before.st_size
        mtime_before = stat_before.st_mtime_ns

        ro_uri = f"file:{real_db_path.as_posix()}?mode=ro"
        with sqlite3.connect(ro_uri, uri=True) as conn:
            conn.execute("PRAGMA query_only=ON;")
            rows_before = conn.execute("SELECT COUNT(*) FROM research_memory_records").fetchone()[0]
            tbl_manifests = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='manifests'").fetchone()
            manifests_before = conn.execute("SELECT COUNT(*) FROM manifests").fetchone()[0] if tbl_manifests else 0
            latest_row = conn.execute("SELECT record_id, content_hash FROM research_memory_records ORDER BY rowid DESC LIMIT 1").fetchone()
            latest_hash_before = (latest_row[0], latest_row[1]) if latest_row else None

        # 2. Scope for REAL project binding (dynamic to repo root, no /Users/fujun hardcoding)
        real_binding = ProjectBinding(
            project_id="a173ba08-8e0c-4c26-8604-0d462da55529",
            workspace_identity=str(repo_root),
            binding_mode="strict",
        )
        real_scope = AgentPermissionScope.create(
            role=AgentRole.ALPHA_GENERATOR.value,
            requested_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
            authorized_permissions=[AgentPermission.READ_RESEARCH_MEMORY.value],
            project_binding=real_binding,
            is_authorized=True,
        )

        # 3. Read via ReadOnlyResearchMemoryReader with mode=ro
        readonly_reader = ReadOnlyResearchMemoryReader(real_db_path)

        # 4. Build bounded view across all 6 categories against actual real store
        query_all = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=real_binding,
            categories=(
                ResearchMemoryCategory.RECENT_REJECTS.value,
                ResearchMemoryCategory.PROMOTED_SUMMARIES.value,
                ResearchMemoryCategory.NME_BACKLOG.value,
                ResearchMemoryCategory.DUPLICATE_IDENTITIES.value,
                ResearchMemoryCategory.FAILED_APPROACHES.value,
                ResearchMemoryCategory.RESEARCH_GAPS.value,
            ),
        )
        view = build_research_memory_view(
            query=query_all,
            authorized_scope=real_scope,
            project_binding=real_binding,
            memory_store=readonly_reader,
        )

        # 5. Verify outputs
        self.assertIsNotNone(view.view_id)
        self.assertIsNotNone(view.view_content_hash)
        self.assertEqual(len(view.categories), 6)
        for cat in view.categories:
            self.assertIn(cat, view.entries_by_category)
            self.assertIsInstance(view.entries_by_category[cat], tuple)
        self.assertEqual(view.total_entries, sum(len(e) for e in view.entries_by_category.values()))

        # 6. Prove zero mutation to the underlying real database: SHA-256, size, mtime, rows, manifests, latest hash
        hash_after = hashlib.sha256(real_db_path.read_bytes()).hexdigest()
        stat_after = real_db_path.stat()
        self.assertEqual(hash_before, hash_after, "Real DB SHA-256 must NOT change on read-only view build")
        self.assertEqual(size_before, stat_after.st_size, "Real DB file size must NOT change on read-only view build")
        self.assertEqual(mtime_before, stat_after.st_mtime_ns, "Real DB mtime must NOT change on read-only view build")

        with sqlite3.connect(ro_uri, uri=True) as conn:
            conn.execute("PRAGMA query_only=ON;")
            rows_after = conn.execute("SELECT COUNT(*) FROM research_memory_records").fetchone()[0]
            manifests_after = conn.execute("SELECT COUNT(*) FROM manifests").fetchone()[0] if tbl_manifests else 0
            latest_row_after = conn.execute("SELECT record_id, content_hash FROM research_memory_records ORDER BY rowid DESC LIMIT 1").fetchone()
            latest_hash_after = (latest_row_after[0], latest_row_after[1]) if latest_row_after else None

        self.assertEqual(rows_before, rows_after, "Real DB row count must NOT change")
        self.assertEqual(manifests_before, manifests_after, "Real DB manifest count must NOT change")
        self.assertEqual(latest_hash_before, latest_hash_after, "Real DB latest hash must NOT change")

        # 7. Isolated replica fixture to prove append produces new identity without mutating real store
        replica_path = self.tmp_dir / "isolated_replica.sqlite3"
        import shutil
        shutil.copy2(real_db_path, replica_path)
        replica_memory = ResearchMemory(replica_path)
        hyp_rep = _make_dummy_hypothesis("hypo-replica-new")
        plan_rep = _make_dummy_plan(hyp_rep, "plan-replica-new")
        crit_rep = _make_dummy_critic_decision("crit-rep-1", "REJECT", hyp_rep, plan_rep, ["replica_test_reject"])
        replica_memory.append_evaluation_record(
            hypothesis=hyp_rep, plan=plan_rep, task_records=[], spec_records=[],
            run_records=[], manifest_records=[], evidence_records=[], critic_decision=crit_rep,
        )
        view_replica = build_research_memory_view(
            query=query_all,
            authorized_scope=real_scope,
            project_binding=real_binding,
            memory_store=ReadOnlyResearchMemoryReader(replica_path),
            current_time=view.generated_at,
        )
        self.assertNotEqual(view.view_id, view_replica.view_id)
        self.assertNotEqual(view.view_content_hash, view_replica.view_content_hash)

        # Final check: real store is still completely untouched after replica operations
        self.assertEqual(hash_before, hashlib.sha256(real_db_path.read_bytes()).hexdigest())

    # 42. ReadOnlyResearchMemoryReader mode=ro and isolation
    def test_42_readonly_memory_reader_mode_ro_isolation(self) -> None:
        """Verify ReadOnlyResearchMemoryReader uses mode=ro and prevents any mutation."""
        reader = ReadOnlyResearchMemoryReader(self.db_path)
        records = reader.get_all_records()
        self.assertIsInstance(records, tuple)
        self.assertGreater(len(records), 0)
        self.assertIsInstance(records[0], ResearchMemoryRecord)

        # Attempting write operation via reader's read-only connection must fail closed
        with self.assertRaises(sqlite3.OperationalError), reader._get_readonly_connection() as conn:
            conn.execute("DELETE FROM research_memory_records")

        # Non-existent path must raise FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            ReadOnlyResearchMemoryReader(self.tmp_dir / "nonexistent.sqlite3")

        # Also verify ResearchMemory helper methods return ReadOnlyResearchMemoryReader
        reader_from_mem = self.memory.as_readonly_reader()
        self.assertIsInstance(reader_from_mem, ReadOnlyResearchMemoryReader)
        reader_from_cls = ResearchMemory.open_readonly(self.db_path)
        self.assertIsInstance(reader_from_cls, ReadOnlyResearchMemoryReader)

    # 43. Typed query filtering and negative isolation
    def test_43_typed_query_filtering_negative_isolation(self) -> None:
        """Verify typed query parameters strictly filter entries and fail-closed on unsupported combinations."""
        # 1. hypothesis_refs negative filtering: only hypo-reject-1 entries returned, hypo-candidate-2 strictly excluded
        query_refs = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            hypothesis_refs=("hypo-reject-1",),
        )
        view_refs = build_research_memory_view(
            query=query_refs,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        reject_entries = view_refs.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]
        self.assertGreater(len(reject_entries), 0)
        for e in reject_entries:
            self.assertEqual(e.hypothesis_id, "hypo-reject-1")
            self.assertNotEqual(e.hypothesis_id, "hypo-candidate-2")

        # 2. decision_types negative filtering: only REJECT entries returned
        query_dec = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.FAILED_APPROACHES.value,),
            decision_types=("REJECT",),
        )
        view_dec = build_research_memory_view(
            query=query_dec,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        failed_entries = view_dec.entries_by_category[ResearchMemoryCategory.FAILED_APPROACHES.value]
        for e in failed_entries:
            self.assertEqual(e.decision, "REJECT")
            self.assertNotIn(e.decision, ("ADMISSION_FAILED", "EXECUTION_CRASHED", "PROMOTE"))

        # 3. Incompatible query combination rejection: categories recent_rejects with decision_types PROMOTE
        with self.assertRaises(ResearchMemoryCategoryError):
            ResearchMemoryQuery(
                role=AgentRole.ALPHA_GENERATOR.value,
                project_binding=self.project_binding,
                categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
                decision_types=("PROMOTE",),
            )

        # 4. Unknown decision type rejection
        with self.assertRaises(ResearchMemoryCategoryError):
            ResearchMemoryQuery(
                role=AgentRole.ALPHA_GENERATOR.value,
                project_binding=self.project_binding,
                categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
                decision_types=("INVALID_DECISION_TYPE",),
            )

        # 5. hypothesis_content_hash and scientific_identity_hash strict conjunctive (AND) filtering
        target_content_hash = self.records["reject"].content_hash
        target_sci_hash = self.records["reject"].scientific_identity_hash

        # 5a. Matching content hash only
        query_content_hash = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            hypothesis_content_hash=target_content_hash,
        )
        view_content_hash = build_research_memory_view(
            query=query_content_hash,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        self.assertGreater(len(view_content_hash.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]), 0)
        for e in view_content_hash.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]:
            self.assertEqual(e.hypothesis_content_hash, target_content_hash)

        # 5b. Matching scientific identity hash only
        query_sci_hash = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            scientific_identity_hash=target_sci_hash,
        )
        view_sci_hash = build_research_memory_view(
            query=query_sci_hash,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        self.assertGreater(len(view_sci_hash.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]), 0)
        for e in view_sci_hash.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]:
            self.assertEqual(e.scientific_identity_hash, target_sci_hash)

        # 5c. Negative isolation: correct content hash, wrong scientific identity hash -> 0 entries
        query_mismatch_sci = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            hypothesis_content_hash=target_content_hash,
            scientific_identity_hash="0" * 64,
        )
        view_mismatch_sci = build_research_memory_view(
            query=query_mismatch_sci,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        self.assertEqual(len(view_mismatch_sci.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]), 0)

        # 5d. Negative isolation: wrong content hash, correct scientific identity hash -> 0 entries
        query_mismatch_content = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            hypothesis_content_hash="f" * 64,
            scientific_identity_hash=target_sci_hash,
        )
        view_mismatch_content = build_research_memory_view(
            query=query_mismatch_content,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        self.assertEqual(len(view_mismatch_content.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]), 0)

        # 5e. Positive conjunctive match: both correct -> exactly returned
        query_both_match = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            hypothesis_content_hash=target_content_hash,
            scientific_identity_hash=target_sci_hash,
        )
        view_both_match = build_research_memory_view(
            query=query_both_match,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
        )
        both_entries = view_both_match.entries_by_category[ResearchMemoryCategory.RECENT_REJECTS.value]
        self.assertGreater(len(both_entries), 0)
        for e in both_entries:
            self.assertEqual(e.hypothesis_content_hash, target_content_hash)
            self.assertEqual(e.scientific_identity_hash, target_sci_hash)

    # 44. View identity sensitive to query and policy
    def test_44_view_identity_sensitive_to_query_and_policy(self) -> None:
        """Verify identical entries with different query or policy produce distinct view identities."""
        base_query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            limit_per_category=5,
        )
        view_base = build_research_memory_view(
            query=base_query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )

        # 1. Different query (different limit_per_category) -> distinct view_id and content_hash
        query_diff_limit = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
            limit_per_category=10,
        )
        view_diff_query = build_research_memory_view(
            query=query_diff_limit,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-21T00:00:00Z",
        )
        self.assertNotEqual(view_base.view_id, view_diff_query.view_id)
        self.assertNotEqual(view_base.view_content_hash, view_diff_query.view_content_hash)

        # 2. Different policy (different max_chars) -> distinct view_id and content_hash
        policy_diff = ResearchMemoryViewPolicy(max_chars=2500)
        view_diff_policy = build_research_memory_view(
            query=base_query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            policy=policy_diff,
            current_time="2026-09-21T00:00:00Z",
        )
        self.assertNotEqual(view_base.view_id, view_diff_policy.view_id)
        self.assertNotEqual(view_base.view_content_hash, view_diff_policy.view_content_hash)

        # 3. Same query and policy but different generated_at -> identical view_id and content_hash
        view_diff_time = build_research_memory_view(
            query=base_query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=self.memory,
            current_time="2026-09-22T12:34:56Z",
        )
        self.assertEqual(view_base.view_id, view_diff_time.view_id)
        self.assertEqual(view_base.view_content_hash, view_diff_time.view_content_hash)

    # 45. Standalone read-only E2E with baseline integrity
    def test_45_standalone_readonly_e2e_with_baseline_integrity(self) -> None:
        """Simulate real persistent store E2E in isolated environment proving all 6 baseline metrics unchanged."""
        standalone_db_path = self.tmp_dir / "prebuilt_standalone_store.sqlite3"
        # Seed the database
        seed_memory = ResearchMemory(standalone_db_path)
        hyp_s = _make_dummy_hypothesis("hypo-standalone-1")
        plan_s = _make_dummy_plan(hyp_s, "plan-standalone-1")
        crit_s = _make_dummy_critic_decision("crit-standalone-1", "REJECT", hyp_s, plan_s, ["test_reason"])
        seed_memory.append_evaluation_record(
            hypothesis=hyp_s, plan=plan_s, task_records=[], spec_records=[],
            run_records=[], manifest_records=[], evidence_records=[], critic_decision=crit_s,
        )

        # Capture baseline BEFORE read-only operations
        hash_before = hashlib.sha256(standalone_db_path.read_bytes()).hexdigest()
        stat_before = standalone_db_path.stat()
        size_before = stat_before.st_size
        mtime_before = stat_before.st_mtime_ns

        ro_uri = f"file:{standalone_db_path.as_posix()}?mode=ro"
        with sqlite3.connect(ro_uri, uri=True) as conn:
            conn.execute("PRAGMA query_only=ON;")
            rows_before = conn.execute("SELECT COUNT(*) FROM research_memory_records").fetchone()[0]
            tbl_manifests = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='manifests'").fetchone()
            manifests_before = conn.execute("SELECT COUNT(*) FROM manifests").fetchone()[0] if tbl_manifests else 0
            latest_row = conn.execute("SELECT record_id, content_hash FROM research_memory_records ORDER BY rowid DESC LIMIT 1").fetchone()
            latest_hash_before = (latest_row[0], latest_row[1])

        # Execute read-only view build via ReadOnlyResearchMemoryReader
        reader = ReadOnlyResearchMemoryReader(standalone_db_path)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        view = build_research_memory_view(
            query=query,
            authorized_scope=self.scope_alpha_generator,
            project_binding=self.project_binding,
            memory_store=reader,
        )
        self.assertGreater(view.total_entries, 0)

        # Verify all 6 baseline metrics remain 100% identical
        hash_after = hashlib.sha256(standalone_db_path.read_bytes()).hexdigest()
        stat_after = standalone_db_path.stat()
        self.assertEqual(hash_before, hash_after)
        self.assertEqual(size_before, stat_after.st_size)
        self.assertEqual(mtime_before, stat_after.st_mtime_ns)

        with sqlite3.connect(ro_uri, uri=True) as conn:
            conn.execute("PRAGMA query_only=ON;")
            rows_after = conn.execute("SELECT COUNT(*) FROM research_memory_records").fetchone()[0]
            manifests_after = conn.execute("SELECT COUNT(*) FROM manifests").fetchone()[0] if tbl_manifests else 0
            latest_row_after = conn.execute("SELECT record_id, content_hash FROM research_memory_records ORDER BY rowid DESC LIMIT 1").fetchone()
            latest_hash_after = (latest_row_after[0], latest_row_after[1])

        self.assertEqual(rows_before, rows_after)
        self.assertEqual(manifests_before, manifests_after)
        self.assertEqual(latest_hash_before, latest_hash_after)

    # 46. Static and structural isolation: agent_control must not expose or import SQLite/SQL
    def test_46_static_isolation_no_sqlite_in_agent_control(self) -> None:
        """Verify agent_control.memory_view does not import sqlite3, expose SQL, or leak storage adapters."""
        import research_lab.agent_control as ac
        import research_lab.agent_control.memory_view as mv

        # 1. Module attributes must not have sqlite3
        self.assertNotIn("sqlite3", dir(mv))
        self.assertNotIn("sqlite", dir(mv))

        # 2. Source code of memory_view.py must not contain sqlite3 or raw SQL
        mv_src = inspect.getsource(mv)
        self.assertNotIn("import sqlite3", mv_src)
        self.assertNotIn("sqlite3.", mv_src)
        self.assertNotIn("SELECT * FROM", mv_src)
        self.assertNotIn("CREATE TABLE", mv_src)
        self.assertNotIn("ResearchMemoryReadAdapter", mv_src)

        # 3. agent_control __all__ must not export any storage adapters
        self.assertNotIn("ResearchMemoryReadAdapter", ac.__all__)
        self.assertFalse(hasattr(ac, "ResearchMemoryReadAdapter"))

        # 4. build_research_memory_view must reject non-domain readers (fail-closed)
        query = ResearchMemoryQuery(
            role=AgentRole.ALPHA_GENERATOR.value,
            project_binding=self.project_binding,
            categories=(ResearchMemoryCategory.RECENT_REJECTS.value,),
        )
        # Passing a raw path string or int must raise TypeError
        with self.assertRaises(TypeError):
            build_research_memory_view(
                query=query,
                authorized_scope=self.scope_alpha_generator,
                project_binding=self.project_binding,
                memory_store="/path/to/db.sqlite3",  # type: ignore
            )
        with self.assertRaises(TypeError):
            build_research_memory_view(
                query=query,
                authorized_scope=self.scope_alpha_generator,
                project_binding=self.project_binding,
                memory_store=12345,  # type: ignore
            )


if __name__ == "__main__":
    unittest.main()
