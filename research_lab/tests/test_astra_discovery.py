from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from pydantic import ValidationError

from research_lab.alpha_database import AlphaDatabase
from research_lab.astra import AstraDiscovery
from research_lab.config import ResearchLabConfig
from research_lab.schemas import AlphaIdea, FailurePattern, LiteratureReference, ResearchMaterial


EXPERIMENT = {
    "schema_version": "research_lab.experiment.v1",
    "experiment_id": "astra-close-return-001",
    "strategy": {"name": "buy_and_hold"},
    "factor": {"name": "close_return"},
    "features": [{"name": "close_return"}],
    "universe": ["DEMO"],
    "dataset": {"name": "fixture", "prices": [100.0, 101.0, 103.0]},
    "parameters": {}, "execution": {"initial_capital": 1000.0, "position_size": 1.0},
    "cost_model": {"bps": 1.0}, "validation": {"method": "holdout"}, "output": {"format": "json"},
}


def material(**changes: object) -> ResearchMaterial:
    values = {
        "material_id": "paper-close-return-001", "source_kind": "public_research",
        "title": "Close return hypothesis", "summary": "A supplied paper summary.",
        "evidence": ["section 2 documents the stated mechanism"], "factor_names": ["close_return"],
        "hypothesis": "Prior close returns contain short-horizon directional information.",
        "economic_logic": "Slow information diffusion can create a delayed price response.",
        "expected_edge": "Positive risk-adjusted OOS return after stated costs.",
        "required_data": ["timestamped daily close prices"],
        "validation_plan": ["Use an untouched holdout period with non-zero costs."],
        "experiment": EXPERIMENT,
        "created_at": datetime(2026, 9, 15, tzinfo=timezone.utc),
    }
    values.update(changes)
    return ResearchMaterial(**values)


class AstraDiscoveryTest(unittest.TestCase):
    def test_material_generates_evidence_linked_proposal_and_runnable_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            discovery = AstraDiscovery.local(Path(directory) / "output")
            proposal, task = discovery.discover(material())

            self.assertEqual(proposal.status, "ready")
            self.assertEqual(proposal.hypothesis, material().hypothesis)
            self.assertIn("material:paper-close-return-001", proposal.evidence)
            self.assertEqual(task.status, "ready")
            self.assertIsNotNone(task.experiment)
            self.assertEqual(task.experiment.factor.name, "close_return")
            self.assertEqual(discovery.get_task(task.task_id), task)
            self.assertEqual(discovery.query_proposals(status="ready"), [proposal])
            self.assertEqual(discovery.query_tasks(proposal_id=proposal.proposal_id), [task])

    def test_alpha_database_history_is_linked_and_critical_failure_blocks_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            database = AlphaDatabase(ResearchLabConfig(root))
            database.save_idea(AlphaIdea(
                idea_id="idea-close-return-001", title="Existing idea", hypothesis="Recorded idea",
                factor_names=["close_return"],
            ))
            database.save_literature_reference(LiteratureReference(
                reference_id="literature-close-return-001", title="Reference", citation="Author (2026)",
                factor_names=["close_return"],
            ))
            database.save_failure_pattern(FailurePattern(
                pattern_id="failure-close-return-001", source_kind="experiment", source_id="old-run-001",
                factor_name="close_return", category="BACKTEST_FAILED", severity="critical",
                summary="Recorded historical failure.", evidence=["engine unavailable"],
            ))
            proposal, task = AstraDiscovery.local(root).discover(material())

            self.assertEqual(proposal.related_idea_ids, ["idea-close-return-001"])
            self.assertEqual(proposal.related_literature_ids, ["literature-close-return-001"])
            self.assertEqual(proposal.related_failure_pattern_ids, ["failure-close-return-001"])
            self.assertIn("HISTORICAL_CRITICAL_FAILURE:failure-close-return-001", proposal.blocked_reasons)
            self.assertEqual(task.status, "blocked")
            self.assertIsNone(task.experiment)

    def test_missing_evidence_or_experiment_is_blocked_without_inventing_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proposal, task = AstraDiscovery.local(Path(directory) / "output").discover(material(
                material_id="incomplete-material-001", hypothesis=None, experiment=None,
            ))

            self.assertEqual(proposal.status, "blocked")
            self.assertIn("MISSING_HYPOTHESIS: explicit hypothesis is required for a research proposal.", proposal.blocked_reasons)
            self.assertEqual(task.status, "blocked")
            self.assertIsNone(task.experiment)
            self.assertTrue(any(reason.startswith("MISSING_EXPERIMENT_SPEC") for reason in task.blocked_reasons))

    def test_ingest_and_discovery_are_idempotent_and_materials_are_queryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            discovery = AstraDiscovery.local(Path(directory) / "output")
            first_material = discovery.ingest(material())
            second_material = discovery.ingest(material())
            first_proposal, first_task = discovery.discover(material())
            second_proposal, second_task = discovery.discover(material())

            self.assertEqual(first_material.content_hash, second_material.content_hash)
            self.assertEqual(first_proposal.content_hash, second_proposal.content_hash)
            self.assertEqual(first_task.content_hash, second_task.content_hash)
            self.assertEqual(discovery.query_materials(factor_name="close_return"), [first_material])
            self.assertEqual(len(list((discovery.root / "materials").glob("*.json"))), 1)
            self.assertEqual(len(list((discovery.root / "proposals").glob("*.json"))), 1)
            self.assertEqual(len(list((discovery.root / "tasks").glob("*.json"))), 1)

    def test_explicit_market_anomaly_is_ingested_without_live_data_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            discovery = AstraDiscovery.local(Path(directory) / "output")
            observed = material(
                material_id="anomaly-close-return-001", source_kind="market_anomaly",
                observed_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
            )
            discovery.ingest(observed)

            self.assertEqual(discovery.query_materials(source_kind="market_anomaly"), [observed.model_copy(update={"content_hash": discovery.get_material(observed.material_id).content_hash})])

    def test_blank_evidence_and_ready_inputs_are_rejected(self) -> None:
        for field in ("evidence", "factor_names", "required_data", "validation_plan"):
            with self.subTest(field=field), self.assertRaisesRegex(ValidationError, "must not be blank"):
                material(**{field: [" "]})

    def test_same_material_identity_and_timestamp_keeps_distinct_auditable_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            discovery = AstraDiscovery.local(Path(directory) / "output")
            ready_proposal, ready_task = discovery.discover(material())
            blocked_proposal, blocked_task = discovery.discover(material(
                hypothesis=None,
            ))

            self.assertNotEqual(ready_proposal.proposal_id, blocked_proposal.proposal_id)
            self.assertNotEqual(ready_task.task_id, blocked_task.task_id)
            self.assertEqual(ready_proposal.status, "ready")
            self.assertEqual(blocked_proposal.status, "blocked")
            self.assertEqual(ready_task.status, "ready")
            self.assertEqual(blocked_task.status, "blocked")
            self.assertEqual(discovery.get_proposal(ready_proposal.proposal_id), ready_proposal)
            self.assertEqual(discovery.get_proposal(blocked_proposal.proposal_id), blocked_proposal)
            self.assertEqual(discovery.get_task(ready_task.task_id), ready_task)
            self.assertEqual(discovery.get_task(blocked_task.task_id), blocked_task)
            self.assertEqual(
                discovery.get_material(ready_proposal.material_id, content_hash=ready_proposal.material_content_hash),
                material().model_copy(update={"content_hash": ready_proposal.material_content_hash}),
            )
            self.assertEqual(
                discovery.get_material(blocked_proposal.material_id, content_hash=blocked_proposal.material_content_hash),
                material(hypothesis=None).model_copy(update={"content_hash": blocked_proposal.material_content_hash}),
            )
            with self.assertRaisesRegex(ValueError, "content_hash is required"):
                discovery.get_material("paper-close-return-001")

    def test_alpha_history_change_creates_a_new_proposal_and_task_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            discovery = AstraDiscovery.local(root)
            ready_proposal, ready_task = discovery.discover(material())
            database = AlphaDatabase(ResearchLabConfig(root))
            database.save_failure_pattern(FailurePattern(
                pattern_id="failure-after-discovery-001", source_kind="experiment", source_id="old-run-002",
                factor_name="close_return", category="BACKTEST_FAILED", severity="critical",
                summary="A later recorded failure.", evidence=["recorded after the first discovery"],
            ))
            blocked_proposal, blocked_task = discovery.discover(material())

            self.assertEqual(ready_proposal.status, "ready")
            self.assertEqual(blocked_proposal.status, "blocked")
            self.assertNotEqual(ready_proposal.proposal_id, blocked_proposal.proposal_id)
            self.assertNotEqual(ready_task.task_id, blocked_task.task_id)
            self.assertEqual(discovery.get_proposal(blocked_proposal.proposal_id), blocked_proposal)
            self.assertEqual(discovery.get_task(ready_task.task_id), ready_task)
            self.assertEqual(discovery.get_task(blocked_task.task_id), blocked_task)


if __name__ == "__main__":
    unittest.main()
