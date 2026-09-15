from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
import json

from research_lab.alpha_database import AlphaDatabase
from research_lab.astra import AstraDiscovery
from research_lab.runners import ExperimentRunner
from research_lab.schemas import ResearchMaterial, SolTaskInput, ValidationSpec
from research_lab.sol import SolOrchestrator, SolStateError
from research_lab.validation import WalkForwardValidationEngine


EXPERIMENT = {
    "schema_version": "research_lab.experiment.v1", "experiment_id": "sol-close-return-001",
    "strategy": {"name": "buy_and_hold"}, "factor": {"name": "close_return"},
    "features": [{"name": "close_return"}], "universe": ["DEMO"],
    "dataset": {"name": "fixture", "prices": [100.0, 101.0, 103.0, 106.0, 110.0, 115.0]},
    "parameters": {}, "execution": {"initial_capital": 1000.0, "position_size": 1.0},
    "cost_model": {"bps": 1.0}, "validation": {"method": "holdout"}, "output": {"format": "json"},
}


def task(root: Path, **changes: object):
    values = {
        "material_id": "sol-paper-001", "source_kind": "public_research", "title": "Sol handoff",
        "summary": "Explicit research input.", "evidence": ["paper section 2"],
        "factor_names": ["close_return"], "hypothesis": "Close returns predict a short horizon.",
        "economic_logic": "Delayed information diffusion.", "expected_edge": "Positive OOS return.",
        "required_data": ["daily close"], "validation_plan": ["Walk forward validation."],
        "experiment": EXPERIMENT, "created_at": datetime(2026, 9, 15, tzinfo=timezone.utc),
    }
    values.update(changes)
    return AstraDiscovery.local(root).discover(ResearchMaterial(**values))[1]


class SolOrchestratorTest(unittest.TestCase):
    def test_approved_cycle_persists_runner_result_and_alpha_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            plan = sol.receive(SolTaskInput(task=task(root)))
            self.assertEqual([event.status for event in plan.events], ["received", "planning", "pending_approval"])
            queued = sol.approve(plan.plan_id, approved_by="researcher")
            reviewed = sol.run_next()

            self.assertEqual(queued.status, "queued")
            self.assertEqual(reviewed.status, "review")
            self.assertEqual(reviewed.result_experiment_id, EXPERIMENT["experiment_id"])
            self.assertEqual(sol.workers()[0].worker_id, "local-runner-v1")
            self.assertEqual(json.loads((root / "sol" / "workers.json").read_text(encoding="utf-8"))[0]["kind"], "runner")
            self.assertEqual(sol.store.get(EXPERIMENT["experiment_id"]).status, "completed")
            self.assertIsNotNone(AlphaDatabase(sol.store.config).get_experiment(EXPERIMENT["experiment_id"]))
            archived = sol.archive(sol.review(reviewed.plan_id).plan_id)
            self.assertEqual(archived.status, "archived")

    def test_unapproved_and_blocked_astra_tasks_cannot_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            plan = sol.receive(SolTaskInput(task=task(root)))
            self.assertIsNone(sol.run_next())
            self.assertEqual(sol.get_plan(plan.plan_id).status, "pending_approval")
            with self.assertRaisesRegex(SolStateError, "only ready Astra tasks"):
                sol.receive(SolTaskInput(task=task(root, material_id="blocked-sol-001", hypothesis=None)))

    def test_failed_worker_requeues_only_within_explicit_limit(self) -> None:
        class BrokenAdapter:
            def run(self, _experiment):
                raise RuntimeError("engine unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            runner = ExperimentRunner.local(root, adapter=BrokenAdapter())
            sol = SolOrchestrator.local(root, runner)
            first = sol.receive(SolTaskInput(task=task(root), max_retries=1))
            sol.approve(first.plan_id, approved_by="researcher")
            retried = sol.run_next()
            failed = sol.run_next()

            self.assertEqual(retried.status, "queued")
            self.assertEqual(retried.retry_count, 1)
            self.assertIn("retry", [event.status for event in retried.events])
            self.assertEqual(failed.status, "failed")
            self.assertEqual(failed.retry_count, 1)
            self.assertEqual(sol.store.get(EXPERIMENT["experiment_id"]).status, "failed")

    def test_explicit_persisted_validation_triggers_critic_only_after_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            plan = sol.receive(SolTaskInput(task=task(root)))
            sol.approve(plan.plan_id, approved_by="researcher")
            review_plan = sol.run_next()
            skipped = sol.review(review_plan.plan_id)
            self.assertEqual(skipped.review_status, "skipped")
            self.assertIsNone(skipped.critic_review_id)
            with self.assertRaisesRegex(SolStateError, "existing persisted"):
                sol.attach_validation(review_plan.plan_id, "missing-validation-001")

            validation = WalkForwardValidationEngine.local(root).run(ValidationSpec(
                schema_version="research_lab.validation.v1", validation_id="sol-validation-001",
                method="walk_forward", train_size=2, test_size=2, step_size=2,
                experiment=task(root).experiment,
            ))
            attached = sol.attach_validation(review_plan.plan_id, validation.validation_id)
            reviewed = sol.review(attached.plan_id)
            self.assertEqual(reviewed.review_status, "reviewed")
            self.assertIsNotNone(reviewed.critic_review_id)
            self.assertIsNotNone(sol.store.get_critic_review(reviewed.critic_review_id))

    def test_receive_is_idempotent_and_illegal_transitions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            handoff = SolTaskInput(task=task(root))
            first = sol.receive(handoff)
            second = sol.receive(handoff)
            self.assertEqual(first, second)
            sol.approve(first.plan_id, approved_by="researcher")
            with self.assertRaisesRegex(SolStateError, "only pending_approval"):
                sol.approve(first.plan_id, approved_by="researcher")
            with self.assertRaisesRegex(SolStateError, "only review plans"):
                sol.archive(first.plan_id)


if __name__ == "__main__":
    unittest.main()
