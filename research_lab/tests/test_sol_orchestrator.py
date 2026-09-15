from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
import json

from pydantic import ValidationError

from research_lab.alpha_database import AlphaDatabase
from research_lab.astra import AstraDiscovery
from research_lab.runners import ExperimentRunner
from research_lab.schemas import (
    ExperimentRecord, ExperimentResult, ResearchMaterial, SolTaskInput, ValidationSpec, WorkerDescriptor,
)
from research_lab.sol import CriticReviewAdapter, SolOrchestrator, SolStateError
from research_lab.sol.state_machine import require_transition, retry_permitted
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

    def test_injected_persisted_validation_reviewer_is_called(self) -> None:
        class RecordingReviewer:
            def __init__(self, store) -> None:
                self.store = store
                self.calls: list[tuple[str, str]] = []

            def review_persisted(self, validation_id: str, *, candidate_id: str):
                self.calls.append((validation_id, candidate_id))
                return CriticReviewAdapter(self.store).review_persisted(
                    validation_id, candidate_id=candidate_id,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            runner = ExperimentRunner.local(root)
            reviewer = RecordingReviewer(runner.store)
            sol = SolOrchestrator.local(root, runner=runner, reviewer=reviewer)
            plan = sol.receive(SolTaskInput(task=task(root)))
            sol.approve(plan.plan_id, approved_by="researcher")
            review_plan = sol.run_next()
            validation = WalkForwardValidationEngine.local(root).run(ValidationSpec(
                schema_version="research_lab.validation.v1", validation_id="sol-adapter-validation-001",
                method="walk_forward", train_size=2, test_size=2, step_size=2,
                experiment=task(root).experiment,
            ))
            reviewed = sol.review(sol.attach_validation(review_plan.plan_id, validation.validation_id).plan_id)

            self.assertEqual(reviewer.calls, [(validation.validation_id, EXPERIMENT["experiment_id"])])
            self.assertIsNotNone(sol.store.get_critic_review(reviewed.critic_review_id))

    def test_default_critic_adapter_and_worker_capabilities_remain_local_metadata(self) -> None:
        class DeclaredWorker:
            descriptor = WorkerDescriptor(
                worker_id="zzz-declared", available=False,
                capabilities={
                    "cpu_cores": 8, "memory_mib": 16384,
                    "supported_engines": ["deterministic"],
                    "supported_datasets": ["special-dataset"],
                    "supported_features": ["special-feature"],
                },
            )

            def execute(self, _plan):
                raise AssertionError("unavailable declared worker must not execute")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            self.assertIsInstance(sol.reviewer, CriticReviewAdapter)
            sol.register_worker(DeclaredWorker())

            persisted = {item.worker_id: item for item in sol.workers()}["zzz-declared"]
            self.assertEqual(persisted.capabilities.cpu_cores, 8)
            self.assertEqual(persisted.capabilities.supported_features, ["special-feature"])
            self.assertEqual(sol.workers()[0].capabilities.supported_engines, ["deterministic"])
            self.assertEqual(sol._select_worker().descriptor.worker_id, "local-runner-v1")
            with self.assertRaises(ValidationError):
                WorkerDescriptor(worker_id="invalid-capability", capabilities={"supported_engines": ["remote"]})

    def test_state_machine_rejects_illegal_transition_and_retry_limit(self) -> None:
        with self.assertRaisesRegex(SolStateError, "illegal Sol transition"):
            require_transition("pending_approval", "review")
        self.assertTrue(retry_permitted(0, 1))
        self.assertFalse(retry_permitted(1, 1))

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

    def test_tampered_plan_json_cannot_bypass_human_approval_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            plan = sol.receive(SolTaskInput(task=task(root)))
            path = root / "sol" / "plans" / f"{plan.plan_id}.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["status"] = "queued"
            payload["events"].append({
                "status": "queued", "reason": "forged approval",
                "created_at": "2026-09-15T00:00:00Z", "previous_hash": None, "integrity_hash": "forged",
            })
            path.write_text(json.dumps(payload), encoding="utf-8")

            restarted = SolOrchestrator.local(root)
            with self.assertRaisesRegex(SolStateError, "integrity error"):
                restarted.get_plan(plan.plan_id)
            with self.assertRaisesRegex(SolStateError, "integrity error"):
                restarted.run_next()

    def test_receive_rejects_an_astra_task_not_equal_to_the_persisted_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            stored_task = task(root)
            tampered = stored_task.model_copy(update={"evidence": [*stored_task.evidence, "forged evidence"]})
            with self.assertRaisesRegex(SolStateError, "does not match"):
                SolOrchestrator.local(root).receive(SolTaskInput(task=tampered))

    def test_forged_completed_worker_callback_cannot_enter_review(self) -> None:
        class ForgedWorker:
            descriptor = WorkerDescriptor(worker_id="aaa-forged")

            def execute(self, plan):
                return ExperimentResult(
                    experiment_id=plan.experiment.experiment_id, status="completed",
                    strategy_name=plan.experiment.strategy.name, factor_name=plan.experiment.factor.name,
                    metrics={"total_return": 1.0, "sharpe": 1.0, "max_drawdown": 0.0,
                             "turnover": 0.0, "transaction_cost": 0.0, "final_equity": 2000.0},
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            plan = sol.receive(SolTaskInput(task=task(root)))
            sol.approve(plan.plan_id, approved_by="researcher")
            sol.register_worker(ForgedWorker())
            failed = sol.run_next()

            self.assertEqual(failed.status, "failed")
            self.assertIn("not the matching persisted", failed.error_message)
            self.assertIsNone(sol.store.get(EXPERIMENT["experiment_id"]))

    def test_stale_alpha_record_with_same_experiment_id_cannot_enter_review(self) -> None:
        class StoredResultWorker:
            descriptor = WorkerDescriptor(worker_id="aaa-stored")

            def __init__(self, result):
                self.result = result

            def execute(self, _plan):
                return self.result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol = SolOrchestrator.local(root)
            plan = sol.receive(SolTaskInput(task=task(root)))
            stored = sol.store.save(ExperimentResult(
                experiment_id=EXPERIMENT["experiment_id"], status="completed", strategy_name="buy_and_hold",
                factor_name="close_return", metrics={"total_return": 0.1, "sharpe": 1.0, "max_drawdown": 0.1,
                                                      "turnover": 1.0, "transaction_cost": 1.0, "final_equity": 1100.0},
            ))
            database = AlphaDatabase(sol.store.config)
            database.save_experiment(ExperimentRecord(
                experiment_id=stored.experiment_id, status="completed", strategy_name="flat",
                factor_name="stale_factor", result_artifact=stored.artifact_location,
                report_location=stored.report_location, metrics=stored.metrics.model_dump(),
            ))
            sol.approve(plan.plan_id, approved_by="researcher")
            sol.register_worker(StoredResultWorker(stored))
            failed = sol.run_next()

            self.assertEqual(failed.status, "failed")
            self.assertIn("not the matching persisted", failed.error_message)
            self.assertEqual(database.get_experiment(stored.experiment_id).factor_name, "stale_factor")


if __name__ == "__main__":
    unittest.main()
