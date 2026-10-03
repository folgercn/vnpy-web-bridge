from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import time
import unittest

from research_lab.astra import AstraDiscovery
from research_lab.farm import FarmQueueError, LocalProcessWorker, SQLiteTaskQueue, WorkerRuntime
from research_lab.runners import ExperimentRunner
from research_lab.schemas import ExperimentResult, ResearchMaterial, SolTaskInput
from research_lab.sol import SolOrchestrator, SolStateError


EXPERIMENT = {
    "schema_version": "research_lab.experiment.v1", "experiment_id": "farm-close-return-001",
    "strategy": {"name": "buy_and_hold"}, "factor": {"name": "close_return"},
    "features": [{"name": "close_return"}], "universe": ["DEMO"],
    "dataset": {"name": "fixture", "prices": [100.0, 101.0, 103.0, 106.0, 110.0, 115.0]},
    "parameters": {}, "execution": {"initial_capital": 1000.0, "position_size": 1.0},
    "cost_model": {"bps": 1.0}, "validation": {"method": "holdout"}, "output": {"format": "json"},
}


def ready_plan(root: Path, *, max_retries: int = 0):
    material = ResearchMaterial(
        material_id="farm-paper-001", source_kind="public_research", title="Farm handoff",
        summary="Explicit research input.", evidence=["paper section 2"], factor_names=["close_return"],
        hypothesis="Close returns predict a short horizon.", economic_logic="Delayed information diffusion.",
        expected_edge="Positive OOS return.", required_data=["daily close"], validation_plan=["Walk forward validation."],
        experiment=EXPERIMENT, created_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
    )
    task = AstraDiscovery.local(root).discover(material)[1]
    sol = SolOrchestrator.local(root)
    plan = sol.receive(SolTaskInput(task=task, max_retries=max_retries))
    return sol, sol.approve(plan.plan_id, approved_by="researcher")


class ResearchFarmRuntimeTest(unittest.TestCase):
    def test_submit_requires_an_approved_queued_sol_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            _, approved = ready_plan(root)
            runtime = WorkerRuntime(root, worker_id="farm-worker-a")
            runtime.register()
            submitted = runtime.submit(approved.plan_id)
            self.assertEqual(submitted.plan_id, approved.plan_id)
            self.assertEqual(submitted.plan_integrity_hash, approved.integrity_hash)
            with self.assertRaisesRegex(SolStateError, "plan not found"):
                runtime.submit("missing-plan")

    def test_two_workers_cannot_double_claim_and_queue_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            _, approved = ready_plan(root)
            first = WorkerRuntime(root, worker_id="farm-worker-a")
            second = WorkerRuntime(root, worker_id="farm-worker-b")
            first.register()
            second.register()
            first.submit(approved.plan_id)
            claim = first.claim_task()
            self.assertIsNotNone(claim)
            self.assertIsNone(second.claim_task())
            restarted = SQLiteTaskQueue(root / "farm" / "queue.sqlite3")
            self.assertEqual({worker.worker_id for worker in restarted.workers()}, {"farm-worker-a", "farm-worker-b"})
            self.assertEqual(restarted.get_task(claim.task.task_id).worker_id, "farm-worker-a")

    def test_expired_lease_is_reclaimed_and_old_attempt_callback_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            _, approved = ready_plan(root)
            first = WorkerRuntime(root, worker_id="farm-worker-a")
            second = WorkerRuntime(root, worker_id="farm-worker-b")
            first.register()
            second.register()
            first.submit(approved.plan_id)
            old = first.claim_task(lease_seconds=1)
            self.assertIsNotNone(old)
            time.sleep(1.05)
            current = second.claim_task()
            self.assertEqual(current.attempt, 2)
            forged = ExperimentResult(experiment_id=EXPERIMENT["experiment_id"], status="completed", strategy_name="buy_and_hold",
                                      factor_name="close_return", metrics={"total_return": 0.0, "sharpe": 0.0, "max_drawdown": 0.0,
                                                                              "turnover": 0.0, "transaction_cost": 0.0, "final_equity": 1000.0})
            with self.assertRaisesRegex(FarmQueueError, "active Farm claim attempt"):
                first.report_result(old, forged)

    def test_same_worker_restart_cannot_commit_an_old_attempt_over_the_reclaim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            _, approved = ready_plan(root)
            worker = WorkerRuntime(root, worker_id="farm-worker-restarted")
            worker.register()
            worker.submit(approved.plan_id)
            old = worker.claim_task(lease_seconds=1)
            time.sleep(1.05)
            current = worker.claim_task()
            self.assertEqual((old.attempt, current.attempt), (1, 2))
            result = worker.execute(current)

            with self.assertRaisesRegex(FarmQueueError, "active Farm claim attempt"):
                worker.report_result(old, result)
            running = SolOrchestrator.local(root).get_plan(approved.plan_id)
            self.assertEqual((running.status, running.worker_id, running.farm_attempt),
                             ("running", "farm-worker-restarted", 2))

            completed = worker.report_result(current, result)
            self.assertEqual(completed.status, "completed")
            self.assertEqual(SolOrchestrator.local(root).get_plan(approved.plan_id).status, "review")

    def test_restart_reconciles_after_sol_commit_before_queue_update_without_reexecution(self) -> None:
        class InterruptedQueue(SQLiteTaskQueue):
            def _before_callback_update(self, _task, _plan) -> None:
                raise RuntimeError("simulated queue write interruption")

        class MustNotExecuteAdapter:
            def run(self, _experiment):
                raise AssertionError("reconciliation must not execute the experiment again")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol, approved = ready_plan(root)
            queue_path = root / "farm" / "queue.sqlite3"
            interrupted = WorkerRuntime(root, worker_id="farm-worker-a", queue=InterruptedQueue(queue_path))
            interrupted.register()
            interrupted.submit(approved.plan_id)
            claim = interrupted.claim_task()
            result = interrupted.execute(claim)
            with self.assertRaisesRegex(RuntimeError, "queue write interruption"):
                interrupted.report_result(claim, result)

            self.assertEqual(sol.get_plan(approved.plan_id).status, "review")
            self.assertEqual(SQLiteTaskQueue(queue_path).get_task(claim.task.task_id).status, "claimed")
            restarted = WorkerRuntime(root, worker_id="farm-worker-a",
                                      runner=ExperimentRunner.local(root, adapter=MustNotExecuteAdapter()))
            restarted.register()
            self.assertEqual([task.status for task in restarted.reconcile()], ["completed"])
            self.assertIsNone(restarted.claim_task())
            self.assertEqual(SQLiteTaskQueue(queue_path).get_task(claim.task.task_id).status, "completed")

    def test_restart_resumes_persisted_retry_then_requeues_without_executing_during_recovery(self) -> None:
        class MustNotExecuteAdapter:
            def run(self, _experiment):
                raise AssertionError("retry reconciliation must not execute the experiment")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol, approved = ready_plan(root, max_retries=1)
            runtime = WorkerRuntime(root, worker_id="farm-worker-a")
            runtime.register()
            runtime.submit(approved.plan_id)
            claim = runtime.claim_task()
            running = sol.get_plan(approved.plan_id)
            failed = sol._transition(running, "failed", "simulated persisted Farm failure")
            retried = sol._transition(failed, "retry", "simulated interruption after retry persistence", retry_count=1)
            self.assertEqual(retried.status, "retry")

            restarted = WorkerRuntime(root, worker_id="farm-worker-a",
                                      runner=ExperimentRunner.local(root, adapter=MustNotExecuteAdapter()))
            restarted.register()
            self.assertEqual([task.status for task in restarted.reconcile()], ["queued"])
            recovered = SolOrchestrator.local(root).get_plan(approved.plan_id)
            self.assertEqual((recovered.status, recovered.retry_count), ("queued", 1))
            self.assertEqual(SQLiteTaskQueue(root / "farm" / "queue.sqlite3").get_task(claim.task.task_id).status, "queued")

            executable = WorkerRuntime(root, worker_id="farm-worker-a")
            executable.register()
            retry_claim = executable.claim_task()
            self.assertEqual(retry_claim.attempt, 2)
            self.assertEqual(executable.report_result(retry_claim, executable.execute(retry_claim)).status, "completed")
            self.assertEqual(SolOrchestrator.local(root).get_plan(approved.plan_id).status, "review")

    def test_independent_local_process_executes_and_callbacks_to_sol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            sol, approved = ready_plan(root)
            submitter = WorkerRuntime(root, worker_id="farm-worker-parent")
            submitter.register()
            submitter.submit(approved.plan_id)
            process = LocalProcessWorker(root, worker_id="farm-worker-child")
            self.assertEqual(process.run_once(), 0)
            current = sol.get_plan(approved.plan_id)
            self.assertEqual(current.status, "review")
            queued = SQLiteTaskQueue(root / "farm" / "queue.sqlite3").get_task(f"farm-{approved.plan_id}")
            self.assertEqual(queued.status, "completed")

    def test_forged_callback_requires_matching_persisted_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            _, approved = ready_plan(root)
            runtime = WorkerRuntime(root, worker_id="farm-worker-a")
            runtime.register()
            runtime.submit(approved.plan_id)
            claim = runtime.claim_task()
            forged = ExperimentResult(experiment_id=EXPERIMENT["experiment_id"], status="completed", strategy_name="buy_and_hold",
                                      factor_name="close_return", metrics={"total_return": 2.0, "sharpe": 2.0, "max_drawdown": 0.0,
                                                                              "turnover": 0.0, "transaction_cost": 0.0, "final_equity": 3000.0})
            with self.assertRaisesRegex(SolStateError, "matching persisted"):
                runtime.report_result(claim, forged)
            self.assertEqual(SolOrchestrator.local(root).get_plan(approved.plan_id).status, "running")

    def test_failed_result_follows_sol_retry_and_terminal_state(self) -> None:
        class BrokenAdapter:
            def run(self, _experiment):
                raise RuntimeError("engine unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            _, approved = ready_plan(root, max_retries=1)
            runtime = WorkerRuntime(root, worker_id="farm-worker-a", runner=ExperimentRunner.local(root, adapter=BrokenAdapter()))
            runtime.register()
            runtime.submit(approved.plan_id)
            first = runtime.run_once()
            self.assertEqual(first.status, "queued")
            self.assertEqual(SolOrchestrator.local(root).get_plan(approved.plan_id).retry_count, 1)
            second = runtime.run_once()
            self.assertEqual(second.status, "failed")
            self.assertEqual(SolOrchestrator.local(root).get_plan(approved.plan_id).status, "failed")


if __name__ == "__main__":
    unittest.main()
