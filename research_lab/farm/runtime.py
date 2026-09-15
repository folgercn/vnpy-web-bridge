from __future__ import annotations

import multiprocessing
from pathlib import Path

from research_lab.runners import ExperimentRunner
from research_lab.schemas import ExperimentResult, FarmClaim, FarmResultCallback, FarmTask, FarmWorker
from research_lab.sol import SolOrchestrator, SolStateError

from .queue import SQLiteTaskQueue


class WorkerRuntime:
    """Explicit local Farm worker facade. It never starts a persistent daemon."""

    def __init__(self, root: Path | str, *, worker_id: str, runner: ExperimentRunner | None = None,
                 queue: SQLiteTaskQueue | None = None) -> None:
        self.root = Path(root)
        self.worker_id = worker_id
        self.sol = SolOrchestrator.local(self.root, runner=runner)
        self.runner = self.sol.runner
        self.queue = queue or SQLiteTaskQueue(self.root / "farm" / "queue.sqlite3")

    def register(self) -> FarmWorker:
        return self.queue.register(FarmWorker(worker_id=self.worker_id))

    def heartbeat(self) -> FarmWorker:
        return self.queue.heartbeat(self.worker_id)

    def submit(self, plan_id: str) -> FarmTask:
        return self.sol.submit_to_farm(plan_id, self.queue)

    def claim_task(self, *, lease_seconds: int = 60) -> FarmClaim | None:
        self.reconcile()
        claim = self.queue.claim(self.worker_id, lease_seconds=lease_seconds)
        if claim is None:
            return None
        try:
            self.sol.claim_farm_task(claim.task, worker_id=self.worker_id)
        except Exception:
            self.queue.release(claim)
            raise
        return claim

    def reconcile(self) -> list[FarmTask]:
        """Explicitly settle queue rows already terminal in the bound Sol plan."""
        settled: list[FarmTask] = []
        for task in self.queue.claimed_tasks():
            plan = self.sol.get_plan(task.plan_id)
            if plan is None:
                continue
            if plan.status == "retry":
                plan = self.sol.resume_farm_retry(task)
            updated = self.queue.reconcile(task, plan)
            if updated.status != task.status:
                settled.append(updated)
        return settled

    def execute(self, claim: FarmClaim) -> ExperimentResult:
        plan = self.sol.get_plan(claim.task.plan_id)
        if (plan is None or plan.status != "running" or plan.worker_id != self.worker_id
                or plan.farm_task_id != claim.task.task_id or plan.farm_attempt != claim.attempt):
            raise SolStateError("Farm claim does not name an active Sol execution")
        return self.runner.run(plan.experiment)

    def report_result(self, claim: FarmClaim, result: ExperimentResult):
        callback = FarmResultCallback(task_id=claim.task.task_id, worker_id=self.worker_id, attempt=claim.attempt, result=result)
        task, _ = self.queue.commit_callback(callback, lambda active: self.sol.report_farm_result(active, callback))
        return task

    def run_once(self, *, lease_seconds: int = 60) -> FarmTask | None:
        self.heartbeat()
        claim = self.claim_task(lease_seconds=lease_seconds)
        if claim is None:
            return None
        try:
            result = self.execute(claim)
        except Exception as exc:
            message = str(exc)
            plan = self.sol.get_plan(claim.task.plan_id)
            if plan is None:
                raise
            result = ExperimentResult(experiment_id=plan.experiment.experiment_id, status="failed",
                                      strategy_name=plan.experiment.strategy.name, factor_name=plan.experiment.factor.name,
                                      error_code="FARM_EXECUTION_FAILED", error_message=message)
            # Execution exceptions have no persisted result and must not be trusted as a callback.
            callback = FarmResultCallback(task_id=claim.task.task_id, worker_id=self.worker_id,
                                          attempt=claim.attempt, result=result)
            task, _ = self.queue.commit_callback(
                callback, lambda active: self.sol.report_farm_exception(active, self.worker_id, claim.attempt, message),
            )
            return task
        return self.report_result(claim, result)


class LocalProcessWorker:
    """One explicitly invoked local child process for an otherwise idle runtime."""

    def __init__(self, root: Path | str, *, worker_id: str) -> None:
        self.root = str(Path(root))
        self.worker_id = worker_id

    def run_once(self, *, lease_seconds: int = 60, timeout_seconds: int = 30) -> int:
        process = multiprocessing.get_context("spawn").Process(target=_process_once,
            args=(self.root, self.worker_id, lease_seconds))
        process.start()
        process.join(timeout_seconds)
        if process.is_alive():
            process.terminate()
            process.join()
            raise TimeoutError("local Farm worker process did not finish")
        return process.exitcode or 0


def _process_once(root: str, worker_id: str, lease_seconds: int) -> None:
    runtime = WorkerRuntime(root, worker_id=worker_id)
    runtime.register()
    runtime.run_once(lease_seconds=lease_seconds)
