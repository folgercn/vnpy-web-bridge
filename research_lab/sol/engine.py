from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from research_lab.config import ResearchLabConfig
from research_lab.critic import CriticAgent
from research_lab.database import ResultStore
from research_lab.runners import ExperimentRunner
from research_lab.schemas import ExperimentPlan, ExperimentResult, PlanEvent, SolTaskInput, WorkerDescriptor


class SolStateError(ValueError):
    """Raised when a caller requests a lifecycle transition without evidence."""


class RunnerWorker(Protocol):
    descriptor: WorkerDescriptor

    def execute(self, plan: ExperimentPlan) -> ExperimentResult: ...


class LocalRunnerWorker:
    """Explicit in-process adapter around the existing ExperimentRunner."""

    def __init__(self, runner: ExperimentRunner, worker_id: str = "local-runner-v1") -> None:
        self.runner = runner
        self.descriptor = WorkerDescriptor(worker_id=worker_id)

    def execute(self, plan: ExperimentPlan) -> ExperimentResult:
        return self.runner.run(plan.experiment)


class SolOrchestrator:
    """Local, call-driven ResearchTask lifecycle manager.

    It does not start a daemon, choose candidates, promote/deploy/trade, or let
    Astra invoke a runner. Every execution begins only through ``run_next``.
    """

    def __init__(self, config: ResearchLabConfig, runner: ExperimentRunner | None = None) -> None:
        self.config = config
        self.store = runner.store if runner is not None else ResultStore(config)
        self.runner = runner or ExperimentRunner(self.store)
        self.root = config.root / "sol"
        self.plans_dir = self.root / "plans"
        self.plans_dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.root / "workers.json"
        self._workers: dict[str, RunnerWorker] = {}
        self.register_worker(LocalRunnerWorker(self.runner))

    @classmethod
    def local(cls, root: Path | str, runner: ExperimentRunner | None = None) -> "SolOrchestrator":
        return cls(ResearchLabConfig(Path(root)), runner)

    def register_worker(self, worker: RunnerWorker) -> WorkerDescriptor:
        self._workers[worker.descriptor.worker_id] = worker
        self._write_json(self.registry_path, [item.model_dump(mode="json") for item in self._worker_descriptors()])
        return worker.descriptor

    def workers(self) -> list[WorkerDescriptor]:
        if not self.registry_path.exists():
            return []
        return [WorkerDescriptor.model_validate(item) for item in json.loads(self.registry_path.read_text(encoding="utf-8"))]

    def receive(self, handoff: SolTaskInput) -> ExperimentPlan:
        task = handoff.task
        if task.status != "ready" or task.experiment is None:
            raise SolStateError("only ready Astra tasks with an ExperimentSpec can be received")
        if not task.content_hash:
            raise SolStateError("Astra task content_hash is required for an auditable handoff")
        plan_id = _plan_id(task.task_id, task.content_hash)
        existing = self.get_plan(plan_id)
        if existing is not None:
            if existing.task_content_hash != task.content_hash:
                raise SolStateError("plan identity collision")
            return existing
        events = [
            PlanEvent(status="received", reason="received explicit ready Astra task version"),
            PlanEvent(status="planning", reason="created deterministic experiment plan from supplied ExperimentSpec"),
            PlanEvent(status="pending_approval", reason="human approval is required before dispatch"),
        ]
        return self._save(ExperimentPlan(
            plan_id=plan_id, task_id=task.task_id, task_content_hash=task.content_hash,
            proposal_id=task.proposal_id, proposal_content_hash=task.proposal_content_hash,
            experiment=task.experiment, status="pending_approval", max_retries=handoff.max_retries,
            events=events,
        ))

    def get_plan(self, plan_id: str) -> ExperimentPlan | None:
        path = self.plans_dir / f"{plan_id}.json"
        return ExperimentPlan.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else None

    def query_plans(self, *, status: str | None = None) -> list[ExperimentPlan]:
        plans = [ExperimentPlan.model_validate_json(path.read_text(encoding="utf-8")) for path in sorted(self.plans_dir.glob("*.json"))]
        return [plan for plan in plans if status is None or plan.status == status]

    def approve(self, plan_id: str, *, approved_by: str) -> ExperimentPlan:
        plan = self._required(plan_id)
        if plan.status != "pending_approval":
            raise SolStateError("only pending_approval plans can be approved")
        if not approved_by.strip():
            raise SolStateError("approved_by is required")
        return self._transition(plan, "queued", "human approval recorded", approved_by=approved_by.strip(), approved_at=datetime.now(timezone.utc))

    def run_next(self) -> ExperimentPlan | None:
        plan = next(iter(self.query_plans(status="queued")), None)
        if plan is None:
            return None
        worker = self._select_worker()
        running = self._transition(plan, "running", f"explicit run_next dispatched to {worker.descriptor.worker_id}", worker_id=worker.descriptor.worker_id)
        try:
            result = worker.execute(running)
        except Exception as exc:
            return self._handle_failure(running, str(exc))
        if result.status == "completed":
            return self._transition(running, "review", "runner completed and persisted result", result_experiment_id=result.experiment_id, review_status="awaiting_validation")
        return self._handle_failure(running, result.error_message or result.error_code or "runner failed", result.experiment_id)

    def _handle_failure(self, plan: ExperimentPlan, message: str, result_experiment_id: str | None = None) -> ExperimentPlan:
        failed = self._transition(plan, "failed", "runner returned failed result", result_experiment_id=result_experiment_id, error_message=message)
        if failed.retry_count >= failed.max_retries:
            return failed
        retry = self._transition(failed, "retry", "retry policy permits another explicit attempt", retry_count=failed.retry_count + 1)
        return self._transition(retry, "queued", "retry requeued; explicit run_next remains required")

    def attach_validation(self, plan_id: str, validation_id: str) -> ExperimentPlan:
        plan = self._required(plan_id)
        if plan.status != "review":
            raise SolStateError("validation can only attach during review")
        if self.store.get_validation(validation_id) is None:
            raise SolStateError("validation_id must name an existing persisted ValidationResult")
        return self._save(plan.model_copy(update={"validation_id": validation_id, "review_status": "awaiting_validation"}))

    def review(self, plan_id: str) -> ExperimentPlan:
        plan = self._required(plan_id)
        if plan.status != "review":
            raise SolStateError("only completed plans in review can be reviewed")
        if plan.validation_id is None:
            return self._save(plan.model_copy(update={"review_status": "skipped", "events": [*plan.events, PlanEvent(status="review", reason="Critic skipped: no explicit persisted validation_id attached")]}))
        review = CriticAgent(self.store).review_persisted(plan.validation_id, candidate_id=plan.experiment.experiment_id)
        return self._save(plan.model_copy(update={"critic_review_id": review.review_id, "review_status": "reviewed", "events": [*plan.events, PlanEvent(status="review", reason=f"Critic reviewed persisted validation {plan.validation_id}")]}))

    def archive(self, plan_id: str) -> ExperimentPlan:
        plan = self._required(plan_id)
        if plan.status != "review":
            raise SolStateError("only review plans can be archived")
        if plan.review_status not in {"reviewed", "skipped"}:
            raise SolStateError("review must be explicitly completed or skipped before archive")
        return self._transition(plan, "archived", "research lifecycle archived; this is not a promotion or deployment decision")

    def _select_worker(self) -> RunnerWorker:
        available = [worker for worker in self._workers.values() if worker.descriptor.available]
        if not available:
            raise SolStateError("no available local runner worker")
        return sorted(available, key=lambda item: item.descriptor.worker_id)[0]

    def _required(self, plan_id: str) -> ExperimentPlan:
        plan = self.get_plan(plan_id)
        if plan is None:
            raise SolStateError(f"plan not found: {plan_id}")
        return plan

    def _transition(self, plan: ExperimentPlan, status: str, reason: str, **updates: object) -> ExperimentPlan:
        payload = {**updates, "status": status, "events": [*plan.events, PlanEvent(status=status, reason=reason)]}
        return self._save(plan.model_copy(update=payload))

    def _save(self, plan: ExperimentPlan) -> ExperimentPlan:
        path = self.plans_dir / f"{plan.plan_id}.json"
        self._write_json(path, plan.model_dump(mode="json"))
        return plan

    def _worker_descriptors(self) -> list[WorkerDescriptor]:
        return [worker.descriptor for _, worker in sorted(self._workers.items())]

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        temporary = path.with_suffix(".json.tmp")
        try:
            temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def _plan_id(task_id: str, content_hash: str) -> str:
    prefix = f"sol-{task_id}-{content_hash[:12]}"
    return prefix if len(prefix) <= 128 else f"sol-{hashlib.sha256(prefix.encode()).hexdigest()[:32]}"
