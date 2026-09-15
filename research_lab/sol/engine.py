from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from research_lab.config import ResearchLabConfig
from research_lab.alpha_database import AlphaDatabase
from research_lab.astra import AstraDiscovery
from research_lab.database import ResultStore
from research_lab.runners import ExperimentRunner
from research_lab.schemas import ExperimentPlan, ExperimentRecord, ExperimentResult, PlanEvent, SolTaskInput, WorkerDescriptor
from research_lab.schemas.sol import PlanStatus
from .review import CriticReviewAdapter, PersistedValidationReviewer
from .state_machine import SolStateError, require_transition, retry_permitted, validate_state_chain


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

    def __init__(
        self,
        config: ResearchLabConfig,
        runner: ExperimentRunner | None = None,
        reviewer: PersistedValidationReviewer | None = None,
    ) -> None:
        self.config = config
        self.store = runner.store if runner is not None else ResultStore(config)
        self.runner = runner or ExperimentRunner(self.store)
        self.root = config.root / "sol"
        self.plans_dir = self.root / "plans"
        self.plans_dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.root / "workers.json"
        self.integrity_key_path = self.root / ".plan-integrity.key"
        self._integrity_key = self._load_integrity_key()
        self._workers: dict[str, RunnerWorker] = {}
        self.reviewer = reviewer or CriticReviewAdapter(self.store)
        self.register_worker(LocalRunnerWorker(self.runner))

    @classmethod
    def local(
        cls,
        root: Path | str,
        runner: ExperimentRunner | None = None,
        reviewer: PersistedValidationReviewer | None = None,
    ) -> "SolOrchestrator":
        return cls(ResearchLabConfig(Path(root)), runner, reviewer)

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
        discovery = AstraDiscovery(self.config)
        persisted_task = discovery.get_task(task.task_id, content_hash=task.content_hash)
        persisted_proposal = discovery.get_proposal(task.proposal_id, content_hash=task.proposal_content_hash)
        if persisted_task is None or persisted_proposal is None:
            raise SolStateError("Astra task and proposal versions must be persisted before Sol can receive them")
        if persisted_task != task or (
            persisted_task.proposal_id != persisted_proposal.proposal_id
            or persisted_task.proposal_content_hash != persisted_proposal.content_hash
        ):
            raise SolStateError("Astra handoff does not match its persisted task/proposal versions")
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
        if not path.exists():
            return None
        try:
            plan = ExperimentPlan.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SolStateError(f"invalid plan JSON: {plan_id}") from exc
        self._verify_plan(plan)
        return plan

    def query_plans(self, *, status: str | None = None) -> list[ExperimentPlan]:
        plans = [self.get_plan(path.stem) for path in sorted(self.plans_dir.glob("*.json"))]
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
        if result.status == "completed" and self._completed_result_is_persisted(running, result):
            return self._transition(running, "review", "runner completed and persisted result", result_experiment_id=result.experiment_id, review_status="awaiting_validation")
        message = result.error_message or result.error_code or "runner failed"
        if result.status == "completed":
            message = "completed callback was not the matching persisted ResultStore and Alpha Database result"
        return self._handle_failure(running, message, result.experiment_id)

    def _handle_failure(self, plan: ExperimentPlan, message: str, result_experiment_id: str | None = None) -> ExperimentPlan:
        failed = self._transition(plan, "failed", "runner returned failed result", result_experiment_id=result_experiment_id, error_message=message)
        if not retry_permitted(failed.retry_count, failed.max_retries):
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
        if self.store.get_validation(plan.validation_id) is None:
            raise SolStateError("validation_id must name an existing persisted ValidationResult")
        review = self.reviewer.review_persisted(plan.validation_id, candidate_id=plan.experiment.experiment_id)
        stored_review = self.store.get_critic_review(review.review_id)
        if stored_review is None or stored_review != review:
            raise SolStateError("reviewer result must exactly match a persisted CriticReview")
        if review.validation_id != plan.validation_id or stored_review.validation_id != plan.validation_id:
            raise SolStateError("persisted CriticReview validation_id does not match the plan")
        if review.candidate_id != plan.experiment.experiment_id or stored_review.candidate_id != plan.experiment.experiment_id:
            raise SolStateError("persisted CriticReview candidate_id does not match the plan experiment")
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

    def _transition(self, plan: ExperimentPlan, status: PlanStatus, reason: str, **updates: object) -> ExperimentPlan:
        require_transition(plan.status, status)
        payload = {**updates, "status": status, "events": [*plan.events, PlanEvent(status=status, reason=reason)]}
        return self._save(plan.model_copy(update=payload))

    def _save(self, plan: ExperimentPlan) -> ExperimentPlan:
        plan = self._seal(plan)
        path = self.plans_dir / f"{plan.plan_id}.json"
        self._write_json(path, plan.model_dump(mode="json"))
        return plan

    def _completed_result_is_persisted(self, plan: ExperimentPlan, result: ExperimentResult) -> bool:
        if result.experiment_id != plan.experiment.experiment_id:
            return False
        stored = self.store.get(result.experiment_id)
        archived = AlphaDatabase(self.store.config).get_experiment(result.experiment_id)
        return bool(
            stored is not None and stored.status == "completed" and stored == result
            and archived is not None and archived.status == "completed"
            and _result_fingerprint(stored) == _alpha_record_fingerprint(archived)
        )

    def _load_integrity_key(self) -> bytes:
        if self.integrity_key_path.exists():
            return self.integrity_key_path.read_bytes()
        key = secrets.token_bytes(32)
        temporary = self.integrity_key_path.with_suffix(".tmp")
        try:
            temporary.write_bytes(key)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.integrity_key_path)
        finally:
            temporary.unlink(missing_ok=True)
        return key

    def _seal(self, plan: ExperimentPlan) -> ExperimentPlan:
        previous: str | None = None
        events: list[PlanEvent] = []
        for event in plan.events:
            payload = event.model_dump(mode="json", exclude={"previous_hash", "integrity_hash"})
            digest = self._digest({"previous_hash": previous, **payload})
            events.append(event.model_copy(update={"previous_hash": previous, "integrity_hash": digest}))
            previous = digest
        unsigned = plan.model_copy(update={"events": events, "integrity_hash": ""})
        integrity_hash = self._digest(unsigned.model_dump(mode="json", exclude={"integrity_hash"}))
        return unsigned.model_copy(update={"integrity_hash": integrity_hash})

    def _verify_plan(self, plan: ExperimentPlan) -> None:
        previous: str | None = None
        for event in plan.events:
            payload = event.model_dump(mode="json", exclude={"previous_hash", "integrity_hash"})
            expected = self._digest({"previous_hash": previous, **payload})
            if event.previous_hash != previous or not hmac.compare_digest(event.integrity_hash, expected):
                raise SolStateError(f"plan event integrity error: {plan.plan_id}")
            previous = event.integrity_hash
        expected_plan = self._digest(plan.model_copy(update={"integrity_hash": ""}).model_dump(mode="json", exclude={"integrity_hash"}))
        if not hmac.compare_digest(plan.integrity_hash, expected_plan):
            raise SolStateError(f"plan integrity error: {plan.plan_id}")
        validate_state_chain(plan)

    def _digest(self, payload: object) -> str:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self._integrity_key, encoded, hashlib.sha256).hexdigest()

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


def _result_fingerprint(result: ExperimentResult) -> str:
    """Stable equality key for a ResultStore row and its Alpha projection."""
    payload = {
        "experiment_id": result.experiment_id, "status": result.status,
        "strategy_name": result.strategy_name, "factor_name": result.factor_name,
        "result_artifact": result.artifact_location, "report_location": result.report_location,
        "error_code": result.error_code, "error_message": result.error_message,
        "metrics": result.metrics.model_dump() if result.metrics else None,
    }
    return _fingerprint(payload)


def _alpha_record_fingerprint(record: ExperimentRecord) -> str:
    payload = {
        "experiment_id": record.experiment_id, "status": record.status,
        "strategy_name": record.strategy_name, "factor_name": record.factor_name,
        "result_artifact": record.result_artifact, "report_location": record.report_location,
        "error_code": record.error_code, "error_message": record.error_message,
        "metrics": record.metrics,
    }
    return _fingerprint(payload)


def _fingerprint(payload: object) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
