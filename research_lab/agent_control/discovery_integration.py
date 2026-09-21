"""Milestone 6 — Alpha Discovery Engine Integration (#573).

Connects admitted M5 Agent candidates to the deterministic Alpha Discovery pipeline:
Screening -> Evidence -> Critic -> Research Memory.

Core Invariants:
- Agent candidate != Evidence
- Agent candidate != CriticDecision
- Provider failure != scientific REJECT
- Agent failure != scientific REJECT
- Parsing failure != scientific REJECT
- Admission failure != scientific REJECT
- Infrastructure failure != scientific REJECT
- PROMOTE != tradable (TRADABLE_AUTHORITY is permanently False)
- Duplicate != unconditional skip (evidence coverage dependent)
- engineering terminal state != scientific terminal decision
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from research_lab.agent_control.alpha_generator import (
    AlphaGenerationCandidate,
    AlphaGenerationError,
    AlphaGenerationRequest,
    AlphaGenerationResult,
    admit_alpha_generation_output,
    parse_alpha_generation_output,
)
from research_lab.agent_control.contracts import (
    AgentResult,
    ProjectBinding,
    TerminalStatus,
    validate_project_binding,
    validate_result_hash,
)
from research_lab.agent_control.errors import (
    ResultAcceptanceError,
    TamperDetectionError,
)
from research_lab.agent_control.memory_view import ResearchMemoryView
from research_lab.alpha_discovery import (
    AlphaDiscoveryEngine,
    AlphaHypothesis,
    CriticDecision,
    DiscoveryItemResult,
    ResearchMemoryRecord,
)
from research_lab.contracts import v2

TRADABLE_AUTHORITY: bool = False
M6_SCHEMA_VERSION = "research_lab.discovery_integration.v1"


class EngineeringStatus(str, Enum):
    """Explicit engineering terminal status distinct from scientific terminal decision."""

    COMPLETED = "COMPLETED"
    AGENT_EXECUTION_FAILED = "AGENT_EXECUTION_FAILED"
    PROVIDER_UNCERTAIN = "PROVIDER_UNCERTAIN"
    RESULT_NOT_ACCEPTED = "RESULT_NOT_ACCEPTED"
    PARSE_FAILED = "PARSE_FAILED"
    ADMISSION_FAILED = "ADMISSION_FAILED"
    SCREENING_FAILED = "SCREENING_FAILED"
    CRITIC_FAILED = "CRITIC_FAILED"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"


@dataclass(frozen=True)
class DiscoveryIntegrationResult:
    """Unified outcome contract for Milestone 6 Discovery Integration.

    Separates engineering terminal state from scientific terminal decision.
    """

    engineering_status: str
    scientific_decision: str | None  # Strictly "REJECT", "NEED_MORE_EVIDENCE", "PROMOTE", or None
    is_tradable: bool = False
    error_code: str | None = None
    error_message: str | None = None

    # Provenance and identity tracking
    request_id: str | None = None
    task_id: str | None = None
    route_id: str | None = None
    provider_job_ref: str | None = None
    provider: str | None = None
    model: str | None = None
    agent_result_id: str | None = None
    agent_result_hash: str | None = None
    hypothesis_id: str | None = None
    hypothesis_content_hash: str | None = None
    scientific_identity_hash: str | None = None
    plan_id: str | None = None
    plan_content_hash: str | None = None

    # Scientific artifacts
    admitted_hypothesis: AlphaHypothesis | dict[str, Any] | None = None
    critic_decision: CriticDecision | None = None
    critic_decision_history: tuple[CriticDecision, ...] = ()
    memory_record_id: str | None = None
    memory_records: tuple[ResearchMemoryRecord, ...] = ()

    # Protocol v2 verification refs
    task_refs: tuple[dict[str, str], ...] = ()
    spec_refs: tuple[dict[str, str], ...] = ()
    run_refs: tuple[dict[str, str], ...] = ()
    manifest_refs: tuple[dict[str, str], ...] = ()
    evidence_refs: tuple[dict[str, str], ...] = ()

    # Project binding
    project_binding: dict[str, str] = field(default_factory=dict)
    schema_version: str = M6_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.is_tradable:
            raise ValueError("Research pipeline results can NEVER grant tradable authority")
        if self.scientific_decision not in (None, "REJECT", "NEED_MORE_EVIDENCE", "PROMOTE"):
            raise ValueError(f"Invalid scientific decision: {self.scientific_decision}")
        if self.engineering_status != EngineeringStatus.COMPLETED.value and self.scientific_decision is not None:
            raise ValueError(
                f"Engineering failure ({self.engineering_status}) cannot produce a scientific decision ({self.scientific_decision})"
            )


def _clean_for_v2(value: Any) -> Any:
    if isinstance(value, (tuple, list)):
        return [_clean_for_v2(x) for x in value]
    if isinstance(value, dict):
        return {str(k): _clean_for_v2(v) for k, v in value.items()}
    return value


@dataclass(frozen=True)
class DiscoveryIntegrationAuditRecord:
    """Tamper-evident audit record for Milestone 6 engine integration."""

    request_id: str | None
    task_id: str | None
    provider_job_ref: str | None
    engineering_status: str
    scientific_decision: str | None
    hypothesis_content_hash: str | None
    scientific_identity_hash: str | None
    plan_content_hash: str | None
    critic_review_hash: str | None
    memory_record_ids: tuple[str, ...]
    audit_content_hash: str

    @classmethod
    def create(cls, result: DiscoveryIntegrationResult) -> DiscoveryIntegrationAuditRecord:
        raw = {
            "critic_review_hash": (
                result.critic_decision.review_content_hash
                if result.critic_decision
                else None
            ),
            "engineering_status": result.engineering_status,
            "hypothesis_content_hash": result.hypothesis_content_hash,
            "memory_record_ids": [r.record_id for r in result.memory_records],
            "plan_content_hash": result.plan_content_hash,
            "provider_job_ref": result.provider_job_ref,
            "request_id": result.request_id,
            "scientific_decision": result.scientific_decision,
            "scientific_identity_hash": result.scientific_identity_hash,
            "task_id": result.task_id,
        }
        return cls(
            request_id=raw["request_id"],
            task_id=raw["task_id"],
            provider_job_ref=raw["provider_job_ref"],
            engineering_status=raw["engineering_status"],
            scientific_decision=raw["scientific_decision"],
            hypothesis_content_hash=raw["hypothesis_content_hash"],
            scientific_identity_hash=raw["scientific_identity_hash"],
            plan_content_hash=raw["plan_content_hash"],
            critic_review_hash=raw["critic_review_hash"],
            memory_record_ids=tuple(raw["memory_record_ids"]),
            audit_content_hash=v2.digest(_clean_for_v2(raw)),
        )

    def verify(self) -> None:
        raw = {
            "critic_review_hash": self.critic_review_hash,
            "engineering_status": self.engineering_status,
            "hypothesis_content_hash": self.hypothesis_content_hash,
            "memory_record_ids": list(self.memory_record_ids),
            "plan_content_hash": self.plan_content_hash,
            "provider_job_ref": self.provider_job_ref,
            "request_id": self.request_id,
            "scientific_decision": self.scientific_decision,
            "scientific_identity_hash": self.scientific_identity_hash,
            "task_id": self.task_id,
        }
        if self.audit_content_hash != v2.digest(_clean_for_v2(raw)):
            raise ValueError("Integration audit tampering detected")


class DiscoveryIntegrationAuditTrail:
    """Append-only audit trail for Discovery Integration."""

    def __init__(self) -> None:
        self._records: list[DiscoveryIntegrationAuditRecord] = []

    def append(self, record: DiscoveryIntegrationAuditRecord) -> None:
        record.verify()
        self._records.append(record)

    def get_records(self) -> tuple[DiscoveryIntegrationAuditRecord, ...]:
        return tuple(self._records)

    def verify_all(self) -> bool:
        for record in self._records:
            record.verify()
        return True


def _extract_model_output_from_result(result: AgentResult) -> str:
    """Safely extract model output string from accepted AgentResult; fail-closed."""
    validate_result_hash(result.to_dict())
    if result.terminal_status != TerminalStatus.SUCCESS.value:
        raise ResultAcceptanceError(
            f"AgentResult terminal_status is not SUCCESS: {result.terminal_status}"
        )
    if result.acceptance_status != "ACCEPTED":
        raise ResultAcceptanceError(
            f"AgentResult acceptance_status is not ACCEPTED: {result.acceptance_status}"
        )
    output = result.structured_output
    if not isinstance(output, dict):
        raise ResultAcceptanceError("accepted provider result has no structured output")
    for key in ("output", "text", "content", "final_output", "response"):
        if isinstance(output.get(key), str):
            return output[key]
    from research_lab.agent_control.alpha_generator import ENVELOPE_FIELDS

    if set(output) == ENVELOPE_FIELDS:
        return json.dumps(output, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    raise ResultAcceptanceError("accepted provider result has no recognizable model output text")


class DiscoveryIntegrationOrchestrator:
    """Minimal M6 integration layer connecting Agent candidate to Alpha Discovery pipeline."""

    def __init__(
        self,
        engine: AlphaDiscoveryEngine,
        *,
        audit_trail: DiscoveryIntegrationAuditTrail | None = None,
    ) -> None:
        self.engine = engine
        self.audit_trail = audit_trail or DiscoveryIntegrationAuditTrail()

    def integrate_candidate(
        self,
        candidate: AlphaGenerationCandidate | AlphaHypothesis,
        snapshot_path: Path | str,
        *,
        dataset_binding: dict[str, Any] | None = None,
        project_binding: ProjectBinding | Mapping[str, str],
        expected_binding: ProjectBinding | Mapping[str, str] | None = None,
        request_id: str | None = None,
        task_id: str | None = None,
        route_id: str | None = None,
        provider_job_ref: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        agent_result_id: str | None = None,
        agent_result_hash: str | None = None,
        auto_supplemental: bool = False,
    ) -> DiscoveryIntegrationResult:
        """Feed an admitted, validated AlphaCandidate into deterministic screening."""
        binding = (
            project_binding.to_dict()
            if isinstance(project_binding, ProjectBinding)
            else dict(project_binding)
        )
        validate_project_binding(binding, expected_binding=expected_binding)

        # Invariant 7 & 8: candidate and hypothesis must NOT be mutated
        hyp_obj = (
            candidate.hypothesis
            if isinstance(candidate, AlphaGenerationCandidate)
            else candidate
        )
        # Deep defensive copy to guarantee candidate immutability
        hyp_dict = copy.deepcopy(hyp_obj.model_dump())

        hyp_id = hyp_dict["hypothesis_id"]
        hyp_hash = hyp_dict["hypothesis_content_hash"]
        sci_hash = hyp_obj.scientific_identity_hash

        # Run through existing deterministic AlphaDiscoveryEngine
        item_result: DiscoveryItemResult = self.engine.run_single(
            hypothesis_input=hyp_dict,
            snapshot_path=snapshot_path,
            dataset_binding=dataset_binding,
            auto_supplemental=auto_supplemental,
        )

        dec_history: list[CriticDecision] = []
        mem_records: list[ResearchMemoryRecord] = []

        if item_result.critic_decision:
            dec_history.append(item_result.critic_decision)
        if item_result.memory_record:
            mem_records.append(item_result.memory_record)

        # Handle supplemental cycle history if auto_supplemental triggered
        if item_result.supplemental_results:
            for supp_item in item_result.supplemental_results:
                if supp_item.critic_decision:
                    dec_history.append(supp_item.critic_decision)
                if supp_item.memory_record:
                    mem_records.append(supp_item.memory_record)

        final_item = (
            item_result.supplemental_results[-1]
            if item_result.supplemental_results
            else item_result
        )

        # Map discovery status to M6 engineering status and scientific decision
        if final_item.status == "completed":
            eng_status = EngineeringStatus.COMPLETED.value
            sci_decision = (
                final_item.critic_decision.decision
                if final_item.critic_decision
                else None
            )
            err_msg = None
        elif final_item.status == "skipped_duplicate":
            eng_status = EngineeringStatus.SKIPPED_DUPLICATE.value
            sci_decision = None
            err_msg = final_item.error_message or "Duplicate screening skipped"
        elif final_item.status == "invalid_definition":
            eng_status = EngineeringStatus.ADMISSION_FAILED.value
            sci_decision = None
            err_msg = final_item.error_message
        else:
            eng_status = EngineeringStatus.SCREENING_FAILED.value
            sci_decision = None
            err_msg = final_item.error_message

        # Collect refs from receipts / memory_record
        task_refs: list[dict[str, str]] = []
        spec_refs: list[dict[str, str]] = []
        run_refs: list[dict[str, str]] = []
        manifest_refs: list[dict[str, str]] = []
        evidence_refs: list[dict[str, str]] = []

        for rec in mem_records:
            task_refs.extend(rec.task_refs)
            spec_refs.extend(rec.spec_refs)
            run_refs.extend(rec.run_refs)
            manifest_refs.extend(rec.manifest_refs)
            evidence_refs.extend(rec.evidence_refs)

        plan_id = final_item.plan.plan_id if final_item.plan else None
        plan_hash = final_item.plan.plan_content_hash if final_item.plan else None

        res = DiscoveryIntegrationResult(
            engineering_status=eng_status,
            scientific_decision=sci_decision,
            is_tradable=False,
            error_code=None if eng_status == EngineeringStatus.COMPLETED.value else eng_status,
            error_message=err_msg,
            request_id=request_id,
            task_id=task_id,
            route_id=route_id,
            provider_job_ref=provider_job_ref,
            provider=provider,
            model=model,
            agent_result_id=agent_result_id,
            agent_result_hash=agent_result_hash,
            hypothesis_id=hyp_id,
            hypothesis_content_hash=hyp_hash,
            scientific_identity_hash=sci_hash,
            plan_id=plan_id,
            plan_content_hash=plan_hash,
            admitted_hypothesis=hyp_obj,
            critic_decision=final_item.critic_decision,
            critic_decision_history=tuple(dec_history),
            memory_record_id=mem_records[-1].record_id if mem_records else None,
            memory_records=tuple(mem_records),
            task_refs=tuple(task_refs),
            spec_refs=tuple(spec_refs),
            run_refs=tuple(run_refs),
            manifest_refs=tuple(manifest_refs),
            evidence_refs=tuple(evidence_refs),
            project_binding=binding,
        )

        audit_rec = DiscoveryIntegrationAuditRecord.create(res)
        self.audit_trail.append(audit_rec)
        return res

    def integrate_agent_result(
        self,
        agent_result: AgentResult,
        *,
        request: AlphaGenerationRequest,
        memory_view: ResearchMemoryView,
        snapshot_path: Path | str,
        task_id: str,
        provider: str,
        actual_model: str,
        created_at: str,
        dataset_binding: dict[str, Any] | None = None,
        expected_binding: ProjectBinding | Mapping[str, str] | None = None,
        auto_supplemental: bool = False,
    ) -> DiscoveryIntegrationResult:
        """Gate check AgentResult and transition into scientific pipeline if valid."""
        binding = (
            expected_binding.to_dict()
            if isinstance(expected_binding, ProjectBinding)
            else (dict(expected_binding) if expected_binding else dict(request.project_binding))
        )
        validate_project_binding(binding, expected_binding=request.project_binding)
        validate_project_binding(dict(memory_view.project_binding), expected_binding=binding)

        # Gate 1: Check AgentResult terminal status & acceptance status
        try:
            validate_result_hash(agent_result.to_dict())
        except (TamperDetectionError, ValueError) as exc:
            res = DiscoveryIntegrationResult(
                engineering_status=EngineeringStatus.AGENT_EXECUTION_FAILED.value,
                scientific_decision=None,
                error_code="RESULT_TAMPERED",
                error_message=f"AgentResult hash verification failed: {exc}",
                request_id=request.request_id,
                task_id=task_id,
                provider_job_ref=agent_result.provider_job_ref,
                provider=provider,
                model=actual_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

        if agent_result.terminal_status == TerminalStatus.UNCERTAIN.value:
            res = DiscoveryIntegrationResult(
                engineering_status=EngineeringStatus.PROVIDER_UNCERTAIN.value,
                scientific_decision=None,
                error_code="PROVIDER_UNCERTAIN",
                error_message="Provider execution ended in UNCERTAIN state; no admission attempted",
                request_id=request.request_id,
                task_id=task_id,
                provider_job_ref=agent_result.provider_job_ref,
                provider=provider,
                model=actual_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

        if agent_result.terminal_status != TerminalStatus.SUCCESS.value:
            res = DiscoveryIntegrationResult(
                engineering_status=EngineeringStatus.AGENT_EXECUTION_FAILED.value,
                scientific_decision=None,
                error_code=f"TERMINAL_STATUS_{agent_result.terminal_status}",
                error_message=f"Agent execution terminated with {agent_result.terminal_status}; no admission attempted",
                request_id=request.request_id,
                task_id=task_id,
                provider_job_ref=agent_result.provider_job_ref,
                provider=provider,
                model=actual_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

        if agent_result.acceptance_status != "ACCEPTED":
            res = DiscoveryIntegrationResult(
                engineering_status=EngineeringStatus.RESULT_NOT_ACCEPTED.value,
                scientific_decision=None,
                error_code=f"ACCEPTANCE_{agent_result.acceptance_status}",
                error_message=f"AgentResult acceptance_status is not ACCEPTED: {agent_result.acceptance_status}",
                request_id=request.request_id,
                task_id=task_id,
                provider_job_ref=agent_result.provider_job_ref,
                provider=provider,
                model=actual_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

        # Gate 2: Extract raw text and perform strict JSON parse check
        try:
            raw_output = _extract_model_output_from_result(agent_result)
            parse_alpha_generation_output(raw_output)
        except (AlphaGenerationError, ResultAcceptanceError) as exc:
            res = DiscoveryIntegrationResult(
                engineering_status=EngineeringStatus.PARSE_FAILED.value,
                scientific_decision=None,
                error_code="STRICT_PARSE_FAILED",
                error_message=f"Output strict JSON parse validation failed: {exc}",
                request_id=request.request_id,
                task_id=task_id,
                provider_job_ref=agent_result.provider_job_ref,
                provider=provider,
                model=actual_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

        # Gate 3: AlphaHypothesis admission
        try:
            candidate = admit_alpha_generation_output(
                raw_output,
                request=request,
                memory_view=memory_view,
                task_id=task_id,
                provider=provider,
                actual_model=actual_model,
                created_at=created_at,
            )
        except (AlphaGenerationError, ValueError) as exc:
            # E2E 3: Record honest admission failure in ResearchMemory without fabricating Run/Evidence/Critic
            raw_hyp = {}
            try:
                raw_hyp = json.loads(raw_output).get("hypothesis", {})
            except (json.JSONDecodeError, AttributeError):
                raw_hyp = {}

            err_msg = f"Candidate hypothesis admission failed: {exc}"
            mem_rec = self.engine.memory.append_admission_failed_record(
                raw_hypothesis=raw_hyp if isinstance(raw_hyp, dict) else {},
                error_message=err_msg,
            )
            res = DiscoveryIntegrationResult(
                engineering_status=EngineeringStatus.ADMISSION_FAILED.value,
                scientific_decision=None,
                error_code="ADMISSION_FAILED",
                error_message=err_msg,
                request_id=request.request_id,
                task_id=task_id,
                provider_job_ref=agent_result.provider_job_ref,
                provider=provider,
                model=actual_model,
                agent_result_id=agent_result.result_id,
                agent_result_hash=agent_result.result_content_hash,
                memory_record_id=mem_rec.record_id,
                memory_records=(mem_rec,),
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

        # Gate 4: Enter scientific discovery pipeline
        route_ref = agent_result.route_ref or {}
        return self.integrate_candidate(
            candidate=candidate,
            snapshot_path=snapshot_path,
            dataset_binding=dataset_binding,
            project_binding=binding,
            expected_binding=expected_binding,
            request_id=request.request_id,
            task_id=task_id,
            route_id=route_ref.get("route_id"),
            provider_job_ref=agent_result.provider_job_ref,
            provider=provider,
            model=actual_model,
            agent_result_id=agent_result.result_id,
            agent_result_hash=agent_result.result_content_hash,
            auto_supplemental=auto_supplemental,
        )

    def integrate_generation_result(
        self,
        generation_result: AlphaGenerationResult,
        snapshot_path: Path | str,
        *,
        dataset_binding: dict[str, Any] | None = None,
        project_binding: ProjectBinding | Mapping[str, str],
        auto_supplemental: bool = False,
    ) -> DiscoveryIntegrationResult:
        """Integrate an M5 AlphaGenerationResult directly."""
        binding = (
            project_binding.to_dict()
            if isinstance(project_binding, ProjectBinding)
            else dict(project_binding)
        )
        validate_project_binding(binding)

        if generation_result.status != "CANDIDATE_ADMITTED" or generation_result.candidate is None:
            code = generation_result.error_code or "GENERATION_FAILED"
            eng_status = (
                EngineeringStatus.PROVIDER_UNCERTAIN.value
                if "UNCERTAIN" in code
                else EngineeringStatus.AGENT_EXECUTION_FAILED.value
            )
            res = DiscoveryIntegrationResult(
                engineering_status=eng_status,
                scientific_decision=None,
                error_code=code,
                error_message=f"AlphaGenerationResult is not admitted ({generation_result.status}): {code}",
                request_id=generation_result.request_id,
                task_id=generation_result.task_id,
                route_id=generation_result.route_id,
                provider_job_ref=generation_result.provider_job_ref,
                provider=generation_result.provider,
                model=generation_result.actual_model,
                agent_result_id=generation_result.agent_result_id,
                agent_result_hash=generation_result.agent_result_content_hash,
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

        return self.integrate_candidate(
            candidate=generation_result.candidate,
            snapshot_path=snapshot_path,
            dataset_binding=dataset_binding,
            project_binding=binding,
            request_id=generation_result.request_id,
            task_id=generation_result.task_id,
            route_id=generation_result.route_id,
            provider_job_ref=generation_result.provider_job_ref,
            provider=generation_result.provider,
            model=generation_result.actual_model,
            agent_result_id=generation_result.agent_result_id,
            agent_result_hash=generation_result.agent_result_content_hash,
            auto_supplemental=auto_supplemental,
        )
