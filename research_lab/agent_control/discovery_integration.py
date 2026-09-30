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
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
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
    compute_hypothesis_content_hash,
)
from research_lab.alpha_discovery.signal_binding import (
    SignalBindingError,
    SyntheticTestEvidence,
    derive_signal_snapshot,
    parse_and_verify_signal_spec,
    parse_strict_utc_iso8601,
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
        allow_synthetic_passthrough: bool = False,
        synthetic_test_evidence: SyntheticTestEvidence | None = None,
    ) -> None:
        self.engine = engine
        self.audit_trail = audit_trail or DiscoveryIntegrationAuditTrail()
        self.allow_synthetic_passthrough = allow_synthetic_passthrough
        self.synthetic_test_evidence = synthetic_test_evidence

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
        if isinstance(hyp_obj, dict):
            hyp_obj = AlphaHypothesis.model_validate(hyp_obj)

        # Deep defensive copy to guarantee candidate immutability and exact hash profile
        dump_with = hyp_obj.model_dump()
        if compute_hypothesis_content_hash(dump_with) == hyp_obj.hypothesis_content_hash:
            hyp_dict = copy.deepcopy(dump_with)
        else:
            hyp_dict = copy.deepcopy(hyp_obj.model_dump(exclude_none=True))

        hyp_id = hyp_dict["hypothesis_id"]
        hyp_hash = hyp_dict["hypothesis_content_hash"]
        sci_hash = hyp_obj.scientific_identity_hash

        # Strict caller isolation: synthetic bypass is ONLY allowed when orchestrator is explicitly
        # instantiated with allow_synthetic_passthrough=True.
        # Any caller-controlled parameters inside dataset_binding (e.g. mode, provenance, allow_synthetic_passthrough)
        # MUST NEVER be trusted to bypass validation.
        is_synthetic_direct = bool(self.allow_synthetic_passthrough)
        effective_snapshot_path = Path(snapshot_path).resolve()
        effective_dataset_binding = dataset_binding

        if not is_synthetic_direct:
            try:
                # 1. Fail-closed parse and verify candidate mathematical specification against whitelist
                spec = parse_and_verify_signal_spec(hyp_dict)

                # 2. Unconditional provenance requirement: must supply provenance_path and expected provenance_sha256
                if not isinstance(dataset_binding, dict):
                    raise SignalBindingError(
                        "MISSING_DATASET_BINDING",
                        "Real candidate signal binding requires dictionary dataset_binding with provenance details",
                    )

                prov_path = dataset_binding.get("provenance_path")
                expected_prov_sha = dataset_binding.get("provenance_sha256")

                if not prov_path:
                    raise SignalBindingError(
                        "MISSING_PROVENANCE_PATH",
                        "Real candidate signal binding strictly requires provenance_path in dataset_binding",
                    )
                if not expected_prov_sha:
                    raise SignalBindingError(
                        "MISSING_PROVENANCE_SHA",
                        "Real candidate signal binding strictly requires provenance_sha256 digest in dataset_binding",
                    )

                p_file = Path(prov_path).resolve()
                if not p_file.exists():
                    raise SignalBindingError(
                        "MISSING_PROVENANCE_FILE",
                        f"Declared provenance file does not exist: {p_file}",
                    )

                prov_bytes = p_file.read_bytes()
                actual_prov_sha = v2.sha(prov_bytes)
                if actual_prov_sha != expected_prov_sha:
                    raise SignalBindingError(
                        "PROVENANCE_HASH_MISMATCH",
                        f"Provenance file at {prov_path} SHA256 {actual_prov_sha} does not match expected {expected_prov_sha}",
                    )

                prov_data = json.loads(prov_bytes.decode("utf-8"))
                if not isinstance(prov_data, dict):
                    raise SignalBindingError(
                        "MALFORMED_PROVENANCE_STRUCTURE",
                        f"Provenance file content must be a JSON object (dict), got {type(prov_data).__name__}",
                    )
                prov_source_days = prov_data.get("source_days")
                if not isinstance(prov_source_days, (list, tuple)) or not prov_source_days:
                    raise SignalBindingError(
                        "MISSING_SOURCE_DAYS",
                        "No source_days found in verified provenance file",
                    )

                # If caller also provided source_days directly, enforce item-by-item exact match
                caller_source_days = dataset_binding.get("source_days")
                if caller_source_days is not None:
                    if caller_source_days != prov_source_days:
                        raise SignalBindingError(
                            "SOURCE_DAYS_MISMATCH",
                            "Caller-supplied source_days does not match canonical verified provenance content",
                        )

                # Always use canonical verified source_days from provenance
                source_days = prov_source_days

                # Derive single-contract candidate snapshot (never overwrite existing files)
                base_derived_dir = Path(self.engine.output_base_dir) / "derived_snapshots"
                expected_csv_name = f"snapshot_{spec.symbol.lower()}_{spec.formula_id}_{sci_hash[:16]}.csv"
                derived_dir = base_derived_dir
                if (derived_dir / expected_csv_name).exists():
                    sub_tag = f"{hyp_id}_{task_id or request_id or hyp_hash[:8]}"
                    derived_dir = base_derived_dir / sub_tag
                    idx = 2
                    while (derived_dir / expected_csv_name).exists():
                        derived_dir = base_derived_dir / f"{sub_tag}_{idx}"
                        idx += 1
                derived_res = derive_signal_snapshot(
                    spec=spec,
                    source_days=source_days,
                    output_dir=derived_dir,
                    candidate_identity_hash=sci_hash,
                    provenance_path=p_file,
                    provenance_sha256=actual_prov_sha,
                    synthetic_test_evidence=self.synthetic_test_evidence,
                    real_source_bundle_root=dataset_binding.get("real_source_bundle_root"),
                    official_rules_root=dataset_binding.get("official_rules_root"),
                )
                effective_snapshot_path = derived_res.path
                effective_dataset_binding = derived_res.dataset_binding
            except (SignalBindingError, ValueError, KeyError, AttributeError, TypeError, json.JSONDecodeError, OSError) as exc:
                err_code = getattr(exc, "reason", "BINDING_FAILED")
                if isinstance(exc, KeyError):
                    err_code = "MALFORMED_PROVENANCE_KEY_ERROR"
                elif isinstance(exc, (AttributeError, TypeError, json.JSONDecodeError)):
                    err_code = f"MALFORMED_PROVENANCE_{type(exc).__name__.upper()}"
                res = DiscoveryIntegrationResult(
                    engineering_status=EngineeringStatus.ADMISSION_FAILED.value,
                    scientific_decision=None,
                    error_code=err_code,
                    error_message=f"Deterministic signal binding rejected [{err_code}]: {exc}",
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
                    admitted_hypothesis=hyp_obj,
                    critic_decision=None,
                    project_binding=binding,
                )
                self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
                return res

        # Run through existing deterministic AlphaDiscoveryEngine with global exception boundary
        try:
            item_result: DiscoveryItemResult = self.engine.run_single(
                hypothesis_input=hyp_dict,
                snapshot_path=effective_snapshot_path,
                dataset_binding=effective_dataset_binding,
                auto_supplemental=auto_supplemental,
            )
        except Exception as exc:  # noqa: BLE001
            err_text = str(exc)
            eng_status = (
                EngineeringStatus.CRITIC_FAILED.value
                if "critic" in err_text.lower()
                else EngineeringStatus.SCREENING_FAILED.value
            )
            res = DiscoveryIntegrationResult(
                engineering_status=eng_status,
                scientific_decision=None,
                error_code=eng_status,
                error_message=f"Screening execution crashed: {exc}",
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
                admitted_hypothesis=hyp_obj,
                critic_decision=None,
                project_binding=binding,
            )
            self.audit_trail.append(DiscoveryIntegrationAuditRecord.create(res))
            return res

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
            final_critic_decision = final_item.critic_decision
            err_msg = None
        elif "critic" in str(final_item.status).lower() or (final_item.error_message and "critic" in str(final_item.error_message).lower()):
            eng_status = EngineeringStatus.CRITIC_FAILED.value
            sci_decision = None
            final_critic_decision = None
            err_msg = final_item.error_message
        elif final_item.status == "skipped_duplicate":
            eng_status = EngineeringStatus.SKIPPED_DUPLICATE.value
            sci_decision = None
            final_critic_decision = None
            err_msg = final_item.error_message or "Duplicate screening skipped"
        elif final_item.status == "invalid_definition":
            eng_status = EngineeringStatus.ADMISSION_FAILED.value
            sci_decision = None
            final_critic_decision = None
            err_msg = final_item.error_message
        else:
            eng_status = EngineeringStatus.SCREENING_FAILED.value
            sci_decision = None
            final_critic_decision = None
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
            critic_decision=final_critic_decision,
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


def recover_round_execution_timing(
    integration_records: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    result_store: Any | None = None,
) -> tuple[str, str]:
    """Recover execution completion timestamp from verified result store receipts.

    Strict Invariants:
    1. 1:1 binding between every declared run_ref and its verified receipt.
    2. When result_store is supplied (e.g. during execution or resume), re-query and
       cryptographically verify each declared run_ref via ResultStore.query_v2_runs(run_id=..., verify=True)
       rather than blindly trusting literal cached receipts in integration JSON.
    3. Validate run_ref content_hash, receipt.run identity, and run.json top-level
       run_id/run_content_hash against bundle inventory SHA256.
    4. timing.completed_at validated as strict UTC ISO8601.
    5. Only returns max(completed_at) on 100% complete coverage across all declared run_refs.
    6. Fails closed to ('unknown', reason) on any missing, duplicate, corrupt, unverified,
       or mismatched receipt; zero directory-globbing / loose filesystem scanning.
    """
    if not integration_records:
        return "unknown", "no integration records provided"

    declared_runs: list[tuple[str, str | None]] = []
    seen_declared_run_ids: set[str] = set()

    for slot_idx, record in enumerate(integration_records):
        if not isinstance(record, dict):
            return "unknown", f"malformed integration record at slot {slot_idx}: expected dict"
        run_refs = record.get("run_refs")
        if run_refs is None:
            continue
        if not isinstance(run_refs, (list, tuple)):
            return "unknown", f"malformed run_refs at slot {slot_idx}: expected list or tuple"
        for r_idx, ref in enumerate(run_refs):
            if isinstance(ref, dict):
                rid = ref.get("run_id") or ref.get("object_id")
                chash = ref.get("content_hash") or ref.get("run_content_hash")
            elif isinstance(ref, str):
                rid = ref
                chash = None
            else:
                return "unknown", f"malformed run_ref at slot {slot_idx}[{r_idx}]: {ref!r}"

            if not rid or not isinstance(rid, str) or not rid.strip():
                return "unknown", f"invalid run_id in declared run_ref at slot {slot_idx}[{r_idx}]"

            if rid in seen_declared_run_ids:
                return "unknown", f"duplicate run_ref declared across slots: {rid}"
            seen_declared_run_ids.add(rid)
            declared_runs.append((rid, chash))

    if not declared_runs:
        return "unknown", "no declared run_refs found in integration records"

    receipt_by_run_id: dict[str, dict[str, Any]] = {}
    if result_store is not None:
        for rid, _ in declared_runs:
            try:
                matched = result_store.query_v2_runs(run_id=rid, verify=True)
            except Exception as exc:
                return "unknown", f"ResultStore verification failed for {rid}: {exc}"
            if not matched or len(matched) != 1:
                return (
                    "unknown",
                    f"ResultStore query_v2_runs returned {len(matched) if matched else 0} receipts for {rid}",
                )
            receipt_by_run_id[rid] = matched[0]
    else:
        for slot_idx, record in enumerate(integration_records):
            receipts = record.get("verified_result_store_receipts")
            if not receipts:
                continue
            if not isinstance(receipts, (list, tuple)):
                return (
                    "unknown",
                    f"malformed verified_result_store_receipts at slot {slot_idx}: expected list or tuple",
                )

            for rc_idx, rc in enumerate(receipts):
                if not isinstance(rc, dict):
                    return "unknown", f"malformed receipt at slot {slot_idx}[{rc_idx}]: expected dict"

                rc_run = rc.get("run")
                if isinstance(rc_run, dict):
                    rc_rid = rc_run.get("object_id") or rc_run.get("run_id")
                elif isinstance(rc_run, str):
                    rc_rid = rc_run
                else:
                    rc_rid = rc.get("run_id")

                if not rc_rid or not isinstance(rc_rid, str) or not rc_rid.strip():
                    return "unknown", f"receipt missing valid run object_id at slot {slot_idx}[{rc_idx}]"

                if rc_rid in receipt_by_run_id:
                    return "unknown", f"duplicate verified receipt declared for run_id: {rc_rid}"

                receipt_by_run_id[rc_rid] = rc

        missing_receipts = [rid for rid, _ in declared_runs if rid not in receipt_by_run_id]
        if missing_receipts:
            return (
                "unknown",
                f"missing verified receipt for declared run_ref(s): {missing_receipts[:3]} "
                f"(missing {len(missing_receipts)}/{len(declared_runs)})",
            )

        unmatched_receipts = [rid for rid in receipt_by_run_id if rid not in seen_declared_run_ids]
        if unmatched_receipts:
            return (
                "unknown",
                f"unmatched verified receipt(s) not in declared run_refs: {unmatched_receipts[:3]}",
            )

    verified_completed_times: list[tuple[datetime, str]] = []
    for rid, declared_hash in declared_runs:
        rc = receipt_by_run_id.get(rid)
        if not rc:
            return "unknown", f"missing verified receipt for {rid}"

        rc_run = rc.get("run")
        if not isinstance(rc_run, dict):
            return "unknown", f"receipt missing run dict for {rid}"
        rc_rid = rc_run.get("object_id") or rc_run.get("run_id")
        if rc_rid != rid:
            return "unknown", f"receipt run object_id mismatch: declared {rid}, receipt has {rc_rid}"
        rc_hash = rc_run.get("content_hash") or rc_run.get("run_content_hash")
        if declared_hash and rc_hash and declared_hash != rc_hash:
            return (
                "unknown",
                f"content_hash mismatch between run_ref and receipt for {rid}: {declared_hash} != {rc_hash}",
            )

        b_loc = rc.get("bundle_location")
        if not b_loc or not isinstance(b_loc, (str, Path)):
            return "unknown", f"verified receipt for {rid} missing bundle_location"

        bundle_path = Path(b_loc)
        run_file = bundle_path / "run.json"
        if not run_file.exists() or not run_file.is_file():
            return "unknown", f"missing run.json at verified bundle_location for {rid}: {run_file}"

        inventory = rc.get("bundle_file_sha256")
        if not isinstance(inventory, dict):
            return "unknown", f"receipt for {rid} missing bundle_file_sha256 inventory"
        expected_run_json_sha = inventory.get("run.json")
        if not expected_run_json_sha:
            return "unknown", f"receipt for {rid} missing run.json in bundle_file_sha256 inventory"

        try:
            raw_bytes = run_file.read_bytes()
        except Exception as exc:
            return "unknown", f"failed to read run.json for {rid}: {exc}"

        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        if actual_sha != expected_run_json_sha:
            return (
                "unknown",
                f"run.json sha256 mismatch against receipt bundle inventory for {rid}: "
                f"expected {expected_run_json_sha}, got {actual_sha}",
            )

        try:
            run_data = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            return "unknown", f"corrupt or unreadable run.json for {rid}: {exc}"

        if not isinstance(run_data, dict):
            return "unknown", f"corrupt run.json for {rid}: expected JSON object"

        # Protocol v2 run.json top-level run_id
        file_rid = run_data.get("run_id")
        if not file_rid:
            nested_run = run_data.get("run")
            if isinstance(nested_run, dict):
                file_rid = nested_run.get("run_id") or nested_run.get("object_id")
        if file_rid != rid:
            return "unknown", f"run.json top-level run_id mismatch for {rid}: found {file_rid}"

        # Protocol v2 run.json top-level run_content_hash
        file_hash = run_data.get("run_content_hash")
        if not file_hash:
            nested_run = run_data.get("run")
            if isinstance(nested_run, dict):
                file_hash = nested_run.get("content_hash") or nested_run.get("run_content_hash")

        if declared_hash and file_hash and declared_hash != file_hash:
            return (
                "unknown",
                f"run.json run_content_hash mismatch with declared run_ref for {rid}: "
                f"expected {declared_hash}, got {file_hash}",
            )
        if rc_hash and file_hash and rc_hash != file_hash:
            return (
                "unknown",
                f"run.json run_content_hash mismatch with receipt for {rid}: "
                f"expected {rc_hash}, got {file_hash}",
            )

        timing = run_data.get("timing")
        if not isinstance(timing, dict):
            return "unknown", f"run.json missing timing object for {rid}"

        c_at = timing.get("completed_at")
        if not c_at or not isinstance(c_at, str) or not c_at.strip():
            return "unknown", f"run.json missing timing.completed_at for {rid}"

        try:
            parsed_dt = parse_strict_utc_iso8601(c_at)
        except Exception as exc:
            return "unknown", f"invalid timing.completed_at format for {rid}: {c_at!r} ({exc})"

        verified_completed_times.append((parsed_dt, c_at))

    if len(verified_completed_times) != len(declared_runs) or len(declared_runs) == 0:
        return (
            "unknown",
            f"incomplete receipt coverage: {len(verified_completed_times)}/{len(declared_runs)}",
        )

    # Chronologically compare by parsed UTC datetime rather than ASCII lexicographical order
    _, latest_c_at = max(verified_completed_times, key=lambda item: (item[0], item[1]))
    source_desc = (
        "recovered from immutable result store execution receipts (latest run.json:timing.completed_at)"
    )
    return latest_c_at, source_desc
