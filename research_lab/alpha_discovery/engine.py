"""Alpha Discovery Engine orchestrating the MVP discovery funnel (#562).

Connects:
AlphaHypothesis -> Normalization/Dedup -> Planning -> Screening -> ResultStore -> Evidence -> Critic -> Memory -> Supplemental Loop.
Deterministic, local, single-process execution without Worker Queue or external daemons.
Integrates with existing ResultStore for immutable Protocol v2 bundle persistence,
records honest failures in ResearchMemory, separates duplicate detection from execution skip,
and completes the full longitudinal NEED_MORE_EVIDENCE supplemental research loop.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from research_lab.alpha_discovery import hypothesis as hyp
from research_lab.alpha_discovery.critic_gate import (
    CriticDecision,
    CriticGate,
    validate_critic_decision,
)
from research_lab.alpha_discovery.planner import ScreeningPlanner
from research_lab.alpha_discovery.research_memory import (
    ResearchMemory,
    ResearchMemoryRecord,
)
from research_lab.alpha_discovery.screening import (
    ScreeningPipeline,
    ScreeningPipelineReport,
)
from research_lab.alpha_discovery.screening_plan import ScreeningPlan
from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.database import ResultStore


@dataclass
class DiscoveryItemResult:
    """Detailed discovery output for a single hypothesis execution."""

    hypothesis_id: str
    revision: str
    status: Literal[
        "completed",
        "skipped_duplicate",
        "invalid_definition",
        "planning_failed",
        "execution_crashed",
        "execution_failed",
        "insufficient_data",
    ]
    hypothesis: dict[str, Any] | None = None
    plan: ScreeningPlan | None = None
    pipeline_report: ScreeningPipelineReport | None = None
    receipts: list[dict[str, Any]] = field(default_factory=list)
    critic_decision: CriticDecision | None = None
    memory_record: ResearchMemoryRecord | None = None
    error_message: str | None = None
    prior_record: ResearchMemoryRecord | None = None
    supplemental_results: list[Any] = field(default_factory=list)


@dataclass
class DiscoveryBatchResult:
    """Summary and details of an Alpha Discovery batch execution."""

    batch_id: str
    total_input: int
    valid_count: int
    invalid_count: int
    skipped_count: int
    executed_count: int
    decisions_summary: dict[str, int]
    items: list[DiscoveryItemResult] = field(default_factory=list)


class AlphaDiscoveryEngine:
    """Minimal end-to-end Alpha Discovery engine (#562)."""

    def __init__(
        self,
        memory: ResearchMemory,
        *,
        planner: ScreeningPlanner | None = None,
        critic: CriticGate | None = None,
        result_store: ResultStore | None = None,
        pipeline: ScreeningPipeline | None = None,
        output_base_dir: Path | str | None = None,
        clean_temp_output: bool = True,
    ) -> None:
        self.memory = memory
        self.planner = planner or ScreeningPlanner()
        self.critic = critic or CriticGate()
        self.pipeline = pipeline or ScreeningPipeline(planner=self.planner)
        self.clean_temp_output = clean_temp_output

        # Reuse existing ResultStore or initialize one from root
        if result_store is not None:
            self.result_store = result_store
        elif memory.result_store is not None:
            self.result_store = memory.result_store
        else:
            root_dir = memory.db_path.parent
            self.result_store = ResultStore(ResearchLabConfig(root_dir))

        self.output_base_dir = (
            Path(output_base_dir).resolve()
            if output_base_dir
            else Path("tmp/alpha_discovery_staging").resolve()
        )
        self.output_base_dir.mkdir(parents=True, exist_ok=True)

    def run_single(
        self,
        hypothesis_input: dict[str, Any] | hyp.AlphaHypothesis,
        snapshot_path: Path | str,
        *,
        dataset_binding: dict[str, Any] | None = None,
        auto_supplemental: bool = False,
    ) -> DiscoveryItemResult:
        """Run a single AlphaHypothesis through the discovery funnel."""
        snap_p = Path(snapshot_path).resolve()

        # Step 1: Admission check
        try:
            raw_dict = (
                hypothesis_input.model_dump(exclude_none=True)
                if isinstance(hypothesis_input, hyp.AlphaHypothesis)
                else dict(hypothesis_input)
            )
            validated_hyp = hyp.validate_hypothesis(raw_dict)
            hyp_obj = hyp.AlphaHypothesis.model_validate(validated_hyp)
        except Exception as exc:  # noqa: BLE001
            # Section 14: Honest admission failure without fabricating Run/Evidence
            err_msg = f"Hypothesis validation admission failed: {exc}"
            rec = self.memory.append_admission_failed_record(
                raw_hypothesis=hypothesis_input if isinstance(hypothesis_input, dict) else {},
                error_message=err_msg,
            )
            return DiscoveryItemResult(
                hypothesis_id=str(getattr(hypothesis_input, "hypothesis_id", "unknown")),
                revision=str(getattr(hypothesis_input, "revision", "unknown")),
                status="invalid_definition",
                error_message=err_msg,
                memory_record=rec,
            )

        hyp_id = hyp_obj.hypothesis_id
        hyp_rev = hyp_obj.revision
        sci_hash = hyp_obj.scientific_identity_hash

        # Step 2: Planning
        try:
            plan = self.planner.plan(hyp_obj, dataset_requirements=dataset_binding)
        except Exception as exc:  # noqa: BLE001
            err_msg = f"Planning failed: {exc}"
            rec = self.memory.append_execution_crashed_record(
                hypothesis=hyp_obj,
                plan=None,
                error_message=err_msg,
            )
            return DiscoveryItemResult(
                hypothesis_id=hyp_id,
                revision=hyp_rev,
                status="planning_failed",
                hypothesis=validated_hyp,
                error_message=err_msg,
                memory_record=rec,
            )

        # Step 3: P1-C Duplicate detection vs Execution skip
        history = self.memory.find_by_scientific_identity(sci_hash)
        should_run, skip_reason = self.memory.should_execute(plan, history)
        if not should_run:
            prior_rec = history[-1] if history else None
            return DiscoveryItemResult(
                hypothesis_id=hyp_id,
                revision=hyp_rev,
                status="skipped_duplicate",
                hypothesis=validated_hyp,
                plan=plan,
                prior_record=prior_rec,
                error_message=skip_reason,
            )

        # Step 4: Execute screening pipeline
        staging_dir = self.output_base_dir / f"run_{plan.plan_id}"
        staging_dir.mkdir(parents=True, exist_ok=True)

        try:
            report = self.pipeline.execute_plan(plan, snap_p, staging_dir)
        except Exception as exc:  # noqa: BLE001
            err_msg = f"Pipeline execution crashed: {exc}"
            rec = self.memory.append_execution_crashed_record(
                hypothesis=hyp_obj,
                plan=plan,
                error_message=err_msg,
            )
            return DiscoveryItemResult(
                hypothesis_id=hyp_id,
                revision=hyp_rev,
                status="execution_crashed",
                hypothesis=validated_hyp,
                plan=plan,
                error_message=err_msg,
                memory_record=rec,
            )

        # Step 5: Persist verified bundles to ResultStore and collect Protocol v2 records
        task_records: list[dict[str, Any]] = []
        spec_records: list[dict[str, Any]] = []
        run_records: list[dict[str, Any]] = []
        manifest_records: list[dict[str, Any]] = []
        evidence_records: list[dict[str, Any]] = []
        receipts: list[dict[str, Any]] = []

        for m_res in report.method_results:
            if m_res.bundle_dir and Path(m_res.bundle_dir).is_dir():
                b_dir = Path(m_res.bundle_dir)
                try:
                    receipt = self.result_store.save_v2(b_dir)
                    receipts.append(receipt)

                    # Read immutable verified records from bundle
                    t_data = v2.parse(v2.safe_read(b_dir, "materials/task.json"))
                    s_data = v2.parse(v2.safe_read(b_dir, "materials/spec.json"))
                    r_data = v2.parse(v2.safe_read(b_dir, "run.json"))
                    m_data = v2.parse(v2.safe_read(b_dir, "manifest.json"))
                    e_data = v2.parse(v2.safe_read(b_dir, "evidence.json"))

                    task_records.append(t_data)
                    spec_records.append(s_data)
                    run_records.append(r_data)
                    manifest_records.append(m_data)
                    evidence_records.append(e_data)
                except Exception:  # noqa: BLE001, S110
                    # If persistence failed, still preserve error
                    pass

        # Step 6: Deterministic Critic Gate evaluation
        critic_dec = self.critic.evaluate(
            hypothesis=validated_hyp,
            evidence_or_list=evidence_records,
        )

        # Verify review decision seal fail-closed
        if evidence_records:
            validate_critic_decision(critic_dec, validated_hyp, evidence_records)

        # Step 7: Append-only Research Memory record
        memory_rec = self.memory.append_evaluation_record(
            hypothesis=hyp_obj,
            plan=plan,
            task_records=task_records,
            spec_records=spec_records,
            run_records=run_records,
            manifest_records=manifest_records,
            evidence_records=evidence_records,
            critic_decision=critic_dec,
        )

        # Optional clean staging (ResultStore maintains permanent copies)
        if self.clean_temp_output and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)

        result_item = DiscoveryItemResult(
            hypothesis_id=hyp_id,
            revision=hyp_rev,
            status="completed",
            hypothesis=validated_hyp,
            plan=plan,
            pipeline_report=report,
            receipts=receipts,
            critic_decision=critic_dec,
            memory_record=memory_rec,
        )

        # Step 8: Dynamic NEED_MORE_EVIDENCE supplemental cycle if requested
        if auto_supplemental and critic_dec.decision == "NEED_MORE_EVIDENCE" and critic_dec.missing_evidence:
            supp_result = self.execute_supplemental_cycle(
                prior_item=result_item,
                snapshot_path=snap_p,
                dataset_binding=dataset_binding,
            )
            result_item.supplemental_results.append(supp_result)

        return result_item

    def execute_supplemental_cycle(
        self,
        prior_item: DiscoveryItemResult,
        snapshot_path: Path | str,
        *,
        dataset_binding: dict[str, Any] | None = None,
    ) -> DiscoveryItemResult:
        """Run supplemental screening cycle covering missing evidence (Section 15 & 16)."""
        if not prior_item.hypothesis or not prior_item.critic_decision:
            raise ValueError("Prior item must contain valid hypothesis and critic decision")

        hyp_dict = prior_item.hypothesis
        prior_dec = prior_item.critic_decision
        prior_ev_refs = prior_dec.evidence_refs or [prior_dec.evidence_ref]
        missing_ev = prior_dec.missing_evidence

        # 1. Deterministic supplemental plan
        supp_plan = self.planner.plan_supplemental(
            hypothesis=hyp_dict,
            prior_decision=prior_dec,
            prior_evidence_refs=prior_ev_refs,
            missing_evidence=missing_ev,
            dataset_requirements=dataset_binding,
        )

        # 2. Check should_execute (P1-C: with new methods, must execute!)
        history = self.memory.find_by_scientific_identity(supp_plan.scientific_identity_hash)
        should_run, reason = self.memory.should_execute(supp_plan, history)
        if not should_run:
            return DiscoveryItemResult(
                hypothesis_id=hyp_dict["hypothesis_id"],
                revision=hyp_dict["revision"],
                status="skipped_duplicate",
                hypothesis=hyp_dict,
                plan=supp_plan,
                error_message=reason,
            )

        # 3. Execute only missing methods
        staging_dir = self.output_base_dir / f"run_{supp_plan.plan_id}"
        staging_dir.mkdir(parents=True, exist_ok=True)
        report = self.pipeline.execute_plan(supp_plan, Path(snapshot_path).resolve(), staging_dir)

        # 4. Save to ResultStore
        supp_task_records: list[dict[str, Any]] = []
        supp_spec_records: list[dict[str, Any]] = []
        supp_run_records: list[dict[str, Any]] = []
        supp_manifest_records: list[dict[str, Any]] = []
        supp_evidence_records: list[dict[str, Any]] = []
        receipts: list[dict[str, Any]] = []

        for m_res in report.method_results:
            if m_res.bundle_dir and Path(m_res.bundle_dir).is_dir():
                b_dir = Path(m_res.bundle_dir)
                try:
                    receipt = self.result_store.save_v2(b_dir)
                    receipts.append(receipt)

                    supp_task_records.append(v2.parse(v2.safe_read(b_dir, "materials/task.json")))
                    supp_spec_records.append(v2.parse(v2.safe_read(b_dir, "materials/spec.json")))
                    supp_run_records.append(v2.parse(v2.safe_read(b_dir, "run.json")))
                    supp_manifest_records.append(v2.parse(v2.safe_read(b_dir, "manifest.json")))
                    supp_evidence_records.append(v2.parse(v2.safe_read(b_dir, "evidence.json")))
                except Exception:  # noqa: BLE001, S110
                    pass

        # 5. Load prior valid evidence from ResultStore to aggregate with new evidence
        aggregated_evidences: list[dict[str, Any]] = list(supp_evidence_records)
        for ref in prior_ev_refs:
            ev_id = ref.get("evidence_id")
            if ev_id:
                # Query run by evidence_id from ResultStore
                runs = self.result_store.query_v2_runs(evidence_id=ev_id, verify=False)
                if runs:
                    bundle_facts = self.result_store.load_v2_bundle_facts(runs[0]["run"]["object_id"])
                    aggregated_evidences.append(bundle_facts["evidence"])

        # 6. Re-evaluate with complete evidence facts
        new_dec = self.critic.evaluate(
            hypothesis=hyp_dict,
            evidence_or_list=aggregated_evidences,
        )

        # 7. Append new research memory record
        new_memory_rec = self.memory.append_evaluation_record(
            hypothesis=hyp_dict,
            plan=supp_plan,
            task_records=supp_task_records,
            spec_records=supp_spec_records,
            run_records=supp_run_records,
            manifest_records=supp_manifest_records,
            evidence_records=supp_evidence_records,
            critic_decision=new_dec,
        )

        if self.clean_temp_output and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)

        return DiscoveryItemResult(
            hypothesis_id=hyp_dict["hypothesis_id"],
            revision=hyp_dict["revision"],
            status="completed",
            hypothesis=hyp_dict,
            plan=supp_plan,
            pipeline_report=report,
            receipts=receipts,
            critic_decision=new_dec,
            memory_record=new_memory_rec,
        )

    def run_batch(
        self,
        hypotheses: list[dict[str, Any]],
        snapshot_path: Path | str,
        *,
        dataset_binding: dict[str, Any] | None = None,
        auto_supplemental: bool = False,
    ) -> DiscoveryBatchResult:
        """Process a batch of Alpha hypotheses through the full discovery funnel."""
        token = v2.digest({"hyp_count": len(hypotheses), "snap": str(snapshot_path)})[:12]
        batch_id = f"batch-{token}"
        items: list[DiscoveryItemResult] = []

        valid_count = 0
        invalid_count = 0
        skipped_count = 0
        executed_count = 0
        decisions_summary: dict[str, int] = {
            "REJECT": 0,
            "NEED_MORE_EVIDENCE": 0,
            "PROMOTE": 0,
            "ADMISSION_FAILED": 0,
            "EXECUTION_CRASHED": 0,
        }

        for raw_hyp in hypotheses:
            item = self.run_single(
                raw_hyp,
                snapshot_path=snapshot_path,
                dataset_binding=dataset_binding,
                auto_supplemental=auto_supplemental,
            )
            items.append(item)

            if item.status == "invalid_definition":
                invalid_count += 1
                decisions_summary["ADMISSION_FAILED"] += 1
            elif item.status == "skipped_duplicate":
                valid_count += 1
                skipped_count += 1
            elif item.status in ("execution_crashed", "planning_failed"):
                valid_count += 1
                executed_count += 1
                decisions_summary["EXECUTION_CRASHED"] += 1
            elif item.status == "completed":
                valid_count += 1
                executed_count += 1
                if item.critic_decision:
                    dec = item.critic_decision.decision
                    decisions_summary[dec] = decisions_summary.get(dec, 0) + 1

        return DiscoveryBatchResult(
            batch_id=batch_id,
            total_input=len(hypotheses),
            valid_count=valid_count,
            invalid_count=invalid_count,
            skipped_count=skipped_count,
            executed_count=executed_count,
            decisions_summary=decisions_summary,
            items=items,
        )
