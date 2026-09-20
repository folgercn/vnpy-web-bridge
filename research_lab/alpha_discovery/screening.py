"""Cheap Screening Pipeline and Sequential Executor for Issue #564.

Bridges ScreeningPlan to Protocol v2 statistical_screening execution:
- Deterministic mapping of PLANNED methods to isolated Protocol v2 Task and ExperimentSpec objects.
- Multi-experiment independent generation (isolated directories, append-only, fail-closed).
- Executes via research_lab.runners.v2_statistical_screening.run_statistical_screening.
- Facts-only extraction (coverage, simple_correlation, direction_consistency, stability_split).
- Strictly preserves statuses: PLANNED / UNSUPPORTED / INSUFFICIENT_DATA / EXECUTION_FAILED / COMPLETED.
- Strictly forbids critic scores, ranking, parameter tuning, trading backtest, or PROMOTE/REJECT decisions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from research_lab.alpha_discovery.hypothesis import (
    AlphaHypothesis,
    validate_hypothesis,
)
from research_lab.alpha_discovery.planner import ScreeningPlanner
from research_lab.alpha_discovery.screening_plan import (
    ScreeningMethodRequest,
    ScreeningPlan,
    validate_screening_plan,
)
from research_lab.contracts import statistical_screening_definition as ssd
from research_lab.contracts import v2
from research_lab.runners.v2_statistical_screening import run_statistical_screening

EXECUTION_STATUSES = frozenset({
    "PLANNED",
    "UNSUPPORTED",
    "INSUFFICIENT_DATA",
    "EXECUTION_FAILED",
    "COMPLETED",
})

FORBIDDEN_REPORT_FIELDS = frozenset({
    "score",
    "rank",
    "decision",
    "gate_decision",
    "promote",
    "reject",
    "recommendation",
    "sharpe",
    "pnl",
    "returns",
    "drawdown",
})


class MethodExecutionResult(BaseModel):
    """Immutable record of an individual screening method execution fact."""

    model_config = ConfigDict(extra="forbid")

    method: str
    status: Literal["PLANNED", "UNSUPPORTED", "INSUFFICIENT_DATA", "EXECUTION_FAILED", "COMPLETED"]
    task_id: str | None = None
    spec_id: str | None = None
    run_id: str | None = None
    evidence_id: str | None = None
    bundle_dir: str | None = None
    facts: dict[str, Any] | None = None
    missing_fields: list[str] | None = None
    error_message: str | None = None


class ScreeningPipelineReport(BaseModel):
    """Facts-only execution summary for a ScreeningPlan across all methods.

    Strictly forbids promotion, rejection, or score decisions.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research_lab.screening_pipeline_report.v1"] = "research_lab.screening_pipeline_report.v1"
    hash_profile: Literal["research-json-v1"] = "research-json-v1"
    plan_id: str
    hypothesis_id: str
    scientific_identity_hash: str
    overall_status: Literal["COMPLETED", "PARTIAL", "FAILED", "INSUFFICIENT_DATA", "UNSUPPORTED"]
    method_results: list[MethodExecutionResult]


def build_protocol_v2_task(
    plan: ScreeningPlan,
    method: str,
    snapshot_path: Path,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate isolated Protocol v2 Task for a single screening method."""
    raw_bytes = snapshot_path.read_bytes()
    raw_sha = v2.sha(raw_bytes)
    raw_len = len(raw_bytes)

    # Use dataset_requirements from plan if present, else infer from physical snapshot
    if plan.dataset_requirements is not None:
        ds_req = plan.dataset_requirements
        req_fields = list(ds_req.required_fields)
        provenance = ds_req.provenance
        time_range = ds_req.time_range
        snap_sha = ds_req.snapshot_sha256
        snap_len = ds_req.snapshot_byte_length
        snap_loc = ds_req.snapshot_locator
    else:
        req_fields = ["timestamp", "symbol", "feature_val", "target_val"]
        provenance = "screening_plan_inferred"
        time_range = None
        snap_sha = raw_sha
        snap_len = raw_len
        snap_loc = str(snapshot_path)

    task_data_req: dict[str, Any] = {
        "snapshot_sha256": snap_sha,
        "snapshot_locator": snap_loc,
        "snapshot_byte_length": snap_len,
        "required_fields": req_fields,
        "provenance": provenance,
    }
    if time_range:
        task_data_req["time_range"] = time_range

    task_token = v2.digest({
        "plan_id": plan.plan_id,
        "plan_content_hash": plan.plan_content_hash,
        "method": method,
    })[:12]
    task: dict[str, Any] = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": f"task-{plan.plan_id}-{method}-{task_token}",
        "revision": "rev.1",
        "research_type": "statistical_factor",
        "task_profile": ssd.PROFILE_NAME,
        "objective": f"Cheap statistical screening ({method}) for {plan.hypothesis_ref.hypothesis_id}",
        "data_requirements": task_data_req,
        "methods": [method],
    }
    if parameters:
        task["parameters"] = parameters
    task["task_content_hash"] = v2.digest({k: v for k, v in task.items() if k != "task_content_hash"})
    return task


def build_protocol_v2_spec(
    task: dict[str, Any],
    plan: ScreeningPlan,
    method: str,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate isolated Protocol v2 ExperimentSpec corresponding to Task."""
    task_token = v2.digest({
        "plan_id": plan.plan_id,
        "plan_content_hash": plan.plan_content_hash,
        "method": method,
    })[:12]
    spec: dict[str, Any] = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": f"spec-{plan.plan_id}-{method}-{task_token}",
        "revision": "rev.1",
        "task_id": task["task_id"],
        "task_revision": task["revision"],
        "task_content_hash": task["task_content_hash"],
        "experiment_type": "statistical_factor",
        "research_stage": "validation",
        "screening_profile": ssd.PROFILE_NAME,
        "dataset_requirements": dict(task["data_requirements"]),
        "methods": [method],
    }
    if parameters:
        spec["parameters"] = parameters
    spec["spec_content_hash"] = v2.digest({k: v for k, v in spec.items() if k != "spec_content_hash"})
    return spec


class SequentialScreeningExecutor:
    """Executes screening methods sequentially with complete isolation."""

    def __init__(self, definitions: v2.Definitions | None = None) -> None:
        self.definitions = definitions or v2.Definitions()

    def execute_method(
        self,
        method_req: ScreeningMethodRequest,
        plan: ScreeningPlan,
        snapshot_path: Path,
        method_output_dir: Path,
    ) -> MethodExecutionResult:
        """Execute a single method request from a ScreeningPlan."""
        method_name = method_req.method

        if method_req.status == "UNSUPPORTED":
            return MethodExecutionResult(
                method=method_name,
                status="UNSUPPORTED",
                error_message=method_req.reason or "not_registered",
            )

        if method_req.status == "INSUFFICIENT_DATA":
            return MethodExecutionResult(
                method=method_name,
                status="INSUFFICIENT_DATA",
                missing_fields=method_req.missing_fields,
                error_message=method_req.reason or "insufficient_data",
            )

        # P1-3: Strict physical snapshot verification before any execution
        # Verify physical properties match plan.dataset_requirements 100%
        # Fail closed immediately BEFORE creating output directory!
        snap_p = snapshot_path.resolve()
        if not snap_p.exists() or not snap_p.is_file() or snap_p.is_symlink():
            return MethodExecutionResult(
                method=method_name,
                status="EXECUTION_FAILED",
                error_message=f"Snapshot path does not exist, is not a regular file, or is symlink: {snapshot_path}",
            )

        try:
            raw_bytes = snap_p.read_bytes()
            raw_sha = v2.sha(raw_bytes)
            raw_len = len(raw_bytes)
        except OSError as exc:
            return MethodExecutionResult(
                method=method_name,
                status="EXECUTION_FAILED",
                error_message=f"Failed reading snapshot file: {exc}",
            )

        if plan.dataset_requirements is not None:
            ds_req = plan.dataset_requirements
            # 1. 100% full 64-character SHA-256 exact match
            if raw_sha != ds_req.snapshot_sha256:
                return MethodExecutionResult(
                    method=method_name,
                    status="EXECUTION_FAILED",
                    error_message=(
                        f"Runtime snapshot sha256 mismatch with plan dataset_requirements: "
                        f"expected {ds_req.snapshot_sha256}, got {raw_sha}"
                    ),
                )
            # 2. Exact byte length match
            if raw_len != ds_req.snapshot_byte_length:
                return MethodExecutionResult(
                    method=method_name,
                    status="EXECUTION_FAILED",
                    error_message=(
                        f"Runtime snapshot byte_length mismatch with plan dataset_requirements: "
                        f"expected {ds_req.snapshot_byte_length}, got {raw_len}"
                    ),
                )
            # 3. Check locator alignment
            expected_locator = Path(ds_req.snapshot_locator)
            if expected_locator.is_absolute() and snap_p != expected_locator.resolve():
                return MethodExecutionResult(
                    method=method_name,
                    status="EXECUTION_FAILED",
                    error_message=(
                        f"Runtime snapshot locator mismatch: "
                        f"expected {expected_locator.resolve()}, got {snap_p}"
                    ),
                )

        # PLANNED method: build Task & Spec, validate against Protocol v2, and execute runner
        try:
            task = build_protocol_v2_task(
                plan,
                method_name,
                snapshot_path,
                parameters=method_req.parameters if method_req.parameters else None,
            )
            spec = build_protocol_v2_spec(
                task,
                plan,
                method_name,
                parameters=method_req.parameters if method_req.parameters else None,
            )
            # Contract admission check
            v2.validate_spec(spec, task, self.definitions)
        except Exception as exc:  # noqa: BLE001
            return MethodExecutionResult(
                method=method_name,
                status="EXECUTION_FAILED",
                error_message=f"Task/Spec admission failed: {exc}",
            )

        if method_output_dir.exists():
            return MethodExecutionResult(
                method=method_name,
                status="EXECUTION_FAILED",
                task_id=task["task_id"],
                spec_id=spec["spec_id"],
                error_message=f"Output directory already exists: {method_output_dir}",
            )

        try:
            run_statistical_screening(
                task=task,
                spec=spec,
                snapshot_path=snapshot_path,
                output_dir=method_output_dir,
            )
        except Exception as exc:  # noqa: BLE001
            return MethodExecutionResult(
                method=method_name,
                status="EXECUTION_FAILED",
                task_id=task["task_id"],
                spec_id=spec["spec_id"],
                bundle_dir=str(method_output_dir),
                error_message=f"Screening runner execution failed: {exc}",
            )

        # Parse verified artifacts from output bundle
        try:
            run_data = v2.parse((method_output_dir / "run.json").read_bytes())
            evidence_data = v2.parse((method_output_dir / "evidence.json").read_bytes())

            run_status = run_data.get("run_status")
            run_id = run_data.get("run_id")
            evidence_id = evidence_data.get("evidence_id")

            if run_status == "COMPLETED":
                summary_data = v2.parse((method_output_dir / "statistical_summary.json").read_bytes())
                raw_facts = summary_data.get("facts", {}).get(method_name, {})
                # Strictly forbid decision words
                for forbidden in FORBIDDEN_REPORT_FIELDS:
                    if forbidden in raw_facts:
                        raise ValueError(f"Forbidden decision field {forbidden!r} present in facts")

                return MethodExecutionResult(
                    method=method_name,
                    status="COMPLETED",
                    task_id=task["task_id"],
                    spec_id=spec["spec_id"],
                    run_id=run_id,
                    evidence_id=evidence_id,
                    bundle_dir=str(method_output_dir),
                    facts=raw_facts,
                )
            elif run_status == "INSUFFICIENT_DATA":
                diag_data = v2.parse((method_output_dir / "failure_diagnostics.json").read_bytes())
                return MethodExecutionResult(
                    method=method_name,
                    status="INSUFFICIENT_DATA",
                    task_id=task["task_id"],
                    spec_id=spec["spec_id"],
                    run_id=run_id,
                    evidence_id=evidence_id,
                    bundle_dir=str(method_output_dir),
                    missing_fields=diag_data.get("missing_fields"),
                    error_message=diag_data.get("error_message"),
                )
            else:
                diag_data = v2.parse((method_output_dir / "failure_diagnostics.json").read_bytes())
                return MethodExecutionResult(
                    method=method_name,
                    status="EXECUTION_FAILED",
                    task_id=task["task_id"],
                    spec_id=spec["spec_id"],
                    run_id=run_id,
                    evidence_id=evidence_id,
                    bundle_dir=str(method_output_dir),
                    error_message=diag_data.get("error_message", "Execution failed"),
                )
        except Exception as exc:  # noqa: BLE001
            return MethodExecutionResult(
                method=method_name,
                status="EXECUTION_FAILED",
                task_id=task["task_id"],
                spec_id=spec["spec_id"],
                bundle_dir=str(method_output_dir),
                error_message=f"Failed parsing bundle results: {exc}",
            )


class ScreeningPipeline:
    """Orchestrates end-to-end deterministic screening from Hypothesis to verified Evidence."""

    def __init__(
        self,
        planner: ScreeningPlanner | None = None,
        executor: SequentialScreeningExecutor | None = None,
    ) -> None:
        self.planner = planner or ScreeningPlanner()
        self.executor = executor or SequentialScreeningExecutor()

    def execute_plan(
        self,
        plan: ScreeningPlan | dict[str, Any],
        snapshot_path: Path | str,
        output_base_dir: Path | str,
    ) -> ScreeningPipelineReport:
        if isinstance(plan, ScreeningPlan):
            raw_dict = plan.model_dump(exclude_none=True)
        elif isinstance(plan, dict):
            raw_dict = plan
        else:
            raise TypeError(f"plan must be ScreeningPlan or dict, got {type(plan)}")

        plan_dict = validate_screening_plan(raw_dict)
        plan_obj = ScreeningPlan.model_validate(plan_dict)

        snap_p = Path(snapshot_path).resolve()
        base_dir = Path(output_base_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)

        results: list[MethodExecutionResult] = []
        for method_req in plan_obj.methods:
            method_out = base_dir / f"{method_req.method}_{plan_obj.plan_id}"
            res = self.executor.execute_method(
                method_req=method_req,
                plan=plan_obj,
                snapshot_path=snap_p,
                method_output_dir=method_out,
            )
            results.append(res)

        # Derive overall status
        statuses = {r.status for r in results}
        if statuses == {"COMPLETED"}:
            overall = "COMPLETED"
        elif statuses == {"INSUFFICIENT_DATA"}:
            overall = "INSUFFICIENT_DATA"
        elif statuses == {"UNSUPPORTED"}:
            overall = "UNSUPPORTED"
        elif statuses == {"EXECUTION_FAILED"}:
            overall = "FAILED"
        elif "COMPLETED" in statuses:
            overall = "PARTIAL"
        else:
            overall = "FAILED"

        report = ScreeningPipelineReport(
            plan_id=plan_obj.plan_id,
            hypothesis_id=plan_obj.hypothesis_ref.hypothesis_id,
            scientific_identity_hash=plan_obj.scientific_identity_hash,
            overall_status=overall,
            method_results=results,
        )
        return report

    def execute_hypothesis(
        self,
        hypothesis: AlphaHypothesis | dict[str, Any],
        snapshot_path: Path | str,
        output_base_dir: Path | str,
        *,
        dataset_requirements: dict[str, Any] | None = None,
    ) -> tuple[ScreeningPlan, ScreeningPipelineReport]:
        """Convenience method: plan hypothesis and execute pipeline in one step."""
        if isinstance(hypothesis, AlphaHypothesis):
            raw_dict = hypothesis.model_dump(exclude_none=True)
        elif isinstance(hypothesis, dict):
            raw_dict = hypothesis
        else:
            raise TypeError(f"hypothesis must be AlphaHypothesis or dict, got {type(hypothesis)}")
        hyp_validated = validate_hypothesis(raw_dict)
        hyp_obj = AlphaHypothesis.model_validate(hyp_validated)

        snap_p = Path(snapshot_path).resolve()
        # If dataset_requirements not passed, build default from snapshot
        if dataset_requirements is None and snap_p.is_file():
            raw_bytes = snap_p.read_bytes()
            dataset_requirements = {
                "snapshot_locator": str(snap_p),
                "snapshot_sha256": v2.sha(raw_bytes),
                "snapshot_byte_length": len(raw_bytes),
                "required_fields": ["timestamp", "symbol", "feature_val", "target_val"],
                "provenance": "synthetic_screening_fixture",
            }

        plan = self.planner.plan(hyp_obj, dataset_requirements=dataset_requirements)
        report = self.execute_plan(plan, snap_p, output_base_dir)
        return plan, report
