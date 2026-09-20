"""Deterministic Sealed Critic Promotion Gate for Alpha Discovery MVP (#565, #562).

Evaluates Protocol v2 Evidence against explicit, deterministic rules and outputs
sealed REJECT / NEED_MORE_EVIDENCE / PROMOTE decisions without modifying source Evidence.
Enforces complete criteria parameter freezing, canonical review content hash sealing,
strict Hypothesis/Evidence reference binding, and fail-closed evaluation across all #565 dimensions.
Does not perform production approval, automated order placement, or LLM evaluation.
"""

from __future__ import annotations

import math
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from research_lab.contracts import statistical_screening_definition as ssd
from research_lab.contracts import v2

RULE_VERSION = "research_lab.critic_gate.rule.v1"
HASH_PROFILE = "research-json-v1"
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")

# Mandatory evaluation dimensions per #565
MANDATORY_DIMENSIONS = frozenset({
    "data_sufficiency",
    "signal_coverage",
    "sample_size",
    "direction_consistency",
    "leakage_lookahead_risk",
    "metric_definability",
    "few_sample_outlier_influence",
    "stability_split",
    "basic_cost_sensitivity",
    "falsification_conditions",
})


def _format_decimal(val: float | None, decimals: int = 6) -> str | None:
    if val is None or math.isnan(val) or math.isinf(val):
        return None
    s = f"{val:.{decimals}f}".rstrip("0").rstrip(".")
    if s in ("", "-0"):
        s = "0"
    return s


class CriticFinding(BaseModel):
    """Specific finding from evaluating an evidence metric against a rule."""

    model_config = ConfigDict(extra="forbid")

    category: str
    assessment: Literal["pass", "risk", "insufficient_evidence"]
    severity: Literal["info", "warning", "critical"]
    summary: str
    evidence_details: dict[str, Any] = Field(default_factory=dict)


class CriticDecision(BaseModel):
    """Deterministic, immutable, sealed evaluation decision for an Alpha Hypothesis based on Evidence.

    Freezes complete criteria parameters and seals review_content_hash over all decision facts.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research_lab.critic_decision.v1"] = "research_lab.critic_decision.v1"
    hash_profile: Literal["research-json-v1"] = HASH_PROFILE
    decision_id: str
    criteria_id: str
    profile: str
    rule_version: str
    criteria: dict[str, Any]
    hypothesis_ref: dict[str, str]
    evidence_ref: dict[str, str]
    evidence_count: int = Field(ge=0, description="Sealed exact cardinality of referenced evidence items.")
    evidence_refs: list[dict[str, str]] = Field(default_factory=list)
    decision: Literal["REJECT", "NEED_MORE_EVIDENCE", "PROMOTE"]
    findings: list[CriticFinding]
    reject_reasons: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    promoted_reasons: list[str] = Field(default_factory=list)
    review_content_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[a-f0-9]{64}$",
        description="Canonical SHA-256 digest sealing all decision and criteria fields.",
    )


def _sanitize_for_canonical(obj: Any) -> Any:
    """Recursively convert values to strict v2 JSON profile-compliant types."""
    if obj is None:
        return None
    if type(obj) is bool:
        return obj
    if type(obj) is int:
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, float):
        return _format_decimal(obj) or "0"
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_sanitize_for_canonical(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_canonical(v) for k, v in obj.items()}
    if hasattr(obj, "model_dump"):
        return _sanitize_for_canonical(obj.model_dump())
    return str(obj)


def compute_review_content_hash(data: dict[str, Any]) -> str:
    """Compute repository-pinned research-json-v1 SHA-256 digest of review decision."""
    clean = {k: v for k, v in data.items() if k not in ("review_content_hash", "decision_id")}
    sanitized = _sanitize_for_canonical(clean)
    return v2.digest(sanitized)


def validate_critic_decision(
    decision: dict[str, Any] | CriticDecision,
    hypothesis: dict[str, Any],
    evidence: dict[str, Any] | list[dict[str, Any]],
) -> dict[str, Any]:
    """Fail-closed validation verifying review hash integrity and exact Hypothesis/Evidence binding.

    Rejects tampered hashes, altered criteria, extra/missing/replaced/duplicated evidence references.
    """
    if isinstance(decision, CriticDecision):
        dec_dict = decision.model_dump()
    elif isinstance(decision, dict):
        dec_dict = dict(decision)
    else:
        raise TypeError(f"decision must be dict or CriticDecision, got {type(decision)}")

    # 1. Check review_content_hash presence and format
    declared_hash = dec_dict.get("review_content_hash")
    if not isinstance(declared_hash, str) or not HASH_PATTERN.fullmatch(declared_hash):
        raise ValueError(f"Invalid review_content_hash format: {declared_hash!r}")

    try:
        expected_hash = compute_review_content_hash(dec_dict)
    except Exception as e:
        raise ValueError(f"review_content_hash computation failed: {e}") from e
    if declared_hash != expected_hash:
        raise ValueError(
            f"review_content_hash mismatch: declared {declared_hash}, computed {expected_hash} (tampered content)"
        )

    # 2. Strict Hypothesis reference binding
    hyp_ref = dec_dict.get("hypothesis_ref", {})
    expected_hyp_id = hypothesis.get("hypothesis_id")
    expected_hyp_rev = hypothesis.get("revision")
    expected_hyp_hash = hypothesis.get("hypothesis_content_hash")
    if (
        hyp_ref.get("hypothesis_id") != expected_hyp_id
        or hyp_ref.get("revision") != expected_hyp_rev
        or hyp_ref.get("content_hash") != expected_hyp_hash
    ):
        raise ValueError(
            f"Hypothesis reference mismatch: decision has {hyp_ref}, expected {expected_hyp_id}@{expected_hyp_rev}:{expected_hyp_hash}"
        )

    # 3. Strict Evidence exact multi-binding (P1-3)
    if isinstance(evidence, dict):
        actual_ev_list = [evidence]
    elif isinstance(evidence, list):
        actual_ev_list = list(evidence)
    else:
        raise TypeError(f"evidence must be dict or list of dicts, got {type(evidence)}")

    actual_ids = [str(e.get("evidence_id", "")) for e in actual_ev_list]
    if len(actual_ids) != len(set(actual_ids)):
        raise ValueError(f"Duplicate evidence items in provided evidence list: {actual_ids}")

    # Sort actual evidence by evidence_id
    sorted_actual = sorted(actual_ev_list, key=lambda e: str(e.get("evidence_id", "")))
    stored_ev_refs = dec_dict.get("evidence_refs", [])
    if not stored_ev_refs and dec_dict.get("evidence_ref"):
        # Single evidence fallback
        stored_ev_refs = [dec_dict["evidence_ref"]]

    stored_ids = [str(r.get("evidence_id", "")) for r in stored_ev_refs]
    if len(stored_ids) != len(set(stored_ids)):
        raise ValueError(f"Duplicate evidence refs declared in decision: {stored_ids}")

    sorted_refs = sorted(stored_ev_refs, key=lambda r: str(r.get("evidence_id", "")))

    sealed_count = dec_dict.get("evidence_count")
    if sealed_count is not None and sealed_count != len(sorted_refs):
        raise ValueError(
            f"Evidence cardinality mismatch: sealed evidence_count={sealed_count}, but declared refs count={len(sorted_refs)}"
        )

    if len(sorted_actual) != len(sorted_refs):
        raise ValueError(
            f"Evidence set cardinality mismatch: actual evidence count {len(sorted_actual)} != decision declared {len(sorted_refs)}"
        )

    for i, (act, ref) in enumerate(zip(sorted_actual, sorted_refs)):
        act_id = str(act.get("evidence_id", ""))
        ref_id = str(ref.get("evidence_id", ""))
        if act_id != ref_id:
            raise ValueError(f"Evidence ID mismatch at index {i}: actual {act_id} != declared {ref_id}")

        act_rev = str(act.get("revision", "rev.1"))
        ref_rev = str(ref.get("revision", "rev.1"))
        if act_rev != ref_rev:
            raise ValueError(f"Evidence revision mismatch for {act_id}: actual {act_rev} != declared {ref_rev}")

        act_hash = str(act.get("evidence_content_hash", ""))
        ref_hash = str(ref.get("content_hash", ""))
        if act_hash != ref_hash:
            raise ValueError(f"Evidence content_hash mismatch for {act_id}: actual {act_hash} != declared {ref_hash}")

        act_status = str(act.get("execution_status") or act.get("run_status_snapshot") or "")
        ref_status = str(ref.get("execution_status", ""))
        if ref_status and act_status and act_status != ref_status:
            raise ValueError(
                f"Evidence execution_status mismatch for {act_id}: actual {act_status} != declared {ref_status}"
            )

    # 4. Schema validation
    return CriticDecision.model_validate(dec_dict).model_dump()


class CriticGate:
    """Deterministic rules-based gate for Alpha Hypothesis screening evidence (#565)."""

    def __init__(
        self,
        *,
        criteria_id: str = ssd.CRITERIA_ID,
        profile: str = ssd.PROFILE_NAME,
        rule_version: str = RULE_VERSION,
        min_coverage: float = 0.80,
        promote_coverage: float = 0.95,
        min_ic: float = 0.05,
        min_consistency: float = 0.45,
        promote_consistency: float = 0.55,
        max_stability_diff: float = 0.30,
        severe_stability_diff: float = 0.50,
        min_sample_size: int = 20,
        promote_sample_size: int = 100,
        required_evidence_dimensions: set[str] | None = None,
    ) -> None:
        self.criteria_id = criteria_id
        self.profile = profile
        self.rule_version = rule_version
        self.min_coverage = min_coverage
        self.promote_coverage = promote_coverage
        self.min_ic = min_ic
        self.min_consistency = min_consistency
        self.promote_consistency = promote_consistency
        self.max_stability_diff = max_stability_diff
        self.severe_stability_diff = severe_stability_diff
        self.min_sample_size = min_sample_size
        self.promote_sample_size = promote_sample_size

        # Fail closed if caller attempts to reduce mandatory dimensions
        if required_evidence_dimensions is not None:
            provided = frozenset(required_evidence_dimensions)
            missing = MANDATORY_DIMENSIONS - provided
            if missing:
                raise ValueError(
                    f"Cannot reduce mandatory evidence dimensions under profile {self.profile}: "
                    f"missing required dimensions {sorted(missing)}"
                )
            self.required_evidence_dimensions = provided
        else:
            self.required_evidence_dimensions = MANDATORY_DIMENSIONS

    def freeze_criteria(self) -> dict[str, Any]:
        """Freeze complete criteria parameters into an immutable dictionary."""
        return {
            "criteria_id": self.criteria_id,
            "profile": self.profile,
            "rule_version": self.rule_version,
            "min_coverage": _format_decimal(self.min_coverage) or "0.8",
            "promote_coverage": _format_decimal(self.promote_coverage) or "0.95",
            "min_ic": _format_decimal(self.min_ic) or "0.05",
            "min_consistency": _format_decimal(self.min_consistency) or "0.45",
            "promote_consistency": _format_decimal(self.promote_consistency) or "0.55",
            "max_stability_diff": _format_decimal(self.max_stability_diff) or "0.3",
            "severe_stability_diff": _format_decimal(self.severe_stability_diff) or "0.5",
            "min_sample_size": int(self.min_sample_size),
            "promote_sample_size": int(self.promote_sample_size),
            "required_evidence_dimensions": sorted(self.required_evidence_dimensions),
        }

    def evaluate(
        self,
        hypothesis: dict[str, Any],
        evidence_or_list: dict[str, Any] | list[dict[str, Any]],
        *,
        summary: dict[str, Any] | None = None,
        failure_diagnostics: dict[str, Any] | None = None,
    ) -> CriticDecision:
        """Evaluate Protocol v2 Evidence for an AlphaHypothesis across all #565 dimensions."""
        findings: list[CriticFinding] = []
        reject_reasons: list[str] = []
        missing_evidence: list[str] = []
        promoted_reasons: list[str] = []

        frozen_criteria = self.freeze_criteria()

        hyp_ref = {
            "hypothesis_id": str(hypothesis.get("hypothesis_id", "")),
            "revision": str(hypothesis.get("revision", "")),
            "content_hash": str(hypothesis.get("hypothesis_content_hash", "")),
        }

        # Normalize evidence input into list
        if isinstance(evidence_or_list, dict):
            ev_list = [evidence_or_list]
        elif isinstance(evidence_or_list, list):
            ev_list = list(evidence_or_list)
        else:
            raise TypeError(f"evidence must be dict or list of dicts, got {type(evidence_or_list)}")

        if not ev_list:
            missing_evidence.append("no_evidence_provided")
            primary_ev_ref = {"evidence_id": "none", "revision": "rev.1", "content_hash": "0" * 64}
            ev_refs = []
        else:
            primary_ev = ev_list[0]
            primary_ev_ref = {
                "evidence_id": str(primary_ev.get("evidence_id", "")),
                "revision": str(primary_ev.get("revision", "rev.1")),
                "content_hash": str(primary_ev.get("evidence_content_hash", "")),
                "execution_status": str(primary_ev.get("execution_status") or primary_ev.get("run_status_snapshot", "")),
            }
            ev_refs = [
                {
                    "evidence_id": str(e.get("evidence_id", "")),
                    "revision": str(e.get("revision", "rev.1")),
                    "content_hash": str(e.get("evidence_content_hash", "")),
                    "execution_status": str(e.get("execution_status") or e.get("run_status_snapshot", "")),
                }
                for e in ev_list
            ]

        # Extract all available facts across all evidence objects
        all_facts: dict[str, Any] = {}
        all_methods_applied: set[str] = set()
        has_execution_failure = False
        has_insufficient_data = False

        for ev in ev_list:
            status = ev.get("execution_status") or ev.get("run_status_snapshot")
            if status in ("FAILED", "EXECUTION_FAILED"):
                has_execution_failure = True
            elif status == "INSUFFICIENT_DATA":
                has_insufficient_data = True

            metrics = ev.get("typed_metrics")
            if isinstance(metrics, dict):
                methods = metrics.get("methods_applied", [])
                all_methods_applied.update(methods)
                facts = metrics.get("facts", {})
                if isinstance(facts, dict):
                    all_facts.update(facts)

        if summary and isinstance(summary, dict):
            methods = summary.get("methods_applied", [])
            all_methods_applied.update(methods)
            facts = summary.get("facts", {})
            if isinstance(facts, dict):
                all_facts.update(facts)

        # Dimension 1: data_sufficiency & P1-B check
        # P1-B: execution failure NEVER equals scientific REJECT
        if has_execution_failure:
            findings.append(
                CriticFinding(
                    category="data_sufficiency",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Execution failure encountered during screening experiment. Engineering failure does not falsify hypothesis.",
                    evidence_details={"has_execution_failure": True},
                )
            )
            missing_evidence.append("execution_failed_rerun_required")
        elif has_insufficient_data:
            findings.append(
                CriticFinding(
                    category="data_sufficiency",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Screening experiment returned INSUFFICIENT_DATA status due to missing fields or empty sample.",
                    evidence_details={"has_insufficient_data": True},
                )
            )
            missing_evidence.append("insufficient_snapshot_data")
        else:
            findings.append(
                CriticFinding(
                    category="data_sufficiency",
                    assessment="pass",
                    severity="info",
                    summary="All screening runs completed successfully without execution failure.",
                    evidence_details={"methods": sorted(all_methods_applied)},
                )
            )

        # Dimension 2: signal_coverage
        cov_fact = all_facts.get("coverage")
        if not cov_fact:
            findings.append(
                CriticFinding(
                    category="signal_coverage",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Missing coverage evidence facts.",
                )
            )
            missing_evidence.append("coverage")
        else:
            cov_ratio_val = float(cov_fact.get("coverage_ratio", 0.0))
            if cov_ratio_val < self.min_coverage:
                findings.append(
                    CriticFinding(
                        category="signal_coverage",
                        assessment="risk",
                        severity="critical",
                        summary=f"Coverage ratio {cov_ratio_val:.4f} is below required threshold {self.min_coverage:.2f}",
                        evidence_details=cov_fact,
                    )
                )
                reject_reasons.append(f"Coverage {cov_ratio_val:.4f} < {self.min_coverage:.2f}")
            elif cov_ratio_val >= self.promote_coverage:
                findings.append(
                    CriticFinding(
                        category="signal_coverage",
                        assessment="pass",
                        severity="info",
                        summary=f"Coverage ratio {cov_ratio_val:.4f} meets promotion threshold {self.promote_coverage:.2f}",
                        evidence_details=cov_fact,
                    )
                )
                promoted_reasons.append("coverage_excellent")
            else:
                findings.append(
                    CriticFinding(
                        category="signal_coverage",
                        assessment="pass",
                        severity="info",
                        summary=f"Coverage ratio {cov_ratio_val:.4f} meets minimum threshold {self.min_coverage:.2f}",
                        evidence_details=cov_fact,
                    )
                )

        # Dimension 3: sample_size & metric_definability
        corr_fact = all_facts.get("simple_correlation")
        if not corr_fact:
            findings.append(
                CriticFinding(
                    category="sample_size",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Missing correlation evidence facts for sample size assessment.",
                )
            )
            missing_evidence.append("simple_correlation")
        else:
            sample_size = int(corr_fact.get("sample_size", 0))
            raw_ic = corr_fact.get("pearson_ic")

            # Metric definability
            if raw_ic is None:
                findings.append(
                    CriticFinding(
                        category="metric_definability",
                        assessment="insufficient_evidence",
                        severity="warning",
                        summary="Pearson IC could not be computed (constant or non-finite values).",
                        evidence_details=corr_fact,
                    )
                )
                missing_evidence.append("non_constant_ic")
            else:
                findings.append(
                    CriticFinding(
                        category="metric_definability",
                        assessment="pass",
                        severity="info",
                        summary="Feature and target metrics are well-defined and finite.",
                        evidence_details={"ic": raw_ic},
                    )
                )

            # Sample size
            if sample_size < self.min_sample_size:
                findings.append(
                    CriticFinding(
                        category="sample_size",
                        assessment="insufficient_evidence",
                        severity="warning",
                        summary=f"Sample size {sample_size} is below required minimum {self.min_sample_size}.",
                        evidence_details=corr_fact,
                    )
                )
                missing_evidence.append("insufficient_sample_size")
            elif sample_size >= self.promote_sample_size:
                findings.append(
                    CriticFinding(
                        category="sample_size",
                        assessment="pass",
                        severity="info",
                        summary=f"Sample size {sample_size} meets promote threshold {self.promote_sample_size}.",
                        evidence_details=corr_fact,
                    )
                )
                promoted_reasons.append("sample_size_adequate")
            else:
                findings.append(
                    CriticFinding(
                        category="sample_size",
                        assessment="pass",
                        severity="info",
                        summary=f"Sample size {sample_size} meets minimum threshold {self.min_sample_size}.",
                        evidence_details=corr_fact,
                    )
                )

        # Dimension 4: direction_consistency
        dir_fact = all_facts.get("direction_consistency")
        if not dir_fact:
            findings.append(
                CriticFinding(
                    category="direction_consistency",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Missing direction consistency evidence facts.",
                )
            )
            missing_evidence.append("direction_consistency")
        else:
            raw_consistency = dir_fact.get("consistency_ratio")
            if raw_consistency is None:
                findings.append(
                    CriticFinding(
                        category="direction_consistency",
                        assessment="insufficient_evidence",
                        severity="warning",
                        summary="Direction consistency ratio is undefined.",
                        evidence_details=dir_fact,
                    )
                )
                missing_evidence.append("valid_direction_consistency")
            else:
                consistency_val = float(raw_consistency)
                if consistency_val < self.min_consistency:
                    findings.append(
                        CriticFinding(
                            category="direction_consistency",
                            assessment="risk",
                            severity="critical",
                            summary=f"Direction consistency {consistency_val:.4f} < {self.min_consistency:.2f}",
                            evidence_details=dir_fact,
                        )
                    )
                    reject_reasons.append(f"Direction consistency {consistency_val:.4f} < {self.min_consistency:.2f}")
                elif consistency_val >= self.promote_consistency:
                    findings.append(
                        CriticFinding(
                            category="direction_consistency",
                            assessment="pass",
                            severity="info",
                            summary=f"Direction consistency {consistency_val:.4f} meets promote threshold {self.promote_consistency:.2f}",
                            evidence_details=dir_fact,
                        )
                    )
                    promoted_reasons.append("direction_consistency_strong")
                else:
                    findings.append(
                        CriticFinding(
                            category="direction_consistency",
                            assessment="pass",
                            severity="info",
                            summary=f"Direction consistency {consistency_val:.4f} meets minimum threshold {self.min_consistency:.2f}",
                            evidence_details=dir_fact,
                        )
                    )

        # Dimension 5: stability_split
        stab_fact = all_facts.get("stability_split")
        if not stab_fact:
            findings.append(
                CriticFinding(
                    category="stability_split",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Missing stability split evidence facts.",
                )
            )
            missing_evidence.append("stability_split")
        else:
            raw_diff = stab_fact.get("correlation_difference")
            if raw_diff is None:
                findings.append(
                    CriticFinding(
                        category="stability_split",
                        assessment="insufficient_evidence",
                        severity="warning",
                        summary="Stability correlation difference could not be evaluated.",
                        evidence_details=stab_fact,
                    )
                )
                missing_evidence.append("valid_stability_split")
            else:
                diff_val = float(raw_diff)
                if diff_val >= self.severe_stability_diff:
                    findings.append(
                        CriticFinding(
                            category="stability_split",
                            assessment="risk",
                            severity="critical",
                            summary=f"Severe stability split difference {diff_val:.4f} >= {self.severe_stability_diff:.2f}",
                            evidence_details=stab_fact,
                        )
                    )
                    reject_reasons.append(f"Severe stability split decay {diff_val:.4f} >= {self.severe_stability_diff:.2f}")
                elif diff_val <= self.max_stability_diff:
                    findings.append(
                        CriticFinding(
                            category="stability_split",
                            assessment="pass",
                            severity="info",
                            summary=f"Stability split difference {diff_val:.4f} is within acceptable bound {self.max_stability_diff:.2f}",
                            evidence_details=stab_fact,
                        )
                    )
                    promoted_reasons.append("stability_split_consistent")
                else:
                    findings.append(
                        CriticFinding(
                            category="stability_split",
                            assessment="risk",
                            severity="warning",
                            summary=f"Moderate stability split difference {diff_val:.4f} exceeds {self.max_stability_diff:.2f}",
                            evidence_details=stab_fact,
                        )
                    )

        # Dimension 6: leakage_lookahead_risk
        leak_fact = all_facts.get("leakage_audit")
        if not leak_fact:
            findings.append(
                CriticFinding(
                    category="leakage_lookahead_risk",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Missing leakage audit evidence facts.",
                )
            )
            missing_evidence.append("leakage_audit")
        else:
            audit_status = leak_fact.get("audit_status")
            missing_meta = leak_fact.get("missing_availability_metadata", True)
            cov_ratio = float(leak_fact.get("audit_coverage_ratio", 0.0))
            unverifiable = int(leak_fact.get("unverifiable_rows", 0))
            temp_violations = leak_fact.get("temporal_violation_count")
            overlap_violations = leak_fact.get("target_overlap_violation_count")

            if (temp_violations is not None and temp_violations > 0) or (
                overlap_violations is not None and overlap_violations > 0
            ):
                findings.append(
                    CriticFinding(
                        category="leakage_lookahead_risk",
                        assessment="risk",
                        severity="critical",
                        summary=(
                            f"Lookahead / temporal causality violation detected "
                            f"(temporal={temp_violations}, overlap={overlap_violations})."
                        ),
                        evidence_details=leak_fact,
                    )
                )
                reject_reasons.append(
                    f"Lookahead leakage violation (temporal={temp_violations}, overlap={overlap_violations})"
                )
            elif (
                audit_status != "COMPLETED"
                or missing_meta
                or unverifiable > 0
                or cov_ratio < 1.0
                or temp_violations is None
                or overlap_violations is None
            ):
                findings.append(
                    CriticFinding(
                        category="leakage_lookahead_risk",
                        assessment="insufficient_evidence",
                        severity="warning",
                        summary=(
                            "Leakage audit unverifiable or incomplete due to missing availability "
                            "or target-window metadata (audit_status!=COMPLETED or unverifiable_rows>0)."
                        ),
                        evidence_details=leak_fact,
                    )
                )
                missing_evidence.append("leakage_audit_verifiable_metadata")
            else:
                findings.append(
                    CriticFinding(
                        category="leakage_lookahead_risk",
                        assessment="pass",
                        severity="info",
                        summary="Audit confirmed feature availability <= decision time and target start > decision time across 100% verified rows.",
                        evidence_details=leak_fact,
                    )
                )
                promoted_reasons.append("leakage_audit_clean")

        # Dimension 7: few_sample_outlier_influence
        outlier_fact = all_facts.get("outlier_sensitivity")
        if not outlier_fact:
            findings.append(
                CriticFinding(
                    category="few_sample_outlier_influence",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Missing outlier sensitivity evidence facts.",
                )
            )
            missing_evidence.append("outlier_sensitivity")
        else:
            dir_preserved = outlier_fact.get("direction_preserved", False)
            base_dir = outlier_fact.get("baseline_direction")
            trim_dir = outlier_fact.get("trimmed_direction")

            if base_dir == "neutral" or outlier_fact.get("baseline_ic") is None:
                findings.append(
                    CriticFinding(
                        category="few_sample_outlier_influence",
                        assessment="insufficient_evidence",
                        severity="warning",
                        summary="Baseline correlation is neutral or undefined; outlier influence cannot be evaluated.",
                        evidence_details=outlier_fact,
                    )
                )
                missing_evidence.append("outlier_sensitivity_valid_baseline")
            elif not dir_preserved:
                findings.append(
                    CriticFinding(
                        category="few_sample_outlier_influence",
                        assessment="risk",
                        severity="critical",
                        summary=f"Outlier sensitivity failed: signal direction reversed or collapsed after 1% trimming ({base_dir} -> {trim_dir}).",
                        evidence_details=outlier_fact,
                    )
                )
                reject_reasons.append(f"Outlier sensitivity direction reversed ({base_dir} -> {trim_dir})")
            else:
                findings.append(
                    CriticFinding(
                        category="few_sample_outlier_influence",
                        assessment="pass",
                        severity="info",
                        summary="Signal direction and magnitude preserved after trimming 1% extreme observations.",
                        evidence_details=outlier_fact,
                    )
                )
                promoted_reasons.append("outlier_sensitivity_direction_preserved")

        # Dimension 8: basic_cost_sensitivity
        cost_fact = all_facts.get("cost_sensitivity")
        if not cost_fact:
            findings.append(
                CriticFinding(
                    category="basic_cost_sensitivity",
                    assessment="insufficient_evidence",
                    severity="warning",
                    summary="Missing cost sensitivity evidence facts.",
                )
            )
            missing_evidence.append("cost_sensitivity")
        else:
            gross_ret = float(cost_fact.get("gross_screening_return", "0"))
            net_0 = float(cost_fact.get("net_return_0bps", "0"))
            net_1 = float(cost_fact.get("net_return_1bps", "0"))
            obs = int(cost_fact.get("observations", 0))

            if obs < self.min_sample_size:
                findings.append(
                    CriticFinding(
                        category="basic_cost_sensitivity",
                        assessment="insufficient_evidence",
                        severity="warning",
                        summary=f"Cost sensitivity observations {obs} below minimum {self.min_sample_size}.",
                        evidence_details=cost_fact,
                    )
                )
                missing_evidence.append("cost_sensitivity_sample_size")
            elif gross_ret <= 0.0 or net_0 <= 0.0:
                findings.append(
                    CriticFinding(
                        category="basic_cost_sensitivity",
                        assessment="risk",
                        severity="critical",
                        summary=f"Gross screening return non-positive ({gross_ret:.6f}) before trading costs.",
                        evidence_details=cost_fact,
                    )
                )
                reject_reasons.append(f"Gross screening return non-positive ({gross_ret:.6f})")
            elif net_1 < 0.0:
                findings.append(
                    CriticFinding(
                        category="basic_cost_sensitivity",
                        assessment="risk",
                        severity="critical",
                        summary=f"Screening return collapses at minimal 1bps trading cost (net_1bps={net_1:.6f}).",
                        evidence_details=cost_fact,
                    )
                )
                reject_reasons.append(f"Return collapses at 1bps cost (net_1bps={net_1:.6f})")
            else:
                findings.append(
                    CriticFinding(
                        category="basic_cost_sensitivity",
                        assessment="pass",
                        severity="info",
                        summary=f"Gross return positive ({gross_ret:.4f}) and survives 1bps friction (net_1bps={net_1:.4f}).",
                        evidence_details=cost_fact,
                    )
                )
                promoted_reasons.append("cost_sensitivity_positive")

        # Dimension 9: falsification_conditions from AlphaHypothesis
        falsification_conds = hypothesis.get("falsification_conditions", [])
        if corr_fact and corr_fact.get("pearson_ic") is not None:
            actual_ic = float(corr_fact["pearson_ic"])
            for cond in falsification_conds:
                # Check for explicit condition strings
                if "ic <" in cond or "IC <" in cond:
                    m = re.search(r"[iI][cC]\s*<\s*([0-9.]+)", cond)
                    if m:
                        thresh = float(m.group(1))
                        if abs(actual_ic) < thresh:
                            findings.append(
                                CriticFinding(
                                    category="falsification_conditions",
                                    assessment="risk",
                                    severity="critical",
                                    summary=f"Falsification condition triggered: actual |IC| {abs(actual_ic):.4f} < {thresh}",
                                    evidence_details={"condition": cond, "actual_ic": _format_decimal(actual_ic) or "0"},
                                )
                            )
                            reject_reasons.append(f"Falsification triggered: |IC| {abs(actual_ic):.4f} < {thresh}")
                if "opposite_direction" in cond or "negative_ic" in cond or "positive_ic" in cond:
                    # P1-2: Strictly read and validate expected_direction; NO silent fallback to 'direction' or 'positive'
                    expected_dir = hypothesis.get("expected_direction")
                    if not expected_dir or expected_dir not in ("positive", "negative"):
                        raise ValueError(f"Hypothesis missing valid expected_direction, got {expected_dir!r}")

                    is_opposite = False
                    if "opposite_direction" in cond:
                        if (expected_dir == "positive" and actual_ic < 0) or (
                            expected_dir == "negative" and actual_ic > 0
                        ):
                            is_opposite = True
                    elif (
                        ("negative_ic" in cond and expected_dir == "positive" and actual_ic < 0)
                        or ("positive_ic" in cond and expected_dir == "negative" and actual_ic > 0)
                    ):
                        is_opposite = True

                    if is_opposite:
                        findings.append(
                            CriticFinding(
                                category="falsification_conditions",
                                assessment="risk",
                                severity="critical",
                                summary=(
                                    f"Falsification condition triggered: actual IC {actual_ic:.4f} "
                                    f"contradicts expected direction ({expected_dir})."
                                ),
                                evidence_details={
                                    "condition": cond,
                                    "actual_ic": _format_decimal(actual_ic) or "0",
                                    "expected_direction": expected_dir,
                                },
                            )
                        )
                        reject_reasons.append(
                            f"Falsification triggered: actual IC contradicts expected direction ({expected_dir})"
                        )

        # Aggregate final decision strictly fail-closed per #565
        # 1. Any execution failure -> NEED_MORE_EVIDENCE (P1-B: never scientific REJECT)
        if has_execution_failure:
            decision = "NEED_MORE_EVIDENCE"
        # 2. Critical falsification / risk -> REJECT
        elif reject_reasons:
            decision = "REJECT"
        # 3. Missing evidence / insufficient data -> NEED_MORE_EVIDENCE
        elif missing_evidence or has_insufficient_data:
            decision = "NEED_MORE_EVIDENCE"
        # 4. Strict promotion: all required dimensions satisfied with zero warnings/risks
        elif len(promoted_reasons) >= 3 and not any(f.assessment != "pass" for f in findings):
            decision = "PROMOTE"
        else:
            decision = "NEED_MORE_EVIDENCE"

        return self._seal_decision(
            criteria=frozen_criteria,
            hyp_ref=hyp_ref,
            ev_ref=primary_ev_ref,
            ev_refs=ev_refs,
            decision=decision,
            findings=findings,
            reject_reasons=sorted(dict.fromkeys(reject_reasons)),
            missing_evidence=sorted(dict.fromkeys(missing_evidence)),
            promoted_reasons=sorted(dict.fromkeys(promoted_reasons)),
        )

    def _seal_decision(
        self,
        criteria: dict[str, Any],
        hyp_ref: dict[str, Any],
        ev_ref: dict[str, Any],
        ev_refs: list[dict[str, Any]],
        decision: Literal["REJECT", "NEED_MORE_EVIDENCE", "PROMOTE"],
        findings: list[CriticFinding],
        reject_reasons: list[str],
        missing_evidence: list[str],
        promoted_reasons: list[str],
    ) -> CriticDecision:
        """Construct sealed CriticDecision with canonical review_content_hash and deterministic ID."""
        sorted_ev_refs = sorted(ev_refs, key=lambda r: str(r.get("evidence_id", "")))
        evidence_count = len(sorted_ev_refs)

        pre_seal = {
            "schema_version": "research_lab.critic_decision.v1",
            "hash_profile": HASH_PROFILE,
            "criteria_id": self.criteria_id,
            "profile": self.profile,
            "rule_version": self.rule_version,
            "criteria": criteria,
            "hypothesis_ref": hyp_ref,
            "evidence_ref": ev_ref,
            "evidence_count": evidence_count,
            "evidence_refs": sorted_ev_refs,
            "decision": decision,
            "findings": [f.model_dump() for f in findings],
            "reject_reasons": list(reject_reasons),
            "missing_evidence": list(missing_evidence),
            "promoted_reasons": list(promoted_reasons),
        }
        pre_seal = _sanitize_for_canonical(pre_seal)
        sanitized_findings = [CriticFinding.model_validate(f) for f in pre_seal["findings"]]

        # Compute deterministic sealed review hash
        review_hash = compute_review_content_hash(pre_seal)
        # Deterministic decision ID derived from review_content_hash, no random UUID
        decision_id = f"rev-{review_hash[:16]}"

        return CriticDecision(
            decision_id=decision_id,
            criteria_id=self.criteria_id,
            profile=self.profile,
            rule_version=self.rule_version,
            criteria=pre_seal["criteria"],
            hypothesis_ref=hyp_ref,
            evidence_ref=ev_ref,
            evidence_count=evidence_count,
            evidence_refs=sorted_ev_refs,
            decision=decision,
            findings=sanitized_findings,
            reject_reasons=reject_reasons,
            missing_evidence=missing_evidence,
            promoted_reasons=promoted_reasons,
            review_content_hash=review_hash,
        )
