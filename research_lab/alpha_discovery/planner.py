"""ScreeningPlanner: Deterministic Mapping from AlphaHypothesis to ScreeningPlan.

Implements #564 planner boundaries:
- Pure deterministic planning: zero UUIDs, zero current-time lookups, stable sorting.
- Strictly supports 4 cheap methods: coverage, simple_correlation, direction_consistency, stability_split.
- Explicit UNSUPPORTED (reason="not_registered") for unrecognised methods.
- Explicit INSUFFICIENT_DATA (missing_fields, reason) when required data fields are absent.
- Falsification conditions retained strictly as falsification_context without making decisions.
- Strictly forbids critic scores, ranking, parameter tuning, or trading promotion/rejection.
"""

from __future__ import annotations

from typing import Any

from research_lab.alpha_discovery.hypothesis import (
    AlphaHypothesis,
    compute_scientific_identity_hash,
    validate_hypothesis,
)
from research_lab.alpha_discovery.screening_plan import (
    ALLOWED_METHODS,
    DatasetRequirements,
    PlanProvenance,
    ScreeningMethodRequest,
    ScreeningPlan,
    compute_plan_content_hash,
    validate_screening_plan,
)
from research_lab.contracts import v2

METHOD_REQUIRED_FIELDS: dict[str, list[str]] = {
    "coverage": ["timestamp", "symbol"],
    "simple_correlation": ["feature_val", "target_val"],
    "direction_consistency": ["feature_val", "target_val"],
    "stability_split": ["feature_val", "target_val"],
    "leakage_audit": ["as_of_time", "feature_availability_time", "target_start_time"],
    "outlier_sensitivity": ["feature_val", "target_val"],
    "cost_sensitivity": ["feature_val", "target_val"],
}


class ScreeningPlanner:
    """Deterministic planner mapping an AlphaHypothesis to a verified ScreeningPlan."""

    def __init__(self, default_dataset_requirements: dict[str, Any] | None = None) -> None:
        self.default_dataset_requirements = default_dataset_requirements

    def plan(
        self,
        hypothesis: AlphaHypothesis | dict[str, Any],
        *,
        dataset_requirements: dict[str, Any] | None = None,
        override_methods: list[str] | None = None,
        planned_at: str | None = None,
        created_by: str = "research_lab.screening_planner",
    ) -> ScreeningPlan:
        """Deterministically map an AlphaHypothesis to a ScreeningPlan.

        Never alters scientific identity, never generates random identifiers,
        and never executes screening experiments.
        """
        if isinstance(hypothesis, AlphaHypothesis):
            raw_dict = hypothesis.model_dump(exclude_none=True)
        elif isinstance(hypothesis, dict):
            raw_dict = hypothesis
        else:
            raise TypeError(f"hypothesis must be AlphaHypothesis or dict, got {type(hypothesis)}")
        hyp_dict = validate_hypothesis(raw_dict)

        hyp_id = hyp_dict["hypothesis_id"]
        hyp_rev = hyp_dict["revision"]
        hyp_hash = hyp_dict["hypothesis_content_hash"]
        scientific_hash = compute_scientific_identity_hash(hyp_dict)

        # Use deterministic timestamp from hypothesis provenance if not explicitly given
        timestamp = planned_at or hyp_dict["provenance"]["created_at"]

        # Determine effective dataset requirements
        effective_ds_req = dataset_requirements or self.default_dataset_requirements
        ds_req_model: DatasetRequirements | None = None
        available_fields: set[str] = set()

        if effective_ds_req is not None:
            # If available_fields explicitly provided in dataset dict, extract it;
            # otherwise fall back to required_fields as declaring what the snapshot provides.
            if "available_fields" in effective_ds_req:
                available_fields = set(effective_ds_req["available_fields"])
            else:
                available_fields = set(effective_ds_req.get("required_fields", []))

            clean_ds = {k: v for k, v in effective_ds_req.items() if k != "available_fields"}
            ds_req_model = DatasetRequirements.model_validate(clean_ds)

        # Process proposed screening methods deterministically
        raw_methods = override_methods if override_methods is not None else hyp_dict.get("proposed_screening_methods", [])
        # Deduplicate and sort alphabetically for 100% stable ordering
        unique_methods = sorted(dict.fromkeys(raw_methods))

        method_requests: list[ScreeningMethodRequest] = []
        for m in unique_methods:
            if m not in ALLOWED_METHODS:
                method_requests.append(
                    ScreeningMethodRequest(
                        method=m,
                        status="UNSUPPORTED",
                        reason="not_registered",
                        missing_fields=None,
                        required_fields=[],
                        parameters={},
                    )
                )
                continue

            # Check data sufficiency for supported method
            expected_fields = METHOD_REQUIRED_FIELDS.get(m, [])
            if ds_req_model is None:
                method_requests.append(
                    ScreeningMethodRequest(
                        method=m,
                        status="INSUFFICIENT_DATA",
                        reason="missing_dataset_requirements",
                        missing_fields=expected_fields,
                        required_fields=expected_fields,
                        parameters={},
                    )
                )
            else:
                # Check whether all required fields are satisfied by the dataset
                missing = [f for f in expected_fields if f not in available_fields]
                if missing:
                    method_requests.append(
                        ScreeningMethodRequest(
                            method=m,
                            status="INSUFFICIENT_DATA",
                            reason="missing_required_fields",
                            missing_fields=missing,
                            required_fields=expected_fields,
                            parameters={},
                        )
                    )
                else:
                    method_requests.append(
                        ScreeningMethodRequest(
                            method=m,
                            status="PLANNED",
                            reason=None,
                            missing_fields=None,
                            required_fields=expected_fields,
                            parameters={},
                        )
                    )

        # Plan ID is deterministic based on hypothesis exact ref, full dataset canonical digest, and normalized methods
        if ds_req_model is not None:
            ds_exact_digest = v2.digest(ds_req_model.model_dump(exclude_none=True))
        else:
            ds_exact_digest = "none"

        plan_identity_payload = {
            "schema_version": "research_lab.screening_plan.v1",
            "hypothesis_id": hyp_id,
            "hypothesis_revision": hyp_rev,
            "hypothesis_content_hash": hyp_hash,
            "scientific_identity_hash": scientific_hash,
            "dataset_digest": ds_exact_digest,
            "methods": unique_methods,
        }
        identity_token = v2.digest(plan_identity_payload)[:16]
        plan_id = f"plan-{hyp_id}-{hyp_rev}-{identity_token}"

        provenance = PlanProvenance(
            created_by=created_by,
            planned_at=timestamp,
            origin_hypothesis_id=hyp_id,
            origin_hypothesis_revision=hyp_rev,
            origin_hypothesis_hash=hyp_hash,
            origin_scientific_identity_hash=scientific_hash,
        )

        plan_dict: dict[str, Any] = {
            "schema_version": "research_lab.screening_plan.v1",
            "hash_profile": "research-json-v1",
            "plan_id": plan_id,
            "hypothesis_ref": {
                "hypothesis_id": hyp_id,
                "revision": hyp_rev,
                "content_hash": hyp_hash,
            },
            "scientific_identity_hash": scientific_hash,
            "methods": [m.model_dump(exclude_none=True) for m in method_requests],
            "falsification_context": list(hyp_dict.get("falsification_conditions", [])),
            "provenance": provenance.model_dump(),
        }
        if ds_req_model is not None:
            plan_dict["dataset_requirements"] = ds_req_model.model_dump(exclude_none=True)

        plan_dict["plan_content_hash"] = compute_plan_content_hash(plan_dict)
        validated = validate_screening_plan(plan_dict)
        return ScreeningPlan.model_validate(validated)

    def plan_supplemental(
        self,
        hypothesis: AlphaHypothesis | dict[str, Any],
        prior_decision: Any,
        prior_evidence_refs: list[dict[str, Any]],
        missing_evidence: list[str],
        *,
        dataset_requirements: dict[str, Any] | None = None,
        planned_at: str | None = None,
        created_by: str = "research_lab.screening_planner.supplemental",
    ) -> ScreeningPlan:
        """Create a deterministic supplemental ScreeningPlan covering missing evidence (Section 15 & 16).

        Binds:
        - Hypothesis exact ref
        - Prior CriticDecision exact ref
        - Prior Evidence refs
        - missing_evidence list
        - Dataset exact identity
        - New method set
        Guarantees that identical inputs yield identical supplemental plan identity.
        """
        # Map missing evidence descriptors to candidate screening methods
        # (e.g. "leakage_audit", "leakage_audit_verifiable_metadata" -> "leakage_audit")
        candidate_methods: set[str] = set()
        for item in missing_evidence:
            for allowed in ALLOWED_METHODS:
                if allowed in item or item in allowed:
                    candidate_methods.add(allowed)

        if not candidate_methods:
            # If no direct method match, fall back to any method in ALLOWED_METHODS not in prior evidence
            prior_methods = {
                ref.get("method") for ref in prior_evidence_refs if ref.get("method")
            }
            candidate_methods = set(ALLOWED_METHODS) - prior_methods

        if not candidate_methods:
            candidate_methods = {"coverage"}

        unique_methods = sorted(candidate_methods)

        if isinstance(prior_decision, dict):
            dec_id = prior_decision.get("decision_id", "dec-unknown")
            dec_hash = prior_decision.get("review_content_hash", "0" * 64)
        else:
            dec_id = getattr(prior_decision, "decision_id", "dec-unknown")
            dec_hash = getattr(prior_decision, "review_content_hash", "0" * 64)

        # Generate base plan with the specific supplemental methods without mutating hypothesis
        base_plan = self.plan(
            hypothesis,
            dataset_requirements=dataset_requirements,
            override_methods=unique_methods,
            planned_at=planned_at,
            created_by=created_by,
        )

        # Re-tag plan_id with supplemental token sealing prior decision, prior evidence, and missing evidence
        supp_token = v2.digest({
            "prior_decision_id": dec_id,
            "prior_decision_hash": dec_hash,
            "prior_evidence_refs": prior_evidence_refs,
            "missing_evidence": sorted(missing_evidence),
            "base_plan_content_hash": base_plan.plan_content_hash,
        })[:12]

        hyp_ref = base_plan.hypothesis_ref
        supp_plan_id = f"plan-supp-{hyp_ref.hypothesis_id}-{hyp_ref.revision}-{supp_token}"

        plan_dict = base_plan.model_dump(exclude_none=True)
        plan_dict["plan_id"] = supp_plan_id
        plan_dict["plan_content_hash"] = compute_plan_content_hash(plan_dict)
        validated = validate_screening_plan(plan_dict)
        return ScreeningPlan.model_validate(validated)
