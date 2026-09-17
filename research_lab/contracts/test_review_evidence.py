"""Synthetic-only review-evidence chains for registered offline profiles."""

import copy

import pytest
from jsonschema import ValidationError

from research_lab.contracts import v2
from research_lab.contracts.test_issue481_backtest import fixture as issue481_bundle
from research_lab.contracts.test_v2 import trend20_bundle


def seal(record, prefix):
    record[prefix + "_content_hash"] = v2.digest(
        {key: value for key, value in record.items() if key != prefix + "_content_hash"}
    )


def present(manifest):
    return [
        {
            "manifest_id": manifest["manifest_id"],
            "manifest_revision": manifest["revision"],
            "manifest_content_hash": manifest["manifest_content_hash"],
            "artifact_id": entry["artifact_id"],
            "role": entry["role"],
            "content_sha256": entry["content_sha256"],
        }
        for entry in manifest["entries"]
        if entry["availability"] == "present"
    ]


def reseal_review_response(records, response):
    review = records["review"]
    evidence = records["result_evidence"]
    review["evidence_id"] = evidence["evidence_id"]
    review["evidence_content_hash"] = evidence["evidence_content_hash"]
    seal(review, "review")
    response["output_refs"] = [v2.check_record(review, "review")]


def objects_for(tmp_path, profile):
    if profile == "trend20":
        task, spec, run, manifest = trend20_bundle(tmp_path)
        criteria_id = "phase0.trend20.review_evidence.criteria"
        metrics = {
            "profile": "trend20_same_exact_contract_structural",
            "metrics_precision": "half_even_12_decimal_places_from_unrounded_daily_values",
            "daily_ic": {
                "value": "-0.012667903046",
                "unit": "correlation",
                "precision": "half_even_12_decimal_places_from_unrounded_daily_values",
            },
            "top_bottom_spread": {
                "value": "-0.001355555878",
                "unit": "log_return",
                "precision": "half_even_12_decimal_places_from_unrounded_daily_values",
            },
        }
    else:
        task, spec, run, manifest = issue481_bundle(tmp_path)
        criteria_id = "phase0.issue481.review_evidence.criteria"
        identities = next(
            entry for entry in manifest["entries"] if entry["role"] == "backtest_summary"
        )
        summary = v2.parse((tmp_path / identities["relative_path"]).read_bytes())
        metrics = {
            "profile": "issue481_corrected603_structural",
            "account_metrics": summary["account_metrics"],
        }
    evidence = {
        "schema_version": "research_lab.evidence.v2",
        "hash_profile": "research-json-v1",
        "evidence_id": profile + "-synthetic-evidence",
        "run_id": run["run_id"],
        "run_status_snapshot": "COMPLETED",
        "run_content_hash": run["run_content_hash"],
        "execution_status": "COMPLETED",
        "manifest_id": manifest["manifest_id"],
        "manifest_revision": manifest["revision"],
        "manifest_content_hash": manifest["manifest_content_hash"],
        "typed_metrics": metrics,
        "supporting_artifacts": present(manifest),
        "missing_reason": None,
    }
    seal(evidence, "evidence")
    definition = next(
        entry
        for entry in v2.Definitions().entries
        if entry["kind"] == "criteria" and entry["name"] == criteria_id
    )
    criteria = {key: definition[key] for key in ("name", "revision", "content_hash")}
    criteria["id"] = criteria.pop("name")
    records = {
        "research_task": task,
        "experiment_spec": spec,
        "experiment_run": run,
        "artifact_manifest": manifest,
        "result_evidence": evidence,
    }
    context = {kind: v2.check_record(value, kind) for kind, value in records.items()}
    request = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": profile + "-synthetic-request",
        "message_kind": "request",
        "operation": "review_evidence",
        "sender_role": "execution",
        "recipient_role": "critic",
        "context_refs": context,
        "artifact_requirements": {
            "role_profile_ref": manifest["artifact_profile"],
            "required_roles": sorted(v2.COMMON | v2.TYPED[spec["experiment_type"]]),
            "exact_refs": present(manifest),
        },
        "expected_outputs": [
            {"object_type": "review", "schema_version": "research_lab.review.v2"}
        ],
        "review_scope": "research_assessment",
        "criteria_ref": criteria,
    }
    review = {
        "schema_version": "research_lab.review.v2",
        "hash_profile": "research-json-v1",
        "review_id": profile + "-synthetic-review",
        "revision": "rev.1",
        "evidence_id": evidence["evidence_id"],
        "evidence_content_hash": evidence["evidence_content_hash"],
        "reviewer": "synthetic structural fixture; not independent acceptance",
        "reviewed_at": "2026-09-17T00:00:00.000000Z",
        "criteria_ref": criteria,
        "recommendation": "improve",
        "reason": "Synthetic structural fixture only; no execution or independent evidence claim.",
    }
    seal(review, "review")
    records["review"] = review
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": profile + "-synthetic-response",
        "message_kind": "response",
        "operation": "review_evidence",
        "sender_role": "critic",
        "recipient_role": "execution",
        "context_refs": context,
        "in_reply_to": request["handoff_id"],
        "status": "completed",
        "output_refs": [v2.check_record(review, "review")],
        "review_scope": "research_assessment",
    }
    return request, records, response


@pytest.mark.parametrize("profile", ["trend20", "issue481"])
def test_registered_review_evidence_chain(tmp_path, profile):
    request, records, response = objects_for(tmp_path, profile)
    payloads = v2.validate_manifest(
        tmp_path,
        records["artifact_manifest"],
        records["experiment_run"],
        task=records["research_task"],
        spec=records["experiment_spec"],
    )
    assert v2.validate_handoff(request, records, response, payloads=payloads)
    assert v2.validate_handoff(request, records, response, root=tmp_path)


@pytest.mark.parametrize(
    "mutation",
    ["criteria", "metric", "profile", "artifact", "roles", "cross_profile", "run", "response", "status"],
)
def test_registered_review_evidence_rejects_rehashed_mutations(tmp_path, mutation):
    request, records, response = objects_for(tmp_path, "trend20")
    if mutation == "criteria":
        request["criteria_ref"]["content_hash"] = "0" * 64
        records["review"]["criteria_ref"] = copy.deepcopy(request["criteria_ref"])
        seal(records["review"], "review")
        response["output_refs"] = [v2.check_record(records["review"], "review")]
    elif mutation == "metric":
        records["result_evidence"]["typed_metrics"]["daily_ic"]["unit"] = "log_return"
        seal(records["result_evidence"], "evidence")
        request["context_refs"]["result_evidence"] = v2.check_record(records["result_evidence"], "result_evidence")
        reseal_review_response(records, response)
    elif mutation == "profile":
        records["result_evidence"]["typed_metrics"]["profile"] = "other"
        seal(records["result_evidence"], "evidence")
        request["context_refs"]["result_evidence"] = v2.check_record(records["result_evidence"], "result_evidence")
        reseal_review_response(records, response)
    elif mutation == "artifact":
        request["artifact_requirements"]["exact_refs"].pop()
    elif mutation == "roles":
        request["artifact_requirements"]["required_roles"].append("quality_summary")
    elif mutation == "cross_profile":
        definition = next(
            entry
            for entry in v2.Definitions().entries
            if entry["name"] == "phase0.method_definition"
        )
        records["artifact_manifest"]["entries"][0]["content_schema_ref"] = {
            key: definition[key]
            for key in ("name", "revision", "content_hash", "locator")
        }
        seal(records["artifact_manifest"], "manifest")
        evidence = records["result_evidence"]
        evidence["manifest_content_hash"] = records["artifact_manifest"]["manifest_content_hash"]
        for ref in evidence["supporting_artifacts"]:
            ref["manifest_content_hash"] = records["artifact_manifest"]["manifest_content_hash"]
        seal(evidence, "evidence")
        request["context_refs"]["artifact_manifest"] = v2.check_record(
            records["artifact_manifest"], "artifact_manifest"
        )
        request["context_refs"]["result_evidence"] = v2.check_record(
            evidence, "result_evidence"
        )
        request["artifact_requirements"]["exact_refs"] = evidence["supporting_artifacts"]
        reseal_review_response(records, response)
    elif mutation == "run":
        records["experiment_run"]["run_id"] = "wrong"
        seal(records["experiment_run"], "run")
        request["context_refs"]["experiment_run"] = v2.check_record(records["experiment_run"], "experiment_run")
    elif mutation == "response":
        response["in_reply_to"] = "wrong"
    else:
        response["status"] = "incomplete"
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, records, response, root=tmp_path)


def test_issue481_account_metrics_are_not_combined(tmp_path):
    request, records, response = objects_for(tmp_path, "issue481")
    rows = records["result_evidence"]["typed_metrics"]["account_metrics"]
    rows[-1] = copy.deepcopy(rows[0])
    seal(records["result_evidence"], "evidence")
    request["context_refs"]["result_evidence"] = v2.check_record(
        records["result_evidence"], "result_evidence"
    )
    reseal_review_response(records, response)
    with pytest.raises((ValueError, ValidationError), match="account"):
        v2.validate_handoff(request, records, response, root=tmp_path)


@pytest.mark.parametrize("value", ["2", "-1.1", "0.1234567890123"])
def test_trend20_ic_range_and_precision_rehashed_rejected(tmp_path, value):
    request, records, response = objects_for(tmp_path, "trend20")
    evidence = records["result_evidence"]
    evidence["typed_metrics"]["daily_ic"]["value"] = value
    seal(evidence, "evidence")
    request["context_refs"]["result_evidence"] = v2.check_record(
        evidence, "result_evidence"
    )
    reseal_review_response(records, response)
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, records, response, root=tmp_path)


def test_trend20_evidence_metrics_summary_mismatch_rehashed_rejected(tmp_path):
    request, records, response = objects_for(tmp_path, "trend20")
    payloads = v2.validate_manifest(
        tmp_path,
        records["artifact_manifest"],
        records["experiment_run"],
        task=records["research_task"],
        spec=records["experiment_spec"],
    )
    evidence = records["result_evidence"]
    evidence["typed_metrics"]["daily_ic"]["value"] = "0.9"
    seal(evidence, "evidence")
    request["context_refs"]["result_evidence"] = v2.check_record(evidence, "result_evidence")
    reseal_review_response(records, response)
    with pytest.raises(ValueError, match="Trend20 daily IC value mismatch"):
        v2.validate_handoff(request, records, response, payloads=payloads)
    with pytest.raises(ValueError, match="Trend20 daily IC value mismatch"):
        v2.validate_handoff(request, records, response, root=tmp_path)

    # Now restore daily_ic but mutate top_bottom_spread
    request, records, response = objects_for(tmp_path, "trend20")
    evidence = records["result_evidence"]
    evidence["typed_metrics"]["top_bottom_spread"]["value"] = "100"
    seal(evidence, "evidence")
    request["context_refs"]["result_evidence"] = v2.check_record(evidence, "result_evidence")
    reseal_review_response(records, response)
    with pytest.raises(ValueError, match="Trend20 top-bottom spread value mismatch"):
        v2.validate_handoff(request, records, response, payloads=payloads)
    with pytest.raises(ValueError, match="Trend20 top-bottom spread value mismatch"):
        v2.validate_handoff(request, records, response, root=tmp_path)


@pytest.mark.parametrize("field,value", [("net_pnl_cny", "999999999"), ("fees_cny", "12345"), ("trade_count", 123456)])
def test_issue481_evidence_metrics_summary_mismatch_rehashed_rejected(tmp_path, field, value):
    request, records, response = objects_for(tmp_path, "issue481")
    payloads = v2.validate_manifest(
        tmp_path,
        records["artifact_manifest"],
        records["experiment_run"],
        task=records["research_task"],
        spec=records["experiment_spec"],
    )
    evidence = records["result_evidence"]
    evidence["typed_metrics"]["account_metrics"][0][field] = value
    seal(evidence, "evidence")
    request["context_refs"]["result_evidence"] = v2.check_record(evidence, "result_evidence")
    reseal_review_response(records, response)
    with pytest.raises(ValueError, match=f"Issue481 {field} mismatch"):
        v2.validate_handoff(request, records, response, payloads=payloads)
    with pytest.raises(ValueError, match=f"Issue481 {field} mismatch"):
        v2.validate_handoff(request, records, response, root=tmp_path)


@pytest.mark.parametrize("profile", ["trend20", "issue481"])
def test_registered_review_evidence_requires_payloads_or_root(tmp_path, profile):
    request, records, response = objects_for(tmp_path, profile)
    with pytest.raises(ValueError, match="verified payloads or root required"):
        v2.validate_handoff(request, records, response)


@pytest.mark.parametrize("profile", ["trend20", "issue481"])
@pytest.mark.parametrize(
    "status,code,outcome",
    [
        ("blocked", "dependency_unavailable", "known"),
        ("rejected", "invalid_input", "not_started"),
        ("incomplete", "missing_delivery", "known"),
        ("unsupported", "capability_unsupported", "not_started"),
        ("blocked", "execution_outcome_unknown", "unknown"),
    ],
)
def test_noncompleted_review_handoff_response(tmp_path, profile, status, code, outcome):
    request, records, _ = objects_for(tmp_path, profile)
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": profile + "-synthetic-noncompleted-response",
        "message_kind": "response",
        "operation": "review_evidence",
        "sender_role": "critic",
        "recipient_role": "execution",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": status,
        "review_scope": request["review_scope"],
        "problem": {
            "code": code,
            "reason": f"Synthetic test {status} condition.",
            "affected_items": ["dataset_metadata"],
            "resume_condition": "Provide required dependency or valid specification.",
            "execution_outcome": outcome,
        },
    }
    records_without_review = {k: v for k, v in records.items() if k != "review"}
    assert v2.validate_handoff(request, records_without_review, response, root=tmp_path)


def test_noncompleted_review_handoff_rejects_output_refs(tmp_path):
    request, records, _ = objects_for(tmp_path, "trend20")
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "trend20-synthetic-illegal-output-response",
        "message_kind": "response",
        "operation": "review_evidence",
        "sender_role": "critic",
        "recipient_role": "execution",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": "blocked",
        "review_scope": request["review_scope"],
        "output_refs": [v2.check_record(records["review"], "review")],
        "problem": {
            "code": "dependency_unavailable",
            "reason": "Synthetic blocked reason.",
            "affected_items": ["dataset_metadata"],
            "resume_condition": "Condition.",
            "execution_outcome": "known",
        },
    }
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, records, response, root=tmp_path)


def test_noncompleted_review_handoff_rejects_scope_mismatch(tmp_path):
    request, records, _ = objects_for(tmp_path, "trend20")
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "trend20-synthetic-scope-mismatch-response",
        "message_kind": "response",
        "operation": "review_evidence",
        "sender_role": "critic",
        "recipient_role": "execution",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": "blocked",
        "review_scope": "failure_diagnosis",  # request has research_assessment
        "problem": {
            "code": "dependency_unavailable",
            "reason": "Synthetic blocked reason.",
            "affected_items": ["dataset_metadata"],
            "resume_condition": "Condition.",
            "execution_outcome": "known",
        },
    }
    records_without_review = {k: v for k, v in records.items() if k != "review"}
    with pytest.raises((ValueError, ValidationError), match="review scope"):
        v2.validate_handoff(request, records_without_review, response, root=tmp_path)


def test_arbitrary_unverified_payload_mapping_rejected(tmp_path):
    request, records, response = objects_for(tmp_path, "trend20")
    # A plain mapping cannot claim provenance from validate_manifest.
    fake_payloads = {
        "statistical_summary": {
            "method_id": "phase0.trend20_same_exact_contract.rev1",
            "research_stage": "exploration",
            "sample_count": 9999,
            "date_count": 999,
            "mean_daily_pearson_ic": "-0.012667903046",
            "mean_top2_minus_bottom2_forward_log_return": "-0.001355555878",
            "precision": "half_even_12_decimal_places_from_unrounded_daily_values",
            "significance_test": "not_performed",
            "label_overlap": True,
        }
    }
    with pytest.raises(ValueError, match="verified payloads required"):
        v2.validate_handoff(request, records, response, payloads=fake_payloads)


def test_verified_payloads_mutation_rejected(tmp_path):
    request, records, response = objects_for(tmp_path, "trend20")
    payloads = v2.validate_manifest(
        tmp_path,
        records["artifact_manifest"],
        records["experiment_run"],
        task=records["research_task"],
        spec=records["experiment_spec"],
    )
    summary_id = next(
        entry["artifact_id"]
        for entry in records["artifact_manifest"]["entries"]
        if entry["role"] == "statistical_summary"
    )
    payloads[summary_id]["mean_daily_pearson_ic"] = "0.9"
    with pytest.raises(ValueError, match="verified payload content mutated"):
        v2.validate_handoff(request, records, response, payloads=payloads)


def test_constructed_verified_payloads_rejected(tmp_path):
    request, records, response = objects_for(tmp_path, "trend20")
    verified = v2.validate_manifest(
        tmp_path,
        records["artifact_manifest"],
        records["experiment_run"],
        task=records["research_task"],
        spec=records["experiment_spec"],
    )
    forged = v2._VerifiedPayloads(
        dict(verified), records["artifact_manifest"], records["artifact_manifest"]["entries"]
    )
    with pytest.raises(ValueError, match="verified payloads required"):
        v2.validate_handoff(request, records, response, payloads=forged)


@pytest.mark.parametrize(
    "status,code,outcome",
    [
        ("rejected", "dependency_unavailable", "known"),
        ("unsupported", "missing_delivery", "not_started"),
        ("incomplete", "execution_outcome_unknown", "unknown"),
        ("blocked", "execution_outcome_unknown", "known"),
    ],
)
def test_noncompleted_review_handoff_rejects_status_problem_mismatch(
    tmp_path, status, code, outcome
):
    request, records, _ = objects_for(tmp_path, "trend20")
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "trend20-synthetic-status-problem-mismatch-response",
        "message_kind": "response",
        "operation": "review_evidence",
        "sender_role": "critic",
        "recipient_role": "execution",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": status,
        "review_scope": request["review_scope"],
        "problem": {
            "code": code,
            "reason": "Synthetic invalid status/problem pairing.",
            "affected_items": ["dataset_metadata"],
            "resume_condition": "Provide a valid response status and problem code.",
            "execution_outcome": outcome,
        },
    }
    records_without_review = {key: value for key, value in records.items() if key != "review"}
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, records_without_review, response, root=tmp_path)
