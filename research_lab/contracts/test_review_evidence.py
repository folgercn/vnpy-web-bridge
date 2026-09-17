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
    assert v2.validate_handoff(request, records, response)


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
    elif mutation == "profile":
        records["result_evidence"]["typed_metrics"]["profile"] = "other"
        seal(records["result_evidence"], "evidence")
        request["context_refs"]["result_evidence"] = v2.check_record(records["result_evidence"], "result_evidence")
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
    elif mutation == "run":
        records["experiment_run"]["run_id"] = "wrong"
        seal(records["experiment_run"], "run")
        request["context_refs"]["experiment_run"] = v2.check_record(records["experiment_run"], "experiment_run")
    elif mutation == "response":
        response["in_reply_to"] = "wrong"
    else:
        response["status"] = "incomplete"
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, records, response)


def test_issue481_account_metrics_are_not_combined(tmp_path):
    request, records, response = objects_for(tmp_path, "issue481")
    rows = records["result_evidence"]["typed_metrics"]["account_metrics"]
    rows[-1] = copy.deepcopy(rows[0])
    seal(records["result_evidence"], "evidence")
    request["context_refs"]["result_evidence"] = v2.check_record(
        records["result_evidence"], "result_evidence"
    )
    with pytest.raises((ValueError, ValidationError), match="account"):
        v2.validate_handoff(request, records, response)

@pytest.mark.parametrize("value", ["2", "-1.1", "0.1234567890123"])
def test_trend20_ic_range_and_precision_rehashed_rejected(tmp_path, value):
    request, records, response = objects_for(tmp_path, "trend20")
    evidence = records["result_evidence"]
    evidence["typed_metrics"]["daily_ic"]["value"] = value
    seal(evidence, "evidence")
    request["context_refs"]["result_evidence"] = v2.check_record(
        evidence, "result_evidence"
    )
    review = records["review"]
    review["evidence_content_hash"] = evidence["evidence_content_hash"]
    seal(review, "review")
    response["output_refs"] = [v2.check_record(review, "review")]
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, records, response)
