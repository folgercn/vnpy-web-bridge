"""Offline contract fixtures for prepare_spec and revise_spec (#523).

These fixtures validate data_quality/validation cross-object transitions offline
against the archived #544 run and definitions.
"""

import copy
import tarfile
from pathlib import Path

import pytest
from jsonschema import ValidationError

from research_lab.contracts import v2
from research_lab.contracts.test_v2 import failed_dq_review_chain, records, reseal


@pytest.fixture
def bundle(tmp_path):
    """Extract the immutable #544 archive into an isolated offline fixture."""
    archive = v2.ROOT / "research/phase0_data_quality/bundles/validation-rev1-ci.tar.gz"
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            relative = member.name
            assert not relative.startswith("/") and ".." not in Path(relative).parts
            if member.isfile():
                target = tmp_path / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.extractfile(member).read())
    return tmp_path


def prepare_request(obj):
    return {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "offline-prepare-spec-request",
        "message_kind": "request",
        "operation": "prepare_spec",
        "sender_role": "research",
        "recipient_role": "research",
        "context_refs": {
            "research_task": v2.check_record(obj["research_task"], "research_task"),
        },
        "artifact_requirements": {
            "role_profile_ref": v2.ROLE_PROFILE,
            "required_roles": [],
            "exact_refs": [],
        },
        "expected_outputs": [
            {"object_type": "experiment_spec", "schema_version": "research_lab.experiment.v2"},
        ],
    }


def prepare_completed_response(request, obj):
    return {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "offline-prepare-spec-response",
        "message_kind": "response",
        "operation": "prepare_spec",
        "sender_role": "research",
        "recipient_role": "research",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": "completed",
        "output_refs": [
            v2.check_record(obj["experiment_spec"], "experiment_spec"),
        ],
    }


def revise_request(obj):
    manifest = obj["artifact_manifest"]
    present = v2._present_artifact_refs(manifest)
    required_roles = sorted(v2.COMMON | v2.TYPED["data_quality"])
    return {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "offline-revise-spec-request",
        "message_kind": "request",
        "operation": "revise_spec",
        "sender_role": "critic",
        "recipient_role": "research",
        "context_refs": {
            kind: v2.check_record(obj[kind], kind)
            for kind in ("research_task", "experiment_spec", "experiment_run",
                         "artifact_manifest", "result_evidence", "review")
        },
        "artifact_requirements": {
            "role_profile_ref": manifest["artifact_profile"],
            "required_roles": required_roles,
            "exact_refs": present,
        },
        "expected_outputs": [
            {"object_type": "experiment_spec", "schema_version": "research_lab.experiment.v2"},
        ],
    }


def make_revised_spec(old_spec, *, strict=False, revision="rev.2"):
    new_spec = copy.deepcopy(old_spec)
    for check in new_spec.get("quality_checks", []):
        check["parameters"] = [
            {"name": "strict", "value_type": "boolean", "value": strict, "unit": "dimensionless"}
        ]
    new_spec["revision"] = revision
    reseal(new_spec, "spec")
    return new_spec


def revise_completed_response(request, revised_spec):
    return {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "offline-revise-spec-response",
        "message_kind": "response",
        "operation": "revise_spec",
        "sender_role": "research",
        "recipient_role": "critic",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": "completed",
        "output_refs": [
            v2.check_record(revised_spec, "experiment_spec"),
        ],
    }


# ==============================================================================
# prepare_spec fixtures
# ==============================================================================

def test_prepare_spec_request_only_is_valid_offline_contract_fixture(bundle):
    obj = records(bundle)
    request = prepare_request(obj)
    assert v2.validate_handoff(request, {"research_task": obj["research_task"]})


def test_prepare_spec_completed_delivery_success(bundle):
    obj = records(bundle)
    request = prepare_request(obj)
    response = prepare_completed_response(request, obj)
    assert v2.validate_handoff(request, {
        "research_task": obj["research_task"],
        "experiment_spec": obj["experiment_spec"],
    }, response)


def test_prepare_spec_rejects_unsupported_optional_context(bundle):
    obj = records(bundle)
    request = prepare_request(obj)
    request["context_refs"]["experiment_spec"] = v2.check_record(obj["experiment_spec"], "experiment_spec")
    with pytest.raises(ValueError, match="unsupported prepare_spec context"):
        v2.validate_handoff(request, obj)


def test_prepare_spec_rejects_future_artifact_requirements(bundle):
    obj = records(bundle)
    request = prepare_request(obj)
    request["artifact_requirements"]["required_roles"] = ["quality_summary"]
    with pytest.raises(ValueError, match="prepare_spec required roles must be empty"):
        v2.validate_handoff(request, obj)

    request2 = prepare_request(obj)
    request2["artifact_requirements"]["exact_refs"] = [{
        "manifest_id": "m1", "manifest_revision": "rev.1",
        "manifest_content_hash": "0" * 64, "artifact_id": "a1",
        "role": "quality_summary", "content_sha256": "0" * 64,
    }]
    with pytest.raises(ValueError, match="prepare_spec exact refs must be empty"):
        v2.validate_handoff(request2, obj)


def test_prepare_spec_rejects_mismatched_task_binding(bundle):
    obj = records(bundle)
    request = prepare_request(obj)
    bad_spec = copy.deepcopy(obj["experiment_spec"])
    bad_spec["task_id"] = "task-phase0-other"
    reseal(bad_spec, "spec")
    response = prepare_completed_response(request, {"experiment_spec": bad_spec})
    with pytest.raises(ValueError, match="Task reference"):
        v2.validate_handoff(request, {
            "research_task": obj["research_task"],
            "experiment_spec": bad_spec,
        }, response)


def test_prepare_spec_rejects_unsupported_profile(bundle):
    obj = records(bundle)
    request = prepare_request(obj)
    bad_spec = copy.deepcopy(obj["experiment_spec"])
    bad_spec["experiment_type"] = "statistical_factor"
    reseal(bad_spec, "spec")
    response = prepare_completed_response(request, {"experiment_spec": bad_spec})
    with pytest.raises(ValueError, match="unsupported prepare_spec profile"):
        v2.validate_handoff(request, {
            "research_task": obj["research_task"],
            "experiment_spec": bad_spec,
        }, response)


def test_prepare_spec_request_only_rejects_non_data_quality_task(bundle):
    obj = records(bundle)
    bad_task = copy.deepcopy(obj["research_task"])
    bad_task["research_type"] = "statistical_factor"
    reseal(bad_task, "task")
    request = prepare_request({"research_task": bad_task})
    with pytest.raises(ValueError, match="unsupported prepare_spec task research_type"):
        v2.validate_handoff(request, {"research_task": bad_task})


def test_prepare_spec_rejects_non_validation_stage_in_delivery(bundle):
    obj = records(bundle)
    request = prepare_request(obj)
    bad_spec = copy.deepcopy(obj["experiment_spec"])
    bad_spec["research_stage"] = "exploration"
    reseal(bad_spec, "spec")
    response = prepare_completed_response(request, {"experiment_spec": bad_spec})
    with pytest.raises(ValueError, match="unsupported prepare_spec profile"):
        v2.validate_handoff(request, {
            "research_task": obj["research_task"],
            "experiment_spec": bad_spec,
        }, response)


# ==============================================================================
# revise_spec fixtures
# ==============================================================================

def test_revise_spec_request_only_is_valid_offline_contract_fixture(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    assert v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_completed_delivery_success(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    response = revise_completed_response(request, revised)
    objects = dict(obj)
    objects["revised_experiment_spec"] = revised
    assert v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_accepts_verified_payloads(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    response = revise_completed_response(request, revised)
    objects = dict(obj)
    objects["revised_experiment_spec"] = revised
    payloads = v2.validate_manifest(bundle, obj["artifact_manifest"], obj["experiment_run"])
    assert v2.validate_handoff(request, objects, response, payloads=payloads)


def test_revise_spec_requires_payloads_or_root(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    with pytest.raises(ValueError, match="verified payloads or root required"):
        v2.validate_handoff(request, obj)


def test_revise_spec_rejects_failed_run_source(bundle):
    obj, _, _ = failed_dq_review_chain(bundle)
    request = revise_request(obj)
    with pytest.raises(ValueError, match="revise_spec requires COMPLETED run"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_same_revision(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.1")
    response = revise_completed_response(request, revised)
    objects = dict(obj, revised_experiment_spec=revised)
    with pytest.raises(ValueError, match="revised spec revision must strictly increase"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_fully_resealed_alternate_source_chain_by_anchor(bundle):
    """A fully resealed, internally self-consistent alternate source chain

    (mutated task_id resealed through Task->Spec->Run->Manifest->Evidence->Review
    plus request and revised Spec) must be rejected specifically by the #544 source anchor.
    """
    obj = records(bundle)
    alt_task_id = "task-phase0-rb-date-order-custom"

    # 1. Mutate and reseal Task
    obj["research_task"]["task_id"] = alt_task_id
    reseal(obj["research_task"], "task")

    # 2. Mutate and reseal Spec
    obj["experiment_spec"]["task_id"] = alt_task_id
    obj["experiment_spec"]["task_content_hash"] = obj["research_task"]["task_content_hash"]
    reseal(obj["experiment_spec"], "spec")

    # 3. Mutate and reseal Run
    obj["experiment_run"]["spec_content_hash"] = obj["experiment_spec"]["spec_content_hash"]
    reseal(obj["experiment_run"], "run")

    # 4. Mutate and reseal Manifest
    obj["artifact_manifest"]["run_content_hash"] = obj["experiment_run"]["run_content_hash"]
    reseal(obj["artifact_manifest"], "manifest")

    # 5. Mutate and reseal Evidence
    obj["result_evidence"]["run_content_hash"] = obj["experiment_run"]["run_content_hash"]
    obj["result_evidence"]["manifest_content_hash"] = obj["artifact_manifest"]["manifest_content_hash"]
    for ref in obj["result_evidence"]["supporting_artifacts"]:
        ref["manifest_content_hash"] = obj["artifact_manifest"]["manifest_content_hash"]
    reseal(obj["result_evidence"], "evidence")

    # 6. Mutate and reseal Review
    obj["review"]["evidence_content_hash"] = obj["result_evidence"]["evidence_content_hash"]
    reseal(obj["review"], "review")

    # 7. Request with all updated context_refs & exact_refs
    request = revise_request(obj)

    # 8. Revised Spec binding the alternate task_id
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    response = revise_completed_response(request, revised)
    objects = dict(obj, revised_experiment_spec=revised)

    # Must be rejected specifically by the #544 source anchor
    with pytest.raises(ValueError, match="#544 source identity anchor mismatch: research_task"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_alternate_spec_revision_source_by_anchor(bundle):
    """An alternate source chain where old Spec has rev.2 is rejected by anchor."""
    obj = records(bundle)
    obj["experiment_spec"]["revision"] = "rev.2"
    reseal(obj["experiment_spec"], "spec")
    obj["experiment_run"]["spec_revision"] = "rev.2"
    obj["experiment_run"]["spec_content_hash"] = obj["experiment_spec"]["spec_content_hash"]
    reseal(obj["experiment_run"], "run")
    obj["artifact_manifest"]["run_content_hash"] = obj["experiment_run"]["run_content_hash"]
    reseal(obj["artifact_manifest"], "manifest")
    obj["result_evidence"]["run_content_hash"] = obj["experiment_run"]["run_content_hash"]
    obj["result_evidence"]["manifest_content_hash"] = obj["artifact_manifest"]["manifest_content_hash"]
    for ref in obj["result_evidence"]["supporting_artifacts"]:
        ref["manifest_content_hash"] = obj["artifact_manifest"]["manifest_content_hash"]
    reseal(obj["result_evidence"], "evidence")
    obj["review"]["evidence_content_hash"] = obj["result_evidence"]["evidence_content_hash"]
    reseal(obj["review"], "review")

    request = revise_request(obj)
    with pytest.raises(ValueError, match="#544 source identity anchor mismatch: experiment_spec"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_same_spec_object(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    response = revise_completed_response(request, obj["experiment_spec"])
    objects = dict(obj)
    objects["revised_experiment_spec"] = obj["experiment_spec"]
    with pytest.raises(ValueError, match="revised spec cannot be identical object"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_identical_content(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    duplicate = copy.deepcopy(obj["experiment_spec"])
    response = revise_completed_response(request, duplicate)
    objects = dict(obj)
    objects["revised_experiment_spec"] = duplicate
    with pytest.raises(ValueError, match="revised spec cannot be identical content"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_missing_revised_spec_object(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    response = revise_completed_response(request, revised)
    with pytest.raises(ValueError, match="missing revised_experiment_spec"):
        v2.validate_handoff(request, obj, response, root=bundle)


@pytest.mark.parametrize("alias", ["revised_spec", "new_spec", "new_experiment_spec"])
def test_revise_spec_rejects_fallback_alias_object_keys(bundle, alias):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    response = revise_completed_response(request, revised)
    objects = dict(obj)
    objects[alias] = revised
    with pytest.raises(ValueError, match="missing revised_experiment_spec"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_empty_required_roles(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    request["artifact_requirements"]["required_roles"] = []
    with pytest.raises(ValueError, match="revise_spec required roles"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_wrong_required_roles(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    request["artifact_requirements"]["required_roles"] = ["dataset_metadata"]
    with pytest.raises(ValueError, match="revise_spec required roles"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_empty_exact_refs(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    request["artifact_requirements"]["exact_refs"] = []
    with pytest.raises(ValueError, match="revise_spec exact artifact references"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_tampered_exact_refs(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    tampered_refs = copy.deepcopy(request["artifact_requirements"]["exact_refs"])
    tampered_refs[0]["content_sha256"] = "0" * 64
    request["artifact_requirements"]["exact_refs"] = tampered_refs
    with pytest.raises(ValueError, match="revise_spec exact artifact references"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_evidence_supporting_artifacts_mismatch(bundle):
    obj = records(bundle)
    tampered_evidence = copy.deepcopy(obj["result_evidence"])
    tampered_evidence["supporting_artifacts"] = tampered_evidence["supporting_artifacts"][:-1]
    reseal(tampered_evidence, "evidence")
    obj["result_evidence"] = tampered_evidence
    obj["review"]["evidence_content_hash"] = tampered_evidence["evidence_content_hash"]
    reseal(obj["review"], "review")
    request = revise_request(obj)
    with pytest.raises(ValueError, match="Evidence artifact references"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_missing_source_payload_file(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    (bundle / "payload/quality_anomalies.json").unlink()
    with pytest.raises((FileNotFoundError, ValueError)):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_cross_run_evidence(bundle):
    obj = records(bundle)
    tampered_evidence = copy.deepcopy(obj["result_evidence"])
    tampered_evidence["run_id"] = "run-other-fake-run-id"
    reseal(tampered_evidence, "evidence")
    obj["result_evidence"] = tampered_evidence
    obj["review"]["evidence_content_hash"] = tampered_evidence["evidence_content_hash"]
    reseal(obj["review"], "review")
    request = revise_request(obj)
    with pytest.raises(ValueError, match="Evidence Run reference"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_cross_run_manifest(bundle):
    obj = records(bundle)
    tampered_manifest = copy.deepcopy(obj["artifact_manifest"])
    tampered_manifest["run_id"] = "run-other-fake-run-id"
    reseal(tampered_manifest, "manifest")
    obj["artifact_manifest"] = tampered_manifest
    obj["result_evidence"]["manifest_content_hash"] = tampered_manifest["manifest_content_hash"]
    for ref in obj["result_evidence"]["supporting_artifacts"]:
        ref["manifest_content_hash"] = tampered_manifest["manifest_content_hash"]
    reseal(obj["result_evidence"], "evidence")
    obj["review"]["evidence_content_hash"] = obj["result_evidence"]["evidence_content_hash"]
    reseal(obj["review"], "review")
    request = revise_request(obj)
    with pytest.raises(ValueError, match="(Manifest )?Run reference"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_fully_resealed_semantic_source_chain_mutation(bundle):
    """Mutate raw payload file, reseal bytes SHA + Manifest + Evidence + Review + Request hashes,

    and verify it still fails semantic binding (dataset metadata time_range mismatch).
    """
    import json
    obj = records(bundle)
    # 1. Mutate dataset_metadata.json on disk (time_range is schema-valid string)
    metadata_path = bundle / "payload/dataset_metadata.json"
    metadata_data = json.loads(metadata_path.read_text())
    metadata_data["time_range"]["end"] = "2023-02-05T00:00:00"
    tampered_bytes = json.dumps(metadata_data, indent=2).encode("utf-8")
    metadata_path.write_bytes(tampered_bytes)

    # 2. Recompute raw bytes SHA256 and byte_length in Manifest
    manifest = obj["artifact_manifest"]
    entry = next(e for e in manifest["entries"] if e["role"] == "dataset_metadata")
    entry["content_sha256"] = v2.sha(tampered_bytes)
    entry["byte_length"] = len(tampered_bytes)
    reseal(manifest, "manifest")

    # 3. Update and reseal Evidence
    evidence = obj["result_evidence"]
    evidence["manifest_content_hash"] = manifest["manifest_content_hash"]
    evidence["supporting_artifacts"] = v2._present_artifact_refs(manifest)
    reseal(evidence, "evidence")

    # 4. Update and reseal Review
    review = obj["review"]
    review["evidence_content_hash"] = evidence["evidence_content_hash"]
    reseal(review, "review")

    # 5. Build request binding all resealed hashes and exact refs
    request = revise_request(obj)
    # Check that it still fails semantic binding
    with pytest.raises(ValueError, match="data-quality dataset metadata binding"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_resealed_quality_summary_semantic_mutation(bundle):
    """Mutate quality_summary raw payload, reseal hashes up the chain,

    and verify it fails Evidence data quality facts semantic binding.
    """
    import json
    obj = records(bundle)
    summary_path = bundle / "payload/quality_summary.json"
    summary_data = json.loads(summary_path.read_text())
    summary_data["comparison_count"] += 10
    tampered_bytes = json.dumps(summary_data, indent=2).encode("utf-8")
    summary_path.write_bytes(tampered_bytes)

    manifest = obj["artifact_manifest"]
    entry = next(e for e in manifest["entries"] if e["role"] == "quality_summary")
    entry["content_sha256"] = v2.sha(tampered_bytes)
    entry["byte_length"] = len(tampered_bytes)
    reseal(manifest, "manifest")

    evidence = obj["result_evidence"]
    evidence["manifest_content_hash"] = manifest["manifest_content_hash"]
    evidence["supporting_artifacts"] = v2._present_artifact_refs(manifest)
    reseal(evidence, "evidence")

    review = obj["review"]
    review["evidence_content_hash"] = evidence["evidence_content_hash"]
    reseal(review, "review")

    request = revise_request(obj)
    with pytest.raises(ValueError, match="Evidence data quality facts"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_cross_task(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    revised["task_id"] = "task-phase0-other"
    reseal(revised, "spec")
    response = revise_completed_response(request, revised)
    objects = dict(obj)
    objects["revised_experiment_spec"] = revised
    with pytest.raises(ValueError, match="revised spec task_id mismatch"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_spec_id_mutation(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    revised["spec_id"] = "spec-phase0-other"
    reseal(revised, "spec")
    response = revise_completed_response(request, revised)
    objects = dict(obj)
    objects["revised_experiment_spec"] = revised
    with pytest.raises(ValueError, match="revised spec must have same spec_id"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_type_or_stage_mutation(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
    revised["research_stage"] = "exploration"
    reseal(revised, "spec")
    response = revise_completed_response(request, revised)
    objects = dict(obj)
    objects["revised_experiment_spec"] = revised
    with pytest.raises(ValueError, match="unsupported revised spec profile"):
        v2.validate_handoff(request, objects, response, root=bundle)


def test_revise_spec_rejects_mismatched_review_criteria(bundle):
    obj = records(bundle)
    obj["review"]["criteria_ref"]["id"] = "wrong-criteria-id"
    reseal(obj["review"], "review")
    request = revise_request(obj)
    with pytest.raises(ValueError, match="unknown criteria definition"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_mismatched_review_evidence(bundle):
    obj = records(bundle)
    obj["review"]["evidence_id"] = "wrong-evidence-id"
    reseal(obj["review"], "review")
    request = revise_request(obj)
    with pytest.raises(ValueError, match="Review Evidence reference"):
        v2.validate_handoff(request, obj, root=bundle)


def test_revise_spec_rejects_fake_review_handoff_fields(bundle):
    obj = records(bundle)
    request = revise_request(obj)
    request["criteria_ref"] = {
        "id": "phase0-date-order-criteria",
        "revision": "rev.1",
        "content_hash": "0" * 64,
    }
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, obj, root=bundle)


# ==============================================================================
# Correlation and In-reply-to checks
# ==============================================================================

@pytest.mark.parametrize("operation", ["prepare_spec", "revise_spec"])
def test_handoff_rejects_in_reply_to_mismatch(bundle, operation):
    obj = records(bundle)
    if operation == "prepare_spec":
        request = prepare_request(obj)
        response = prepare_completed_response(request, obj)
        objects = {"research_task": obj["research_task"], "experiment_spec": obj["experiment_spec"]}
        root = None
    else:
        request = revise_request(obj)
        revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
        response = revise_completed_response(request, revised)
        objects = dict(obj, revised_experiment_spec=revised)
        root = bundle

    response["in_reply_to"] = "wrong-id"
    with pytest.raises(ValueError, match="response correlation"):
        v2.validate_handoff(request, objects, response, root=root)


@pytest.mark.parametrize("operation", ["prepare_spec", "revise_spec"])
def test_handoff_rejects_same_handoff_id(bundle, operation):
    obj = records(bundle)
    if operation == "prepare_spec":
        request = prepare_request(obj)
        response = prepare_completed_response(request, obj)
        objects = {"research_task": obj["research_task"], "experiment_spec": obj["experiment_spec"]}
        root = None
    else:
        request = revise_request(obj)
        revised = make_revised_spec(obj["experiment_spec"], strict=False, revision="rev.2")
        response = revise_completed_response(request, revised)
        objects = dict(obj, revised_experiment_spec=revised)
        root = bundle

    response["handoff_id"] = request["handoff_id"]
    with pytest.raises(ValueError, match="response handoff_id must differ"):
        v2.validate_handoff(request, objects, response, root=root)


# ==============================================================================
# Non-success responses (rejected, unsupported, blocked, incomplete)
# ==============================================================================

@pytest.mark.parametrize("operation", ["prepare_spec", "revise_spec"])
@pytest.mark.parametrize("status, code, outcome", [
    ("blocked", "dependency_unavailable", "known"),
    ("incomplete", "missing_delivery", "known"),
    ("unsupported", "capability_unsupported", "not_started"),
    ("rejected", "invalid_input", "not_started"),
    ("blocked", "execution_outcome_unknown", "unknown"),
])
def test_noncompleted_response_reports_problem_without_spec_delivery(bundle, operation, status, code, outcome):
    obj = records(bundle)
    if operation == "prepare_spec":
        request = prepare_request(obj)
        sender, recipient = "research", "research"
        objects = {"research_task": obj["research_task"]}
        root = None
    else:
        request = revise_request(obj)
        sender, recipient = "research", "critic"
        objects = obj
        root = bundle

    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"offline-{operation}-problem",
        "message_kind": "response",
        "operation": operation,
        "sender_role": sender,
        "recipient_role": recipient,
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": status,
        "problem": {
            "code": code,
            "reason": f"offline fixture reports a known {operation} condition",
            "affected_items": ["experiment_spec"],
            "resume_condition": "supply verified records",
            "execution_outcome": outcome,
        },
    }
    assert v2.validate_handoff(request, objects, response, root=root)

    invalid = copy.deepcopy(response)
    invalid["output_refs"] = [v2.check_record(obj["experiment_spec"], "experiment_spec")]
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, objects, invalid, root=root)


@pytest.mark.parametrize("operation", ["prepare_spec", "revise_spec"])
def test_rejected_response_allows_unresolvable_request(bundle, operation):
    obj = records(bundle)
    if operation == "prepare_spec":
        request = prepare_request(obj)
        sender, recipient = "research", "research"
        request.pop("artifact_requirements")  # structurally invalid
    else:
        request = revise_request(obj)
        sender, recipient = "research", "critic"
        request["context_refs"].pop("experiment_spec")  # incomplete context

    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"offline-{operation}-rejected-response",
        "message_kind": "response",
        "operation": operation,
        "sender_role": sender,
        "recipient_role": recipient,
        "context_refs": {},
        "in_reply_to": request["handoff_id"],
        "status": "rejected",
        "problem": {
            "code": "invalid_input",
            "reason": "request is structurally invalid",
            "affected_items": ["context_refs"],
            "resume_condition": "provide valid request",
            "execution_outcome": "not_started",
        },
    }
    assert v2.validate_handoff(request, obj, response)


@pytest.mark.parametrize("operation", ["prepare_spec", "revise_spec"])
@pytest.mark.parametrize("status, code", [
    ("rejected", "invalid_input"),
    ("unsupported", "capability_unsupported"),
    ("blocked", "dependency_unavailable"),
    ("incomplete", "missing_delivery"),
])
def test_noncompleted_response_rejects_same_handoff_id(bundle, operation, status, code):
    obj = records(bundle)
    if operation == "prepare_spec":
        request = prepare_request(obj)
        sender, recipient = "research", "research"
        objects = {"research_task": obj["research_task"]}
        root = None
    else:
        request = revise_request(obj)
        sender, recipient = "research", "critic"
        objects = obj
        root = bundle

    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": request["handoff_id"],  # SAME handoff_id
        "message_kind": "response",
        "operation": operation,
        "sender_role": sender,
        "recipient_role": recipient,
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": status,
        "problem": {
            "code": code,
            "reason": f"offline fixture reports a known {operation} condition",
            "affected_items": ["experiment_spec"],
            "resume_condition": "supply verified records",
            "execution_outcome": "not_started" if status in ("rejected", "unsupported") else "known",
        },
    }
    with pytest.raises(ValueError, match="response handoff_id must differ from request"):
        v2.validate_handoff(request, objects, response, root=root)
