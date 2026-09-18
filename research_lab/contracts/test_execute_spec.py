"""Offline execute_spec fixtures consume the archived #544 validation result."""

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


def execute_request(obj):
    return {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "offline-execute-spec-request",
        "message_kind": "request",
        "operation": "execute_spec",
        "sender_role": "research",
        "recipient_role": "execution",
        "context_refs": {
            kind: v2.check_record(obj[kind], kind)
            for kind in ("research_task", "experiment_spec")
        },
        "artifact_requirements": {
            "role_profile_ref": v2.ROLE_PROFILE,
            "required_roles": sorted(v2.COMMON | v2.TYPED["data_quality"]),
            "exact_refs": [],
        },
        "expected_outputs": [
            {"object_type": "experiment_run", "schema_version": "research_lab.run.v2"},
            {"object_type": "artifact_manifest", "schema_version": "research_lab.artifact_manifest.v2"},
            {"object_type": "result_evidence", "schema_version": "research_lab.evidence.v2"},
        ],
    }


def completed_response(request, obj):
    return {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "offline-execute-spec-response",
        "message_kind": "response",
        "operation": "execute_spec",
        "sender_role": "execution",
        "recipient_role": "research",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": "completed",
        "output_refs": [
            v2.check_record(obj[kind], kind)
            for kind in ("experiment_run", "artifact_manifest", "result_evidence")
        ],
    }


def reseal_delivery(obj):
    reseal(obj["experiment_run"], "run")
    manifest = obj["artifact_manifest"]
    manifest["run_content_hash"] = obj["experiment_run"]["run_content_hash"]
    reseal(manifest, "manifest")
    evidence = obj["result_evidence"]
    evidence.update(run_content_hash=obj["experiment_run"]["run_content_hash"],
                    manifest_content_hash=manifest["manifest_content_hash"])
    for ref in evidence["supporting_artifacts"]:
        ref["manifest_content_hash"] = manifest["manifest_content_hash"]
    reseal(evidence, "evidence")


def reseal_spec_and_run(obj):
    """Resign synthetic Task/Spec/Run changes while retaining archived payloads."""
    reseal(obj["research_task"], "task")
    spec = obj["experiment_spec"]
    spec.update(task_revision=obj["research_task"]["revision"],
                task_content_hash=obj["research_task"]["task_content_hash"])
    reseal(spec, "spec")
    run = obj["experiment_run"]
    run.update(spec_revision=spec["revision"], spec_content_hash=spec["spec_content_hash"])
    run["scientific_fingerprint"] = v2.digest(run["resolved_computation_manifest"])
    reseal_delivery(obj)


def test_execute_spec_request_only_is_valid_offline_contract_fixture(bundle):
    obj = records(bundle)
    request = execute_request(obj)
    minimal = {key: obj[key] for key in ("research_task", "experiment_spec")}
    assert v2.validate_handoff(request, minimal)


def test_execute_spec_rejects_other_profile_before_delivery(bundle):
    obj = records(bundle)
    obj["experiment_spec"]["research_stage"] = "exploration"
    reseal(obj["experiment_spec"], "spec")
    request = execute_request(obj)
    with pytest.raises(ValueError, match="unsupported execute_spec profile"):
        v2.validate_handoff(request, obj)


@pytest.mark.parametrize("operation", ["prepare_spec", "revise_spec"])
def test_non_execute_operations_remain_unsupported(bundle, operation):
    obj = records(bundle)
    request = execute_request(obj)
    request.update(
        operation=operation,
        sender_role="research" if operation == "prepare_spec" else "critic",
        recipient_role="research",
        expected_outputs=[
            {"object_type": "experiment_spec", "schema_version": "research_lab.experiment.v2"}
        ],
    )
    if operation == "prepare_spec":
        request["context_refs"] = {"research_task": v2.check_record(obj["research_task"], "research_task")}
    else:
        request["context_refs"] = {
            kind: v2.check_record(value, kind) for kind, value in obj.items()
        }
    with pytest.raises(ValueError, match="unsupported cross-object operation"):
        v2.validate_handoff(request, obj)


def test_execute_spec_archived_success_delivery(bundle):
    obj = records(bundle)
    request = execute_request(obj)
    assert v2.validate_handoff(request, obj, completed_response(request, obj), root=bundle)


def test_execute_spec_archived_success_delivery_accepts_verified_payloads(bundle):
    obj = records(bundle)
    request = execute_request(obj)
    payloads = v2.validate_manifest(bundle, obj["artifact_manifest"], obj["experiment_run"])
    assert v2.validate_handoff(request, obj, completed_response(request, obj), payloads=payloads)


@pytest.mark.parametrize("field, value", [
    ("resolved_parameters", {"strict": False}),
    ("scientific_time", {"start": "2023-01-03T00:00:00.000000Z", "end": "2023-01-10T00:00:00.000000Z"}),
    ("raw_bytes_sha256", "0" * 64),
])
@pytest.mark.parametrize("mode", ["root", "payloads"])
def test_execute_spec_binds_resolved_data_quality_inputs(bundle, field, value, mode):
    obj = records(bundle)
    obj["experiment_run"]["resolved_computation_manifest"][field] = value
    obj["experiment_run"]["scientific_fingerprint"] = v2.digest(
        obj["experiment_run"]["resolved_computation_manifest"]
    )
    reseal_delivery(obj)
    request = execute_request(obj)
    response = completed_response(request, obj)
    kwargs = {"root": bundle} if mode == "root" else {
        "payloads": v2.validate_manifest(bundle, obj["artifact_manifest"], obj["experiment_run"])
    }
    with pytest.raises(ValueError, match="Run data-quality Spec binding"):
        v2.validate_handoff(request, obj, response, **kwargs)


@pytest.mark.parametrize("mode", ["root", "payloads"])
@pytest.mark.parametrize("mutation", ["snapshot", "shorter_range"])
def test_execute_spec_binds_verified_dataset_metadata_after_rehash(bundle, mode, mutation):
    obj = records(bundle)
    task, spec, run = (obj["research_task"], obj["experiment_spec"], obj["experiment_run"])
    if mutation == "snapshot":
        spec["dataset_requirements"]["snapshot_sha256"] = "0" * 64
        run["resolved_computation_manifest"]["raw_bytes_sha256"] = "0" * 64
    else:
        task.update(revision="rev.2", data_requirements={
            **task["data_requirements"], "date_end_exclusive": "2023-01-10",
        })
        spec.update(revision="rev.2", dataset_requirements={
            **spec["dataset_requirements"], "time_range": {
                **spec["dataset_requirements"]["time_range"], "end": "2023-01-10T00:00:00.000000Z",
            },
        })
        run["resolved_computation_manifest"]["scientific_time"]["end"] = "2023-01-10T00:00:00.000000Z"
    reseal_spec_and_run(obj)
    request, response = execute_request(obj), completed_response(execute_request(obj), obj)
    kwargs = {"root": bundle} if mode == "root" else {
        "payloads": v2.validate_manifest(bundle, obj["artifact_manifest"], obj["experiment_run"])
    }
    with pytest.raises(ValueError, match="data-quality dataset metadata binding"):
        v2.validate_handoff(request, obj, response, **kwargs)


def test_execute_spec_reversed_request_roles_are_set_semantic(bundle):
    obj = records(bundle)
    request = execute_request(obj)
    request["artifact_requirements"]["required_roles"].reverse()
    minimal = {key: obj[key] for key in ("research_task", "experiment_spec")}
    assert v2.validate_handoff(request, minimal)
    assert v2.validate_handoff(request, obj, completed_response(request, obj), root=bundle)


def test_execute_spec_rejects_mutated_verified_quality_summary(bundle):
    obj = records(bundle)
    request = execute_request(obj)
    payloads = v2.validate_manifest(bundle, obj["artifact_manifest"], obj["experiment_run"])
    summary_entry = next(
        entry for entry in obj["artifact_manifest"]["entries"]
        if entry["role"] == "quality_summary"
    )
    payloads[summary_entry["artifact_id"]]["timestamp_monotonicity_violations"] = 1
    obj["result_evidence"]["typed_metrics"][0]["value"] = 1
    reseal(obj["result_evidence"], "evidence")
    response = completed_response(request, obj)
    with pytest.raises(ValueError, match="verified payload content mutated: quality_summary"):
        v2.validate_handoff(request, obj, response, payloads=payloads)


def test_execute_spec_archived_failed_delivery(bundle):
    obj, _, _ = failed_dq_review_chain(bundle)
    request = execute_request(obj)
    assert v2.validate_handoff(request, obj, completed_response(request, obj), root=bundle)


@pytest.mark.parametrize("mode", ["root", "payloads"])
@pytest.mark.parametrize("field, value", [("typed_metrics", []), ("missing_reason", None)])
def test_execute_spec_failed_delivery_rejects_fabricated_metrics(bundle, mode, field, value):
    obj, _, _ = failed_dq_review_chain(bundle)
    obj["result_evidence"][field] = value
    reseal(obj["result_evidence"], "evidence")
    request = execute_request(obj)
    kwargs = {"root": bundle} if mode == "root" else {
        "payloads": v2.validate_manifest(bundle, obj["artifact_manifest"], obj["experiment_run"])
    }
    with pytest.raises(ValueError, match="FAILED evidence delivery"):
        v2.validate_handoff(request, obj, completed_response(request, obj), **kwargs)


@pytest.mark.parametrize("mutation", ["role", "file"])
def test_execute_spec_success_delivery_requires_actual_roles_and_files(bundle, mutation):
    obj = records(bundle)
    request = execute_request(obj)
    manifest = obj["artifact_manifest"]
    entry = next(item for item in manifest["entries"] if item["role"] == "quality_summary")
    if mutation == "role":
        manifest["entries"].remove(entry)
        reseal(manifest, "manifest")
        obj["result_evidence"]["manifest_content_hash"] = manifest["manifest_content_hash"]
        for ref in obj["result_evidence"]["supporting_artifacts"]:
            ref["manifest_content_hash"] = manifest["manifest_content_hash"]
        reseal(obj["result_evidence"], "evidence")
    else:
        (bundle / entry["relative_path"]).unlink()
    with pytest.raises((ValueError, OSError)):
        v2.validate_handoff(request, obj, completed_response(request, obj), root=bundle)


def test_execute_spec_failed_delivery_requires_failure_diagnostics(bundle):
    obj, _, _ = failed_dq_review_chain(bundle)
    request = execute_request(obj)
    manifest = obj["artifact_manifest"]
    diagnostic = next(entry for entry in manifest["entries"] if entry["role"] == "failure_diagnostics")
    for field in ("relative_path", "media_type", "byte_length", "content_sha256", "producer"):
        diagnostic.pop(field)
    diagnostic.update(availability="unavailable", coverage="none", unavailable_reason="execution_interrupted")
    reseal(manifest, "manifest")
    evidence = obj["result_evidence"]
    evidence["manifest_content_hash"] = manifest["manifest_content_hash"]
    evidence["supporting_artifacts"] = [
        ref for ref in evidence["supporting_artifacts"] if ref["role"] != "failure_diagnostics"
    ]
    for ref in evidence["supporting_artifacts"]:
        ref["manifest_content_hash"] = manifest["manifest_content_hash"]
    reseal(evidence, "evidence")
    with pytest.raises(ValueError):
        v2.validate_handoff(request, obj, completed_response(request, obj), root=bundle)


@pytest.mark.parametrize("mutation", ["spec", "run", "reply", "roles", "duplicate_roles", "bytes", "facts", "missing"])
def test_execute_spec_rejects_delivery_tampering(bundle, mutation):
    obj = records(bundle)
    request = execute_request(obj)
    response = completed_response(request, obj)
    if mutation == "spec":
        obj["experiment_run"]["spec_revision"] = "rev.9"
        reseal(obj["experiment_run"], "run")
        obj["artifact_manifest"]["run_content_hash"] = obj["experiment_run"]["run_content_hash"]
        reseal(obj["artifact_manifest"], "manifest")
        obj["result_evidence"].update(
            run_content_hash=obj["experiment_run"]["run_content_hash"],
            manifest_content_hash=obj["artifact_manifest"]["manifest_content_hash"],
        )
        for ref in obj["result_evidence"]["supporting_artifacts"]:
            ref["manifest_content_hash"] = obj["artifact_manifest"]["manifest_content_hash"]
        reseal(obj["result_evidence"], "evidence")
    elif mutation == "run":
        obj["artifact_manifest"]["run_id"] = "other-run"
        reseal(obj["artifact_manifest"], "manifest")
        obj["result_evidence"]["manifest_content_hash"] = obj["artifact_manifest"]["manifest_content_hash"]
        for ref in obj["result_evidence"]["supporting_artifacts"]:
            ref["manifest_content_hash"] = obj["artifact_manifest"]["manifest_content_hash"]
        reseal(obj["result_evidence"], "evidence")
    elif mutation == "reply":
        response["in_reply_to"] = "different-request"
    elif mutation == "roles":
        request["artifact_requirements"]["required_roles"].pop()
    elif mutation == "duplicate_roles":
        request["artifact_requirements"]["required_roles"].append("quality_summary")
    elif mutation == "bytes":
        entry = next(e for e in obj["artifact_manifest"]["entries"] if e["role"] == "quality_summary")
        path = bundle / entry["relative_path"]
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "facts":
        obj["result_evidence"]["typed_metrics"][0]["value"] = 1
        reseal(obj["result_evidence"], "evidence")
    else:
        obj.pop("result_evidence")
    if mutation in {"spec", "run", "facts"}:
        response["output_refs"] = [
            v2.check_record(obj[kind], kind)
            for kind in ("experiment_run", "artifact_manifest", "result_evidence")
        ]
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_handoff(request, obj, response, root=bundle)


@pytest.mark.parametrize("status, code, outcome", [
    ("blocked", "dependency_unavailable", "known"),
    ("incomplete", "missing_delivery", "known"),
    ("unsupported", "capability_unsupported", "not_started"),
    ("rejected", "invalid_input", "not_started"),
    ("blocked", "execution_outcome_unknown", "unknown"),
])
def test_execute_spec_noncompleted_response_can_report_without_delivery(bundle, status, code, outcome):
    obj = records(bundle)
    request = execute_request(obj)
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "offline-execute-spec-problem",
        "message_kind": "response",
        "operation": "execute_spec",
        "sender_role": "execution",
        "recipient_role": "research",
        "context_refs": request["context_refs"],
        "in_reply_to": request["handoff_id"],
        "status": status,
        "problem": {
            "code": code,
            "reason": "offline fixture reports a known delivery condition",
            "affected_items": ["result_evidence"],
            "resume_condition": "supply independently verified records before a new request",
            "execution_outcome": outcome,
        },
    }
    minimal = {key: obj[key] for key in ("research_task", "experiment_spec")}
    assert v2.validate_handoff(request, minimal, response)
    invalid = copy.deepcopy(response)
    invalid["output_refs"] = completed_response(request, obj)["output_refs"]
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, minimal, invalid)


@pytest.mark.parametrize("status, code", [
    ("rejected", "invalid_input"), ("unsupported", "capability_unsupported"),
])
@pytest.mark.parametrize("context", [{}, {"research_task": "verified"}])
def test_execute_spec_problem_response_allows_unresolvable_context(bundle, status, code, context):
    obj = records(bundle)
    request = execute_request(obj)
    request["handoff_id"] = "unresolvable-execute-request"
    request["context_refs"]["experiment_spec"]["content_hash"] = "0" * 64
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "unresolvable-execute-response",
        "message_kind": "response",
        "operation": "execute_spec",
        "sender_role": "execution",
        "recipient_role": "research",
        "context_refs": ({} if not context else {
            "research_task": request["context_refs"]["research_task"],
        }),
        "in_reply_to": request["handoff_id"],
        "status": status,
        "problem": {"code": code, "reason": "cannot resolve submitted references",
                    "affected_items": ["experiment_spec"], "resume_condition": "supply exact records",
                    "execution_outcome": "not_started"},
    }
    assert v2.validate_handoff(request, obj, response)
    invalid = copy.deepcopy(response)
    invalid["context_refs"] = {"experiment_spec": v2.check_record(obj["experiment_spec"], "experiment_spec")}
    with pytest.raises(ValueError, match="execute_spec problem context"):
        v2.validate_handoff(request, obj, invalid)


@pytest.mark.parametrize("status, code, context", [
    ("blocked", "dependency_unavailable", {}),
    ("blocked", "execution_outcome_unknown", {"research_task": {}}),
    ("incomplete", "missing_delivery", {}),
])
def test_execute_spec_blocked_or_incomplete_requires_valid_request(bundle, status, code, context):
    request = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "invalid-problem-request",
        "message_kind": "request",
        "operation": "execute_spec",
        "sender_role": "research",
        "recipient_role": "execution",
        "context_refs": context,
    }
    response = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": "invalid-problem-response",
        "message_kind": "response",
        "operation": "execute_spec",
        "sender_role": "execution",
        "recipient_role": "research",
        "context_refs": context,
        "in_reply_to": request["handoff_id"],
        "status": status,
        "problem": {"code": code, "reason": "requires admitted request",
                    "affected_items": ["experiment_spec"], "resume_condition": "admit request",
                    "execution_outcome": "unknown" if code == "execution_outcome_unknown" else "known"},
    }
    with pytest.raises(ValidationError):
        v2.validate_handoff(request, {}, response)
