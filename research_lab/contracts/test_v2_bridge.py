"""Focused tests for Protocol v2 local one-shot execution bridge (#554)."""

import copy
import subprocess
import sys
import tarfile
from unittest.mock import patch

import pytest

from research_lab.contracts import v2
from research_lab.runners.v2_bridge import V2ExecutionBridge, execute_v2_spec


def reseal(obj: dict, prefix: str) -> dict:
    obj[prefix + "_content_hash"] = v2.digest(
        {k: v for k, v in obj.items() if k != prefix + "_content_hash"}
    )
    return obj


@pytest.fixture
def phase0_materials(tmp_path):
    """Extract standard #544 reference inputs from checked-in archive."""
    archive = v2.ROOT / "research/phase0_data_quality/bundles/validation-rev1-ci.tar.gz"
    extract_dir = tmp_path / "source"
    with tarfile.open(archive) as tf:
        tf.extractall(extract_dir, filter="data")

    materials_dir = extract_dir / "materials"
    task = v2.parse((materials_dir / "task.json").read_bytes())
    spec = v2.parse((materials_dir / "spec.json").read_bytes())
    raw_csv = (materials_dir / "input.csv").read_bytes()
    provenance = v2.parse((materials_dir / "provenance.json").read_bytes())

    return {
        "materials_dir": materials_dir,
        "task": task,
        "spec": spec,
        "raw_csv": raw_csv,
        "provenance": provenance,
    }


def test_positive_execution_and_public_handoff_consumption(phase0_materials, tmp_path):
    """Test standard positive execution produces valid Run/Manifest/Evidence consumed by frozen public handoff."""
    out_dir = tmp_path / "run_out"
    task = phase0_materials["task"]
    spec = phase0_materials["spec"]
    raw_csv = phase0_materials["raw_csv"]
    prov = phase0_materials["provenance"]

    bridge = V2ExecutionBridge()
    result = bridge.execute(
        task=task,
        spec=spec,
        input_data=raw_csv,
        output_dir=out_dir,
        provenance=prov,
    )

    run = result["run"]
    manifest = result["manifest"]
    evidence = result["evidence"]

    assert result["run_status"] == "COMPLETED"
    assert result["process_exit_code"] == 0
    assert run["run_status"] == "COMPLETED"
    assert run["process_exit_code"] == 0
    assert run["spec_id"] == spec["spec_id"]
    assert run["spec_content_hash"] == spec["spec_content_hash"]

    # Evidence checks: facts only, no review / evaluation
    assert "review" not in evidence
    assert "recommendation" not in evidence
    assert evidence["execution_status"] == "COMPLETED"
    assert evidence["missing_reason"] is None
    assert len(evidence["typed_metrics"]) == 1
    metric_entry = evidence["typed_metrics"][0]
    assert metric_entry["metric"]["metric_name"] == "timestamp_monotonicity_violations"
    assert metric_entry["value"] == 0
    assert metric_entry["sample_count"] == 179

    # Replay materials delivered inside bundle
    assert (out_dir / "materials/task.json").is_file()
    assert (out_dir / "materials/spec.json").is_file()
    assert (out_dir / "materials/input.csv").is_file()
    assert (out_dir / "materials/provenance.json").is_file()

    # Public frozen v2.validate_handoff independent re-consumption check for execute_spec
    req = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"test-req-{run['run_id']}",
        "message_kind": "request",
        "operation": "execute_spec",
        "sender_role": "research",
        "recipient_role": "execution",
        "context_refs": {
            "research_task": v2.check_record(task, "research_task"),
            "experiment_spec": v2.check_record(spec, "experiment_spec"),
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
    resp = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"test-resp-{run['run_id']}",
        "message_kind": "response",
        "operation": "execute_spec",
        "sender_role": "execution",
        "recipient_role": "research",
        "context_refs": req["context_refs"],
        "in_reply_to": req["handoff_id"],
        "status": "completed",
        "output_refs": [
            v2.check_record(run, "experiment_run"),
            v2.check_record(manifest, "artifact_manifest"),
            v2.check_record(evidence, "result_evidence"),
        ],
    }
    handoff_objs = {
        "research_task": task,
        "experiment_spec": spec,
        "experiment_run": run,
        "artifact_manifest": manifest,
        "result_evidence": evidence,
    }
    assert v2.validate_handoff(req, handoff_objs, resp, root=out_dir)

    # Public frozen v2.validate_handoff independent re-consumption check for review_evidence
    review_req = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"review-req-{run['run_id']}",
        "message_kind": "request",
        "operation": "review_evidence",
        "sender_role": "execution",
        "recipient_role": "critic",
        "context_refs": {
            kind: v2.check_record(handoff_objs[kind], kind)
            for kind in ("research_task", "experiment_spec", "experiment_run", "artifact_manifest", "result_evidence")
        },
        "artifact_requirements": {
            "role_profile_ref": v2.ROLE_PROFILE,
            "required_roles": sorted(v2.COMMON | v2.TYPED["data_quality"]),
            "exact_refs": v2._present_artifact_refs(manifest),
        },
        "expected_outputs": [{"object_type": "review", "schema_version": "research_lab.review.v2"}],
        "review_scope": "research_assessment",
        "criteria_ref": {
            "id": "phase0-date-order-criteria",
            "revision": "rev.1",
            "content_hash": "5b0705750fa07a19905abbc2ee5567828a200246b32ce5a9c554989fe1f8c03f",
        },
    }
    assert v2.validate_handoff(review_req, handoff_objs, None, root=out_dir)


def test_rerun_creates_new_run_id_with_identical_scientific_fingerprint(phase0_materials, tmp_path):
    """Identical spec + identical input + identical code rerun generates new run_id with identical fingerprint."""
    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"
    task = phase0_materials["task"]
    spec = phase0_materials["spec"]
    raw_csv = phase0_materials["raw_csv"]
    prov = phase0_materials["provenance"]

    res1 = execute_v2_spec(task, spec, raw_csv, out1, provenance=prov)
    res2 = execute_v2_spec(task, spec, raw_csv, out2, provenance=prov)

    assert res1["run"]["run_id"] != res2["run"]["run_id"]
    assert res1["manifest"]["manifest_id"] != res2["manifest"]["manifest_id"]
    assert res1["evidence"]["evidence_id"] != res2["evidence"]["evidence_id"]

    # Scientific fingerprint and computation manifest must match exactly
    assert res1["run"]["scientific_fingerprint"] == res2["run"]["scientific_fingerprint"]
    assert (
        res1["run"]["resolved_computation_manifest"]
        == res2["run"]["resolved_computation_manifest"]
    )


def test_no_overwrite_and_lock_timing(phase0_materials, tmp_path):
    """Target directory already containing a run must reject overwrite; lock must precede completion."""
    out_dir = tmp_path / "run_locked"
    task = phase0_materials["task"]
    spec = phase0_materials["spec"]
    raw_csv = phase0_materials["raw_csv"]
    prov = phase0_materials["provenance"]

    res = execute_v2_spec(task, spec, raw_csv, out_dir, provenance=prov)
    run = res["run"]
    lock = v2.parse((out_dir / "input-lock.json").read_bytes())

    # Timing order contract check: locked_at <= started_at <= completed_at
    assert v2.time_value(lock["locked_at"]) <= v2.time_value(run["timing"]["started_at"])
    assert v2.time_value(run["timing"]["started_at"]) <= v2.time_value(run["timing"]["completed_at"])

    # Overwrite guard: second execution targeting the same output directory must raise FileExistsError
    with pytest.raises(FileExistsError, match="Target directory .* already exists"):
        execute_v2_spec(task, spec, raw_csv, out_dir, provenance=prov)


@pytest.mark.parametrize(
    "mutation",
    [
        "shortened_spec_end_date",
        "wrong_required_fields",
        "corrupted_snapshot_hash",
        "mismatched_raw_bytes",
        "unsupported_profile",
        "unsupported_stage",
        "unknown_method",
        "unknown_parameter",
        "reversed_timerange",
        "task_hash_mismatch",
        "missing_provenance",
    ],
)
def test_pre_execution_admission_fail_closed_and_computation_not_started(
    phase0_materials, tmp_path, mutation
):
    """Every invalid input must fail closed in admission BEFORE computation starts (scan.call_count == 0)."""
    task = copy.deepcopy(phase0_materials["task"])
    spec = copy.deepcopy(phase0_materials["spec"])
    raw_csv = phase0_materials["raw_csv"]
    prov = copy.deepcopy(phase0_materials["provenance"])
    out_dir = tmp_path / f"mut_{mutation}"

    if mutation == "shortened_spec_end_date":
        # Shorten Spec end to 2023-01-10 and reseal spec_content_hash
        spec["dataset_requirements"]["time_range"]["end"] = "2023-01-10T00:00:00.000000Z"
        reseal(spec, "spec")
    elif mutation == "wrong_required_fields":
        # Change required_fields to wrong column and reseal
        spec["dataset_requirements"]["required_fields"] = ["wrong_column"]
        reseal(spec, "spec")
    elif mutation == "corrupted_snapshot_hash":
        spec["dataset_requirements"]["snapshot_sha256"] = "0" * 64
        reseal(spec, "spec")
    elif mutation == "mismatched_raw_bytes":
        # Alter one byte of raw CSV
        raw_csv = raw_csv + b"\n"
    elif mutation == "unsupported_profile":
        spec["experiment_type"] = "trading_backtest"
        reseal(spec, "spec")
    elif mutation == "unsupported_stage":
        spec["research_stage"] = "confirmation"
        reseal(spec, "spec")
    elif mutation == "unknown_method":
        spec["quality_checks"][0]["implementation_ref"] = "candidate.phase0.unknown.rev1"
        reseal(spec, "spec")
    elif mutation == "unknown_parameter":
        spec["quality_checks"][0]["parameters"].append(
            {"name": "invented", "value_type": "boolean", "unit": "dimensionless", "value": True}
        )
        reseal(spec, "spec")
    elif mutation == "reversed_timerange":
        spec["dataset_requirements"]["time_range"]["start"] = "2023-02-01T00:00:00.000000Z"
        spec["dataset_requirements"]["time_range"]["end"] = "2023-01-03T00:00:00.000000Z"
        reseal(spec, "spec")
    elif mutation == "task_hash_mismatch":
        spec["task_content_hash"] = "1" * 64
        reseal(spec, "spec")
    elif mutation == "missing_provenance":
        prov = None

    with patch("quality.scan") as mock_scan:
        with pytest.raises((ValueError, Exception)):
            execute_v2_spec(task, spec, raw_csv, out_dir, provenance=prov)

        # Hard assertion: computation must NEVER start
        assert mock_scan.call_count == 0


def test_failed_execution_captures_diagnostics_without_fabricating_completion(
    phase0_materials, tmp_path
):
    """When calculation fails, FAILED run and failure_diagnostics must be preserved honestly."""
    task = phase0_materials["task"]
    spec = phase0_materials["spec"]
    raw_csv = phase0_materials["raw_csv"]
    prov = phase0_materials["provenance"]
    out_dir = tmp_path / "failed_run"

    bridge = V2ExecutionBridge()

    with patch(
        "quality.scan",
        side_effect=RuntimeError("Simulated scanner anomaly during row evaluation"),
    ):
        result = bridge.execute(
            task=task,
            spec=spec,
            input_data=raw_csv,
            output_dir=out_dir,
            provenance=prov,
        )

    run = result["run"]
    manifest = result["manifest"]
    evidence = result["evidence"]

    assert result["run_status"] == "FAILED"
    assert result["process_exit_code"] == 1
    assert run["run_status"] == "FAILED"
    assert run["process_exit_code"] == 1

    # Evidence must NOT fabricate completed metrics
    assert evidence["execution_status"] == "FAILED"
    assert evidence["typed_metrics"] is None
    assert evidence["missing_reason"] == "execution_failed"

    # Manifest entries must record failure_diagnostics as present and summaries as unavailable
    entries_by_role = {e["role"]: e for e in manifest["entries"]}
    assert "failure_diagnostics" in entries_by_role
    assert entries_by_role["failure_diagnostics"]["availability"] == "present"
    assert entries_by_role["quality_summary"]["availability"] == "unavailable"
    assert entries_by_role["quality_anomalies"]["availability"] == "unavailable"

    # Verify failure_diagnostics payload content
    diag_data = v2.parse((out_dir / "payload/failure_diagnostics.json").read_bytes())
    assert diag_data["error_type"] == "RuntimeError"
    assert "Simulated scanner anomaly" in diag_data["message"]
    assert diag_data["stage"] == "quality_scan"

    # Re-consumed by public v2.validate_handoff
    req = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"test-failed-req-{run['run_id']}",
        "message_kind": "request",
        "operation": "execute_spec",
        "sender_role": "research",
        "recipient_role": "execution",
        "context_refs": {
            "research_task": v2.check_record(task, "research_task"),
            "experiment_spec": v2.check_record(spec, "experiment_spec"),
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
    resp = {
        "schema_version": "research_lab.agent_handoff.v2",
        "handoff_id": f"test-failed-resp-{run['run_id']}",
        "message_kind": "response",
        "operation": "execute_spec",
        "sender_role": "execution",
        "recipient_role": "research",
        "context_refs": req["context_refs"],
        "in_reply_to": req["handoff_id"],
        "status": "completed",
        "output_refs": [
            v2.check_record(run, "experiment_run"),
            v2.check_record(manifest, "artifact_manifest"),
            v2.check_record(evidence, "result_evidence"),
        ],
    }
    handoff_objs = {
        "research_task": task,
        "experiment_spec": spec,
        "experiment_run": run,
        "artifact_manifest": manifest,
        "result_evidence": evidence,
    }
    assert v2.validate_handoff(req, handoff_objs, resp, root=out_dir)


def test_independent_replay_from_bundle_materials(phase0_materials, tmp_path):
    """The generated output bundle must contain self-contained materials that can be cleanly replayed."""
    out_dir = tmp_path / "primary_run"
    replay_out = tmp_path / "replay_run"

    bridge = V2ExecutionBridge()
    result = bridge.execute(
        task=phase0_materials["task"],
        spec=phase0_materials["spec"],
        input_data=phase0_materials["raw_csv"],
        output_dir=out_dir,
        provenance=phase0_materials["provenance"],
    )
    assert result["run_status"] == "COMPLETED"

    # Replay using the bundled materials and case.py
    replay_cmd = [
        sys.executable,
        str(out_dir / "materials/case.py"),
        "run",
        "--inputs",
        str(out_dir / "materials"),
        "--bundle",
        str(replay_out),
    ]
    proc = subprocess.run(replay_cmd, cwd=v2.ROOT, capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    replay_run = v2.parse((replay_out / "run.json").read_bytes())
    assert replay_run["run_status"] == "COMPLETED"
    assert replay_run["scientific_fingerprint"] == result["run"]["scientific_fingerprint"]
    assert replay_run["run_id"] != result["run"]["run_id"]


def test_execute_from_materials(phase0_materials, tmp_path):
    """Test execution directly from a materials directory."""
    out_dir = tmp_path / "materials_run"
    bridge = V2ExecutionBridge()
    result = bridge.execute_from_materials(
        materials_dir=phase0_materials["materials_dir"],
        output_dir=out_dir,
    )
    assert result["run_status"] == "COMPLETED"
    assert (out_dir / "run.json").is_file()
    assert (out_dir / "manifest.json").is_file()
    assert (out_dir / "evidence.json").is_file()


def test_cli_execution(phase0_materials, tmp_path):
    """Test CLI entrypoint via subprocess python -m research_lab.runners.v2_bridge."""
    out_dir = tmp_path / "cli_run"
    materials_dir = phase0_materials["materials_dir"]

    cmd = [
        sys.executable,
        "-m",
        "research_lab.runners.v2_bridge",
        "--materials",
        str(materials_dir),
        "--output",
        str(out_dir),
    ]
    res = subprocess.run(cmd, cwd=v2.ROOT, capture_output=True, text=True, check=False)
    assert res.returncode == 0
    assert "COMPLETED" in res.stdout
    assert (out_dir / "run.json").is_file()


def test_scan_concurrent_interference_prevented(phase0_materials, tmp_path):
    """Simulating another party planting output/run.json during scan must fail closed with FileExistsError and no overwrite."""
    out_dir = tmp_path / "concurrent_test"
    task = phase0_materials["task"]
    spec = phase0_materials["spec"]
    raw_csv = phase0_materials["raw_csv"]
    prov = phase0_materials["provenance"]

    from research.phase0_data_quality import quality
    original_scan = quality.scan

    def malicious_interfering_scan(raw, spec_arg):
        # Simulate an external actor dropping a malicious run.json inside out_dir while calculation is running
        (out_dir / "run.json").write_text('{"planted": true}')
        return original_scan(raw, spec_arg)

    bridge = V2ExecutionBridge()
    with patch("quality.scan", side_effect=malicious_interfering_scan), pytest.raises(FileExistsError):
        bridge.execute(
            task=task,
            spec=spec,
            input_data=raw_csv,
            output_dir=out_dir,
            provenance=prov,
        )

    # The planted file must NOT have been silently overwritten by the runner
    assert (out_dir / "run.json").read_text() == '{"planted": true}'


def test_issue_a_materials_dir_not_found_raises_file_not_found_without_fallback(
    phase0_materials, tmp_path
):
    """Missing materials_dir must raise FileNotFoundError immediately and NEVER silently fall back."""
    out_dir = tmp_path / "missing_materials_run"
    bridge = V2ExecutionBridge()
    non_existent = tmp_path / "non_existent_materials_dir"

    with patch("quality.scan") as mock_scan:
        with pytest.raises(FileNotFoundError, match="Materials directory does not exist"):
            bridge.execute(
                task=phase0_materials["task"],
                spec=phase0_materials["spec"],
                input_data=phase0_materials["raw_csv"],
                output_dir=out_dir,
                provenance=phase0_materials["provenance"],
                materials_dir=non_existent,
            )
        assert mock_scan.call_count == 0
    assert not out_dir.exists()


def test_issue_a_spec_mismatch_with_materials_dir_fails_closed_before_scan(
    phase0_materials, tmp_path
):
    """When passed Spec contradicts spec.json in materials_dir, abort before scan with ValueError (no 'A-vs-B' execution)."""
    out_dir = tmp_path / "mismatch_spec_run"
    materials_dir = phase0_materials["materials_dir"]

    # Construct a valid strict=False Spec
    strict_false_spec = copy.deepcopy(phase0_materials["spec"])
    strict_false_spec["quality_checks"][0]["parameters"] = [
        {"name": "strict", "value_type": "boolean", "unit": "dimensionless", "value": False}
    ]
    reseal(strict_false_spec, "spec")

    bridge = V2ExecutionBridge()
    with patch("quality.scan") as mock_scan:
        with pytest.raises(ValueError, match="single source of truth violated"):
            bridge.execute(
                task=phase0_materials["task"],
                spec=strict_false_spec,
                input_data=phase0_materials["raw_csv"],
                output_dir=out_dir,
                provenance=phase0_materials["provenance"],
                materials_dir=materials_dir,
            )
        assert mock_scan.call_count == 0

    assert not out_dir.exists()


def test_issue_b_corrupted_provenance_source_sha_fails_closed_before_scan(
    phase0_materials, tmp_path
):
    """Corrupted provenance source_sha256 ('a'*64) must fail closed BEFORE quality.scan (scan.call_count == 0)."""
    out_dir = tmp_path / "corrupted_prov_run"
    task = phase0_materials["task"]
    spec = phase0_materials["spec"]
    raw_csv = phase0_materials["raw_csv"]

    corrupted_prov = copy.deepcopy(phase0_materials["provenance"])
    corrupted_prov["source_sha256"] = "a" * 64

    bridge = V2ExecutionBridge()
    with patch("quality.scan") as mock_scan:
        with pytest.raises(ValueError, match="Provenance violates phase0-payload|source_sha256 mismatch"):
            bridge.execute(
                task=task,
                spec=spec,
                input_data=raw_csv,
                output_dir=out_dir,
                provenance=corrupted_prov,
            )
        assert mock_scan.call_count == 0

    assert not out_dir.exists()


def test_issue_b_criteria_mismatch_fails_closed_before_scan(
    phase0_materials, tmp_path
):
    """Spec with invalid candidate_decision_criteria must abort before quality.scan starts."""
    out_dir = tmp_path / "bad_criteria_run"
    task = phase0_materials["task"]
    spec = copy.deepcopy(phase0_materials["spec"])
    raw_csv = phase0_materials["raw_csv"]
    prov = phase0_materials["provenance"]

    spec["candidate_decision_criteria"] = {"max_allowed_timestamp_reversals": 1}
    reseal(spec, "spec")

    bridge = V2ExecutionBridge()
    with patch("quality.scan") as mock_scan:
        with pytest.raises(ValueError, match="candidate_decision_criteria"):
            bridge.execute(
                task=task,
                spec=spec,
                input_data=raw_csv,
                output_dir=out_dir,
                provenance=prov,
            )
        assert mock_scan.call_count == 0

    assert not out_dir.exists()


def test_issue_c_arbitrary_raw_bytes_fails_closed_without_fabricating_preparation(
    phase0_materials, tmp_path
):
    """Arbitrary raw bytes (e.g. appended newline with resealed spec) must be rejected before scan, not signed with prep."""
    out_dir = tmp_path / "arbitrary_raw_run"
    task = phase0_materials["task"]
    prov = phase0_materials["provenance"]

    # Append newline to raw CSV and reseal spec snapshot_sha256
    modified_raw = phase0_materials["raw_csv"] + b"\n"
    spec = copy.deepcopy(phase0_materials["spec"])
    spec["dataset_requirements"]["snapshot_sha256"] = v2.sha(modified_raw)
    reseal(spec, "spec")

    bridge = V2ExecutionBridge()
    with patch("quality.scan") as mock_scan:
        with pytest.raises(ValueError, match="Arbitrary raw data injection is prohibited"):
            bridge.execute(
                task=task,
                spec=spec,
                input_data=modified_raw,
                output_dir=out_dir,
                provenance=prov,
            )
        assert mock_scan.call_count == 0

    assert not out_dir.exists()


def test_positive_strict_false_spec_execution(phase0_materials, tmp_path):
    """Legitimate strict=False spec execution succeeds and produces valid completed run and evidence."""
    out_dir = tmp_path / "strict_false_run"
    task = phase0_materials["task"]
    prov = phase0_materials["provenance"]
    raw_csv = phase0_materials["raw_csv"]

    strict_false_spec = copy.deepcopy(phase0_materials["spec"])
    strict_false_spec["quality_checks"][0]["parameters"] = [
        {"name": "strict", "value_type": "boolean", "unit": "dimensionless", "value": False}
    ]
    reseal(strict_false_spec, "spec")

    bridge = V2ExecutionBridge()
    result = bridge.execute(
        task=task,
        spec=strict_false_spec,
        input_data=raw_csv,
        output_dir=out_dir,
        provenance=prov,
    )

    assert result["run_status"] == "COMPLETED"
    assert result["run"]["spec_id"] == strict_false_spec["spec_id"]
    assert result["run"]["spec_content_hash"] == strict_false_spec["spec_content_hash"]
    assert (
        result["run"]["resolved_computation_manifest"]["resolved_parameters"]["strict"] is False
    )


def test_review_r3_tampered_source_base_revision_rejected_before_scan(
    phase0_materials, tmp_path
):
    """Tampered source_base_revision ('a'*40) in preparation.json must fail closed before scan with no run generated."""
    import shutil
    materials_copy = tmp_path / "tampered_rev_mat"
    shutil.copytree(phase0_materials["materials_dir"], materials_copy)

    # Tamper source_base_revision to 'a'*40
    prep_path = materials_copy / "preparation.json"
    prep = v2.parse(prep_path.read_bytes())
    prep["source_base_revision"] = "a" * 40
    prep_path.write_text(v2.canonical(prep) + "\n")

    out_dir = tmp_path / "tampered_rev_out"
    bridge = V2ExecutionBridge()

    with patch("quality.scan") as mock_scan:
        with pytest.raises(ValueError, match="Invalid preparation.source_base_revision"):
            bridge.execute_from_materials(materials_copy, out_dir)
        assert mock_scan.call_count == 0

    assert not out_dir.exists()
    assert not (v2.ROOT / "tmp").exists() or not list((v2.ROOT / "tmp").glob("stage-*"))


def test_review_r3_tampered_payload_schema_rejected_before_scan(
    phase0_materials, tmp_path
):
    """Tampered payload.schema.json with resealed preparation must fail closed before scan (no scan, no run)."""
    import shutil
    materials_copy = tmp_path / "tampered_schema_mat"
    shutil.copytree(phase0_materials["materials_dir"], materials_copy)

    # Add title='tampered' to $defs.quality_summary in payload.schema.json
    schema_path = materials_copy / "payload.schema.json"
    schema = v2.parse(schema_path.read_bytes())
    schema["$defs"]["quality_summary"]["title"] = "tampered"
    schema_path.write_text(v2.canonical(schema) + "\n")

    # Recompute preparation.files['payload.schema.json'] to simulate deceptive materials
    prep_path = materials_copy / "preparation.json"
    prep = v2.parse(prep_path.read_bytes())
    prep["files"]["payload.schema.json"] = v2.sha(schema_path.read_bytes())
    prep_path.write_text(v2.canonical(prep) + "\n")

    out_dir = tmp_path / "tampered_schema_out"
    bridge = V2ExecutionBridge()

    with patch("quality.scan") as mock_scan:
        with pytest.raises(ValueError, match="Tampered immutable material"):
            bridge.execute_from_materials(materials_copy, out_dir)
        assert mock_scan.call_count == 0

    assert not out_dir.exists()
    assert not (v2.ROOT / "tmp").exists() or not list((v2.ROOT / "tmp").glob("stage-*"))


def test_review_r3_execution_isolated_from_subsequent_external_materials_mutation(
    phase0_materials, tmp_path
):
    """Execution is captured into isolated staging, preventing TOCTOU or校验A执行B."""
    import shutil
    materials_copy = tmp_path / "isolated_mat"
    shutil.copytree(phase0_materials["materials_dir"], materials_copy)

    out_dir = tmp_path / "isolated_out"
    bridge = V2ExecutionBridge()

    # Normal execution succeeds cleanly
    result = bridge.execute_from_materials(materials_copy, out_dir)
    assert result["run_status"] == "COMPLETED"
    assert result["run"]["resolved_computation_manifest"]["code_revision"] == "4c4691c3f1491d54b4a2f84aa24192e33552db67"
    assert not (v2.ROOT / "tmp").exists() or not list((v2.ROOT / "tmp").glob("stage-*"))
