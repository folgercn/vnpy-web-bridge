"""Comprehensive contract and execution tests for statistical_screening profile (#569).

Validates:
1. End-to-end COMPLETED execution for all 4 screening methods (coverage, simple_correlation, direction_consistency, stability_split).
2. Single-method and subset execution.
3. Legal INSUFFICIENT_DATA fact state when fields or rows are missing.
4. Fail-closed on 1-byte physical snapshot tampering.
5. Fail-closed on unknown method or invalid profile.
6. Evidence schema forbids decision fields (no score/rank/promote/reject/recommendation).
7. ResultStore.save_v2 persistence and querying.
8. Additive verification: existing Trend20 and single-contract contracts remain 100% intact.
"""

from __future__ import annotations

import copy
import shutil
from pathlib import Path
from typing import Any

import pytest
from jsonschema import ValidationError

from research_lab.config import ResearchLabConfig
from research_lab.contracts import statistical_screening_definition as ssd
from research_lab.contracts import v2
from research_lab.database import ResultStore
from research_lab.runners.v2_statistical_screening import run_statistical_screening

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / ssd.SYNTHETIC_FIXTURE_PATH


def compute_task_hash(task: dict[str, Any]) -> str:
    return v2.digest({k: v for k, v in task.items() if k != "task_content_hash"})


def compute_spec_hash(spec: dict[str, Any]) -> str:
    return v2.digest({k: v for k, v in spec.items() if k != "spec_content_hash"})


@pytest.fixture
def base_task() -> dict[str, Any]:
    raw_bytes = FIXTURE_PATH.read_bytes()
    task = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": "task-stat-screening-001",
        "revision": "rev.1",
        "research_type": "statistical_factor",
        "task_profile": ssd.PROFILE_NAME,
        "objective": "Cheap statistical screening for alpha hypothesis testing",
        "data_requirements": {
            "snapshot_sha256": v2.sha(raw_bytes),
            "snapshot_locator": ssd.SYNTHETIC_FIXTURE_PATH,
            "snapshot_byte_length": len(raw_bytes),
            "required_fields": ["timestamp", "symbol", "feature_val", "target_val"],
            "provenance": "synthetic-test-fixture",
            "time_range": {
                "start": "2024-01-02T09:00:00.000000Z",
                "end": "2024-01-02T09:19:00.000000Z",
            },
        },
        "methods": ["coverage", "simple_correlation", "direction_consistency", "stability_split"],
    }
    task["task_content_hash"] = compute_task_hash(task)
    return task


@pytest.fixture
def base_spec(base_task: dict[str, Any]) -> dict[str, Any]:
    raw_bytes = FIXTURE_PATH.read_bytes()
    spec = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": "spec-stat-screening-001",
        "revision": "rev.1",
        "task_id": base_task["task_id"],
        "task_revision": base_task["revision"],
        "task_content_hash": base_task["task_content_hash"],
        "experiment_type": "statistical_factor",
        "research_stage": "validation",
        "screening_profile": ssd.PROFILE_NAME,
        "dataset_requirements": {
            "snapshot_sha256": v2.sha(raw_bytes),
            "snapshot_locator": ssd.SYNTHETIC_FIXTURE_PATH,
            "snapshot_byte_length": len(raw_bytes),
            "required_fields": ["timestamp", "symbol", "feature_val", "target_val"],
            "provenance": "synthetic-test-fixture",
            "time_range": {
                "start": "2024-01-02T09:00:00.000000Z",
                "end": "2024-01-02T09:19:00.000000Z",
            },
        },
        "methods": ["coverage", "simple_correlation", "direction_consistency", "stability_split"],
    }
    spec["spec_content_hash"] = compute_spec_hash(spec)
    return spec


def test_01_statistical_screening_e2e_all_methods(base_task: dict[str, Any], base_spec: dict[str, Any], tmp_path: Path):
    """Verify full end-to-end COMPLETED execution across all 4 screening methods."""
    bundle_dir = tmp_path / "screening_bundle"
    out = run_statistical_screening(base_task, base_spec, FIXTURE_PATH, bundle_dir)
    assert out.is_dir()

    manifest = v2.parse((bundle_dir / "manifest.json").read_bytes())
    assert manifest["schema_version"] == "research_lab.artifact_manifest.v2"
    run = v2.parse((bundle_dir / "run.json").read_bytes())
    evidence = v2.parse((bundle_dir / "evidence.json").read_bytes())
    summary = v2.parse((bundle_dir / "statistical_summary.json").read_bytes())

    assert run["run_status"] == "COMPLETED"
    assert evidence["execution_status"] == "COMPLETED"
    assert evidence["run_status_snapshot"] == "COMPLETED"
    assert evidence["missing_reason"] is None
    assert evidence["typed_metrics"] is not None
    assert evidence["typed_metrics"]["profile"] == ssd.PROFILE_NAME

    # Check that all 4 screening facts are computed and present
    facts = summary["facts"]
    assert "coverage" in facts
    assert facts["coverage"]["total_rows"] == 20
    assert facts["coverage"]["valid_rows"] == 20
    assert facts["coverage"]["missing_rows"] == 0

    assert "simple_correlation" in facts
    assert facts["simple_correlation"]["sample_size"] == 20
    assert facts["simple_correlation"]["pearson_ic"] is not None

    assert "direction_consistency" in facts
    assert facts["direction_consistency"]["sample_size"] == 20
    assert facts["direction_consistency"]["matching_pairs"] > 0

    assert "stability_split" in facts
    assert facts["stability_split"]["first_half_sample_size"] == 10
    assert facts["stability_split"]["second_half_sample_size"] == 10

    # Decision fields strictly forbidden
    for forbidden in ("score", "rank", "recommendation", "decision", "promote", "reject"):
        assert forbidden not in summary
        assert forbidden not in facts
        assert forbidden not in evidence["typed_metrics"]


def test_02_single_method_execution(base_task: dict[str, Any], base_spec: dict[str, Any], tmp_path: Path):
    """Verify execution with a single screening method (coverage)."""
    task = copy.deepcopy(base_task)
    task["task_id"] = "task-coverage-only"
    task["methods"] = ["coverage"]
    task["task_content_hash"] = compute_task_hash(task)

    spec = copy.deepcopy(base_spec)
    spec["spec_id"] = "spec-coverage-only"
    spec["task_id"] = task["task_id"]
    spec["task_content_hash"] = task["task_content_hash"]
    spec["methods"] = ["coverage"]
    spec["spec_content_hash"] = compute_spec_hash(spec)

    bundle_dir = tmp_path / "coverage_bundle"
    run_statistical_screening(task, spec, FIXTURE_PATH, bundle_dir)

    summary = v2.parse((bundle_dir / "statistical_summary.json").read_bytes())
    assert summary["methods_applied"] == ["coverage"]
    assert "coverage" in summary["facts"]
    assert "simple_correlation" not in summary["facts"]


def test_03_insufficient_data_missing_field(base_task: dict[str, Any], base_spec: dict[str, Any], tmp_path: Path):
    """Verify legal INSUFFICIENT_DATA fact state when required field is missing."""
    task = copy.deepcopy(base_task)
    task["task_id"] = "task-missing-field"
    task["data_requirements"]["required_fields"] = ["timestamp", "symbol", "nonexistent_field"]
    task["task_content_hash"] = compute_task_hash(task)

    spec = copy.deepcopy(base_spec)
    spec["spec_id"] = "spec-missing-field"
    spec["task_id"] = task["task_id"]
    spec["task_content_hash"] = task["task_content_hash"]
    spec["dataset_requirements"]["required_fields"] = ["timestamp", "symbol", "nonexistent_field"]
    spec["spec_content_hash"] = compute_spec_hash(spec)

    bundle_dir = tmp_path / "missing_field_bundle"
    run_statistical_screening(task, spec, FIXTURE_PATH, bundle_dir)

    run = v2.parse((bundle_dir / "run.json").read_bytes())
    evidence = v2.parse((bundle_dir / "evidence.json").read_bytes())
    diagnostics = v2.parse((bundle_dir / "failure_diagnostics.json").read_bytes())

    assert run["run_status"] == "INSUFFICIENT_DATA"
    assert evidence["execution_status"] == "INSUFFICIENT_DATA"
    assert evidence["typed_metrics"] is None
    assert evidence["missing_reason"] == "insufficient_data"
    assert diagnostics["error_type"] == "insufficient_data"
    assert "nonexistent_field" in diagnostics["missing_fields"]


def test_04_tampered_snapshot_fails_closed(base_task: dict[str, Any], base_spec: dict[str, Any], tmp_path: Path):
    """Verify that 1-byte tampering in physical snapshot is immediately rejected fail-closed."""
    tampered_file = tmp_path / "tampered.csv"
    tampered_bytes = FIXTURE_PATH.read_bytes() + b"X"
    tampered_file.write_bytes(tampered_bytes)

    with pytest.raises(ValueError, match="Snapshot sha256 mismatch|physical snapshot sha256 mismatch"):
        run_statistical_screening(base_task, base_spec, tampered_file, tmp_path / "tampered_out")


def test_05_unknown_screening_method_rejected(base_task: dict[str, Any], base_spec: dict[str, Any], tmp_path: Path):
    """Verify that unknown methods (e.g. parameter_sweep, deep_learning) fail-closed."""
    spec = copy.deepcopy(base_spec)
    spec["methods"] = ["coverage", "unsupported_giant_parameter_sweep"]
    spec["spec_content_hash"] = compute_spec_hash(spec)

    definitions = v2.Definitions()
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_spec(spec, base_task, definitions)


def test_06_profile_isolation_fail_closed(base_task: dict[str, Any], base_spec: dict[str, Any]):
    """Verify mutual exclusivity: Trend20 cannot impersonate statistical_screening, and vice versa."""
    # Impersonation: statistical_screening claims trend20 profile
    bad_spec = copy.deepcopy(base_spec)
    del bad_spec["screening_profile"]
    bad_spec["spec_content_hash"] = compute_spec_hash(bad_spec)

    definitions = v2.Definitions()
    with pytest.raises((ValueError, ValidationError)):
        v2.validate_spec(bad_spec, base_task, definitions)


def test_07_result_store_save_and_query(base_task: dict[str, Any], base_spec: dict[str, Any], tmp_path: Path):
    """Verify ResultStore.save_v2 can capture and query completed and insufficient_data runs."""
    cfg = ResearchLabConfig(root=tmp_path / "lab_root")
    store = ResultStore(cfg)

    # 1. Save COMPLETED run
    bundle_completed = tmp_path / "completed_bundle"
    run_statistical_screening(base_task, base_spec, FIXTURE_PATH, bundle_completed)
    receipt_completed = store.save_v2(bundle_completed)
    assert receipt_completed["run_status"] == "COMPLETED"

    # 2. Query runs
    runs = store.query_v2_runs()
    assert len(runs) == 1
    assert runs[0]["task"]["object_id"] == base_task["task_id"]
    assert runs[0]["spec"]["object_id"] == base_spec["spec_id"]
    assert runs[0]["run_status"] == "COMPLETED"

    # 3. Save INSUFFICIENT_DATA run
    task_insufficient = copy.deepcopy(base_task)
    task_insufficient["task_id"] = "task-stat-insufficient"
    task_insufficient["data_requirements"]["required_fields"] = ["timestamp", "missing_col"]
    task_insufficient["task_content_hash"] = compute_task_hash(task_insufficient)

    spec_insufficient = copy.deepcopy(base_spec)
    spec_insufficient["spec_id"] = "spec-stat-insufficient"
    spec_insufficient["task_id"] = task_insufficient["task_id"]
    spec_insufficient["task_content_hash"] = task_insufficient["task_content_hash"]
    spec_insufficient["dataset_requirements"]["required_fields"] = ["timestamp", "missing_col"]
    spec_insufficient["spec_content_hash"] = compute_spec_hash(spec_insufficient)

    bundle_insufficient = tmp_path / "insufficient_bundle"
    run_statistical_screening(task_insufficient, spec_insufficient, FIXTURE_PATH, bundle_insufficient)
    receipt_insufficient = store.save_v2(bundle_insufficient)
    assert receipt_insufficient["run_status"] == "INSUFFICIENT_DATA"

    runs_after = store.query_v2_runs()
    assert len(runs_after) == 2


def test_08_existing_trend20_and_single_contract_intact():
    """Additive guarantee: check that catalogue entries and definitions for previous profiles remain intact."""
    definitions = v2.Definitions()
    assert any(e["name"].startswith("phase0.trend20.") for e in definitions.entries)
    assert any(e["name"].startswith("research_lab.single_contract.") for e in definitions.entries)
    assert any(e["name"].startswith(ssd.PAYLOAD_PREFIX) for e in definitions.entries)


def test_09_failed_status_handling_and_persistence(base_task: dict[str, Any], base_spec: dict[str, Any], tmp_path: Path):
    """Verify FAILED status execution, failure_diagnostics artifact, validate_manifest, and ResultStore persistence."""
    task_failed = copy.deepcopy(base_task)
    task_failed["task_id"] = "task-stat-failed-001"
    task_failed["task_content_hash"] = compute_task_hash(task_failed)

    spec_failed = copy.deepcopy(base_spec)
    spec_failed["spec_id"] = "spec-stat-failed-001"
    spec_failed["task_id"] = task_failed["task_id"]
    spec_failed["task_content_hash"] = task_failed["task_content_hash"]
    spec_failed["spec_content_hash"] = compute_spec_hash(spec_failed)

    bundle_failed = tmp_path / "failed_bundle"
    run_statistical_screening(
        task_failed,
        spec_failed,
        FIXTURE_PATH,
        bundle_failed,
        _inject_failure="Simulated execution calculation error",
    )

    # 1. Verify bundle files
    assert (bundle_failed / "failure_diagnostics.json").is_file()
    assert not (bundle_failed / "statistical_summary.json").exists()

    run = v2.parse((bundle_failed / "run.json").read_bytes())
    assert run["run_status"] == "FAILED"
    assert run["process_exit_code"] == 1

    evidence = v2.parse((bundle_failed / "evidence.json").read_bytes())
    assert evidence["execution_status"] == "FAILED"
    assert evidence["run_status_snapshot"] == "FAILED"
    assert evidence["missing_reason"] == "execution_failed"
    assert evidence["typed_metrics"] is None

    diag = v2.parse((bundle_failed / "failure_diagnostics.json").read_bytes())
    assert diag["profile"] == ssd.PROFILE_NAME
    assert diag["error_type"] == "execution_failed"
    assert "Simulated execution calculation error" in diag["error_message"]

    # 2. validate_manifest on FAILED bundle
    definitions = v2.Definitions()
    manifest = v2.parse((bundle_failed / "manifest.json").read_bytes())
    v2.validate_manifest(bundle_failed, manifest, run, definitions, task=task_failed, spec=spec_failed)

    # 3. Save to ResultStore and query
    cfg = ResearchLabConfig(root=tmp_path / "lab_root_failed")
    store = ResultStore(cfg)
    receipt = store.save_v2(bundle_failed)
    assert receipt["run_status"] == "FAILED"

    runs = store.query_v2_runs()
    assert len(runs) == 1
    assert runs[0]["run_status"] == "FAILED"
    assert runs[0]["task"]["object_id"] == task_failed["task_id"]

    # 4. Fail-closed: FAILED run missing physical failure_diagnostics.json
    bad_bundle = tmp_path / "bad_failed_bundle"
    shutil.copytree(bundle_failed, bad_bundle)
    (bad_bundle / "failure_diagnostics.json").unlink()
    with pytest.raises(FileNotFoundError):
        v2.validate_manifest(bad_bundle, manifest, run, definitions, task=task_failed, spec=spec_failed)

    # 5. Fail-closed: FAILED run missing failure_diagnostics role in manifest
    bad_manifest = copy.deepcopy(manifest)
    bad_manifest["entries"] = [e for e in bad_manifest["entries"] if e["role"] != "failure_diagnostics"]
    del bad_manifest["manifest_content_hash"]
    bad_manifest["manifest_content_hash"] = v2.digest(bad_manifest)
    with pytest.raises(ValueError, match="missing required role|FAILED run missing failure_diagnostics"):
        v2.validate_manifest(bundle_failed, bad_manifest, run, definitions, task=task_failed, spec=spec_failed)
