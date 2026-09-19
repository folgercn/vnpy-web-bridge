"""Focused append-only result-loop coverage for Protocol v2 (#555)."""

from __future__ import annotations

import shutil
import sqlite3
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.database import ResultStore
from research_lab.reports import render_v2_report, write_v2_report
from research_lab.runners.v2_bridge import V2ExecutionBridge


@pytest.fixture
def materials(tmp_path: Path) -> Path:
    archive = v2.ROOT / "research/phase0_data_quality/bundles/validation-rev1-ci.tar.gz"
    with tarfile.open(archive) as source:
        source.extractall(tmp_path / "source", filter="data")
    return tmp_path / "source/materials"


def test_v2_result_loop_is_append_only_and_keeps_exact_references(
    materials: Path, tmp_path: Path
) -> None:
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge(result_store=store)

    first = bridge.execute_from_materials(materials, tmp_path / "run-1")
    second = bridge.execute_from_materials(materials, tmp_path / "run-2")
    with patch(
        "research_lab.runners.v2_bridge.quality.scan",
        side_effect=RuntimeError("scanner failed"),
    ):
        failed = bridge.execute_from_materials(materials, tmp_path / "run-failed")

    assert first["run"]["run_id"] != second["run"]["run_id"]
    assert (
        first["run"]["scientific_fingerprint"]
        == second["run"]["scientific_fingerprint"]
    )
    assert failed["run_status"] == "FAILED"

    receipts = store.query_v2_runs(spec_id=first["run"]["spec_id"])
    assert [receipt["run"]["object_id"] for receipt in receipts] == [
        first["run"]["run_id"],
        second["run"]["run_id"],
        failed["run"]["run_id"],
    ]
    assert all(
        Path(receipt["receipt_location"]).is_file()
        for receipt in (
            first["stored_result"],
            second["stored_result"],
            failed["stored_result"],
        )
    )
    assert Path(first["report_path"]).is_file()
    assert (
        first["stored_result"]["run"]["content_hash"]
        == first["run"]["run_content_hash"]
    )
    assert (
        first["stored_result"]["manifest"]["content_hash"]
        == first["manifest"]["manifest_content_hash"]
    )
    assert (
        first["stored_result"]["evidence"]["content_hash"]
        == first["evidence"]["evidence_content_hash"]
    )

    fact_before = store.get_v2_run(first["run"]["run_id"])
    report_before = Path(first["report_path"]).read_bytes()
    assert fact_before == store.get_v2_run(first["run"]["run_id"])
    assert report_before == Path(first["report_path"]).read_bytes()

    with pytest.raises(FileExistsError, match="already stored"):
        store.save_v2(first["output_dir"])
    assert store.get_v2_run(first["run"]["run_id"]) == fact_before

    report_record = store.get_v2_report(first["run"]["run_id"])
    assert report_record is not None
    assert report_record["report_location"] == str(Path(first["report_path"]).resolve())
    assert report_record["evidence_id"] == first["evidence"]["evidence_id"]
    assert report_record["evidence_content_hash"] == first["evidence"]["evidence_content_hash"]


def test_v2_store_holds_independent_snapshot_immune_to_source_tampering(
    materials: Path, tmp_path: Path
) -> None:
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge(result_store=store)
    result = bridge.execute_from_materials(materials, tmp_path / "run-src")

    run_id = result["run"]["run_id"]
    stored_before = store.get_v2_run(run_id)
    assert stored_before is not None

    snapshot_dir = Path(stored_before["bundle_location"])
    assert snapshot_dir.is_dir()
    assert snapshot_dir != result["output_dir"]

    # Completely remove the source run directory
    shutil.rmtree(result["output_dir"])
    assert not result["output_dir"].exists()

    # The store must still cleanly verify and read all facts
    stored_after = store.get_v2_run(run_id)
    assert stored_after == stored_before

    facts = store.load_v2_bundle_facts(run_id)
    assert facts["run"]["run_id"] == run_id
    assert facts["spec"]["spec_id"] == result["run"]["spec_id"]
    assert facts["manifest"]["manifest_id"] == result["manifest"]["manifest_id"]
    assert facts["evidence"]["evidence_id"] == result["evidence"]["evidence_id"]


def test_v2_store_rejects_damaged_bundle_without_creating_a_record(
    materials: Path, tmp_path: Path
) -> None:
    bridge = V2ExecutionBridge()
    result = bridge.execute_from_materials(materials, tmp_path / "run")

    payload = next((tmp_path / "run").glob("payload/*.json"))
    payload.write_bytes(payload.read_bytes() + b"\n")

    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    with pytest.raises(ValueError, match="payload bytes mismatch"):
        store.save_v2(result["output_dir"])

    assert store.get_v2_run(result["run"]["run_id"]) is None
    bundle_target = store.config.artifacts_dir / "v2" / "bundles" / result["run"]["run_id"]
    assert not bundle_target.exists()


def test_v2_store_fail_closed_on_corrupted_snapshot_or_receipt(
    materials: Path, tmp_path: Path
) -> None:
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge(result_store=store)
    result = bridge.execute_from_materials(materials, tmp_path / "run-normal")
    run_id = result["run"]["run_id"]

    receipt = store.get_v2_run(run_id)
    assert receipt is not None
    snapshot_dir = Path(receipt["bundle_location"])

    # Corrupt a payload file inside the snapshot
    target_payload = next(snapshot_dir.glob("payload/*.json"))
    original_bytes = target_payload.read_bytes()
    target_payload.write_bytes(original_bytes + b"\n")

    with pytest.raises(ValueError, match="Stored bundle file sha256 mismatch"):
        store.get_v2_run(run_id)

    with pytest.raises(ValueError, match="Stored bundle file sha256 mismatch"):
        store.query_v2_runs(run_id=run_id)

    # Restore payload and corrupt receipt
    target_payload.write_bytes(original_bytes)
    assert store.get_v2_run(run_id) is not None

    receipt_file = Path(receipt["receipt_location"])
    tampered_receipt = dict(receipt)
    tampered_receipt["run_status"] = "TAMPERED"
    clean_tampered = {k: v for k, v in tampered_receipt.items() if k != "receipt_location"}
    receipt_file.write_text(v2.canonical(clean_tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="Stored receipt content mismatch"):
        store.get_v2_run(run_id)


def test_v2_store_exact_reference_queries(
    materials: Path, tmp_path: Path
) -> None:
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge(result_store=store)
    first = bridge.execute_from_materials(materials, tmp_path / "run-q1")
    second = bridge.execute_from_materials(materials, tmp_path / "run-q2")
    assert first["run"]["run_id"] != second["run"]["run_id"]

    run_1_id = first["run"]["run_id"]
    run_1_hash = first["run"]["run_content_hash"]
    spec_id = first["run"]["spec_id"]
    spec_rev = first["run"]["spec_revision"]
    spec_hash = first["run"]["spec_content_hash"]
    task_id = first["stored_result"]["task"]["object_id"]
    task_rev = first["stored_result"]["task"]["revision"]
    task_hash = first["stored_result"]["task"]["content_hash"]

    # Match exact triad for Task
    q_task = store.query_v2_runs(
        task_id=task_id, task_revision=task_rev, task_content_hash=task_hash
    )
    assert len(q_task) == 2

    # Match exact triad for Spec
    q_spec = store.query_v2_runs(
        spec_id=spec_id, spec_revision=spec_rev, spec_content_hash=spec_hash
    )
    assert len(q_spec) == 2

    # Match exact run_id + run_content_hash
    q_run = store.query_v2_runs(run_id=run_1_id, run_content_hash=run_1_hash)
    assert len(q_run) == 1
    assert q_run[0]["run"]["object_id"] == run_1_id

    # Non-matching queries return empty
    assert len(store.query_v2_runs(spec_content_hash="nonexistent_hash")) == 0
    assert store.get_v2_run(run_1_id, run_content_hash="mismatched_hash") is None


def test_v2_admission_and_snapshot_integrity_for_input_lock(
    materials: Path, tmp_path: Path
) -> None:
    """Regression test for issue where modifying input-lock.json was bypassed."""
    bridge = V2ExecutionBridge()
    result = bridge.execute_from_materials(materials, tmp_path / "run-input-lock")
    out_dir = result["output_dir"]

    # 1. Tampering source input-lock.json before save_v2 must fail admission
    corrupted_dir = tmp_path / "run-corrupted-lock"
    shutil.copytree(out_dir, corrupted_dir)
    (corrupted_dir / "input-lock.json").write_text("{}", encoding="utf-8")

    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    with pytest.raises(ValueError, match="input-lock.json sha256 mismatch"):
        store.save_v2(corrupted_dir)
    assert store.get_v2_run(result["run"]["run_id"]) is None

    # 2. Legitimate save succeeds
    receipt = store.save_v2(out_dir)
    run_id = receipt["run"]["object_id"]
    snapshot_dir = Path(receipt["bundle_location"])

    # 3. Tampering snapshot input-lock.json after save must fail-closed on get_v2_run
    (snapshot_dir / "input-lock.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Stored bundle file sha256 mismatch for input-lock.json"):
        store.get_v2_run(run_id)


@pytest.mark.parametrize(
    "missing_file",
    [
        "materials/input.csv",
        "materials/preparation.json",
        "materials/provenance.json",
        "materials/method.json",
        "materials/criteria.json",
        "materials/case.py",
        "materials/quality.py",
        "input-lock.json",
    ],
)
def test_v2_save_rejects_missing_essential_materials_and_preserves_existing_runs(
    materials: Path, tmp_path: Path, missing_file: str
) -> None:
    """Deleting essential prepared materials before save_v2 must fail admission and preserve existing runs."""
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge(result_store=store)

    # 1. Save an existing legitimate run first
    first_run = bridge.execute_from_materials(materials, tmp_path / "run-existing")
    first_run_id = first_run["run"]["run_id"]
    assert store.get_v2_run(first_run_id) is not None

    # 2. Execute a second run to an output directory
    raw_bridge = V2ExecutionBridge()
    second_exec = raw_bridge.execute_from_materials(materials, tmp_path / "run-to-tamper")
    second_run_id = second_exec["run"]["run_id"]
    tamper_dir = tmp_path / "tampered-dir"
    shutil.copytree(second_exec["output_dir"], tamper_dir)

    # Remove the targeted essential material
    target_path = tamper_dir / missing_file
    target_path.unlink()

    # save_v2 must fail closed and refuse to create row/snapshot
    with pytest.raises((ValueError, FileNotFoundError)):
        store.save_v2(tamper_dir)

    # Verification: second run must NOT be stored
    assert store.get_v2_run(second_run_id) is None
    assert store.query_v2_runs(run_id=second_run_id) == []
    with store._connect() as conn:
        assert conn.execute("SELECT 1 FROM v2_result_runs WHERE run_id = ?", (second_run_id,)).fetchone() is None
        assert conn.execute("SELECT COUNT(*) FROM v2_result_runs").fetchone()[0] == 1

    snapshot_target = store.config.artifacts_dir / "v2" / "bundles" / second_run_id
    assert not snapshot_target.exists()
    assert list((store.config.artifacts_dir / "v2" / "bundles").iterdir()) == [
        store.config.artifacts_dir / "v2" / "bundles" / first_run_id
    ]

    # Verification: first run must be fully preserved and verifiable
    preserved = store.get_v2_run(first_run_id)
    assert preserved is not None
    assert preserved["run"]["object_id"] == first_run_id


@pytest.mark.parametrize(
    "missing_target",
    [
        "materials/input.csv",
        "materials/preparation.json",
    ],
)
def test_v2_save_rejects_missing_input_csv_or_preparation_json_without_leaving_index_or_snapshot(
    materials: Path, tmp_path: Path, missing_target: str
) -> None:
    """Missing input.csv or preparation.json must be rejected by save_v2 leaving no DB index or snapshot."""
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    raw_bridge = V2ExecutionBridge()
    execution = raw_bridge.execute_from_materials(materials, tmp_path / "run-src")
    run_id = execution["run"]["run_id"]
    output_dir = Path(execution["output_dir"])

    target_file = output_dir / missing_target
    assert target_file.is_file()
    target_file.unlink()

    with pytest.raises((ValueError, FileNotFoundError)):
        store.save_v2(output_dir)

    # 1. No success index in database
    assert store.get_v2_run(run_id) is None
    assert store.query_v2_runs(run_id=run_id) == []
    with store._connect() as conn:
        assert conn.execute("SELECT 1 FROM v2_result_runs WHERE run_id = ?", (run_id,)).fetchone() is None
        assert conn.execute("SELECT COUNT(*) FROM v2_result_runs").fetchone()[0] == 0

    # 2. No snapshot directory created
    bundles_dir = store.config.artifacts_dir / "v2" / "bundles"
    assert not (bundles_dir / run_id).exists()
    if bundles_dir.exists():
        assert list(bundles_dir.iterdir()) == []


def test_v2_snapshot_inventory_detects_extra_and_missing_files(
    materials: Path, tmp_path: Path
) -> None:
    """Store inventory must reject both unrecorded extra files and missing recorded files."""
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge(result_store=store)
    result = bridge.execute_from_materials(materials, tmp_path / "run-inventory")
    run_id = result["run"]["run_id"]

    receipt = store.get_v2_run(run_id)
    assert receipt is not None
    snapshot_dir = Path(receipt["bundle_location"])

    # 1. Adding an unrecorded extra file into snapshot must fail verification
    extra_file = snapshot_dir / "extra.json"
    extra_file.write_text('{"unauthorized": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="Stored bundle contains unrecorded extra files"):
        store.get_v2_run(run_id)

    extra_file.unlink()
    assert store.get_v2_run(run_id) is not None

    # 2. Removing a recorded file must fail verification with FileNotFoundError
    evidence_file = snapshot_dir / "evidence.json"
    evidence_content = evidence_file.read_bytes()
    evidence_file.unlink()
    with pytest.raises(FileNotFoundError, match="Stored bundle missing recorded inventory files"):
        store.get_v2_run(run_id)

    evidence_file.write_bytes(evidence_content)
    assert store.get_v2_run(run_id) is not None


def test_v2_report_exact_content_binding_and_store_owned_copy(
    materials: Path, tmp_path: Path
) -> None:
    """Regression test for Report deterministic verification, status/revision tampering and store persistence."""
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge()
    exec_result = bridge.execute_from_materials(materials, tmp_path / "run-rep")
    receipt = store.save_v2(exec_result["output_dir"])
    run_id = receipt["run"]["object_id"]

    # 1. Valid report content
    valid_report_text = render_v2_report(receipt)

    # 2. Tampering status from COMPLETED to FAILED must be rejected by save_v2_report
    tampered_status_text = valid_report_text.replace("- Status: COMPLETED", "- Status: FAILED")
    tampered_status_path = tmp_path / "tampered_status.report.md"
    tampered_status_path.write_text(tampered_status_text, encoding="utf-8")
    with pytest.raises(ValueError, match="Report content does not match expected deterministic report"):
        store.save_v2_report(receipt, tampered_status_path)

    # 3. Tampering Task revision must be rejected by save_v2_report
    tampered_rev_text = valid_report_text.replace("rev.1", "rev.2")
    tampered_rev_path = tmp_path / "tampered_rev.report.md"
    tampered_rev_path.write_text(tampered_rev_text, encoding="utf-8")
    with pytest.raises(ValueError, match="Report content does not match expected deterministic report"):
        store.save_v2_report(receipt, tampered_rev_path)

    # 4. Save external legitimate report and then delete the external file
    external_dir = tmp_path / "external_temp"
    external_dir.mkdir()
    external_report_path = external_dir / "external.report.md"
    external_report_path.write_text(valid_report_text, encoding="utf-8")

    report_record = store.save_v2_report(receipt, external_report_path)
    assert report_record["run_id"] == run_id
    stored_report_location = Path(report_record["report_location"])
    assert stored_report_location.is_file()
    assert stored_report_location != external_report_path

    # Delete external source report
    shutil.rmtree(external_dir)
    assert not external_report_path.exists()

    # Store-owned copy must survive and cleanly verify
    retrieved = store.get_v2_report(run_id)
    assert retrieved is not None
    assert retrieved["report_location"] == str(stored_report_location)
    assert Path(retrieved["report_location"]).is_file()

    # Tampering stored report on disk must fail-closed on get_v2_report
    stored_report_location.write_text("corrupted content\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Report content sha256 mismatch"):
        store.get_v2_report(run_id)


@pytest.mark.parametrize(
    "corrupt_column,bad_value",
    [
        ("task_id", "wrong-task"),
        ("task_revision", "rev.999"),
        ("task_content_hash", "0" * 64),
        ("spec_id", "wrong-spec"),
        ("spec_revision", "rev.999"),
        ("spec_content_hash", "0" * 64),
        ("run_content_hash", "0" * 64),
        ("manifest_id", "wrong-manifest"),
        ("manifest_revision", "rev.999"),
        ("manifest_content_hash", "0" * 64),
        ("evidence_id", "wrong-evidence"),
        ("evidence_content_hash", "0" * 64),
        ("run_status", "CORRUPTED_STATUS"),
        ("bundle_location", "/nonexistent/bundle/path"),
    ],
)
def test_v2_store_rejects_sql_index_corruption(
    materials: Path, tmp_path: Path, corrupt_column: str, bad_value: str
) -> None:
    """When SQL index columns are corrupted, get_v2_run and query_v2_runs must fail-closed."""
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    bridge = V2ExecutionBridge(result_store=store)
    result = bridge.execute_from_materials(materials, tmp_path / "run-sql-corrupt")
    run_id = result["run"]["run_id"]

    # Simulate database column index corruption
    db_path = store.config.database_path
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            f"UPDATE v2_result_runs SET {corrupt_column} = ? WHERE run_id = ?",  # noqa: S608
            (bad_value, run_id),
        )

    # get_v2_run must detect index corruption and fail-closed
    with pytest.raises(ValueError, match=f"Index corruption detected: column {corrupt_column}"):
        store.get_v2_run(run_id)

    # query_v2_runs searching by the corrupted value must also fail-closed and not return invalid fact
    kwargs = {corrupt_column: bad_value} if corrupt_column in ("task_id", "spec_id", "run_status") else {}
    with pytest.raises(ValueError, match=f"Index corruption detected: column {corrupt_column}"):
        store.query_v2_runs(**kwargs)


def _reseal_bundle_with_run_id(bundle_dir: Path, new_run_id: str) -> None:
    """Tamper run_id in a valid bundle and reseal all signatures to pass frozen validators."""
    run_path = bundle_dir / "run.json"
    run_obj = v2.parse(run_path.read_bytes())
    run_obj["run_id"] = new_run_id
    run_content = {k: v for k, v in run_obj.items() if k != "run_content_hash"}
    run_obj["run_content_hash"] = v2.digest(run_content)
    run_path.write_text(v2.canonical(run_obj), encoding="utf-8")

    manifest_path = bundle_dir / "manifest.json"
    manifest_obj = v2.parse(manifest_path.read_bytes())
    manifest_obj["run_id"] = new_run_id
    manifest_obj["run_content_hash"] = run_obj["run_content_hash"]
    manifest_content = {k: v for k, v in manifest_obj.items() if k != "manifest_content_hash"}
    manifest_obj["manifest_content_hash"] = v2.digest(manifest_content)
    manifest_path.write_text(v2.canonical(manifest_obj), encoding="utf-8")

    evidence_path = bundle_dir / "evidence.json"
    evidence_obj = v2.parse(evidence_path.read_bytes())
    evidence_obj["run_id"] = new_run_id
    evidence_obj["run_content_hash"] = run_obj["run_content_hash"]
    evidence_obj["manifest_id"] = manifest_obj["manifest_id"]
    evidence_obj["manifest_content_hash"] = manifest_obj["manifest_content_hash"]
    for art in evidence_obj.get("supporting_artifacts", []):
        art["manifest_id"] = manifest_obj["manifest_id"]
        art["manifest_content_hash"] = manifest_obj["manifest_content_hash"]
    evidence_content = {k: v for k, v in evidence_obj.items() if k != "evidence_content_hash"}
    evidence_obj["evidence_content_hash"] = v2.digest(evidence_content)
    evidence_path.write_text(v2.canonical(evidence_obj), encoding="utf-8")

    req_path = bundle_dir / "review-request.json"
    if req_path.exists():
        req_obj = v2.parse(req_path.read_bytes())
        ctx = req_obj.get("context_refs", {})
        if "experiment_run" in ctx:
            ctx["experiment_run"]["object_id"] = new_run_id
            ctx["experiment_run"]["content_hash"] = run_obj["run_content_hash"]
        if "artifact_manifest" in ctx:
            ctx["artifact_manifest"]["content_hash"] = manifest_obj["manifest_content_hash"]
        if "result_evidence" in ctx:
            ctx["result_evidence"]["content_hash"] = evidence_obj["evidence_content_hash"]
        if "artifact_requirements" in ctx:
            for art in ctx["artifact_requirements"].get("exact_refs", []):
                art["manifest_id"] = manifest_obj["manifest_id"]
                art["manifest_content_hash"] = manifest_obj["manifest_content_hash"]
        req_path.write_text(v2.canonical(req_obj), encoding="utf-8")


def test_v2_storage_and_reports_reject_path_traversal_run_id(
    materials: Path, tmp_path: Path
) -> None:
    """Run with path traversal run_id passing frozen validator must be rejected with no escaped files."""
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    raw_bridge = V2ExecutionBridge()
    exec_res = raw_bridge.execute_from_materials(materials, tmp_path / "run-clean")
    clean_dir = Path(exec_res["output_dir"])

    traversal_dir = tmp_path / "run-traversal"
    shutil.copytree(clean_dir, traversal_dir)
    escaped_run_id = "../../escaped-run"
    _reseal_bundle_with_run_id(traversal_dir, escaped_run_id)

    # 1. Verify that resealed bundle satisfies the frozen manifest validator
    manifest_obj = v2.parse((traversal_dir / "manifest.json").read_bytes())
    run_obj = v2.parse((traversal_dir / "run.json").read_bytes())
    task_obj = v2.parse((traversal_dir / "materials/task.json").read_bytes())
    spec_obj = v2.parse((traversal_dir / "materials/spec.json").read_bytes())
    v2.validate_manifest(traversal_dir, manifest_obj, run_obj, task=task_obj, spec=spec_obj)

    # 2. save_v2 must fail-closed on storage boundary
    with pytest.raises(ValueError, match="Path separators forbidden in run_id"):
        store.save_v2(traversal_dir)

    # 3. Verify no escaped snapshot files exist outside or inside bundles directory
    assert not (store.config.artifacts_dir / "escaped-run").exists()
    bundles_root = store.config.artifacts_dir / "v2" / "bundles"
    assert not (bundles_root / "escaped-run").exists()
    assert not (bundles_root / escaped_run_id).resolve().exists()
    if bundles_root.exists():
        assert list(bundles_root.iterdir()) == []

    # 4. Verify no records in database
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM v2_result_runs").fetchone()[0] == 0

    # 5. Queries must fail-closed on path traversal run_id
    with pytest.raises(ValueError, match="Path separators forbidden in run_id"):
        store.get_v2_run(escaped_run_id)
    with pytest.raises(ValueError, match="Path separators forbidden in run_id"):
        store.query_v2_runs(run_id=escaped_run_id)
    with pytest.raises(ValueError, match="Path separators forbidden in run_id"):
        store.get_v2_report(escaped_run_id)

    # 6. Report write and save entrances must fail-closed
    fake_receipt = {
        "run": {"object_id": escaped_run_id, "content_hash": run_obj["run_content_hash"]},
        "task": {"object_id": "t", "revision": "r1", "content_hash": "h1"},
        "spec": {"object_id": "s", "revision": "r1", "content_hash": "h2"},
        "manifest": {"object_id": "m", "revision": "r1", "content_hash": "h3"},
        "evidence": {"object_id": "e", "content_hash": "h4"},
        "run_status": "COMPLETED",
    }
    with pytest.raises(ValueError, match="Path separators forbidden in run_id"):
        write_v2_report(store.config.artifacts_dir, fake_receipt)
    assert not (store.config.artifacts_dir / "escaped-run.report.md").exists()

    dummy_report = tmp_path / "dummy.report.md"
    dummy_report.write_text("test report", encoding="utf-8")
    with pytest.raises(ValueError, match="Path separators forbidden in run_id"):
        store.save_v2_report(fake_receipt, dummy_report)


@pytest.mark.parametrize(
    "bad_run_id",
    [
        "..",
        ".",
        "../escaped",
        "nested/run1",
        "nested\\run2",
        "/absolute/run",
        "run\x00corrupt",
    ],
)
def test_v2_storage_rejects_various_path_traversal_patterns(
    tmp_path: Path, bad_run_id: str
) -> None:
    """Store endpoints must reject relative, absolute, separated, or null-containing run_ids."""
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    with pytest.raises(ValueError):
        store.get_v2_run(bad_run_id)
    with pytest.raises(ValueError):
        store.query_v2_runs(run_id=bad_run_id)
    with pytest.raises(ValueError):
        store.get_v2_report(bad_run_id)
