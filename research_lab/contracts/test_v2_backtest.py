"""Focused Protocol v2 single-contract trading_backtest execution & result-loop contract tests (#556).

Enforces end-to-end integration:
Task + Spec -> S1-S7 v2 Admission -> Physical Snapshot Byte & Hash Binding ->
DeterministicBacktestAdapter -> Run/Manifest/Evidence ->
append-only ResultStore -> Human-readable Report -> Independent Snapshot Re-consumption.
"""

from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest

from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.contracts.single_contract_definition import (
    PROFILE_NAME,
    SYNTHETIC_FIXTURE_BYTES,
    SYNTHETIC_FIXTURE_PATH,
    SYNTHETIC_FIXTURE_SHA256,
)
from research_lab.database import ResultStore
from research_lab.runners.v2_backtest import (
    execute_v2_backtest_from_materials,
    execute_v2_backtest_spec,
)


def _seal(obj: dict, prefix: str) -> None:
    key = prefix + "_content_hash"
    obj[key] = v2.digest({k: v for k, v in obj.items() if k != key})


@pytest.fixture
def single_contract_bundle() -> tuple[dict, dict]:
    """Provide a validated Task and Spec conforming to research_lab.single_contract_backtest.v1."""
    task = {
        "schema_version": "research_lab.task.v2",
        "hash_profile": "research-json-v1",
        "task_id": "task-sc-rb-001",
        "revision": "rev.1",
        "research_type": "trading_backtest",
        "task_profile": PROFILE_NAME,
        "objective": "Single contract deterministic trading backtest validation",
        "data_requirements": {
            "product": "rb",
            "exact_contract": "rb2405",
            "time_range": {
                "start": "2024-01-02T09:00:00.000000Z",
                "end": "2024-01-02T09:05:00.000000Z",
            },
            "snapshot_sha256": SYNTHETIC_FIXTURE_SHA256,
            "snapshot_locator": SYNTHETIC_FIXTURE_PATH,
            "provenance": "synthetic_physical_fixture_rb2405",
        },
    }
    _seal(task, "task")

    spec = {
        "schema_version": "research_lab.experiment.v2",
        "hash_profile": "research-json-v1",
        "spec_id": "spec-sc-rb-001",
        "revision": "rev.1",
        "task_id": task["task_id"],
        "task_revision": task["revision"],
        "task_content_hash": task["task_content_hash"],
        "experiment_type": "trading_backtest",
        "research_stage": "validation",
        "backtest_profile": PROFILE_NAME,
        "dataset_requirements": {
            "product": "rb",
            "exact_contract": "rb2405",
            "time_range": {
                "start": "2024-01-02T09:00:00.000000Z",
                "end": "2024-01-02T09:05:00.000000Z",
            },
            "snapshot_sha256": SYNTHETIC_FIXTURE_SHA256,
            "snapshot_locator": SYNTHETIC_FIXTURE_PATH,
            "provenance": "synthetic_physical_fixture_rb2405",
        },
        "contract_specifications": {
            "target_symbol": "rb2405",
            "multiplier": "10",
            "price_tick": "1",
            "price_currency": "CNY",
            "margin_ratio": "0.1",
        },
        "strategy_spec": {
            "strategy_name": "buy_and_hold",
            "implementation_ref": "strategies/buy_and_hold.py",
            "parameters": {},
        },
        "execution_config": {
            "initial_capital": "100000",
            "capital_currency": "CNY",
            "position_sizing": {"mode": "fixed_lots", "lots": 1},
        },
        "cost_model": {
            "commission_bps": "1",
            "slippage_ticks": 1,
            "currency": "CNY",
        },
        "holdout_policy": "not_used",
    }
    _seal(spec, "spec")
    return task, spec


def test_1_completed_e2e_with_result_store_and_report(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate full positive E2E execution: physical snapshot bytes -> real adapter -> store & report."""
    task, spec = single_contract_bundle
    output_dir = tmp_path / "backtest_run_completed"
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))

    res = execute_v2_backtest_spec(task, spec, output_dir, result_store=store)

    # 1. Execution status & exit code
    assert res["run_status"] == "COMPLETED"
    assert res["process_exit_code"] == 0
    assert res["output_dir"] == output_dir

    # 2. Run record
    run = res["run"]
    assert run["run_status"] == "COMPLETED"
    assert run["process_exit_code"] == 0
    assert run["spec_id"] == spec["spec_id"]
    computation = run["resolved_computation_manifest"]
    assert computation["profile"] == PROFILE_NAME
    assert computation["product"] == "rb"
    assert computation["exact_contract"] == "rb2405"
    assert computation["snapshot_byte_length"] == SYNTHETIC_FIXTURE_BYTES
    assert computation["snapshot_sha256"] == SYNTHETIC_FIXTURE_SHA256
    assert computation["stop_reason"] == "COMPLETED_END_OF_DATA"

    # 3. Artifact Manifest
    manifest = res["manifest"]
    assert manifest["experiment_type"] == "trading_backtest"
    assert manifest["run_id"] == run["run_id"]
    entry_roles = {e["role"] for e in manifest["entries"]}
    expected_roles = {
        "dataset_metadata",
        "method_definition",
        "environment_lock",
        "replay_instructions",
        "backtest_summary",
        "trade_blotter",
        "equity_curve",
    }
    assert expected_roles == entry_roles
    assert all(e["availability"] == "present" for e in manifest["entries"])

    # 4. Result Evidence
    evidence = res["evidence"]
    assert evidence["run_id"] == run["run_id"]
    assert evidence["run_status_snapshot"] == "COMPLETED"
    assert evidence["execution_status"] == "COMPLETED"
    assert evidence["missing_reason"] is None
    typed = evidence["typed_metrics"]
    assert typed["profile"] == PROFILE_NAME
    assert typed["product"] == "rb"
    assert typed["exact_contract"] == "rb2405"
    assert typed["trade_count"] >= 1
    assert float(typed["total_fees"]) > 0

    # 5. Underlying factual payload files (verify no 23 account padding)
    summary = v2.parse((output_dir / "backtest_summary.json").read_bytes())
    blotter = v2.parse((output_dir / "trade_blotter.json").read_bytes())
    curve = v2.parse((output_dir / "equity_curve.json").read_bytes())
    metadata = v2.parse((output_dir / "dataset_metadata.json").read_bytes())

    assert (output_dir / "materials" / "snapshot.csv").is_file()
    assert metadata["snapshot_locator"] == "materials/snapshot.csv"
    assert metadata["snapshot_sha256"] == SYNTHETIC_FIXTURE_SHA256
    assert metadata["snapshot_byte_length"] == SYNTHETIC_FIXTURE_BYTES

    assert "accounts" not in summary and "accounts" not in blotter and "accounts" not in curve
    assert summary["product"] == "rb" and summary["exact_contract"] == "rb2405"
    assert blotter["product"] == "rb" and blotter["exact_contract"] == "rb2405"
    assert curve["product"] == "rb" and curve["exact_contract"] == "rb2405"

    assert len(blotter["trades"]) == typed["trade_count"]
    assert summary["net_pnl"] == typed["net_pnl"]
    assert summary["total_fees"] == typed["total_fees"]
    assert summary["total_trades"] == typed["trade_count"]

    # Verify timestamps order in equity curve
    pts_times = [p["timestamp"] for p in curve["points"]]
    assert pts_times == sorted(pts_times)
    assert len(curve["points"]) == 5

    # 6. ResultStore persistence
    stored = res["stored_result"]
    assert stored is not None
    assert stored["run_status"] == "COMPLETED"
    assert Path(stored["bundle_location"]).is_dir()
    assert Path(stored["receipt_location"]).is_file()

    # 7. Report linkage & content
    report_path = res["report_path"]
    assert report_path is not None
    assert report_path.is_file()
    report_text = report_path.read_text(encoding="utf-8")
    assert run["run_id"] in report_text
    assert spec["spec_id"] in report_text
    assert "COMPLETED" in report_text
    assert "rb2405" in report_text
    assert typed["net_pnl"] in report_text

    # 8. Querying via ResultStore
    queried_runs = store.query_v2_runs(spec_id=spec["spec_id"])
    assert len(queried_runs) == 1
    assert queried_runs[0]["run"]["object_id"] == run["run_id"]

    report_rec = store.get_v2_report(run["run_id"])
    assert report_rec["run_id"] == run["run_id"]
    assert report_rec["report_location"] == str(report_path)


def test_2_failed_e2e_saved_to_result_store(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that FAILED status generates diagnostics, null metrics, and is saved append-only in ResultStore."""
    task, spec = single_contract_bundle
    output_dir = tmp_path / "backtest_run_failed"
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))

    res = execute_v2_backtest_spec(task, spec, output_dir, result_store=store, force_failure=True)

    # 1. Execution status
    assert res["run_status"] == "FAILED"
    assert res["process_exit_code"] == 1

    # 2. Run record
    run = res["run"]
    assert run["run_status"] == "FAILED"
    assert run["process_exit_code"] == 1
    assert run["resolved_computation_manifest"]["stop_reason"] == "FAILED_RUNTIME_ERROR"

    # 3. Manifest record (contains failure_diagnostics and unavailable required payloads)
    manifest = res["manifest"]
    roles = {e["role"]: e for e in manifest["entries"]}
    assert "failure_diagnostics" in roles
    assert roles["failure_diagnostics"]["availability"] == "present"
    assert roles["backtest_summary"]["availability"] == "unavailable"
    assert roles["trade_blotter"]["availability"] == "unavailable"
    assert roles["equity_curve"]["availability"] == "unavailable"

    # 4. Evidence record
    evidence = res["evidence"]
    assert evidence["execution_status"] == "FAILED"
    assert evidence["run_status_snapshot"] == "FAILED"
    assert evidence["typed_metrics"] is None
    assert evidence["missing_reason"] == "execution_failed"

    # 5. Failure diagnostics payload
    diag_file = output_dir / "failure_diagnostics.json"
    assert diag_file.is_file()
    diag = v2.parse(diag_file.read_bytes())
    assert diag["profile"] == PROFILE_NAME
    assert diag["error_type"] == "RuntimeError"
    assert "Forced simulation failure" in diag["error_message"]
    assert diag["process_exit_code"] == 1

    # 6. ResultStore persistence of FAILED run
    stored = res["stored_result"]
    assert stored is not None
    assert stored["run_status"] == "FAILED"

    # 7. Derived report shows failure status and no fabricated metrics
    report_path = res["report_path"]
    assert report_path is not None
    assert report_path.is_file()
    report_text = report_path.read_text(encoding="utf-8")
    assert "FAILED" in report_text
    assert "execution_failed" in report_text
    assert "Net PnL" not in report_text

    # 8. Query via store
    queried = store.query_v2_runs(spec_id=spec["spec_id"])
    assert len(queried) == 1
    assert queried[0]["run_status"] == "FAILED"


def test_3_same_spec_rerun_fingerprint_consistency(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate rerun isolation: same Spec produces distinct run_ids with deterministic fingerprint."""
    task, spec = single_contract_bundle
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))

    res1 = execute_v2_backtest_spec(task, spec, tmp_path / "run_1", result_store=store)
    res2 = execute_v2_backtest_spec(task, spec, tmp_path / "run_2", result_store=store)

    run1 = res1["run"]
    run2 = res2["run"]

    assert run1["run_id"] != run2["run_id"]
    assert run1["scientific_fingerprint"] == run2["scientific_fingerprint"]
    assert res1["stored_result"]["bundle_location"] != res2["stored_result"]["bundle_location"]

    runs = store.query_v2_runs(spec_id=spec["spec_id"])
    assert len(runs) == 2
    assert {r["run"]["object_id"] for r in runs} == {run1["run_id"], run2["run_id"]}


def test_4_same_spec_completed_and_failed_coexist_in_result_store(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that both COMPLETED and FAILED runs for the same Spec coexist in ResultStore."""
    task, spec = single_contract_bundle
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))

    res_ok = execute_v2_backtest_spec(task, spec, tmp_path / "run_ok", result_store=store)
    res_fail = execute_v2_backtest_spec(
        task, spec, tmp_path / "run_fail", result_store=store, force_failure=True
    )

    runs = store.query_v2_runs(spec_id=spec["spec_id"])
    assert len(runs) == 2
    statuses = {r["run_status"] for r in runs}
    assert statuses == {"COMPLETED", "FAILED"}

    ok_run = store.get_v2_run(res_ok["run"]["run_id"])
    fail_run = store.get_v2_run(res_fail["run"]["run_id"])
    assert ok_run["run_status"] == "COMPLETED"
    assert fail_run["run_status"] == "FAILED"


def test_5_physical_snapshot_tamper_1byte_rejected(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Verify that tampering physical snapshot bytes by even 1 byte is rejected at pre-execution admission."""
    task, spec = single_contract_bundle

    # Create a 1-byte tampered copy of the synthetic fixture
    fixture_path = v2.ROOT / SYNTHETIC_FIXTURE_PATH
    tampered_csv = tmp_path / "tampered.csv"
    raw_bytes = fixture_path.read_bytes()
    # Flip one byte
    tampered_bytes = raw_bytes[:-1] + (b"X" if raw_bytes[-1:] != b"X" else b"Y")
    tampered_csv.write_bytes(tampered_bytes)

    spec_tampered = copy.deepcopy(spec)
    spec_tampered["dataset_requirements"]["snapshot_locator"] = str(tampered_csv)
    # But keep expected snapshot_sha256 unchanged to trigger admission fail-closed
    _seal(spec_tampered, "spec")

    task_tampered = copy.deepcopy(task)
    task_tampered["data_requirements"]["snapshot_locator"] = str(tampered_csv)
    _seal(task_tampered, "task")

    with pytest.raises(ValueError, match="Physical snapshot sha256 mismatch"):
        execute_v2_backtest_spec(task_tampered, spec_tampered, tmp_path / "out_tampered")


def test_6_owned_snapshot_standalone_reconsumption(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Strict 8-step core regression: temporary physical snapshot -> execution -> delete external snapshot ->
    delete output dir -> only Store owned bundle remains -> load facts -> validate manifest -> CLI replay.

    Proves that captured snapshot in materials/snapshot.csv guarantees 100% self-contained replayability.
    """
    from research_lab.runners.v2_backtest import main

    task_base, spec_base = single_contract_bundle

    # Step 1: Create a temporary physical snapshot outside the repository
    temp_snapshot = tmp_path / "temp_external_snapshot.csv"
    orig_bytes = (v2.ROOT / SYNTHETIC_FIXTURE_PATH).read_bytes()
    temp_snapshot.write_bytes(orig_bytes)
    temp_sha = v2.sha(orig_bytes)

    task = copy.deepcopy(task_base)
    task["data_requirements"]["snapshot_locator"] = str(temp_snapshot)
    task["data_requirements"]["snapshot_sha256"] = temp_sha
    _seal(task, "task")

    spec = copy.deepcopy(spec_base)
    spec["task_content_hash"] = task["task_content_hash"]
    spec["dataset_requirements"]["snapshot_locator"] = str(temp_snapshot)
    spec["dataset_requirements"]["snapshot_sha256"] = temp_sha
    _seal(spec, "spec")

    # Step 2: Execute and persist to ResultStore
    output_dir = tmp_path / "original_output"
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))
    res = execute_v2_backtest_spec(task, spec, output_dir, result_store=store)

    run_id = res["run"]["run_id"]
    original_fingerprint = res["run"]["scientific_fingerprint"]
    original_summary = v2.parse((output_dir / "backtest_summary.json").read_bytes())
    original_blotter = v2.parse((output_dir / "trade_blotter.json").read_bytes())
    original_curve = v2.parse((output_dir / "equity_curve.json").read_bytes())
    store_bundle = Path(res["stored_result"]["bundle_location"])

    # Step 3: Delete the external physical snapshot file
    temp_snapshot.unlink()
    assert not temp_snapshot.exists()

    # Step 4: Delete the original execution output directory
    shutil.rmtree(output_dir)
    assert not output_dir.exists()

    # Step 5: Only ResultStore owned bundle remains
    assert store_bundle.is_dir()
    assert (store_bundle / "materials" / "snapshot.csv").is_file()

    # Step 6: load_v2_bundle_facts succeeds from Store owned bundle
    facts = store.load_v2_bundle_facts(run_id)
    assert facts["run"]["run_id"] == run_id
    assert facts["run"]["run_status"] == "COMPLETED"
    assert facts["run"]["scientific_fingerprint"] == original_fingerprint

    # Step 7: validate_manifest succeeds using ONLY the Store owned bundle
    manifest = facts["manifest"]
    run = facts["run"]
    v2.validate_manifest(store_bundle, manifest, run, task=task, spec=spec)

    # Step 8: CLI replay succeeds completely independently from store bundle materials
    replayed_out = tmp_path / "replayed_output"
    ret = main(["--materials", str(store_bundle / "materials"), "--output", str(replayed_out)])
    assert ret == 0

    replayed_run = v2.parse((replayed_out / "run.json").read_bytes())
    replayed_summary = v2.parse((replayed_out / "backtest_summary.json").read_bytes())
    replayed_blotter = v2.parse((replayed_out / "trade_blotter.json").read_bytes())
    replayed_curve = v2.parse((replayed_out / "equity_curve.json").read_bytes())

    # Verify replay produces identical scientific fingerprint, new run_id, and identical facts
    assert replayed_run["scientific_fingerprint"] == original_fingerprint
    assert replayed_run["run_id"] != run_id
    assert replayed_summary["net_pnl"] == original_summary["net_pnl"]
    assert replayed_summary["total_fees"] == original_summary["total_fees"]
    assert len(replayed_blotter["trades"]) == len(original_blotter["trades"])
    assert replayed_curve["points"][-1]["equity"] == original_curve["points"][-1]["equity"]


def test_7_s7_admission_fail_closed_on_invalid_parameters(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Verify S7 semantic admission constraints fail closed before starting execution."""
    task, spec = single_contract_bundle

    # 1. Non-positive initial capital
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["execution_config"]["initial_capital"] = "0"
    with pytest.raises(ValueError, match="S7 violation: initial_capital must be > 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_1")

    # 2. Currency mismatch
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["execution_config"]["capital_currency"] = "USD"
    with pytest.raises(ValueError, match="S7 violation: capital_currency must be CNY"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_2")

    # 3. Non-positive multiplier
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["contract_specifications"]["multiplier"] = "-10"
    with pytest.raises(ValueError, match="S7 violation: multiplier must be > 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_3")

    # 4. Out-of-bound margin ratio
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["contract_specifications"]["margin_ratio"] = "1.5"
    with pytest.raises(ValueError, match="S7 violation: margin_ratio must be in"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_4")

    # 5. Negative fee
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["cost_model"]["commission_bps"] = "-2.0"
    with pytest.raises(ValueError, match="S7 violation: commission_bps must be >= 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_5")

    # 6. Negative slippage
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["cost_model"]["slippage_ticks"] = -1
    with pytest.raises(ValueError, match="S7 violation: slippage_ticks must be >= 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_6")

    # 7. Invalid time range (start >= end)
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["dataset_requirements"]["time_range"] = {
        "start": "2025-01-01T00:00:00.000000Z",
        "end": "2023-01-01T00:00:00.000000Z",
    }
    with pytest.raises(ValueError, match="Invalid time range"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_7")

    # 8. Existing directory exclusivity
    existing_dir = tmp_path / "existing"
    existing_dir.mkdir(parents=True)
    with pytest.raises(FileExistsError, match="Target output directory already exists"):
        execute_v2_backtest_spec(task, spec, existing_dir)


def test_8_from_materials_success(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Verify loading and execution from a materials directory containing task.json and spec.json."""
    task, spec = single_contract_bundle
    materials_dir = tmp_path / "custom_materials"
    materials_dir.mkdir(parents=True)
    (materials_dir / "task.json").write_text(v2.canonical(task) + "\n", encoding="utf-8")
    (materials_dir / "spec.json").write_text(v2.canonical(spec) + "\n", encoding="utf-8")

    res = execute_v2_backtest_from_materials(materials_dir, tmp_path / "out_mat")
    assert res["run_status"] == "COMPLETED"
    assert (tmp_path / "out_mat" / "manifest.json").is_file()
    assert (tmp_path / "out_mat" / "backtest_summary.json").is_file()


def test_9_custom_physical_snapshot_dynamically_effective(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Verify that different physical snapshot bytes dynamically change factual returns and costs.

    Strictly satisfies P1-A: Zero override_prices bypass. Must consume real physical CSV files.
    """
    task_base, spec_base = single_contract_bundle

    # 1. Create two physical CSV files: one flat, one trending up
    flat_csv = tmp_path / "flat_snapshot.csv"
    up_csv = tmp_path / "up_snapshot.csv"

    header = "timestamp,symbol,open,high,low,close,volume,open_interest\n"
    flat_lines = [
        "2024-01-02T09:00:00.000000Z,rb2405,3900.0,3900.0,3900.0,3900.0,100,500\n",
        "2024-01-02T09:01:00.000000Z,rb2405,3900.0,3900.0,3900.0,3900.0,100,500\n",
        "2024-01-02T09:02:00.000000Z,rb2405,3900.0,3900.0,3900.0,3900.0,100,500\n",
        "2024-01-02T09:03:00.000000Z,rb2405,3900.0,3900.0,3900.0,3900.0,100,500\n",
        "2024-01-02T09:04:00.000000Z,rb2405,3900.0,3900.0,3900.0,3900.0,100,500\n",
    ]
    up_lines = [
        "2024-01-02T09:00:00.000000Z,rb2405,3900.0,3910.0,3890.0,3900.0,100,500\n",
        "2024-01-02T09:01:00.000000Z,rb2405,3900.0,4010.0,3900.0,4000.0,120,510\n",
        "2024-01-02T09:02:00.000000Z,rb2405,4000.0,4110.0,4000.0,4100.0,80,505\n",
        "2024-01-02T09:03:00.000000Z,rb2405,4100.0,4210.0,4100.0,4200.0,150,520\n",
        "2024-01-02T09:04:00.000000Z,rb2405,4200.0,4310.0,4200.0,4300.0,200,530\n",
    ]
    flat_bytes = (header + "".join(flat_lines)).encode("utf-8")
    up_bytes = (header + "".join(up_lines)).encode("utf-8")

    flat_csv.write_bytes(flat_bytes)
    up_csv.write_bytes(up_bytes)

    flat_sha = v2.sha(flat_bytes)
    up_sha = v2.sha(up_bytes)

    # 2. Build flat Task & Spec
    task_flat = copy.deepcopy(task_base)
    task_flat["data_requirements"]["snapshot_locator"] = str(flat_csv)
    task_flat["data_requirements"]["snapshot_sha256"] = flat_sha
    _seal(task_flat, "task")

    spec_flat = copy.deepcopy(spec_base)
    spec_flat["task_content_hash"] = task_flat["task_content_hash"]
    spec_flat["dataset_requirements"]["snapshot_locator"] = str(flat_csv)
    spec_flat["dataset_requirements"]["snapshot_sha256"] = flat_sha
    _seal(spec_flat, "spec")

    # 3. Build up Task & Spec
    task_up = copy.deepcopy(task_base)
    task_up["data_requirements"]["snapshot_locator"] = str(up_csv)
    task_up["data_requirements"]["snapshot_sha256"] = up_sha
    _seal(task_up, "task")

    spec_up = copy.deepcopy(spec_base)
    spec_up["task_content_hash"] = task_up["task_content_hash"]
    spec_up["dataset_requirements"]["snapshot_locator"] = str(up_csv)
    spec_up["dataset_requirements"]["snapshot_sha256"] = up_sha
    _seal(spec_up, "spec")

    # 4. Execute both via physical files
    res_flat = execute_v2_backtest_spec(task_flat, spec_flat, tmp_path / "flat_out")
    res_up = execute_v2_backtest_spec(task_up, spec_up, tmp_path / "up_out")

    metrics_flat = res_flat["evidence"]["typed_metrics"]
    metrics_up = res_up["evidence"]["typed_metrics"]

    assert float(metrics_up["net_pnl"]) > float(metrics_flat["net_pnl"])
    assert res_flat["run"]["resolved_computation_manifest"]["snapshot_sha256"] == flat_sha
    assert res_up["run"]["resolved_computation_manifest"]["snapshot_sha256"] == up_sha


def test_10_cost_multiplier_lot_slippage_accounting_reconciliation(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate numerical accounting reconciliation across blotter, summary, evidence, and adapter facts.

    Satisfies P1-B:
    - blotter trade fee sum == summary total_fees == evidence typed_metrics total_fees
    - ending_equity == initial_capital + floating_pnl - total_fees
    - net_pnl == ending_equity - initial_capital
    - non-zero multiplier, lot, slippage, and commission are reconciled down to the cent.
    """
    task_base, spec_base = single_contract_bundle

    # Configure non-zero parameters: lots=2, multiplier=10, price_tick=1, slippage_ticks=2, commission_bps=2
    task = copy.deepcopy(task_base)
    _seal(task, "task")

    spec = copy.deepcopy(spec_base)
    spec["task_content_hash"] = task["task_content_hash"]
    spec["contract_specifications"]["multiplier"] = "10"
    spec["contract_specifications"]["price_tick"] = "1"
    spec["execution_config"]["initial_capital"] = "100000"
    spec["execution_config"]["position_sizing"] = {"mode": "fixed_lots", "lots": 2}
    spec["cost_model"]["commission_bps"] = "2"  # 2 bps = 0.0002
    spec["cost_model"]["slippage_ticks"] = 2    # 2 ticks * 1 * 10 = 20 CNY per lot
    _seal(spec, "spec")

    output_dir = tmp_path / "reconciliation_out"
    res = execute_v2_backtest_spec(task, spec, output_dir)

    assert res["run_status"] == "COMPLETED"

    # Read factual payloads
    blotter = v2.parse((output_dir / "trade_blotter.json").read_bytes())
    summary = v2.parse((output_dir / "backtest_summary.json").read_bytes())
    curve = v2.parse((output_dir / "equity_curve.json").read_bytes())
    typed = res["evidence"]["typed_metrics"]

    # 1. Trade blotter vs summary vs evidence fee reconciliation
    blotter_trades = blotter["trades"]
    assert len(blotter_trades) == 1  # 1 buy trade for buy_and_hold
    t0 = blotter_trades[0]
    assert t0["side"] == "BUY"
    assert t0["volume"] == 2

    trade_p = float(t0["price"])  # 3910.0 (bar 1 price where position shifted 0 -> 2)
    turnover = trade_p * 10 * 2
    commission_fee = turnover * 0.0002
    slippage_cost = 2 * 1 * 10 * 2  # 40.0
    expected_trade_fee = commission_fee + slippage_cost

    actual_trade_fee = float(t0["fee"])
    assert round(actual_trade_fee, 4) == round(expected_trade_fee, 4)

    blotter_fee_sum = sum(float(t["fee"]) for t in blotter_trades)
    summary_fees = float(summary["total_fees"])
    evidence_fees = float(typed["total_fees"])

    assert round(blotter_fee_sum, 4) == round(summary_fees, 4)
    assert round(summary_fees, 4) == round(evidence_fees, 4)

    # 2. Equity curve and PnL reconciliation
    initial_cap = float(summary["initial_capital"])
    ending_eq = float(summary["ending_equity"])
    net_pnl = float(summary["net_pnl"])

    assert round(ending_eq, 4) == round(initial_cap + net_pnl, 4)
    assert round(float(curve["points"][-1]["equity"]), 4) == round(ending_eq, 4)

    # Floating PnL from bar 1 entry (3910.0) to bar 4 close (3945.0)
    last_price = 3945.0
    entry_price = trade_p
    floating_pnl = (last_price - entry_price) * 10 * 2
    expected_ending_equity = initial_cap + floating_pnl - actual_trade_fee

    assert round(ending_eq, 4) == round(expected_ending_equity, 4)
    assert round(net_pnl, 4) == round(floating_pnl - actual_trade_fee, 4)


def test_11_flat_market_net_pnl_equals_negative_cost(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that in a flat market, net PnL is exactly equal to negative transaction cost."""
    task_base, spec_base = single_contract_bundle

    # Create 5-bar flat CSV at 3900.0
    flat_csv = tmp_path / "flat.csv"
    header = "timestamp,symbol,open,high,low,close,volume,open_interest\n"
    lines = [
        f"2024-01-02T09:0{i}:00.000000Z,rb2405,3900.0,3900.0,3900.0,3900.0,100,500\n"
        for i in range(5)
    ]
    raw = (header + "".join(lines)).encode("utf-8")
    flat_csv.write_bytes(raw)
    raw_sha = v2.sha(raw)

    task = copy.deepcopy(task_base)
    task["data_requirements"]["snapshot_locator"] = str(flat_csv)
    task["data_requirements"]["snapshot_sha256"] = raw_sha
    _seal(task, "task")

    spec = copy.deepcopy(spec_base)
    spec["task_content_hash"] = task["task_content_hash"]
    spec["dataset_requirements"]["snapshot_locator"] = str(flat_csv)
    spec["dataset_requirements"]["snapshot_sha256"] = raw_sha
    spec["cost_model"]["commission_bps"] = "1"
    spec["cost_model"]["slippage_ticks"] = 1
    _seal(spec, "spec")

    output_dir = tmp_path / "flat_run"
    res = execute_v2_backtest_spec(task, spec, output_dir)
    assert res["run_status"] == "COMPLETED"

    summary = v2.parse((output_dir / "backtest_summary.json").read_bytes())
    net_pnl = float(summary["net_pnl"])
    total_fees = float(summary["total_fees"])
    initial_cap = float(summary["initial_capital"])
    ending_eq = float(summary["ending_equity"])

    assert total_fees > 0
    assert round(net_pnl, 4) == round(-total_fees, 4)
    assert round(ending_eq, 4) == round(initial_cap - total_fees, 4)


def test_12_single_lot_return_matches_multiplier(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that single-lot gross return is strictly proportional to multiplier."""
    task_base, spec_base = single_contract_bundle

    # Run 1: multiplier = 10, zero cost
    spec10 = copy.deepcopy(spec_base)
    spec10["contract_specifications"]["multiplier"] = "10"
    spec10["cost_model"]["commission_bps"] = "0"
    spec10["cost_model"]["slippage_ticks"] = 0
    _seal(spec10, "spec")

    # Run 2: multiplier = 20, zero cost
    spec20 = copy.deepcopy(spec_base)
    spec20["contract_specifications"]["multiplier"] = "20"
    spec20["cost_model"]["commission_bps"] = "0"
    spec20["cost_model"]["slippage_ticks"] = 0
    _seal(spec20, "spec")

    res10 = execute_v2_backtest_spec(task_base, spec10, tmp_path / "mult_10")
    res20 = execute_v2_backtest_spec(task_base, spec20, tmp_path / "mult_20")

    pnl10 = float(res10["evidence"]["typed_metrics"]["net_pnl"])
    pnl20 = float(res20["evidence"]["typed_metrics"]["net_pnl"])

    assert pnl10 > 0
    assert round(pnl20, 4) == round(pnl10 * 2.0, 4)


def test_13_zero_trades_no_fabrication(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that when strategy generates no trades, 0 trades are recorded without fabrication."""
    task_base, spec_base = single_contract_bundle

    spec = copy.deepcopy(spec_base)
    spec["strategy_spec"]["strategy_name"] = "flat"
    _seal(spec, "spec")

    output_dir = tmp_path / "zero_trades_out"
    res = execute_v2_backtest_spec(task_base, spec, output_dir)
    assert res["run_status"] == "COMPLETED"

    blotter = v2.parse((output_dir / "trade_blotter.json").read_bytes())
    summary = v2.parse((output_dir / "backtest_summary.json").read_bytes())
    typed = res["evidence"]["typed_metrics"]

    assert blotter["trades"] == []
    assert summary["total_trades"] == 0
    assert summary["total_fees"] == "0"
    assert summary["net_pnl"] == "0"
    assert summary["ending_equity"] == summary["initial_capital"]
    assert typed["trade_count"] == 0
    assert float(typed["total_fees"]) == 0.0
    assert float(typed["net_pnl"]) == 0.0


def test_14_cli_replay_command_executable(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that the CLI entry point main() directly executes and satisfies replay instructions."""
    task, spec = single_contract_bundle
    spec_file = tmp_path / "spec.json"
    task_file = tmp_path / "task.json"
    cli_out = tmp_path / "cli_out"

    spec_file.write_text(v2.canonical(spec) + "\n", encoding="utf-8")
    task_file.write_text(v2.canonical(task) + "\n", encoding="utf-8")

    from research_lab.runners.v2_backtest import main

    # Execute CLI with --spec, --task, --output
    ret = main(["--spec", str(spec_file), "--task", str(task_file), "--output", str(cli_out)])
    assert ret == 0

    assert (cli_out / "run.json").is_file()
    assert (cli_out / "manifest.json").is_file()
    assert (cli_out / "evidence.json").is_file()
    assert (cli_out / "backtest_summary.json").is_file()
    assert (cli_out / "trade_blotter.json").is_file()
    assert (cli_out / "equity_curve.json").is_file()


def test_15_captured_snapshot_tamper_and_missing_rejected(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that missing or tampering captured snapshot in materials/snapshot.csv fails closed."""
    task, spec = single_contract_bundle
    output_dir = tmp_path / "captured_tamper_out"

    res = execute_v2_backtest_spec(task, spec, output_dir)
    assert res["run_status"] == "COMPLETED"

    captured_csv = output_dir / "materials" / "snapshot.csv"
    assert captured_csv.is_file()

    manifest = res["manifest"]
    run = res["run"]

    # 1. Tamper 1 byte of captured snapshot -> validate_manifest must reject
    raw = captured_csv.read_bytes()
    tampered_bytes = raw[:-1] + (b"X" if raw[-1:] != b"X" else b"Y")
    captured_csv.write_bytes(tampered_bytes)

    with pytest.raises(ValueError, match="(?:SingleContract captured )?snapshot sha256 mismatch"):
        v2.validate_manifest(output_dir, manifest, run, task=task, spec=spec)

    # 2. Missing captured snapshot -> validate_manifest and validate_spec must reject (zero fallback)
    captured_csv.unlink()
    assert not captured_csv.exists()

    with pytest.raises(ValueError, match="SingleContract captured snapshot missing or not regular file"):
        v2.validate_manifest(output_dir, manifest, run, task=task, spec=spec)

    with pytest.raises(ValueError, match="SingleContract captured snapshot missing or not regular file"):
        v2.validate_spec(spec, task, root=output_dir)


def test_16_captured_snapshot_create_only_no_overwrite(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that create-only capture forbids overwriting existing captured snapshot."""
    task, spec = single_contract_bundle
    output_dir = tmp_path / "create_only_out"

    # Pre-create output directory to trigger exclusivity check
    output_dir.mkdir(parents=True)
    with pytest.raises(FileExistsError, match="Target output directory already exists"):
        execute_v2_backtest_spec(task, spec, output_dir)


def test_17_failed_run_preserves_captured_snapshot(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that even when execution fails, captured snapshot is preserved in materials."""
    task, spec = single_contract_bundle
    output_dir = tmp_path / "failed_capture_out"

    res = execute_v2_backtest_spec(task, spec, output_dir, force_failure=True)
    assert res["run_status"] == "FAILED"

    captured_csv = output_dir / "materials" / "snapshot.csv"
    assert captured_csv.is_file()
    assert v2.sha(captured_csv.read_bytes()) == spec["dataset_requirements"]["snapshot_sha256"]
    assert len(captured_csv.read_bytes()) == SYNTHETIC_FIXTURE_BYTES

    # validate_manifest for FAILED run succeeds with captured snapshot
    v2.validate_manifest(output_dir, res["manifest"], res["run"], task=task, spec=spec)


def test_18_dataset_metadata_byte_length_mismatch_rejected(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Validate that tampered snapshot_byte_length in dataset_metadata is rejected even if entry is sealed in manifest."""
    task, spec = single_contract_bundle
    output_dir = tmp_path / "metadata_byte_len_tamper_out"

    res = execute_v2_backtest_spec(task, spec, output_dir)
    assert res["run_status"] == "COMPLETED"

    manifest = copy.deepcopy(res["manifest"])
    run = res["run"]

    # Read and tamper dataset_metadata.json's snapshot_byte_length
    meta_path = output_dir / "dataset_metadata.json"
    meta = v2.parse(meta_path.read_bytes())
    original_byte_len = meta["snapshot_byte_length"]
    meta["snapshot_byte_length"] = original_byte_len + 100

    # Write back tampered dataset_metadata
    tampered_bytes = (v2.canonical(meta) + "\n").encode("utf-8")
    meta_path.write_bytes(tampered_bytes)

    # Update manifest entry for dataset_metadata with new byte_length and content_sha256
    for entry in manifest["entries"]:
        if entry["role"] == "dataset_metadata":
            entry["byte_length"] = len(tampered_bytes)
            entry["content_sha256"] = v2.sha(tampered_bytes)

    # Reseal manifest so payload bytes/sha match manifest entry, but metadata byte length mismatches computation/captured bytes
    _seal(manifest, "manifest")
    (output_dir / "manifest.json").write_text(v2.canonical(manifest) + "\n", encoding="utf-8")

    # validate_manifest must reject due to snapshot byte length mismatch
    with pytest.raises(ValueError, match="SingleContract snapshot byte length binding"):
        v2.validate_manifest(output_dir, manifest, run, task=task, spec=spec)
