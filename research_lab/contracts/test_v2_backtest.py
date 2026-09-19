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
    """Ensure ResultStore owned snapshot can be independently validated even if original directory is deleted."""
    task, spec = single_contract_bundle
    output_dir = tmp_path / "original_output"
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))

    res = execute_v2_backtest_spec(task, spec, output_dir, result_store=store)
    run_id = res["run"]["run_id"]

    # Delete original output directory completely
    shutil.rmtree(output_dir)
    assert not output_dir.exists()

    # Load bundle facts from store
    facts = store.load_v2_bundle_facts(run_id)
    assert facts["run"]["run_id"] == run_id
    assert facts["run"]["run_status"] == "COMPLETED"

    # Verify frozen public validator can re-consume the stored bundle
    bundle_path = Path(res["stored_result"]["bundle_location"])
    manifest = facts["manifest"]
    run = facts["run"]
    v2.validate_manifest(bundle_path, manifest, run, task=task, spec=spec)


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


def test_9_custom_price_series_dynamically_effective(
    single_contract_bundle: tuple[dict, dict], tmp_path: Path
) -> None:
    """Verify that different price series dynamically change factual returns and costs."""
    task, spec = single_contract_bundle

    res_flat = execute_v2_backtest_spec(
        task, spec, tmp_path / "flat", override_prices=[3900.0, 3900.0, 3900.0, 3900.0, 3900.0]
    )
    res_up = execute_v2_backtest_spec(
        task, spec, tmp_path / "up", override_prices=[3900.0, 4000.0, 4100.0, 4200.0, 4300.0]
    )

    metrics_flat = res_flat["evidence"]["typed_metrics"]
    metrics_up = res_up["evidence"]["typed_metrics"]

    assert float(metrics_up["net_pnl"]) > float(metrics_flat["net_pnl"])
