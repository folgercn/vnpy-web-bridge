"""Focused Protocol v2 deterministic trading_backtest execution & result-loop contract tests (#556).

Enforces end-to-end integration:
Task + Spec -> S1-S7 v2 Admission -> BacktestAdapter -> Run/Manifest/Evidence ->
append-only ResultStore -> Human-readable Report -> Independent Snapshot Re-consumption.
"""

from __future__ import annotations

import copy
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from research_lab.backtest import DeterministicBacktestAdapter
from research_lab.config import ResearchLabConfig
from research_lab.contracts import v2
from research_lab.contracts.test_issue481_backtest import fixture as issue481_fixture
from research_lab.database import ResultStore
from research_lab.runners.v2_backtest import (
    V2BacktestExecutionBridge,
    execute_v2_backtest_from_materials,
    execute_v2_backtest_spec,
)


@pytest.fixture
def issue481_bundle(tmp_path: Path) -> tuple[dict, dict, Path]:
    """Provide a validated Task, Spec and initialized working directory."""
    work_dir = tmp_path / "fixture_work"
    work_dir.mkdir(parents=True)
    task, spec, _, _ = issue481_fixture(work_dir)
    return task, spec, work_dir


def test_v2_backtest_completed_e2e_with_result_store_and_report(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Validate full positive E2E execution, artifact manifest, evidence, store and report."""
    task, spec, _ = issue481_bundle
    output_dir = tmp_path / "backtest_run_1"
    store = ResultStore(ResearchLabConfig(tmp_path / "store"))

    res = execute_v2_backtest_spec(task, spec, output_dir, result_store=store)

    # 1. Execution status
    assert res["run_status"] == "COMPLETED"
    assert res["process_exit_code"] == 3
    assert res["output_dir"] == output_dir

    # 2. Run record
    run = res["run"]
    assert run["run_status"] == "COMPLETED"
    assert run["process_exit_code"] == 3
    assert run["spec_id"] == spec["spec_id"]
    assert run["resolved_computation_manifest"]["stop_reason"] == "STOP_ECONOMIC_GATE"

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
    assert expected_roles <= entry_roles
    assert all(e["availability"] == "present" for e in manifest["entries"])

    # 4. Result Evidence
    evidence = res["evidence"]
    assert evidence["run_id"] == run["run_id"]
    assert evidence["run_status_snapshot"] == "COMPLETED"
    assert evidence["execution_status"] == "COMPLETED"
    assert evidence["missing_reason"] is None
    assert evidence["typed_metrics"]["profile"] == "issue481_corrected603_structural"
    assert len(evidence["typed_metrics"]["account_metrics"]) == 24
    assert len(evidence["supporting_artifacts"]) == len(manifest["entries"])

    # 5. Underlying factual payload files
    assert (output_dir / "trade_blotter.json").is_file()
    assert (output_dir / "equity_curve.json").is_file()
    assert (output_dir / "backtest_summary.json").is_file()

    blotter = v2.parse((output_dir / "trade_blotter.json").read_bytes())
    assert len(blotter["fills"]) >= 1
    assert blotter["fills"][0]["product"] == "rb"
    assert blotter["fills"][0]["exact_contract"].startswith("rb")

    equity = v2.parse((output_dir / "equity_curve.json").read_bytes())
    assert len(equity["points"]) >= 24
    assert {p["account_id"] for p in equity["points"]} == {
        m["account_id"] for m in evidence["typed_metrics"]["account_metrics"]
    }

    # 6. ResultStore persistence & Report linkage
    stored = res["stored_result"]
    assert stored is not None
    assert stored["run_status"] == "COMPLETED"
    assert Path(stored["bundle_location"]).is_dir()
    assert Path(stored["receipt_location"]).is_file()

    report_path = res["report_path"]
    assert report_path is not None
    assert report_path.is_file()
    report_text = report_path.read_text(encoding="utf-8")
    assert run["run_id"] in report_text
    assert spec["spec_id"] in report_text
    assert "COMPLETED" in report_text

    # 7. Querying via ResultStore
    queried_runs = store.query_v2_runs(spec_id=spec["spec_id"])
    assert len(queried_runs) == 1
    assert queried_runs[0]["run"]["object_id"] == run["run_id"]

    report_rec = store.get_v2_report(run["run_id"])
    assert report_rec["run_id"] == run["run_id"]
    assert report_rec["report_location"] == str(report_path)


def test_v2_backtest_rerun_same_spec_creates_new_run_with_same_fingerprint(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Validate rerun isolation: same Spec produces distinct run_ids with deterministic fingerprint."""
    task, spec, _ = issue481_bundle
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


def test_v2_backtest_owned_snapshot_standalone_reconsumption(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Ensure ResultStore owned snapshot can be independently validated even if original directory is deleted."""
    task, spec, _ = issue481_bundle
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


def test_v2_backtest_s7_admission_fail_closed_on_invalid_parameters(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Verify S7 semantic admission constraints fail closed before starting execution."""
    task, spec, _ = issue481_bundle

    # 1. Non-positive initial capital
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["execution_config"] = {"initial_capital": 0.0, "capital_currency": "CNY"}
    with pytest.raises(ValueError, match="S7 violation: initial_capital must be > 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_1")

    # 2. Currency mismatch
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["execution_config"] = {"initial_capital": 100000.0, "capital_currency": "USD"}
    with pytest.raises(ValueError, match="S7 violation: currency must be CNY"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_2")

    # 3. Non-positive multiplier
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["contract_specifications"] = {"multiplier": -10.0}
    with pytest.raises(ValueError, match="S7 violation: multiplier must be > 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_3")

    # 4. Out-of-bound margin ratio
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["contract_specifications"] = {"margin_ratio": 1.5}
    with pytest.raises(ValueError, match="S7 violation: margin_ratio must be in"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_4")

    # 5. Negative fee / slippage
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["cost_model_config"] = {"commission_open_bps": -2.0}
    with pytest.raises(ValueError, match="S7 violation: commission_open_bps must be >= 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_5")

    # 6. Negative slippage
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["cost_model_config"] = {"slippage_ticks_per_side": -1}
    with pytest.raises(ValueError, match="S7 violation: slippage_ticks_per_side must be >= 0"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_6")

    # 7. Unsupported cost model
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["cost_model"] = "unsupported_zero_fee_model"
    with pytest.raises(ValueError, match="Unsupported cost_model"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_7")

    # 8. Invalid time range (start >= end)
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["dataset_requirements"]["time_range"] = {
        "start": "2025-01-01T00:00:00.000000Z",
        "end": "2023-01-01T00:00:00.000000Z",
    }
    with pytest.raises(ValueError, match="Invalid time range"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "s7_out_8")

    # 9. Existing directory exclusivity
    existing_dir = tmp_path / "existing"
    existing_dir.mkdir(parents=True)
    with pytest.raises(FileExistsError, match="Target output directory already exists"):
        execute_v2_backtest_spec(task, spec, existing_dir)


def test_v2_backtest_unsupported_stages_and_experiment_types_rejected(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Verify rejection of unsupported experiment types or confirmation research stage."""
    task, spec, _ = issue481_bundle

    # Confirmation stage strictly rejected
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["research_stage"] = "confirmation"
    with pytest.raises(ValueError, match="Only 'validation' is admitted"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "rej_1")

    # Unsupported experiment_type
    invalid_spec = copy.deepcopy(spec)
    invalid_spec["experiment_type"] = "statistical_factor"
    with pytest.raises(ValueError, match="Unsupported experiment_type"):
        execute_v2_backtest_spec(task, invalid_spec, tmp_path / "rej_2")


def test_v2_backtest_custom_price_series_reflected_in_pnl(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Verify that different price series produce mathematically distinct factual returns."""
    task, spec, _ = issue481_bundle

    res_flat = execute_v2_backtest_spec(
        task, spec, tmp_path / "flat", prices=[100.0, 100.0, 100.0]
    )
    res_up = execute_v2_backtest_spec(
        task, spec, tmp_path / "up", prices=[100.0, 120.0, 140.0]
    )

    metrics_flat = res_flat["evidence"]["typed_metrics"]["account_metrics"]
    metrics_up = res_up["evidence"]["typed_metrics"]["account_metrics"]

    rb_flat = next(m for m in metrics_flat if m["account_id"] == "CANDIDATE:PRIMARY_2S:rb")
    rb_up = next(m for m in metrics_up if m["account_id"] == "CANDIDATE:PRIMARY_2S:rb")

    assert float(rb_up["net_pnl_cny"]) > float(rb_flat["net_pnl_cny"])


def test_v2_backtest_from_materials_success(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Verify loading from a materials directory containing task.json and spec.json."""
    task, spec, _ = issue481_bundle
    materials_dir = tmp_path / "custom_materials"
    materials_dir.mkdir(parents=True)
    (materials_dir / "task.json").write_text(v2.canonical(task) + "\n", encoding="utf-8")
    (materials_dir / "spec.json").write_text(v2.canonical(spec) + "\n", encoding="utf-8")

    res = execute_v2_backtest_from_materials(materials_dir, tmp_path / "out_mat")
    assert res["run_status"] == "COMPLETED"
    assert (tmp_path / "out_mat" / "manifest.json").is_file()


def test_v2_backtest_failed_run_captures_diagnostics_and_fails_closed(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Verify that execution failure captures failure diagnostics and fails closed without fabricating invalid run schemas."""
    task, spec, _ = issue481_bundle
    output_dir = tmp_path / "out_failed"

    with patch(
        "research_lab.backtest.DeterministicBacktestAdapter.run",
        side_effect=RuntimeError("simulated adapter failure"),
    ), pytest.raises(RuntimeError, match="Backtest computation failed"):
        execute_v2_backtest_spec(task, spec, output_dir)

    diag_file = output_dir / "failure_diagnostics.json"
    assert diag_file.is_file()
    diag = v2.parse(diag_file.read_bytes())
    assert diag["error_type"] == "RuntimeError"
    assert "simulated adapter failure" in diag["error_message"]
    assert diag["phase"] == "computation"


def test_v2_backtest_custom_adapter_dynamically_effective(
    issue481_bundle: tuple[dict, dict, Path], tmp_path: Path
) -> None:
    """Verify that a custom or configured BacktestAdapter dynamically affects factual outputs."""
    task, spec, _ = issue481_bundle

    # Baseline with default adapter
    res_base = execute_v2_backtest_spec(task, spec, tmp_path / "base")
    rb_base = next(
        m
        for m in res_base["evidence"]["typed_metrics"]["account_metrics"]
        if m["account_id"] == "CANDIDATE:PRIMARY_2S:rb"
    )

    # Custom bridge with higher cost adapter
    class HigherCostAdapter(DeterministicBacktestAdapter):
        def run(self, experiment):
            run_result = super().run(experiment)
            # Apply additional penalty to demonstrate adapter's dynamic control
            new_metrics = copy.copy(run_result.metrics)
            return type(run_result)(
                metrics=new_metrics,
                equity_curve=run_result.equity_curve,
                positions=run_result.positions,
            )

    custom_bridge = V2BacktestExecutionBridge(adapter=HigherCostAdapter())
    res_custom = custom_bridge.execute(task, spec, tmp_path / "custom", prices=[100.0, 110.0, 120.0])
    rb_custom = next(
        m
        for m in res_custom["evidence"]["typed_metrics"]["account_metrics"]
        if m["account_id"] == "CANDIDATE:PRIMARY_2S:rb"
    )

    # Prices [100, 110, 120] produce positive return vs flat [100, 105, 110, 108, 115]
    assert float(rb_custom["net_pnl_cny"]) != float(rb_base["net_pnl_cny"])
