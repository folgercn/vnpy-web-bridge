from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from research_lab.database import ResultStore
from research_lab.experiments import ExperimentLoadError, load_experiment
from research_lab.runners import ExperimentRunner


EXPERIMENT_YAML = """\
schema_version: research_lab.experiment.v1
experiment_id: test-buy-hold-001
strategy:
  name: buy_and_hold
factor:
  name: close_return
universe: [DEMO]
dataset:
  name: test_prices
  prices: [100.0, 110.0, 121.0]
parameters: {}
execution:
  initial_capital: 1000.0
  position_size: 1.0
cost_model:
  bps: 10.0
validation:
  method: in_sample
output:
  format: json
"""


class ResearchLabMvpTest(unittest.TestCase):
    def test_yaml_runner_persists_complete_result_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            experiment_path = root / "experiment.yaml"
            experiment_path.write_text(EXPERIMENT_YAML, encoding="utf-8")

            result = ExperimentRunner.local(root / "output").run_yaml(experiment_path)

            self.assertEqual(result.status, "completed")
            self.assertAlmostEqual(result.metrics.total_return, 0.209, places=8)
            self.assertEqual(result.metrics.turnover, 1.0)
            self.assertEqual(result.metrics.transaction_cost, 1.0)
            self.assertTrue(Path(result.artifact_location).is_file())
            self.assertTrue(Path(result.report_location).is_file())
            payload = json.loads(Path(result.artifact_location).read_text(encoding="utf-8"))
            self.assertEqual(payload["details"]["equity_curve"], [1000.0, 1100.0, 1209.0])
            stored = ResultStore(ExperimentRunner.local(root / "output").store.config)
            self.assertEqual(stored.get(result.experiment_id).metrics.final_equity, 1209.0)
            self.assertEqual(len(stored.query(strategy_name="buy_and_hold")), 1)
            self.assertEqual(len(stored.query(factor_name="close_return")), 1)

    def test_invalid_yaml_is_rejected_by_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yaml"
            path.write_text(EXPERIMENT_YAML.replace("buy_and_hold", "unsupported"), encoding="utf-8")
            with self.assertRaises(ExperimentLoadError):
                load_experiment(path)

    def test_non_finite_prices_are_rejected_at_yaml_load_time(self) -> None:
        for value in (".nan", ".inf", "-.inf"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "invalid-prices.yaml"
                path.write_text(
                    EXPERIMENT_YAML.replace("[100.0, 110.0, 121.0]", f"[100.0, {value}, 121.0]"),
                    encoding="utf-8",
                )
                with self.assertRaises(ExperimentLoadError):
                    load_experiment(path)

    def test_legacy_inline_prices_accept_multi_symbol_universe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "legacy-universe.yaml"
            path.write_text(EXPERIMENT_YAML.replace("universe: [DEMO]", "universe: [DEMO, DEMO2]"), encoding="utf-8")

            result = ExperimentRunner.local(root / "output").run_yaml(path)

            self.assertEqual(result.status, "completed")
            self.assertAlmostEqual(result.metrics.total_return, 0.209, places=8)

    def test_failed_backtest_is_indexed_by_failure_code(self) -> None:
        class BrokenAdapter:
            def run(self, experiment):
                raise RuntimeError("engine unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "experiment.yaml"
            path.write_text(EXPERIMENT_YAML, encoding="utf-8")
            runner = ExperimentRunner.local(root / "output", adapter=BrokenAdapter())
            result = runner.run_yaml(path)

            self.assertEqual(result.status, "failed")
            self.assertEqual(result.error_code, "BACKTEST_FAILED")
            self.assertEqual(runner.store.query(error_code="BACKTEST_FAILED")[0].experiment_id, result.experiment_id)


if __name__ == "__main__":
    unittest.main()
