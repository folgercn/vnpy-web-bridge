from __future__ import annotations

import inspect
from pathlib import Path
import tempfile
import unittest

from research_lab.backtest import BacktestAdapter
from research_lab.experiments import ExperimentLoadError, load_validation
from research_lab.runners import ExperimentRunner
from research_lab.validation import ValidationExecutionError, WalkForwardValidationEngine, generate_folds


VALIDATION_YAML = """\
schema_version: research_lab.validation.v1
validation_id: fixture-validation-001
method: walk_forward
train_size: 3
test_size: 2
step_size: 2
experiment:
  schema_version: research_lab.experiment.v1
  experiment_id: fixture-validation-base-001
  strategy:
    name: buy_and_hold
  factor:
    name: close_return
  universe: [DEMO]
  dataset:
    name: fixture_prices
    prices: [100.0, 110.0, 121.0, 133.1, 146.41, 161.051, 177.1561]
  parameters: {}
  execution:
    initial_capital: 1000.0
    position_size: 1.0
  cost_model:
    bps: 0.0
  validation:
    method: in_sample
  output:
    format: json
"""


class WalkForwardValidationTest(unittest.TestCase):
    def _spec(self, root: Path, source: str = VALIDATION_YAML):
        path = root / "validation.yaml"
        path.write_text(source, encoding="utf-8")
        return load_validation(path)

    def test_config_rejects_invalid_windows_and_unknown_fields(self) -> None:
        cases = (
            VALIDATION_YAML.replace("train_size: 3", "train_size: 1"),
            VALIDATION_YAML.replace("method: walk_forward", "method: train_test_split").replace("step_size: 2", "step_size: 1"),
            VALIDATION_YAML.replace("test_size: 2", "test_size: 3").replace("step_size: 2", "step_size: 1"),
            VALIDATION_YAML.replace("step_size: 2", "unexpected: true"),
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ExperimentLoadError):
                    self._spec(Path(directory), source)

    def test_fold_generators_are_ordered_disjoint_and_have_no_lookahead(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            walk = generate_folds(self._spec(root), 7)
            rolling = generate_folds(self._spec(root, VALIDATION_YAML.replace("method: walk_forward", "method: rolling_window")), 7)
            split = generate_folds(self._spec(root, VALIDATION_YAML.replace("method: walk_forward", "method: train_test_split").replace("step_size: 2\n", "")), 5)

        self.assertEqual([(fold.train_start, fold.train_end, fold.test_start, fold.test_end) for fold in walk], [(0, 3, 3, 5), (0, 5, 5, 7)])
        self.assertEqual([(fold.train_start, fold.train_end, fold.test_start, fold.test_end) for fold in rolling], [(0, 3, 3, 5), (2, 5, 5, 7)])
        self.assertEqual([(fold.train_start, fold.train_end, fold.test_start, fold.test_end) for fold in split], [(0, 3, 3, 5)])
        for fold in walk + rolling + split:
            self.assertLessEqual(fold.train_end, fold.test_start)
        self.assertEqual([(fold.test_start, fold.test_end) for fold in walk], [(3, 5), (5, 7)])
        self.assertEqual([(fold.test_start, fold.test_end) for fold in rolling], [(3, 5), (5, 7)])

    def test_generator_rejects_partial_train_test_split_and_short_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._spec(Path(directory), VALIDATION_YAML.replace("method: walk_forward", "method: train_test_split").replace("step_size: 2\n", ""))
        with self.assertRaises(ValidationExecutionError):
            generate_folds(spec, 6)
        with self.assertRaises(ValidationExecutionError):
            generate_folds(spec, 4)

    def test_run_persists_fold_results_analyses_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = WalkForwardValidationEngine.local(root / "output").run(self._spec(root))

            self.assertEqual(result.status, "completed")
            self.assertEqual(len(result.folds), 2)
            self.assertIsNotNone(result.stability)
            self.assertIsNotNone(result.degradation)
            self.assertAlmostEqual(result.stability.positive_oos_fraction, 1.0)
            self.assertTrue(Path(result.artifact_location).is_file())
            report = Path(result.report_location).read_text(encoding="utf-8")
            self.assertIn("not a promotion decision", report)
            self.assertIn("Critic integration", report)
            self.assertEqual(WalkForwardValidationEngine.local(root / "output").runner.store.get_validation(result.validation_id), result)
            self.assertEqual(len(WalkForwardValidationEngine.local(root / "output").runner.store.query()), 4)

    def test_local_csv_uses_the_same_normalized_fold_path(self) -> None:
        header = "timestamp,symbol,open,high,low,close,volume,open_interest\n"
        prices = (100, 110, 121, 133.1, 146.41)
        rows = "".join(
            f"2026-01-0{index + 1}T00:00:00+00:00,DEMO,{price},{price},{price},{price},0,0\n"
            for index, price in enumerate(prices)
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "prices.csv"
            csv_path.write_text(header + rows, encoding="utf-8")
            source = (
                VALIDATION_YAML.replace("method: walk_forward", "method: train_test_split")
                .replace("step_size: 2\n", "")
                .replace("prices: [100.0, 110.0, 121.0, 133.1, 146.41, 161.051, 177.1561]", f"provider: local_csv\n    path: {csv_path}")
            )
            result = WalkForwardValidationEngine.local(root / "output").run(self._spec(root, source))

        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.folds), 1)
        self.assertAlmostEqual(result.folds[0].out_of_sample.metrics.total_return, 0.1)

    def test_failed_folds_are_persisted_and_excluded_from_analysis(self) -> None:
        class BrokenAdapter(BacktestAdapter):
            def run(self, experiment):
                raise RuntimeError("fixture failure")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = WalkForwardValidationEngine.local(root / "output", BrokenAdapter()).run(self._spec(root))

        self.assertEqual(result.status, "completed_with_failures")
        self.assertIsNone(result.stability)
        self.assertIsNone(result.degradation)
        self.assertEqual({item.in_sample.error_code for item in result.folds}, {"BACKTEST_FAILED"})
        self.assertEqual([item.completed_folds for item in result.regimes], [0, 0, 0])

    def test_validation_does_not_change_experiment_runner_interface(self) -> None:
        self.assertEqual(list(inspect.signature(ExperimentRunner.run).parameters), ["self", "experiment"])
        self.assertEqual(list(inspect.signature(ExperimentRunner.run_yaml).parameters), ["self", "path"])
        self.assertFalse(hasattr(ExperimentRunner, "run_validation"))


if __name__ == "__main__":
    unittest.main()
