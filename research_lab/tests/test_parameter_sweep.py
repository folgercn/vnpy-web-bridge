from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from research_lab.backtest import BacktestAdapter
from research_lab.experiments import ExperimentLoadError, load_sweep
from research_lab.sweeps import ParameterSweepEngine, generate_trials


SWEEP_YAML = """\
schema_version: research_lab.sweep.v1
sweep_id: fixture-sweep-001
experiment:
  schema_version: research_lab.experiment.v1
  experiment_id: fixture-base-001
  strategy:
    name: buy_and_hold
  factor:
    name: close_return
  universe: [DEMO]
  dataset:
    name: fixture_prices
    prices: [100.0, 110.0, 121.0]
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
search_strategy: cartesian
parameters:
  - path: execution.position_size
    values: [0.5, 1.0]
  - path: cost_model.bps
    values: [0.0, 10.0]
ranking:
  metric: total_return
  direction: maximize
"""


class ParameterSweepTest(unittest.TestCase):
    def _spec(self, root: Path, source: str = SWEEP_YAML):
        path = root / "sweep.yaml"
        path.write_text(source, encoding="utf-8")
        return load_sweep(path)

    def test_config_rejects_unsafe_paths_duplicate_paths_and_invalid_direct_values(self) -> None:
        cases = (
            SWEEP_YAML.replace("- path: execution.position_size", "- path: dataset.path"),
            SWEEP_YAML.replace("  - path: cost_model.bps", "  - path: execution.position_size"),
            SWEEP_YAML.replace("values: [0.5, 1.0]", "values: [0.0, 1.0]"),
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ExperimentLoadError):
                    self._spec(Path(directory), source)

    def test_generator_uses_declared_cartesian_order_and_unique_trial_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._spec(Path(directory))
            trials = generate_trials(spec)

        self.assertEqual(spec.search_strategy, "cartesian")
        self.assertEqual(len(trials), 4)
        self.assertEqual(
            [trial.parameter_values for trial in trials],
            [
                {"execution.position_size": 0.5, "cost_model.bps": 0.0},
                {"execution.position_size": 0.5, "cost_model.bps": 10.0},
                {"execution.position_size": 1.0, "cost_model.bps": 0.0},
                {"execution.position_size": 1.0, "cost_model.bps": 10.0},
            ],
        )
        self.assertEqual(len({trial.experiment.experiment_id for trial in trials}), 4)
        self.assertNotIn("fixture-base-001", {trial.experiment.experiment_id for trial in trials})

    def test_max_length_sweep_ids_with_a_shared_prefix_preserve_separate_trials(self) -> None:
        shared_prefix = "s" + "a" * 126
        first_sweep_id = shared_prefix + "a"
        second_sweep_id = shared_prefix + "b"
        source = SWEEP_YAML.replace("values: [0.5, 1.0]", "values: [1.0]").replace(
            "values: [0.0, 10.0]", "values: [0.0]"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = ParameterSweepEngine.local(root / "output")
            first = engine.run(self._spec(root, source.replace("fixture-sweep-001", first_sweep_id)))
            second = engine.run(self._spec(root, source.replace("fixture-sweep-001", second_sweep_id)))

            first_trial = first.trials[0].result
            second_trial = second.trials[0].result
            self.assertNotEqual(first_trial.experiment_id, second_trial.experiment_id)
            self.assertIsNotNone(engine.runner.store.get(first_trial.experiment_id))
            self.assertIsNotNone(engine.runner.store.get(second_trial.experiment_id))
            self.assertTrue(Path(first_trial.artifact_location).is_file())
            self.assertTrue(Path(second_trial.artifact_location).is_file())

    def test_local_sequential_run_persists_trials_ranking_and_stability_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = ParameterSweepEngine.local(root / "output")
            result = engine.run(self._spec(root))

            self.assertEqual(engine.execution_mode, "local_sequential")
            self.assertEqual(result.status, "completed")
            self.assertEqual(len(result.trials), 4)
            self.assertEqual(len(result.ranked_trials), 4)
            self.assertEqual(result.ranked_trials[0].parameter_values["execution.position_size"], 1.0)
            self.assertEqual(len(result.stability), 4)
            self.assertTrue(Path(result.artifact_location).is_file())
            self.assertTrue(Path(result.report_location).is_file())
            self.assertIn("local, sequential", Path(result.report_location).read_text(encoding="utf-8"))
            self.assertEqual(engine.runner.store.get_sweep(result.sweep_id), result)
            self.assertIsNone(engine.runner.store.get("fixture-base-001"))
            self.assertEqual(len(engine.runner.store.query(strategy_name="buy_and_hold")), 4)

    def test_ranking_breaks_metric_ties_by_experiment_id(self) -> None:
        source = SWEEP_YAML.replace("name: buy_and_hold", "name: flat").replace(
            "execution.position_size", "strategy.parameters.variant", 1
        ).replace("values: [0.5, 1.0]", "values: [first, second]")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = ParameterSweepEngine.local(root / "output").run(self._spec(root, source))

        ids = [trial.experiment_id for trial in result.ranked_trials]
        self.assertEqual(ids, sorted(ids))

    def test_ranking_honors_minimize_direction(self) -> None:
        source = SWEEP_YAML.replace("metric: total_return\n  direction: maximize", "metric: transaction_cost\n  direction: minimize")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = ParameterSweepEngine.local(root / "output").run(self._spec(root, source))

        self.assertEqual(result.ranked_trials[0].parameter_values["cost_model.bps"], 0.0)

    def test_failed_trials_are_saved_and_excluded_from_ranking_and_stability(self) -> None:
        class BrokenAdapter(BacktestAdapter):
            def run(self, experiment):
                raise RuntimeError("fixture failure")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = ParameterSweepEngine.local(root / "output", BrokenAdapter())
            result = engine.run(self._spec(root))

            self.assertEqual(result.status, "completed_with_failures")
            self.assertEqual(result.ranked_trials, [])
            self.assertEqual(result.stability, [])
            self.assertEqual({trial.result.error_code for trial in result.trials}, {"BACKTEST_FAILED"})

    def test_sweep_has_no_queue_or_parallel_execution_surface(self) -> None:
        self.assertEqual(ParameterSweepEngine.execution_mode, "local_sequential")
        self.assertFalse(hasattr(ParameterSweepEngine, "worker_pool"))
        self.assertFalse(hasattr(ParameterSweepEngine, "queue"))


if __name__ == "__main__":
    unittest.main()
