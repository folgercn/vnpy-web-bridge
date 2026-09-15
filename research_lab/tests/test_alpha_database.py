from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from research_lab.alpha_database import AlphaDatabase
from research_lab.config import ResearchLabConfig
from research_lab.critic import CriticAgent
from research_lab.runners import ExperimentRunner
from research_lab.schemas import AlphaIdea, LiteratureReference
from research_lab.validation import WalkForwardValidationEngine


EXPERIMENT_YAML = """\
schema_version: research_lab.experiment.v1
experiment_id: alpha-record-001
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

VALIDATION_YAML = """\
schema_version: research_lab.validation.v1
validation_id: alpha-validation-001
method: walk_forward
train_size: 3
test_size: 2
step_size: 2
experiment:
  schema_version: research_lab.experiment.v1
  experiment_id: alpha-validation-base
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


class AlphaDatabaseTest(unittest.TestCase):
    def _write(self, root: Path, name: str, content: str) -> Path:
        path = root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_completed_experiment_is_archived_as_git_trackable_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = ExperimentRunner.local(root / "output").run_yaml(self._write(root, "experiment.yaml", EXPERIMENT_YAML))
            database = AlphaDatabase(ResearchLabConfig(root / "output"))

            record = database.get_experiment(result.experiment_id)
            self.assertIsNotNone(record)
            self.assertEqual(record.status, "completed")
            self.assertEqual(database.query_experiments(strategy_name="buy_and_hold"), [record])
            self.assertEqual(database.query_experiments(factor_name="close_return", status="completed"), [record])
            knowledge = database.get_factor_knowledge("close_return")
            self.assertEqual(knowledge.experiment_ids, [result.experiment_id])
            asset_root = root / "output" / "alpha_database"
            self.assertTrue((asset_root / "experiments" / "alpha-record-001.json").is_file())
            self.assertIn("not a promotion", (asset_root / "experiments" / "alpha-record-001.md").read_text(encoding="utf-8"))

    def test_failed_experiment_is_archived_once_with_a_failure_pattern(self) -> None:
        class BrokenAdapter:
            def run(self, experiment):
                raise RuntimeError("engine unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._write(root, "experiment.yaml", EXPERIMENT_YAML.replace("alpha-record-001", "alpha-failure-001"))
            runner = ExperimentRunner.local(root / "output", adapter=BrokenAdapter())
            first = runner.run_yaml(path)
            second = runner.run_yaml(path)
            database = AlphaDatabase(runner.store.config)

            self.assertEqual(first.status, "failed")
            self.assertEqual(first.experiment_id, second.experiment_id)
            patterns = database.query_failure_patterns(category="BACKTEST_FAILED", factor_name="close_return")
            self.assertEqual(len(patterns), 1)
            self.assertEqual(patterns[0].source_id, first.experiment_id)
            self.assertEqual(database.get_factor_knowledge("close_return").failure_pattern_ids, [patterns[0].pattern_id])

    def test_critic_nonpass_findings_are_archived_and_queryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validation = WalkForwardValidationEngine.local(root / "output").run_yaml(
                self._write(root, "validation.yaml", VALIDATION_YAML)
            )
            review = CriticAgent.local(root / "output").review(validation)
            database = AlphaDatabase(ResearchLabConfig(root / "output"))

            patterns = database.query_failure_patterns(source_id=review.review_id)
            self.assertTrue(patterns)
            self.assertTrue(all(pattern.source_kind == "critic_review" for pattern in patterns))
            self.assertEqual(
                database.query_failure_patterns(category="future_data")[0].pattern_id,
                f"{review.review_id}-future_data",
            )

    def test_ideas_literature_and_factor_history_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = AlphaDatabase(ResearchLabConfig(Path(directory) / "output"))
            idea = AlphaIdea(
                idea_id="idea-close-return", title="Close return", hypothesis="Prior close returns may be useful.",
                factor_names=["close_return"], tags=["momentum"],
            )
            reference = LiteratureReference(
                reference_id="paper-momentum", title="Momentum reference", citation="Author (2026)",
                factor_names=["close_return"],
            )
            database.save_idea(idea)
            database.save_idea(idea)
            database.save_literature_reference(reference)

            self.assertEqual(len(list((database.root / "ideas").glob("*.json"))), 1)
            self.assertEqual(len(database.query_factor_knowledge(factor_name="close_return")), 1)
            self.assertTrue((database.root / "literature" / "paper-momentum.md").is_file())


if __name__ == "__main__":
    unittest.main()
