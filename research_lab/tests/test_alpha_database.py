from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

from research_lab.alpha_database import AlphaDatabase
from research_lab.config import ResearchLabConfig
from research_lab.critic import CriticAgent
from research_lab.database import ResultStore
from research_lab.runners import ExperimentRunner
from research_lab.schemas import AlphaIdea, ExperimentRecord, ExperimentResult, FactorKnowledge, LiteratureReference
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
            experiment_assets = list((asset_root / "experiments").glob("alpha-record-001--*.json"))
            self.assertEqual(len(experiment_assets), 1)
            markdown = experiment_assets[0].with_suffix(".md").read_text(encoding="utf-8")
            self.assertIn("not a promotion", markdown)
            for heading in ("## hypothesis", "## evidence", "## conclusion", "## next_action"):
                self.assertIn(heading, markdown)

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
            factor_patterns = database.query_failure_patterns(
                category="future_data", factor_name="close_return",
            )
            self.assertEqual([pattern.pattern_id for pattern in factor_patterns], [f"{review.review_id}-future_data"])
            knowledge = database.get_factor_knowledge("close_return")
            self.assertIn(f"{review.review_id}-future_data", knowledge.failure_pattern_ids)

    def test_sync_projects_existing_result_and_critic_history_without_rerunning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            validation = WalkForwardValidationEngine.local(root).run_yaml(
                self._write(Path(directory), "validation.yaml", VALIDATION_YAML)
            )
            agent = CriticAgent.local(root)
            review = agent.review(validation)
            shutil.rmtree(root / "alpha_database")

            database = AlphaDatabase(ResearchLabConfig(root), result_store=agent.store)
            first_counts = database.sync_from_result_store(agent.store)
            second_counts = database.sync_from_result_store(agent.store)

            self.assertEqual(first_counts, second_counts)
            self.assertTrue(database.query_experiments())
            self.assertEqual(
                database.query_failure_patterns(source_id=review.review_id, factor_name="close_return")[0].source_id,
                review.review_id,
            )
            self.assertEqual(len(list((database.root / "failure_patterns").glob("*.json"))), len({
                pattern.pattern_id for pattern in database.query_failure_patterns()
            }))

    def test_sync_projects_preexisting_result_store_records_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ResearchLabConfig(Path(directory) / "output")
            store = ResultStore(config)
            store.save(ExperimentResult(
                experiment_id="history-result-001", status="completed", strategy_name="flat",
                factor_name="historical-factor",
            ))

            database = AlphaDatabase(config, result_store=store)
            self.assertEqual(database.sync_from_result_store(store), (1, 0))
            self.assertEqual([record.experiment_id for record in database.query_experiments()], ["history-result-001"])
            self.assertEqual(database.get_factor_knowledge("historical-factor").experiment_ids, ["history-result-001"])

    def test_factor_asset_filenames_do_not_collide_for_legal_factor_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = AlphaDatabase(ResearchLabConfig(Path(directory) / "output"))
            first = database.save_factor_knowledge(FactorKnowledge(factor_name="mean/reversion"))
            second = database.save_factor_knowledge(FactorKnowledge(factor_name="mean?reversion"))

            self.assertEqual(database.get_factor_knowledge(first.factor_name), first)
            self.assertEqual(database.get_factor_knowledge(second.factor_name), second)
            self.assertEqual(len(list((database.root / "factors").glob("*.json"))), 2)

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
            self.assertEqual(len(list((database.root / "literature").glob("paper-momentum--*.md"))), 1)

    def test_changed_asset_keeps_versioned_history_and_injected_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = AlphaDatabase(
                ResearchLabConfig(Path(directory) / "output"), created_commit="test-commit-499",
            )
            first = database.save_experiment(ExperimentRecord(
                experiment_id="versioned-record-001", status="completed", strategy_name="flat",
                factor_name="versioned-factor", created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ))
            changed = database.save_experiment(ExperimentRecord(
                experiment_id="versioned-record-001", status="failed", strategy_name="flat",
                factor_name="versioned-factor", error_code="BACKTEST_FAILED",
                created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ))

            history = database.query_experiments(factor_name="versioned-factor")
            self.assertEqual({item.status for item in history}, {"completed", "failed"})
            self.assertEqual({item.content_hash for item in history}, {first.content_hash, changed.content_hash})
            self.assertTrue(all(item.created_commit == "test-commit-499" for item in history))
            self.assertEqual(database.get_experiment("versioned-record-001"), changed)
            self.assertEqual(len(list((database.root / "experiments").glob("versioned-record-001--*.json"))), 2)
            tampered_path = database.root / "experiments" / f"versioned-record-001--{first.content_hash}.json"
            tampered = json.loads(tampered_path.read_text(encoding="utf-8"))
            tampered["created_at"] = "2030-01-01T00:00:00+00:00"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "asset integrity error"):
                database.get_experiment("versioned-record-001")

    def test_markdown_marks_missing_evidence_and_records_available_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with_feature = EXPERIMENT_YAML.replace(
                "factor:\n", "features:\n  - name: close_return\nfactor:\n",
            ).replace("alpha-record-001", "lineage-record-001")
            ExperimentRunner.local(root / "output").run_yaml(self._write(root, "experiment.yaml", with_feature))
            validation_yaml = VALIDATION_YAML.replace(
                "factor:\n", "features:\n    - name: close_return\n  factor:\n",
            )
            validation = WalkForwardValidationEngine.local(root / "output").run_yaml(
                self._write(root, "validation.yaml", validation_yaml)
            )
            CriticAgent.local(root / "output").review(validation)
            database = AlphaDatabase(ResearchLabConfig(root / "output"))
            database.save_literature_reference(LiteratureReference(
                reference_id="lineage-paper-001", title="Lineage", citation="Author (2026)",
                factor_names=["close_return"],
            ))

            knowledge = database.get_factor_knowledge("close_return")
            self.assertTrue(knowledge.feature_lineage)
            self.assertEqual(knowledge.feature_lineage[0]["feature"]["name"], "close_return")
            self.assertTrue(knowledge.dataset_lineage[0]["input_data_identity"])
            self.assertIn(validation.validation_id, knowledge.validation_result_ids)
            self.assertIn("lineage-paper-001", knowledge.literature_reference_ids)
            factor_markdown = next((database.root / "factors").glob("close_return--*.md")).read_text(encoding="utf-8")
            self.assertIn("## evidence", factor_markdown)
            self.assertIn("unavailable: this asset does not record it", factor_markdown)


if __name__ == "__main__":
    unittest.main()
