from __future__ import annotations

import inspect
from pathlib import Path
import tempfile
import unittest

from research_lab.critic import CriticAgent
from research_lab.runners import ExperimentRunner
from research_lab.schemas import CriticFinding
from research_lab.validation import WalkForwardValidationEngine
from pydantic import ValidationError


VALIDATION_YAML = """\
schema_version: research_lab.validation.v1
validation_id: critic-validation-001
method: walk_forward
train_size: 3
test_size: 2
step_size: 2
experiment:
  schema_version: research_lab.experiment.v1
  experiment_id: critic-base-001
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


class CriticAgentTest(unittest.TestCase):
    def _validation(self, root: Path):
        path = root / "validation.yaml"
        path.write_text(VALIDATION_YAML, encoding="utf-8")
        return WalkForwardValidationEngine.local(root / "output").run_yaml(path)

    def test_review_covers_all_required_categories_and_evidence_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._validation(Path(directory))
            review = CriticAgent.local(Path(directory) / "output").review(result)

        findings = {item.category: item for item in review.findings}
        self.assertEqual(set(findings), {
            "fold_boundary", "future_data", "overfit_degradation", "sample_selection",
            "parameter_stability", "transaction_cost", "regime_dependence",
        })
        self.assertEqual(findings["fold_boundary"].assessment, "pass")
        self.assertEqual(findings["future_data"].assessment, "insufficient_evidence")
        self.assertEqual(findings["sample_selection"].assessment, "insufficient_evidence")
        self.assertEqual(findings["parameter_stability"].assessment, "insufficient_evidence")
        self.assertEqual(findings["transaction_cost"].assessment, "insufficient_evidence")
        self.assertEqual(findings["regime_dependence"].assessment, "insufficient_evidence")
        self.assertEqual(review.recommendation, "improve")
        self.assertLess(review.confidence, 1.0)

    def test_detects_recorded_boundary_and_degradation_risks_without_claiming_future_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._validation(Path(directory))
            bad_fold = result.folds[0].model_copy(update={
                "fold": result.folds[0].fold.model_copy(update={"test_start": 1}),
            })
            degraded = result.degradation.model_copy(update={"sharpe_delta": -1.0})
            review = CriticAgent.local(Path(directory) / "output").review(result.model_copy(update={
                "folds": [bad_fold, *result.folds[1:]], "degradation": degraded,
            }))

        findings = {item.category: item for item in review.findings}
        self.assertEqual(findings["fold_boundary"].assessment, "risk")
        self.assertEqual(findings["fold_boundary"].severity, "critical")
        self.assertEqual(findings["overfit_degradation"].assessment, "risk")
        self.assertEqual(findings["future_data"].assessment, "insufficient_evidence")
        self.assertEqual(review.recommendation, "reject")

    def test_cost_risk_requires_recorded_cost_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._validation(Path(directory))
            folds = []
            for fold in result.folds:
                metrics = fold.out_of_sample.metrics.model_copy(update={"total_return": 0.01, "transaction_cost": 0.02})
                folds.append(fold.model_copy(update={"out_of_sample": fold.out_of_sample.model_copy(update={"metrics": metrics})}))
            review = CriticAgent.local(Path(directory) / "output").review(result.model_copy(update={"folds": folds}))

        finding = next(item for item in review.findings if item.category == "transaction_cost")
        self.assertEqual(finding.assessment, "risk")

    def test_empty_folds_rejects_and_pass_findings_require_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._validation(Path(directory))
            review = CriticAgent.local(Path(directory) / "output").review(result.model_copy(update={"folds": []}))

        finding = next(item for item in review.findings if item.category == "fold_boundary")
        self.assertEqual(finding.assessment, "risk")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(review.recommendation, "reject")
        with self.assertRaises(ValidationError):
            CriticFinding(
                category="fold_boundary", assessment="pass", severity="info", summary="unsupported pass",
            )

    def test_persists_queries_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self._validation(root)
            agent = CriticAgent.local(root / "output")
            first = agent.review(result, candidate_id="candidate-001")
            second = agent.review_persisted(result.validation_id, candidate_id="candidate-001")

            self.assertEqual(first, second)
            self.assertTrue(Path(first.artifact_location).is_file())
            self.assertTrue(Path(first.report_location).is_file())
            self.assertIn("never a promotion", Path(first.report_location).read_text(encoding="utf-8"))
            self.assertEqual(agent.store.get_critic_review(first.review_id), first)
            self.assertEqual(agent.store.query_critic_reviews(validation_id=result.validation_id), [first])
            self.assertEqual(agent.store.query_critic_reviews(candidate_id="candidate-001"), [first])
            self.assertEqual(agent.store.query_critic_reviews(category="future_data"), [first])
            self.assertEqual(agent.store.query_critic_reviews(category="parameter_stability"), [first])
            self.assertEqual(agent.store.query_critic_reviews(category="fold_boundary"), [])

    def test_critic_does_not_change_experiment_runner_api(self) -> None:
        self.assertEqual(list(inspect.signature(ExperimentRunner.run).parameters), ["self", "experiment"])
        self.assertEqual(list(inspect.signature(ExperimentRunner.run_yaml).parameters), ["self", "path"])
        self.assertFalse(hasattr(ExperimentRunner, "run_critic"))


if __name__ == "__main__":
    unittest.main()
