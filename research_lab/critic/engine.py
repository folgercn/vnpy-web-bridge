from __future__ import annotations

import hashlib
from pathlib import Path

from research_lab.alpha_database import AlphaDatabase
from research_lab.config import ResearchLabConfig
from research_lab.database import ResultStore
from research_lab.schemas import CriticFinding, CriticReview, ValidationResult


def _safe_identity(prefix: str, *parts: str) -> str:
    text = "-".join((prefix, *parts))
    if len(text) <= 128:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{text[:111]}-{digest}"


def _completed_pairs(result: ValidationResult) -> list:
    return [
        fold for fold in result.folds
        if fold.in_sample.status == "completed" and fold.out_of_sample.status == "completed"
        and fold.in_sample.metrics is not None and fold.out_of_sample.metrics is not None
    ]


class CriticAgent:
    """Deterministic local reviewer of a persisted walk-forward result.

    The reviewer only assesses evidence present in ``ValidationResult``. It
    never selects, promotes, deploys, or trades a candidate.
    """

    def __init__(self, store: ResultStore) -> None:
        self.store = store

    @classmethod
    def local(cls, root: Path | str) -> "CriticAgent":
        return cls(ResultStore(ResearchLabConfig(Path(root))))

    def review_persisted(self, validation_id: str, *, candidate_id: str | None = None) -> CriticReview:
        result = self.store.get_validation(validation_id)
        if result is None:
            raise ValueError(f"validation result not found: {validation_id}")
        return self.review(result, candidate_id=candidate_id)

    def review(self, result: ValidationResult, *, candidate_id: str | None = None) -> CriticReview:
        candidate = candidate_id or self._candidate_id(result)
        findings = self._findings(result)
        recommendation = self._recommendation(findings)
        confidence = sum(item.assessment == "pass" for item in findings) / len(findings)
        review = CriticReview(
            review_id=_safe_identity(result.validation_id, "critic", "v1"),
            validation_id=result.validation_id,
            candidate_id=candidate,
            recommendation=recommendation,
            confidence=confidence,
            findings=findings,
        )
        stored = self.store.save_critic_review(review)
        from research_lab.reports import write_critic_report

        report_path = write_critic_report(self.store.config.artifacts_dir, stored)
        stored = self.store.save_critic_review(stored.model_copy(update={"report_location": str(report_path)}))
        AlphaDatabase(self.store.config, result_store=self.store).archive_critic_review(stored, validation=result)
        return stored

    @staticmethod
    def _candidate_id(result: ValidationResult) -> str:
        if not result.folds:
            return "unknown-candidate"
        item = result.folds[0].in_sample
        return _safe_identity(item.strategy_name, item.factor_name)

    @staticmethod
    def _recommendation(findings: list[CriticFinding]) -> str:
        if any(item.severity == "critical" and item.assessment == "risk" for item in findings):
            return "reject"
        if any(item.assessment != "pass" for item in findings):
            return "improve"
        return "accept"

    @staticmethod
    def _findings(result: ValidationResult) -> list[CriticFinding]:
        pairs = _completed_pairs(result)
        boundaries_ok = bool(result.folds) and all(
            fold.fold.train_start < fold.fold.train_end <= fold.fold.test_start < fold.fold.test_end
            for fold in result.folds
        )
        boundary = CriticFinding(
            category="fold_boundary",
            assessment="pass" if boundaries_ok else "risk",
            severity="info" if boundaries_ok else "critical",
            summary=(
                "Recorded IS/OOS fold boundaries are ordered and disjoint."
                if boundaries_ok else "No recorded folds, or recorded fold boundaries overlap or are out of order."
            ),
            evidence=[
                f"fold={item.fold.index}: train=[{item.fold.train_start},{item.fold.train_end}), "
                f"test=[{item.fold.test_start},{item.fold.test_end})" for item in result.folds
            ] or ["ValidationResult.folds is empty."],
            required_additional_tests=[] if boundaries_ok else ["Record at least one ordered, disjoint IS/OOS fold."],
        )
        future_data = CriticFinding(
            category="future_data", assessment="insufficient_evidence", severity="warning",
            summary="ValidationResult has no feature availability timestamps or preprocessing lineage.",
            evidence=["ValidationResult records fold metrics and index boundaries only."],
            required_additional_tests=["Record feature timestamps and verify each feature is available at decision time."],
        )
        if result.degradation is None:
            degradation = CriticFinding(
                category="overfit_degradation", assessment="insufficient_evidence", severity="warning",
                summary="No completed IS/OOS metric pairs are available for degradation assessment.",
                evidence=[f"status={result.status}; completed_pairs={len(pairs)}"],
                required_additional_tests=["Run completed IS/OOS folds before assessing degradation."],
            )
        else:
            weak = result.degradation.total_return_delta < 0 or result.degradation.sharpe_delta < 0
            degradation = CriticFinding(
                category="overfit_degradation", assessment="risk" if weak else "pass",
                severity="warning" if weak else "info",
                summary=("OOS metrics are weaker than IS on at least one recorded aggregate." if weak
                         else "Recorded aggregate OOS metrics do not degrade from IS."),
                evidence=[
                    f"total_return_delta={result.degradation.total_return_delta:.6f}",
                    f"sharpe_delta={result.degradation.sharpe_delta:.6f}",
                    f"completed_pairs={result.degradation.completed_folds}",
                ],
                required_additional_tests=["Test additional untouched periods and parameter neighborhoods."] if weak else [],
            )
        sample = CriticFinding(
            category="sample_selection", assessment="insufficient_evidence", severity="warning",
            summary="Candidate selection history and dataset inclusion rules are not stored in ValidationResult.",
            evidence=[f"method={result.method}; completed_pairs={len(pairs)}; total_folds={len(result.folds)}"],
            required_additional_tests=["Record candidate-generation and universe-selection lineage; validate on an untouched sample."],
        )
        parameter = CriticFinding(
            category="parameter_stability", assessment="insufficient_evidence", severity="warning",
            summary="ValidationResult has no parameter-neighborhood or perturbation results.",
            evidence=["ValidationResult records fold outcomes, not parameter stability evidence."],
            required_additional_tests=["Run a parameter-neighborhood sweep on untouched validation periods."],
        )
        costs = [item.out_of_sample.metrics.transaction_cost for item in pairs]
        returns = [item.out_of_sample.metrics.total_return for item in pairs]
        if not costs:
            cost = CriticFinding(
                category="transaction_cost", assessment="insufficient_evidence", severity="warning",
                summary="No completed OOS transaction-cost metrics are available.",
                evidence=[f"completed_pairs={len(pairs)}"],
                required_additional_tests=["Run OOS validation with an explicit transaction-cost model."],
            )
        elif all(value == 0 for value in costs):
            cost = CriticFinding(
                category="transaction_cost", assessment="insufficient_evidence", severity="warning",
                summary="Recorded OOS transaction cost is zero, so cost sensitivity is unassessed.",
                evidence=[f"mean_oos_transaction_cost={sum(costs) / len(costs):.6f}"],
                required_additional_tests=["Repeat OOS validation across documented non-zero cost assumptions."],
            )
        elif sum(returns) / len(returns) <= sum(costs) / len(costs):
            cost = CriticFinding(
                category="transaction_cost", assessment="risk", severity="warning",
                summary="Mean recorded OOS return does not exceed mean recorded transaction cost.",
                evidence=[f"mean_oos_return={sum(returns) / len(returns):.6f}", f"mean_oos_transaction_cost={sum(costs) / len(costs):.6f}"],
                required_additional_tests=["Repeat OOS validation across documented cost assumptions."],
            )
        else:
            cost = CriticFinding(
                category="transaction_cost", assessment="insufficient_evidence", severity="warning",
                summary="A single recorded cost model does not establish transaction-cost sensitivity.",
                evidence=[f"mean_oos_return={sum(returns) / len(returns):.6f}", f"mean_oos_transaction_cost={sum(costs) / len(costs):.6f}"],
                required_additional_tests=["Repeat OOS validation across documented cost assumptions."],
            )
        regime = CriticFinding(
            category="regime_dependence", assessment="insufficient_evidence", severity="warning",
            summary="Return-sign groups are not market-regime labels, so regime dependence is unassessed.",
            evidence=[f"{item.regime}: completed_folds={item.completed_folds}" for item in result.regimes],
            required_additional_tests=["Define market-regime inputs before testing OOS performance by regime."],
        )
        return [boundary, future_data, degradation, sample, parameter, cost, regime]
