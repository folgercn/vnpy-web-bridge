from __future__ import annotations

import hashlib
import json
from pathlib import Path
from statistics import fmean, pstdev

from research_lab.backtest import BacktestAdapter, DeterministicBacktestAdapter
from research_lab.experiments import load_validation
from research_lab.market_data import DefaultMarketDataProvider, MarketDataProvider, NormalizedDataset
from research_lab.reports import write_validation_report
from research_lab.runners import ExperimentRunner
from research_lab.schemas import (
    DegradationAnalysis, ExperimentResult, RegimeSummary, StabilityAnalysis,
    ValidationFold, ValidationFoldResult, ValidationResult, ValidationSpec,
)


class ValidationExecutionError(ValueError):
    """Raised when a validation plan cannot produce a safe fold."""


class _FoldProvider(MarketDataProvider):
    """Return one immutable normalized slice for both features and backtesting."""

    def __init__(self, dataset: NormalizedDataset) -> None:
        self.dataset = dataset

    def load(self, _experiment) -> NormalizedDataset:
        return self.dataset


class _FoldAdapter(BacktestAdapter):
    """Give the existing runner a sliced provider without changing its interface."""

    def __init__(self, adapter: BacktestAdapter, provider: MarketDataProvider) -> None:
        self.provider = provider
        self._adapter = (
            DeterministicBacktestAdapter(provider)
            if isinstance(adapter, DeterministicBacktestAdapter)
            else adapter
        )

    def run(self, experiment):
        return self._adapter.run(experiment)


def generate_folds(spec: ValidationSpec, observation_count: int) -> list[ValidationFold]:
    """Generate ordered, disjoint observation windows with no test lookahead."""
    if observation_count < spec.train_size + spec.test_size:
        raise ValidationExecutionError("dataset does not contain one complete train/test fold")
    if spec.method == "train_test_split":
        if observation_count != spec.train_size + spec.test_size:
            raise ValidationExecutionError("train_test_split must account for every observation")
        return [ValidationFold(
            index=1, train_start=0, train_end=spec.train_size,
            test_start=spec.train_size, test_end=observation_count,
        )]

    folds: list[ValidationFold] = []
    index = 1
    test_start = spec.train_size
    while test_start + spec.test_size <= observation_count:
        train_start = 0 if spec.method == "walk_forward" else test_start - spec.train_size
        folds.append(ValidationFold(
            index=index, train_start=train_start, train_end=test_start,
            test_start=test_start, test_end=test_start + spec.test_size,
        ))
        test_start += spec.effective_step_size
        index += 1
    if not folds:
        raise ValidationExecutionError("dataset does not contain one complete train/test fold")
    return folds


def _fold_experiment_id(validation_id: str, original_id: str, fold: ValidationFold, split: str) -> str:
    identity = {
        "validation_id": validation_id, "experiment_id": original_id,
        "fold": fold.model_dump(), "split": split,
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    suffix = f"-f{fold.index}-{split}-{digest}"
    return f"{validation_id[:128 - len(suffix)]}{suffix}"


def _select_rows(dataset: NormalizedDataset, symbol: str) -> tuple:
    rows = tuple(row for row in dataset.rows if row.symbol == symbol)
    if len(rows) < 2:
        raise ValidationExecutionError(f"dataset needs at least two rows for requested symbol: {symbol}")
    return rows


def _sliced_dataset(dataset: NormalizedDataset, rows: tuple, fold: ValidationFold, split: str) -> NormalizedDataset:
    return NormalizedDataset(name=f"{dataset.name}:{fold.index}:{split}", rows=rows)


def _summaries(folds: list[ValidationFoldResult]) -> tuple[StabilityAnalysis | None, DegradationAnalysis | None, list[RegimeSummary]]:
    pairs = [
        item for item in folds
        if item.in_sample.metrics is not None and item.out_of_sample.metrics is not None
        and item.in_sample.status == "completed" and item.out_of_sample.status == "completed"
    ]
    grouped: dict[str, list[float]] = {"positive": [], "flat": [], "negative": []}
    for item in pairs:
        score = item.out_of_sample.metrics.total_return
        grouped["positive" if score > 0 else "negative" if score < 0 else "flat"].append(score)
    regimes = [
        RegimeSummary(regime=name, completed_folds=len(values), mean_total_return=fmean(values) if values else None)
        for name, values in grouped.items()
    ]
    if not pairs:
        return None, None, regimes

    is_returns = [item.in_sample.metrics.total_return for item in pairs]
    oos_returns = [item.out_of_sample.metrics.total_return for item in pairs]
    is_sharpes = [item.in_sample.metrics.sharpe for item in pairs]
    oos_sharpes = [item.out_of_sample.metrics.sharpe for item in pairs]
    mean_is_sharpe = fmean(is_sharpes)
    mean_oos_sharpe = fmean(oos_sharpes)
    sharpe_stddev = pstdev(oos_sharpes)
    positive_fraction = sum(value > 0 for value in oos_returns) / len(oos_returns)
    degradation_factor = max(0.0, 1.0 - max(0.0, mean_is_sharpe - mean_oos_sharpe) / (abs(mean_is_sharpe) + 1.0))
    consistency_factor = 1.0 / (1.0 + sharpe_stddev)
    stability = StabilityAnalysis(
        completed_folds=len(pairs),
        stability_score=100.0 * positive_fraction * consistency_factor * degradation_factor,
        positive_oos_fraction=positive_fraction,
        oos_sharpe_stddev=sharpe_stddev,
    )
    degradation = DegradationAnalysis(
        completed_folds=len(pairs),
        mean_in_sample_total_return=fmean(is_returns),
        mean_out_of_sample_total_return=fmean(oos_returns),
        total_return_delta=fmean(oos_returns) - fmean(is_returns),
        mean_in_sample_sharpe=mean_is_sharpe,
        mean_out_of_sample_sharpe=mean_oos_sharpe,
        sharpe_delta=mean_oos_sharpe - mean_is_sharpe,
    )
    return stability, degradation, regimes


class WalkForwardValidationEngine:
    """Local deterministic IS/OOS validation through the stable ExperimentRunner API.

    The bundled deterministic adapter validates only ``universe[0]``. It does
    not infer market regimes, select alpha candidates, or promote any result.
    """

    execution_mode = "local_sequential"

    def __init__(self, runner: ExperimentRunner) -> None:
        self.runner = runner

    @classmethod
    def local(cls, root: Path | str, adapter: BacktestAdapter | None = None) -> "WalkForwardValidationEngine":
        return cls(ExperimentRunner.local(root, adapter))

    def run_yaml(self, path: Path | str) -> ValidationResult:
        return self.run(load_validation(path))

    def run(self, spec: ValidationSpec) -> ValidationResult:
        provider = getattr(self.runner.adapter, "provider", None) or DefaultMarketDataProvider()
        dataset = provider.load(spec.experiment)
        rows = _select_rows(dataset, spec.experiment.universe[0])
        folds = generate_folds(spec, len(rows))
        results: list[ValidationFoldResult] = []
        for fold in folds:
            in_sample = self._run_slice(spec, dataset, rows[fold.train_start:fold.train_end], fold, "is")
            out_of_sample = self._run_slice(spec, dataset, rows[fold.test_start:fold.test_end], fold, "oos")
            results.append(ValidationFoldResult(fold=fold, in_sample=in_sample, out_of_sample=out_of_sample))
        stability, degradation, regimes = _summaries(results)
        status = "completed" if all(
            item.in_sample.status == "completed" and item.out_of_sample.status == "completed" for item in results
        ) else "completed_with_failures"
        result = ValidationResult(
            validation_id=spec.validation_id, status=status, method=spec.method,
            folds=results, stability=stability, degradation=degradation, regimes=regimes,
        )
        stored = self.runner.store.save_validation(result)
        report_path = write_validation_report(self.runner.store.config.artifacts_dir, stored)
        return self.runner.store.save_validation(stored.model_copy(update={"report_location": str(report_path)}))

    def _run_slice(self, spec: ValidationSpec, dataset: NormalizedDataset, rows: tuple, fold: ValidationFold, split: str) -> ExperimentResult:
        experiment = spec.experiment.model_copy(update={
            "experiment_id": _fold_experiment_id(spec.validation_id, spec.experiment.experiment_id, fold, split),
        })
        adapter = _FoldAdapter(self.runner.adapter, _FoldProvider(_sliced_dataset(dataset, rows, fold, split)))
        return ExperimentRunner(self.runner.store, adapter).run(experiment)
