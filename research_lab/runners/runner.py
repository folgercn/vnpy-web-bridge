from __future__ import annotations

from pathlib import Path

from research_lab.backtest import BacktestAdapter, DeterministicBacktestAdapter
from research_lab.alpha_database import AlphaDatabase
from research_lab.config import ResearchLabConfig
from research_lab.database import ResultStore
from research_lab.experiments import load_experiment
from research_lab.features import FeatureStore
from research_lab.market_data import DefaultMarketDataProvider
from research_lab.reports import write_report
from research_lab.schemas import ExperimentResult, ExperimentSpec


class ExperimentRunner:
    def __init__(self, store: ResultStore, adapter: BacktestAdapter | None = None) -> None:
        self.store = store
        self.adapter = adapter or DeterministicBacktestAdapter()
        self.feature_store = FeatureStore(self.store.config)
        self.alpha_database = AlphaDatabase(self.store.config)

    @classmethod
    def local(cls, root: Path | str, adapter: BacktestAdapter | None = None) -> "ExperimentRunner":
        return cls(ResultStore(ResearchLabConfig(Path(root))), adapter)

    def run_yaml(self, path: Path | str) -> ExperimentResult:
        experiment = load_experiment(path)
        return self.run(experiment)

    def run(self, experiment: ExperimentSpec) -> ExperimentResult:
        try:
            provider = getattr(self.adapter, "provider", None) or DefaultMarketDataProvider()
            features = self.feature_store.compute(experiment, provider)
            run = self.adapter.run(experiment)
        except Exception as exc:
            failed = ExperimentResult(
                experiment_id=experiment.experiment_id, status="failed",
                strategy_name=experiment.strategy.name, factor_name=experiment.factor.name,
                error_code="BACKTEST_FAILED", error_message=str(exc),
            )
            return self._save_and_archive(failed)
        result = ExperimentResult(
            experiment_id=experiment.experiment_id, status="completed",
            strategy_name=experiment.strategy.name, factor_name=experiment.factor.name,
            metrics=run.metrics,
            details={"equity_curve": list(run.equity_curve), "positions": list(run.positions),
                     "features": [feature.lineage for feature in features]},
        )
        stored = self.store.save(result)
        report_path = write_report(self.store.config.artifacts_dir, stored)
        return self._save_and_archive(stored.model_copy(update={"report_location": str(report_path)}))

    def _save_and_archive(self, result: ExperimentResult) -> ExperimentResult:
        stored = self.store.save(result)
        self.alpha_database.archive_experiment(stored)
        return stored
