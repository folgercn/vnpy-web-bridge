from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol, Sequence

from research_lab.schemas import ExperimentSpec, PerformanceMetrics


class StrategyLoader(Protocol):
    def load(self, experiment: ExperimentSpec) -> Sequence[float]: ...


class MarketDataProvider(Protocol):
    def load_prices(self, experiment: ExperimentSpec) -> Sequence[float]: ...


class ExecutionSimulator(Protocol):
    def transaction_cost(self, turnover: float, cost_bps: float) -> float: ...


class PortfolioManager(Protocol):
    def equity_curve(self, prices: Sequence[float], positions: Sequence[float], initial_capital: float) -> Sequence[float]: ...


class MetricsCalculator(Protocol):
    def calculate(self, equity_curve: Sequence[float], turnover: float, transaction_cost: float) -> PerformanceMetrics: ...


@dataclass(frozen=True)
class BacktestRun:
    metrics: PerformanceMetrics
    equity_curve: tuple[float, ...]
    positions: tuple[float, ...]


class BacktestAdapter(ABC):
    """Stable runner boundary; engines can be replaced without changing Runner."""

    @abstractmethod
    def run(self, experiment: ExperimentSpec) -> BacktestRun:
        raise NotImplementedError
