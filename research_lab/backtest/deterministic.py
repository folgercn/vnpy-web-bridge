from __future__ import annotations

import math
from statistics import fmean, stdev

from research_lab.backtest.adapter import BacktestAdapter, BacktestRun
from research_lab.market_data import DefaultMarketDataProvider, MarketDataProvider
from research_lab.schemas import ExperimentSpec, PerformanceMetrics


class DeterministicBacktestAdapter(BacktestAdapter):
    """A dependency-free MVP engine using a replaceable MarketDataProvider."""

    def __init__(self, provider: MarketDataProvider | None = None) -> None:
        self.provider = provider or DefaultMarketDataProvider()

    def run(self, experiment: ExperimentSpec) -> BacktestRun:
        # The MVP engine has always run one shared price series. Keep legacy
        # inline YAML with multi-symbol universes compatible by using its first
        # symbol as the deterministic series selector.
        prices = self.provider.load(experiment).close_prices((experiment.universe[0],))
        if experiment.strategy.name == "buy_and_hold":
            positions = (0.0,) + (experiment.execution.position_size,) * (len(prices) - 1)
        else:
            positions = (0.0,) * len(prices)

        turnover = sum(abs(current - previous) for previous, current in zip(positions, positions[1:]))
        notional = experiment.execution.initial_capital * turnover
        transaction_cost = notional * experiment.cost_model.bps / 10_000
        equity_curve = [experiment.execution.initial_capital]
        for index in range(1, len(prices)):
            price_return = prices[index] / prices[index - 1] - 1.0
            equity_curve.append(equity_curve[-1] * (1 + positions[index] * price_return))
        equity_curve[-1] -= transaction_cost

        returns = [equity_curve[index] / equity_curve[index - 1] - 1.0 for index in range(1, len(equity_curve))]
        running_peak = equity_curve[0]
        max_drawdown = 0.0
        for value in equity_curve:
            running_peak = max(running_peak, value)
            max_drawdown = min(max_drawdown, value / running_peak - 1.0)
        sharpe = 0.0
        if len(returns) > 1 and stdev(returns) > 0:
            sharpe = fmean(returns) / stdev(returns) * math.sqrt(252)
        metrics = PerformanceMetrics(
            total_return=equity_curve[-1] / equity_curve[0] - 1.0,
            sharpe=sharpe,
            max_drawdown=max_drawdown,
            turnover=turnover,
            transaction_cost=transaction_cost,
            final_equity=equity_curve[-1],
        )
        return BacktestRun(metrics=metrics, equity_curve=tuple(equity_curve), positions=positions)
