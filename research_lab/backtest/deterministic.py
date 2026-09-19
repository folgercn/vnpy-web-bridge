import itertools
import math
from collections.abc import Sequence
from statistics import fmean, stdev

from research_lab.backtest.adapter import (
    BacktestAdapter,
    BacktestPoint,
    BacktestRun,
    BacktestTrade,
)
from research_lab.market_data import DefaultMarketDataProvider, MarketDataProvider
from research_lab.schemas import ExperimentSpec, PerformanceMetrics


class DeterministicBacktestAdapter(BacktestAdapter):
    """A dependency-free MVP engine using a replaceable MarketDataProvider."""

    def __init__(self, provider: MarketDataProvider | None = None) -> None:
        self.provider = provider or DefaultMarketDataProvider()

    def run(
        self,
        experiment: ExperimentSpec,
        *,
        multiplier: float | None = None,
        price_tick: float | None = None,
        margin_ratio: float | None = None,
        slippage_ticks: int | None = None,
        timestamps: Sequence[str] | None = None,
        lots: int | None = None,
    ) -> BacktestRun:
        if multiplier is not None:
            return self._run_single_contract(
                experiment,
                multiplier=multiplier,
                price_tick=price_tick if price_tick is not None else 1.0,
                margin_ratio=margin_ratio if margin_ratio is not None else 0.1,
                slippage_ticks=slippage_ticks if slippage_ticks is not None else 0,
                timestamps=timestamps,
                lots=lots,
            )
        return self._run_legacy_v1(experiment)

    def _run_legacy_v1(self, experiment: ExperimentSpec) -> BacktestRun:
        prices = self.provider.load(experiment).close_prices((experiment.universe[0],))
        if experiment.strategy.name == "buy_and_hold":
            positions = (0.0,) + (experiment.execution.position_size,) * (len(prices) - 1)
        else:
            positions = (0.0,) * len(prices)

        turnover = sum(abs(current - previous) for previous, current in itertools.pairwise(positions))
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

    def _run_single_contract(
        self,
        experiment: ExperimentSpec,
        multiplier: float,
        price_tick: float,
        margin_ratio: float,
        slippage_ticks: int,
        timestamps: Sequence[str] | None,
        lots: int | None,
    ) -> BacktestRun:
        """Unified deterministic execution producing trade facts, points, fees and equity directly from the adapter."""
        prices = self.provider.load(experiment).close_prices((experiment.universe[0],))
        n_prices = len(prices)
        ts_list = list(timestamps) if timestamps is not None and len(timestamps) == n_prices else [
            f"2024-01-02T09:0{i}:00.000000Z" for i in range(n_prices)
        ]

        initial_capital = experiment.execution.initial_capital
        commission_bps = experiment.cost_model.bps
        lots_val = lots if lots is not None else max(1, round(experiment.execution.position_size))

        if experiment.strategy.name == "buy_and_hold":
            positions = (0.0,) + (float(lots_val),) * (n_prices - 1)
        else:
            positions = (0.0,) * n_prices

        trades: list[BacktestTrade] = []
        total_fees = 0.0
        entry_price = 0.0

        # Step 0: initial state before trading
        equity_curve = [initial_capital]
        points: list[BacktestPoint] = [
            BacktestPoint(timestamp=ts_list[0], equity=initial_capital, cash=initial_capital, margin=0.0)
        ]

        # Step 1..n-1: process steps with actual trades, fees, and mark-to-market equity
        for i in range(1, n_prices):
            diff = round(positions[i] - positions[i - 1])
            if diff != 0:
                side = "BUY" if diff > 0 else "SELL"
                vol = abs(diff)
                p = prices[i]
                turnover = p * multiplier * vol
                commission_fee = turnover * (commission_bps / 10_000.0)
                slippage_cost = slippage_ticks * price_tick * multiplier * vol
                trade_fee = commission_fee + slippage_cost
                total_fees += trade_fee
                entry_price = p
                trades.append(
                    BacktestTrade(
                        trade_id=f"T{len(trades) + 1:03d}",
                        timestamp=ts_list[i],
                        side=side,
                        price=p,
                        volume=vol,
                        fee=trade_fee,
                        turnover=turnover,
                    )
                )

            pos = positions[i]
            floating_pnl = (prices[i] - entry_price) * multiplier * pos if pos != 0 else 0.0
            equity = initial_capital + floating_pnl - total_fees
            margin = abs(pos) * prices[i] * multiplier * margin_ratio
            cash = equity - margin

            equity_curve.append(equity)
            points.append(BacktestPoint(timestamp=ts_list[i], equity=equity, cash=cash, margin=margin))

        # Metrics calculation
        returns = [
            equity_curve[index] / equity_curve[index - 1] - 1.0
            for index in range(1, len(equity_curve))
            if equity_curve[index - 1] > 0
        ]
        running_peak = equity_curve[0]
        max_drawdown = 0.0
        for value in equity_curve:
            running_peak = max(running_peak, value)
            if running_peak > 0:
                max_drawdown = min(max_drawdown, value / running_peak - 1.0)
        sharpe = 0.0
        if len(returns) > 1 and stdev(returns) > 0:
            sharpe = fmean(returns) / stdev(returns) * math.sqrt(252)

        total_turnover = sum(t.turnover for t in trades)
        metrics = PerformanceMetrics(
            total_return=equity_curve[-1] / equity_curve[0] - 1.0,
            sharpe=sharpe,
            max_drawdown=max_drawdown,
            turnover=total_turnover,
            transaction_cost=total_fees,
            final_equity=equity_curve[-1],
        )

        return BacktestRun(
            metrics=metrics,
            equity_curve=tuple(equity_curve),
            positions=positions,
            trades=tuple(trades),
            points=tuple(points),
            total_fees=total_fees,
        )
