from __future__ import annotations

from datetime import datetime, timedelta, timezone

from research_lab.schemas import ExperimentSpec

from .dataset import DatasetRow, NormalizedDataset
from .provider import MarketDataError, MarketDataProvider


class InlinePriceProvider(MarketDataProvider):
    """Compatibility provider for the original inline `dataset.prices` YAML."""

    def load(self, experiment: ExperimentSpec) -> NormalizedDataset:
        spec = experiment.dataset
        if spec.provider != "inline" or spec.prices is None:
            raise MarketDataError("InlinePriceProvider requires an inline dataset request")
        start = datetime(1970, 1, 1, tzinfo=timezone.utc)
        symbol = experiment.universe[0]
        rows = tuple(
            DatasetRow(
                timestamp=start + timedelta(days=index), symbol=symbol,
                open=price, high=price, low=price, close=price,
                volume=0.0, open_interest=0.0,
            )
            for index, price in enumerate(spec.prices)
        )
        return NormalizedDataset(name=spec.name, rows=rows)
