from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import math

from .provider import MarketDataError


@dataclass(frozen=True)
class DatasetRow:
    """One normalized OHLCV/open-interest observation."""

    timestamp: datetime
    symbol: str
    open: float
    high: float
    low: float
    close: float
    volume: float
    open_interest: float


@dataclass(frozen=True)
class NormalizedDataset:
    """Provider-independent tabular dataset consumed by backtest adapters."""

    name: str
    rows: tuple[DatasetRow, ...]

    def __post_init__(self) -> None:
        if len(self.rows) < 2:
            raise MarketDataError("dataset must contain at least two rows")
        previous_timestamps: dict[str, datetime] = {}
        for row in self.rows:
            if not row.symbol.strip():
                raise MarketDataError("dataset symbol must be nonempty")
            if row.timestamp.tzinfo is None:
                raise MarketDataError("dataset timestamps must include a timezone")
            prices = (row.open, row.high, row.low, row.close)
            if any(not math.isfinite(value) or value <= 0 for value in prices):
                raise MarketDataError("OHLC prices must be finite and positive")
            if row.low > min(row.open, row.close) or row.high < max(row.open, row.close):
                raise MarketDataError("OHLC prices must satisfy low <= open/close <= high")
            if any(not math.isfinite(value) or value < 0 for value in (row.volume, row.open_interest)):
                raise MarketDataError("volume and open_interest must be finite and nonnegative")
            previous = previous_timestamps.get(row.symbol)
            if previous is not None and row.timestamp <= previous:
                raise MarketDataError("timestamps must be strictly increasing for each symbol")
            previous_timestamps[row.symbol] = row.timestamp

    def close_prices(self, symbols: tuple[str, ...]) -> tuple[float, ...]:
        requested = set(symbols)
        rows = tuple(row for row in self.rows if row.symbol in requested)
        present = {row.symbol for row in rows}
        missing = requested - present
        if missing:
            raise MarketDataError(f"dataset is missing requested symbols: {', '.join(sorted(missing))}")
        if len(present) != 1:
            raise MarketDataError("the deterministic adapter supports exactly one symbol")
        if len(rows) < 2:
            raise MarketDataError("dataset must contain at least two rows for the requested symbol")
        return tuple(row.close for row in rows)
