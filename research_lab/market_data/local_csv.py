from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from research_lab.schemas import ExperimentSpec

from .dataset import DatasetRow, NormalizedDataset
from .provider import MarketDataError, MarketDataProvider


_COLUMNS = ("timestamp", "symbol", "open", "high", "low", "close", "volume", "open_interest")


class LocalCSVProvider(MarketDataProvider):
    """Load a UTF-8 CSV with the normalized Dataset schema columns."""

    def load(self, experiment: ExperimentSpec) -> NormalizedDataset:
        spec = experiment.dataset
        if spec.provider != "local_csv" or spec.path is None:
            raise MarketDataError("LocalCSVProvider requires a local_csv dataset request")
        path = Path(spec.path)
        try:
            with path.open("r", encoding="utf-8", newline="") as source:
                reader = csv.DictReader(source)
                if reader.fieldnames is None:
                    raise MarketDataError("CSV must include a header row")
                if tuple(reader.fieldnames) != _COLUMNS:
                    raise MarketDataError(
                        "CSV columns must be exactly: " + ", ".join(_COLUMNS)
                    )
                rows = tuple(self._parse_row(row, row_number) for row_number, row in enumerate(reader, start=2))
        except OSError as exc:
            raise MarketDataError(f"unable to read CSV: {path}") from exc
        return NormalizedDataset(name=spec.name, rows=rows)

    @staticmethod
    def _parse_row(row: dict[str, str | None], row_number: int) -> DatasetRow:
        if None in row:
            raise MarketDataError(f"CSV row {row_number} has surplus columns")
        if any(row.get(column) is None or not row[column].strip() for column in _COLUMNS):
            raise MarketDataError(f"CSV row {row_number} has missing required values")
        timestamp_text = row["timestamp"]
        assert timestamp_text is not None
        try:
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MarketDataError(f"CSV row {row_number} has invalid ISO-8601 timestamp") from exc
        try:
            values = {column: float(row[column]) for column in _COLUMNS[2:]}
        except (TypeError, ValueError) as exc:
            raise MarketDataError(f"CSV row {row_number} has non-numeric market data") from exc
        symbol = row["symbol"]
        assert symbol is not None
        return DatasetRow(timestamp=timestamp, symbol=symbol.strip(), **values)
