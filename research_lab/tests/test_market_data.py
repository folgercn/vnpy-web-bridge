from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from research_lab.backtest import DeterministicBacktestAdapter
from research_lab.experiments import load_experiment
from research_lab.market_data import DatasetRow, LocalCSVProvider, MarketDataError, MarketDataProvider, NormalizedDataset
from research_lab.runners import ExperimentRunner


CSV_HEADER = "timestamp,symbol,open,high,low,close,volume,open_interest\n"
VALID_ROWS = (
    "2026-01-02T00:00:00+00:00,DEMO,100,101,99,100,10,20\n"
    "2026-01-05T00:00:00+00:00,DEMO,100,111,99,110,11,21\n"
    "2026-01-06T00:00:00+00:00,DEMO,110,122,109,121,12,22\n"
)


def local_csv_yaml(path: Path) -> str:
    return f"""\
schema_version: research_lab.experiment.v1
experiment_id: local-csv-test-001
strategy:
  name: buy_and_hold
factor:
  name: close_return
universe: [DEMO]
dataset:
  name: fixture
  provider: local_csv
  path: {path}
parameters: {{}}
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


class LocalCSVProviderTest(unittest.TestCase):
    def _load(self, root: Path, csv_content: str):
        csv_path = root / "prices.csv"
        yaml_path = root / "experiment.yaml"
        csv_path.write_text(csv_content, encoding="utf-8")
        yaml_path.write_text(local_csv_yaml(csv_path), encoding="utf-8")
        return load_experiment(yaml_path)

    def test_runner_loads_local_csv_through_default_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            experiment = self._load(root, CSV_HEADER + VALID_ROWS)

            result = ExperimentRunner.local(root / "output").run(experiment)

            self.assertEqual(result.status, "completed")
            self.assertAlmostEqual(result.metrics.total_return, 0.21)
            self.assertEqual(result.details["equity_curve"], [1000.0, 1100.0, 1210.0])

    def test_local_csv_rejects_bad_schema_and_values(self) -> None:
        cases = {
            "columns": "timestamp,symbol,close\n2026-01-02T00:00:00+00:00,DEMO,100\n",
            "missing": CSV_HEADER + "2026-01-02T00:00:00+00:00,DEMO,100,101,99,,10,20\n",
            "types": CSV_HEADER + "2026-01-02T00:00:00+00:00,DEMO,100,101,99,abc,10,20\n",
            "finite": CSV_HEADER + "2026-01-02T00:00:00+00:00,DEMO,100,101,99,nan,10,20\n",
            "order": CSV_HEADER + VALID_ROWS + "2026-01-01T00:00:00+00:00,DEMO,121,122,120,121,13,23\n",
            "surplus": CSV_HEADER + "2026-01-02T00:00:00+00:00,DEMO,100,101,99,100,10,20,extra\n",
        }
        for name, content in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                experiment = self._load(Path(directory), content)
                with self.assertRaises(MarketDataError):
                    LocalCSVProvider().load(experiment)

    def test_adapter_accepts_a_replacement_provider_with_normalized_rows(self) -> None:
        class FixtureProvider(MarketDataProvider):
            def load(self, experiment):
                start = datetime(2026, 1, 1, tzinfo=timezone.utc)
                return NormalizedDataset(
                    name="replacement",
                    rows=tuple(
                        DatasetRow(
                            timestamp=start + timedelta(days=index), symbol="DEMO",
                            open=price, high=price, low=price, close=price,
                            volume=0.0, open_interest=0.0,
                        )
                        for index, price in enumerate((100.0, 120.0, 144.0))
                    ),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            experiment = self._load(root, CSV_HEADER + VALID_ROWS)
            result = ExperimentRunner.local(
                root / "output", adapter=DeterministicBacktestAdapter(FixtureProvider())
            ).run(experiment)

            self.assertEqual(result.status, "completed")
            self.assertAlmostEqual(result.metrics.total_return, 0.44)


if __name__ == "__main__":
    unittest.main()
