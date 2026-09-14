from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from research_lab.experiments import ExperimentLoadError, load_experiment
from research_lab.features import FeatureStore
from research_lab.market_data import DatasetRow, NormalizedDataset
from research_lab.schemas import FeatureRequest


EXPERIMENT_YAML = """\
schema_version: research_lab.experiment.v1
experiment_id: features-test-001
strategy:
  name: flat
factor:
  name: close_return
features:
  - name: close_return
  - name: simple_moving_average
    version: v1
    parameters:
      window: 2
universe: [DEMO]
dataset:
  name: test_prices
  prices: [100.0, 110.0, 121.0]
parameters: {}
execution: {}
cost_model: {}
validation:
  method: in_sample
output:
  format: json
"""


def dataset(closes: tuple[float, ...] = (100.0, 110.0, 121.0)) -> NormalizedDataset:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return NormalizedDataset(
        name="fixture",
        rows=tuple(
            DatasetRow(start + timedelta(days=index), "DEMO", close, close, close, close, 0.0, 0.0)
            for index, close in enumerate(closes)
        ),
    )


class FeatureStoreTest(unittest.TestCase):
    def test_yaml_declares_versioned_features(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "experiment.yaml"
            path.write_text(EXPERIMENT_YAML, encoding="utf-8")
            experiment = load_experiment(path)

            self.assertEqual([(feature.name, feature.version) for feature in experiment.features],
                             [("close_return", "v1"), ("simple_moving_average", "v1")])
            self.assertEqual(experiment.features[1].parameters, {"window": 2})

    def test_yaml_rejects_invalid_feature_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "experiment.yaml"
            path.write_text(EXPERIMENT_YAML.replace("window: 2", "window: 0"), encoding="utf-8")
            with self.assertRaises(ExperimentLoadError):
                load_experiment(path)

    def test_cache_reuses_matching_input_and_invalidates_data_or_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FeatureStore(directory)
            first = store.get_or_compute(dataset(), FeatureRequest(name="simple_moving_average", parameters={"window": 2}))
            files_after_first = list((Path(directory) / "feature_cache").glob("*.json"))
            second = store.get_or_compute(dataset(), FeatureRequest(name="simple_moving_average", parameters={"window": 2}))
            changed_data = store.get_or_compute(dataset((100.0, 110.0, 122.0)), FeatureRequest(name="simple_moving_average", parameters={"window": 2}))
            changed_parameters = store.get_or_compute(dataset(), FeatureRequest(name="simple_moving_average", parameters={"window": 3}))

            self.assertEqual(first.cache_key, second.cache_key)
            self.assertEqual(len(files_after_first), 1)
            self.assertNotEqual(first.cache_key, changed_data.cache_key)
            self.assertNotEqual(first.cache_key, changed_parameters.cache_key)
            self.assertEqual(len(store.query(name="simple_moving_average")), 3)

    def test_cache_read_recomputes_when_cached_contents_are_tampered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FeatureStore(directory)
            request = FeatureRequest(name="close_return")
            first = store.get_or_compute(dataset(), request)
            path = Path(directory) / "feature_cache" / f"{first.cache_key}.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["rows"][1]["value"] = 123.0
            path.write_text(json.dumps(payload), encoding="utf-8")

            self.assertEqual(store.query(name="close_return"), [])

            repaired = store.get_or_compute(dataset(), request)

            self.assertEqual(repaired.rows[0].value, 0.0)
            self.assertAlmostEqual(repaired.rows[1].value, 0.1)
            self.assertAlmostEqual(repaired.rows[2].value, 0.1)

    def test_features_use_no_data_after_the_output_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FeatureStore(directory)
            request = FeatureRequest(name="simple_moving_average", parameters={"window": 2})
            original = store.get_or_compute(dataset((100.0, 110.0, 121.0)), request)
            changed_future = store.get_or_compute(dataset((100.0, 110.0, 999.0)), request)

            self.assertEqual([row.value for row in original.rows[:2]], [100.0, 105.0])
            self.assertEqual([row.value for row in changed_future.rows[:2]], [100.0, 105.0])
            self.assertEqual(changed_future.rows[2].value, 554.5)

    def test_lineage_and_normalized_feature_schema_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = FeatureStore(directory).get_or_compute(dataset(), FeatureRequest(name="close_return"))

            self.assertEqual(result.lineage["feature"], {"name": "close_return", "version": "v1", "parameters": {}})
            self.assertEqual(result.rows[0].feature_name, "close_return")
            self.assertEqual(result.rows[0].feature_version, "v1")
            self.assertEqual(result.rows[0].symbol, "DEMO")


if __name__ == "__main__":
    unittest.main()
