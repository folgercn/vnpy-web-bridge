from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path

from research_lab.config import ResearchLabConfig
from research_lab.market_data import MarketDataProvider, NormalizedDataset
from research_lab.schemas import ExperimentSpec, FeatureRequest


class FeatureError(ValueError):
    """Raised when a requested feature cannot be produced or validated."""


@dataclass(frozen=True)
class FeatureRow:
    """One normalized point-in-time feature observation."""

    timestamp: datetime
    symbol: str
    feature_name: str
    feature_version: str
    value: float

    def __post_init__(self) -> None:
        if not self.symbol.strip() or not self.feature_name or not self.feature_version:
            raise FeatureError("feature identity fields must be nonempty")
        if self.timestamp.tzinfo is None or not math.isfinite(self.value):
            raise FeatureError("feature timestamps must be timezone-aware and values finite")


@dataclass(frozen=True)
class FeatureSet:
    """Stable feature output schema plus reproducible input lineage."""

    cache_key: str
    input_data_identity: str
    definition_name: str
    definition_version: str
    parameters: dict[str, float | int | str | bool]
    rows: tuple[FeatureRow, ...]

    def __post_init__(self) -> None:
        if not self.cache_key or not self.input_data_identity:
            raise FeatureError("feature cache and input identities must be nonempty")
        if not self.rows:
            raise FeatureError("feature output must contain rows")
        previous: dict[str, datetime] = {}
        for row in self.rows:
            if row.feature_name != self.definition_name or row.feature_version != self.definition_version:
                raise FeatureError("feature rows must match their definition lineage")
            if row.timestamp <= previous.get(row.symbol, row.timestamp):
                if row.symbol in previous:
                    raise FeatureError("feature timestamps must be strictly increasing per symbol")
            previous[row.symbol] = row.timestamp

    @property
    def lineage(self) -> dict[str, object]:
        return {
            "input_data_identity": self.input_data_identity,
            "feature": {"name": self.definition_name, "version": self.definition_version,
                        "parameters": self.parameters},
            "cache_key": self.cache_key,
        }


class FeatureStore:
    """Local, content-addressed technical feature cache for experiment inputs."""

    def __init__(self, config: ResearchLabConfig | Path | str) -> None:
        self.config = config if isinstance(config, ResearchLabConfig) else ResearchLabConfig(Path(config))
        self.config.feature_cache_dir.mkdir(parents=True, exist_ok=True)

    def compute(self, experiment: ExperimentSpec, provider: MarketDataProvider) -> list[FeatureSet]:
        dataset = provider.load(experiment)
        return [self.get_or_compute(dataset, request) for request in experiment.features]

    def get_or_compute(self, dataset: NormalizedDataset, request: FeatureRequest) -> FeatureSet:
        input_identity = self._dataset_identity(dataset)
        cache_key = self._cache_key(input_identity, request)
        path = self.config.feature_cache_dir / f"{cache_key}.json"
        cached = self._read(path, dataset, cache_key, input_identity, request)
        if cached is not None:
            return cached
        rows = self._calculate(dataset, request)
        result = FeatureSet(cache_key, input_identity, request.name, request.version,
                            dict(request.parameters), rows)
        self._write(path, result)
        return result

    def query(self, *, name: str, version: str = "v1") -> list[FeatureSet]:
        """Return valid cached feature sets so research callers can reuse them."""
        matches: list[FeatureSet] = []
        for path in sorted(self.config.feature_cache_dir.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not self._has_valid_content_digest(payload):
                    continue
                request = FeatureRequest.model_validate(payload["request"])
                if request.name != name or request.version != version:
                    continue
                value = self._deserialize(payload)
                if value.cache_key != path.stem or self._cache_key(value.input_data_identity, request) != value.cache_key:
                    continue
                matches.append(value)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
        return matches

    @staticmethod
    def _dataset_identity(dataset: NormalizedDataset) -> str:
        rows = [
            {"timestamp": row.timestamp.isoformat(), "symbol": row.symbol, "open": row.open,
             "high": row.high, "low": row.low, "close": row.close,
             "volume": row.volume, "open_interest": row.open_interest}
            for row in dataset.rows
        ]
        encoded = json.dumps({"name": dataset.name, "rows": rows}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _cache_key(input_identity: str, request: FeatureRequest) -> str:
        payload = {"input_data_identity": input_identity, "name": request.name,
                   "version": request.version, "parameters": request.parameters}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def _read(self, path: Path, dataset: NormalizedDataset, cache_key: str,
              input_identity: str, request: FeatureRequest) -> FeatureSet | None:
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not self._has_valid_content_digest(payload):
                return None
            value = self._deserialize(payload)
            stored_request = FeatureRequest.model_validate(payload["request"])
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None
        if (value.cache_key != cache_key or value.input_data_identity != input_identity
                or stored_request != request or value.definition_name != request.name
                or value.definition_version != request.version or value.parameters != request.parameters):
            return None
        if value.rows != self._calculate(dataset, request):
            return None
        return value

    @staticmethod
    def _calculate(dataset: NormalizedDataset, request: FeatureRequest) -> tuple[FeatureRow, ...]:
        output: list[FeatureRow] = []
        history: dict[str, list[float]] = {}
        for row in dataset.rows:
            closes = history.setdefault(row.symbol, [])
            # Append the current close only when its timestamp is reached: every
            # output can therefore depend only on observations at or before it.
            closes.append(row.close)
            if request.name == "close_return":
                value = 0.0 if len(closes) == 1 else closes[-1] / closes[-2] - 1.0
            elif request.name == "simple_moving_average":
                window = request.parameters["window"]
                assert isinstance(window, int)
                value = sum(closes[-window:]) / min(len(closes), window)
            else:  # Schema validation makes this unreachable; retain a clear boundary.
                raise FeatureError(f"unsupported feature: {request.name}")
            output.append(FeatureRow(row.timestamp, row.symbol, request.name, request.version, value))
        return tuple(output)

    @staticmethod
    def _deserialize(payload: dict[str, object]) -> FeatureSet:
        rows = tuple(
            FeatureRow(datetime.fromisoformat(row["timestamp"]), row["symbol"], row["feature_name"],
                       row["feature_version"], float(row["value"]))
            for row in payload["rows"]
        )
        return FeatureSet(str(payload["cache_key"]), str(payload["input_data_identity"]),
                          str(payload["definition_name"]), str(payload["definition_version"]),
                          dict(payload["parameters"]), rows)

    @staticmethod
    def _content_digest(payload: dict[str, object]) -> str:
        content = {key: value for key, value in payload.items() if key != "content_digest"}
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @classmethod
    def _has_valid_content_digest(cls, payload: dict[str, object]) -> bool:
        digest = payload.get("content_digest")
        return isinstance(digest, str) and digest == cls._content_digest(payload)

    @staticmethod
    def _write(path: Path, value: FeatureSet) -> None:
        payload = {
            "cache_key": value.cache_key, "input_data_identity": value.input_data_identity,
            "definition_name": value.definition_name, "definition_version": value.definition_version,
            "parameters": value.parameters,
            "request": {"name": value.definition_name, "version": value.definition_version,
                        "parameters": value.parameters},
            "rows": [{**asdict(row), "timestamp": row.timestamp.isoformat()} for row in value.rows],
        }
        payload["content_digest"] = FeatureStore._content_digest(payload)
        temporary = path.with_suffix(".json.tmp")
        try:
            temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
