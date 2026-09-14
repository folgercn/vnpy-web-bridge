# Research Lab MVP

This package implements the first local experiment loop:

```text
experiment.yaml -> MarketDataProvider -> FeatureStore -> BacktestAdapter -> JSON + SQLite + report
```

The only bundled engine is deterministic and accepts inline prices or a local
CSV through a replaceable `MarketDataProvider`, with the `buy_and_hold` or
`flat` strategy. CSV data is normalized to rows with `timestamp`, `symbol`,
`open`, `high`, `low`, `close`, `volume`, and `open_interest`; timestamps must
be timezone-aware and strictly increasing per symbol. It is an adapter test
engine, not a production trading or alpha-discovery system. `agents/` and
`workers/` are module boundaries only; no Astra/Sol runtime or task queue is
included.

Create a dedicated environment and install the Research Lab's direct
dependencies from the repository root:

```bash
python -m venv .venv-research-lab
.venv-research-lab/bin/python -m pip install -r research_lab/requirements.txt
```

Run its focused tests and included example:

```bash
PYTHONPATH=. .venv-research-lab/bin/python -m unittest discover -s research_lab/tests -v
PYTHONPATH=. .venv-research-lab/bin/python -m research_lab.runners research_lab/examples/buy_and_hold.yaml --output /tmp/research-lab-output
PYTHONPATH=. .venv-research-lab/bin/python -m research_lab.runners research_lab/examples/buy_and_hold_local_csv.yaml --output /tmp/research-lab-csv-output
```

The output directory contains `artifacts/<experiment>.result.json`,
`artifacts/<experiment>.report.md`, and `research_lab.sqlite3`. Query indexed
results through `research_lab.database.ResultStore.query()` using strategy,
factor, or failure-code filters.

Experiments may declare reusable technical features in `features`. The MVP
supports `close_return` and `simple_moving_average` (with integer `window`),
both at version `v1`. Their normalized output rows contain `timestamp`,
`symbol`, `feature_name`, `feature_version`, and `value`. The local Feature
Store writes content-addressed entries under `feature_cache/`; each cache key
binds the exact normalized input dataset, feature name/version, and parameters.
Feature lineage is included in completed result details, and callers can reuse
valid cached sets with `FeatureStore(...).query(name="close_return")`.

Features are point-in-time technical calculations: an output at a timestamp
uses only that observation and earlier observations for its symbol. This MVP
does not provide fundamental data, term structure, volatility surfaces, TQSDK,
or live market data.

For a custom CSV, set `dataset.provider: local_csv` and provide `dataset.path`.
The deterministic engine currently consumes one requested symbol's `close`
series: it uses the first item in `universe`, matching the original inline
price-series behavior. Other providers can implement `MarketDataProvider.load()`
and return the same `NormalizedDataset` schema without changing
`ExperimentRunner`.

## Local parameter sweeps

`research_lab.sweep.v1` declares a finite Cartesian set of allowed experiment
parameter paths. `search_strategy` currently accepts only `cartesian`. The
bundled sweep engine creates a distinct deterministic
experiment ID for each combination, calls the unchanged `ExperimentRunner`
sequentially, stores each trial in the normal result history, and stores a
separate sweep JSON/report artifact. It ranks completed trials by the selected
metric, breaking ties by experiment ID, and reports the mean, best, and
standard deviation for every parameter value across completed trials.

Run the included example:

```bash
PYTHONPATH=. .venv-research-lab/bin/python -m research_lab.sweeps research_lab/examples/buy_and_hold_sweep.yaml --output /tmp/research-lab-sweep-output
```

Only `strategy.parameters.<name>`, `factor.parameters.<name>`,
`parameters.<name>`, `execution.initial_capital`, `execution.position_size`,
and `cost_model.bps` are accepted paths. This is local, deterministic,
sequential execution only. It does not create a Worker queue, schedule work in
parallel, call an LLM, or provide walk-forward/Astra functionality; those are
separate future milestones.
