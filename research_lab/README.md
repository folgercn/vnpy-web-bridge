# Research Lab MVP

This package implements the first local experiment loop:

```text
experiment.yaml -> ExperimentRunner -> BacktestAdapter -> JSON + SQLite + report
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

For a custom CSV, set `dataset.provider: local_csv` and provide `dataset.path`.
The deterministic engine currently consumes one requested symbol's `close`
series: it uses the first item in `universe`, matching the original inline
price-series behavior. Other providers can implement `MarketDataProvider.load()`
and return the same `NormalizedDataset` schema without changing
`ExperimentRunner`.
