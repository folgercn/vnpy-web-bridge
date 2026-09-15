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
parallel, call an LLM, or provide Astra functionality; those are separate
future milestones.

## Walk-forward validation

`research_lab.validation.v1` declares local observation-count windows around
one existing experiment. `train_test_split` consumes every selected-symbol
observation in one train/test fold. `rolling_window` keeps a fixed-size train
window, while `walk_forward` expands it. For rolling and walk-forward plans,
`step_size` must be at least `test_size`, so OOS observations are not counted
in more than one fold. All test windows begin at or after their paired train
end; the engine reloads a distinct normalized data slice for
each IS and OOS run through the unchanged `ExperimentRunner` interface.

Run the included walk-forward example:

```bash
PYTHONPATH=. .venv-research-lab/bin/python -m research_lab.validation research_lab/examples/buy_and_hold_walk_forward.yaml --output /tmp/research-lab-validation-output
```

The result is saved as `artifacts/<validation>.validation.json`, indexed in
`research_lab.sqlite3`, and rendered as a robustness report. It includes each
fold's IS/OOS metrics, a documented heuristic stability score, aggregate OOS
minus IS degradation, and minimal OOS return-sign regime counts. The score is
not a selection or promotion decision. This deterministic MVP supports only
`universe[0]`; local CSV works through the same normalized provider path, but
multi-symbol portfolio validation, TQSDK, live data, queues, Critic Agent, LLM
evaluation, and Astra discovery are outside this milestone. The versioned
validation result is the stable local handoff boundary for a future Critic.

## Critic review

`research_lab.critic-review.v1` is a deterministic, local independent review
of a persisted `ValidationResult`. It records fold-boundary evidence and
reviews OOS degradation, while reporting missing feature-time lineage,
candidate selection history, parameter stability, cost sensitivity, and market-regime evidence as
`insufficient_evidence`. Its `accept` / `improve` / `reject` recommendation is
only a research handoff; it cannot select, promote, deploy, or trade a
candidate.

After running the example validation, review its stored result:

```bash
PYTHONPATH=. .venv-research-lab/bin/python -m research_lab.critic --validation-id demo-walk-forward-001 --output /tmp/research-lab-validation-output
```

The Critic writes `artifacts/<review>.critic.json`, a Markdown risk report,
and indexes review history in `research_lab.sqlite3`. `ResultStore` can query
the local Alpha-Database-compatible record by `validation_id`, `candidate_id`,
or a non-pass finding category. It does not add LLM/Astra/Sol, a worker queue,
TQSDK, or realtime data.

## Alpha Database

Every `ExperimentRunner` result is also archived under
`alpha_database/experiments/` as deterministic JSON and Markdown assets, so a
research directory can be committed and reviewed with Git. Each saved asset
records `asset_version`, a content-derived `content_hash`, and `created_commit`
(or the explicit offline fallback `unavailable`). The filename binds identity
and content hash: a changed asset with the same identity creates a second,
queryable historical version instead of replacing the earlier one. Pass
`created_commit=` to `AlphaDatabase(...)` when an offline workflow has stable
provenance to record.

Markdown uses fixed `hypothesis`, `evidence`, `conclusion`, and `next_action`
sections. Missing source data is labelled `unavailable` with the required
evidence; the archive does not invent a research conclusion. Failed experiments
add a failure pattern; Critic non-pass findings add evidence-backed failure
patterns under `alpha_database/failure_patterns/`. Factor knowledge records
experiments, failures, available feature and dataset hashes, literature
references, and validation IDs. It only records lineage present in the source
result. The same local store can also save `AlphaIdea` and `LiteratureReference`
assets.

Use `AlphaDatabase(ResearchLabConfig(output_root))` to query experiment
history, failure categories, and factor knowledge. This is a filesystem
projection of ResultStore's existing research history, not SQLite/Postgres, a
knowledge graph, a vector database, Astra/Sol, LLM functionality, or a
promotion/deployment/trading mechanism.
