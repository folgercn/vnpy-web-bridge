# Phase B worker seam

The three independent workers use only Python's standard library and never
import the web application. `market-data-worker` owns the fsync'd verified tick
journal, sequence/watermark and tick sink acknowledgement; `execution-quality-
worker` reads that journal and advances its checkpoint only after append-only
evidence succeeds; `monitor-worker` reads typed projections, persists incident
episodes/outbox state, and optionally sends monitor-scoped Telegram alerts.

Every identity hard-codes `production_allowed`, `live_trading_authorized`, and
`countable_forward` to false. State directories are mounted per worker and a
worker can be restarted without an in-process fanout.

```text
python -m phase_b_workers.market_data_worker --version|--health|--ready|--metrics|--run
python -m phase_b_workers.execution_quality_worker --version|--health|--ready|--metrics|--consume|--run
python -m phase_b_workers.monitor_worker --version|--health|--ready|--metrics|--check|--run
```
