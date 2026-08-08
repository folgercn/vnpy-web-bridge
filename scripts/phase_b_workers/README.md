# Phase B worker seam

The three independent workers never import the web application.
`market-data-worker` owns the fsync'd verified tick journal, sequence/watermark
and tick sink acknowledgement; `execution-quality-
worker` reads that journal and advances its checkpoint only after append-only
evidence succeeds; `monitor-worker` reads typed projections, persists incident
episodes/outbox state, and optionally sends monitor-scoped Telegram alerts.

Every identity hard-codes `production_allowed`, `live_trading_authorized`, and
`countable_forward` to false. State directories are mounted per worker and a
worker can be restarted without an in-process fanout.

`market-data-worker` has exactly two optional external adapters: a ZMQ `SUB`
socket to `PHASE_B_MARKET_PUBLISH_ENDPOINT`, and a PGWire QuestDB writer from
`PHASE_B_QUESTDB_PG_DSN` or the mode-0600
`PHASE_B_QUESTDB_PG_DSN_FILE`.  It has no request socket and no account,
position, order, send, or cancel capability.  The QuestDB table is pre-created
by its schema owner: this worker issues only `INSERT INTO market_ticks`, `SELECT
1` health, and a narrow readback query, never DDL.

The verified-tick contract maps exactly to v3 `ts`, `received_at`, identity,
`vt_symbol`/split symbol+exchange, `last_price`, `last_volume`, and L1
bid/ask prices and volumes.  `gateway_name`, name/dates, turnover/interest,
OHLC/limits and L2-L5 are explicitly SQL `NULL`; this is not a claim that the
small verified-tick contract is field-equivalent to vn.py `TickData`.

```text
python -m phase_b_workers.market_data_worker --version|--health|--ready|--metrics|--run
python -m phase_b_workers.execution_quality_worker --version|--health|--ready|--metrics|--consume|--run
python -m phase_b_workers.monitor_worker --version|--health|--ready|--metrics|--check|--run
```
