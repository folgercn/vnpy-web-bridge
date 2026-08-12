# Issue #328 benchmark assets

`issue328_benchmark.py` is an offline, synthetic benchmark. It writes only a
temporary local directory and never opens ZMQ, QuestDB, RPC, or trading
connections. Run it from the repository root:

```sh
python3 scripts/phase_b_workers/benchmarks/issue328_benchmark.py \
  --ticks 2000 --sample-every 500
```

Use a larger `--ticks` value (for example `1000000`) for a million-tick-equivalent
RSS/recovery run. For that measurement, use stream-only mode so the run does
not serially repeat the same million ticks through lookup and worker-path
benchmarks:

```sh
python3 scripts/phase_b_workers/benchmarks/issue328_benchmark.py \
  --stream-only --ticks 1000000 --sample-every 10000 \
  --json-out /tmp/issue328-stream-1m.json
```

`--stream-only` runs only the real fsync-backed durable stream append path,
RSS samples/trend, and read-only restart recovery. Its JSON result has
`"mode": "stream-only"` and only the `stream` section. The default remains
the full suite (stream, lookup, worker-path, and projection); `--probes` is
validated only for that full mode.

The current implementation intentionally may be slow at million-tick scale:
the result is evidence of the pre-Phase-A baseline, not a pass claim.
Results include append/ack throughput, restart/recovery time, RSS samples,
positive source-event/raw-hash duplicate fallback probes, and projection write
frequency. The `worker_path` section drives the actual
`MarketDataWorker.accept()` → `process_one()` deterministic
`gateway-publish-proxy` path and reports source-fence checkpoint size and
event-entry count. Deterministic identities intentionally keep the event map
empty; this is distinct from arbitrary-source capacity exhaustion. All writes
use normal fsync durability (`"fsync": true`); no capacity-only numbers are
mixed into the real-durability throughput result. `--json-out` stores
machine-readable evidence.

## Durable fsync breakdown (#332)

`durable_fsync_breakdown.py` measures the current implementation in a real
temporary directory. It reports elapsed time and syscall counts for journal
append, checkpoint write, source-fence checkpoint write, and acknowledgement
journal append (including payload write, file fsync, parent-directory fsync,
and atomic replace where applicable).

```sh
python3 scripts/phase_b_workers/benchmarks/durable_fsync_breakdown.py \
  --iterations 100 --groups 1,32,64 --json-out /tmp/issue332-fsync.json
```

`group_size` repeats the existing operation and is **not** group commit. The
result is a baseline only; it never opens ZMQ, QuestDB, RPC, or trading
connections. Use 100–1000 iterations for comparable measurements.
