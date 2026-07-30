# Research Warehouse M2 daily runtime v1

Issue #198 adds an operational layer to the frozen M2 release without adding
research-signing or trading authority.

## Trust inputs

`research-warehouse-job` and `research-warehouse-monitor` load the root-managed
`/usr/local/libexec/vnpyresearch/runtime-input-v1.json`. The strict canonical
input names the frozen isolation policy and source registry and carries external
raw-SHA pins for:

- the signed SHFE/INE official calendar and its public key;
- the calendar availability anchor;
- the independent backup public key and verified anchor-chain head;
- the monitor start day.

Each invocation obtains a fresh clock sample from the fixed
`time.apple.com:123` NTP endpoint. The client binds the reply to its transmitted
timestamp and rejects excessive offset, delay, stale/leap-unsynchronised, or
invalid-stratum responses.

The service cannot infer a closed day from HTTP 404. A signed calendar
classification is required before any decision.

## Daily state transition

On a calendar-closed day the scheduler performs no HTTP request and returns an
idempotent skip. After 18:00 Asia/Shanghai on an official day it acquires the
frozen SHFE and INE endpoints in registry order. It publishes
`runtime/run-receipts/YYYY-MM-DD.json` only after both exact-byte acquisitions
are present and revalidated against observation and raw custody. A timeout,
partial response, or second-source failure leaves no success receipt. An
existing valid receipt prevents another download.

The receipt is create-only, canonical, private, and binds the registry,
calendar, availability anchor, two observation/revision IDs, raw paths, byte
counts, and SHA-256 values. It grants no authority.

## Monitor facts

The monitor computes facts instead of accepting a caller-supplied healthy
snapshot:

- expected and missing days come from the signed official calendar;
- success, revision changes, and hash mismatches come from re-reading run
  receipts, observations, and exact raw bytes;
- free space comes from the custody filesystem;
- backup freshness and verification come from the externally pinned signed
  backup head plus a complete independent-store readback.

Every result is published create-only under `runtime/monitor-receipts/` with a
content-bound ID. `load_monitor_receipt(..., expected_raw_sha256=...)` is the
fail-closed binding surface for the #172 verifier.

Neither runtime entrypoint imports a private-key loader, Web Bridge, RPC,
account, order, position, or trading code.
