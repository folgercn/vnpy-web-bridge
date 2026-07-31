# Research Warehouse M2 historical backfill v1

Issue #213 supplies the one-time, bounded acquisition needed for the frozen
126-official-day trend plus 60-official-day volatility window. It extends the
existing #198/#203 pipeline; it grants no Research, deployment, RPC, account,
position, order or trading authority.

## Invariants

- The signed official calendar selects exactly 186 days, oldest first.
- Every request uses a fresh live NTP sample. Historical `observed_at`,
  `first_seen_at`, `last_seen_at`, `sealed_at`, `committed_at` and
  `available_at` are never caller supplied or reconstructed.
- Existing valid daily receipts are re-read, fully verified and skipped without
  a network request. A missing or conflicting receipt resumes at that day.
- Requests remain limited to the frozen SHFE/INE endpoints. The default request
  start interval is two seconds. Daily and historical processes share one
  service-owned flock plus a durably fsynced last-start timestamp; the lock is
  held across the HTTP scope, so restart or a second process cannot bypass the
  limit. Only network/timeout, HTTP 429 and HTTP 5xx failures receive at most
  four bounded exponential retries; the first terminal failure stops the batch.
- A daily receipt is not published until both exact raw objects and all ten
  frozen products have been verified.
- Checkpoint state is the create-only daily receipts, signed manifest chain,
  commit receipts and root-pinned commit-anchor ledger. There is no mutable
  caller-controlled cursor.

The existing 2026-07-30 manifest remains the chain genesis. Backfill signing
appends previously missing days in oldest-to-newest order. When the plan reaches
an already committed day with the identical observation fingerprint, it verifies
and skips that node instead of creating a duplicate.

## Acquisition and resume

Run outside the daily 18:30–19:10 window. Keep the existing PF policy and service
identity unchanged:

```sh
sudo -u vnpyresearch \
  /usr/local/libexec/vnpyresearch/release-lock-runner warehouse \
  --history-through 2026-07-30 \
  --history-days 186 \
  --minimum-request-interval-seconds 2 \
  --maximum-attempts 4 \
  --initial-backoff-seconds 5
```

The canonical result prints the create-only backfill receipt path and its raw
SHA-256. Re-run the exact command after any bounded failure. Complete days cause
zero HTTP requests; the first incomplete day resumes.

Do not use `--trusted-now`, `--observed-at`, copied historical timestamps,
additional hosts, proxy credentials or a broader PF rule.

## Signed chain and root pins

Use the exact acquisition receipt path and independently retained raw SHA:

```sh
sudo /usr/local/libexec/vnpyresearch/release-lock-runner manifest-signer \
  --history-receipt /Users/Shared/vnpy-research/runtime/backfill-receipts/RECEIPT.json \
  --expected-history-receipt-sha256 SHA256
```

The signer verifies every daily receipt after irreversible UID/GID handoff.
Before advancing the root state, each manifest and commit receipt is durably
re-read and a new live NTP sample records external availability. Each append
verifies only the root-pinned current head plus that day's receipt, exact raw
bytes, manifest and commit. Re-running resumes from the root-pinned contiguous
prefix and signs only missing days. It does not walk prior raw evidence or the
full manifest chain for every append.

## Manual full-chain maintenance

Rebuild, backup and the full-chain history verifier remain available as
explicit operator tools, but are not invoked by the history signer or scheduled
automatically. They intentionally perform high-I/O whole-chain work and should
only be run when an operator explicitly requests a rebuild, recovery exercise
or full audit:

```sh
sudo -u vnpyresearch \
  /usr/local/libexec/vnpyresearch/release-lock-runner rebuild

sudo /usr/local/libexec/vnpyresearch/release-lock-runner backup-signer

sudo -u vnpyresearch \
  /usr/local/libexec/vnpyresearch/release-lock-runner warehouse \
  --verify-history-receipt \
  /Users/Shared/vnpy-research/runtime/backfill-receipts/RECEIPT.json \
  --expected-history-receipt-sha256 SHA256
```

When explicitly run, the final status is
`M2_RESEARCH_HISTORY_BACKFILL_VERIFIED`. It binds:

- exactly 186 official days and ten products with 186 observations each;
- every daily receipt, exact raw hash and byte count;
- manifest genesis/head, commit head and commit-anchor ledger;
- deterministic derived catalog and release source/dependency pins;
- append-only backup head and rebuild fingerprint.

Retain exact canonical stdout bytes with create-only mode (`umask 077` and shell
`noclobber`), hash those bytes independently, then run the existing isolation
evidence capture/final verifier. No step contacts Web Bridge, Docker, Windows
RPC, CTP, SimNow, accounts, positions or orders.
