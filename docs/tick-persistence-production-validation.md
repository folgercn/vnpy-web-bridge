# Tick Persistence Production Validation

This runbook closes the production-only verification tracked by Issue #79. It uses the existing Macmini self-hosted runner and the deployed `vnpy-web-bridge` / QuestDB containers.

## Safety gate

The validation workflow is manual. Select `issue79-production-validation` in the CD workflow and enter the exact confirmation `ISSUE79_PRODUCTION`. Without both values, no production container is stopped or restarted.

The runner performs a preflight before fault injection and always starts QuestDB and Web Bridge again from a `finally` recovery path. It never deletes volumes, changes the deployment `.env`, or prints credentials, RPC addresses, database DSNs, Telegram tokens, or chat IDs.

## Validation scope

- Select the latest QuestDB `trading_day` that contains both the previous evening's night session and the following day session.
- Record Tick row/symbol/exchange counts, time range, peak TPS, average active TPS, required-field completeness, `(ts, ingest_seq)` ordering, historical query, CSV export, and one-minute bar results.
- Run normal and forced-overflow synthetic load at no less than twice the historical peak TPS; require enqueue P95 at or below 10 ms, normal end-to-end persistence within 2 seconds, zero drops, and complete cleanup of validation symbols.
- Stop QuestDB while real RPC Tick traffic continues, verify spool growth, restore QuestDB, and require the backlog to drain without drops.
- Repeat the outage with a Web Bridge restart while backlog exists, proving persisted spool discovery after process restart.
- Restart QuestDB independently and require automatic Web Bridge recovery.
- Finish only when both containers are healthy, the writer is alive, queue/spool are empty, no corrupt spool file exists, and `dropped_total == 0`.

## Trigger

```bash
gh workflow run cd.yml \
  --ref <validation-branch> \
  -f operation=issue79-production-validation \
  -f confirmation=ISSUE79_PRODUCTION
```

The workflow uploads a sanitized JSON record and a Markdown summary. Copy the verified summary into the Production evidence section below and attach the workflow URL to the PR and Issue #79 comments.

## Production evidence

Pending the first controlled production run.
