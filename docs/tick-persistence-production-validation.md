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
- Kill Web Bridge during replay, start it again, and require the recovered backlog to drain without drops.
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

Full validation passed on 2026-07-17 10:40–10:42 CST in [CD run 29550459564](https://github.com/folgercn/vnpy-web-bridge/actions/runs/29550459564), using validation revision `23c9d56d`. The deployed images were `vnpy-web-bridge:sha-da4eb1b17b204dbde0100180f79e8afd6e56c5f7` and QuestDB `9.4.3`.

| Area | Production result |
|---|---|
| Historical day | `20260716`; 384,014 rows, 5 symbols, 2 exchanges; QuestDB UTC window `2026-07-15 12:24:11.5`–`2026-07-16 11:48:24.5`, covering the CST night and day sessions |
| Data quality | All required-field null counts 0; duplicate ingest IDs 0; stable `(ts, ingest_seq)` order; history query 50 rows; CSV header valid; 20 one-minute bars |
| Observed throughput | Peak 20 Tick/s; average active 11.56 Tick/s; required validation rate 40 Tick/s |
| Normal capacity | 2,000/2,000 persisted in 0.999 s; 2,002.16 persist/s; enqueue P95 0.026 ms; zero difference, drops, and residual spool |
| Forced overflow | Queue capacity 100; 1,900 rows spooled; 2,000/2,000 persisted in 0.681 s; 2,936.46 persist/s; enqueue P95 0.159 ms; zero difference, drops, and residual spool |
| QuestDB outage | Real Tick traffic created replay spool during the 50-second outage; 3 replay files observed; recovered with `valid_total == persisted_total == 8,388`, zero drops, and zero pending spool |
| Process restart | Backlog survived Web Bridge restart (`spool_rows` 3 before and 45 after restart); a SIGKILL during replay was followed by successful restart and complete drain |
| Independent restart | QuestDB restart recovered automatically with zero drops and no pending spool |
| Final state | `valid_total == persisted_total == 276`; queue, inflight, spool, bad/replay files, dropped, corrupt, and quarantine counts all 0; active monitor incidents 0 |
| Resource peaks | Web Bridge 2.24% CPU / 65.96 MiB; QuestDB 97.11% CPU / 932.70 MiB; QuestDB data range 18,115,556–18,164,424 KiB, net growth 4,364 KiB |

The synthetic capacity run used the isolated `2099-12-31` partition; all 4,000 rows were removed and the partition had 0 rows afterward. An earlier tool-development run wrote 2,000 `ISSUE79NORMAL*.LOCAL` rows into the live `2026-07-17` partition before partition isolation was added. They remain intentionally because QuestDB does not support row-level `DELETE`, and rebuilding a live production partition would present greater risk than retaining clearly tagged synthetic rows.

The uploaded JSON and Markdown artifacts omit credentials, DSNs, RPC addresses, Telegram tokens, and chat IDs.
