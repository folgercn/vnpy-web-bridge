# Issue #45 Production Validation

The final Phase 7 drill runs only through the owner-only `Issue 45 Production Monitoring Validation` workflow. It writes sanitized JSON and Markdown artifacts and never removes Docker volumes or changes the deployment `.env`.

## Safety gates

- Production-stage confirmation: `ISSUE45_PRODUCTION`.
- Testing-stage override: select `testing` and type `ISSUE45_TESTING`. This explicitly allows any time window and records active-order rows without blocking, while still requiring zero non-zero positions, healthy containers, zero active incidents, owner-only dispatch, and full automatic recovery.
- Repository owner and actor must both be `folgercn`.
- Weekday window: 15:30–19:30 Asia/Shanghai; weekend window: 04:00–19:30. The early cutoff keeps the bounded workflow clear of the 21:00 night session.
- `APP_ENV=production`, monitoring, and Telegram must be enabled.
- Web Bridge, QuestDB, and PostgreSQL must be healthy before the drill.
- Backend and watchdog states must have zero active incidents.
- Real RPC must report zero non-zero positions. Production stage also requires zero active orders; testing stage records but does not block on active-order rows.

The script uses the existing production `.env` only for runtime configuration. Secrets, addresses, DSNs, account data, symbols, and balances are excluded from artifacts and logs.

When a drill or automatic recovery fails, the JSON artifact also records two bounded diagnostic snapshots: container state and health-check output plus error-filtered Web Bridge log lines. Transport addresses, credentials, IP addresses, account identifiers, symbols, order identifiers, and trade identifiers are redacted before the artifact is written.

## Scenarios

1. Restart Web Bridge under the deployment maintenance window and verify no watchdog episode is created.
2. Stop Web Bridge, force a Telegram transport failure in a manual watchdog cycle, verify retry delivery, then verify one recovery delivery.
3. Stop QuestDB and verify only `questdb_unavailable:market_ticks` is active; the derived persistence incident remains suppressed. Start QuestDB and verify recovery.
4. Stop PostgreSQL and verify firing and recovery for `postgres_unavailable:watchlist`.
5. Recreate only Web Bridge with loopback RPC endpoints, verify `rpc_unavailable:CTP` while Gateway, tick, and strategy RPC incidents remain suppressed, then restore the original Compose configuration and verify recovery. Off-hours `info` delivery may be intentionally skipped by `TELEGRAM_SEND_LEVELS` and is recorded as such.
6. Verify all containers, public liveness, alert states, and read-only RPC exposure after recovery.

Every mutation is wrapped in a recovery path that starts QuestDB and PostgreSQL, restores Web Bridge from the original Compose file, removes only the validation-owned override/maintenance files, and verifies liveness. Evidence is uploaded even when a scenario fails.

## Manual preflight

The preflight mode performs no fault injection or recovery mutation:

```bash
python3 scripts/monitoring_production_validation.py \
  --mode preflight \
  --output artifacts/issue-45-production-validation.json \
  --markdown-output artifacts/issue-45-production-validation.md
```

The full mode must be launched through GitHub Actions after reviewing the current exposure. Use the testing-stage override only while the entire environment is explicitly operating as a test system.
