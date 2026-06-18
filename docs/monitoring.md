# Production Monitoring

## Scope

Phase 7 monitoring is split into four layers:

- P0 alert state, Telegram delivery, ack, silence, and liveness APIs.
- P1 application checkers for RPC, Gateway, QuestDB, PostgreSQL, tick freshness, strategies, risk state, API 5xx, and trade route failures.
- P2 Mac host watchdog for Docker/container/liveness/log/disk checks and deploy maintenance windows.
- P3 dashboard summary and this runbook.

## Configuration

Backend monitor settings live in the deployment `.env`.

```env
MONITOR_ENABLED=true
MONITOR_INTERVAL_SECONDS=15
MONITOR_FAILURE_THRESHOLD=3
MONITOR_RECOVERY_THRESHOLD=2
MONITOR_STARTUP_GRACE_SECONDS=120
MONITOR_STATE_PATH=/app/logs/monitor/state.json
MONITOR_EVENTS_PATH=/app/logs/monitor/events.jsonl
MONITOR_MAINTENANCE_PATH=/app/logs/watchdog/maintenance.json
MONITOR_EXPECTED_STRATEGIES=

TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_SEND_LEVELS=critical,warning
```

The host watchdog reuses `TELEGRAM_*` and writes its own state under `logs/watchdog`.

```env
WATCHDOG_ENABLED=true
WATCHDOG_CONTAINER_NAME=vnpy-web-bridge
WATCHDOG_LIVENESS_URL=http://127.0.0.1:8080/api/health/live
WATCHDOG_MAINTENANCE_FILE=/Users/fujun/services/vnpy-web-bridge/logs/watchdog/maintenance.json
```

Never commit real bot tokens, chat IDs, database DSNs, or RPC addresses into the repository. Rotate the Telegram bot token from BotFather, update the deployment secret/env file, restart the app/watchdog, and send `/api/monitor/telegram/test`.

## Alert Lifecycle

- First failures enter `pending`.
- After failure threshold and grace, the incident becomes `firing` and sends one Telegram message.
- Repeated failures update the same `rule_id:scope_id` fingerprint.
- Stable recovery sends one `resolved` message.
- Manual silences keep updating incident state but suppress delivery until expiry.
- RPC root-cause failures suppress Gateway, tick, and strategy-derived alerts.

## Operations

Install or update the watchdog after deploying scripts:

```bash
DEPLOY_PATH=/Users/fujun/services/vnpy-web-bridge scripts/install-watchdog.sh install
scripts/install-watchdog.sh status
```

Run one manual watchdog cycle:

```bash
scripts/watchdog.py --env-file /Users/fujun/services/vnpy-web-bridge/.env --once
```

Deployments write `logs/watchdog/maintenance.json` before restarting containers. The backend reads the same file through `MONITOR_MAINTENANCE_PATH` and suppresses runtime dependency checks during an active deployment window. Successful liveness smoke removes the file. Failed smoke leaves a `deployment_smoke_failed:web-bridge` watchdog incident.

## Drill Checklist

- Stop Windows vn.py RPC: expect one `rpc_unavailable:CTP` firing and one recovery.
- Stop QuestDB: expect aggregated `questdb_unavailable:market_ticks` or tick persistence incident.
- Stop PostgreSQL: expect `postgres_unavailable:watchlist` while monitor state remains file-backed.
- Stop the web container: expect watchdog `container_not_running:vnpy-web-bridge`.
- Run deploy smoke failure: expect one `deployment_smoke_failed:web-bridge`.
- Block Telegram temporarily: active incidents should keep state and not block API/trading paths.

## Production Drill Record

Recorded on 2026-06-18 against `https://trade.sunnywifi.cn:3088` with `APP_ENV=production`.
Telegram evidence is the delivery result returned by the Bot API; tokens, chat IDs, RPC addresses, and DSNs are intentionally omitted.

| Time (Asia/Shanghai) | Drill | Incident | Result |
|---|---|---|---|
| 16:49 | Host disk pressure detected by watchdog | `disk_space_high:logs` | Fired once, Telegram message `4733`. Root cause was an unused Docker volume `deployments_postgres_data` with `LINKS=0`; current PostgreSQL uses `deployments_postgres-data`. Removed the orphan volume and build cache, disk dropped from 98% to 61%, resolved once with message `4741`. |
| 16:52 | Stopped `vnpy-web-bridge` container | `container_not_running:vnpy-web-bridge` and `app_liveness_failed:web-bridge` | Watchdog fired once per root symptom with messages `4735` and `4736`. After container start, recovery messages were `4737` and `4738`. Public `/api/health/live` returned 200 with `env=production`. |
| 16:56 | Stopped QuestDB container | `questdb_unavailable:market_ticks` | App monitor fired one aggregated warning, message `4739`. No per-symbol alert flood was observed. After QuestDB restart and stable checks, recovery message was `4740`. |
| 17:02 | Stopped PostgreSQL container | `postgres_unavailable:watchlist` | App monitor state stayed file-backed under `logs/monitor/state.json`. Fired once with message `4742`; after PostgreSQL restart and stable checks, recovery message was `4743`. |
| 17:06 | Temporarily pointed app RPC env at an unused port and recreated only `web-bridge` under a watchdog maintenance window | `rpc_unavailable:CTP` | Fired once with message `4744`; Gateway, tick, and strategy-derived checks were suppressed by the RPC root cause. Restored the original `.env`, recreated `web-bridge`, and received one recovery message `4745`. |

Final verification:

- `GET /api/health/live` returned 200 with `env=production`.
- `GET /api/status` returned 200 with `env=production`.
- `logs/monitor/state.json` had no active `pending`, `firing`, `acknowledged`, or `recovering` incident.
- `logs/watchdog/state.json` had no active `pending`, `firing`, `acknowledged`, or `recovering` incident.
- `vnpy-web-bridge`, `vnpy-web-bridge-questdb`, and `vnpy-web-bridge-postgres` were all Docker healthy.
- `test_rpc_readonly.py` against the production RPC returned 18253 contracts, 1 account, and 1 position.
