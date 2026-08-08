#!/usr/bin/env bash
# Fresh-volume final-runtime smoke.  It is entirely offline: no Windows RPC,
# gateway proxy, signer, private key, order send, or cancellation is started.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose_file="deployments/final/docker-compose.runtime-smoke.yml"
project="issue291-final-smoke-${RANDOM}${RANDOM}"

if docker compose version >/dev/null 2>&1; then
  compose_command=(docker compose)
else
  # Local Colima images may lack the desktop plugin.  Compose-bin still talks
  # only to the local Docker socket and is not a reason to skip the runtime
  # test; CI normally takes the native branch above.
  compose_command=(
    docker run --rm --entrypoint /docker-compose
    -v /var/run/docker.sock:/var/run/docker.sock
    -v "$root":/work -w /work docker/compose-bin:latest
  )
fi
compose() { "${compose_command[@]}" --project-name "$project" -f "$compose_file" "$@"; }

diagnose() {
  compose ps >&2 || true
  compose logs --no-color --tail=100 2>&1 \
    | sed -E '/secret|password|token|dsn|keyring/ s/.*/[redacted sensitive log line]/' >&2 \
    || true
}
cleanup() { compose down --volumes --remove-orphans >/dev/null 2>&1 || true; }
on_exit() {
  status=$?
  if (( status != 0 )); then diagnose; fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

compose config --quiet
# Keep normal CI output compact; failure diagnostics below remain redacted.
compose up --build --detach >/dev/null

container_id() {
  compose ps -q "$1"
}
market_container="$(container_id market-data-worker)"
custody_container="$(container_id artifact-custody)"
eq_container="$(container_id execution-quality-worker)"
monitor_container="$(container_id monitor-worker)"

for _attempt in $(seq 1 45); do
  if docker exec "$market_container" python - <<'PY' >/dev/null 2>&1
import os
import psycopg

with psycopg.connect(os.environ["PHASE_B_QUESTDB_PG_DSN"], connect_timeout=2) as db:
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM market_ticks")
        assert cur.fetchone()[0] == 1
PY
  then
    break
  fi
  sleep 1
done

docker exec "$custody_container" python - <<'PY'
from urllib.error import HTTPError
from urllib.request import Request, urlopen

assert urlopen("http://127.0.0.1:8091/health/ready", timeout=3).status == 200
execution = Request(
    "http://127.0.0.1:8091/internal/v1/artifacts/smoke-target-plan-0001",
    headers={
        "X-Phase-C-Principal": "execution-orchestrator",
        "X-Phase-C-Custody-Secret": "smoke-execution-read-secret",
    },
)
try:
    urlopen(execution, timeout=3)
except HTTPError as exc:
    assert exc.code == 404
else:
    raise AssertionError("unexpected smoke artifact")
control = Request(
    "http://127.0.0.1:8091/internal/v1/artifacts/smoke-target-plan-0001",
    headers={
        "X-Phase-C-Principal": "control-api",
        "X-Phase-C-Custody-Secret": "smoke-control-secret",
    },
)
try:
    urlopen(control, timeout=3)
except HTTPError as exc:
    assert exc.code == 401
else:
    raise AssertionError("control read unexpectedly authorised")
PY

docker exec "$market_container" python - <<'PY'
import json
import os
from pathlib import Path

import psycopg

with psycopg.connect(os.environ["PHASE_B_QUESTDB_PG_DSN"], connect_timeout=3) as db:
    with db.cursor() as cur:
        cur.execute("SELECT count(*), min(vt_symbol), min(last_price) FROM market_ticks")
        count, symbol, price = cur.fetchone()
        assert (count, symbol, float(price)) == (1, "RB2601.SHFE", 3500.0)
        cur.execute("SELECT \"column\", upsertKey, designated FROM table_columns('market_ticks')")
        metadata = {name: (key, designated) for name, key, designated in cur.fetchall()}
        assert metadata["ts"] == (True, True)
        assert metadata["ingest_id"] == (True, False)
fence = json.loads(Path("/var/lib/phase-b/market-data/publish_proxy_cursor.json").read_text())
assert int(fence["last_source_seq"]) >= 2, fence
PY

for _attempt in $(seq 1 30); do
  if docker exec "$eq_container" python -m phase_b_workers.execution_quality_worker \
    --state-dir /var/lib/phase-b/execution-quality --ready >/dev/null 2>&1 \
    && docker exec "$monitor_container" python -m phase_b_workers.monitor_worker \
      --state-dir /var/lib/phase-b/monitor --ready >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done
echo "EQ/monitor did not reach ready state" >&2
exit 1
