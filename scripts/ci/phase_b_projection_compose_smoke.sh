#!/usr/bin/env bash
# Fresh-volume standalone Phase-B projection smoke.  This is intentionally
# offline-only: it builds/runs no batch profile, key ceremony, RPC or trading.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose_file="$repo_root/deployments/docker-compose.phase-b.yml"
project_name="${PHASE_B_COMPOSE_PROJECT:-phase-b-projection-smoke-${RANDOM}${RANDOM}}"

: "${CUSTODY_WRITER_EPOCH:=1}"
: "${MAP_ACCEPTANCE_KEYRING_SHA256:=0000000000000000000000000000000000000000000000000000000000000000}"
export CUSTODY_WRITER_EPOCH MAP_ACCEPTANCE_KEYRING_SHA256

if docker compose version >/dev/null 2>&1; then
  compose_command=(docker compose)
elif [ -n "${DOCKER_COMPOSE_BIN:-}" ]; then
  compose_command=("$DOCKER_COMPOSE_BIN")
else
  echo "Docker Compose v2 is required (set DOCKER_COMPOSE_BIN when it is not a docker plugin)" >&2
  exit 2
fi

compose() {
  "${compose_command[@]}" --project-name "$project_name" --file "$compose_file" "$@"
}

cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

compose config --quiet
compose up --build --detach --wait \
  artifact-custody market-data-worker execution-quality-worker monitor-worker

check_projection() {
  local service=$1
  local path=$2
  compose exec -T "$service" python -c "
from pathlib import Path
import json
path = Path('$path')
assert path.is_file(), path
payload = json.loads(path.read_text(encoding='utf-8'))
assert payload['service_id'] == '$service', payload
assert payload['production'] is False and payload['live'] is False
"
}

check_projection artifact-custody /var/lib/phase-b/projection/artifact-custody.json
check_projection market-data-worker /var/lib/phase-b/projection/market-data-worker.json
check_projection execution-quality-worker /var/lib/phase-b/projection/execution-quality-worker.json
compose exec -T monitor-worker python -m phase_b_workers.monitor_worker \
  --state-dir /var/lib/phase-b/monitor --ready | python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload["ready"] is True, payload
'
