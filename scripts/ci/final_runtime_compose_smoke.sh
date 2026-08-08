#!/usr/bin/env bash
# Final-runtime configuration smoke.  It is intentionally offline: no Windows
# RPC connection, private key, signing process, order send or cancel is used.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
dsn_file="$(mktemp /tmp/issue291-final-questdb-dsn.XXXXXX)"
keyring_dir="$(mktemp -d /tmp/issue291-final-keyrings.XXXXXX)"
trap 'rm -f "$dsn_file"; rm -rf "$keyring_dir"' EXIT
chmod 0600 "$dsn_file"
printf '%s\n' 'postgresql://admin:quest@questdb:8812/qdb' > "$dsn_file"

export QUESTDB_WRITER_DSN_HOST_PATH="$dsn_file"
export PHASE_C_CUSTODY_PUBLIC_KEYRING_DIR="$keyring_dir"
export CONTROL_EXECUTION_SHARED_SECRET=final-ci-control-secret
export CONTROL_EXECUTION_PRINCIPAL=final-ci-control CONTROL_EXECUTION_ROLE=admin
export CONTROL_DATABASE_URL=postgresql://control:control@postgres:5432/vnpy
export EXECUTION_DATABASE_URL=postgresql://execution:execution@postgres:5432/vnpy
export JWT_SECRET_KEY=final-ci-jwt-secret-not-for-runtime
export AUTH_USERS_JSON='[{"username":"ci","password_sha256":"ci"}]'
export PHASE_C_CUSTODY_SHARED_SECRET=final-ci-custody-control-secret
export PHASE_C_CUSTODY_EXECUTION_READ_SECRET=final-ci-custody-execution-read-secret
export PHASE_C_EXECUTION_SHARED_SECRET=final-ci-phase-c-execution-secret
export PHASE_C_CUSTODY_POLICIES_JSON='{"map_acceptance":{"keyring_path":"/run/keys/map.json","keyring_raw_sha256":"0000000000000000000000000000000000000000000000000000000000000000","key_purpose":"map"},"c_fast_acceptance":{"keyring_path":"/run/keys/cfast.json","keyring_raw_sha256":"0000000000000000000000000000000000000000000000000000000000000000","key_purpose":"cfast"},"runtime_authorization":{"keyring_path":"/run/keys/runtime.json","keyring_raw_sha256":"0000000000000000000000000000000000000000000000000000000000000000","key_purpose":"runtime"}}'
export CUSTODY_WRITER_EPOCH=1 EXECUTION_SCOPE=account:final-ci
export EXECUTION_ALLOWED_SCOPE_JSON='{"account_scope":"account:final-ci","environment":"SIMNOW"}'
export GATEWAY_RPC_REQ_PROXY_PORT=2014 GATEWAY_RPC_PUB_PROXY_PORT=4102
export WINDOWS_RPC_REQ_ADDRESS=tcp://192.0.2.1:2014 WINDOWS_RPC_PUB_ADDRESS=tcp://192.0.2.1:4102
export POSTGRES_DB=vnpy POSTGRES_ADMIN_USER=postgres POSTGRES_ADMIN_PASSWORD=postgres
export CONTROL_DB_USER=control CONTROL_DB_PASSWORD=control EXECUTION_DB_USER=execution EXECUTION_DB_PASSWORD=execution

if docker compose version >/dev/null 2>&1; then
  compose_command=(docker compose)
elif [ -n "${DOCKER_COMPOSE_BIN:-}" ]; then
  compose_command=("$DOCKER_COMPOSE_BIN")
else
  echo "Docker Compose v2 is required (set DOCKER_COMPOSE_BIN when unavailable)" >&2
  exit 2
fi
compose() { "${compose_command[@]}" "$@"; }

compose -f deployments/docker-compose.final.yml config --quiet
compose -f deployments/docker-compose.final.yml config --format json | python3 -c '
import json, sys
services = json.load(sys.stdin)["services"]
assert services["execution-orchestrator"]["environment"]["EXECUTION_ALLOW_SIMNOW_EXECUTION"] == "false"
assert "gateway-egress" not in services["execution-orchestrator"]["networks"]
assert services["market-data-worker"]["networks"] == ["market-ingress", "questdb-data"]
assert services["map-producer"]["profiles"] == ["batch"]
'
