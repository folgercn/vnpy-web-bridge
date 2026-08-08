#!/usr/bin/env bash
# Validate only the selected unit's Phase A/B Compose contract.  Image smoke
# itself happens in the same isolated matrix job before this script runs.
set -euo pipefail

phase="${1:?phase A or B required}"
image="${2:?selected image reference required}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

case "$phase" in
  A)
    export FRONTEND_IMAGE="${FRONTEND_IMAGE:-vnpy-web-bridge-frontend:phase-c-placeholder}"
    export CONTROL_API_IMAGE="${CONTROL_API_IMAGE:-vnpy-web-bridge-control-api:phase-c-placeholder}"
    export EXECUTION_IMAGE="${EXECUTION_IMAGE:-vnpy-web-bridge-execution:phase-c-placeholder}"
    export GATEWAY_PROXY_IMAGE="${GATEWAY_PROXY_IMAGE:-vnpy-web-bridge-gateway-proxy:phase-c-placeholder}"
    export CONTROL_DATABASE_URL='postgresql://control:phase-c-control@postgres:5432/vnpy'
    export EXECUTION_DATABASE_URL='postgresql://execution:phase-c-execution@postgres:5432/vnpy'
    export CONTROL_EXECUTION_SHARED_SECRET='phase-c-ci-not-a-runtime-secret'
    export CONTROL_EXECUTION_PRINCIPAL='phase-c-ci'
    export CONTROL_EXECUTION_ROLE='admin'
    export EXECUTION_SCOPE='account:phase-c-ci'
    export EXECUTION_ENVIRONMENT='phase-c-ci'
    export GATEWAY_RPC_REQ_PROXY_PORT=2014 GATEWAY_RPC_PUB_PROXY_PORT=4102
    export WINDOWS_RPC_REQ_ADDRESS='tcp://192.0.2.1:2014' WINDOWS_RPC_PUB_ADDRESS='tcp://192.0.2.1:4102'
    export JWT_SECRET_KEY='phase-c-ci-not-a-runtime-secret'
    export AUTH_USERS_JSON='[{"username":"ci","password_sha256":"ci"}]'
    export POSTGRES_DB=vnpy POSTGRES_ADMIN_USER=postgres POSTGRES_ADMIN_PASSWORD=phase-c
    export CONTROL_DB_USER=control CONTROL_DB_PASSWORD=phase-c-control
    export EXECUTION_DB_USER=execution EXECUTION_DB_PASSWORD=phase-c-execution
    docker compose -f deployments/docker-compose.phase-a.yml config --quiet
    ;;
  B)
    export ARTIFACT_CUSTODY_IMAGE="${ARTIFACT_CUSTODY_IMAGE:-vnpy-web-bridge-artifact-custody:phase-c-placeholder}"
    export C_FAST_PRODUCER_IMAGE="${C_FAST_PRODUCER_IMAGE:-vnpy-web-bridge-c-fast-producer:phase-c-placeholder}"
    export EXECUTION_QUALITY_WORKER_IMAGE="${EXECUTION_QUALITY_WORKER_IMAGE:-vnpy-web-bridge-execution-quality-worker:phase-c-placeholder}"
    export MAP_PRODUCER_IMAGE="${MAP_PRODUCER_IMAGE:-vnpy-web-bridge-map-producer:phase-c-placeholder}"
    export MARKET_DATA_WORKER_IMAGE="${MARKET_DATA_WORKER_IMAGE:-vnpy-web-bridge-market-data-worker:phase-c-placeholder}"
    export MONITOR_WORKER_IMAGE="${MONITOR_WORKER_IMAGE:-vnpy-web-bridge-monitor-worker:phase-c-placeholder}"
    export SIGNING_AUTHORITY_IMAGE="${SIGNING_AUTHORITY_IMAGE:-vnpy-web-bridge-signing-authority:phase-c-placeholder}"
    export CUSTODY_WRITER_EPOCH=1
    export MAP_ACCEPTANCE_KEYRING_SHA256=0000000000000000000000000000000000000000000000000000000000000000
    docker compose -f deployments/docker-compose.phase-b.yml config --quiet
    ;;
  *) echo "unsupported phase: $phase" >&2; exit 2 ;;
esac

docker image inspect "$image" >/dev/null
