#!/usr/bin/env bash
# Validate the selected unit's Phase A/B Compose contract.  Image smoke itself
# happens in the same isolated matrix job before this script runs.
set -euo pipefail

phase="${1:?phase A or B required}"
unit="${2:?selected unit required}"
image="${3:?selected image reference required}"
compose_profile=""
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

if docker compose version >/dev/null 2>&1; then
  compose_command=(docker compose)
elif [ -n "${DOCKER_COMPOSE_BIN:-}" ]; then
  compose_command=("$DOCKER_COMPOSE_BIN")
else
  echo "Docker Compose v2 is required (set DOCKER_COMPOSE_BIN when it is not a docker plugin)" >&2
  exit 2
fi

compose() {
  "${compose_command[@]}" "$@"
}

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
    export JWT_SECRET_KEY='phase-c-ci-not-a-runtime-secret-x'
    export AUTH_USERS_JSON='[{"username":"ci","password_sha256":"ci"}]'
    export POSTGRES_DB=vnpy POSTGRES_ADMIN_USER=postgres POSTGRES_ADMIN_PASSWORD=phase-c
    export CONTROL_DB_USER=control CONTROL_DB_PASSWORD=phase-c-control
    export EXECUTION_DB_USER=execution EXECUTION_DB_PASSWORD=phase-c-execution
    case "$unit" in
      frontend-edge) FRONTEND_IMAGE="$image"; export FRONTEND_IMAGE ;;
      control-api) CONTROL_API_IMAGE="$image"; export CONTROL_API_IMAGE ;;
      execution-orchestrator) EXECUTION_IMAGE="$image"; export EXECUTION_IMAGE ;;
      gateway-rpc-request-proxy|gateway-rpc-publish-proxy)
        # Both runtime services use one reviewed gateway image pin.
        GATEWAY_PROXY_IMAGE="$image"; export GATEWAY_PROXY_IMAGE
        ;;
      *) echo "unsupported Phase A unit: $unit" >&2; exit 2 ;;
    esac
    compose_file=deployments/docker-compose.phase-a.yml
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
    case "$unit" in
      artifact-custody) ARTIFACT_CUSTODY_IMAGE="$image"; export ARTIFACT_CUSTODY_IMAGE ;;
      c-fast-producer) C_FAST_PRODUCER_IMAGE="$image"; export C_FAST_PRODUCER_IMAGE; compose_profile=batch ;;
      execution-quality-worker) EXECUTION_QUALITY_WORKER_IMAGE="$image"; export EXECUTION_QUALITY_WORKER_IMAGE ;;
      map-producer) MAP_PRODUCER_IMAGE="$image"; export MAP_PRODUCER_IMAGE; compose_profile=batch ;;
      market-data-worker) MARKET_DATA_WORKER_IMAGE="$image"; export MARKET_DATA_WORKER_IMAGE ;;
      monitor-worker) MONITOR_WORKER_IMAGE="$image"; export MONITOR_WORKER_IMAGE ;;
      signing-authority) SIGNING_AUTHORITY_IMAGE="$image"; export SIGNING_AUTHORITY_IMAGE; compose_profile=offline-signing ;;
      *) echo "unsupported Phase B unit: $unit" >&2; exit 2 ;;
    esac
    compose_file=deployments/docker-compose.phase-b.yml
    ;;
  *) echo "unsupported phase: $phase" >&2; exit 2 ;;
esac

docker image inspect "$image" >/dev/null
rendered=$(mktemp /tmp/issue291-phase-c-compose.XXXXXX.json)
trap 'rm -f "$rendered"' EXIT
compose_args=(-f "$compose_file")
if [[ -n "$compose_profile" ]]; then
  compose_args=(--profile "$compose_profile" "${compose_args[@]}")
fi
compose "${compose_args[@]}" config --quiet
compose "${compose_args[@]}" config --format json > "$rendered"
python3 - "$phase" "$unit" "$image" "$rendered" <<'PY'
import json
import sys

phase, unit, image, path = sys.argv[1:]
services = json.load(open(path, encoding="utf-8"))["services"]
expected = {
    ("A", "frontend-edge"): ("frontend-edge",),
    ("A", "control-api"): ("control-api",),
    ("A", "execution-orchestrator"): ("execution-orchestrator",),
    ("A", "gateway-rpc-request-proxy"): (
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    ),
    ("A", "gateway-rpc-publish-proxy"): (
        "gateway-rpc-request-proxy",
        "gateway-rpc-publish-proxy",
    ),
}
expected_commands = {
    "gateway-rpc-request-proxy": ["request"],
    "gateway-rpc-publish-proxy": ["publish"],
}
if phase == "B":
    expected[(phase, unit)] = (unit,)
targets = expected.get((phase, unit))
if not targets:
    raise SystemExit(f"no expected Compose service mapping for {phase}/{unit}")
for service in targets:
    actual = services.get(service, {}).get("image")
    if actual != image:
        raise SystemExit(f"{service} image mismatch: expected {image!r}, got {actual!r}")
    if service in expected_commands:
        command = services.get(service, {}).get("command")
        expected_command = expected_commands[service]
        if command != expected_command:
            raise SystemExit(
                f"{service} command mismatch: expected {expected_command!r}, got {command!r}"
            )
PY
