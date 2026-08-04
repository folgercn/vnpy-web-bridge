#!/usr/bin/env bash
set -Eeuo pipefail

export PATH="/Applications/Docker.app/Contents/Resources/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

DEPLOY_PATH=${DEPLOY_PATH:-/Users/fujun/services/vnpy-web-bridge}
COMPOSE_FILE="$DEPLOY_PATH/deployments/docker-compose.prod.yml"
PRIVATE_PROFILE_FILE="$DEPLOY_PATH/deployments/c-fast-simnow-profile.env"
PRIVATE_RUNTIME_ENV_FILE="$DEPLOY_PATH/deployments/c-fast-simnow-runtime.env"
PRIVATE_COMPOSE_FILE="$DEPLOY_PATH/deployments/docker-compose.c-fast-simnow-private.yml"
IMAGE_REPO=${IMAGE_REPO:-ghcr.io/folgercn/vnpy-web-bridge-app}
IMAGE_TAG=${IMAGE_TAG:-latest}
DOCKER_CONFIG_DIR=${DOCKER_CONFIG_DIR:-$DEPLOY_PATH/.docker-ci}
DEPLOY_SERVICES=${DEPLOY_SERVICES:-web-bridge}
ENV_FILE=${ENV_FILE:-$DEPLOY_PATH/.env}
DEPLOY_SKIP_PULL=${DEPLOY_SKIP_PULL:-false}
WATCHDOG_MAINTENANCE_FILE=${WATCHDOG_MAINTENANCE_FILE:-$DEPLOY_PATH/logs/watchdog/maintenance.json}
DEPLOY_MAINTENANCE_TTL_SECONDS=${DEPLOY_MAINTENANCE_TTL_SECONDS:-300}
DEPLOY_SMOKE_URL=${DEPLOY_SMOKE_URL:-http://127.0.0.1:8080/api/health/live}
DEPLOY_SMOKE_TIMEOUT_SECONDS=${DEPLOY_SMOKE_TIMEOUT_SECONDS:-180}

write_maintenance() {
  local status=$1
  local reason=${2:-}
  mkdir -p "$(dirname "$WATCHDOG_MAINTENANCE_FILE")"
  python3 - "$WATCHDOG_MAINTENANCE_FILE" "$status" "$reason" <<'PY'
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import sys

path, status, reason = sys.argv[1:4]
ttl = int(os.environ.get("DEPLOY_MAINTENANCE_TTL_SECONDS", "300"))
now = datetime.now(timezone.utc)
payload = {
    "status": status,
    "reason": reason,
    "started_at": now.isoformat(timespec="seconds"),
    "expires_at": (now + timedelta(seconds=ttl)).isoformat(timespec="seconds"),
    "image": f"{os.environ.get('IMAGE_REPO', '')}:{os.environ.get('IMAGE_TAG', '')}",
    "services": os.environ.get("DEPLOY_SERVICES", "web-bridge"),
}
tmp = f"{path}.tmp"
with open(tmp, "w", encoding="utf-8") as file:
    json.dump(payload, file, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp, path)
PY
}

clear_maintenance() {
  rm -f "$WATCHDOG_MAINTENANCE_FILE"
}

on_error() {
  local line=$1
  write_maintenance failed "deploy failed at line $line"
}

smoke_liveness() {
  local deadline=$((SECONDS + DEPLOY_SMOKE_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if python3 - "$DEPLOY_SMOKE_URL" <<'PY'
from __future__ import annotations

import sys
import urllib.request

url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=3) as response:
        if response.status < 200 or response.status >= 300:
            raise SystemExit(1)
except Exception:
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 5
  done
  return 1
}

dump_deploy_debug() {
  echo "Compose status after failed smoke:" >&2
  "${COMPOSE_CMD[@]}" "${COMPOSE_ARGS[@]}" ps >&2 || true
  for service in "${deploy_args[@]}"; do
    echo "Recent logs for $service:" >&2
    "${COMPOSE_CMD[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail=200 "$service" >&2 || true
  done
}

trap 'on_error $LINENO' ERR

if ! command -v docker >/dev/null 2>&1; then
  echo "docker command not found; install Docker Desktop or another Docker runtime on this Mac." >&2
  exit 127
fi
if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo "docker compose command not found; install Docker Compose." >&2
  exit 127
fi

mkdir -p "$DEPLOY_PATH/deployments" "$DEPLOY_PATH/scripts" "$DEPLOY_PATH/logs" "$DEPLOY_PATH/logs/watchdog"
chmod 750 "$DEPLOY_PATH/logs"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  echo "Copy backend/.env to $DEPLOY_PATH/.env before deploying, or set ENV_FILE." >&2
  exit 1
fi
chmod 600 "$ENV_FILE"

COMPOSE_ARGS=(--env-file "$ENV_FILE" -f "$COMPOSE_FILE")
if [[ -e "$PRIVATE_PROFILE_FILE" ]]; then
  profile_enabled=$(python3 - "$PRIVATE_PROFILE_FILE" <<'PY'
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
info = path.lstat()
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise SystemExit("C_FAST SimNow profile marker must be a regular non-symlink file")
if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
    raise SystemExit("C_FAST SimNow profile marker must be owner-only and owned by deploy user")
lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
print("true" if lines == ["ENABLE_C_FAST_SIMNOW_PROFILE=true"] else "false")
PY
  )
  if [[ "$profile_enabled" != "true" ]]; then
    echo "Invalid C_FAST SimNow profile marker: $PRIVATE_PROFILE_FILE" >&2
    exit 1
  fi
  python3 - "$PRIVATE_RUNTIME_ENV_FILE" "$PRIVATE_COMPOSE_FILE" <<'PY'
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys

for raw in sys.argv[1:]:
    path = Path(raw)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"private deployment input must be a regular non-symlink file: {path}")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise SystemExit(f"private deployment input must be owner-only and owned by deploy user: {path}")
PY
  COMPOSE_ARGS+=(--env-file "$PRIVATE_RUNTIME_ENV_FILE" -f "$PRIVATE_COMPOSE_FILE")
  echo "C_FAST SimNow private deployment profile: enabled"
fi

if [[ "$IMAGE_REPO" == ghcr.io/* ]]; then
  if [[ -z "${GHCR_USERNAME:-}" || -z "${GHCR_TOKEN:-}" ]]; then
    echo "Missing GHCR credentials for private image pull. Required env: GHCR_USERNAME and GHCR_TOKEN" >&2
    echo "Current image: ${IMAGE_REPO}:${IMAGE_TAG}" >&2
    exit 1
  fi

  printf '%s' "$GHCR_TOKEN" | docker login ghcr.io --username "$GHCR_USERNAME" --password-stdin >/dev/null

  if ! docker manifest inspect "${IMAGE_REPO}:${IMAGE_TAG}" >/dev/null 2>&1; then
    echo "Unable to access image manifest: ${IMAGE_REPO}:${IMAGE_TAG}" >&2
    echo "Check GHCR token permissions, package visibility, image tag, and repository linkage." >&2
    exit 1
  fi
fi

export IMAGE_REPO IMAGE_TAG

echo "Deploy image: ${IMAGE_REPO}:${IMAGE_TAG}"
echo "Deploy services: ${DEPLOY_SERVICES}"
write_maintenance running "deploy in progress"

deploy_args=()
for service in $DEPLOY_SERVICES; do
  case "$service" in
    web-bridge)
      deploy_args+=("$service")
      ;;
    *)
      echo "Unsupported DEPLOY_SERVICES entry: $service" >&2
      echo "Allowed services: web-bridge" >&2
      exit 2
      ;;
  esac
done

if [[ "$DEPLOY_SKIP_PULL" != "true" ]]; then
  "${COMPOSE_CMD[@]}" "${COMPOSE_ARGS[@]}" pull "${deploy_args[@]}"
fi
"${COMPOSE_CMD[@]}" "${COMPOSE_ARGS[@]}" up -d --remove-orphans "${deploy_args[@]}"
docker image prune -f >/dev/null 2>&1 || true

if smoke_liveness; then
  clear_maintenance
else
  trap - ERR
  write_maintenance failed "deploy smoke failed: $DEPLOY_SMOKE_URL"
  echo "Deploy smoke failed: $DEPLOY_SMOKE_URL" >&2
  dump_deploy_debug
  exit 1
fi

echo "Deploy finished: ${IMAGE_REPO}:${IMAGE_TAG}"
