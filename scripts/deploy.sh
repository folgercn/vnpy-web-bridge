#!/usr/bin/env bash
set -euo pipefail

export PATH="/Applications/Docker.app/Contents/Resources/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

DEPLOY_PATH=${DEPLOY_PATH:-/Users/fujun/services/vnpy-web-bridge}
COMPOSE_FILE="$DEPLOY_PATH/deployments/docker-compose.prod.yml"
IMAGE_REPO=${IMAGE_REPO:-ghcr.io/folgercn/vnpy-web-bridge-app}
IMAGE_TAG=${IMAGE_TAG:-latest}
DOCKER_CONFIG_DIR=${DOCKER_CONFIG_DIR:-$DEPLOY_PATH/.docker-ci}
DEPLOY_SERVICES=${DEPLOY_SERVICES:-web-bridge}
ENV_FILE=${ENV_FILE:-$DEPLOY_PATH/.env}
DEPLOY_SKIP_PULL=${DEPLOY_SKIP_PULL:-false}

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

mkdir -p "$DEPLOY_PATH/deployments" "$DEPLOY_PATH/scripts" "$DEPLOY_PATH/logs"
chmod 750 "$DEPLOY_PATH/logs"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  echo "Copy backend/.env to $DEPLOY_PATH/.env before deploying, or set ENV_FILE." >&2
  exit 1
fi
chmod 600 "$ENV_FILE"

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
  "${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" pull "${deploy_args[@]}"
fi
"${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" up -d --remove-orphans "${deploy_args[@]}"
docker image prune -f >/dev/null 2>&1 || true

echo "Deploy finished: ${IMAGE_REPO}:${IMAGE_TAG}"
