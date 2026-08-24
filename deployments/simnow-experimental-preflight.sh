#!/bin/bash
# One-shot, no-mutation host adapter for the SIMNOW_EXPERIMENTAL preflight.
# It deliberately uses an isolated Compose project and external runtime graph.
set -euo pipefail

: "${SIMNOW_EXPERIMENTAL_TARGET_PATH:?required}"
: "${SIMNOW_EXPERIMENTAL_MONTHLY_BUNDLE_DIR:?required}"
: "${SIMNOW_EXPERIMENTAL_COMPOSE_FILE:?required}"
: "${SIMNOW_EXPERIMENTAL_PROJECT_DIRECTORY:?required}"
: "${COMPOSE_PROJECT_NAME:?required}"

docker_bin="${SIMNOW_EXPERIMENTAL_DOCKER_BIN:-/Applications/Docker.app/Contents/Resources/bin/docker}"
docker_context="${SIMNOW_EXPERIMENTAL_DOCKER_CONTEXT:-desktop-linux}"
target_path="$SIMNOW_EXPERIMENTAL_TARGET_PATH"
bundle_directory="$SIMNOW_EXPERIMENTAL_MONTHLY_BUNDLE_DIR"
export SIMNOW_EXPERIMENTAL_ACTIVE_PROJECT="$COMPOSE_PROJECT_NAME"

source_month="$(/usr/bin/python3 - "$target_path" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], "rb") as target:
        source_month = json.load(target)["source_month"]
except (OSError, ValueError, KeyError, TypeError):
    raise SystemExit(1)
if not isinstance(source_month, str) or re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])", source_month) is None:
    raise SystemExit(1)
print(source_month)
PY
)"
bundle_path="$bundle_directory/$source_month.json"

compose=("$docker_bin" --context "$docker_context" compose
  --project-name "${COMPOSE_PROJECT_NAME}-simnow-experimental"
  --project-directory "$SIMNOW_EXPERIMENTAL_PROJECT_DIRECTORY"
  -f "$SIMNOW_EXPERIMENTAL_COMPOSE_FILE")

if ! "${compose[@]}" config -q; then
  echo "STOP compose=config-invalid" >&2
  exit 1
fi
image="$("${compose[@]}" config --images simnow-experimental-runner)"
if [[ -z "$image" ]] || ! "$docker_bin" --context "$docker_context" image inspect "$image" >/dev/null; then
  echo "STOP image=missing" >&2
  exit 1
fi

# This reads only the one non-secret boolean from the exact active Custody
# container.  Do not inspect or print the full environment: it contains the
# custody shared secret.  The one-off Compose config is useful wiring evidence,
# but the running container is the source of truth for this gate.
custody_container="${SIMNOW_EXPERIMENTAL_CUSTODY_CONTAINER:-${COMPOSE_PROJECT_NAME}-artifact-custody-1}"
if ! keyless_enabled="$("$docker_bin" --context "$docker_context" inspect \
  --format '{{range .Config.Env}}{{if eq . "SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED=true"}}true{{else if eq . "SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED=false"}}false{{end}}{{end}}' \
  "$custody_container" 2>/dev/null)"; then
  echo "STOP custody-config=container-unavailable" >&2
  exit 1
fi
case "$keyless_enabled" in
  true) ;;
  false)
    echo "STOP custody-config=keyless-disabled" >&2
    exit 1
    ;;
  "")
    echo "STOP custody-config=keyless-setting-missing" >&2
    exit 1
    ;;
  *)
    echo "STOP custody-config=keyless-setting-invalid" >&2
    exit 1
    ;;
esac

exec "${compose[@]}" run --rm --no-deps --entrypoint python simnow-experimental-runner \
  /app/scripts/simnow_experimental_preflight.py \
  --target /run/simnow-experimental/target.json \
  --monthly-planner-bundle "/run/simnow-experimental/monthly/$source_month.json"
