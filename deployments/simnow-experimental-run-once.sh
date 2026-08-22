#!/bin/zsh
# Wake-only host adapter for one SIMNOW_EXPERIMENTAL runner invocation.
# It owns no target state or retry loop: the target/materializer and existing
# Execution lifecycle remain the sole sources of state and mutation authority.
set -euo pipefail

: "${SIMNOW_EXPERIMENTAL_TARGET_PATH:?required}"
: "${SIMNOW_EXPERIMENTAL_MONTHLY_BUNDLE_DIR:?required}"
: "${SIMNOW_EXPERIMENTAL_BASE_COMPOSE_FILE:?required}"
: "${SIMNOW_EXPERIMENTAL_COMPOSE_FILE:?required}"
: "${SIMNOW_EXPERIMENTAL_UID:?required}"
: "${SIMNOW_EXPERIMENTAL_GID:?required}"
: "${SIMNOW_EXPERIMENTAL_PROJECT_DIRECTORY:?required}"

target_path="$SIMNOW_EXPERIMENTAL_TARGET_PATH"
bundle_directory="$SIMNOW_EXPERIMENTAL_MONTHLY_BUNDLE_DIR"

# WatchPaths and calendar wakes commonly occur before the materializer has a
# target.  Do not start Docker, create a file, or mutate any runtime state.
[[ -f "$target_path" ]] || exit 0

source_month="$(/usr/bin/python3 - "$target_path" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], "rb") as target:
        value = json.load(target)
    source_month = value["source_month"]
except (OSError, ValueError, KeyError, TypeError):
    raise SystemExit(1)
if not isinstance(source_month, str) or re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])", source_month) is None:
    raise SystemExit(1)
print(source_month)
PY
)"
bundle_path="$bundle_directory/$source_month.json"
[[ -f "$bundle_path" ]] || exit 1

# BSD date is intentional: this launcher runs on the M2 launchd host.  Each
# one-shot gets a short new planner expiry rather than retaining a schedule
# cursor or retry state.
expires_at="$(/bin/date -u -v+300S '+%Y-%m-%dT%H:%M:%SZ')"

export SIMNOW_EXPERIMENTAL_TARGET_PATH
export SIMNOW_EXPERIMENTAL_MONTHLY_BUNDLE_DIR
export SIMNOW_EXPERIMENTAL_UID
export SIMNOW_EXPERIMENTAL_GID

exec "${SIMNOW_EXPERIMENTAL_DOCKER_BIN:-/Applications/Docker.app/Contents/Resources/bin/docker}" \
  --context "${SIMNOW_EXPERIMENTAL_DOCKER_CONTEXT:-desktop-linux}" \
  compose \
  --project-directory "$SIMNOW_EXPERIMENTAL_PROJECT_DIRECTORY" \
  -f "$SIMNOW_EXPERIMENTAL_BASE_COMPOSE_FILE" \
  -f "$SIMNOW_EXPERIMENTAL_COMPOSE_FILE" \
  run --rm --no-deps simnow-experimental-runner \
  --target /run/simnow-experimental/target.json \
  --monthly-planner-bundle "/run/simnow-experimental/monthly/$source_month.json" \
  --expires-at "$expires_at" \
  --execute
