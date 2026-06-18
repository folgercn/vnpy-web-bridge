#!/usr/bin/env bash
set -euo pipefail

LABEL=${WATCHDOG_LABEL:-com.vnpy-web-bridge.watchdog}
DEPLOY_PATH=${DEPLOY_PATH:-/Users/fujun/services/vnpy-web-bridge}
PLIST_TARGET="$HOME/Library/LaunchAgents/${LABEL}.plist"
PYTHON_BIN=${PYTHON_BIN:-/usr/bin/python3}

write_plist() {
  mkdir -p "$HOME/Library/LaunchAgents" "$DEPLOY_PATH/logs/watchdog"
  "$PYTHON_BIN" - "$PLIST_TARGET" "$LABEL" "$DEPLOY_PATH" <<'PY'
from __future__ import annotations

import plistlib
import sys
from pathlib import Path

target, label, deploy_path = sys.argv[1:4]
deploy = Path(deploy_path)
payload = {
    "Label": label,
    "ProgramArguments": [
        "/usr/bin/python3",
        str(deploy / "scripts/watchdog.py"),
        "--env-file",
        str(deploy / ".env"),
    ],
    "WorkingDirectory": str(deploy),
    "RunAtLoad": True,
    "KeepAlive": True,
    "StandardOutPath": str(deploy / "logs/watchdog/stdout.log"),
    "StandardErrorPath": str(deploy / "logs/watchdog/stderr.log"),
    "EnvironmentVariables": {
        "PATH": "/Applications/Docker.app/Contents/Resources/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "WATCHDOG_ENABLED": "true",
    },
}
with open(target, "wb") as file:
    plistlib.dump(payload, file)
PY
}

run_launchctl() {
  "$PYTHON_BIN" - "$@" <<'PY'
from __future__ import annotations

import subprocess
import sys

try:
    result = subprocess.run(["launchctl", *sys.argv[1:]], timeout=20)
except subprocess.TimeoutExpired:
    print(f"launchctl timed out: {' '.join(sys.argv[1:])}", file=sys.stderr)
    raise SystemExit(124)
raise SystemExit(result.returncode)
PY
}

case "${1:-install}" in
  install)
    if [[ ! -f "$DEPLOY_PATH/scripts/watchdog.py" ]]; then
      echo "Missing watchdog script: $DEPLOY_PATH/scripts/watchdog.py" >&2
      exit 1
    fi
    write_plist
    run_launchctl bootout "gui/$(id -u)" "$PLIST_TARGET" >/dev/null 2>&1 || true
    run_launchctl bootstrap "gui/$(id -u)" "$PLIST_TARGET"
    run_launchctl enable "gui/$(id -u)/$LABEL"
    run_launchctl kickstart -k "gui/$(id -u)/$LABEL"
    echo "installed $LABEL"
    ;;
  uninstall)
    run_launchctl bootout "gui/$(id -u)" "$PLIST_TARGET" >/dev/null 2>&1 || true
    rm -f "$PLIST_TARGET"
    echo "uninstalled $LABEL"
    ;;
  status)
    run_launchctl print "gui/$(id -u)/$LABEL"
    ;;
  *)
    echo "Usage: $0 [install|uninstall|status]" >&2
    exit 2
    ;;
esac
