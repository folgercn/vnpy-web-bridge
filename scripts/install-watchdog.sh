#!/usr/bin/env bash
set -euo pipefail

LABEL=${WATCHDOG_LABEL:-com.vnpy-web-bridge.watchdog}
DEPLOY_PATH=${DEPLOY_PATH:-/Users/fujun/services/vnpy-web-bridge}
PLIST_SOURCE=${PLIST_SOURCE:-$DEPLOY_PATH/deployments/${LABEL}.plist}
PLIST_TARGET="$HOME/Library/LaunchAgents/${LABEL}.plist"

case "${1:-install}" in
  install)
    if [[ ! -f "$PLIST_SOURCE" ]]; then
      echo "Missing plist: $PLIST_SOURCE" >&2
      exit 1
    fi
    mkdir -p "$HOME/Library/LaunchAgents"
    cp "$PLIST_SOURCE" "$PLIST_TARGET"
    launchctl bootout "gui/$(id -u)" "$PLIST_TARGET" >/dev/null 2>&1 || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST_TARGET"
    launchctl enable "gui/$(id -u)/$LABEL"
    launchctl kickstart -k "gui/$(id -u)/$LABEL"
    echo "installed $LABEL"
    ;;
  uninstall)
    launchctl bootout "gui/$(id -u)" "$PLIST_TARGET" >/dev/null 2>&1 || true
    rm -f "$PLIST_TARGET"
    echo "uninstalled $LABEL"
    ;;
  status)
    launchctl print "gui/$(id -u)/$LABEL"
    ;;
  *)
    echo "Usage: $0 [install|uninstall|status]" >&2
    exit 2
    ;;
esac
