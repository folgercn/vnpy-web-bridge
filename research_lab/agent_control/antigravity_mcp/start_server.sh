#!/usr/bin/env bash
# ==============================================================================
# Start Codex Antigravity Network MCP Server
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VNPY_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

export PYTHONPATH="${VNPY_ROOT}:${SCRIPT_DIR}:${SCRIPT_DIR}/core:${PYTHONPATH:-}"

PYTHON_BIN="/Users/fujun/.codex/skills/antigravity-delegate/.mcp-venv/bin/python"
if [[ ! -f "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

HOST="${AGY_MCP_HOST:-127.0.0.1}"
PORT="${AGY_MCP_PORT:-8765}"
TRANSPORT="${AGY_MCP_TRANSPORT:-sse}"

echo "======================================================================"
echo " Starting Antigravity Network MCP Server for Codex..."
echo " Python    : ${PYTHON_BIN}"
echo " Transport : ${TRANSPORT}"
echo " Bind Host : ${HOST}"
echo " Port      : ${PORT}"
echo "======================================================================"

exec "${PYTHON_BIN}" "${SCRIPT_DIR}/server.py" \
  --transport "${TRANSPORT}" \
  --host "${HOST}" \
  --port "${PORT}"
