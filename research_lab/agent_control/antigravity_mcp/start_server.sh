#!/usr/bin/env bash
# ==============================================================================
# Start Codex Antigravity Network MCP Server
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VNPY_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

export PYTHONPATH="${VNPY_ROOT}:${SCRIPT_DIR}:${SCRIPT_DIR}/core:${PYTHONPATH:-}"

# 优先使用本地项目虚拟环境
if [[ -f "${VNPY_ROOT}/.venv/bin/python" ]] && "${VNPY_ROOT}/.venv/bin/python" -c "import mcp" 2>/dev/null; then
  PYTHON_BIN="${VNPY_ROOT}/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

HOST="${AGY_MCP_HOST:-127.0.0.1}"
PORT="${AGY_MCP_PORT:-8765}"
TRANSPORT="${AGY_MCP_TRANSPORT:-sse}"

echo "======================================================================"
echo " Starting Antigravity Network MCP Server..."
echo " Python    : ${PYTHON_BIN}"
echo " Transport : ${TRANSPORT}"
echo " Bind Host : ${HOST}"
echo " Port      : ${PORT}"
echo "======================================================================"

exec "${PYTHON_BIN}" "${SCRIPT_DIR}/server.py" \
  --transport "${TRANSPORT}" \
  --host "${HOST}" \
  --port "${PORT}"
