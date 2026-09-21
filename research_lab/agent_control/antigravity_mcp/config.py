"""Configuration for Codex Antigravity Network MCP with multi-account inspection."""
import os
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
DATA_DIR = CURRENT_DIR / "data"
STATS_FILE = DATA_DIR / "usage_stats.json"

# MCP Server network listening configuration
DEFAULT_HOST = os.environ.get("AGY_MCP_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("AGY_MCP_PORT", "8765"))
DEFAULT_TRANSPORT = os.environ.get("AGY_MCP_TRANSPORT", "sse")

# Security access token (Bearer or ?api_key=)
AGY_MCP_API_KEY = os.environ.get("AGY_MCP_API_KEY", "").strip()

# Local Unix Domain Socket (UDS) configuration
# Default to data/run/antigravity_mcp.sock (dedicated isolated runtime directory)
RUN_DIR = DATA_DIR / "run"
DEFAULT_SOCKET_PATH = Path(os.environ.get("AGY_MCP_SOCKET_PATH", str(RUN_DIR / "antigravity_mcp.sock")))
AGY_MCP_SOCKET_AUTH = os.environ.get("AGY_MCP_SOCKET_AUTH", "false").lower() in ("true", "1", "yes")

# External multi-account tools local paths
HOME_DIR = Path.home()
ANTIGRAVITY_TOOLS_DIR = HOME_DIR / ".antigravity_tools"
ANTIGRAVITY_TOOLS_ACCOUNTS_JSON = ANTIGRAVITY_TOOLS_DIR / "accounts.json"
ANTIGRAVITY_TOOLS_ACCOUNTS_DIR = ANTIGRAVITY_TOOLS_DIR / "accounts"
ANTIGRAVITY_TOOLS_GUI_CONFIG = ANTIGRAVITY_TOOLS_DIR / "gui_config.json"

# Antigravity-Manager HTTP API configuration
ANTIGRAVITY_MANAGER_HOST = os.environ.get("AGY_MANAGER_HOST", "127.0.0.1")
ANTIGRAVITY_MANAGER_PORT = int(os.environ.get("AGY_MANAGER_PORT", "0"))  # 0: auto-detect from gui_config.json, default 8045
ANTIGRAVITY_MANAGER_API_KEY = os.environ.get("AGY_MANAGER_API_KEY", "")  # empty: auto-detect from gui_config.json

# Local Gemini / Antigravity credential paths
GEMINI_OAUTH_CREDS_JSON = HOME_DIR / ".gemini" / "oauth_creds.json"

# Usage statistics persistence (DATA_DIR and STATS_FILE defined above)

# Waiting duration after switching account for credential reload (seconds)
SWITCH_SETTLE_SECONDS = float(os.environ.get("AGY_SWITCH_SETTLE_SECONDS", "1.5"))
