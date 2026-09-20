"""Configuration for Codex Antigravity Network MCP with multi-account inspection."""
import os
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent

# MCP Server network listening configuration
DEFAULT_HOST = os.environ.get("AGY_MCP_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("AGY_MCP_PORT", "8765"))
DEFAULT_TRANSPORT = os.environ.get("AGY_MCP_TRANSPORT", "sse")

# Security access token (Bearer or ?api_key=)
AGY_MCP_API_KEY = os.environ.get("AGY_MCP_API_KEY", "").strip()

# External multi-account tools local paths
HOME_DIR = Path.home()
ANTIGRAVITY_TOOLS_DIR = HOME_DIR / ".antigravity_tools"
ANTIGRAVITY_TOOLS_ACCOUNTS_JSON = ANTIGRAVITY_TOOLS_DIR / "accounts.json"
ANTIGRAVITY_TOOLS_ACCOUNTS_DIR = ANTIGRAVITY_TOOLS_DIR / "accounts"

COCKPIT_DIR = HOME_DIR / ".antigravity_cockpit"
COCKPIT_SERVER_JSON = COCKPIT_DIR / "server.json"
COCKPIT_ACCOUNTS_JSON = COCKPIT_DIR / "accounts.json"
COCKPIT_CURRENT_ACCOUNT_JSON = COCKPIT_DIR / "current_account.json"

# Local Gemini / Antigravity credential paths
GEMINI_OAUTH_CREDS_JSON = HOME_DIR / ".gemini" / "oauth_creds.json"

# Usage statistics persistence
DATA_DIR = CURRENT_DIR / "data"
STATS_FILE = DATA_DIR / "usage_stats.json"

# Waiting duration after switching account for credential reload (seconds)
SWITCH_SETTLE_SECONDS = float(os.environ.get("AGY_SWITCH_SETTLE_SECONDS", "1.5"))
