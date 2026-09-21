"""Tool discovery and runtime availability inspector.

Checks presence and health of Antigravity-Manager (~/.antigravity_tools).
Antigravity-Manager provides:
1. Multi-account discovery, live quota inspection & weekly limit breakdowns
2. Safe account switching with official app restart (/Applications/Antigravity.app)
"""
import json
import logging
from pathlib import Path
from typing import Any

from research_lab.agent_control.antigravity_mcp.config import (
    ANTIGRAVITY_TOOLS_ACCOUNTS_DIR,
    ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
    ANTIGRAVITY_TOOLS_GUI_CONFIG,
)

logger = logging.getLogger("antigravity_mcp.inspector")


class ToolInspector:
    """Inspects external multi-account tooling environments and determines available capabilities."""

    def __init__(
        self,
        antigravity_tools_json: Path = ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
        antigravity_tools_dir: Path = ANTIGRAVITY_TOOLS_ACCOUNTS_DIR,
        antigravity_gui_config: Path = ANTIGRAVITY_TOOLS_GUI_CONFIG,
    ):
        self.antigravity_tools_json = Path(antigravity_tools_json)
        self.antigravity_tools_dir = Path(antigravity_tools_dir)
        self.antigravity_gui_config = Path(antigravity_gui_config)

    def check_antigravity_tools(self) -> tuple[bool, str]:
        """Check if Antigravity-Manager (~/.antigravity_tools) is installed with valid accounts."""
        if not self.antigravity_tools_json.exists():
            return False, "Antigravity-Manager (~/.antigravity_tools/accounts.json) 未找到。"

        try:
            content = json.loads(self.antigravity_tools_json.read_text(encoding="utf-8"))
            accounts = content.get("accounts", [])
            count = len(accounts)
            if count == 0:
                return False, "Antigravity-Manager 已安装但未导入任何账号。"
            return True, f"Antigravity-Manager 正常运行，已检测到 {count} 个已注册账号及实时额度配置。"
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
            return False, f"Antigravity-Manager 配置文件读取异常: {e}"

    def get_capabilities_report(self) -> dict[str, Any]:
        """
        Generate a comprehensive capability diagnostic report.
        Clearly informs Codex whether multi-account inspection and safe switching are supported.
        """
        has_manager, manager_msg = self.check_antigravity_tools()

        features = {
            "multi_account_quota_pool": has_manager,
            "weekly_quota_breakdown": has_manager,
            "safe_account_switching": has_manager,
            "single_account_native_mode": True,
        }

        status_notes = []
        if has_manager:
            mode = "MANAGER_FULL_MODE"
            summary_message = (
                "【Antigravity-Manager 完整模式】已检测到 Antigravity-Manager 运行环境。"
                "全面支持多账号高精度额度查看（含 Gemini 3.1 Pro、周全局额度）及安全切号（重启 APP 方式）。"
            )
        else:
            mode = "SINGLE_ACCOUNT_FALLBACK"
            summary_message = (
                "【单账号原生模式】未在本地检测到 Antigravity-Manager。"
                "多账号池与切号功能已关闭，MCP 以单账号模式稳定运行，核心任务派发不受影响。"
            )
            status_notes.append("Antigravity-Manager 未配置: 多账号聚合额度与切号功能不可用。")

        return {
            "mode": mode,
            "antigravity_tools": {
                "available": has_manager,
                "message": manager_msg,
            },
            "features": features,
            "summary_message": summary_message,
            "status_notes": status_notes,
        }
