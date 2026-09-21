"""Tool discovery and runtime availability inspector.

Checks presence and health of external tools:
1. Antigravity-Manager (~/.antigravity_tools): Provides multi-account quotas & weekly limits
2. Cockpit-Tools (~/.antigravity_cockpit): Provides seamless zero-restart account switching
"""
import json
import logging
from pathlib import Path
from typing import Any

from research_lab.agent_control.antigravity_mcp.config import (
    ANTIGRAVITY_TOOLS_ACCOUNTS_DIR,
    ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
    COCKPIT_SERVER_JSON,
)

logger = logging.getLogger("antigravity_mcp.inspector")


class ToolInspector:
    """Inspects external multi-account tooling environments and determines available capabilities."""

    def __init__(
        self,
        antigravity_tools_json: Path = ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
        antigravity_tools_dir: Path = ANTIGRAVITY_TOOLS_ACCOUNTS_DIR,
        cockpit_server_json: Path = COCKPIT_SERVER_JSON,
    ):
        self.antigravity_tools_json = Path(antigravity_tools_json)
        self.antigravity_tools_dir = Path(antigravity_tools_dir)
        self.cockpit_server_json = Path(cockpit_server_json)

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
            return True, f"Antigravity-Manager 正常运行，已检测到 {count} 个已注册账号及实时额度缓存。"
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
            return False, f"Antigravity-Manager 配置文件读取异常: {e}"

    def check_cockpit_tools(self) -> tuple[bool, str]:
        """Check if Cockpit-Tools (~/.antigravity_cockpit) is running with active server info."""
        if not self.cockpit_server_json.exists():
            return False, "Cockpit-Tools 本地服务未运行 (~/.antigravity_cockpit/server.json 不存在)。"

        try:
            server_info = json.loads(self.cockpit_server_json.read_text(encoding="utf-8"))
            ws_port = server_info.get("ws_port")
            if not ws_port:
                return False, "Cockpit-Tools server.json 中未配置有效 WebSocket 端口。"
            return True, f"Cockpit-Tools 本地后台正在运行 (WebSocket 端口: {ws_port})。"
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
            return False, f"Cockpit-Tools 状态检查异常: {e}"

    def get_capabilities_report(self) -> dict[str, Any]:
        """
        Generate a comprehensive capability diagnostic report.
        Clearly informs Codex whether multi-account inspection and switching are supported.
        """
        has_manager, manager_msg = self.check_antigravity_tools()
        has_cockpit, cockpit_msg = self.check_cockpit_tools()

        features = {
            "multi_account_quota_pool": has_manager,
            "weekly_quota_breakdown": has_manager,
            "seamless_account_switching": has_cockpit,
            "single_account_native_mode": True,
        }

        # Build user/codex-facing explanation
        status_notes = []
        if has_manager and has_cockpit:
            mode = "FULL_HYBRID_MODE"
            summary_message = (
                "【完全体模式】已同时检测到 Antigravity-Manager 与 Cockpit-Tools。"
                "全面支持全账号高精度额度查看（含 Gemini 3.1 Pro、周全局硬顶额度）及毫秒级无感热切号。"
            )
        elif has_manager and not has_cockpit:
            mode = "QUOTA_MONITOR_ONLY"
            summary_message = (
                "【配额监控模式】已检测到 Antigravity-Manager，可查看全部账号额度明细与周额度；"
                "但未检测到 Cockpit-Tools 运行，当前不提供自动化热切号功能（如需切号请在客户端手动切换或启动 Cockpit）。"
            )
            status_notes.append("Cockpit-Tools 缺失: switch_account 处于降级状态。")
        elif not has_manager and has_cockpit:
            mode = "SWITCH_ONLY"
            summary_message = (
                "【快速切号模式】已检测到 Cockpit-Tools，支持账号热切换；"
                "但未检测到 Antigravity-Manager，多账号高精配额池无法使用，额度仅依赖官方原生接口。"
            )
            status_notes.append("Antigravity-Manager 缺失: 无法预读取所有未激活账号的模型与周额度。")
        else:
            mode = "SINGLE_ACCOUNT_FALLBACK"
            summary_message = (
                "【单账号原生模式】未在本地检测到 Antigravity-Manager 或 Cockpit-Tools。"
                "多账号池与切号功能已关闭，MCP 以单账号模式稳定运行，核心派单（submit/watch/status）不受影响。"
            )
            status_notes.append("两项多账号外部工具均未配置，不提供多账号聚合额度与切号功能。")

        return {
            "mode": mode,
            "antigravity_tools": {
                "available": has_manager,
                "message": manager_msg,
            },
            "cockpit_tools": {
                "available": has_cockpit,
                "message": cockpit_msg,
            },
            "features": features,
            "summary_message": summary_message,
            "status_notes": status_notes,
        }
