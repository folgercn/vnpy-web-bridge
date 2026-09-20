"""Cockpit Tools seamless account switcher adapter.

Communicates with Cockpit Tools via local WebSocket IPC to perform
instant, zero-restart account switches for Antigravity.
"""
import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import websockets

from research_lab.agent_control.antigravity_mcp.config import (
    ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
    COCKPIT_ACCOUNTS_JSON,
    COCKPIT_SERVER_JSON,
    SWITCH_SETTLE_SECONDS,
)

logger = logging.getLogger("antigravity_mcp.switcher")


class CockpitSwitcher:
    """Performs account switching requests against local Cockpit Tools backend."""

    def __init__(
        self,
        server_json: Path = COCKPIT_SERVER_JSON,
        cockpit_accounts_json: Path = COCKPIT_ACCOUNTS_JSON,
        manager_accounts_json: Path = ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
    ):
        self.server_json = Path(server_json)
        self.cockpit_accounts_json = Path(cockpit_accounts_json)
        self.manager_accounts_json = Path(manager_accounts_json)

    def is_available(self) -> bool:
        """Check if Cockpit Tools server configuration is present."""
        return self.server_json.exists()

    def _resolve_account_id_from_email(self, identifier: str) -> Optional[str]:
        """Resolve account_id from either Cockpit accounts or Antigravity-Manager accounts."""
        if not identifier:
            return None

        # Check if identifier is already a UUID-like string
        if len(identifier) >= 30 and "-" in identifier and "@" not in identifier:
            return identifier

        # Search Cockpit accounts.json
        if self.cockpit_accounts_json.exists():
            try:
                data = json.loads(self.cockpit_accounts_json.read_text(encoding="utf-8"))
                for acc in data.get("accounts", []):
                    if acc.get("email") == identifier or acc.get("id") == identifier:
                        return acc.get("id")
            except Exception:
                pass

        # Search Antigravity-Manager accounts.json
        if self.manager_accounts_json.exists():
            try:
                data = json.loads(self.manager_accounts_json.read_text(encoding="utf-8"))
                for acc in data.get("accounts", []):
                    if acc.get("email") == identifier or acc.get("id") == identifier:
                        return acc.get("id")
            except Exception:
                pass

        return None

    async def switch_account(self, identifier: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Switch active Antigravity account using Cockpit Tools.
        Identifier can be account_id or email address.
        Returns: (success: bool, message: str, details: dict)
        """
        if not self.is_available():
            msg = (
                "【无法执行后台切号】未检测到正在运行的 Cockpit-Tools 本地服务 (~/.antigravity_cockpit/server.json)。"
                "如需使用多账号无感热切功能，请先在本地启动 Cockpit-Tools；或在 Antigravity 客户端中手动切换登录。"
            )
            return False, msg, {"supported": False, "reason": "COCKPIT_NOT_RUNNING"}

        target_id = self._resolve_account_id_from_email(identifier)
        if not target_id:
            msg = f"未找到与 '{identifier}' 匹配的已注册账号 ID。"
            return False, msg, {"identifier": identifier, "resolved_id": None}

        try:
            server_info = json.loads(self.server_json.read_text(encoding="utf-8"))
            ws_port = server_info.get("ws_port")
            auth_token = server_info.get("auth_token", "")
            if not ws_port:
                return False, "Cockpit-Tools server.json 中缺少 ws_port 配置。", {}
        except Exception as e:
            return False, f"读取 Cockpit-Tools server.json 失败: {e}", {}

        uri = f"ws://127.0.0.1:{ws_port}"
        req_id = f"switch-{int(time.time() * 1000)}"
        msg = {
            "type": "request.switch_account",
            "id": req_id,
            "data": {
                "account_id": target_id,
                "auth_token": auth_token,
            },
        }

        try:
            async with websockets.connect(uri, ping_timeout=5, close_timeout=3) as ws:
                await ws.send(json.dumps(msg))
                # Loop to receive responses, ignoring initial greeting events like event.ready
                deadline = time.time() + 6.0
                while time.time() < deadline:
                    remain = max(0.5, deadline - time.time())
                    raw_resp = await asyncio.wait_for(ws.recv(), timeout=remain)
                    resp = json.loads(raw_resp)
                    r_type = resp.get("type", "")

                    if r_type in ("event.ready", "event.state", "event.sync"):
                        continue

                    if r_type == "response.switch_account" or r_type == "event.account_switched":
                        success = (
                            r_type == "event.account_switched"
                            or resp.get("data", {}).get("success", False)
                        )
                        if success:
                            await asyncio.sleep(SWITCH_SETTLE_SECONDS)
                            success_msg = f"成功通过 Cockpit-Tools 切换至目标账号 (ID: {target_id})。"
                            logger.info(success_msg)
                            return True, success_msg, {"account_id": target_id, "identifier": identifier}
                        else:
                            err_msg = resp.get("data", {}).get("message") or "Cockpit-Tools 返回切号失败。"
                            return False, f"切号失败: {err_msg}", resp

                return False, "等待 Cockpit-Tools 切号响应超时 (6.0s)", {}
        except Exception as e:
            logger.error("Failed to execute switch via Cockpit WebSocket: %s", e)
            return False, f"与 Cockpit-Tools WebSocket 通信异常: {e}", {"error": str(e)}
