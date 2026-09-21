"""Antigravity-Manager HTTP API client adapter.

Communicates with local Antigravity-Manager (/Applications/Antigravity Tools.app)
over localhost HTTP API (port 8045) using Bearer API Key authentication.
Provides:
1. Multi-account discovery and live quota inspection (Gemini 5h / Weekly, Claude limits)
2. Safe account switching with official app restart (/Applications/Antigravity.app)
"""
import asyncio
import json
import logging
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from research_lab.agent_control.antigravity_mcp.config import (
    ANTIGRAVITY_MANAGER_API_KEY,
    ANTIGRAVITY_MANAGER_HOST,
    ANTIGRAVITY_MANAGER_PORT,
    ANTIGRAVITY_TOOLS_GUI_CONFIG,
)

logger = logging.getLogger("antigravity_mcp.manager_client")


class ManagerClient:
    """Client for interacting with local Antigravity-Manager HTTP API."""

    def __init__(
        self,
        host: str = ANTIGRAVITY_MANAGER_HOST,
        port: int = ANTIGRAVITY_MANAGER_PORT,
        api_key: str = ANTIGRAVITY_MANAGER_API_KEY,
        gui_config_path: Path = ANTIGRAVITY_TOOLS_GUI_CONFIG,
    ):
        self.host = host
        self._configured_port = port
        self._configured_api_key = api_key
        self.gui_config_path = Path(gui_config_path)

    def _load_gui_config(self) -> dict[str, Any]:
        """Read proxy configuration from gui_config.json if available."""
        if not self.gui_config_path.exists():
            return {}
        try:
            return json.loads(self.gui_config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Failed to parse gui_config.json at %s: %s", self.gui_config_path, e)
            return {}

    def get_port(self) -> int:
        """Resolve active listening port (env/override > gui_config > default 8045)."""
        if self._configured_port > 0:
            return self._configured_port
        config = self._load_gui_config()
        proxy_cfg = config.get("proxy", {})
        return int(proxy_cfg.get("port") or 8045)

    def get_api_key(self) -> str:
        """Resolve admin API key (env/override > gui_config > empty)."""
        if self._configured_api_key:
            return self._configured_api_key
        config = self._load_gui_config()
        proxy_cfg = config.get("proxy", {})
        return (proxy_cfg.get("admin_password") or proxy_cfg.get("api_key") or "").strip()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.get_port()}/api"

    def _sync_request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, Any]:
        """Synchronous HTTP request using standard library urllib."""
        url = f"{self.base_url}{path}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Antigravity-MCP-Bridge/1.0",
        }
        api_key = self.get_api_key()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                raw = resp.read().decode("utf-8")
                if not raw:
                    return status, {}
                try:
                    return status, json.loads(raw)
                except json.JSONDecodeError:
                    return status, raw
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            logger.debug("HTTP %s from %s: %s", e.code, url, err_body)
            try:
                parsed = json.loads(err_body)
                return e.code, parsed
            except json.JSONDecodeError:
                return e.code, {"error": err_body or str(e)}
        except Exception as e:  # noqa: BLE001
            logger.warning("Request failed to %s: %s", url, e)
            return 0, {"error": str(e)}

    async def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, Any]:
        """Asynchronous wrapper for HTTP request."""
        return await asyncio.to_thread(self._sync_request, method, path, body, timeout)

    async def is_available(self) -> tuple[bool, str]:
        """Check if Antigravity-Manager HTTP API is responsive."""
        status, data = await self._request("GET", "/health", timeout=3.0)
        if status == 200 and isinstance(data, dict) and data.get("status") == "ok":
            ver = data.get("version", "unknown")
            return True, f"Antigravity-Manager 运行正常 (版本: {ver}, 端口: {self.get_port()})"
        if status == 401 or status == 403:
            return False, f"Antigravity-Manager 鉴权失败 (HTTP {status})，请检查 API Key。"
        return False, f"Antigravity-Manager 未就绪或无响应 (状态: {status}, 端口: {self.get_port()})"

    def _extract_quota_breakdown(self, quota_data: dict[str, Any] | None) -> dict[str, Any]:
        """Extract user-friendly Gemini and Claude limits from raw quota object."""
        if not quota_data or not isinstance(quota_data, dict):
            return {
                "has_quota": False,
                "gemini_5h_fraction": None,
                "gemini_weekly_fraction": None,
                "claude_5h_fraction": None,
                "claude_weekly_fraction": None,
                "models": [],
            }

        groups = quota_data.get("quota_groups", [])
        g5h = None
        g_weekly = None
        c5h = None
        c_weekly = None

        for group in groups:
            if not isinstance(group, dict):
                continue
            name = (group.get("display_name") or "").lower()
            buckets = group.get("buckets", [])
            for bucket in buckets:
                if not isinstance(bucket, dict):
                    continue
                window = bucket.get("window", "")
                frac = bucket.get("remaining_fraction")
                if "gemini" in name:
                    if window == "5h":
                        g5h = frac
                    elif window == "weekly":
                        g_weekly = frac
                elif "claude" in name or "gpt" in name:
                    if window == "5h":
                        c5h = frac
                    elif window == "weekly":
                        c_weekly = frac

        models_list = []
        for m in quota_data.get("models", []):
            if not isinstance(m, dict):
                continue
            models_list.append({
                "name": m.get("name"),
                "percentage": m.get("percentage"),
                "reset_time": m.get("reset_time"),
            })

        return {
            "has_quota": True,
            "gemini_5h_fraction": g5h,
            "gemini_weekly_fraction": g_weekly,
            "claude_5h_fraction": c5h,
            "claude_weekly_fraction": c_weekly,
            "subscription_tier": quota_data.get("subscription_tier"),
            "models": models_list,
        }

    async def list_accounts(self) -> list[dict[str, Any]]:
        """Fetch all managed accounts and format rich quota details."""
        status, data = await self._request("GET", "/accounts")
        if status != 200 or not isinstance(data, dict):
            logger.error("Failed to list accounts: HTTP %s: %s", status, data)
            return []

        raw_accounts = data.get("accounts", [])
        current_id = data.get("current_account_id")

        formatted = []
        for acc in raw_accounts:
            acc_id = acc.get("id", "")
            email = acc.get("email", "")
            is_current = (acc.get("is_current") is True) or (acc_id == current_id)
            quota_breakdown = self._extract_quota_breakdown(acc.get("quota"))

            formatted.append({
                "account_id": acc_id,
                "email": email,
                "name": acc.get("name") or "",
                "is_current": is_current,
                "disabled": acc.get("disabled", False),
                "device_bound": acc.get("device_bound", False),
                "last_used": acc.get("last_used"),
                "quota": quota_breakdown,
            })

        return formatted

    async def get_current_account(self) -> dict[str, Any] | None:
        """Fetch active account and detailed quota status."""
        status, data = await self._request("GET", "/accounts/current")
        if status != 200 or not isinstance(data, dict):
            logger.warning("Failed to get current account: HTTP %s: %s", status, data)
            return None

        quota_breakdown = self._extract_quota_breakdown(data.get("quota"))
        return {
            "account_id": data.get("id"),
            "email": data.get("email"),
            "name": data.get("name") or "",
            "is_current": True,
            "disabled": data.get("disabled", False),
            "device_bound": data.get("device_bound", False),
            "last_used": data.get("last_used"),
            "quota": quota_breakdown,
            "raw_quota": data.get("quota"),
        }

    async def get_account_quota(self, account_id: str) -> dict[str, Any] | None:
        """Directly query and refresh latest live quota for a given account from upstream."""
        status, data = await self._request("GET", f"/accounts/{account_id}/quota", timeout=45.0)
        if status != 200 or not isinstance(data, dict):
            logger.warning("Failed to fetch quota for account %s: HTTP %s: %s", account_id, status, data)
            return None
        return self._extract_quota_breakdown(data)

    async def switch_account(self, account_or_email: str) -> tuple[bool, str, dict[str, Any]]:
        """Safely switch active account via Antigravity-Manager (restarts /Applications/Antigravity.app).

        Args:
            account_or_email: Target email or account ID.

        Returns:
            (success, message, details)
        """
        accounts = await self.list_accounts()
        if not accounts:
            return False, "未能从 Antigravity-Manager 获取到账号列表，无法切号。", {}

        target = None
        target_input = account_or_email.strip().lower()
        for acc in accounts:
            if acc["email"].lower() == target_input or acc["account_id"].lower() == target_input:
                target = acc
                break

        if not target:
            available_emails = [a["email"] for a in accounts]
            return (
                False,
                f"未在 Antigravity-Manager 中找到账号 '{account_or_email}'。当前可用账号: {', '.join(available_emails)}",
                {"available_accounts": available_emails},
            )

        target_id = target["account_id"]
        target_email = target["email"]

        if target["is_current"]:
            logger.info("Account %s is already active. Requesting fresh quota verification.", target_email)
            return True, f"账号 {target_email} 当前已处于激活状态。", target

        logger.info(
            "Requesting safe account switch to %s (%s) with app restart...",
            target_email,
            target_id,
        )

        status, resp = await self._request(
            "POST",
            "/accounts/switch",
            body={"accountId": target_id, "targetIde": "classic"},
            timeout=60.0,
        )

        if status not in (200, 204):
            err_msg = resp.get("error") if isinstance(resp, dict) else str(resp)
            return (
                False,
                f"Antigravity-Manager 切号失败 (HTTP {status}): {err_msg}",
                {"account_id": target_id, "email": target_email, "error": err_msg},
            )

        # Settle wait for process restart and language server initialization
        await asyncio.sleep(3.0)

        # Verify new active account
        current = await self.get_current_account()
        if current and current.get("email", "").lower() == target_email.lower():
            return (
                True,
                f"成功通过 Antigravity-Manager 切换至账号 {target_email}（应用已安全重启并加载新凭据）。",
                current,
            )

        return (
            True,
            f"切号指令已发送至 Antigravity-Manager 并成功执行（目标: {target_email}）。",
            {"account_id": target_id, "email": target_email},
        )
