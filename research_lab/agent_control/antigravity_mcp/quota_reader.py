"""Antigravity Multi-Account Quota & Weekly Limit Reader.

Directly reads high-precision model quotas and weekly quota ceilings
from Antigravity-Manager (~/.antigravity_tools/accounts/*.json).
"""
import glob
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from research_lab.agent_control.antigravity_mcp.config import (
    ANTIGRAVITY_TOOLS_ACCOUNTS_DIR,
    ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
    GEMINI_OAUTH_CREDS_JSON,
)

logger = logging.getLogger("antigravity_mcp.quota_reader")


class QuotaReader:
    """Reads and parses detailed per-account quotas including Gemini 3.1 Pro and Weekly ceilings."""

    def __init__(
        self,
        accounts_json: Path = ANTIGRAVITY_TOOLS_ACCOUNTS_JSON,
        accounts_dir: Path = ANTIGRAVITY_TOOLS_ACCOUNTS_DIR,
        oauth_creds_json: Path = GEMINI_OAUTH_CREDS_JSON,
    ):
        self.accounts_json = Path(accounts_json)
        self.accounts_dir = Path(accounts_dir)
        self.oauth_creds_json = Path(oauth_creds_json)

    def get_current_active_identity(self) -> Dict[str, Optional[str]]:
        """Identify the currently active account ID and email from local configs."""
        active_id = None
        active_email = None

        # 1. Try Antigravity-Manager accounts.json
        if self.accounts_json.exists():
            try:
                data = json.loads(self.accounts_json.read_text(encoding="utf-8"))
                active_id = data.get("current_account_id")
            except Exception:
                pass

        # 2. Try ~/.gemini/oauth_creds.json for active email
        if self.oauth_creds_json.exists():
            try:
                creds = json.loads(self.oauth_creds_json.read_text(encoding="utf-8"))
                active_email = creds.get("email")
            except Exception:
                pass

        return {"current_account_id": active_id, "current_email": active_email}

    def read_account_file(self, account_file: Path) -> Optional[Dict[str, Any]]:
        """Parse a single account json file and extract structured quotas."""
        if not account_file.exists():
            return None

        try:
            raw = json.loads(account_file.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error("Failed to parse account file %s: %s", account_file, e)
            return None

        account_id = raw.get("id") or account_file.stem
        email = raw.get("email", "unknown")
        name = raw.get("name", "")
        quota_data = raw.get("quota") or {}

        # 1. Extract raw model percentages (5h sliding window)
        models_list = quota_data.get("models", [])
        models_dict = {m.get("name"): m for m in models_list if isinstance(m, dict) and m.get("name")}

        # Specific model lookups
        gemini_3_1_pro_high = models_dict.get("gemini-3.1-pro-high", {})
        gemini_3_1_pro_low = models_dict.get("gemini-3.1-pro-low", {})
        gemini_2_5_pro = models_dict.get("gemini-2.5-pro", {})
        claude_sonnet = models_dict.get("claude-sonnet-4-6", {})
        gpt_oss = models_dict.get("gpt-oss-120b-medium", {})

        gemini_pro_pct = (
            gemini_3_1_pro_high.get("percentage")
            if gemini_3_1_pro_high.get("percentage") is not None
            else gemini_3_1_pro_low.get("percentage")
        )
        gemini_pro_reset = gemini_3_1_pro_high.get("reset_time") or gemini_3_1_pro_low.get("reset_time")

        claude_pct = claude_sonnet.get("percentage", 100)
        claude_reset = claude_sonnet.get("reset_time")

        # 2. Extract underlying Quota Groups (Weekly Limit vs 5h Limit)
        quota_groups = quota_data.get("quota_groups", [])
        gemini_weekly_frac: Optional[float] = None
        gemini_weekly_reset: Optional[str] = None
        gemini_5h_frac: Optional[float] = None
        gemini_5h_reset: Optional[str] = None

        claude_weekly_frac: Optional[float] = None
        claude_5h_frac: Optional[float] = None

        for group in quota_groups:
            if not isinstance(group, dict):
                continue
            g_name = group.get("display_name", "")
            for bucket in group.get("buckets", []):
                if not isinstance(bucket, dict):
                    continue
                window = bucket.get("window")
                frac = bucket.get("remaining_fraction")
                rst = bucket.get("reset_time")

                if "Gemini" in g_name:
                    if window == "weekly":
                        gemini_weekly_frac = frac
                        gemini_weekly_reset = rst
                    elif window == "5h":
                        gemini_5h_frac = frac
                        gemini_5h_reset = rst
                elif "Claude" in g_name or "3p" in str(bucket.get("bucket_id", "")):
                    if window == "weekly":
                        claude_weekly_frac = frac
                    elif window == "5h":
                        claude_5h_frac = frac

        # Risk assessment synthesis
        risk_warnings = []
        is_exhausted = False

        if gemini_weekly_frac is not None:
            if gemini_weekly_frac < 0.15:
                risk_warnings.append(f"【严重警告】Gemini 周全局硬顶仅剩 {gemini_weekly_frac*100:.1f}%，极度危险！切勿分配大任务")
                is_exhausted = True
            elif gemini_weekly_frac < 0.35:
                risk_warnings.append(f"【周额度吃紧】Gemini 周额度剩余 {gemini_weekly_frac*100:.1f}%，建议优先分配短期或轻量任务")

        if gemini_5h_frac is not None and gemini_5h_frac < 0.15:
            risk_warnings.append(f"【5小时额度见底】Gemini 当前短期额度仅剩 {gemini_5h_frac*100:.1f}%，建议切换账号或等待恢复")
            is_exhausted = True

        if not risk_warnings:
            health_status = "HEALTHY"
            recommendation = "额度充沛，适宜执行各类复杂或长期编码任务。"
        elif is_exhausted:
            health_status = "CRITICAL_LOW"
            recommendation = "建议立即切换至其他健康账号，避免产生 429 报错中断任务。"
        else:
            health_status = "CAUTION"
            recommendation = "周额度正在消耗中，建议审慎分配重型任务。"

        return {
            "id": account_id,
            "email": email,
            "name": name,
            "subscription_tier": quota_data.get("subscription_tier", "PRO"),
            "health_status": health_status,
            "recommendation": recommendation,
            "quotas": {
                "gemini_3_1_pro": {
                    "remaining_5h": f"{gemini_pro_pct}%" if gemini_pro_pct is not None else "100%",
                    "reset_time_5h": gemini_pro_reset,
                },
                "gemini_weekly_limit": {
                    "remaining": f"{gemini_weekly_frac * 100:.1f}%" if gemini_weekly_frac is not None else "未知",
                    "remaining_fraction": gemini_weekly_frac,
                    "reset_time": gemini_weekly_reset,
                },
                "claude_sonnet_4_6": {
                    "remaining_5h": f"{claude_pct}%",
                    "remaining_weekly": f"{claude_weekly_frac * 100:.1f}%" if claude_weekly_frac is not None else "100%",
                    "reset_time": claude_reset,
                },
            },
            "risk_warnings": risk_warnings,
        }

    def list_all_accounts(self) -> List[Dict[str, Any]]:
        """Return full list of accounts with active status and rich quota breakdowns."""
        active_info = self.get_current_active_identity()
        current_id = active_info.get("current_account_id")
        current_email = active_info.get("current_email")

        pattern = str(self.accounts_dir / "*.json")
        account_files = sorted(glob.glob(pattern))

        results = []
        for p_str in account_files:
            parsed = self.read_account_file(Path(p_str))
            if not parsed:
                continue

            acc_id = parsed.get("id")
            acc_email = parsed.get("email")
            is_current = (
                (current_id and acc_id == current_id)
                or (current_email and acc_email == current_email)
            )
            parsed["is_current"] = bool(is_current)
            results.append(parsed)

        # Sort accounts: Current account first, then by highest Gemini weekly remaining
        def sort_key(acc):
            is_curr = 0 if acc.get("is_current") else 1
            weekly_frac = acc.get("quotas", {}).get("gemini_weekly_limit", {}).get("remaining_fraction")
            try:
                weekly_val = float(weekly_frac) if weekly_frac is not None else 1.0
            except (ValueError, TypeError):
                weekly_val = 1.0
            return (is_curr, -weekly_val)

        results.sort(key=sort_key)
        return results
