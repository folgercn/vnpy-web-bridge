"""Antigravity Multi-Account Quota & Weekly Limit Reader.

Directly reads high-precision model quotas and weekly quota ceilings
from Antigravity-Manager (~/.antigravity_tools/accounts/*.json).
"""
import contextlib
import glob
import json
import logging
from pathlib import Path
from typing import Any

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

    def get_current_active_identity(self) -> dict[str, str | None]:
        """Identify the currently active account ID and email from local configs."""
        active_id = None
        active_email = None

        # 1. Try Antigravity-Manager accounts.json
        if self.accounts_json.exists():
            with contextlib.suppress(OSError, json.JSONDecodeError, KeyError):
                data = json.loads(self.accounts_json.read_text(encoding="utf-8"))
                active_id = data.get("current_account_id")

        # 2. Try ~/.gemini/oauth_creds.json for active email
        if self.oauth_creds_json.exists():
            with contextlib.suppress(OSError, json.JSONDecodeError, KeyError):
                creds = json.loads(self.oauth_creds_json.read_text(encoding="utf-8"))
                active_email = creds.get("email")

        return {"current_account_id": active_id, "current_email": active_email}

    def read_account_file(self, account_file: Path) -> dict[str, Any] | None:
        """Parse a single account json file and extract structured quotas."""
        if not account_file.exists():
            return None

        try:
            raw = json.loads(account_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
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
        claude_sonnet = models_dict.get("claude-sonnet-4-6", {})

        gemini_pro_pct = (
            gemini_3_1_pro_high.get("percentage")
            if gemini_3_1_pro_high.get("percentage") is not None
            else gemini_3_1_pro_low.get("percentage")
        )
        gemini_pro_reset = gemini_3_1_pro_high.get("reset_time") or gemini_3_1_pro_low.get("reset_time")

        claude_pct = claude_sonnet.get("percentage")
        claude_reset = claude_sonnet.get("reset_time")

        # 2. Extract underlying Quota Groups (Weekly Limit vs 5h Limit)
        quota_groups = quota_data.get("quota_groups", [])
        gemini_weekly_frac: float | None = None
        gemini_weekly_reset: str | None = None
        gemini_5h_frac: float | None = None
        gemini_5h_reset: str | None = None

        claude_weekly_frac: float | None = None
        claude_5h_frac: float | None = None

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

        # Effective Gemini 3.1 Pro 5h remaining fraction synthesis
        # Merges models percentage (0..100) and quota_groups remaining_fraction (0.0..1.0)
        pro_model_frac = (gemini_pro_pct / 100.0) if gemini_pro_pct is not None else None
        effective_gemini_5h_frac: float | None = None
        if pro_model_frac is not None and gemini_5h_frac is not None:
            effective_gemini_5h_frac = min(pro_model_frac, gemini_5h_frac)
        elif pro_model_frac is not None:
            effective_gemini_5h_frac = pro_model_frac
        elif gemini_5h_frac is not None:
            effective_gemini_5h_frac = gemini_5h_frac

        # Risk assessment synthesis
        risk_warnings = []
        is_exhausted = False
        is_unknown = (gemini_weekly_frac is None and effective_gemini_5h_frac is None)

        if is_unknown:
            health_status = "UNKNOWN"
            recommendation = "未获取到该账号的配额信息或数据字段缺失，无法评估健康度，建议谨慎调度。"
            risk_warnings.append("【额度数据未知】未获取到该账号的真实配额信息，切换至此账号可能产生意外限流")
        else:
            # 1. Short-term quota (5h / Model percentage) assessment
            if effective_gemini_5h_frac is not None:
                if effective_gemini_5h_frac <= 0.0:
                    risk_warnings.append(
                        "【Gemini 3.1 Pro 额度已耗尽】当前短期额度为 0%，无法执行任何请求，切勿分配任务"
                    )
                    is_exhausted = True
                elif effective_gemini_5h_frac < 0.15:
                    risk_warnings.append(
                        f"【Gemini 3.1 Pro 额度见底】当前短期额度仅剩 {effective_gemini_5h_frac * 100:.1f}%，极度危险！切勿分配任务"
                    )
                    is_exhausted = True
                elif effective_gemini_5h_frac < 0.35:
                    risk_warnings.append(
                        f"【Gemini 3.1 Pro 额度偏低】当前短期额度剩余 {effective_gemini_5h_frac * 100:.1f}%，建议优先分配短期或轻量任务"
                    )

            # 2. Weekly global limit assessment
            if gemini_weekly_frac is not None:
                if gemini_weekly_frac <= 0.0:
                    risk_warnings.append(
                        "【严重警告】Gemini 周全局硬顶已耗尽（0.0%），极度危险！切勿分配任务"
                    )
                    is_exhausted = True
                elif gemini_weekly_frac < 0.15:
                    risk_warnings.append(
                        f"【严重警告】Gemini 周全局硬顶仅剩 {gemini_weekly_frac * 100:.1f}%，极度危险！切勿分配大任务"
                    )
                    is_exhausted = True
                elif gemini_weekly_frac < 0.35:
                    risk_warnings.append(
                        f"【周额度吃紧】Gemini 周额度剩余 {gemini_weekly_frac * 100:.1f}%，建议优先分配短期或轻量任务"
                    )

            if is_exhausted:
                health_status = "CRITICAL_LOW"
                recommendation = "当前账号额度已耗尽或见底，切勿分配任务，建议立即切换至其他健康账号。"
            elif risk_warnings:
                health_status = "CAUTION"
                recommendation = "额度偏低或正在消耗中，建议审慎分配重型任务。"
            else:
                health_status = "HEALTHY"
                recommendation = "额度充沛，适宜执行各类复杂或长期编码任务。"

        return {
            "id": account_id,
            "email": email,
            "name": name,
            "subscription_tier": quota_data.get("subscription_tier", "PRO"),
            "health_status": health_status,
            "recommendation": recommendation,
            "quotas": {
                "gemini_3_1_pro": {
                    "remaining_5h": (
                        f"{gemini_pro_pct}%"
                        if gemini_pro_pct is not None
                        else (f"{gemini_5h_frac * 100:.1f}%" if gemini_5h_frac is not None else "unknown")
                    ),
                    "remaining_fraction_5h": effective_gemini_5h_frac,
                    "reset_time_5h": gemini_pro_reset or gemini_5h_reset,
                },
                "gemini_weekly_limit": {
                    "remaining": f"{gemini_weekly_frac * 100:.1f}%" if gemini_weekly_frac is not None else "unknown",
                    "remaining_fraction": gemini_weekly_frac,
                    "reset_time": gemini_weekly_reset,
                },
                "claude_sonnet_4_6": {
                    "remaining_5h": (
                        f"{claude_pct}%"
                        if claude_pct is not None
                        else (f"{claude_5h_frac * 100:.1f}%" if claude_5h_frac is not None else "unknown")
                    ),
                    "remaining_weekly": (
                        f"{claude_weekly_frac * 100:.1f}%" if claude_weekly_frac is not None else "unknown"
                    ),
                    "reset_time": claude_reset,
                },
            },
            "risk_warnings": risk_warnings,
        }

    def list_all_accounts(self) -> list[dict[str, Any]]:
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

        # Sort accounts:
        # 1. Current account first (0 vs 1)
        # 2. Critical exhausted accounts last (0 for non-exhausted vs 1 for CRITICAL_LOW)
        # 3. Known quota first (0) vs unknown quota (1)
        # 4. Highest remaining fraction descending (-score)
        def sort_key(acc: dict[str, Any]) -> tuple[int, int, int, float]:
            is_curr = 0 if acc.get("is_current") else 1
            is_crit = 1 if acc.get("health_status") == "CRITICAL_LOW" else 0

            weekly_frac = acc.get("quotas", {}).get("gemini_weekly_limit", {}).get("remaining_fraction")
            short_frac = acc.get("quotas", {}).get("gemini_3_1_pro", {}).get("remaining_fraction_5h")

            if weekly_frac is not None and short_frac is not None:
                score = min(float(weekly_frac), float(short_frac))
                has_known = 0
            elif weekly_frac is not None:
                score = float(weekly_frac)
                has_known = 0
            elif short_frac is not None:
                score = float(short_frac)
                has_known = 0
            else:
                score = 0.0
                has_known = 1

            return (is_curr, is_crit, has_known, -score)

        results.sort(key=sort_key)
        return results
