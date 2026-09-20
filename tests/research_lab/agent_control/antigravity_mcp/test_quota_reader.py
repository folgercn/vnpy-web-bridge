"""Tests for QuotaReader parsing Gemini 3.1 Pro and Weekly quotas."""
import json
from pathlib import Path
from research_lab.agent_control.antigravity_mcp.quota_reader import QuotaReader


def test_quota_reader_parsing_gemini_3_1_pro_and_weekly(tmp_path: Path):
    accounts_dir = tmp_path / "accounts"
    accounts_dir.mkdir()

    # 1. Healthy account
    healthy_file = accounts_dir / "acc-1.json"
    healthy_file.write_text(json.dumps({
        "id": "acc-1",
        "email": "healthy@example.com",
        "name": "Healthy User",
        "quota": {
            "subscription_tier": "PRO",
            "models": [
                {"name": "gemini-3.1-pro-high", "percentage": 100, "reset_time": "2026-09-20T21:00:00Z"},
                {"name": "claude-sonnet-4-6", "percentage": 100, "reset_time": "2026-09-20T21:00:00Z"}
            ],
            "quota_groups": [
                {
                    "display_name": "Gemini Models",
                    "buckets": [
                        {"window": "weekly", "remaining_fraction": 0.85, "reset_time": "2026-09-27T00:00:00Z"},
                        {"window": "5h", "remaining_fraction": 1.0, "reset_time": "2026-09-20T21:00:00Z"}
                    ]
                }
            ]
        }
    }), encoding="utf-8")

    # 2. Critical weekly limit account
    critical_file = accounts_dir / "acc-2.json"
    critical_file.write_text(json.dumps({
        "id": "acc-2",
        "email": "critical@example.com",
        "name": "Critical User",
        "quota": {
            "subscription_tier": "PRO",
            "models": [
                {"name": "gemini-3.1-pro-high", "percentage": 60, "reset_time": "2026-09-20T21:00:00Z"}
            ],
            "quota_groups": [
                {
                    "display_name": "Gemini Models",
                    "buckets": [
                        {"window": "weekly", "remaining_fraction": 0.12, "reset_time": "2026-09-25T00:00:00Z"},
                        {"window": "5h", "remaining_fraction": 0.60, "reset_time": "2026-09-20T21:00:00Z"}
                    ]
                }
            ]
        }
    }), encoding="utf-8")

    accounts_json = tmp_path / "accounts.json"
    accounts_json.write_text(json.dumps({
        "current_account_id": "acc-1",
        "accounts": [{"id": "acc-1"}, {"id": "acc-2"}]
    }), encoding="utf-8")

    oauth_creds = tmp_path / "oauth_creds.json"
    oauth_creds.write_text(json.dumps({"email": "healthy@example.com"}), encoding="utf-8")

    reader = QuotaReader(
        accounts_json=accounts_json,
        accounts_dir=accounts_dir,
        oauth_creds_json=oauth_creds,
    )

    all_accounts = reader.list_all_accounts()
    assert len(all_accounts) == 2

    acc1 = next(a for a in all_accounts if a["id"] == "acc-1")
    assert acc1["is_current"] is True
    assert acc1["health_status"] == "HEALTHY"
    assert acc1["quotas"]["gemini_3_1_pro"]["remaining_5h"] == "100%"
    assert acc1["quotas"]["gemini_weekly_limit"]["remaining"] == "85.0%"

    acc2 = next(a for a in all_accounts if a["id"] == "acc-2")
    assert acc2["is_current"] is False
    assert acc2["health_status"] == "CRITICAL_LOW"
    assert "严重警告" in acc2["risk_warnings"][0]
    assert acc2["quotas"]["gemini_weekly_limit"]["remaining"] == "12.0%"
