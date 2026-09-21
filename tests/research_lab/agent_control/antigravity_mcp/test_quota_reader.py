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


def test_quota_reader_missing_quota_is_unknown_and_sorted_last(tmp_path: Path):
    """Ensure accounts with missing/null quotas are marked UNKNOWN and sorted last (no fail-open)."""
    accounts_dir = tmp_path / "accounts"
    accounts_dir.mkdir()

    # 1. Normal known account
    known_file = accounts_dir / "acc-known.json"
    known_file.write_text(json.dumps({
        "id": "acc-known",
        "email": "known@example.com",
        "quota": {
            "models": [{"name": "gemini-3.1-pro-high", "percentage": 80}],
            "quota_groups": [{"display_name": "Gemini Models", "buckets": [{"window": "weekly", "remaining_fraction": 0.8}]}]
        }
    }), encoding="utf-8")

    # 2. Account with missing/empty quota dict
    empty_file = accounts_dir / "acc-empty.json"
    empty_file.write_text(json.dumps({
        "id": "acc-empty",
        "email": "empty@example.com",
        "quota": None
    }), encoding="utf-8")

    # 3. Account with empty models and quota_groups
    unknown_file = accounts_dir / "acc-unknown.json"
    unknown_file.write_text(json.dumps({
        "id": "acc-unknown",
        "email": "unknown@example.com",
        "quota": {"models": [], "quota_groups": []}
    }), encoding="utf-8")

    accounts_json = tmp_path / "accounts.json"
    accounts_json.write_text(json.dumps({
        "current_account_id": "acc-empty",
        "accounts": [{"id": "acc-known"}, {"id": "acc-empty"}, {"id": "acc-unknown"}]
    }), encoding="utf-8")

    reader = QuotaReader(
        accounts_json=accounts_json,
        accounts_dir=accounts_dir,
    )

    all_accounts = reader.list_all_accounts()
    assert len(all_accounts) == 3

    empty_acc = next(a for a in all_accounts if a["id"] == "acc-empty")
    assert empty_acc["health_status"] == "UNKNOWN"
    assert empty_acc["quotas"]["gemini_3_1_pro"]["remaining_5h"] == "unknown"
    assert empty_acc["quotas"]["gemini_weekly_limit"]["remaining"] == "unknown"
    assert "【额度数据未知】" in empty_acc["risk_warnings"][0]

    unknown_acc = next(a for a in all_accounts if a["id"] == "acc-unknown")
    assert unknown_acc["health_status"] == "UNKNOWN"

    known_acc = next(a for a in all_accounts if a["id"] == "acc-known")
    assert known_acc["health_status"] == "HEALTHY"

    # Verify smart sorting:
    # 1. Current active account is always kept at index 0 for immediate visibility
    assert all_accounts[0]["id"] == "acc-empty"
    assert all_accounts[0]["is_current"] is True

    # 2. Among candidate switch targets (non-current), known quotas MUST be prioritized over UNKNOWN quotas
    candidates = [a for a in all_accounts if not a["is_current"]]
    assert len(candidates) == 2
    assert candidates[0]["id"] == "acc-known"
    assert candidates[1]["id"] == "acc-unknown"


def test_quota_reader_zero_model_quota_without_quota_groups_is_critical_low(tmp_path: Path):
    """Ensure account with 0% model quota and missing quota_groups is CRITICAL_LOW, not HEALTHY."""
    accounts_dir = tmp_path / "accounts"
    accounts_dir.mkdir()

    # 1. Exhausted account: models has gemini-3.1-pro-high: 0%, but quota_groups is omitted
    zero_file = accounts_dir / "acc-zero.json"
    zero_file.write_text(json.dumps({
        "id": "acc-zero",
        "email": "zero@example.com",
        "name": "Zero Quota User",
        "quota": {
            "subscription_tier": "PRO",
            "models": [
                {"name": "gemini-3.1-pro-high", "percentage": 0, "reset_time": "2026-09-21T12:00:00Z"}
            ]
            # Notice: quota_groups is completely missing
        }
    }), encoding="utf-8")

    # 2. Healthy account
    healthy_file = accounts_dir / "acc-healthy.json"
    healthy_file.write_text(json.dumps({
        "id": "acc-healthy",
        "email": "healthy@example.com",
        "quota": {
            "models": [{"name": "gemini-3.1-pro-high", "percentage": 100}],
            "quota_groups": [{"display_name": "Gemini Models", "buckets": [{"window": "weekly", "remaining_fraction": 0.9}]}]
        }
    }), encoding="utf-8")

    # 3. Unknown quota account
    unknown_file = accounts_dir / "acc-unknown.json"
    unknown_file.write_text(json.dumps({
        "id": "acc-unknown",
        "email": "unknown@example.com",
        "quota": {"models": [], "quota_groups": []}
    }), encoding="utf-8")

    accounts_json = tmp_path / "accounts.json"
    accounts_json.write_text(json.dumps({
        "current_account_id": "acc-healthy",
        "accounts": [{"id": "acc-healthy"}, {"id": "acc-zero"}, {"id": "acc-unknown"}]
    }), encoding="utf-8")

    reader = QuotaReader(
        accounts_json=accounts_json,
        accounts_dir=accounts_dir,
    )

    all_accounts = reader.list_all_accounts()
    assert len(all_accounts) == 3

    zero_acc = next(a for a in all_accounts if a["id"] == "acc-zero")
    # P1 Critical assertion: MUST NOT be HEALTHY!
    assert zero_acc["health_status"] == "CRITICAL_LOW"
    assert zero_acc["quotas"]["gemini_3_1_pro"]["remaining_5h"] == "0%"
    assert zero_acc["quotas"]["gemini_3_1_pro"]["remaining_fraction_5h"] == 0.0
    assert any("额度已耗尽" in w for w in zero_acc["risk_warnings"])

    # Sorting assertion: Among candidates (non-current),
    # healthy comes first, UNKNOWN comes next, and CRITICAL_LOW exhausted comes LAST
    candidates = [a for a in all_accounts if not a["is_current"]]
    assert len(candidates) == 2
    assert candidates[0]["id"] == "acc-unknown"
    assert candidates[1]["id"] == "acc-zero"
