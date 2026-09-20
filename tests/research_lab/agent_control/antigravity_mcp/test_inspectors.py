"""Tests for ToolInspector discovery and fallback diagnostics."""
import json
from pathlib import Path
from research_lab.agent_control.antigravity_mcp.inspectors import ToolInspector


def test_inspector_full_hybrid_mode(tmp_path: Path):
    """Test full mode when both tools are present."""
    mgr_json = tmp_path / "mgr_accounts.json"
    mgr_json.write_text(json.dumps({"accounts": [{"id": "acc-1"}]}), encoding="utf-8")

    mgr_dir = tmp_path / "accounts"
    mgr_dir.mkdir()

    cockpit_json = tmp_path / "server.json"
    cockpit_json.write_text(json.dumps({"ws_port": 62395}), encoding="utf-8")

    inspector = ToolInspector(
        antigravity_tools_json=mgr_json,
        antigravity_tools_dir=mgr_dir,
        cockpit_server_json=cockpit_json,
    )
    report = inspector.get_capabilities_report()

    assert report["mode"] == "FULL_HYBRID_MODE"
    assert report["features"]["multi_account_quota_pool"] is True
    assert report["features"]["seamless_account_switching"] is True
    assert "完全体模式" in report["summary_message"]


def test_inspector_fallback_when_both_missing(tmp_path: Path):
    """Test graceful fallback when neither external tool is installed."""
    non_existent_mgr = tmp_path / "non_existent_mgr.json"
    non_existent_dir = tmp_path / "non_existent_dir"
    non_existent_cockpit = tmp_path / "non_existent_cockpit.json"

    inspector = ToolInspector(
        antigravity_tools_json=non_existent_mgr,
        antigravity_tools_dir=non_existent_dir,
        cockpit_server_json=non_existent_cockpit,
    )
    report = inspector.get_capabilities_report()

    assert report["mode"] == "SINGLE_ACCOUNT_FALLBACK"
    assert report["features"]["multi_account_quota_pool"] is False
    assert report["features"]["seamless_account_switching"] is False
    assert "单账号原生模式" in report["summary_message"]
    assert len(report["status_notes"]) > 0


def test_inspector_quota_monitor_only(tmp_path: Path):
    """Test mode when only Antigravity-Manager is present but Cockpit is absent."""
    mgr_json = tmp_path / "mgr_accounts.json"
    mgr_json.write_text(json.dumps({"accounts": [{"id": "acc-1"}]}), encoding="utf-8")

    mgr_dir = tmp_path / "accounts"
    mgr_dir.mkdir()

    non_existent_cockpit = tmp_path / "non_existent_cockpit.json"

    inspector = ToolInspector(
        antigravity_tools_json=mgr_json,
        antigravity_tools_dir=mgr_dir,
        cockpit_server_json=non_existent_cockpit,
    )
    report = inspector.get_capabilities_report()

    assert report["mode"] == "QUOTA_MONITOR_ONLY"
    assert report["features"]["multi_account_quota_pool"] is True
    assert report["features"]["seamless_account_switching"] is False
    assert "配额监控模式" in report["summary_message"]
