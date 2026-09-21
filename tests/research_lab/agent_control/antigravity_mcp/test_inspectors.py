"""Tests for ToolInspector discovery and fallback diagnostics."""
import json
from pathlib import Path

from research_lab.agent_control.antigravity_mcp.inspectors import ToolInspector


def test_inspector_manager_full_mode(tmp_path: Path):
    """Test full mode when Antigravity-Manager accounts.json is present."""
    mgr_json = tmp_path / "accounts.json"
    mgr_json.write_text(json.dumps({"accounts": [{"id": "acc-1"}]}), encoding="utf-8")

    mgr_dir = tmp_path / "accounts"
    mgr_dir.mkdir()

    gui_cfg = tmp_path / "gui_config.json"
    gui_cfg.write_text(json.dumps({"proxy": {"port": 8045}}), encoding="utf-8")

    inspector = ToolInspector(
        antigravity_tools_json=mgr_json,
        antigravity_tools_dir=mgr_dir,
        antigravity_gui_config=gui_cfg,
    )
    report = inspector.get_capabilities_report()

    assert report["mode"] == "MANAGER_FULL_MODE"
    assert report["features"]["multi_account_quota_pool"] is True
    assert report["features"]["safe_account_switching"] is True
    assert "完整模式" in report["summary_message"]


def test_inspector_fallback_when_manager_missing(tmp_path: Path):
    """Test graceful fallback when Antigravity-Manager is missing."""
    non_existent_mgr = tmp_path / "non_existent_mgr.json"
    non_existent_dir = tmp_path / "non_existent_dir"
    non_existent_cfg = tmp_path / "non_existent_cfg.json"

    inspector = ToolInspector(
        antigravity_tools_json=non_existent_mgr,
        antigravity_tools_dir=non_existent_dir,
        antigravity_gui_config=non_existent_cfg,
    )
    report = inspector.get_capabilities_report()

    assert report["mode"] == "SINGLE_ACCOUNT_FALLBACK"
    assert report["features"]["multi_account_quota_pool"] is False
    assert report["features"]["safe_account_switching"] is False
    assert "单账号原生模式" in report["summary_message"]
    assert len(report["status_notes"]) > 0
