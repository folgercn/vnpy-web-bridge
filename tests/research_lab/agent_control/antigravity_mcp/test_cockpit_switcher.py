"""Tests for CockpitSwitcher adapter."""
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
from research_lab.agent_control.antigravity_mcp.cockpit_switcher import CockpitSwitcher


def test_cockpit_switcher_when_not_running(tmp_path: Path):
    async def _run():
        non_existent = tmp_path / "non_existent_server.json"
        switcher = CockpitSwitcher(server_json=non_existent)

        success, msg, details = await switcher.switch_account("user@example.com")
        assert success is False
        assert "无法执行后台切号" in msg
        assert details.get("reason") == "COCKPIT_NOT_RUNNING"

    asyncio.run(_run())


def test_cockpit_switcher_id_resolution(tmp_path: Path):
    cockpit_acc = tmp_path / "cockpit_accounts.json"
    cockpit_acc.write_text(json.dumps({
        "accounts": [
            {"id": "uuid-12345", "email": "test@example.com"}
        ]
    }), encoding="utf-8")

    server_json = tmp_path / "server.json"
    server_json.write_text(json.dumps({"ws_port": 12345}), encoding="utf-8")

    switcher = CockpitSwitcher(server_json=server_json, cockpit_accounts_json=cockpit_acc)
    resolved_id = switcher._resolve_account_id_from_email("test@example.com")
    assert resolved_id == "uuid-12345"

    # Already a UUID
    uuid_str = "12345678-1234-1234-1234-123456789012"
    assert switcher._resolve_account_id_from_email(uuid_str) == uuid_str


def test_cockpit_switcher_mocked_websocket(tmp_path: Path):
    async def _run():
        cockpit_acc = tmp_path / "cockpit_accounts.json"
        cockpit_acc.write_text(json.dumps({
            "accounts": [{"id": "uuid-99999", "email": "target@example.com"}]
        }), encoding="utf-8")

        server_json = tmp_path / "server.json"
        server_json.write_text(json.dumps({"ws_port": 8888, "auth_token": "secret"}), encoding="utf-8")

        switcher = CockpitSwitcher(server_json=server_json, cockpit_accounts_json=cockpit_acc)

        # Mock websockets: First emits event.ready, then emits switch response
        mock_ws = AsyncMock()
        mock_ws.recv.side_effect = [
            json.dumps({"type": "event.ready", "data": {}}),
            json.dumps({
                "type": "response.switch_account",
                "data": {"success": True}
            })
        ]

        class MockConnectContext:
            async def __aenter__(self):
                return mock_ws
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        with patch("websockets.connect", return_value=MockConnectContext()), \
             patch("asyncio.sleep", return_value=None):
            success, msg, details = await switcher.switch_account("target@example.com")
            assert success is True
            assert "成功通过 Cockpit-Tools 切换" in msg
            assert details["account_id"] == "uuid-99999"

    asyncio.run(_run())
