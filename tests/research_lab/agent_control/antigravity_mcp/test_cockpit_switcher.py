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

        sent_payloads = []
        mock_ws = AsyncMock()

        async def _mock_send(data):
            sent_payloads.append(json.loads(data))

        async def _mock_recv():
            if not mock_ws._recv_step:
                mock_ws._recv_step = 1
                return json.dumps({"type": "event.ready", "data": {}})
            req_id = sent_payloads[0]["id"]
            return json.dumps({
                "type": "response.switch_account",
                "id": req_id,
                "data": {"success": True},
            })

        mock_ws._recv_step = 0
        mock_ws.send.side_effect = _mock_send
        mock_ws.recv.side_effect = _mock_recv

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


def test_cockpit_switcher_skips_mismatched_frames(tmp_path: Path):
    """Ensure mismatched req_id or account_id frames are ignored, and matches succeed."""
    async def _run():
        cockpit_acc = tmp_path / "cockpit_accounts.json"
        cockpit_acc.write_text(json.dumps({
            "accounts": [{"id": "uuid-target", "email": "target@example.com"}]
        }), encoding="utf-8")

        server_json = tmp_path / "server.json"
        server_json.write_text(json.dumps({"ws_port": 8888}), encoding="utf-8")

        switcher = CockpitSwitcher(server_json=server_json, cockpit_accounts_json=cockpit_acc)

        mock_ws = AsyncMock()
        mock_ws.recv.side_effect = [
            # 1. Ready event
            json.dumps({"type": "event.ready", "data": {}}),
            # 2. Mismatched req_id response from concurrent request
            json.dumps({
                "type": "response.switch_account",
                "id": "switch-other-req-id",
                "data": {"success": True},
            }),
            # 3. Mismatched account event from someone else
            json.dumps({
                "type": "event.account_switched",
                "data": {"account_id": "uuid-other"},
            }),
            # 4. Correct account switched event
            json.dumps({
                "type": "event.account_switched",
                "data": {"account_id": "uuid-target"},
            }),
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
            assert "成功通过 Cockpit-Tools 事件确认切换至目标账号" in msg
            assert details["account_id"] == "uuid-target"

    asyncio.run(_run())
