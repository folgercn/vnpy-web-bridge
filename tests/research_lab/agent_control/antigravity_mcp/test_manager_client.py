"""Unit tests for Antigravity-Manager HTTP API client adapter."""
import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from research_lab.agent_control.antigravity_mcp.manager_client import ManagerClient


@pytest.fixture
def mock_gui_config(tmp_path: Path) -> Path:
    config_file = tmp_path / "gui_config.json"
    data = {
        "proxy": {
            "port": 8045,
            "api_key": "test-secret-key-12345",
        }
    }
    config_file.write_text(json.dumps(data), encoding="utf-8")
    return config_file


def test_manager_client_config_resolution(mock_gui_config: Path):
    """Test resolving port and api_key from gui_config.json and overrides."""
    client = ManagerClient(gui_config_path=mock_gui_config)
    assert client.get_port() == 8045
    assert client.get_api_key() == "test-secret-key-12345"
    assert client.base_url == "http://127.0.0.1:8045/api"

    # Explicit override test
    override_client = ManagerClient(
        port=9999,
        api_key="override-key",
        gui_config_path=mock_gui_config,
    )
    assert override_client.get_port() == 9999
    assert override_client.get_api_key() == "override-key"


def test_manager_client_health(mock_gui_config: Path):
    """Test health check and availability detection."""
    async def _run():
        client = ManagerClient(gui_config_path=mock_gui_config)

        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = (200, {"status": "ok", "version": "4.7.6"})
            is_avail, msg = await client.is_available()
            assert is_avail is True
            assert "4.7.6" in msg
            assert "8045" in msg

        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = (401, {"error": "unauthorized"})
            is_avail, msg = await client.is_available()
            assert is_avail is False
            assert "鉴权失败" in msg

    asyncio.run(_run())


def test_manager_client_list_accounts_and_extract_quota(mock_gui_config: Path):
    """Test accounts listing and rich quota breakdown parsing."""
    async def _run():
        client = ManagerClient(gui_config_path=mock_gui_config)

        sample_response = {
            "accounts": [
                {
                    "id": "acc-1",
                    "email": "user1@gmail.com",
                    "name": "User 1",
                    "is_current": True,
                    "disabled": False,
                    "quota": {
                        "subscription_tier": "PRO",
                        "quota_groups": [
                            {
                                "display_name": "Gemini Models",
                                "buckets": [
                                    {"window": "5h", "remaining_fraction": 0.45},
                                    {"window": "weekly", "remaining_fraction": 0.85},
                                ],
                            },
                            {
                                "display_name": "Claude and GPT models",
                                "buckets": [
                                    {"window": "5h", "remaining_fraction": 1.0},
                                    {"window": "weekly", "remaining_fraction": 0.9},
                                ],
                            },
                        ],
                        "models": [
                            {"name": "gemini-3.1-pro-high", "percentage": 45, "reset_time": "2026-09-21T12:00:00Z"}
                        ],
                    },
                },
                {
                    "id": "acc-2",
                    "email": "user2@gmail.com",
                    "name": "User 2",
                    "is_current": False,
                    "disabled": False,
                    "quota": None,
                },
            ],
            "current_account_id": "acc-1",
        }

        with patch.object(client, "_request") as mock_req:
            mock_req.return_value = (200, sample_response)
            accounts = await client.list_accounts()

            assert len(accounts) == 2
            acc1 = accounts[0]
            assert acc1["account_id"] == "acc-1"
            assert acc1["is_current"] is True
            assert acc1["quota"]["gemini_5h_fraction"] == 0.45
            assert acc1["quota"]["gemini_weekly_fraction"] == 0.85
            assert acc1["quota"]["claude_5h_fraction"] == 1.0
            assert acc1["quota"]["claude_weekly_fraction"] == 0.9
            assert len(acc1["quota"]["models"]) == 1

            acc2 = accounts[1]
            assert acc2["is_current"] is False
            assert acc2["quota"]["has_quota"] is False

    asyncio.run(_run())


def test_manager_client_switch_account_success(mock_gui_config: Path):
    """Test switching account flow with app restart."""
    async def _run():
        client = ManagerClient(gui_config_path=mock_gui_config)

        accounts_list = [
            {"account_id": "acc-1", "email": "user1@gmail.com", "is_current": True, "quota": {}},
            {"account_id": "acc-2", "email": "quickcoin2016@gmail.com", "is_current": False, "quota": {}},
        ]

        with patch.object(client, "list_accounts", return_value=accounts_list), \
             patch.object(client, "_request") as mock_req, \
             patch.object(client, "get_current_account") as mock_curr, \
             patch("asyncio.sleep", return_value=None):

            mock_req.return_value = (200, {"status": "ok"})
            mock_curr.return_value = {
                "account_id": "acc-2",
                "email": "quickcoin2016@gmail.com",
                "is_current": True,
            }

            success, msg, details = await client.switch_account("quickcoin2016@gmail.com")
            assert success is True
            assert "quickcoin2016@gmail.com" in msg
            assert details["account_id"] == "acc-2"

            # Verify switch payload was sent with classic targetIde
            mock_req.assert_called_once_with(
                "POST",
                "/accounts/switch",
                body={"accountId": "acc-2", "targetIde": "classic"},
                timeout=60.0,
            )

    asyncio.run(_run())


def test_manager_client_switch_account_already_current(mock_gui_config: Path):
    """Test switching to an account that is already active."""
    async def _run():
        client = ManagerClient(gui_config_path=mock_gui_config)

        accounts_list = [
            {"account_id": "acc-1", "email": "user1@gmail.com", "is_current": True, "quota": {}},
        ]

        with patch.object(client, "list_accounts", return_value=accounts_list), \
             patch.object(client, "_request") as mock_req:

            success, msg, _details = await client.switch_account("user1@gmail.com")
            assert success is True
            assert "当前已处于激活状态" in msg
            mock_req.assert_not_called()

    asyncio.run(_run())


def test_manager_client_switch_account_not_found(mock_gui_config: Path):
    """Test switching to an unknown account returns helpful error."""
    async def _run():
        client = ManagerClient(gui_config_path=mock_gui_config)

        accounts_list = [
            {"account_id": "acc-1", "email": "user1@gmail.com", "is_current": True, "quota": {}},
        ]

        with patch.object(client, "list_accounts", return_value=accounts_list):
            success, msg, details = await client.switch_account("nonexistent@gmail.com")
            assert success is False
            assert "未在 Antigravity-Manager 中找到账号" in msg
            assert "user1@gmail.com" in details["available_accounts"]

    asyncio.run(_run())
