"""End-to-end integration test for Antigravity MCP over Unix Domain Socket."""
# ruff: noqa: ASYNC220
import asyncio
import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parents[3]
SERVER_SCRIPT = REPO_ROOT / "research_lab" / "agent_control" / "antigravity_mcp" / "server.py"

logger = logging.getLogger("test_uds_e2e")


def test_antigravity_mcp_uds_e2e():
    """Start MCP server in socket mode and perform full JSON-RPC handshake over UDS."""
    asyncio.run(_run_test_uds_e2e())


async def _run_test_uds_e2e():
    tmp_dir = REPO_ROOT / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    sock_path = tmp_dir / "test_antigravity.sock"
    if sock_path.exists():
        sock_path.unlink()

    # Start server subprocess on temporary socket
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    # Ensure no token auth for local socket test
    env.pop("AGY_MCP_API_KEY", None)
    env["AGY_MCP_SOCKET_AUTH"] = "false"

    proc = subprocess.Popen(
        [
            sys.executable,
            str(SERVER_SCRIPT),
            "--transport",
            "socket",
            "--socket",
            str(sock_path),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # Wait up to 5 seconds for socket file to appear
        start_wait = time.time()
        while not sock_path.exists() and time.time() - start_wait < 5.0:
            await asyncio.sleep(0.1)

        if not sock_path.exists():
            out, err = proc.communicate(timeout=1.0)
            raise AssertionError(f"Socket was not created. stdout:\n{out}\nstderr:\n{err}")

        transport = httpx.AsyncHTTPTransport(uds=str(sock_path))
        async with (
            httpx.AsyncClient(transport=transport, timeout=10.0) as client,
            client.stream("GET", "http://localhost/sse") as response,
        ):
            assert response.status_code == 200

            endpoint_queue: asyncio.Queue[str] = asyncio.Queue()
            messages_queue: asyncio.Queue[dict] = asyncio.Queue()

            async def read_sse():
                try:
                    async for line in response.aiter_lines():
                        if line.startswith("data: /messages/"):
                            await endpoint_queue.put(line.split("data: ")[1].strip())
                        elif line.startswith("data: "):
                            data_str = line[6:].strip()
                            with contextlib.suppress(json.JSONDecodeError):
                                await messages_queue.put(json.loads(data_str))
                except (httpx.HTTPError, asyncio.CancelledError):
                    logger.debug("SSE read stream stopped")

            reader_task = asyncio.create_task(read_sse())
            endpoint_url = await asyncio.wait_for(endpoint_queue.get(), timeout=5.0)
            full_endpoint = f"http://localhost{endpoint_url}"

            # 2. Perform MCP Initialize handshake
            init_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-uds-agent", "version": "1.0"},
                },
            }
            init_resp = await client.post(full_endpoint, json=init_payload)
            assert init_resp.status_code == 202

            # Send initialized notification
            notif_payload = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
            await client.post(full_endpoint, json=notif_payload)

            # 3. Call tool: list_accounts
            call_payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "list_accounts",
                    "arguments": {},
                },
            }
            tool_resp = await client.post(full_endpoint, json=call_payload)
            assert tool_resp.status_code == 202

            # 4. Wait for response with id == 2
            while True:
                msg = await asyncio.wait_for(messages_queue.get(), timeout=10.0)
                if msg.get("id") == 2:
                    assert "result" in msg
                    content = msg["result"].get("content", [])
                    assert len(content) > 0
                    result_text = content[0].get("text", "")
                    parsed_data = json.loads(result_text)
                    assert "accounts" in parsed_data
                    assert parsed_data["total_accounts"] >= 1
                    assert "capabilities" in parsed_data
                    break

            # 5. Call tool: account_usage over UDS
            usage_payload = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "account_usage",
                    "arguments": {},
                },
            }
            usage_resp = await client.post(full_endpoint, json=usage_payload)
            assert usage_resp.status_code == 202

            while True:
                msg = await asyncio.wait_for(messages_queue.get(), timeout=10.0)
                if msg.get("id") == 3:
                    assert "result" in msg
                    content = msg["result"].get("content", [])
                    assert len(content) > 0
                    result_text = content[0].get("text", "")
                    parsed_usage = json.loads(result_text)
                    assert "active_email" in parsed_usage
                    assert "account_id" in parsed_usage
                    assert "capabilities_report" in parsed_usage
                    break

            reader_task.cancel()

    finally:
        # Gracefully terminate server
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1.0)

        # Verify socket was cleanly unlinked upon exit
        assert not sock_path.exists(), "Socket file was not cleaned up on server exit"
        try:
            tmp_dir.rmdir()
        except OSError:
            pass
