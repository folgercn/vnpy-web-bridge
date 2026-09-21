"""Codex Antigravity Network MCP Server.

Provides a network-accessible FastMCP bridge with multi-account inspection
(Gemini 3.1 Pro & Weekly limit breakdowns) and Antigravity-Manager safe switching.
Designed for autonomous LLM agents (Codex) to inspect quotas and select accounts.
"""
import argparse
import asyncio
import atexit
import contextlib
import json
import logging
import os
import signal
import socket
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import uvicorn

from research_lab.agent_control.antigravity_mcp.config import (
    AGY_MCP_API_KEY,
    AGY_MCP_SOCKET_AUTH,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_SOCKET_PATH,
    DEFAULT_TRANSPORT,
)
from research_lab.agent_control.antigravity_mcp.inspectors import (
    ToolInspector,
)
from research_lab.agent_control.antigravity_mcp.manager_client import (
    ManagerClient,
)
from research_lab.agent_control.antigravity_mcp.quota_reader import (
    QuotaReader,
)
from research_lab.agent_control.antigravity_mcp.usage_tracker import (
    UsageTracker,
)

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parents[2]
for path_dir in (CURRENT_DIR, REPO_ROOT):
    if str(path_dir) not in sys.path:
        sys.path.insert(0, str(path_dir))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("antigravity_mcp.server")

SERVICE = CURRENT_DIR / "core" / "agy_service.py"

inspector = ToolInspector()
quota_reader = QuotaReader()
manager_client = ManagerClient()
usage_tracker = UsageTracker()


class ApiKeyAuthMiddleware:
    """ASGI middleware to validate API key via Bearer token or ?api_key= query parameter."""

    def __init__(self, app, api_key: str):
        self.app = app
        self.api_key = api_key.strip()
        self._authenticated_sessions: dict[str, float] = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.api_key:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="ignore").strip()

        token = ""
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

        query_string = scope.get("query_string", b"").decode("utf-8", errors="ignore")
        query_params = parse_qs(query_string)

        if not token:
            token = query_params.get("api_key", [""])[0].strip()

        session_id = query_params.get("session_id", [""])[0].strip()
        now = time.time()

        is_authenticated = (token == self.api_key)
        if not is_authenticated and session_id:
            exp = self._authenticated_sessions.get(session_id, 0)
            if exp > now:
                is_authenticated = True

        if not is_authenticated:
            response_body = b'{"error": "Unauthorized", "message": "Invalid or missing API key"}\n'
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(response_body)).encode("utf-8")),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": response_body,
            })
            return

        if session_id:
            self._authenticated_sessions[session_id] = now + 1800
            if len(self._authenticated_sessions) > 50:
                self._authenticated_sessions = {
                    sid: exp for sid, exp in self._authenticated_sessions.items() if exp > now
                }

        await self.app(scope, receive, send)


async def invoke(operation: str, arguments: dict[str, Any], on_events=None, on_status=None):
    """Invoke the agy_service business backend via disposable sub-process."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(SERVICE),
        "_call",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        limit=1024 * 1024,
        env=dict(
            os.environ,
            PYTHONPATH=str(CURRENT_DIR / "core") + ":" + os.environ.get("PYTHONPATH", ""),
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONPYCACHEPREFIX=str(Path(tempfile.gettempdir()) / ("agy-call-" + uuid.uuid4().hex)),
        ),
    )
    try:
        proc.stdin.write((json.dumps({"version": 1, "operation": operation, "arguments": arguments}) + "\n").encode())
        await proc.stdin.drain()
        fragments = []
        position = 0
        while True:
            line = await proc.stdout.readline()
            if not line:
                raise RuntimeError(
                    "Business helper exited without a result; inspect the same job/request_id before retrying."
                )
            part = json.loads(line)
            if part["offset"] != position:
                raise RuntimeError("Invalid business frame offset")
            fragments.append(part["chunk"])
            position += len(part["chunk"])
            if not part["final"]:
                continue
            frame = json.loads("".join(fragments))
            fragments = []
            position = 0
            kind = frame["kind"]
            data = frame["data"]
            if kind == "result":
                await proc.wait()
                if proc.returncode:
                    raise RuntimeError("Business helper failed after result")
                return data
            if kind == "error":
                raise RuntimeError(data["type"] + ": " + data["message"])
            if kind == "status":
                if on_status:
                    await on_status(data)
            elif kind == "events":
                delivered = on_events is not None and await on_events(data) is not False
                proc.stdin.write((json.dumps({"delivered": delivered}) + "\n").encode())
                await proc.stdin.drain()
            else:
                raise RuntimeError("Unknown business protocol frame")
    finally:
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 3)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
        if proc.stdin:
            proc.stdin.close()


def create_mcp_server():
    """Create and configure the FastMCP instance."""
    from mcp.server.fastmcp import Context, FastMCP

    mcp = FastMCP(
        "antigravity",
        instructions=(
            "Delegate one work block per task_id. submit returns job_id; call watch to hold the connection, "
            "which streams upstream events via logging notifications and returns progress_update with activity "
            "snapshots every 60s. On progress_update, read activity and immediately resume watch with the SAME "
            "job_id and resume.cursor; do not resubmit or message. Raw events remain available through events. "
            "If watch is unavailable, check status at most once every 180-300s. A disconnected watch never cancels/replays work; "
            "reconnect to the SAME job. New continuations use message with a new request_id. Desktop must remain running. "
            "Multi-account quota inspection and safe official switching are powered by Antigravity-Manager."
        ),
        host=DEFAULT_HOST,
        port=DEFAULT_PORT,
    )

    @mcp._mcp_server.set_logging_level()
    async def set_logging_level(level):
        mcp.get_context().session._agy_log_level = level

    @mcp.tool(name="list_accounts")
    async def list_accounts_tool() -> dict:
        """
        List all registered accounts with rich quota breakdown and weekly limits.
        Allows Codex to view remaining quotas (Gemini 3.1 Pro 5h, Weekly global ceiling,
        Claude Sonnet) across accounts and pick the most suitable account to switch to.
        """
        cap_report = inspector.get_capabilities_report()
        has_manager = cap_report["features"]["multi_account_quota_pool"]

        if not has_manager:
            return {
                "supported": False,
                "message": "未检测到 Antigravity-Manager (~/.antigravity_tools/)，不提供多账号聚合额度池功能。当前以单账号本地模式运行。",
                "capabilities": cap_report,
                "accounts": [],
            }

        # Query manager client first; fallback to local quota_reader if manager API is unavailable
        accounts = await manager_client.list_accounts()
        if not accounts:
            accounts = quota_reader.list_all_accounts()

        usage_summary = usage_tracker.get_summary()

        # Inject task count to each account
        for acc in accounts:
            email = acc.get("email", "")
            stats = usage_tracker.get_account_stats(email) or {}
            acc["task_dispatch_count"] = stats.get("task_count", 0)
            acc["switch_in_count"] = stats.get("switch_in_count", 0)

        return {
            "supported": True,
            "capabilities": cap_report,
            "total_accounts": len(accounts),
            "accounts": accounts,
            "usage_leaderboard": usage_summary.get("leaderboard", []),
        }

    @mcp.tool(name="switch_account")
    async def switch_account_tool(account_or_email: str) -> dict:
        """
        Safely switch active Antigravity account using Antigravity-Manager.
        Passes an account email (e.g. 'quickcoin2016@gmail.com') or account_id.
        Performs safe credential rotation with official app restart (/Applications/Antigravity.app).
        """
        # 1. Capture current active email BEFORE switching
        before_active = await manager_client.get_current_account()
        before_email = before_active.get("email") if before_active else None
        if not before_email:
            before_local = quota_reader.get_current_active_identity()
            before_email = before_local.get("current_email")

        success, msg, details = await manager_client.switch_account(account_or_email)
        if success:
            target_email = details.get("email") or account_or_email
            target_id = details.get("account_id")

            if target_email:
                await usage_tracker.record_switch(
                    from_email=before_email,
                    to_email=target_email,
                    account_id=target_id,
                    reason="codex_instructed_switch",
                )
        return {
            "success": success,
            "message": msg,
            "details": details,
        }

    @mcp.tool(name="account_usage")
    async def account_usage_tool() -> dict:
        """
        Read the active signed-in account's identity, subscription plan, and every quota bucket
        from Antigravity-Manager, enriched with multi-account inspection report.
        """
        current = await manager_client.get_current_account()
        if current:
            usage = {
                "active_email": current.get("email"),
                "account_id": current.get("account_id"),
                "name": current.get("name"),
                "subscription_tier": current.get("quota", {}).get("subscription_tier"),
                "quota": current.get("quota"),
                "raw_quota": current.get("raw_quota"),
            }
        else:
            try:
                usage = await invoke("account_usage", {})
            except Exception as e:  # noqa: BLE001
                usage = {"error": str(e), "message": "Failed to read usage from both Manager and desktop RPC"}

        cap_report = inspector.get_capabilities_report()
        usage["capabilities_report"] = cap_report
        usage["usage_summary"] = usage_tracker.get_summary()
        return usage

    @mcp.tool(name="account_leaderboard")
    async def account_leaderboard_tool() -> dict:
        """
        Get comprehensive usage statistics, rankings, and distribution across all accounts.
        Shows who is used most/least, total task distribution, and switch counts.
        """
        return usage_tracker.get_summary()

    @mcp.tool(name="tool_status")
    async def tool_status_tool() -> dict:
        """
        Check health and runtime availability of Antigravity-Manager.
        Informs whether multi-account quota reading and safe switching are currently active.
        """
        is_avail, avail_msg = await manager_client.is_available()
        report = inspector.get_capabilities_report()
        report["manager_api_status"] = {
            "available": is_avail,
            "message": avail_msg,
            "port": manager_client.get_port(),
        }
        return report

    @mcp.tool(name="projects")
    async def projects_tool(cwd: str = "") -> dict:
        """
        List desktop projects, or resolve one absolute worktree to exactly one project.
        This is read-only. A missing or ambiguous cwd is an error; no default project is selected.
        """
        return await invoke("projects", {"cwd": cwd})

    @mcp.tool(name="submit")
    async def submit_tool(
        task_id: str,
        prompt: str,
        cwd: str,
        request_id: str,
        mode: str = "implement",
        timeout_seconds: float = 600,
        ack_uncertain: bool = False,
    ) -> dict:
        """
        Submit an authorized work block, or continue a finished task's SAME desktop conversation.
        Supply exact scope and acceptance criteria in prompt. Idempotent per task_id/request_id.
        Returns immediately with a job_id; follow with one watch call.
        """
        active_email = ""
        with contextlib.suppress(Exception):
            active_info = quota_reader.get_current_active_identity()
            active_email = active_info.get("current_email") or ""

        if active_email:
            try:
                await usage_tracker.record_task(
                    email=active_email,
                    task_id=task_id,
                    prompt_preview=prompt,
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to record task dispatch: %s", e)

        try:
            return await invoke(
                "submit",
                {
                    "task_id": task_id,
                    "prompt": prompt,
                    "cwd": cwd,
                    "request_id": request_id,
                    "mode": mode,
                    "timeout_seconds": timeout_seconds,
                    "ack_uncertain": ack_uncertain,
                },
            )
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "quota" in err_str or "exhaust" in err_str:
                logger.warning("Task execution hit quota limit / 429: %s", e)
                if active_email:
                    await usage_tracker.record_429(active_email)
            raise

    @mcp.tool(name="message")
    async def message_tool(
        task_id: str,
        prompt: str,
        request_id: str,
        timeout_seconds: float = 600,
        ack_uncertain: bool = False,
    ) -> dict:
        """
        Continue a completed managed task in its existing desktop conversation. Uses saved cwd/mode.
        Active tasks return TASK_BUSY; do not inject an interrupting message. After cancel, inspect
        evidence before ack_uncertain. Follow new job with one watch call.
        """
        return await invoke(
            "message",
            {
                "task_id": task_id,
                "prompt": prompt,
                "request_id": request_id,
                "timeout_seconds": timeout_seconds,
                "ack_uncertain": ack_uncertain,
            },
        )

    @mcp.tool(name="watch")
    async def watch_tool(job_id: str, ctx: Context, cursor: int = 0, timeout_seconds: float = 1800) -> dict:
        """
        Hold this request to monitor work execution. Push full upstream events via MCP logging notifications
        and state changes via progress notifications. Returns within at most 60 seconds with an activity snapshot.
        On progress_update: read activity, then immediately call watch with the SAME job_id and resume.cursor.
        Disconnect does not stop work; resume the same job/cursor. Raw output remains readable with events.
        """
        progress = 0

        async def pushed(page):
            try:
                if getattr(ctx.session, "_agy_log_level", "info") not in ("debug", "info"):
                    return False
                await ctx.session.send_log_message(
                    "info", dict(job_id=job_id, **page), logger="antigravity.upstream", related_request_id=ctx.request_id
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to send log message notification: %s", exc)
                return False
            return True

        async def status_changed(state):
            nonlocal progress
            progress += 1
            try:
                await ctx.report_progress(progress, message=json.dumps(state, ensure_ascii=False))
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to report progress notification: %s", exc)

        return await invoke(
            "watch",
            {"job_id": job_id, "cursor": cursor, "timeout_seconds": timeout_seconds},
            pushed,
            status_changed,
        )

    @mcp.tool(name="events")
    async def events_tool(job_id: str, cursor: int = 0) -> dict:
        """
        Explicit raw event replay/readback. Not a status probe. While executing use watch instead of
        repeatedly reading pages. Resume byte cursor for all preserved upstream fields.
        """
        return await invoke("events", {"job_id": job_id, "cursor": cursor})

    @mcp.tool(name="wait")
    async def wait_tool(job_id: str, cursor: int = 0, timeout_seconds: float = 25) -> dict:
        """
        Legacy explicit event read/wait. Prefer watch for completion; do not loop on this while work runs.
        Maximum wait is 50 seconds.
        """
        return await invoke("wait", {"job_id": job_id, "cursor": cursor, "timeout_seconds": timeout_seconds})

    @mcp.tool(name="status")
    async def status_tool(job_id: str | None = None) -> dict:
        """
        Read a job or shared adapter state without submitting work. Does not launch the desktop.
        - When job_id is provided: inspects that job's conversation readiness (readiness: ready/busy/unknown,
          unfinished_steps count, blocking_job_ids, can_continue boolean).
        - When job_id is omitted: checks local adapter queues, active tasks and concurrency limits.
        """
        res = await invoke("status", {"job_id": job_id})
        if not job_id and isinstance(res, dict):
            with contextlib.suppress(Exception):
                current_acc = await manager_client.get_current_account()
                if current_acc:
                    res["active_account"] = {
                        "email": current_acc.get("email"),
                        "gemini_5h_fraction": current_acc.get("quota", {}).get("gemini_5h_fraction"),
                        "gemini_weekly_fraction": current_acc.get("quota", {}).get("gemini_weekly_fraction"),
                    }
        return res

    @mcp.tool(name="result")
    async def result_tool(job_id: str, offset: int = 0, max_chars: int = 8000) -> dict:
        """
        Read the saved final result of a terminal job; paginate response using next_offset.
        Does not rerun the task. Contains result_status, issues, recovery, and efficiency metrics.
        """
        return await invoke("result", {"job_id": job_id, "offset": offset, "max_chars": max_chars})

    @mcp.tool(name="cancel")
    async def cancel_tool(job_id: str) -> dict:
        """
        Request cancellation only for this bridge-owned job, including queued jobs.
        Confirm via wait/result. Never kills the shared desktop backend.
        """
        return await invoke("cancel", {"job_id": job_id})

    return mcp


def print_startup_banner(
    transport: str = "sse",
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    socket_path: Path | None = None,
    auth_enabled: bool = False,
):
    """Print clean diagnostic banner regarding external tools status and transport."""
    report = inspector.get_capabilities_report()
    mgr_avail = report["features"]["multi_account_quota_pool"]
    mgr_msg = report["antigravity_tools"]["message"]
    print("=" * 70)
    print("    🚀 Antigravity Network MCP Bridge (Powered by Antigravity-Manager)")
    print(f"    Mode: {report['mode']}")
    print("-" * 70)
    if transport == "socket":
        sock_str = str(socket_path or DEFAULT_SOCKET_PATH)
        auth_str = "Token Auth ENABLED" if auth_enabled else "免密开箱即用 (Local UDS Open Access)"
        print(f"  * Transport           : Local Unix Domain Socket (unix:{sock_str})")
        print(f"  * Security Auth       : {auth_str}")
    elif transport == "sse":
        auth_str = "Token Auth ENABLED" if auth_enabled else "Open Access (No Token)"
        print(f"  * Transport           : Network SSE (http://{host}:{port}/sse)")
        print(f"  * Security Auth       : {auth_str}")
    else:
        print("  * Transport           : stdio")
    print(f"  * Antigravity-Manager : {'[ON] ' + mgr_msg if mgr_avail else '[OFF] ' + mgr_msg}")
    print("  * Account Switch Mode : Safe official restart (/Applications/Antigravity.app)")
    print(f"  * Status Summary      : {report['summary_message']}")
    print("=" * 70)


def run_socket_server(
    mcp_server: Any,
    socket_path: Path,
    api_key: str = "",
    require_auth: bool = False,
) -> None:
    """Run FastMCP SSE server listening on a local Unix Domain Socket (UDS)."""
    socket_path = Path(socket_path).resolve()
    # Check AF_UNIX path length limitation (macOS limit is 104 characters, Linux is 108)
    if len(str(socket_path).encode("utf-8")) >= 104:
        raise ValueError(
            f"Unix domain socket path is too long ({len(str(socket_path))} chars, limit 104): '{socket_path}'. "
            "Please specify a shorter path via --socket or AGY_MCP_SOCKET_PATH."
        )

    # Ensure parent directory exists safely:
    # Only apply 0700 permission to directories newly created by this process.
    # Never chmod existing parent directories (such as /tmp, system shared dirs, or existing workspace dirs).
    parent_dir = socket_path.parent
    newly_created_dirs: list[Path] = []
    curr = parent_dir
    while not (curr.exists() or os.path.lexists(curr)):
        newly_created_dirs.append(curr)
        if curr == curr.parent:
            break
        curr = curr.parent

    parent_dir.mkdir(parents=True, exist_ok=True)
    for d in newly_created_dirs:
        with contextlib.suppress(OSError):
            os.chmod(d, 0o700)

    # 1. Probe existing path: refuse non-sockets and refuse active sockets
    if socket_path.exists() or os.path.lexists(socket_path):
        try:
            st = os.lstat(socket_path)
        except OSError as exc:
            raise RuntimeError(f"Cannot inspect existing path '{socket_path}': {exc}") from exc

        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError(
                f"Cannot bind Unix Domain Socket: path '{socket_path}' exists and is not a socket."
            )

        # Path is a socket file; test if another process is actively listening
        probe_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe_sock.connect(str(socket_path))
            # If connect succeeds, an active server is listening; refuse to overwrite!
            raise RuntimeError(
                f"Cannot bind Unix Domain Socket: another process is actively listening on '{socket_path}' (Address in use)."
            )
        except ConnectionRefusedError:
            # No listener is active (stale socket file from previous crash/exit); safe to unlink
            logger.warning("Cleaning up stale socket file from inactive instance: %s", socket_path)
            try:
                socket_path.unlink()
            except OSError as exc:
                raise RuntimeError(f"Failed to remove stale socket '{socket_path}': {exc}") from exc
        except FileNotFoundError:
            pass
        finally:
            with contextlib.suppress(Exception):
                probe_sock.close()

    # 2. Track bound socket inode to prevent TOCTOU deletion race
    bound_inode: list[tuple[int, int] | None] = [None]

    def _cleanup_socket() -> None:
        try:
            if not (socket_path.exists() or os.path.lexists(socket_path)):
                return
            st = os.lstat(socket_path)
            if not stat.S_ISSOCK(st.st_mode):
                logger.warning("Skipping cleanup: path '%s' is no longer a socket", socket_path)
                return
            # Fail closed: Never delete unless this instance successfully bound and recorded inode
            if bound_inode[0] is None:
                logger.warning(
                    "Skipping cleanup: socket '%s' was never verified or bound by this instance", socket_path
                )
                return
            curr_inode = (st.st_dev, st.st_ino)
            if curr_inode != bound_inode[0]:
                logger.warning(
                    "Skipping cleanup: socket '%s' inode changed (expected %s, got %s); owned by another process",
                    socket_path,
                    bound_inode[0],
                    curr_inode,
                )
                return
            socket_path.unlink(missing_ok=True)
            logger.info("Cleaned up Unix Domain Socket: %s", socket_path)
        except OSError as exc:
            logger.debug("Failed to clean up socket %s: %s", socket_path, exc)

    atexit.register(_cleanup_socket)

    # Disable DNS rebinding protection for local socket transport as UDS does not use DNS
    if hasattr(mcp_server.settings, "transport_security") and mcp_server.settings.transport_security:
        mcp_server.settings.transport_security.enable_dns_rebinding_protection = False
        if hasattr(mcp_server.settings, "allowed_hosts"):
            mcp_server.settings.transport_security.allowed_hosts.extend(["localhost", "127.0.0.1", ""])

    app = mcp_server.sse_app()
    if require_auth:
        if not (api_key and api_key.strip()):
            raise ValueError("Cannot start socket server: authentication is required but API Key is missing or empty.")
        logger.info("Security: API Key authentication ENABLED on socket %s", socket_path)
        app = ApiKeyAuthMiddleware(app, api_key)
    else:
        logger.info("Security: Open local access (no token required for local socket)")

    config = uvicorn.Config(
        app,
        uds=str(socket_path),
        log_level=mcp_server.settings.log_level.lower(),
    )
    server = uvicorn.Server(config)

    # Direct lifecycle hook: wrap server.startup to capture bound inode at 0ms and chmod 0600
    orig_startup = server.startup

    async def _wrapped_startup(sockets: list[socket.socket] | None = None) -> None:
        await orig_startup(sockets=sockets)
        if socket_path.exists() or os.path.lexists(socket_path):
            try:
                st = os.lstat(socket_path)
                if stat.S_ISSOCK(st.st_mode):
                    bound_inode[0] = (st.st_dev, st.st_ino)
                    with contextlib.suppress(OSError):
                        os.chmod(socket_path, 0o600)
                    logger.debug("Bound socket %s with inode %s and chmod 0600", socket_path, bound_inode[0])
            except OSError as exc:
                logger.warning("Failed to secure socket %s during startup: %s", socket_path, exc)

    server.startup = _wrapped_startup

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _handle_signal(*args: Any) -> None:
        server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda *_: setattr(server, "should_exit", True))

    try:
        logger.info("Starting Codex Antigravity MCP Server (Local Socket) at unix:%s", socket_path)
        loop.run_until_complete(server.serve())
    finally:
        _cleanup_socket()


def main():
    parser = argparse.ArgumentParser(description="Codex Antigravity Network MCP Server")
    parser.add_argument(
        "--transport",
        choices=["sse", "socket", "stdio"],
        default=DEFAULT_TRANSPORT,
        help=f"Transport protocol: 'sse' (network), 'socket' (local Unix Domain Socket), 'stdio' (default: {DEFAULT_TRANSPORT})",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Host to bind SSE server to (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port for SSE server (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--socket",
        "--socket-path",
        dest="socket_path",
        default=str(DEFAULT_SOCKET_PATH),
        help=f"Path to Unix Domain Socket file for 'socket' transport (default: {DEFAULT_SOCKET_PATH})",
    )
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--require-auth",
        action="store_true",
        default=False,
        help="Explicitly require API Key authentication (fails if key is not configured)",
    )
    auth_group.add_argument(
        "--no-auth",
        action="store_true",
        default=False,
        help="Explicitly disable API Key authentication (open access)",
    )

    args = parser.parse_args()

    # Determine authentication requirement
    if args.no_auth:
        auth_required = False
    elif args.require_auth:
        auth_required = True
    else:
        # Default behavior:
        # - Socket transport: default exempt from token (AGY_MCP_SOCKET_AUTH is False by default)
        # - SSE transport: require token if AGY_MCP_API_KEY is configured
        if args.transport == "socket":
            auth_required = AGY_MCP_SOCKET_AUTH
        else:
            auth_required = bool(AGY_MCP_API_KEY and AGY_MCP_API_KEY.strip())

    # Fail fast: If auth is required but no valid key exists, refuse to start in open mode
    has_valid_key = bool(AGY_MCP_API_KEY and AGY_MCP_API_KEY.strip())
    if auth_required and not has_valid_key:
        logger.error(
            "Authentication required (--require-auth or configuration) but AGY_MCP_API_KEY is not set or empty! "
            "Refusing to start in open mode."
        )
        sys.exit(1)

    socket_path = Path(args.socket_path) if args.transport == "socket" else None
    print_startup_banner(
        transport=args.transport,
        host=args.host,
        port=args.port,
        socket_path=socket_path,
        auth_enabled=auth_required and has_valid_key,
    )
    mcp = create_mcp_server()

    if args.transport == "socket":
        run_socket_server(
            mcp_server=mcp,
            socket_path=Path(args.socket_path),
            api_key=AGY_MCP_API_KEY,
            require_auth=auth_required,
        )
    elif args.transport == "sse":
        logger.info("Starting Codex Antigravity Network MCP Server (SSE) on http://%s:%d/sse", args.host, args.port)
        mcp.settings.host = args.host
        mcp.settings.port = args.port

        if auth_required and has_valid_key:
            logger.info("Security: API Key authentication ENABLED")
            app = mcp.sse_app()
            app = ApiKeyAuthMiddleware(app, AGY_MCP_API_KEY)
            config = uvicorn.Config(
                app,
                host=args.host,
                port=args.port,
                log_level=mcp.settings.log_level.lower(),
            )
            server = uvicorn.Server(config)
            asyncio.run(server.serve())
        else:
            logger.info("Security: Open access mode (no API key configured)")
            mcp.run(transport="sse")
    else:
        logger.info("Starting Codex Antigravity MCP Server (stdio)")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
