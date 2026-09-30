"""Actual FastMCP protocol peer. It never starts a model/provider task."""
import asyncio
import os
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("isolated-protocol-regression")

@mcp.tool()
def account_usage() -> dict:
    return {}

@mcp.tool()
def projects(cwd: str = "") -> dict:
    return {"project": {"cwd": cwd}}

@mcp.tool()
def status() -> dict:
    return {}

@mcp.tool()
def result() -> dict:
    return {}

@mcp.tool()
def submit() -> dict:
    raise AssertionError("Provider submissions forbidden in protocol test")

@mcp.tool()
async def watch(job_id: str, ctx: Context, cursor: int = 0, timeout_seconds: float = 60) -> dict:
    next_cursor = max(cursor, 7)
    await ctx.session.send_log_message("info", {"job_id": job_id, "cursor": next_cursor},
                                      logger="antigravity.upstream", related_request_id=ctx.request_id)
    await asyncio.sleep(0.05)
    if job_id == "disconnect":
        os._exit(0)
    if job_id == "timeout":
        await asyncio.sleep(10)
    if job_id == "tool-error":
        raise ValueError("controlled tool error")
    return {"status": "completed" if cursor >= 7 else "running",
            "resume": {"job_id": job_id, "cursor": next_cursor}}

mcp.run(transport="stdio")
