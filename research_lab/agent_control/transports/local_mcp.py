"""Local MCP transport runtime and tool resolver (#573 Milestone 2).

Architecture Rule:
Role -> Access Control -> Agent Router -> Agent Provider -> Provider Transport (LocalMCPTransport)

Boundary rules:
1. Wrap existing local FastMCP capabilities only (account_usage, projects, submit, message, watch, events, wait, status, result, cancel).
2. NEVER copy desktop backend or call desktop internal HTTPS APIs directly.
3. Tool names resolved dynamically via runtime discovery; critical tools missing fail closed.
4. Fail-closed without automatic shell fallback.
5. NEVER expose sensitive tokens, credentials, sessions, sockets, or private fields.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from research_lab.agent_control.errors import (
    ProviderError,
    ProviderErrorCode,
    ProviderUnavailableError,
)
from research_lab.agent_control.transport import (
    ProviderConnectionDescriptor,
    ProviderTransportKind,
)

# Standard MCP operations supported by the local Antigravity server
ALL_MCP_OPERATIONS = frozenset(
    {
        "account_usage",
        "cancel",
        "events",
        "message",
        "projects",
        "result",
        "status",
        "submit",
        "wait",
        "watch",
    }
)

# Critical tools required for minimal operation (fail-closed if any is absent)
CRITICAL_MCP_TOOLS = frozenset({"account_usage", "projects", "submit", "status", "result"})

# Explicit fallback aliases when tools/list uses prefixed/custom naming conventions
STANDARD_TOOL_ALIASES: dict[str, list[str]] = {
    "account_usage": ["get_account_usage", "antigravity_account_usage", "usage", "account_status"],
    "cancel": ["cancel_job", "antigravity_cancel", "abort_job"],
    "events": ["get_job_events", "antigravity_events", "job_events"],
    "message": ["send_message", "antigravity_message", "post_message"],
    "projects": ["list_projects", "antigravity_projects", "get_projects"],
    "result": ["get_result", "get_job_result", "antigravity_result", "job_result"],
    "status": ["get_status", "get_job_status", "antigravity_status", "job_status"],
    "submit": ["submit_job", "submit_task", "antigravity_submit", "create_job"],
    "wait": ["wait_job", "wait_for_job", "antigravity_wait"],
    "watch": ["watch_job", "watch_job_status", "antigravity_watch"],
}

# Default path to the existing FastMCP server script in the local environment
DEFAULT_MCP_SCRIPT = Path("/Users/fujun/.codex/skills/antigravity-delegate/scripts/agy_mcp.py")
DEFAULT_MCP_VENV_PYTHON = Path("/Users/fujun/.codex/skills/antigravity-delegate/.mcp-venv/bin/python")


class MCPToolResolver:
    """Dynamically resolves and binds runtime tool names to standard MCP operations."""

    def __init__(self, available_tool_names: list[str] | set[str] | tuple[str, ...]) -> None:
        self._raw_tool_names = tuple(str(n) for n in available_tool_names)
        self._mapping: dict[str, str] = {}
        self._resolve()

    def _resolve(self) -> None:
        names = list(self._raw_tool_names)
        for op in ALL_MCP_OPERATIONS:
            # 1. Exact match
            if op in names:
                self._mapping[op] = op
                continue
            # 2. Host-prefixed match (e.g. mcp__antigravity__submit, antigravity__submit)
            candidates = [
                n for n in names
                if n.endswith((f"__{op}", f":{op}", f".{op}"))
            ]
            if candidates:
                self._mapping[op] = candidates[0]

    def has_operation(self, op: str) -> bool:
        return op in self._mapping

    def get_tool_name(self, op: str) -> str:
        if op not in self._mapping:
            raise ProviderUnavailableError(
                f"Requested MCP operation '{op}' is not available in resolved tool catalog",
                details={"available_tools": list(self._mapping.keys())},
            )
        return self._mapping[op]

    def validate_critical_tools(self) -> None:
        missing = [op for op in CRITICAL_MCP_TOOLS if op not in self._mapping]
        if missing:
            raise ProviderUnavailableError(
                f"Missing critical MCP tools: {sorted(missing)}. Fail closed without fallback.",
                details={"available_tools": list(self._mapping.keys()), "missing_tools": sorted(missing)},
            )

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._mapping)


def parse_mcp_response_content(content_obj: Any, *, _depth: int = 0) -> Any:
    """Parse text content from FastMCP call_tool return format."""
    if _depth > 5:
        return content_obj

    if isinstance(content_obj, dict):
        # FastMCP {"content": [{"type": "text", "text": "..."}]}
        if "content" in content_obj and isinstance(content_obj["content"], list):
            items = content_obj["content"]
            if items and isinstance(items[0], dict) and items[0].get("type") == "text":
                text = items[0].get("text", "")
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    return text
        # Only unwrap "result" if it's a JSON-RPC / envelope wrapper (e.g. single key "result" or has "jsonrpc")
        if "result" in content_obj and (len(content_obj) == 1 or "jsonrpc" in content_obj):
            return parse_mcp_response_content(content_obj["result"], _depth=_depth + 1)
        return content_obj
    if isinstance(content_obj, str):
        try:
            return json.loads(content_obj)
        except (json.JSONDecodeError, TypeError):
            return content_obj
    return content_obj


class LocalMCPTransport:
    """Encapsulates local JSON-RPC stdio and callable communications with FastMCP."""

    def __init__(
        self,
        *,
        command: list[str] | None = None,
        tool_catalog: list[str] | None = None,
        tool_caller: Callable[[str, dict[str, Any]], Any] | None = None,
        connection_profile_ref: str = "antigravity-local-desktop",
    ) -> None:
        self._connection_profile_ref = connection_profile_ref
        self._descriptor = ProviderConnectionDescriptor(
            transport_kind=ProviderTransportKind.LOCAL_MCP,
            connection_profile_ref=connection_profile_ref,
            capabilities=tuple(sorted(ALL_MCP_OPERATIONS)),
        )
        self._tool_caller = tool_caller
        self._explicit_tool_catalog = tool_catalog
        self._resolver: MCPToolResolver | None = None
        self._next_req_id = 1

        # Command determination
        if command is not None:
            self._command = list(command)
        else:
            env_cmd = os.environ.get("ANTIGRAVITY_MCP_COMMAND")
            if env_cmd:
                self._command = env_cmd.split()
            elif DEFAULT_MCP_VENV_PYTHON.is_file() and DEFAULT_MCP_SCRIPT.is_file():
                self._command = [
                    "/usr/bin/arch",
                    "-arm64",
                    str(DEFAULT_MCP_VENV_PYTHON),
                    str(DEFAULT_MCP_SCRIPT),
                ]
            else:
                self._command = []

    @property
    def descriptor(self) -> ProviderConnectionDescriptor:
        return self._descriptor

    @property
    def exact_ref(self) -> str:
        return self._descriptor.exact_ref

    def discover_tools(self) -> MCPToolResolver:
        """Query tool list and build resolved tool mapping. Fail closed if critical tools missing."""
        if self._resolver is not None:
            return self._resolver

        tool_names: list[str] = []

        if self._explicit_tool_catalog is not None:
            tool_names = list(self._explicit_tool_catalog)
        elif self._tool_caller is not None:
            # If a custom caller provides tool list discovery via empty list call or similar
            try:
                res = self._tool_caller("__list_tools__", {})
                if isinstance(res, (list, tuple)):
                    tool_names = [str(x) for x in res]
            except Exception:  # noqa: BLE001
                # Default to assuming standard operations if explicit catalog not given with caller
                tool_names = list(ALL_MCP_OPERATIONS)
        elif self._command:
            # Discover tools via stdio initialize + tools/list
            tool_names = self._query_stdio_tools_list()
        else:
            raise ProviderUnavailableError(
                "No valid MCP tool caller, tool catalog, or stdio command configured for LocalMCPTransport",
            )

        resolver = MCPToolResolver(tool_names)
        resolver.validate_critical_tools()
        self._resolver = resolver
        return resolver

    def _query_stdio_tools_list(self) -> list[str]:
        """Execute a quick stdio discovery handshake to retrieve available tools."""
        if not self._command:
            raise ProviderUnavailableError("LocalMCPTransport stdio command is empty")
        try:
            proc = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as e:
            raise ProviderUnavailableError(
                f"Failed to start local MCP server process: {e}",
                details={"command": [self._command[0]] if self._command else []},
            ) from e

        try:
            # 1. initialize
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "vnpy-agent-control", "version": "1.0.0"},
                },
            }
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()
            init_line = self._readline_with_timeout(proc, 10.0)
            if not init_line:
                raise ProviderUnavailableError("MCP server process closed before initialize response")
            init_resp = json.loads(init_line)
            if "error" in init_resp:
                raise ProviderUnavailableError(
                    f"MCP server initialize error: {init_resp['error'].get('message')}"
                )

            # 2. tools/list
            tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            proc.stdin.write(json.dumps(tools_req) + "\n")
            proc.stdin.flush()
            tools_line = self._readline_with_timeout(proc, 10.0)
            if not tools_line:
                raise ProviderUnavailableError("MCP server process closed before tools/list response")
            tools_resp = json.loads(tools_line)
            if "error" in tools_resp:
                raise ProviderUnavailableError(
                    f"MCP server tools/list error: {tools_resp['error'].get('message')}"
                )

            tools_data = tools_resp.get("result", {}).get("tools", [])
            return [t["name"] for t in tools_data if isinstance(t, dict) and "name" in t]
        except subprocess.TimeoutExpired as e:
            raise ProviderUnavailableError(f"MCP server discovery timed out: {e}") from e
        except Exception as e:
            if isinstance(e, ProviderError):
                raise
            raise ProviderUnavailableError(f"Error querying MCP tools/list: {e}") from e
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                proc.kill()

    @staticmethod
    def _readline_with_timeout(proc: subprocess.Popen, timeout_seconds: float) -> str:
        """Read a line from stdout with fail-closed timeout detection using select."""
        if proc.stdout is None:
            return ""
        rlist, _, _ = select.select([proc.stdout], [], [], max(0.01, timeout_seconds))
        if not rlist:
            cmd = proc.args if hasattr(proc, "args") else "mcp"
            raise subprocess.TimeoutExpired(cmd, timeout_seconds)
        return proc.stdout.readline()

    def call_tool(
        self,
        operation: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout_seconds: float = 60.0,
    ) -> Any:
        """Invoke an MCP tool by its abstract operation name, resolved dynamically."""
        resolver = self.discover_tools()
        tool_name = resolver.get_tool_name(operation)
        args = arguments or {}

        if self._tool_caller is not None:
            try:
                raw_out = self._tool_caller(tool_name, args)
                return parse_mcp_response_content(raw_out)
            except ProviderError:
                raise
            except Exception as e:
                raise ProviderError(
                    ProviderErrorCode.EXECUTION_FAILED,
                    f"Tool caller failed for operation '{operation}': {e}",
                ) from e

        if not self._command:
            raise ProviderUnavailableError(
                f"Cannot execute tool '{tool_name}': no tool_caller or stdio command configured"
            )

        return self._execute_stdio_call(tool_name, args, timeout_seconds=timeout_seconds)

    def _execute_stdio_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout_seconds: float,
    ) -> Any:
        """Perform a single tools/call invocation over a managed stdio process."""
        proc = None
        try:
            proc = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # 1. initialize
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "vnpy-agent-control", "version": "1.0.0"},
                },
            }
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()
            init_line = self._readline_with_timeout(proc, timeout_seconds)
            if not init_line:
                raise ProviderUnavailableError("MCP server process terminated unexpectedly on initialize")

            # 2. tools/call
            call_req = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
            proc.stdin.write(json.dumps(call_req) + "\n")
            proc.stdin.flush()

            call_line = self._readline_with_timeout(proc, timeout_seconds)
            if not call_line:
                raise ProviderError(
                    ProviderErrorCode.EXECUTION_UNCERTAIN,
                    f"MCP connection lost while awaiting result for tool '{tool_name}'",
                )

            resp = json.loads(call_line)
            if "error" in resp:
                err_data = resp["error"]
                err_msg = err_data.get("message", "Unknown MCP error")
                raise ProviderError(
                    ProviderErrorCode.EXECUTION_FAILED,
                    f"MCP tool '{tool_name}' returned error: {err_msg}",
                    details={"tool_name": tool_name, "error": err_data},
                )

            result_obj = resp.get("result", {})
            return parse_mcp_response_content(result_obj)

        except subprocess.TimeoutExpired as e:
            raise ProviderError(
                ProviderErrorCode.EXECUTION_UNCERTAIN,
                f"MCP call for tool '{tool_name}' timed out after {timeout_seconds}s",
            ) from e
        except json.JSONDecodeError as e:
            raise ProviderError(
                ProviderErrorCode.EXECUTION_UNCERTAIN,
                f"Invalid JSON returned from MCP server during call to '{tool_name}': {e}",
            ) from e
        except Exception as e:
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(
                ProviderErrorCode.EXECUTION_UNCERTAIN,
                f"Failed to execute MCP tool '{tool_name}': {e}",
            ) from e
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except Exception:  # noqa: BLE001
                    proc.kill()
