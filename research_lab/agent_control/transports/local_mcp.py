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
import time
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
                stderr=subprocess.DEVNULL,
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
            deadline = time.monotonic() + 10.0
            init_resp = self._read_response(proc, 1, deadline)
            if "error" in init_resp:
                raise ProviderUnavailableError(
                    f"MCP server initialize error: {init_resp['error'].get('message')}"
                )

            self._send_initialized(proc)

            # 2. tools/list
            tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            proc.stdin.write(json.dumps(tools_req) + "\n")
            proc.stdin.flush()
            tools_resp = self._read_response(proc, 2, deadline)
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
    def _send_initialized(proc: subprocess.Popen) -> None:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

    @staticmethod
    def _readline_with_timeout(proc: subprocess.Popen, timeout_seconds: float) -> str:
        """Read complete UTF-8 frames without TextIO prefetch or partial-line hangs."""
        if proc.stdout is None:
            return ""
        deadline = time.monotonic() + max(0, timeout_seconds)
        buffer = getattr(proc, "_mcp_frame_buffer", b"")
        while True:
            if b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                proc._mcp_frame_buffer = buffer
                return line.decode("utf-8")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
                raise subprocess.TimeoutExpired(proc.args, timeout_seconds)
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                if buffer:
                    raise ValueError("MCP EOF inside an incomplete JSON-RPC frame")
                return ""
            buffer += chunk
            if len(buffer) > 4 * 1024 * 1024:
                raise ValueError("MCP response frame exceeds size limit")

    @classmethod
    def _read_response(cls, proc: subprocess.Popen, request_id: int, deadline: float, on_notification=None) -> dict:
        """Ignore notifications/unrelated responses; accept only the exact request ID."""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(proc.args, 0)
            line = cls._readline_with_timeout(proc, remaining)
            if not line:
                raise EOFError("MCP EOF before matching JSON-RPC response")
            message = json.loads(line)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise ValueError("Invalid MCP JSON-RPC frame")
            if "id" not in message and isinstance(message.get("method"), str):
                if on_notification is not None:
                    on_notification(message)
                continue
            if "method" in message:
                raise ValueError("Unsupported MCP server request")
            if "result" not in message and "error" not in message:
                raise ValueError("MCP response has neither result nor error")
            # bool and numeric/string aliases cannot match our integer request ID.
            if type(message.get("id")) is not int or message["id"] != request_id:
                continue
            return message

    def call_tool(
        self,
        operation: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout_seconds: float = 60.0,
        on_notification: Callable[[dict], None] | None = None,
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

        return self._execute_stdio_call(tool_name, args, timeout_seconds=timeout_seconds, on_notification=on_notification)

    def _execute_stdio_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout_seconds: float,
        on_notification: Callable[[dict], None] | None = None,
    ) -> Any:
        """Perform a single tools/call invocation over a managed stdio process."""
        proc = None
        try:
            proc = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
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
            deadline = time.monotonic() + timeout_seconds
            init_response = self._read_response(proc, 1, deadline)
            if "error" in init_response:
                raise ProviderUnavailableError("MCP initialize returned an error")
            self._send_initialized(proc)

            # 2. tools/call
            call_req = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
            proc.stdin.write(json.dumps(call_req) + "\n")
            proc.stdin.flush()

            resp = self._read_response(proc, 2, deadline, on_notification)
            if "error" in resp:
                err_data = resp["error"]
                err_msg = err_data.get("message", "Unknown MCP error")
                raise ProviderError(
                    ProviderErrorCode.EXECUTION_FAILED,
                    f"MCP tool '{tool_name}' returned error: {err_msg}",
                    details={"tool_name": tool_name, "error": err_data},
                )

            result_obj = resp["result"]
            if isinstance(result_obj, dict) and result_obj.get("isError") is True:
                raise ProviderError(ProviderErrorCode.EXECUTION_FAILED,
                                    f"MCP tool '{tool_name}' returned isError=true")
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
