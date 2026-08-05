"""Fixed-target TCP proxy for the Phase A Windows RPC boundary.

The image bakes a root-owned allowlist.  Runtime environment values are only
accepted after strict parsing and an exact host/port match for the selected
request or publish role.  No shell parses or executes an address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

ALLOWLIST_PATH = Path("/etc/vnpy/gateway-allowlist.json")
ADDRESS_RE = re.compile(
    r"tcp://(?P<host>[0-9]{1,3}(?:\.[0-9]{1,3}){3}):(?P<port>[0-9]{1,5})\Z"
)
VERSION_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
HEALTH_PORT = 18080
PROXY_VERSION = "phase-a"


class ProxyConfigurationError(RuntimeError):
    """The sidecar configuration is absent or outside the baked allowlist."""


def _read_allowlist(role: str) -> dict[str, int | str]:
    try:
        raw: Any = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProxyConfigurationError("baked gateway allowlist is unreadable") from exc
    entry = raw.get(role) if isinstance(raw, dict) else None
    if not isinstance(entry, dict):
        raise ProxyConfigurationError(f"baked gateway allowlist has no {role} entry")
    host = entry.get("target_host")
    target_port = entry.get("target_port")
    listen_port = entry.get("listen_port")
    if (
        not isinstance(host, str)
        or not isinstance(target_port, int)
        or not isinstance(listen_port, int)
        or target_port < 1
        or target_port > 65535
        or listen_port < 1
        or listen_port > 65535
    ):
        raise ProxyConfigurationError(
            f"baked gateway allowlist has invalid {role} entry"
        )
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ProxyConfigurationError(
            f"baked gateway allowlist has invalid {role} host"
        ) from exc
    return {"target_host": host, "target_port": target_port, "listen_port": listen_port}


def _parse_exact_target(
    raw: str, expected: dict[str, int | str], role: str
) -> tuple[str, int]:
    match = ADDRESS_RE.fullmatch(raw)
    if match is None:
        environment_role = "REQ" if role == "request" else "PUB"
        raise ProxyConfigurationError(
            f"WINDOWS_RPC_{environment_role}_ADDRESS must be tcp://<IPv4>:<port>"
        )
    host = match.group("host")
    port_text = match.group("port")
    try:
        ipaddress.ip_address(host)
        port = int(port_text, 10)
    except ValueError as exc:
        raise ProxyConfigurationError(
            "gateway target address is not a valid IPv4 endpoint"
        ) from exc
    if str(port) != port_text or port < 1 or port > 65535:
        raise ProxyConfigurationError("gateway target port is not canonical")
    if host != expected["target_host"] or port != expected["target_port"]:
        raise ProxyConfigurationError(
            f"{role} gateway target is outside the baked Windows allowlist"
        )
    return host, port


def _parse_listen_port(expected: dict[str, int | str]) -> int:
    raw = os.getenv("PROXY_LISTEN_PORT", "")
    if not raw.isdecimal() or str(int(raw, 10)) != raw:
        raise ProxyConfigurationError(
            "PROXY_LISTEN_PORT must be a canonical decimal port"
        )
    port = int(raw, 10)
    if port != expected["listen_port"]:
        raise ProxyConfigurationError(
            "proxy listen port differs from the baked allowlist"
        )
    return port


def _service_version() -> str:
    version = os.getenv("GATEWAY_PROXY_VERSION", "phase-a")
    if VERSION_RE.fullmatch(version) is None:
        raise ProxyConfigurationError("GATEWAY_PROXY_VERSION is invalid")
    return version


def _parse_health_port() -> int:
    raw = os.getenv("PROXY_HEALTH_PORT", str(HEALTH_PORT))
    if raw != str(HEALTH_PORT):
        raise ProxyConfigurationError(
            f"PROXY_HEALTH_PORT must be the fixed internal port {HEALTH_PORT}"
        )
    return HEALTH_PORT


async def _copy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(64 * 1024):
            writer.write(chunk)
            await writer.drain()
    finally:
        try:
            writer.write_eof()
            await writer.drain()
        except (AttributeError, ConnectionError, OSError):
            pass


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    target_host: str,
    target_port: int,
) -> None:
    upstream: asyncio.StreamWriter | None = None
    try:
        upstream_reader, upstream = await asyncio.open_connection(
            target_host, target_port
        )
        await asyncio.gather(_copy(reader, upstream), _copy(upstream_reader, writer))
    except (ConnectionError, OSError, asyncio.TimeoutError):
        # A failed target is a closed connection, not a fallback or a second
        # destination.  The next client may retry the same fixed target.
        return
    finally:
        writer.close()
        if upstream is not None:
            upstream.close()
        await writer.wait_closed()
        if upstream is not None:
            await upstream.wait_closed()


async def _target_is_ready(target_host: str, target_port: int) -> bool:
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port), timeout=2.0
        )
        return True
    except (ConnectionError, OSError, asyncio.TimeoutError):
        return False
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()


async def _handle_health(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    target_host: str,
    target_port: int,
    proxy_server: asyncio.Server,
    version: str,
) -> None:
    status = "404 Not Found"
    body: dict[str, str] = {"status": "not_found", "service": "gateway-rpc-proxy"}
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        fields = request_line.decode("ascii", errors="strict").strip().split()
        if len(fields) != 3 or fields[0] != "GET":
            status = "405 Method Not Allowed"
            body["status"] = "invalid_request"
        elif fields[1] == "/health/live":
            live = proxy_server.is_serving()
            status = "200 OK" if live else "503 Service Unavailable"
            body["status"] = "live" if live else "not_live"
        elif fields[1] == "/health/ready":
            ready = proxy_server.is_serving() and await _target_is_ready(
                target_host, target_port
            )
            status = "200 OK" if ready else "503 Service Unavailable"
            body["status"] = "ready" if ready else "not_ready"
        elif fields[1] == "/version":
            status = "200 OK"
            body = {
                "status": "ok",
                "service": "gateway-rpc-proxy",
                "version": version,
            }
    except (UnicodeError, asyncio.TimeoutError, ValueError):
        status = "400 Bad Request"
        body["status"] = "invalid_request"
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = (
        f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
        f"Cache-Control: no-store\r\nContent-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    writer.write(headers + payload)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def _serve(
    target_host: str,
    target_port: int,
    listen_port: int,
    health_port: int,
    version: str,
) -> None:
    proxy_server = await asyncio.start_server(
        lambda reader, writer: _handle(
            reader,
            writer,
            target_host=target_host,
            target_port=target_port,
        ),
        host="0.0.0.0",
        port=listen_port,
    )
    try:
        health_server = await asyncio.start_server(
            lambda reader, writer: _handle_health(
                reader,
                writer,
                target_host=target_host,
                target_port=target_port,
                proxy_server=proxy_server,
                version=version,
            ),
            host="0.0.0.0",
            port=health_port,
        )
    except BaseException:
        proxy_server.close()
        await proxy_server.wait_closed()
        raise
    async with proxy_server, health_server:
        await asyncio.gather(
            proxy_server.serve_forever(), health_server.serve_forever()
        )


def _probe_local_health() -> int:
    port = _parse_health_port()
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health/ready", timeout=3
        ) as response:
            body = json.load(response)
        return 0 if response.status == 200 and body.get("status") == "ready" else 1
    except (OSError, ValueError):
        return 1


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if args == ["health"]:
        return _probe_local_health()
    if args == ["version"]:
        print(
            json.dumps(
                {"service": "gateway-rpc-proxy", "version": PROXY_VERSION},
                separators=(",", ":"),
            )
        )
        return 0
    if len(args) != 1 or args[0] not in {"request", "publish"}:
        print("usage: gateway_proxy.py request|publish|health|version", file=sys.stderr)
        return 64
    role = args[0]
    try:
        expected = _read_allowlist(role)
        env_key = (
            "WINDOWS_RPC_REQ_ADDRESS"
            if role == "request"
            else "WINDOWS_RPC_PUB_ADDRESS"
        )
        target_host, target_port = _parse_exact_target(
            os.getenv(env_key, ""), expected, role
        )
        listen_port = _parse_listen_port(expected)
        health_port = _parse_health_port()
        version = _service_version()
        asyncio.run(
            _serve(
                target_host,
                target_port,
                listen_port,
                health_port,
                version,
            )
        )
    except (ProxyConfigurationError, OSError) as exc:
        print(f"gateway proxy refused to start: {exc}", file=sys.stderr)
        return 78
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
