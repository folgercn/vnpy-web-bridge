from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def test_phase_a_compose_has_only_frontend_host_port_and_private_execution_network() -> (
    None
):
    compose = (ROOT / "deployments/docker-compose.phase-a.yml").read_text(
        encoding="utf-8"
    )
    assert '"8080:8080"' in compose
    assert '"8081:8081"' not in compose
    assert '"8090:8090"' not in compose
    assert "private-control:" in compose
    assert "edge-control:" in compose
    assert "internal: true" in compose
    assert "execution-egress:" not in compose
    assert "gateway-proxy:" in compose
    assert "gateway-egress:" in compose
    assert "Execution never joins gateway-egress" in compose
    assert "gateway-rpc-request-proxy:" in compose
    assert "gateway-rpc-publish-proxy:" in compose
    assert 'command: ["request"]' in compose
    assert 'command: ["publish"]' in compose
    assert "/bin/sh" not in compose
    assert "gateway_proxy.py" in (
        ROOT / "deployments/phase-a/Containerfile.gateway-proxy"
    ).read_text(encoding="utf-8")
    assert "VNPY_RPC_" not in compose
    assert "EXECUTION_RPC_REQ_ADDRESS: tcp://gateway-rpc-request-proxy:" in compose
    assert "EXECUTION_RPC_PUB_ADDRESS: tcp://gateway-rpc-publish-proxy:" in compose
    assert "${GATEWAY_RPC_REQ_PROXY_PORT:?" in compose
    assert "${GATEWAY_RPC_PUB_PROXY_PORT:?" in compose
    assert "${WINDOWS_RPC_REQ_ADDRESS:?" in compose
    assert "${WINDOWS_RPC_PUB_ADDRESS:?" in compose
    assert compose.count("condition: service_healthy") >= 3
    assert compose.count('\n      PROXY_HEALTH_PORT: "18080"') == 2
    assert compose.count('/usr/local/bin/gateway_proxy.py", "health"') == 2
    assert "http://gateway-rpc-request-proxy" not in compose
    assert (
        'for host in (\\"gateway-rpc-request-proxy\\",\\"gateway-rpc-publish-proxy\\")'
    ) in compose
    allowlist = (ROOT / "deployments/phase-a/gateway-allowlist.json").read_text(
        encoding="utf-8"
    )
    assert '"192.168.100.187"' in allowlist
    assert '"target_port": 2014' in allowlist
    assert '"target_port": 4102' in allowlist
    assert "./phase-a/postgres-init.sh" in compose
    assert "control-data:" in compose
    assert "execution-data:" in compose
    assert "CONTROL_DB_USER: ${CONTROL_DB_USER:?" in compose
    assert "EXECUTION_DB_USER: ${EXECUTION_DB_USER:?" in compose
    assert (
        "CONTROL_EXECUTION_BASE_URL: ${CONTROL_EXECUTION_BASE_URL:-http://execution-orchestrator:8090}"
        in compose
    )
    assert (
        "CONTROL_EXECUTION_SHARED_SECRET: ${CONTROL_EXECUTION_SHARED_SECRET:?"
        in compose
    )
    assert "CONTROL_EXECUTION_PRINCIPAL: ${CONTROL_EXECUTION_PRINCIPAL:?" in compose
    assert "CONTROL_EXECUTION_ROLE: ${CONTROL_EXECUTION_ROLE:?" in compose
    assert "EXECUTION_SCOPE: ${EXECUTION_SCOPE:?" in compose
    assert "EXECUTION_ENVIRONMENT: ${EXECUTION_ENVIRONMENT:?" in compose
    assert 'os.environ[\\"CONTROL_EXECUTION_SHARED_SECRET\\"]' in compose
    assert "X-Control-Execution-Secret" in compose
    assert "JWT_SECRET_KEY: ${JWT_SECRET_KEY:?" in compose
    assert "AUTH_USERS_JSON: ${AUTH_USERS_JSON:?" in compose
    assert 'PRODUCTION: "false"' in compose
    assert 'LIVE_TRADING_AUTHORIZED: "false"' in compose
    assert 'COUNTABLE_FORWARD: "false"' in compose
    assert "http://control_api/health/ready" in (
        ROOT / "frontend/nginx.conf"
    ).read_text(encoding="utf-8")
    assert "execution-orchestrator:\n        condition: service_started" in compose
    assert "control-api:\n        condition: service_started" in compose
    execution_block = compose.split("  execution-orchestrator:", 1)[1].split(
        "  # These two sidecars", 1
    )[0]
    assert "- gateway-proxy" in execution_block
    assert "gateway-egress" not in execution_block
    frontend_block = compose.split("  frontend-edge:", 1)[1].split("  control-api:", 1)[
        0
    ]
    control_block = compose.split("  control-api:", 1)[1].split(
        "  execution-orchestrator:", 1
    )[0]
    assert "- edge\n" in frontend_block
    assert "- edge-control" in frontend_block
    assert "- edge-control" in control_block
    assert "- edge\n" not in control_block


def test_rpc_env_contract_is_canonical_and_prod_entrypoint_includes_phase_a() -> None:
    gateway = (ROOT / "backend/app/execution/gateway.py").read_text(encoding="utf-8")
    prod = (ROOT / "deployments/docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "EXECUTION_RPC_REQ_ADDRESS" in gateway
    assert "EXECUTION_RPC_PUB_ADDRESS" in gateway
    assert "VNPY_RPC_REQ_ADDRESS" not in gateway
    assert "VNPY_RPC_PUB_ADDRESS" not in gateway
    assert "include:" in prod
    assert "./docker-compose.phase-a.yml" in prod
    assert "web-bridge:" not in prod


def test_gateway_proxy_rejects_any_target_outside_baked_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_path = ROOT / "deployments/phase-a/gateway_proxy.py"
    spec = importlib.util.spec_from_file_location("phase_a_gateway_proxy", proxy_path)
    assert spec is not None and spec.loader is not None
    proxy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proxy)
    proxy.ALLOWLIST_PATH = tmp_path / "gateway-allowlist.json"
    proxy.ALLOWLIST_PATH.write_text(
        (ROOT / "deployments/phase-a/gateway-allowlist.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    expected = proxy._read_allowlist("request")
    assert proxy._parse_exact_target(
        "tcp://192.168.100.187:2014", expected, "request"
    ) == ("192.168.100.187", 2014)
    for invalid in (
        "tcp://192.168.100.186:2014",
        "tcp://192.168.100.187:4102",
        "tcp://192.168.100.187:02014",
        "http://192.168.100.187:2014",
        "tcp://192.168.100.187:2014;touch /tmp/pwned",
    ):
        with pytest.raises(proxy.ProxyConfigurationError):
            proxy._parse_exact_target(invalid, expected, "request")

    monkeypatch.setenv("PROXY_HEALTH_PORT", "18080")
    monkeypatch.setenv("GATEWAY_PROXY_VERSION", "phase-a.1")
    assert proxy._parse_health_port() == 18080
    assert proxy._service_version() == "phase-a.1"
    monkeypatch.setenv("PROXY_HEALTH_PORT", "18081")
    with pytest.raises(proxy.ProxyConfigurationError):
        proxy._parse_health_port()


def test_gateway_proxy_version_is_fixed_offline_and_unknown_args_fail(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy_path = ROOT / "deployments/phase-a/gateway_proxy.py"
    spec = importlib.util.spec_from_file_location(
        "phase_a_gateway_proxy_version", proxy_path
    )
    assert spec is not None and spec.loader is not None
    proxy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proxy)
    monkeypatch.setenv("GATEWAY_PROXY_VERSION", "tampered-at-runtime")
    assert proxy.main(["version"]) == 0
    assert '"version":"phase-a"' in capsys.readouterr().out
    assert proxy.main(["unknown"]) == 64


def test_gateway_proxy_readiness_fails_when_fixed_target_is_down() -> None:
    proxy_path = ROOT / "deployments/phase-a/gateway_proxy.py"
    spec = importlib.util.spec_from_file_location(
        "phase_a_gateway_proxy_health", proxy_path
    )
    assert spec is not None and spec.loader is not None
    proxy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proxy)

    async def scenario() -> None:
        async def close_target(
            _reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.close()
            await writer.wait_closed()

        target = await asyncio.start_server(close_target, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        data_server = await asyncio.start_server(close_target, "127.0.0.1", 0)
        health = await asyncio.start_server(
            lambda reader, writer: proxy._handle_health(
                reader,
                writer,
                target_host="127.0.0.1",
                target_port=target_port,
                proxy_server=data_server,
                version="gate-test",
            ),
            "127.0.0.1",
            0,
        )
        health_port = health.sockets[0].getsockname()[1]

        async def get(path: str) -> bytes:
            reader, writer = await asyncio.open_connection("127.0.0.1", health_port)
            writer.write(f"GET {path} HTTP/1.1\r\nHost: proxy\r\n\r\n".encode())
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            return response

        try:
            assert (await get("/health/live")).startswith(b"HTTP/1.1 200")
            assert b'"status":"ready"' in await get("/health/ready")
            assert b'"version":"gate-test"' in await get("/version")
            target.close()
            await target.wait_closed()
            assert (await get("/health/ready")).startswith(b"HTTP/1.1 503")
        finally:
            health.close()
            data_server.close()
            target.close()
            await asyncio.gather(
                health.wait_closed(), data_server.wait_closed(), target.wait_closed()
            )

    asyncio.run(scenario())


def test_phase_a_images_use_dedicated_control_and_execution_entries() -> None:
    control = (ROOT / "deployments/phase-a/Containerfile.control-api").read_text(
        encoding="utf-8"
    )
    execution = (
        ROOT / "deployments/phase-a/Containerfile.execution-orchestrator"
    ).read_text(encoding="utf-8")
    assert "app.control_api:app" in control
    assert '--port", "8081' in control
    assert "COPY backend/app/control_ws_ticket.py" in control
    assert "frontend/dist" not in control
    assert 'python", "-m", "app.execution_orchestrator' in execution
    assert "--port" not in execution or "8090" in execution
    assert "COPY frontend" not in execution
    assert "USER 65532:65532" in control
    assert "USER 65532:65532" in execution
    assert "/var/lib/vnpy-control" in control
    assert "/var/lib/vnpy-execution/archive" in execution
    proxy = (ROOT / "deployments/phase-a/Containerfile.gateway-proxy").read_text(
        encoding="utf-8"
    )
    assert 'ENTRYPOINT ["python", "/usr/local/bin/gateway_proxy.py"]' in proxy
    assert 'CMD ["request"]' in proxy
    assert 'CMD ["python", "/usr/local/bin/gateway_proxy.py", "health"]' in proxy
    proxy_source = (ROOT / "deployments/phase-a/gateway_proxy.py").read_text(
        encoding="utf-8"
    )
    assert 'fields[1] == "/health/live"' in proxy_source
    assert 'fields[1] == "/health/ready"' in proxy_source
    assert 'fields[1] == "/version"' in proxy_source
    assert "asyncio.open_connection(target_host, target_port)" in proxy_source


def test_phase_a_postgres_init_uses_safe_roles_schemas_and_search_paths() -> None:
    init = (ROOT / "deployments/phase-a/postgres-init.sh").read_text(encoding="utf-8")
    assert "DO $$" not in init
    assert "format('CREATE ROLE %I LOGIN'" in init
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" in init
    assert "CONTROL_DB_USER and EXECUTION_DB_USER must be distinct" in init
    assert "application roles must not reuse POSTGRES_USER" in init
    assert "ALTER SCHEMA control OWNER" in init
    assert "ALTER SCHEMA execution OWNER" in init
    assert "SET search_path = control, pg_catalog" in init
    assert "SET search_path = execution, pg_catalog" in init
    assert "REVOKE ALL ON SCHEMA execution" in init
    assert "REVOKE ALL ON SCHEMA control" in init
