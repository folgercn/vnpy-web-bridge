"""Tests for Antigravity MCP server transports (Network SSE & Local Unix Domain Socket)."""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from research_lab.agent_control.antigravity_mcp.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_SOCKET_PATH,
    DEFAULT_TRANSPORT,
)
from research_lab.agent_control.antigravity_mcp.server import (
    ApiKeyAuthMiddleware,
    main,
    print_startup_banner,
    run_socket_server,
)


def test_default_transport_configs():
    """Verify default configurations for transports and socket path."""
    assert DEFAULT_TRANSPORT == "sse"
    assert DEFAULT_HOST == "127.0.0.1"
    assert DEFAULT_PORT == 8765
    assert str(DEFAULT_SOCKET_PATH).endswith("antigravity_mcp.sock")


def test_cli_parser_defaults():
    """Verify CLI parser defaults when no flags are supplied."""
    mock_mcp = MagicMock()
    with (
        patch("sys.argv", ["server.py"]),
        patch("research_lab.agent_control.antigravity_mcp.server.create_mcp_server", return_value=mock_mcp),
        patch("research_lab.agent_control.antigravity_mcp.server.print_startup_banner"),
        patch.object(mock_mcp, "run") as mock_run,
        patch("research_lab.agent_control.antigravity_mcp.server.AGY_MCP_API_KEY", ""),
    ):
        main()
        mock_run.assert_called_once_with(transport="sse")


def test_cli_parser_socket_transport(tmp_path):
    """Verify CLI parser for --transport socket with custom socket path."""
    sock_file = tmp_path / "custom.sock"
    mock_mcp = MagicMock()
    with (
        patch("sys.argv", ["server.py", "--transport", "socket", "--socket", str(sock_file)]),
        patch("research_lab.agent_control.antigravity_mcp.server.create_mcp_server", return_value=mock_mcp),
        patch("research_lab.agent_control.antigravity_mcp.server.print_startup_banner"),
        patch("research_lab.agent_control.antigravity_mcp.server.run_socket_server") as mock_run_socket,
    ):
        main()
        mock_run_socket.assert_called_once()
        call_kwargs = mock_run_socket.call_args.kwargs
        assert call_kwargs["socket_path"] == sock_file
        # By default local socket should be exempt from token auth
        assert call_kwargs["require_auth"] is False


def test_cli_auth_flags():
    """Verify --require-auth and --no-auth flags handling."""
    # Test --require-auth with socket transport
    with (
        patch("sys.argv", ["server.py", "--transport", "socket", "--require-auth"]),
        patch("research_lab.agent_control.antigravity_mcp.server.create_mcp_server"),
        patch("research_lab.agent_control.antigravity_mcp.server.print_startup_banner"),
        patch("research_lab.agent_control.antigravity_mcp.server.run_socket_server") as mock_run_socket,
    ):
        main()
        assert mock_run_socket.call_args.kwargs["require_auth"] is True

    # Test --no-auth with sse transport when AGY_MCP_API_KEY is present
    mock_mcp = MagicMock()
    with (
        patch("sys.argv", ["server.py", "--transport", "sse", "--no-auth"]),
        patch("research_lab.agent_control.antigravity_mcp.server.create_mcp_server", return_value=mock_mcp),
        patch("research_lab.agent_control.antigravity_mcp.server.print_startup_banner"),
        patch("research_lab.agent_control.antigravity_mcp.server.AGY_MCP_API_KEY", "secret"),
        patch.object(mock_mcp, "run") as mock_run,
    ):
        main()
        mock_run.assert_called_once_with(transport="sse")


def test_run_socket_server_stale_file_cleanup_and_directory_creation():
    """Verify run_socket_server cleans up stale socket files and ensures parent directory."""
    repo_root = Path(__file__).resolve().parents[4]
    sock_dir = repo_root / "tmp" / "nested" / "sockets"
    sock_path = sock_dir / "test.sock"

    # Pre-create directory and stale socket file
    sock_dir.mkdir(parents=True, exist_ok=True)
    sock_path.touch()
    assert sock_path.exists()

    mock_mcp = MagicMock()
    mock_app = MagicMock()
    mock_mcp.sse_app.return_value = mock_app
    mock_mcp.settings.log_level = "info"

    with (
        patch("uvicorn.Server") as mock_server_cls,
        patch("uvicorn.Config") as mock_config_cls,
    ):
        mock_server = MagicMock()
        mock_server.serve = AsyncMock()
        mock_server_cls.return_value = mock_server

        try:
            run_socket_server(
                mcp_server=mock_mcp,
                socket_path=sock_path,
                api_key="",
                require_auth=False,
            )

            mock_config_cls.assert_called_once_with(
                mock_app,
                uds=str(sock_path.resolve()),
                log_level="info",
            )
            mock_server.serve.assert_awaited_once()
        finally:
            if sock_path.exists():
                sock_path.unlink()
            try:
                sock_dir.rmdir()
                (repo_root / "tmp" / "nested").rmdir()
                (repo_root / "tmp").rmdir()
            except OSError:
                pass


def test_run_socket_server_auth_middleware_wrapping():
    """Verify run_socket_server wraps app in ApiKeyAuthMiddleware only when require_auth=True."""
    repo_root = Path(__file__).resolve().parents[4]
    tmp_dir = repo_root / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    sock_path = tmp_dir / "auth_test.sock"

    mock_mcp = MagicMock()
    mock_app = MagicMock()
    mock_mcp.sse_app.return_value = mock_app
    mock_mcp.settings.log_level = "info"

    with (
        patch("uvicorn.Server") as mock_server_cls,
        patch("uvicorn.Config") as mock_config_cls,
    ):
        mock_server = MagicMock()
        mock_server.serve = AsyncMock()
        mock_server_cls.return_value = mock_server

        try:
            # When require_auth=True and api_key is present
            run_socket_server(
                mcp_server=mock_mcp,
                socket_path=sock_path,
                api_key="my_secret_token",
                require_auth=True,
            )

            app_arg = mock_config_cls.call_args[0][0]
            assert isinstance(app_arg, ApiKeyAuthMiddleware)
            assert app_arg.api_key == "my_secret_token"
        finally:
            if sock_path.exists():
                sock_path.unlink()
            try:
                tmp_dir.rmdir()
            except OSError:
                pass


def test_run_socket_server_path_too_long_raises():
    """Verify run_socket_server raises ValueError if socket path exceeds 104 chars."""
    mock_mcp = MagicMock()
    long_path = Path("/" + "a" * 120 + ".sock")
    try:
        run_socket_server(
            mcp_server=mock_mcp,
            socket_path=long_path,
            api_key="",
            require_auth=False,
        )
        assert False, "Expected ValueError for long socket path"
    except ValueError as exc:
        assert "too long" in str(exc)


def test_print_startup_banner_socket_and_sse(capsys):
    """Verify print_startup_banner output formatting for both socket and sse transports."""
    # Test socket banner
    test_sock = Path("/tmp/test_banner.sock")
    print_startup_banner(transport="socket", socket_path=test_sock, auth_enabled=False)
    captured = capsys.readouterr().out
    assert "Local Unix Domain Socket (unix:/tmp/test_banner.sock)" in captured
    assert "免密开箱即用" in captured

    # Test sse banner
    print_startup_banner(transport="sse", host="127.0.0.1", port=9999, auth_enabled=True)
    captured_sse = capsys.readouterr().out
    assert "Network SSE (http://127.0.0.1:9999/sse)" in captured_sse
    assert "Token Auth ENABLED" in captured_sse
