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
    # Test --require-auth with socket transport and configured key
    with (
        patch("sys.argv", ["server.py", "--transport", "socket", "--require-auth"]),
        patch("research_lab.agent_control.antigravity_mcp.server.create_mcp_server"),
        patch("research_lab.agent_control.antigravity_mcp.server.print_startup_banner"),
        patch("research_lab.agent_control.antigravity_mcp.server.AGY_MCP_API_KEY", "valid_key"),
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


def test_cli_require_auth_missing_key_fails_fast():
    """Verify --require-auth without configured API Key fails fast with sys.exit(1)."""
    import pytest

    with (
        patch("sys.argv", ["server.py", "--transport", "socket", "--require-auth"]),
        patch("research_lab.agent_control.antigravity_mcp.server.create_mcp_server"),
        patch("research_lab.agent_control.antigravity_mcp.server.print_startup_banner"),
        patch("research_lab.agent_control.antigravity_mcp.server.AGY_MCP_API_KEY", ""),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


def test_cli_mutually_exclusive_auth_flags():
    """Verify --require-auth and --no-auth cannot be specified together."""
    import pytest

    with (
        patch("sys.argv", ["server.py", "--require-auth", "--no-auth"]),
        patch("research_lab.agent_control.antigravity_mcp.server.create_mcp_server"),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
        # argparse mutually exclusive group error exits with code 2
        assert exc_info.value.code == 2


def test_run_socket_server_refuses_regular_file():
    """Verify run_socket_server refuses to overwrite regular files and raises RuntimeError."""
    repo_root = Path(__file__).resolve().parents[4]
    tmp_dir = repo_root / "tmp" / "test_refuse_file"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    reg_file = tmp_dir / "not_a_socket.txt"
    reg_file.write_text("important user data")

    mock_mcp = MagicMock()
    try:
        import pytest

        with pytest.raises(RuntimeError, match="is not a socket"):
            run_socket_server(
                mcp_server=mock_mcp,
                socket_path=reg_file,
                api_key="",
                require_auth=False,
            )
        # Verify file was NOT deleted
        assert reg_file.exists()
        assert reg_file.read_text() == "important user data"
    finally:
        if reg_file.exists():
            reg_file.unlink()
        try:
            tmp_dir.rmdir()
        except OSError:
            pass


def test_run_socket_server_refuses_active_listening_socket():
    """Verify run_socket_server refuses to overwrite an active listening socket."""
    import socket

    import pytest

    repo_root = Path(__file__).resolve().parents[4]
    tmp_dir = repo_root / "tmp" / "test_active_sock"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    sock_path = tmp_dir / "active.sock"

    active_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        active_listener.bind(str(sock_path))
        active_listener.listen(1)

        mock_mcp = MagicMock()
        with pytest.raises(RuntimeError, match="actively listening"):
            run_socket_server(
                mcp_server=mock_mcp,
                socket_path=sock_path,
                api_key="",
                require_auth=False,
            )
    finally:
        active_listener.close()
        if sock_path.exists():
            sock_path.unlink()
        try:
            tmp_dir.rmdir()
        except OSError:
            pass


def test_run_socket_server_cleans_up_stale_socket_and_enforces_permissions():
    """Verify run_socket_server safely unlinks inactive stale socket and sets 0700 dir / 0600 socket."""
    import socket
    import stat

    repo_root = Path(__file__).resolve().parents[4]
    sock_dir = repo_root / "tmp" / "test_stale_sock"
    sock_path = sock_dir / "stale.sock"

    # Create a stale socket: bind then close socket without unlinking
    sock_dir.mkdir(parents=True, exist_ok=True)
    dummy = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dummy.bind(str(sock_path))
    dummy.close()
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

        async def mock_serve():
            # Simulate uvicorn binding socket
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(str(sock_path))
            import asyncio
            await asyncio.sleep(0.15)
            # Verify chmod 0600 has been applied
            sock_mode = stat.S_IMODE(sock_path.stat().st_mode)
            assert sock_mode == 0o600
            s.close()

        mock_server.serve = mock_serve
        mock_server.should_exit = False
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

            # Verify parent directory permission is 0700
            dir_mode = stat.S_IMODE(sock_dir.stat().st_mode)
            assert dir_mode == 0o700
        finally:
            if sock_path.exists():
                sock_path.unlink()
            try:
                sock_dir.rmdir()
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


def test_create_mcp_server_instructions_and_tools():
    """Verify create_mcp_server registers complete tool catalog and instructions."""
    from research_lab.agent_control.antigravity_mcp.server import create_mcp_server

    mcp = create_mcp_server()
    assert "Delegate one work block per task_id" in mcp.instructions
    assert "watch" in mcp.instructions
    assert "Antigravity-Manager" in mcp.instructions

    # Verify key tools are registered
    tool_names = set(mcp._tool_manager._tools.keys())
    expected_tools = {
        "list_accounts",
        "switch_account",
        "account_usage",
        "account_leaderboard",
        "tool_status",
        "projects",
        "submit",
        "message",
        "watch",
        "events",
        "wait",
        "status",
        "result",
        "cancel",
    }
    assert expected_tools.issubset(tool_names)


def test_cleanup_socket_preserves_new_instance_when_inode_changes():
    """Verify _cleanup_socket does not delete a new socket created by another process when inode changes."""
    import asyncio
    import socket

    repo_root = Path(__file__).resolve().parents[4]
    tmp_dir = repo_root / "tmp" / "test_inode_safety"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    sock_path = tmp_dir / "safety.sock"

    mock_mcp = MagicMock()
    mock_app = MagicMock()
    mock_mcp.sse_app.return_value = mock_app
    mock_mcp.settings.log_level = "info"

    with (
        patch("uvicorn.Server") as mock_server_cls,
        patch("uvicorn.Config"),
    ):
        mock_server = MagicMock()
        initial_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        async def mock_serve():
            initial_sock.bind(str(sock_path))
            await asyncio.sleep(0.15)
            # Socket bound and inode recorded
            initial_sock.close()

        mock_server.serve = mock_serve
        mock_server.should_exit = False
        mock_server_cls.return_value = mock_server

        try:
            with patch("atexit.register") as mock_atexit:
                run_socket_server(
                    mcp_server=mock_mcp,
                    socket_path=sock_path,
                    api_key="",
                    require_auth=False,
                )
                assert mock_atexit.called
                cleanup_fn = mock_atexit.call_args[0][0]

            # In normal flow, run_socket_server's finally called cleanup_fn on exit.
            # Now simulate: A NEW process comes in and creates a new socket at the same path!
            new_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            new_sock.bind(str(sock_path))

            # Simulate old process's cleanup_fn (e.g. from delayed atexit or concurrent thread)
            cleanup_fn()

            # The new socket must STILL exist because inode did not match!
            assert sock_path.exists()
            new_sock.close()
        finally:
            if sock_path.exists():
                sock_path.unlink()
            try:
                tmp_dir.rmdir()
            except OSError:
                pass
