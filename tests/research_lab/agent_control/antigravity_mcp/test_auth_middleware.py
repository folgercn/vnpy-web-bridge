"""Tests for ApiKeyAuthMiddleware ASGI interception."""
import asyncio
from research_lab.agent_control.antigravity_mcp.server import ApiKeyAuthMiddleware


def test_auth_middleware_disabled_allows_all():
    async def _run():
        received_scope = None

        async def mock_app(scope, receive, send):
            nonlocal received_scope
            received_scope = scope
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"OK"})

        mw = ApiKeyAuthMiddleware(mock_app, api_key="")

        sent_events = []

        async def send(event):
            sent_events.append(event)

        scope = {
            "type": "http",
            "headers": [],
            "query_string": b"",
        }
        await mw(scope, None, send)
        assert received_scope is not None
        assert sent_events[0]["status"] == 200

    asyncio.run(_run())


def test_auth_middleware_blocks_missing_or_invalid_key():
    async def _run():
        async def mock_app(scope, receive, send):
            pass

        mw = ApiKeyAuthMiddleware(mock_app, api_key="secret-token-123")

        sent_events = []

        async def send(event):
            sent_events.append(event)

        # 1. Missing key
        scope = {"type": "http", "headers": [], "query_string": b""}
        await mw(scope, None, send)
        assert sent_events[0]["status"] == 401

        # 2. Invalid key
        sent_events.clear()
        scope = {
            "type": "http",
            "headers": [(b"authorization", b"Bearer wrong-token")],
            "query_string": b"",
        }
        await mw(scope, None, send)
        assert sent_events[0]["status"] == 401

    asyncio.run(_run())


def test_auth_middleware_allows_valid_bearer_and_query_param():
    async def _run():
        async def mock_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"AUTHORIZED"})

        mw = ApiKeyAuthMiddleware(mock_app, api_key="secret-token-123")

        # 1. Valid Bearer Token
        sent_events = []

        async def send1(event):
            sent_events.append(event)

        scope1 = {
            "type": "http",
            "headers": [(b"authorization", b"Bearer secret-token-123")],
            "query_string": b"session_id=sess-abc",
        }
        await mw(scope1, None, send1)
        assert sent_events[0]["status"] == 200

        # 2. Re-using authenticated session_id without sending token again
        sent_events.clear()
        scope2 = {
            "type": "http",
            "headers": [],
            "query_string": b"session_id=sess-abc",
        }
        await mw(scope2, None, send1)
        assert sent_events[0]["status"] == 200

        # 3. Valid URL query param ?api_key=
        sent_events.clear()
        scope3 = {
            "type": "http",
            "headers": [],
            "query_string": b"api_key=secret-token-123",
        }
        await mw(scope3, None, send1)
        assert sent_events[0]["status"] == 200

    asyncio.run(_run())
