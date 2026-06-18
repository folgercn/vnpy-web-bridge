from __future__ import annotations

import asyncio

from fastapi import WebSocketDisconnect

from app.ws.manager import WebSocketManager


class BrokenWebSocket:
    async def accept(self) -> None:
        return None

    async def send_json(self, message: dict) -> None:
        raise WebSocketDisconnect(code=1006)


class HealthyWebSocket:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def accept(self) -> None:
        return None

    async def send_json(self, message: dict) -> None:
        self.messages.append(message)


def test_broadcast_removes_disconnected_websockets() -> None:
    async def run() -> None:
        manager = WebSocketManager()
        broken = BrokenWebSocket()
        healthy = HealthyWebSocket()

        await manager.connect(broken)  # type: ignore[arg-type]
        await manager.connect(healthy)  # type: ignore[arg-type]
        await manager.broadcast({"type": "test"})

        assert healthy.messages == [{"type": "test"}]
        assert broken not in manager._connections
        assert healthy in manager._connections

    asyncio.run(run())
