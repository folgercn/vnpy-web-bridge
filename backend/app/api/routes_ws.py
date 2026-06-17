from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.vnpy_rpc_service import rpc_service
from app.ws.events import ws_message
from app.ws.manager import ws_manager

router = APIRouter()


@router.websocket("/ws/events")
async def events(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    await websocket.send_json(ws_message("gateway_status", rpc_service.status()))
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json(ws_message("pong", {}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
