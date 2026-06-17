from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.errors import AuthRequiredError, PermissionDeniedError
from app.core.security import decode_access_token
from app.services.vnpy_rpc_service import rpc_service
from app.ws.events import ws_message
from app.ws.manager import ws_manager

router = APIRouter()


@router.websocket("/ws/events")
async def events(websocket: WebSocket) -> None:
    token = websocket.query_params.get("token")
    try:
        if not token:
            authorization = websocket.headers.get("authorization", "")
            token = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""
        user = decode_access_token(token)
        if user.role not in {"viewer", "trader", "admin"}:
            raise PermissionDeniedError()
    except (AuthRequiredError, PermissionDeniedError):
        await websocket.close(code=1008)
        return

    await ws_manager.connect(websocket)
    await websocket.send_json(ws_message("gateway_status", rpc_service.status()))
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json(ws_message("pong", {}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
