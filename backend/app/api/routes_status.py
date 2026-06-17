from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.services.risk_service import risk_service
from app.services.vnpy_rpc_service import rpc_service

router = APIRouter()


@router.get("/status")
def status() -> dict:
    settings = get_settings()
    return ok({"app": settings.app_name, "env": settings.app_env, "status": "ok"})


@router.get("/rpc/status")
def rpc_status(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(rpc_service.status(probe=True))


@router.get("/gateway/status")
def gateway_status(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    rpc_status_data = rpc_service.status()
    return ok(
        {
            "gateway_name": rpc_status_data["gateway_name"],
            "rpc_connected": rpc_status_data["connected"],
            "status": "connected" if rpc_status_data["connected"] else "disconnected",
        }
    )


@router.get("/trade/config")
def trade_config(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    settings = get_settings()
    risk_status_data = risk_service.status()
    return ok(
        {
            "web_trade_enabled": risk_status_data["web_trade_enabled"],
            "default_gateway_name": settings.default_gateway_name,
            "order_confirm_required": settings.order_confirm_required,
            "trade_reference_prefix": settings.trade_reference_prefix,
            "emergency_stopped": risk_status_data["emergency_stopped"],
        }
    )
