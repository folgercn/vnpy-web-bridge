from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from app.api import routes_account, routes_auth, routes_market, routes_risk, routes_status, routes_trade, routes_ws
from app.core.config import get_settings
from app.core.errors import AppError, app_error_handler, unhandled_error_handler, validation_error_handler
from app.core.logging import configure_logging
from app.services.vnpy_rpc_service import rpc_service

settings = get_settings()
configure_logging(settings)
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.app_name)
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(RequestValidationError, validation_error_handler)
app.add_exception_handler(Exception, unhandled_error_handler)

app.include_router(routes_status.router, prefix="/api")
app.include_router(routes_auth.router, prefix="/api")
app.include_router(routes_market.router, prefix="/api")
app.include_router(routes_account.router, prefix="/api")
app.include_router(routes_trade.router, prefix="/api")
app.include_router(routes_risk.router, prefix="/api")
app.include_router(routes_ws.router)


@app.on_event("startup")
async def startup() -> None:
    rpc_service.bind_loop(asyncio.get_running_loop())
    try:
        rpc_service.start()
    except AppError as exc:
        logger.warning("backend started without RPC connection: %s", exc.message)


@app.on_event("shutdown")
async def shutdown() -> None:
    rpc_service.stop()
