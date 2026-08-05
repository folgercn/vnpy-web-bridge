"""Phase A Control API process entrypoint.

The module is intentionally a small FastAPI application.  It owns
authentication, typed command issuance, and read-only Execution projections;
all execution/RPC lifecycle and mutation code runs in the separate
``execution-orchestrator`` process.
"""

from __future__ import annotations

import json
import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app.api import routes_auth
from app.api.routes_control_execution import router as control_execution_router
from app.api.routes_control_safe import router as control_safe_router
from app.core.config import get_settings
from app.core.errors import (
    AppError,
    app_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from app.core.logging import configure_logging

SERVICE_VERSION = os.getenv("CONTROL_API_VERSION", "phase-a-dev")


def _require_runtime_auth_configuration() -> None:
    """Reject insecure authentication defaults outside local/test processes."""

    runtime = os.getenv("APP_ENV", "development").strip().lower()
    if runtime in {"test", "development", "local"}:
        return
    secret = os.getenv("JWT_SECRET_KEY", "").strip()
    execution_secret = os.getenv("CONTROL_EXECUTION_SHARED_SECRET", "").strip()
    users_raw = os.getenv("AUTH_USERS_JSON", "").strip()
    if not secret or secret == "change-me-in-production" or len(secret) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY must be a non-default secret of at least 32 characters"
        )
    if not execution_secret or len(execution_secret) < 32:
        raise RuntimeError(
            "CONTROL_EXECUTION_SHARED_SECRET must be supplied for the private boundary"
        )
    try:
        users = json.loads(users_raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "AUTH_USERS_JSON must be valid JSON in non-test environments"
        ) from exc
    if not isinstance(users, list) or not users:
        raise RuntimeError("AUTH_USERS_JSON must contain at least one configured user")
    for user in users:
        if not isinstance(user, dict) or not user.get("username"):
            raise RuntimeError("AUTH_USERS_JSON contains an invalid user")
        if not (user.get("password_hash") or user.get("password_sha256")):
            raise RuntimeError("AUTH_USERS_JSON users require password_hash")


_require_runtime_auth_configuration()

# Logging configuration is side-effect free and does not start a worker. Invalid
# runtime configuration must fail closed instead of silently disabling logging.
configure_logging(get_settings())


app = FastAPI(
    title="VnPy Web Bridge Control API",
    version=SERVICE_VERSION,
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CONTROL_API_CORS_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080"
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Correlation-ID", "X-Request-ID"],
)
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(Exception, unhandled_error_handler)

app.add_exception_handler(RequestValidationError, validation_error_handler)


@app.middleware("http")
async def add_correlation_header(request: Request, call_next):
    response = await call_next(request)
    correlation_id = request.headers.get("X-Correlation-ID")
    if correlation_id:
        response.headers["X-Correlation-ID"] = correlation_id
    return response


app.include_router(routes_auth.router, prefix="/api")
app.include_router(control_execution_router)
app.include_router(control_safe_router)


__all__ = ["app"]
