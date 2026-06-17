from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class AppError(Exception):
    status_code = 500
    code = "INTERNAL_ERROR"
    message = "服务内部错误"

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.status_code = status_code or self.status_code
        self.detail = detail or {}
        super().__init__(self.message)


class RpcUnavailableError(AppError):
    status_code = 503
    code = "RPC_UNAVAILABLE"
    message = "RPC 未连接"


class RpcTimeoutError(AppError):
    status_code = 504
    code = "RPC_TIMEOUT"
    message = "RPC 调用超时"


class RpcCallError(AppError):
    status_code = 502
    code = "RPC_CALL_FAILED"
    message = "RPC 调用失败"


def ok(data: Any = None) -> dict[str, Any]:
    return {"ok": True, "data": data if data is not None else {}}


def error_payload(exc: AppError) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": exc.code,
            "message": exc.message,
            "detail": exc.detail,
        },
    }


async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=error_payload(exc))


async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    app_error = AppError(
        "请求参数错误",
        code="VALIDATION_ERROR",
        status_code=422,
        detail={"errors": exc.errors()},
    )
    return JSONResponse(status_code=422, content=error_payload(app_error))


async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    app_error = AppError(detail={"type": exc.__class__.__name__})
    return JSONResponse(status_code=500, content=error_payload(app_error))
