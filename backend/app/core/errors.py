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
    code = "RPC_ERROR"
    message = "RPC 调用失败"


class TradeDisabledError(AppError):
    status_code = 403
    code = "TRADE_DISABLED"
    message = "Web 交易开关关闭"


class OrderConfirmRequiredError(AppError):
    status_code = 400
    code = "ORDER_CONFIRM_REQUIRED"
    message = "下单需要二次确认"


class InvalidOrderRequestError(AppError):
    status_code = 400
    code = "INVALID_ORDER_REQUEST"
    message = "下单参数非法"


class OrderNotFoundError(AppError):
    status_code = 404
    code = "ORDER_NOT_FOUND"
    message = "委托不存在"


class OrderNotCancelableError(AppError):
    status_code = 409
    code = "ORDER_NOT_CANCELABLE"
    message = "委托当前状态不可撤"


class AuthRequiredError(AppError):
    status_code = 401
    code = "AUTH_REQUIRED"
    message = "未登录"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "PERMISSION_DENIED"
    message = "权限不足"


class RiskSymbolBlockedError(AppError):
    status_code = 400
    code = "RISK_SYMBOL_BLOCKED"
    message = "合约被禁止"


class RiskExchangeNotAllowedError(AppError):
    status_code = 400
    code = "RISK_EXCHANGE_NOT_ALLOWED"
    message = "交易所不允许"


class RiskMaxOrderVolumeError(AppError):
    status_code = 400
    code = "RISK_MAX_ORDER_VOLUME"
    message = "超过单笔手数限制"


class RiskMaxSymbolPositionError(AppError):
    status_code = 400
    code = "RISK_MAX_SYMBOL_POSITION"
    message = "超过单合约持仓限制"


class RiskPriceProtectionError(AppError):
    status_code = 400
    code = "RISK_PRICE_PROTECTION"
    message = "超过价格保护范围"


class RiskDailyLossLimitError(AppError):
    status_code = 400
    code = "RISK_DAILY_LOSS_LIMIT"
    message = "超过每日亏损限制"


class RiskTradingTimeError(AppError):
    status_code = 400
    code = "RISK_TRADING_TIME"
    message = "非允许交易时间"


class StrategyNotFoundError(AppError):
    status_code = 404
    code = "STRATEGY_NOT_FOUND"
    message = "策略不存在"


class StrategyRpcMethodNotAvailableError(AppError):
    status_code = 501
    code = "STRATEGY_RPC_METHOD_NOT_AVAILABLE"
    message = "Windows 侧 RPC 未暴露策略方法"


class StrategyInvalidSettingError(AppError):
    status_code = 400
    code = "STRATEGY_INVALID_SETTING"
    message = "策略参数非法"


class StrategyOperationFailedError(AppError):
    status_code = 502
    code = "STRATEGY_OPERATION_FAILED"
    message = "策略操作失败"


class StrategyNotInitializedError(AppError):
    status_code = 409
    code = "STRATEGY_NOT_INITIALIZED"
    message = "策略未初始化"


class StrategyAlreadyRunningError(AppError):
    status_code = 409
    code = "STRATEGY_ALREADY_RUNNING"
    message = "策略已运行"


class StrategyNotRunningError(AppError):
    status_code = 409
    code = "STRATEGY_NOT_RUNNING"
    message = "策略未运行"


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
