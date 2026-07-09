from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

from app.core.config import Settings, get_settings
from app.core.errors import AppError, InvalidOrderRequestError, OrderNotCancelableError, OrderNotFoundError
from app.schemas.common import STATUS_VALUE_MAP, to_plain_dict
from app.schemas.trade import CancelAllRequestDTO, CancelRequestDTO, OrderRequestDTO
from app.services.audit_service import AuditService, audit_service
from app.services.monitoring_service import monitoring_service
from app.services.risk_service import RiskService, risk_service
from app.services.vnpy_rpc_service import rpc_service

try:
    from vnpy.trader.constant import Direction, Exchange, Offset, OrderType, Status
    from vnpy.trader.object import OrderRequest
except ImportError:  # pragma: no cover
    Direction = Exchange = Offset = OrderType = Status = None  # type: ignore[assignment]
    OrderRequest = None  # type: ignore[assignment]


DIRECTION_MAP = {
    "long": "LONG",
    "short": "SHORT",
}

OFFSET_MAP = {
    "open": "OPEN",
    "close": "CLOSE",
    "closetoday": "CLOSETODAY",
    "closeyesterday": "CLOSEYESTERDAY",
}

ORDER_TYPE_MAP = {
    "limit": "LIMIT",
}

CANCELABLE_STATUSES = {"submitting", "not_traded", "part_traded"}


class TradeService:
    def __init__(
        self,
        settings: Settings | None = None,
        audit: AuditService | None = None,
        risk: RiskService | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.audit = audit or audit_service
        self.risk = risk or risk_service

    def config_status(self) -> dict[str, Any]:
        return {
            "web_trade_enabled": self.settings.web_trade_enabled,
            "default_gateway_name": self.settings.default_gateway_name,
            "order_confirm_required": self.settings.order_confirm_required,
            "trade_reference_prefix": self.settings.trade_reference_prefix,
        }

    def send_order(
        self,
        payload: OrderRequestDTO,
        *,
        source_ip: str | None = None,
        operator: str = "anonymous",
    ) -> dict[str, Any]:
        request_data = payload.model_dump()
        self.audit.record(action="order_request", request=request_data, operator=operator, source_ip=source_ip)
        try:
            self.risk.check_order(payload)
            order_request = self.to_vnpy_order_request(payload)
            gateway_name = payload.gateway_name or self.settings.default_gateway_name
            vt_orderid = rpc_service.send_order(order_request, gateway_name)
            result = {"vt_orderid": vt_orderid, "accepted": True}
            self.audit.record(
                action="order_response",
                request=request_data,
                result=result,
                operator=operator,
                source_ip=source_ip,
            )
            return result
        except Exception as exc:
            if isinstance(exc, AppError) and exc.code.startswith("RISK_"):
                self.audit.record(
                    action="risk_reject",
                    request=request_data,
                    error_code=exc.code,
                    error_message=exc.message,
                    operator=operator,
                    source_ip=source_ip,
                )
            self.audit.record(
                action="order_failed",
                request=request_data,
                error=str(exc),
                error_code=getattr(exc, "code", None),
                error_message=getattr(exc, "message", str(exc)),
                operator=operator,
                source_ip=source_ip,
            )
            monitoring_service.record_trade_failure("order", str(getattr(exc, "code", exc.__class__.__name__)))
            raise

    def cancel_order(
        self,
        vt_orderid: str,
        payload: CancelRequestDTO | None = None,
        *,
        source_ip: str | None = None,
        operator: str = "anonymous",
    ) -> dict[str, Any]:
        payload = payload or CancelRequestDTO()
        request_data = {"vt_orderid": vt_orderid, **payload.model_dump()}
        self.audit.record(action="cancel_request", request=request_data, operator=operator, source_ip=source_ip)
        try:
            self.risk.check_trade_allowed(confirm=True)
            order = rpc_service.get_order_raw(vt_orderid)
            if not order:
                raise OrderNotFoundError(detail={"vt_orderid": vt_orderid})

            status = normalize_status(getattr(order, "status", None))
            if not is_cancelable_status(status):
                raise OrderNotCancelableError(detail={"vt_orderid": vt_orderid, "status": status})

            cancel_request = order.create_cancel_request()
            gateway_name = payload.gateway_name or getattr(order, "gateway_name", None) or self.settings.default_gateway_name
            rpc_service.cancel_order(cancel_request, gateway_name)
            result = {"vt_orderid": vt_orderid, "cancel_requested": True, "status": status}
            self.audit.record(
                action="cancel_response",
                request=request_data,
                result=result,
                operator=operator,
                source_ip=source_ip,
            )
            return result
        except Exception as exc:
            self.audit.record(
                action="cancel_failed",
                request=request_data,
                error=str(exc),
                error_code=getattr(exc, "code", None),
                error_message=getattr(exc, "message", str(exc)),
                operator=operator,
                source_ip=source_ip,
            )
            monitoring_service.record_trade_failure("cancel", str(getattr(exc, "code", exc.__class__.__name__)))
            raise

    def cancel_all(
        self,
        payload: CancelAllRequestDTO,
        *,
        source_ip: str | None = None,
        operator: str = "anonymous",
        bypass_trade_check: bool = False,
    ) -> dict[str, Any]:
        request_data = payload.model_dump()
        self.audit.record(action="cancel_all_request", request=request_data, operator=operator, source_ip=source_ip)
        if not bypass_trade_check:
            self.risk.check_trade_allowed(confirm=True)
        orders = [order for order in rpc_service.get_active_orders_raw() if self._matches_filter(order, payload)]
        items: list[dict[str, Any]] = []

        for order in orders:
            vt_orderid = getattr(order, "vt_orderid", None) or getattr(order, "orderid", None)
            try:
                status = normalize_status(getattr(order, "status", None))
                if not is_cancelable_status(status):
                    raise OrderNotCancelableError(detail={"vt_orderid": vt_orderid, "status": status})
                cancel_request = order.create_cancel_request()
                gateway_name = payload.gateway_name or getattr(order, "gateway_name", None) or self.settings.default_gateway_name
                rpc_service.cancel_order(cancel_request, gateway_name)
                items.append({"vt_orderid": vt_orderid, "cancel_requested": True, "error": None})
            except Exception as exc:
                items.append({"vt_orderid": vt_orderid, "cancel_requested": False, "error": str(exc)})
                monitoring_service.record_trade_failure("cancel_all", str(getattr(exc, "code", exc.__class__.__name__)))

        result = {
            "requested": len(items),
            "success": sum(1 for item in items if item["cancel_requested"]),
            "failed": sum(1 for item in items if not item["cancel_requested"]),
            "items": items,
        }
        self.audit.record(
            action="cancel_all_response",
            request=request_data,
            result=result,
            operator=operator,
            source_ip=source_ip,
        )
        return result

    def to_vnpy_order_request(self, payload: OrderRequestDTO) -> Any:
        if OrderRequest is None:
            raise InvalidOrderRequestError("vn.py 未安装")

        try:
            exchange = Exchange(payload.exchange)  # type: ignore[operator]
        except ValueError:
            try:
                exchange = Exchange[payload.exchange]  # type: ignore[index]
            except KeyError as exc:
                raise InvalidOrderRequestError("交易所代码无效", detail={"exchange": payload.exchange}) from exc

        reference = payload.reference or self.make_reference()
        return OrderRequest(
            symbol=payload.symbol,
            exchange=exchange,
            direction=Direction[DIRECTION_MAP[payload.direction]],  # type: ignore[index]
            offset=Offset[OFFSET_MAP[payload.offset]],  # type: ignore[index]
            type=OrderType[ORDER_TYPE_MAP[payload.type]],  # type: ignore[index]
            price=payload.price,
            volume=payload.volume,
            reference=reference,
        )

    def make_reference(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        return f"{self.settings.trade_reference_prefix}_{timestamp}"

    def _matches_filter(self, order: Any, payload: CancelAllRequestDTO) -> bool:
        order_data = to_plain_dict(order)
        if payload.symbol and order_data.get("symbol") != payload.symbol:
            return False
        if payload.exchange and order_data.get("exchange") != payload.exchange:
            return False
        if payload.gateway_name and order_data.get("gateway_name") != payload.gateway_name:
            return False
        return True


def normalize_status(status: Any) -> str:
    if status is None:
        return "unknown"
    raw = getattr(status, "value", status)
    raw_text = str(raw)
    mapped = STATUS_VALUE_MAP.get(raw_text)
    if mapped:
        return mapped
    return raw_text.strip().lower().replace(" ", "_").replace("-", "_")


def is_cancelable_status(status: Any) -> bool:
    return normalize_status(status) in CANCELABLE_STATUSES


def order_to_dict(order: Any) -> dict[str, Any]:
    if is_dataclass(order):
        return asdict(order)
    return getattr(order, "__dict__", {"value": order})


trade_service = TradeService()
