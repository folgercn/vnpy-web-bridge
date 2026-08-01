from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from threading import RLock
from typing import Any, Callable

from app.core.config import Settings, get_settings
from app.core.errors import AppError, InvalidOrderRequestError, OrderNotCancelableError, OrderNotFoundError
from app.schemas.common import STATUS_VALUE_MAP, to_plain_dict
from app.schemas.trade import CancelAllRequestDTO, CancelRequestDTO, OrderRequestDTO
from app.services.audit_service import AuditService, audit_service
from app.services.monitoring_service import monitoring_service
from app.services.risk_service import RiskService, risk_service
from app.services.vnpy_rpc_service import VnpyRpcService, rpc_service

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

_C_FAST_CAPABILITY_CONSTRUCTION_KEY = object()


class _CFastOrderVolumeCapability:
    """Opaque process-local authority for the C_FAST child-order lane."""

    __slots__ = ("owner",)

    def __init__(self, owner: object, *, construction_key: object) -> None:
        if construction_key is not _C_FAST_CAPABILITY_CONSTRUCTION_KEY:
            raise TypeError("C_FAST order-volume capability cannot be constructed")
        self.owner = owner


class TradeService:
    def __init__(
        self,
        settings: Settings | None = None,
        audit: AuditService | None = None,
        risk: RiskService | None = None,
        rpc: VnpyRpcService | None = None,
        _c_fast_capability_issuers: tuple[object, ...] = (),
    ) -> None:
        self.settings = settings or get_settings()
        self.audit = audit or audit_service
        self.risk = risk or risk_service
        self.rpc = rpc or rpc_service
        self._c_fast_capability_lock = RLock()
        self._c_fast_capability_issuers = tuple(
            _c_fast_capability_issuers
        )
        self._c_fast_order_volume_capabilities: set[
            _CFastOrderVolumeCapability
        ] = set()

    def _bind_c_fast_order_volume_capability(
        self,
        owner: object,
    ) -> _CFastOrderVolumeCapability:
        """Bind an opaque capability to an exact CommoditySimNow owner."""

        # Import lazily to avoid the module cycle at import time.  An exact
        # type check prevents callers from spoofing the owner with a subclass
        # or a same-named object.
        from app.services.commodity_simnow import (
            CommoditySimNowService,
            commodity_simnow_service,
        )

        if (
            type(owner) is not CommoditySimNowService
            or getattr(owner, "trade", None) is not self
            or (
                owner is not commodity_simnow_service
                and not any(
                    owner is issuer
                    for issuer in self._c_fast_capability_issuers
                )
            )
        ):
            raise TypeError("C_FAST capability owner is invalid")
        capability = _CFastOrderVolumeCapability(
            owner,
            construction_key=_C_FAST_CAPABILITY_CONSTRUCTION_KEY,
        )
        with self._c_fast_capability_lock:
            self._c_fast_order_volume_capabilities.add(capability)
        return capability

    def _is_c_fast_order_volume_capability(
        self, capability: object, owner: object
    ) -> bool:
        with self._c_fast_capability_lock:
            return bool(
                type(capability) is _CFastOrderVolumeCapability
                and capability
                in self._c_fast_order_volume_capabilities
                and capability.owner is owner
            )

    def _validate_c_fast_send_contract(
        self,
        payload: OrderRequestDTO,
        *,
        owner: object,
        capability: object,
        pre_rpc_guard: Callable[[], Any],
        send_linearization_lock: Any,
    ) -> None:
        from app.services.commodity_simnow import (
            CommoditySimNowService,
            commodity_simnow_service,
        )

        owner_allowed = bool(
            type(owner) is CommoditySimNowService
            and getattr(owner, "trade", None) is self
            and (
                owner is commodity_simnow_service
                or any(
                    owner is issuer
                    for issuer in self._c_fast_capability_issuers
                )
            )
        )
        if (
            not owner_allowed
            or not self._is_c_fast_order_volume_capability(
                capability, owner
            )
        ):
            raise RuntimeError("C_FAST order-volume capability is invalid")
        if (
            getattr(pre_rpc_guard, "__self__", None) is not owner
            or getattr(pre_rpc_guard, "__func__", None)
            is not CommoditySimNowService._c_fast_pre_rpc_guard
            or send_linearization_lock
            is not getattr(owner, "_dispatch_abort_lock", None)
            or not str(payload.reference or "").startswith(
                "commodity_cf:sh:"
            )
        ):
            raise RuntimeError("C_FAST guarded-send contract is invalid")

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
        pre_rpc_guard: Callable[[], Any] | None = None,
        send_linearization_lock: Any | None = None,
    ) -> dict[str, Any]:
        return self._send_order(
            payload,
            source_ip=source_ip,
            operator=operator,
            pre_rpc_guard=pre_rpc_guard,
            send_linearization_lock=send_linearization_lock,
            c_fast_order_owner=None,
            c_fast_order_volume_capability=None,
        )

    def _send_c_fast_order(
        self,
        payload: OrderRequestDTO,
        *,
        c_fast_order_owner: object,
        c_fast_order_volume_capability: object,
        source_ip: str | None = None,
        operator: str = "anonymous",
        pre_rpc_guard: Callable[[], Any],
        send_linearization_lock: Any,
    ) -> dict[str, Any]:
        """Send one C_FAST SimNow child through the capability-only lane."""

        self._validate_c_fast_send_contract(
            payload,
            owner=c_fast_order_owner,
            capability=c_fast_order_volume_capability,
            pre_rpc_guard=pre_rpc_guard,
            send_linearization_lock=send_linearization_lock,
        )
        return self._send_order(
            payload,
            source_ip=source_ip,
            operator=operator,
            pre_rpc_guard=pre_rpc_guard,
            send_linearization_lock=send_linearization_lock,
            c_fast_order_owner=c_fast_order_owner,
            c_fast_order_volume_capability=c_fast_order_volume_capability,
        )

    def _send_order(
        self,
        payload: OrderRequestDTO,
        *,
        source_ip: str | None,
        operator: str,
        pre_rpc_guard: Callable[[], Any] | None,
        send_linearization_lock: Any | None,
        c_fast_order_owner: object | None,
        c_fast_order_volume_capability: object | None,
    ) -> dict[str, Any]:
        request_data = payload.model_dump()
        self.audit.record(action="order_request", request=request_data, operator=operator, source_ip=source_ip)
        try:
            if c_fast_order_volume_capability is None:
                self.risk.check_order(payload)
            elif (
                c_fast_order_owner is not None
                and pre_rpc_guard is not None
            ):
                self._validate_c_fast_send_contract(
                    payload,
                    owner=c_fast_order_owner,
                    capability=c_fast_order_volume_capability,
                    pre_rpc_guard=pre_rpc_guard,
                    send_linearization_lock=send_linearization_lock,
                )
                self.risk._check_c_fast_order(payload)
            else:
                raise RuntimeError(
                    "C_FAST order-volume capability is invalid"
                )
            order_request = self.to_vnpy_order_request(payload)
            gateway_name = payload.gateway_name or self.settings.default_gateway_name
            if pre_rpc_guard is None:
                vt_orderid = self.rpc.send_order(
                    order_request, gateway_name
                )
            else:
                guarded_send = getattr(
                    self.rpc, "send_order_guarded", None
                )
                if not callable(guarded_send):
                    raise RuntimeError(
                        "guarded non-idempotent RPC unavailable"
                    )
                vt_orderid = guarded_send(
                    order_request,
                    gateway_name,
                    pre_rpc_guard,
                    linearization_lock=send_linearization_lock,
                )
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
        bypass_trade_check: bool = False,
    ) -> dict[str, Any]:
        payload = payload or CancelRequestDTO()
        request_data = {"vt_orderid": vt_orderid, **payload.model_dump()}
        self.audit.record(action="cancel_request", request=request_data, operator=operator, source_ip=source_ip)
        try:
            if not bypass_trade_check:
                self.risk.check_trade_allowed(confirm=True)
            order = self.rpc.get_order_raw(vt_orderid)
            if not order:
                raise OrderNotFoundError(detail={"vt_orderid": vt_orderid})

            status = normalize_status(getattr(order, "status", None))
            if not is_cancelable_status(status):
                raise OrderNotCancelableError(detail={"vt_orderid": vt_orderid, "status": status})

            cancel_request = order.create_cancel_request()
            gateway_name = payload.gateway_name or getattr(order, "gateway_name", None) or self.settings.default_gateway_name
            self.rpc.cancel_order(cancel_request, gateway_name)
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
        orders = [order for order in self.rpc.get_active_orders_raw() if self._matches_filter(order, payload)]
        items: list[dict[str, Any]] = []

        for order in orders:
            vt_orderid = getattr(order, "vt_orderid", None) or getattr(order, "orderid", None)
            try:
                status = normalize_status(getattr(order, "status", None))
                if not is_cancelable_status(status):
                    raise OrderNotCancelableError(detail={"vt_orderid": vt_orderid, "status": status})
                cancel_request = order.create_cancel_request()
                gateway_name = payload.gateway_name or getattr(order, "gateway_name", None) or self.settings.default_gateway_name
                self.rpc.cancel_order(cancel_request, gateway_name)
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
