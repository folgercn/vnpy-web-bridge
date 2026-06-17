from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from app.core.errors import (
    AppError,
    RpcUnavailableError,
    StrategyInvalidSettingError,
    StrategyNotFoundError,
    StrategyOperationFailedError,
    StrategyRpcMethodNotAvailableError,
    TradeDisabledError,
)
from app.schemas.common import to_plain_dict, to_plain_list
from app.schemas.strategy import StrategySettingDTO
from app.services.audit_service import AuditService, audit_service
from app.services.risk_service import risk_service
from app.services.vnpy_rpc_service import rpc_service
from app.stores.memory_store import memory_store
from app.ws.events import ws_message
from app.ws.manager import ws_manager


class StrategyService:
    def __init__(self, audit: AuditService | None = None) -> None:
        self.audit = audit or audit_service

    def list_strategies(self) -> list[dict[str, Any]]:
        data = self._call_candidates(["get_all_strategy_status", "get_strategy_status", "get_all_strategies"])
        strategies = to_plain_list(data if isinstance(data, list) else data.values() if isinstance(data, dict) else [])
        return [self._normalize_summary(item) for item in strategies]

    def get_strategy(self, strategy_name: str) -> dict[str, Any]:
        strategy = self._find_strategy(strategy_name)
        strategy["setting"] = self.get_setting(strategy_name)
        strategy["variables"] = self.get_variables(strategy_name)
        return strategy

    def get_setting(self, strategy_name: str) -> dict[str, Any]:
        data = self._call_candidates(["get_strategy_parameters", "get_strategy_setting", "get_strategy_config"], strategy_name)
        return to_plain_dict(data)

    def get_variables(self, strategy_name: str) -> dict[str, Any]:
        data = self._call_candidates(["get_strategy_variables", "get_strategy_variable"], strategy_name)
        return to_plain_dict(data)

    async def init_strategy(self, strategy_name: str, *, user_id: str, role: str, source_ip: str | None = None) -> dict[str, Any]:
        return await self._operation("init", ["init_strategy", "init_cta_strategy"], strategy_name, user_id, role, source_ip)

    async def start_strategy(self, strategy_name: str, *, user_id: str, role: str, source_ip: str | None = None) -> dict[str, Any]:
        self._ensure_strategy_start_allowed()
        return await self._operation("start", ["start_strategy", "start_cta_strategy"], strategy_name, user_id, role, source_ip)

    async def stop_strategy(self, strategy_name: str, *, user_id: str, role: str, source_ip: str | None = None) -> dict[str, Any]:
        return await self._operation("stop", ["stop_strategy", "stop_cta_strategy"], strategy_name, user_id, role, source_ip)

    async def update_setting(
        self,
        strategy_name: str,
        payload: StrategySettingDTO,
        *,
        user_id: str,
        role: str,
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        if not payload.setting:
            raise StrategyInvalidSettingError("策略参数不能为空")
        self._find_strategy(strategy_name)
        request = {"strategy_name": strategy_name, "setting": payload.setting}
        self.audit.record(
            action="strategy_setting_update_request",
            user_id=user_id,
            role=role,
            request=request,
            source_ip=source_ip,
        )
        try:
            self._call_candidates(["edit_strategy", "update_strategy_setting", "set_strategy_setting"], strategy_name, payload.setting)
            setting = self.get_setting(strategy_name)
            result = {"strategy_name": strategy_name, "setting": setting}
            self.audit.record(
                action="strategy_setting_update_response",
                user_id=user_id,
                role=role,
                request=request,
                result=result,
                source_ip=source_ip,
            )
            await self._broadcast("strategy_status", {"strategy_name": strategy_name, "operation": "setting_update"})
            return result
        except AppError:
            raise
        except Exception as exc:
            raise StrategyOperationFailedError(detail={"strategy_name": strategy_name, "error": str(exc)}) from exc

    def get_logs(self, strategy_name: str) -> list[dict[str, Any]]:
        return memory_store.strategy_logs(strategy_name)

    async def append_log(self, strategy_name: str, message: str, level: str = "info") -> dict[str, Any]:
        payload = {
            "ts": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="milliseconds"),
            "strategy_name": strategy_name,
            "level": level,
            "message": message,
        }
        memory_store.save_strategy_log(payload)
        await self._broadcast("strategy_log", payload)
        return payload

    async def _operation(
        self,
        operation: str,
        methods: list[str],
        strategy_name: str,
        user_id: str,
        role: str,
        source_ip: str | None,
    ) -> dict[str, Any]:
        self._find_strategy(strategy_name)
        request = {"strategy_name": strategy_name, "operation": operation}
        self.audit.record(
            action=f"strategy_{operation}_request",
            user_id=user_id,
            role=role,
            request=request,
            source_ip=source_ip,
        )
        try:
            self._call_candidates(methods, strategy_name)
            result = {"strategy_name": strategy_name, "operation": operation, "accepted": True}
            self.audit.record(
                action=f"strategy_{operation}_response",
                user_id=user_id,
                role=role,
                request=request,
                result=result,
                source_ip=source_ip,
            )
            await self.append_log(strategy_name, f"strategy {operation} accepted")
            await self._broadcast("strategy_status", result)
            return result
        except AppError:
            raise
        except Exception as exc:
            raise StrategyOperationFailedError(detail={"strategy_name": strategy_name, "operation": operation, "error": str(exc)}) from exc

    def _find_strategy(self, strategy_name: str) -> dict[str, Any]:
        for strategy in self.list_strategies():
            if strategy.get("strategy_name") == strategy_name:
                return strategy
        raise StrategyNotFoundError(detail={"strategy_name": strategy_name})

    def _ensure_strategy_start_allowed(self) -> None:
        status = rpc_service.status()
        if not status.get("connected"):
            raise RpcUnavailableError()
        risk_status = risk_service.status()
        if not risk_status["web_trade_enabled"] or risk_status["emergency_stopped"]:
            raise TradeDisabledError("Web 风控未允许策略启动")

    def _call_candidates(self, methods: list[str], *args: Any) -> Any:
        errors: list[str] = []
        for method in methods:
            try:
                return rpc_service.call(method, *args)
            except AppError as exc:
                errors.append(f"{method}: {exc.code}")
                continue
            except Exception as exc:
                errors.append(f"{method}: {exc.__class__.__name__}")
                continue
        raise StrategyRpcMethodNotAvailableError(detail={"methods": methods, "errors": errors})

    def _normalize_summary(self, item: dict[str, Any]) -> dict[str, Any]:
        strategy_name = item.get("strategy_name") or item.get("name") or item.get("strategy")
        inited = bool(item.get("inited") or item.get("initialized"))
        trading = bool(item.get("trading") or item.get("running"))
        status = "running" if trading else "initializing" if inited and item.get("status") == "initializing" else "stopped"
        if str(item.get("status", "")).lower() in {"running", "stopped", "initializing", "error"}:
            status = str(item["status"]).lower()
        return {
            "strategy_name": strategy_name,
            "class_name": item.get("class_name"),
            "vt_symbol": item.get("vt_symbol"),
            "status": status,
            "inited": inited,
            "trading": trading,
        }

    async def _broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        await ws_manager.broadcast(ws_message(event_type, data))


strategy_service = StrategyService()
