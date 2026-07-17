from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import math
import re
from datetime import date, datetime, timezone
from functools import wraps
from pathlib import Path
from threading import RLock
from typing import Any, Callable
from zoneinfo import ZoneInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.config import Settings, get_settings
from app.core.errors import (
    CommoditySimNowBatchError,
    CommoditySimNowDisabledError,
    CommoditySimNowSafetyError,
    CommoditySimNowStateError,
)
from app.schemas.commodity_simnow import (
    CommodityPlanExecuteRequestDTO,
    CommoditySimNowDisableRequestDTO,
    CommoditySimNowEnableRequestDTO,
    CommodityTemplateStartRequestDTO,
    CommodityTargetBatchDTO,
)
from app.schemas.common import STATUS_VALUE_MAP
from app.schemas.trade import OrderRequestDTO
from app.services.audit_service import AuditService, audit_service
from app.services.risk_service import RiskService, risk_service
from app.services.trade_service import TradeService, trade_service
from app.services.vnpy_rpc_service import VnpyRpcService, rpc_service
from app.stores.memory_store import memory_store

logger = logging.getLogger(__name__)
CHINA_TZ = ZoneInfo("Asia/Shanghai")
REFERENCE_PREFIX = "commodity_static_core"
ACTIVE_ORDER_STATUSES = {"submitting", "not_traded", "part_traded", "submitting_order"}

PRODUCT_SPECS: dict[str, dict[str, Any]] = {
    "ag": {"exchange": "SHFE", "sector": "precious", "multiplier": 15, "price_tick": 1.0},
    "al": {"exchange": "SHFE", "sector": "nonferrous", "multiplier": 5, "price_tick": 5.0},
    "au": {"exchange": "SHFE", "sector": "precious", "multiplier": 1000, "price_tick": 0.02},
    "bu": {"exchange": "SHFE", "sector": "energy", "multiplier": 10, "price_tick": 1.0},
    "cu": {"exchange": "SHFE", "sector": "nonferrous", "multiplier": 5, "price_tick": 10.0},
    "rb": {"exchange": "SHFE", "sector": "ferrous", "multiplier": 10, "price_tick": 1.0},
    "ru": {"exchange": "SHFE", "sector": "chemicals", "multiplier": 10, "price_tick": 5.0},
    "sc": {"exchange": "INE", "sector": "energy", "multiplier": 1000, "price_tick": 0.1},
    "sp": {"exchange": "SHFE", "sector": "agriculture", "multiplier": 10, "price_tick": 2.0},
    "zn": {"exchange": "SHFE", "sector": "nonferrous", "multiplier": 5, "price_tick": 5.0},
}


def _serialized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._cycle_lock:
            return method(self, *args, **kwargs)

    return wrapped


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _normalize_direction(value: Any) -> str:
    raw = _value(value).strip().lower()
    return {"多": "long", "空": "short", "long": "long", "short": "short"}.get(raw, raw)


def _normalize_status(value: Any) -> str:
    raw = _value(value).strip()
    return STATUS_VALUE_MAP.get(raw, raw.lower().replace(" ", "_").replace("-", "_"))


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            result = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=CHINA_TZ)
    return result.astimezone(timezone.utc)


def _csv_set(value: str) -> set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _exact_to_vt(exact_contract: str) -> str:
    exchange, symbol = exact_contract.split(".", 1)
    return f"{symbol}.{exchange}"


def _split_vt(vt_symbol: str) -> tuple[str, str]:
    symbol, exchange = vt_symbol.rsplit(".", 1)
    return symbol, exchange


def _product_from_symbol(symbol: str) -> str:
    match = re.match(r"^([A-Za-z]+)\d{4}$", symbol)
    return match.group(1).lower() if match else ""


def _delivery_year_month(exact_contract: str) -> tuple[int, int]:
    match = re.fullmatch(r"[A-Z]+\.[A-Za-z]+(\d{2})(\d{2})", exact_contract)
    if not match:
        raise ValueError("exact contract has no four-digit delivery month")
    year = 2000 + int(match.group(1))
    month = int(match.group(2))
    if not 1 <= month <= 12:
        raise ValueError("invalid delivery month")
    return year, month


def _round_price(price: float, tick: float) -> float:
    decimals = max(0, len(f"{tick:.10f}".rstrip("0").split(".")[1]) if "." in f"{tick:.10f}".rstrip("0") else 0)
    return round(round(price / tick) * tick, decimals)


class CommoditySimNowService:
    mode = "SIMNOW_AUTO_TWO_PHASE"
    scheduler_id = "STATIC_CORE_EQUAL"
    source_combination_arm = "CORE_EQUAL_TARGET"
    production_allowed = False
    virtual_nav_cny = 20_000_000

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        rpc: VnpyRpcService | None = None,
        trade: TradeService | None = None,
        risk: RiskService | None = None,
        audit: AuditService | None = None,
        tick_store: Any | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.rpc = rpc or rpc_service
        self.trade = trade or trade_service
        self.risk = risk or risk_service
        self.audit = audit or audit_service
        self.tick_store = tick_store or memory_store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.enabled = False
        self.manual_approval = False
        self.simnow_mode = False
        self.auto_dispatch_authorized = False
        self.template_authorized = False
        self.order_endpoint_touched = False
        self.current_plan: dict[str, Any] | None = None
        self.events: list[dict[str, Any]] = []
        self._cycle_lock = RLock()
        self._task: asyncio.Task[Any] | None = None
        self._state_load_error: str | None = None
        self._completed_state = self._load_completed_state()

    @_serialized
    def status(self) -> dict[str, Any]:
        auto_dispatch_allowed = self._auto_dispatch_allowed()
        worker_alive = bool(self._task and not self._task.done())
        template_path = self.settings.commodity_simnow_template_batch_path.strip()
        return {
            "mode": self.mode,
            "scheduler_id": self.scheduler_id,
            "source_combination_arm": self.source_combination_arm,
            "configured": self.settings.commodity_simnow_enabled,
            "enabled": self.enabled,
            "manual_approval": self.manual_approval,
            "simnow_mode": self.simnow_mode,
            "production_allowed": self.production_allowed,
            "auto_dispatch_configured": self.settings.commodity_simnow_auto_dispatch_enabled,
            "auto_dispatch_allowed": auto_dispatch_allowed,
            "auto_dispatch_active": auto_dispatch_allowed and worker_alive,
            "auto_dispatch_worker_alive": worker_alive,
            "auto_dispatch_interval_seconds": self.settings.commodity_simnow_auto_dispatch_interval_seconds,
            "auto_dispatch_reconcile_grace_seconds": (
                self.settings.commodity_simnow_auto_dispatch_reconcile_grace_seconds
            ),
            "strategy_template": {
                "template_id": "STATIC_CORE_EQUAL_AUTO_V1",
                "configured": bool(template_path and Path(template_path).expanduser().is_file()),
                "authorized": self.template_authorized,
                "products": sorted(PRODUCT_SPECS),
                "rebalance_cycle": "monthly",
                "contract_selection": "PIT_OI_MAIN_FROM_SIGNED_TARGET",
                "target_source": "SIGNED_FROZEN_RESEARCH_PIPELINE",
                "roll_policy": "SIGNED_MAIN_CHANGE_CLOSE_RECONCILE_OPEN",
                "delivery_month_cutoff_day": self.settings.commodity_simnow_delivery_month_cutoff_day,
                "sc_pre_delivery_cutoff_day": (self.settings.commodity_simnow_sc_pre_delivery_cutoff_day),
                "manual_product_selection": False,
                "manual_cycle_selection": False,
                "manual_contract_selection": False,
            },
            "order_endpoint_touched": self.order_endpoint_touched,
            "plan_status": self.current_plan.get("status") if self.current_plan else "IDLE",
            "plan_hash": self.current_plan.get("plan_hash") if self.current_plan else None,
            "last_completed_batch_hash": self._completed_state.get("last_completed_batch_hash"),
            "state_load_error": self._state_load_error,
            "max_child_order_lots": self.settings.commodity_simnow_max_child_order_lots,
            "max_orders_per_phase": self.settings.commodity_simnow_max_orders_per_phase,
            "min_source_month": self.settings.commodity_simnow_min_source_month,
        }

    def start(self) -> None:
        if (
            self._task
            or not self.settings.commodity_simnow_enabled
            or not self.settings.commodity_simnow_auto_dispatch_enabled
        ):
            return
        self._task = asyncio.create_task(self._run_auto_dispatch_loop())

    async def stop(self) -> None:
        if not self._task:
            return
        await asyncio.to_thread(self._revoke_auto_dispatch)
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    @_serialized
    def _revoke_auto_dispatch(self) -> None:
        self.auto_dispatch_authorized = False
        self.template_authorized = False

    @_serialized
    def enable(
        self,
        payload: CommoditySimNowEnableRequestDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        if not self.settings.commodity_simnow_enabled:
            raise CommoditySimNowDisabledError(
                detail={"required_setting": "COMMODITY_SIMNOW_ENABLED=true"}
            )
        confirmations = (
            payload.manual_approval,
            payload.simnow_mode,
            payload.confirm_simnow_only,
            payload.confirm_no_production,
            payload.confirm_cold_start_or_reconciled_state,
            payload.confirm_manual_two_phase_dispatch,
            payload.confirm_no_auto_promotion,
        )
        if not all(confirmations):
            raise CommoditySimNowSafetyError("SimNow 人工授权确认不完整")
        if self.settings.commodity_simnow_auto_dispatch_enabled and not payload.confirm_auto_dispatch:
            raise CommoditySimNowSafetyError("SimNow 自动派单授权确认不完整")
        snapshot = self._safety_snapshot(require_trade_enabled=True)
        self.enabled = True
        self.manual_approval = True
        self.simnow_mode = True
        self.auto_dispatch_authorized = (
            self.settings.commodity_simnow_auto_dispatch_enabled and payload.confirm_auto_dispatch
        )
        result = {**self.status(), "safety": snapshot, "reason": payload.reason}
        self._event("enabled", result={"account_hash": snapshot["account_hash"]})
        self.audit.record(
            action="commodity_simnow_enable",
            user_id=operator,
            role=role,
            request=payload.model_dump(),
            result=result,
            source_ip=source_ip,
        )
        return result

    @_serialized
    def disable(
        self,
        payload: CommoditySimNowDisableRequestDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        self.enabled = False
        self.manual_approval = False
        self.simnow_mode = False
        self.auto_dispatch_authorized = False
        self.template_authorized = False
        result = {**self.status(), "reason": payload.reason}
        self._event("disabled", result={"reason": payload.reason})
        self.audit.record(
            action="commodity_simnow_disable",
            user_id=operator,
            role=role,
            request=payload.model_dump(),
            result=result,
            source_ip=source_ip,
        )
        return result

    @_serialized
    def start_template(
        self,
        payload: CommodityTemplateStartRequestDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        confirmations = (
            payload.confirm_strategy_template,
            payload.confirm_simnow_only,
            payload.confirm_auto_dispatch,
            payload.confirm_no_production,
        )
        if not all(confirmations):
            raise CommoditySimNowSafetyError("一键策略模板授权确认不完整")
        if not self.settings.commodity_simnow_template_batch_path.strip():
            raise CommoditySimNowBatchError(
                "一键策略模板目标文件未配置",
                detail={"required_setting": "COMMODITY_SIMNOW_TEMPLATE_BATCH_PATH"},
            )
        if self.current_plan and self.current_plan.get("status") not in {"COMPLETE"}:
            raise CommoditySimNowStateError(
                "存在未完成委托计划，不允许重新启动模板",
                detail={
                    "status": self.current_plan.get("status"),
                    "plan_hash": self.current_plan.get("plan_hash"),
                },
            )

        self.enable(
            CommoditySimNowEnableRequestDTO(
                manual_approval=True,
                simnow_mode=True,
                reason=payload.reason,
                confirm_simnow_only=True,
                confirm_no_production=True,
                confirm_cold_start_or_reconciled_state=True,
                confirm_manual_two_phase_dispatch=True,
                confirm_auto_dispatch=True,
                confirm_no_auto_promotion=True,
            ),
            operator=operator,
            role=role,
            source_ip=source_ip,
        )
        self.template_authorized = True
        try:
            prepared = self.auto_template_advance(
                operator=operator,
                role=role,
                source_ip=source_ip,
            )
            if prepared.get("action") == "halted":
                raise CommoditySimNowSafetyError(
                    "一键策略模板触发合约到期保护，未启动自动派单",
                    detail={"prepared": prepared},
                )
            dispatched = self.auto_advance(
                operator=operator,
                role=role,
                source_ip=source_ip,
            )
        except Exception:
            self.enabled = False
            self.manual_approval = False
            self.simnow_mode = False
            self.template_authorized = False
            self.auto_dispatch_authorized = False
            self._event("strategy_template_start_failed", result={"reason": payload.reason})
            raise

        result = {
            "action": "strategy_template_started",
            "prepared": prepared,
            "dispatched": dispatched,
            **self.status(),
        }
        self._event(
            "strategy_template_started",
            plan_hash=self.current_plan.get("plan_hash") if self.current_plan else None,
            result={
                "prepared_action": prepared.get("action"),
                "dispatch_action": dispatched.get("action"),
            },
        )
        self.audit.record(
            action="commodity_simnow_strategy_template_start",
            user_id=operator,
            role=role,
            request=payload.model_dump(),
            result=result,
            source_ip=source_ip,
        )
        return result

    @_serialized
    def preview(
        self,
        batch: CommodityTargetBatchDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if self.current_plan and self.current_plan.get("status") in {
            "SUBMITTING_CLOSE",
            "SUBMITTING_OPEN",
            "CLOSE_SUBMITTED",
            "OPEN_SUBMITTED",
            "CLOSE_SUBMISSION_PARTIAL",
            "OPEN_SUBMISSION_PARTIAL",
            "CLOSE_RECONCILIATION_MISMATCH",
            "OPEN_RECONCILIATION_MISMATCH",
        }:
            raise CommoditySimNowStateError(
                "存在未完成委托计划，不允许覆盖",
                detail={"status": self.current_plan["status"], "plan_hash": self.current_plan["plan_hash"]},
            )
        safety = self._safety_snapshot(require_trade_enabled=True)
        batch_hash = self._verify_batch(batch)
        positions = self._position_snapshot()
        self._verify_previous_state(batch, positions)
        contracts = self._contract_snapshot()
        self._verify_target_exposures(batch)
        close_orders, open_orders, after_close, final_positions, quote_hash = self._build_orders(
            batch, positions, contracts
        )
        limit = self.settings.commodity_simnow_max_orders_per_phase
        if len(close_orders) > limit or len(open_orders) > limit:
            raise CommoditySimNowSafetyError(
                "拆单数量超过单阶段上限",
                detail={"close_orders": len(close_orders), "open_orders": len(open_orders), "limit": limit},
            )
        previous_positions = self._signed_positions(positions)
        roll_products = sorted(row.product for row in batch.targets if row.previous_exact_contract and row.previous_exact_contract != row.exact_contract and (row.previous_target_quantity or row.target_quantity))
        plan_core = {
            "batch_hash": batch_hash,
            "batch_id": batch.batch_id,
            "execution_lane": batch.execution_lane,
            "countable_forward": batch.execution_lane == "official_forward",
            "account_hash": safety["account_hash"],
            "previous_positions": previous_positions,
            "expected_after_close": after_close,
            "expected_final_positions": final_positions,
            "close_orders": close_orders,
            "open_orders": open_orders,
            "quote_snapshot_hash": quote_hash,
            "roll_products": roll_products,
        }
        plan_hash = _sha256_json(plan_core)
        if close_orders:
            status = "READY_CLOSE"
        elif open_orders:
            status = "READY_OPEN"
        else:
            status = "COMPLETE"
        self.current_plan = {
            **plan_core,
            "plan_hash": plan_hash,
            "status": status,
            "created_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
            "source_month": batch.source_month,
            "execution_day": batch.execution_day.isoformat(),
            "targets": [row.model_dump(mode="json") for row in batch.targets],
            "submitted": {"close": [], "open": []},
            "submitted_at_utc": {"close": None, "open": None},
        }
        if status == "COMPLETE":
            self._save_completed_state(self.current_plan)
        result = self.plan()
        self._event(
            "plan_previewed",
            plan_hash=plan_hash,
            result={
                "status": status,
                "execution_lane": batch.execution_lane,
                "countable_forward": batch.execution_lane == "official_forward",
            },
        )
        self.audit.record(
            action="commodity_simnow_plan_preview",
            user_id=operator,
            role=role,
            request={"batch_id": batch.batch_id, "batch_hash": batch_hash},
            result=result,
            source_ip=source_ip,
        )
        return result

    @_serialized
    def execute(
        self,
        payload: CommodityPlanExecuteRequestDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
        dispatch_mode: str = "manual",
    ) -> dict[str, Any]:
        self._require_enabled()
        if dispatch_mode not in {"manual", "auto"}:
            raise CommoditySimNowSafetyError("未知派单模式")
        if dispatch_mode == "auto":
            if not self._auto_dispatch_allowed():
                raise CommoditySimNowSafetyError("SimNow 自动派单未授权")
        elif not (payload.confirm and payload.confirm_simnow_only and payload.confirm_manual_one_shot):
            raise CommoditySimNowSafetyError("执行确认不完整")
        plan = self._require_plan(payload.plan_hash)
        execution_day = datetime.fromisoformat(plan["execution_day"]).date()
        if execution_day != self.clock().astimezone(CHINA_TZ).date():
            raise CommoditySimNowStateError(
                "计划已过执行日，不允许提交委托",
                detail={"execution_day": execution_day.isoformat()},
            )
        expected_status = "READY_CLOSE" if payload.phase == "close" else "READY_OPEN"
        if plan["status"] != expected_status:
            raise CommoditySimNowStateError(
                detail={"phase": payload.phase, "status": plan["status"], "expected": expected_status}
            )
        safety = self._safety_snapshot(require_trade_enabled=True)
        if safety["account_hash"] != plan["account_hash"]:
            raise CommoditySimNowSafetyError("SimNow 账户在 preview 后发生变化")
        expected_positions = (
            plan["previous_positions"] if payload.phase == "close" else plan["expected_after_close"]
        )
        observed_positions = self._signed_positions(self._position_snapshot())
        if observed_positions != expected_positions:
            raise CommoditySimNowStateError(
                "执行前持仓与计划不一致",
                detail={"expected": expected_positions, "observed": observed_positions},
            )
        active = self._active_strategy_orders()
        if active:
            raise CommoditySimNowStateError("仍有活动策略委托", detail={"active_order_ids": active})
        orders = list(plan[f"{payload.phase}_orders"])
        if not orders:
            raise CommoditySimNowStateError("该阶段没有待提交委托")

        plan["status"] = f"SUBMITTING_{payload.phase.upper()}"
        submitted: list[dict[str, Any]] = []
        try:
            for order in orders:
                repriced = self._reprice_order(order)
                request = OrderRequestDTO(
                    symbol=repriced["symbol"],
                    exchange=repriced["exchange"],
                    direction=repriced["direction"],
                    offset=repriced["offset"],
                    type="limit",
                    price=repriced["price"],
                    volume=repriced["volume"],
                    gateway_name=self.settings.commodity_simnow_gateway_name,
                    reference=repriced["reference"],
                    confirm=True,
                )
                result = self.trade.send_order(request, source_ip=source_ip, operator=operator)
                submitted.append(
                    {
                        **repriced,
                        "decision_price": order["price"],
                        "dispatch_mode": dispatch_mode,
                        **result,
                    }
                )
                self.order_endpoint_touched = True
        except Exception as exc:
            plan["status"] = f"{payload.phase.upper()}_SUBMISSION_PARTIAL"
            plan["submitted"][payload.phase].extend(submitted)
            if dispatch_mode == "auto":
                self._revoke_auto_dispatch()
            self._event(
                "submission_partial",
                plan_hash=plan["plan_hash"],
                result={
                    "phase": payload.phase,
                    "dispatch_mode": dispatch_mode,
                    "submitted": len(submitted),
                    "error": exc.__class__.__name__,
                },
            )
            self.audit.record(
                action="commodity_simnow_execute_partial",
                user_id=operator,
                role=role,
                request={
                    "plan_hash": plan["plan_hash"],
                    "phase": payload.phase,
                    "dispatch_mode": dispatch_mode,
                    "reason": payload.reason,
                },
                result={"submitted": submitted, "status": plan["status"]},
                error=str(exc),
                error_code=getattr(exc, "code", None),
                source_ip=source_ip,
            )
            raise CommoditySimNowStateError(
                "委托部分提交，必须人工检查并处理",
                detail={"phase": payload.phase, "submitted_order_ids": [row.get("vt_orderid") for row in submitted]},
            ) from exc

        plan["submitted"][payload.phase].extend(submitted)
        plan["submitted_at_utc"][payload.phase] = self.clock().astimezone(timezone.utc).isoformat()
        plan["status"] = f"{payload.phase.upper()}_SUBMITTED"
        result = self.plan()
        self._event(
            "phase_submitted",
            plan_hash=plan["plan_hash"],
            result={
                "phase": payload.phase,
                "dispatch_mode": dispatch_mode,
                "order_count": len(submitted),
            },
        )
        self.audit.record(
            action="commodity_simnow_execute_phase",
            user_id=operator,
            role=role,
            request={
                "plan_hash": plan["plan_hash"],
                "phase": payload.phase,
                "dispatch_mode": dispatch_mode,
                "reason": payload.reason,
            },
            result={"submitted": submitted, "status": plan["status"]},
            source_ip=source_ip,
        )
        return result

    @_serialized
    def reconcile(
        self,
        plan_hash: str,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
        dispatch_mode: str = "manual",
    ) -> dict[str, Any]:
        self._require_enabled()
        plan = self._require_plan(plan_hash)
        safety = self._safety_snapshot(require_trade_enabled=True)
        if safety["account_hash"] != plan["account_hash"]:
            raise CommoditySimNowSafetyError("SimNow 账户在 preview 后发生变化")
        if plan["status"] not in {"CLOSE_SUBMITTED", "OPEN_SUBMITTED"}:
            raise CommoditySimNowStateError(
                "当前状态不允许对账", detail={"status": plan["status"]}
            )
        active = self._active_strategy_orders()
        observed = self._signed_positions(self._position_snapshot())
        plan["execution"] = self._execution_snapshot(plan)
        phase = "close" if plan["status"] == "CLOSE_SUBMITTED" else "open"
        expected = plan["expected_after_close"] if phase == "close" else plan["expected_final_positions"]
        matched = not active and observed == expected
        reconciliation_mismatch = False
        if not matched and not active and dispatch_mode == "auto":
            submitted_at = _parse_datetime(plan["submitted_at_utc"].get(phase))
            age = (
                (self.clock().astimezone(timezone.utc) - submitted_at).total_seconds()
                if submitted_at
                else float("inf")
            )
            if age >= self.settings.commodity_simnow_auto_dispatch_reconcile_grace_seconds:
                plan["status"] = f"{phase.upper()}_RECONCILIATION_MISMATCH"
                self._revoke_auto_dispatch()
                reconciliation_mismatch = True
        if matched and phase == "close":
            plan["status"] = "READY_OPEN" if plan["open_orders"] else "COMPLETE"
        elif matched:
            plan["status"] = "COMPLETE"
        if plan["status"] == "COMPLETE":
            self._save_completed_state(plan)
        result = {
            **self.plan(),
            "reconciliation": {
                "phase": phase,
                "matched": matched,
                "active_order_ids": active,
                "expected_positions": expected,
                "observed_positions": observed,
                "mismatch_halted": reconciliation_mismatch,
            },
        }
        if dispatch_mode == "manual" or matched or reconciliation_mismatch:
            self._event("reconciled", plan_hash=plan_hash, result=result["reconciliation"])
            self.audit.record(
                action="commodity_simnow_reconcile",
                user_id=operator,
                role=role,
                request={"plan_hash": plan_hash, "dispatch_mode": dispatch_mode},
                result=result,
                source_ip=source_ip,
            )
        return result

    @_serialized
    def auto_advance(
        self,
        *,
        operator: str = "commodity-simnow-auto",
        role: str | None = "system",
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        if not self._auto_dispatch_allowed():
            return {"action": "idle", "reason": "auto_dispatch_not_active", **self.status()}
        if not self.current_plan:
            return {"action": "idle", "reason": "no_plan", **self.status()}

        plan = self.current_plan
        status = plan["status"]
        if status in {"CLOSE_SUBMISSION_PARTIAL", "OPEN_SUBMISSION_PARTIAL"}:
            self._revoke_auto_dispatch()
            self._event(
                "auto_dispatch_halted",
                plan_hash=plan["plan_hash"],
                result={"reason": "partial_submission", "status": status},
            )
            return {"action": "halted", "reason": "partial_submission", **self.status()}

        if status in {"READY_CLOSE", "READY_OPEN"}:
            phase = "close" if status == "READY_CLOSE" else "open"
            result = self.execute(
                CommodityPlanExecuteRequestDTO(
                    plan_hash=plan["plan_hash"],
                    phase=phase,
                    confirm=True,
                    confirm_simnow_only=True,
                    confirm_manual_one_shot=True,
                    reason=f"authorized SimNow automatic {phase} dispatch",
                ),
                operator=operator,
                role=role,
                source_ip=source_ip,
                dispatch_mode="auto",
            )
            return {"action": f"{phase}_submitted", **result}

        if status in {"CLOSE_SUBMITTED", "OPEN_SUBMITTED"}:
            phase = "close" if status == "CLOSE_SUBMITTED" else "open"
            result = self.reconcile(
                plan["plan_hash"],
                operator=operator,
                role=role,
                source_ip=source_ip,
                dispatch_mode="auto",
            )
            if result["reconciliation"]["mismatch_halted"]:
                return {"action": f"{phase}_reconciliation_mismatch", **result}
            if result["status"] == "READY_OPEN":
                submitted = self.execute(
                    CommodityPlanExecuteRequestDTO(
                        plan_hash=plan["plan_hash"],
                        phase="open",
                        confirm=True,
                        confirm_simnow_only=True,
                        confirm_manual_one_shot=True,
                        reason="authorized SimNow automatic open after close reconciliation",
                    ),
                    operator=operator,
                    role=role,
                    source_ip=source_ip,
                    dispatch_mode="auto",
                )
                return {"action": "close_reconciled_open_submitted", **submitted}
            return {"action": f"{phase}_reconciled", **result}

        return {"action": "idle", "reason": f"plan_status_{status.lower()}", **self.status()}

    @_serialized
    def auto_template_advance(
        self,
        *,
        operator: str = "commodity-simnow-template",
        role: str | None = "system",
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        if not self.template_authorized:
            return {"action": "idle", "reason": "strategy_template_not_authorized"}
        if not self._auto_dispatch_allowed():
            return {"action": "idle", "reason": "auto_dispatch_not_active"}
        local_today = self.clock().astimezone(CHINA_TZ).date()
        if self.current_plan and self.current_plan.get("status") != "COMPLETE":
            execution_day = datetime.fromisoformat(self.current_plan["execution_day"]).date()
            if execution_day != local_today:
                self._revoke_auto_dispatch()
                result = {
                    "action": "halted",
                    "reason": "active_plan_execution_day_expired",
                    "execution_day": execution_day.isoformat(),
                    "local_today": local_today.isoformat(),
                    "status": self.current_plan.get("status"),
                    "plan_hash": self.current_plan.get("plan_hash"),
                }
                self._event(
                    "strategy_template_active_plan_expired",
                    plan_hash=self.current_plan.get("plan_hash"),
                    result=result,
                )
                return result
            return {
                "action": "idle",
                "reason": "plan_active",
                "status": self.current_plan.get("status"),
                "plan_hash": self.current_plan.get("plan_hash"),
            }

        batch = self._load_template_batch()
        if batch.execution_day > local_today:
            expiry_halt = self._halt_if_delivery_guard_breached(local_today)
            if expiry_halt:
                return expiry_halt
            return {
                "action": "waiting",
                "reason": "target_execution_day_not_reached",
                "execution_day": batch.execution_day.isoformat(),
            }
        if batch.execution_day < local_today:
            expiry_halt = self._halt_if_delivery_guard_breached(local_today)
            if expiry_halt:
                return expiry_halt
            return {
                "action": "waiting",
                "reason": "target_file_stale",
                "execution_day": batch.execution_day.isoformat(),
            }

        payload = batch.model_dump(mode="json", exclude={"signature"})
        batch_hash = hashlib.sha256(_canonical_json(payload)).hexdigest()
        if self.current_plan and self.current_plan.get("batch_hash") == batch_hash:
            expiry_halt = self._halt_if_delivery_guard_breached(local_today)
            if expiry_halt:
                return expiry_halt
            return {
                "action": "idle",
                "reason": "target_already_loaded",
                "status": self.current_plan.get("status"),
                "plan_hash": self.current_plan.get("plan_hash"),
            }
        if self._completed_state.get("last_completed_batch_hash") == batch_hash:
            expiry_halt = self._halt_if_delivery_guard_breached(local_today)
            if expiry_halt:
                return expiry_halt
            return {"action": "idle", "reason": "target_already_completed"}

        try:
            plan = self.preview(
                batch,
                operator=operator,
                role=role,
                source_ip=source_ip,
            )
        except Exception as exc:
            self._revoke_auto_dispatch()
            self._event(
                "strategy_template_target_rejected",
                result={
                    "error_type": exc.__class__.__name__,
                    "error_code": getattr(exc, "code", None),
                },
            )
            raise
        return {
            "action": "target_loaded",
            "execution_lane": plan["execution_lane"],
            "countable_forward": plan["countable_forward"],
            "status": plan["status"],
            "plan_hash": plan["plan_hash"],
        }

    async def _run_auto_dispatch_loop(self) -> None:
        while True:
            try:
                if self.template_authorized:
                    await asyncio.to_thread(self.auto_template_advance)
                await asyncio.to_thread(self.auto_advance)
            except Exception:
                logger.exception("commodity SimNow auto-dispatch cycle failed")
            await asyncio.sleep(self.settings.commodity_simnow_auto_dispatch_interval_seconds)

    def _load_template_batch(self) -> CommodityTargetBatchDTO:
        path = Path(self.settings.commodity_simnow_template_batch_path).expanduser()
        try:
            if not path.is_file():
                raise FileNotFoundError(path)
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("target file exceeds 2 MiB")
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("target file must contain one JSON object")
            return CommodityTargetBatchDTO.model_validate(payload)
        except Exception as exc:
            self.template_authorized = False
            self.auto_dispatch_authorized = False
            self._event(
                "strategy_template_target_rejected",
                result={"error_type": exc.__class__.__name__},
            )
            raise CommoditySimNowBatchError(
                "一键策略模板目标文件无效",
                detail={"error_type": exc.__class__.__name__},
            ) from exc

    def _halt_if_delivery_guard_breached(self, local_today: date) -> dict[str, Any] | None:
        violations: list[dict[str, Any]] = []
        try:
            positions = self._position_snapshot()
        except Exception as exc:
            self._revoke_auto_dispatch()
            result = {
                "action": "halted",
                "reason": "delivery_guard_position_snapshot_failed",
                "error_type": exc.__class__.__name__,
            }
            self._event("strategy_template_delivery_guard_halted", result=result)
            return result
        for vt_symbol, row in positions.items():
            if not row.get("signed_quantity"):
                continue
            symbol, exchange = _split_vt(vt_symbol)
            exact_contract = f"{exchange}.{symbol}"
            try:
                self._verify_target_delivery(exact_contract, local_today)
            except CommoditySimNowBatchError as exc:
                violations.append(
                    {
                        "vt_symbol": vt_symbol,
                        "signed_quantity": row["signed_quantity"],
                        "detail": exc.detail,
                    }
                )
        if not violations:
            return None
        self._revoke_auto_dispatch()
        result = {
            "action": "halted",
            "reason": "delivery_guard_breached_without_current_roll_target",
            "violations": violations,
        }
        self._event("strategy_template_delivery_guard_halted", result=result)
        return result

    @_serialized
    def plan(self) -> dict[str, Any]:
        if not self.current_plan:
            return {}
        plan = json.loads(json.dumps(self.current_plan, ensure_ascii=False, default=str))
        return plan

    @_serialized
    def list_events(self, limit: int = 200) -> list[dict[str, Any]]:
        return list(reversed(self.events[-max(1, min(limit, 1000)) :]))

    def _auto_dispatch_allowed(self) -> bool:
        return bool(
            self.settings.commodity_simnow_auto_dispatch_enabled
            and self.enabled
            and self.manual_approval
            and self.simnow_mode
            and self.auto_dispatch_authorized
        )

    def _require_enabled(self) -> None:
        if not (self.settings.commodity_simnow_enabled and self.enabled and self.manual_approval and self.simnow_mode):
            raise CommoditySimNowDisabledError()

    def _require_plan(self, plan_hash: str) -> dict[str, Any]:
        if not self.current_plan or self.current_plan.get("plan_hash") != plan_hash:
            raise CommoditySimNowStateError("计划不存在或哈希不匹配")
        return self.current_plan

    def _safety_snapshot(self, *, require_trade_enabled: bool) -> dict[str, Any]:
        if self._state_load_error:
            raise CommoditySimNowSafetyError("持久化状态损坏", detail={"error": self._state_load_error})
        self._trusted_keys()
        status = self.rpc.status(probe=True)
        if not status.get("connected"):
            raise CommoditySimNowSafetyError("RPC 未连接")
        gateway = str(status.get("gateway_name") or "")
        if gateway != self.settings.commodity_simnow_gateway_name:
            raise CommoditySimNowSafetyError(
                "RPC gateway 与 SimNow 配置不一致",
                detail={"observed_gateway": gateway, "required_gateway": self.settings.commodity_simnow_gateway_name},
            )
        risk_status = self.risk.status()
        if risk_status.get("emergency_stopped"):
            raise CommoditySimNowSafetyError("风控处于紧急停止状态")
        if require_trade_enabled and not risk_status.get("web_trade_enabled"):
            raise CommoditySimNowSafetyError("Web 交易开关未开启")
        account_hash = self._simnow_account_hash()
        return {
            "rpc_connected": True,
            "gateway_name": gateway,
            "account_hash": account_hash,
            "web_trade_enabled": bool(risk_status.get("web_trade_enabled")),
            "emergency_stopped": bool(risk_status.get("emergency_stopped")),
            "trusted_key_ids": sorted(self._trusted_keys()),
            "production_allowed": False,
        }

    def _simnow_account_hash(self) -> str:
        allowlist = _csv_set(self.settings.commodity_simnow_account_hashes)
        if not allowlist:
            raise CommoditySimNowSafetyError("SimNow 账户哈希白名单为空")
        matches: list[str] = []
        for account in self.rpc.get_accounts():
            gateway = _value(account.get("gateway_name") or account.get("gateway") or "")
            if gateway and gateway != self.settings.commodity_simnow_gateway_name:
                continue
            account_id = str(
                account.get("accountid")
                or account.get("account_id")
                or account.get("vt_accountid")
                or ""
            )
            if not account_id:
                continue
            digest = hashlib.sha256(account_id.encode("utf-8")).hexdigest()
            if digest.lower() in allowlist:
                matches.append(digest)
        if len(matches) != 1:
            raise CommoditySimNowSafetyError(
                "必须且只能识别一个白名单 SimNow 账户",
                detail={"allowlisted_account_matches": len(matches)},
            )
        return matches[0]

    def _trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        try:
            raw = json.loads(self.settings.commodity_simnow_trusted_public_keys_json)
        except json.JSONDecodeError as exc:
            raise CommoditySimNowSafetyError("Ed25519 公钥配置不是有效 JSON") from exc
        if not isinstance(raw, dict) or not raw:
            raise CommoditySimNowSafetyError("Ed25519 公钥信任集为空")
        keys: dict[str, Ed25519PublicKey] = {}
        for key_id, encoded in raw.items():
            try:
                key_bytes = base64.b64decode(str(encoded), validate=True)
                if len(key_bytes) != 32:
                    raise ValueError("Ed25519 public key must be 32 bytes")
                keys[str(key_id)] = Ed25519PublicKey.from_public_bytes(key_bytes)
            except (ValueError, binascii.Error) as exc:
                raise CommoditySimNowSafetyError(
                    "Ed25519 公钥配置无效", detail={"key_id": str(key_id)}
                ) from exc
        return keys

    def _verify_batch(self, batch: CommodityTargetBatchDTO) -> str:
        key = self._trusted_keys().get(batch.signer_key_id)
        if key is None:
            raise CommoditySimNowBatchError("签名 key_id 不在信任集")
        payload = batch.model_dump(mode="json", exclude={"signature"})
        canonical = _canonical_json(payload)
        try:
            signature = base64.b64decode(batch.signature, validate=True)
            key.verify(signature, canonical)
        except (InvalidSignature, ValueError, binascii.Error) as exc:
            raise CommoditySimNowBatchError("目标批次 Ed25519 签名无效") from exc

        if batch.candidate_weights.model_dump() != {"C": 0.5, "D": 0.5}:
            raise CommoditySimNowBatchError("候选权重不是冻结的 50%C + 50%D")
        if batch.guardband.model_dump() != {
            "product": 0.12,
            "sector": 0.27,
            "gross": 0.8,
            "target_net": 0.0,
        }:
            raise CommoditySimNowBatchError("guardband 与冻结 v2 不一致")
        products = [row.product for row in batch.targets]
        if set(products) != set(PRODUCT_SPECS) or len(products) != len(set(products)):
            raise CommoditySimNowBatchError("目标批次必须且只能包含冻结十品种")
        local_today = self.clock().astimezone(CHINA_TZ).date()
        if batch.execution_day != local_today:
            raise CommoditySimNowBatchError(
                "目标批次只能在 execution day 当日预览和执行",
                detail={"execution_day": batch.execution_day.isoformat(), "local_today": local_today.isoformat()},
            )
        if batch.execution_lane == "official_forward":
            if batch.source_month < self.settings.commodity_simnow_min_source_month:
                raise CommoditySimNowBatchError(
                    "official forward source month 早于允许边界",
                    detail={
                        "source_month": batch.source_month,
                        "minimum": self.settings.commodity_simnow_min_source_month,
                    },
                )
            source_year, source_month = (int(item) for item in batch.source_month.split("-"))
            expected_year = source_year + (1 if source_month == 12 else 0)
            expected_month = 1 if source_month == 12 else source_month + 1
            if (batch.execution_day.year, batch.execution_day.month) != (expected_year, expected_month):
                raise CommoditySimNowBatchError(
                    "official forward execution day 必须位于 source month 的下一个自然月"
                )
        else:
            current_month = local_today.strftime("%Y-%m")
            if batch.source_month > current_month:
                raise CommoditySimNowBatchError(
                    "SimNow shakedown 不得使用未来 source month",
                    detail={"source_month": batch.source_month, "current_month": current_month},
                )
        for row in batch.targets:
            self._verify_target_row(row.model_dump())
            if row.target_quantity:
                self._verify_target_delivery(row.exact_contract, local_today)
        self._verify_weight_caps(batch)
        self._verify_completed_chain(batch)
        return hashlib.sha256(canonical).hexdigest()

    def _verify_target_row(self, row: dict[str, Any]) -> None:
        product = row["product"]
        spec = PRODUCT_SPECS[product]
        expected_prefix = f"{spec['exchange']}.{product}"
        if not re.fullmatch(rf"{re.escape(expected_prefix)}\d{{4}}", row["exact_contract"]):
            raise CommoditySimNowBatchError("exact contract 与品种/交易所不一致", detail={"product": product})
        previous = row.get("previous_exact_contract")
        if previous and not re.fullmatch(rf"{re.escape(expected_prefix)}\d{{4}}", previous):
            raise CommoditySimNowBatchError("previous exact contract 与品种/交易所不一致", detail={"product": product})
        if row["multiplier"] != spec["multiplier"] or not math.isclose(
            row["price_tick"], spec["price_tick"], rel_tol=0, abs_tol=1e-12
        ):
            raise CommoditySimNowBatchError("合约乘数或最小跳动与冻结 spec 不一致", detail={"product": product})
        if abs(row["previous_target_quantity"]) > 500 or abs(row["target_quantity"]) > 500:
            raise CommoditySimNowBatchError("目标手数超过 SimNow 安全上限", detail={"product": product})
        for field in ("source_target_weight", "buffered_target_weight", "reference_open_price"):
            if not math.isfinite(float(row[field])):
                raise CommoditySimNowBatchError("目标数值非有限数", detail={"product": product, "field": field})
        target_quantity = int(row["target_quantity"])
        buffered_weight = float(row["buffered_target_weight"])
        if target_quantity and (not buffered_weight or math.copysign(1, target_quantity) != math.copysign(1, buffered_weight)):
            raise CommoditySimNowBatchError("整数目标方向与 buffered target 不一致", detail={"product": product})

    def _verify_target_delivery(self, exact_contract: str, local_today: date) -> None:
        try:
            delivery_year, delivery_month = _delivery_year_month(exact_contract)
        except ValueError as exc:
            raise CommoditySimNowBatchError(
                "目标合约交割月份无法识别",
                detail={"exact_contract": exact_contract},
            ) from exc
        delivery_value = delivery_year * 100 + delivery_month
        current_value = local_today.year * 100 + local_today.month
        cutoff = self.settings.commodity_simnow_delivery_month_cutoff_day
        product = _product_from_symbol(exact_contract.split(".", 1)[1])
        if delivery_month == 1:
            preceding_year, preceding_month = delivery_year - 1, 12
        else:
            preceding_year, preceding_month = delivery_year, delivery_month - 1
        sc_cutoff = self.settings.commodity_simnow_sc_pre_delivery_cutoff_day
        if product == "sc" and (local_today.year, local_today.month) == (preceding_year, preceding_month) and local_today.day >= sc_cutoff:
            raise CommoditySimNowBatchError(
                "原油目标合约已进入交割前月到期保护区间",
                detail={
                    "exact_contract": exact_contract,
                    "local_date": local_today.isoformat(),
                    "pre_delivery_cutoff_day": sc_cutoff,
                },
            )
        if delivery_value < current_value or (delivery_value == current_value and local_today.day >= cutoff):
            raise CommoditySimNowBatchError(
                "目标合约已进入交割风险截止区间",
                detail={
                    "exact_contract": exact_contract,
                    "delivery_year_month": delivery_value,
                    "local_date": local_today.isoformat(),
                    "cutoff_day": cutoff,
                },
            )

    def _verify_weight_caps(self, batch: CommodityTargetBatchDTO) -> None:
        rows = [row.model_dump() for row in batch.targets]
        for field, product_limit, sector_limit, gross_limit in (
            ("source_target_weight", 0.20, 0.35, 1.0),
            ("buffered_target_weight", 0.12, 0.27, 0.8),
        ):
            values = {row["product"]: float(row[field]) for row in rows}
            if max(abs(value) for value in values.values()) > product_limit + 1e-12:
                raise CommoditySimNowBatchError(f"{field} 超过产品上限")
            if sum(abs(value) for value in values.values()) > gross_limit + 1e-12:
                raise CommoditySimNowBatchError(f"{field} 超过 gross 上限")
            if abs(sum(values.values())) > 1e-10:
                raise CommoditySimNowBatchError(f"{field} 不是净额零")
            for sector in {spec["sector"] for spec in PRODUCT_SPECS.values()}:
                gross = sum(
                    abs(values[product])
                    for product, spec in PRODUCT_SPECS.items()
                    if spec["sector"] == sector
                )
                if gross > sector_limit + 1e-12:
                    raise CommoditySimNowBatchError(f"{field} 超过板块上限", detail={"sector": sector})

    def _verify_target_exposures(self, batch: CommodityTargetBatchDTO) -> None:
        weights = {
            row.product: row.target_quantity * row.reference_open_price * row.multiplier / self.virtual_nav_cny
            for row in batch.targets
        }
        if max(abs(value) for value in weights.values()) >= 0.15:
            raise CommoditySimNowBatchError("整数目标超过严格 15% 产品硬上限")
        if sum(abs(value) for value in weights.values()) >= 1.0:
            raise CommoditySimNowBatchError("整数目标超过严格 100% gross 硬上限")
        if abs(sum(weights.values())) >= 0.10:
            raise CommoditySimNowBatchError("整数目标超过严格 10% 净敞口硬上限")
        for sector in {spec["sector"] for spec in PRODUCT_SPECS.values()}:
            gross = sum(
                abs(weights[product])
                for product, spec in PRODUCT_SPECS.items()
                if spec["sector"] == sector
            )
            if gross >= 0.35:
                raise CommoditySimNowBatchError("整数目标超过严格 35% 板块硬上限", detail={"sector": sector})

    def _verify_completed_chain(self, batch: CommodityTargetBatchDTO) -> None:
        last_hash = self._completed_state.get("last_completed_batch_hash")
        last_targets = {
            row["product"]: row for row in self._completed_state.get("targets", [])
        }
        if last_hash:
            if batch.previous_batch_hash != last_hash:
                raise CommoditySimNowBatchError("previous_batch_hash 与本地完成状态不一致")
            for row in batch.targets:
                previous = last_targets.get(row.product)
                if not previous or previous["exact_contract"] != row.previous_exact_contract or previous[
                    "target_quantity"
                ] != row.previous_target_quantity:
                    raise CommoditySimNowBatchError("previous target 与本地完成状态不一致", detail={"product": row.product})
        else:
            if batch.previous_batch_hash is not None:
                raise CommoditySimNowBatchError("冷启动不得携带未知 previous_batch_hash")
            if any(row.previous_target_quantity != 0 or row.previous_exact_contract for row in batch.targets):
                raise CommoditySimNowBatchError("冷启动必须从十品种全平状态开始")

    def _contract_snapshot(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for contract in self.rpc.get_contracts():
            vt_symbol = str(
                contract.get("vt_symbol")
                or f"{contract.get('symbol')}.{_value(contract.get('exchange'))}"
            )
            result[vt_symbol] = contract
        return result

    def _position_snapshot(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for position in self.rpc.get_positions():
            symbol = str(position.get("symbol") or "")
            exchange = _value(position.get("exchange") or "")
            vt_symbol = str(position.get("vt_symbol") or f"{symbol}.{exchange}")
            if not symbol and "." in vt_symbol:
                symbol, exchange = _split_vt(vt_symbol)
            product = _product_from_symbol(symbol)
            if product not in PRODUCT_SPECS:
                continue
            direction = _normalize_direction(position.get("direction"))
            if direction not in {"long", "short"}:
                raise CommoditySimNowSafetyError("持仓方向无法识别", detail={"vt_symbol": vt_symbol})
            volume = int(float(position.get("volume") or 0))
            frozen = int(float(position.get("frozen") or 0))
            yd = int(float(position.get("yd_volume") or position.get("ydPosition") or 0))
            if frozen:
                raise CommoditySimNowSafetyError("冻结持仓不允许生成新计划", detail={"vt_symbol": vt_symbol})
            if volume <= 0:
                continue
            signed = volume if direction == "long" else -volume
            if vt_symbol in result and result[vt_symbol]["signed_quantity"] * signed < 0:
                raise CommoditySimNowSafetyError("同合约同时存在多空持仓", detail={"vt_symbol": vt_symbol})
            previous = result.get(vt_symbol, {"signed_quantity": 0, "yd_quantity": 0, "today_quantity": 0})
            previous["signed_quantity"] += signed
            previous["yd_quantity"] += min(yd, volume)
            previous["today_quantity"] += max(volume - yd, 0)
            result[vt_symbol] = previous
        return result

    def _verify_previous_state(self, batch: CommodityTargetBatchDTO, positions: dict[str, dict[str, Any]]) -> None:
        expected: dict[str, int] = {}
        for row in batch.targets:
            if row.previous_target_quantity:
                if not row.previous_exact_contract:
                    raise CommoditySimNowBatchError("非零 previous target 缺少 previous exact contract")
                expected[_exact_to_vt(row.previous_exact_contract)] = row.previous_target_quantity
        observed = self._signed_positions(positions)
        if observed != expected:
            raise CommoditySimNowStateError(
                "SimNow 当前持仓与签名 previous target 不一致",
                detail={"expected": expected, "observed": observed},
            )
        today = {vt: row["today_quantity"] for vt, row in positions.items() if row["today_quantity"]}
        if today:
            raise CommoditySimNowSafetyError(
                "冻结月度路径不允许从平今仓位生成批次", detail={"today_positions": today}
            )

    def _build_orders(
        self,
        batch: CommodityTargetBatchDTO,
        positions: dict[str, dict[str, Any]],
        contracts: dict[str, dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int], dict[str, int], str]:
        close_orders: list[dict[str, Any]] = []
        open_orders: list[dict[str, Any]] = []
        quote_rows: list[dict[str, Any]] = []
        for row in sorted(batch.targets, key=lambda item: item.product):
            previous_vt = _exact_to_vt(row.previous_exact_contract) if row.previous_exact_contract else None
            target_vt = _exact_to_vt(row.exact_contract)
            previous_quantity = row.previous_target_quantity
            target_quantity = row.target_quantity
            if previous_vt and previous_quantity:
                self._verify_contract(previous_vt, row.product, contracts)
            if target_quantity:
                self._verify_contract(target_vt, row.product, contracts)
            if previous_vt and previous_vt != target_vt:
                if previous_quantity:
                    close_orders.extend(
                        self._orders_for_leg(
                            batch.batch_id,
                            row.product,
                            previous_vt,
                            -previous_quantity,
                            "closeyesterday",
                            quote_rows,
                        )
                    )
                if target_quantity:
                    open_orders.extend(
                        self._orders_for_leg(
                            batch.batch_id,
                            row.product,
                            target_vt,
                            target_quantity,
                            "open",
                            quote_rows,
                        )
                    )
                continue

            delta = target_quantity - previous_quantity
            if not delta:
                continue
            if previous_quantity and target_quantity and previous_quantity * target_quantity < 0:
                close_orders.extend(
                    self._orders_for_leg(
                        batch.batch_id, row.product, target_vt, -previous_quantity, "closeyesterday", quote_rows
                    )
                )
                open_orders.extend(
                    self._orders_for_leg(
                        batch.batch_id, row.product, target_vt, target_quantity, "open", quote_rows
                    )
                )
            elif previous_quantity and abs(target_quantity) < abs(previous_quantity) and previous_quantity * target_quantity >= 0:
                close_orders.extend(
                    self._orders_for_leg(
                        batch.batch_id, row.product, target_vt, delta, "closeyesterday", quote_rows
                    )
                )
            else:
                open_orders.extend(
                    self._orders_for_leg(batch.batch_id, row.product, target_vt, delta, "open", quote_rows)
                )

        close_orders = self._number_references(close_orders, batch.batch_id, "close")
        open_orders = self._number_references(open_orders, batch.batch_id, "open")
        start = self._signed_positions(positions)
        after_close = self._apply_orders(start, close_orders)
        final_positions = self._apply_orders(after_close, open_orders)
        expected_final = {
            _exact_to_vt(row.exact_contract): row.target_quantity
            for row in batch.targets
            if row.target_quantity
        }
        if final_positions != expected_final:
            raise CommoditySimNowBatchError(
                "委托计划无法重建最终目标", detail={"planned": final_positions, "expected": expected_final}
            )
        return close_orders, open_orders, after_close, final_positions, _sha256_json(quote_rows)

    def _verify_contract(
        self, vt_symbol: str, product: str, contracts: dict[str, dict[str, Any]]
    ) -> None:
        contract = contracts.get(vt_symbol)
        if not contract:
            raise CommoditySimNowSafetyError("SimNow 缺少目标 exact contract", detail={"vt_symbol": vt_symbol})
        spec = PRODUCT_SPECS[product]
        size = int(float(contract.get("size") or contract.get("contract_size") or 0))
        tick = float(contract.get("pricetick") or contract.get("price_tick") or 0)
        gateway = _value(contract.get("gateway_name") or contract.get("gateway") or "")
        if size != spec["multiplier"] or not math.isclose(tick, spec["price_tick"], rel_tol=0, abs_tol=1e-12):
            raise CommoditySimNowSafetyError(
                "SimNow 合约规格与冻结 spec 不一致",
                detail={"vt_symbol": vt_symbol, "size": size, "price_tick": tick},
            )
        if gateway and gateway != self.settings.commodity_simnow_gateway_name:
            raise CommoditySimNowSafetyError("目标合约不属于配置的 SimNow gateway", detail={"vt_symbol": vt_symbol})

    def _orders_for_leg(
        self,
        batch_id: str,
        product: str,
        vt_symbol: str,
        signed_delta: int,
        offset: str,
        quote_rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if signed_delta == 0:
            return []
        symbol, exchange = _split_vt(vt_symbol)
        direction = "long" if signed_delta > 0 else "short"
        quote = self._quote(vt_symbol, PRODUCT_SPECS[product]["price_tick"])
        quote_rows.append({"vt_symbol": vt_symbol, **quote})
        price = self._protected_price(direction, quote, PRODUCT_SPECS[product]["price_tick"])
        maximum = self.settings.commodity_simnow_max_child_order_lots
        remaining = abs(signed_delta)
        orders: list[dict[str, Any]] = []
        while remaining:
            volume = min(remaining, maximum)
            orders.append(
                {
                    "batch_id": batch_id,
                    "product": product,
                    "vt_symbol": vt_symbol,
                    "symbol": symbol,
                    "exchange": exchange,
                    "direction": direction,
                    "offset": offset,
                    "volume": volume,
                    "price": price,
                    "reference": "",
                }
            )
            remaining -= volume
        return orders

    def _number_references(self, orders: list[dict[str, Any]], batch_id: str, phase: str) -> list[dict[str, Any]]:
        safe_batch = re.sub(r"[^A-Za-z0-9]", "", batch_id)[-12:]
        for index, order in enumerate(orders, start=1):
            order["reference"] = f"{REFERENCE_PREFIX}:{safe_batch}:{phase[0]}:{index}"
        return orders

    def _quote(self, vt_symbol: str, tick: float) -> dict[str, Any]:
        raw = self.tick_store.get_tick(vt_symbol)
        if not raw:
            symbol, exchange = _split_vt(vt_symbol)
            self.rpc.subscribe_market(symbol, exchange)
            raise CommoditySimNowSafetyError(
                "盘口尚未就绪，已发起订阅，请等待 tick 后重试", detail={"vt_symbol": vt_symbol}
            )
        bid = float(raw.get("bid_price_1") or raw.get("bid_price1") or 0)
        ask = float(raw.get("ask_price_1") or raw.get("ask_price1") or 0)
        bid_volume = float(raw.get("bid_volume_1") or raw.get("bid_volume1") or 0)
        ask_volume = float(raw.get("ask_volume_1") or raw.get("ask_volume1") or 0)
        timestamp = _parse_datetime(raw.get("received_at") or raw.get("datetime"))
        if bid <= 0 or ask <= 0 or ask < bid or bid_volume <= 0 or ask_volume <= 0 or timestamp is None:
            raise CommoditySimNowSafetyError("盘口字段不完整", detail={"vt_symbol": vt_symbol})
        age = (self.clock().astimezone(timezone.utc) - timestamp).total_seconds()
        if age < -2 or age > self.settings.commodity_simnow_max_quote_age_seconds:
            raise CommoditySimNowSafetyError(
                "盘口已过期", detail={"vt_symbol": vt_symbol, "quote_age_seconds": round(age, 3)}
            )
        spread_ticks = (ask - bid) / tick
        if spread_ticks > self.settings.commodity_simnow_max_spread_ticks + 1e-12:
            raise CommoditySimNowSafetyError(
                "盘口价差超过 SimNow 上限",
                detail={"vt_symbol": vt_symbol, "spread_ticks": spread_ticks},
            )
        return {
            "bid_price_1": bid,
            "ask_price_1": ask,
            "bid_volume_1": bid_volume,
            "ask_volume_1": ask_volume,
            "received_at": timestamp.isoformat(),
            "spread_ticks": spread_ticks,
        }

    def _protected_price(self, direction: str, quote: dict[str, Any], tick: float) -> float:
        raw = quote["ask_price_1"] + tick if direction == "long" else quote["bid_price_1"] - tick
        return _round_price(raw, tick)

    def _reprice_order(self, order: dict[str, Any]) -> dict[str, Any]:
        tick = PRODUCT_SPECS[order["product"]]["price_tick"]
        quote = self._quote(order["vt_symbol"], tick)
        return {**order, "price": self._protected_price(order["direction"], quote, tick)}

    def _signed_positions(self, positions: dict[str, dict[str, Any]]) -> dict[str, int]:
        return {vt: int(row["signed_quantity"]) for vt, row in sorted(positions.items()) if row["signed_quantity"]}

    def _apply_orders(self, start: dict[str, int], orders: list[dict[str, Any]]) -> dict[str, int]:
        result = dict(start)
        for order in orders:
            delta = order["volume"] if order["direction"] == "long" else -order["volume"]
            result[order["vt_symbol"]] = result.get(order["vt_symbol"], 0) + delta
            if result[order["vt_symbol"]] == 0:
                result.pop(order["vt_symbol"])
        return dict(sorted(result.items()))

    def _active_strategy_orders(self) -> list[str]:
        active: list[str] = []
        for order in self.rpc.get_orders():
            reference = str(order.get("reference") or "")
            status = _normalize_status(order.get("status"))
            if reference.startswith(REFERENCE_PREFIX) and status in ACTIVE_ORDER_STATUSES:
                active.append(str(order.get("vt_orderid") or order.get("orderid") or "unknown"))
        return sorted(active)

    def _execution_snapshot(self, plan: dict[str, Any]) -> dict[str, Any]:
        try:
            orders = self.rpc.get_orders()
            trades = self.rpc.get_trades()
        except Exception as exc:
            return {
                "captured_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
                "available": False,
                "error_type": exc.__class__.__name__,
                "orders": [],
            }

        order_by_id: dict[str, dict[str, Any]] = {}
        for order in orders:
            for order_id in self._order_ids(order):
                order_by_id[order_id] = order

        rows: list[dict[str, Any]] = []
        expected_volume = 0
        filled_volume = 0.0
        adverse_slippage_ticks_volume = 0.0
        slippage_cny = 0.0
        for phase in ("close", "open"):
            for submitted in plan["submitted"][phase]:
                expected = int(submitted["volume"])
                expected_volume += expected
                ids = self._order_ids(submitted)
                matching_trades = [
                    trade for trade in trades if ids.intersection(self._order_ids(trade))
                ]
                fill_volume = sum(float(trade.get("volume") or 0) for trade in matching_trades)
                fill_notional = sum(
                    float(trade.get("price") or 0) * float(trade.get("volume") or 0)
                    for trade in matching_trades
                )
                average_fill_price = fill_notional / fill_volume if fill_volume else None
                decision_price = float(submitted["decision_price"])
                tick = float(PRODUCT_SPECS[submitted["product"]]["price_tick"])
                multiplier = float(PRODUCT_SPECS[submitted["product"]]["multiplier"])
                direction_factor = 1.0 if submitted["direction"] == "long" else -1.0
                adverse_ticks = (
                    direction_factor * (average_fill_price - decision_price) / tick
                    if average_fill_price is not None
                    else None
                )
                order = next((order_by_id[order_id] for order_id in ids if order_id in order_by_id), {})
                rows.append(
                    {
                        "phase": phase,
                        "vt_orderid": submitted.get("vt_orderid"),
                        "product": submitted["product"],
                        "vt_symbol": submitted["vt_symbol"],
                        "direction": submitted["direction"],
                        "offset": submitted["offset"],
                        "expected_volume": expected,
                        "filled_volume": fill_volume,
                        "fill_ratio": min(fill_volume / expected, 1.0) if expected else 0.0,
                        "decision_price": decision_price,
                        "submit_price": float(submitted["price"]),
                        "average_fill_price": average_fill_price,
                        "adverse_slippage_ticks": adverse_ticks,
                        "slippage_cny": (
                            direction_factor
                            * (average_fill_price - decision_price)
                            * multiplier
                            * fill_volume
                            if average_fill_price is not None
                            else None
                        ),
                        "trade_count": len(matching_trades),
                        "order_status": _normalize_status(order.get("status")) if order else "unknown",
                    }
                )
                filled_volume += fill_volume
                if adverse_ticks is not None:
                    adverse_slippage_ticks_volume += adverse_ticks * fill_volume
                    slippage_cny += (
                        direction_factor
                        * (average_fill_price - decision_price)
                        * multiplier
                        * fill_volume
                    )

        return {
            "captured_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
            "available": True,
            "expected_volume": expected_volume,
            "filled_volume": filled_volume,
            "fill_ratio": min(filled_volume / expected_volume, 1.0) if expected_volume else 1.0,
            "average_adverse_slippage_ticks": (
                adverse_slippage_ticks_volume / filled_volume if filled_volume else None
            ),
            "slippage_cny": slippage_cny if filled_volume else None,
            "orders": rows,
        }

    def _order_ids(self, row: dict[str, Any]) -> set[str]:
        ids = {
            str(value)
            for value in (row.get("vt_orderid"), row.get("orderid"))
            if value is not None and str(value)
        }
        ids.update(value.rsplit(".", 1)[-1] for value in list(ids) if "." in value)
        return ids

    def _load_completed_state(self) -> dict[str, Any]:
        path = Path(self.settings.commodity_simnow_state_path)
        if not path.exists():
            return {"last_completed_batch_hash": None, "targets": []}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("invalid state shape")
            if payload.get("schema_version") != "commodity_static_core_equal_completed_state_v1":
                raise ValueError("invalid state schema")
            last_hash = payload.get("last_completed_batch_hash")
            if not isinstance(last_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", last_hash):
                raise ValueError("invalid state batch hash")
            targets = payload.get("targets")
            if not isinstance(targets, list) or len(targets) != len(PRODUCT_SPECS):
                raise ValueError("invalid state targets")
            products = [row.get("product") for row in targets if isinstance(row, dict)]
            if len(products) != len(targets) or set(products) != set(PRODUCT_SPECS):
                raise ValueError("invalid state products")
            for row in targets:
                product = row["product"]
                spec = PRODUCT_SPECS[product]
                exact = row.get("exact_contract")
                if not isinstance(exact, str) or not re.fullmatch(
                    rf"{re.escape(spec['exchange'])}\.{product}\d{{4}}", exact
                ):
                    raise ValueError("invalid state contract")
                quantity = row.get("target_quantity")
                if not isinstance(quantity, int) or isinstance(quantity, bool) or abs(quantity) > 500:
                    raise ValueError("invalid state quantity")
            return payload
        except Exception as exc:
            self._state_load_error = exc.__class__.__name__
            return {"last_completed_batch_hash": None, "targets": []}

    def _save_completed_state(self, plan: dict[str, Any]) -> None:
        payload = {
            "schema_version": "commodity_static_core_equal_completed_state_v1",
            "last_completed_batch_hash": plan["batch_hash"],
            "updated_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
            "execution_lane": plan["execution_lane"],
            "countable_forward": plan["countable_forward"],
            "source_month": plan["source_month"],
            "execution_day": plan["execution_day"],
            "roll_products": plan.get("roll_products", []),
            "targets": [
                {
                    "product": row["product"],
                    "exact_contract": row["exact_contract"],
                    "target_quantity": row["target_quantity"],
                }
                for row in plan["targets"]
            ],
            "execution": plan.get("execution"),
        }
        path = Path(self.settings.commodity_simnow_state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        self._completed_state = payload

    def _event(
        self,
        event_type: str,
        *,
        plan_hash: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        self.events.append(
            {
                "event_time_utc": self.clock().astimezone(timezone.utc).isoformat(),
                "event_type": event_type,
                "plan_hash": plan_hash,
                "result": result or {},
            }
        )
        if len(self.events) > 1000:
            self.events = self.events[-1000:]


commodity_simnow_service = CommoditySimNowService()
