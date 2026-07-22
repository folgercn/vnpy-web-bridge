from __future__ import annotations

import asyncio
import base64
import binascii
import calendar
import hashlib
import json
import logging
import math
import re
import uuid
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
    AppError,
    CommoditySimNowBatchError,
    CommoditySimNowDisabledError,
    CommoditySimNowSafetyError,
    CommoditySimNowStateError,
)
from app.schemas.commodity_simnow import (
    CommodityPlanExecuteRequestDTO,
    CommodityPositionManagerShadowDTO,
    CommoditySimNowDisableRequestDTO,
    CommoditySimNowEnableRequestDTO,
    CommodityTemplateStartRequestDTO,
    CommodityTargetBatchDTO,
)
from app.schemas.common import STATUS_VALUE_MAP
from app.schemas.trade import OrderRequestDTO
from app.services.audit_service import AuditService, audit_service
from app.services.calendar_service import calendar_service
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

POSITION_MANAGER_SECTOR_MAP_V1: dict[str, str] = {
    "ag": "precious",
    "al": "nonferrous",
    "au": "precious",
    "bu": "energy_chemical",
    "cu": "nonferrous",
    "rb": "ferrous",
    "ru": "energy_chemical",
    "sc": "energy",
    "sp": "light_industry",
    "zn": "nonferrous",
}
POSITION_MANAGER_GENESIS_SOURCE_MONTH = "2026-08"


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
        self.current_plan = self._load_active_plan()

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
            "submission_outcome_grace_seconds": (
                self.settings.commodity_simnow_submission_outcome_grace_seconds
            ),
            "submission_outcome_min_empty_snapshots": (
                self.settings.commodity_simnow_submission_outcome_min_empty_snapshots
            ),
            "acceptance_passive_limit_enabled": (
                self.settings.commodity_simnow_acceptance_passive_limit_enabled
            ),
            "acceptance_passive_limit_ttl_seconds": (
                self.settings.commodity_simnow_acceptance_passive_limit_ttl_seconds
            ),
            "acceptance_max_total_orders": self.settings.commodity_simnow_acceptance_max_total_orders,
            "acceptance_max_total_lots": self.settings.commodity_simnow_acceptance_max_total_lots,
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
            "position_manager_shadow": self._position_manager_shadow_snapshot(
                include_targets=False
            ),
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
        if self.current_plan and self.current_plan.get("status") != "COMPLETE":
            self._begin_safe_halt(
                "process_restart_recovery",
                operator="commodity-simnow-recovery",
                source_ip=None,
            )
        if self._task or not self.settings.commodity_simnow_enabled:
            return
        self._task = asyncio.create_task(self._run_auto_dispatch_loop())

    async def stop(self) -> None:
        await asyncio.to_thread(
            self._begin_safe_halt,
            "service_stop",
            operator="commodity-simnow-shutdown",
            source_ip=None,
        )
        if not self._task:
            return
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
        self._resume_halted_plan_after_authorization()
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
        halt = self._begin_safe_halt(
            payload.reason,
            operator=operator,
            source_ip=source_ip,
        )
        self.enabled = False
        self.manual_approval = False
        self.simnow_mode = False
        self.auto_dispatch_authorized = False
        self.template_authorized = False
        result = {**self.status(), "reason": payload.reason, "halt": halt}
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
        if self.current_plan and self.current_plan.get("status") not in {
            "COMPLETE",
            "HALTED_RECONCILED",
            "HALTED_PRE_SUBMIT_SAFE",
        }:
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
            if self.current_plan and self.current_plan.get("status") in {"READY_CLOSE", "READY_OPEN"}:
                self._begin_safe_halt(
                    "strategy_template_start_failed",
                    operator=operator,
                    source_ip=source_ip,
                )
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
            "CANCEL_PENDING",
            "SUBMISSION_OUTCOME_UNKNOWN",
            "HALTED_RECONCILE_REQUIRED",
            "HALTED_RECONCILED",
            "HALTED_PRE_SUBMIT_SAFE",
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
        exposure_snapshot = self._verify_realtime_exposures(
            [row.model_dump(mode="json") for row in batch.targets],
            final_positions,
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
            "preview_exposure_snapshot": exposure_snapshot,
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
            "send_intents": {"close": [], "open": []},
            "submitted_at_utc": {"close": None, "open": None},
            "latest_exposure_snapshot": exposure_snapshot,
        }
        self._persist_active_plan()
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
        if dispatch_mode not in {"manual", "auto", "shakedown_auto"}:
            raise CommoditySimNowSafetyError("未知派单模式")
        if dispatch_mode == "auto":
            if not self._auto_dispatch_allowed():
                raise CommoditySimNowSafetyError("SimNow 自动派单未授权")
        elif dispatch_mode == "shakedown_auto":
            if not self._position_manager_shakedown_auto_dispatch_allowed():
                raise CommoditySimNowSafetyError("候选 SimNow 自动派单未授权")
        elif not (payload.confirm and payload.confirm_simnow_only and payload.confirm_manual_one_shot):
            raise CommoditySimNowSafetyError("执行确认不完整")
        plan = self._require_plan(payload.plan_hash)
        if plan.get("position_manager_shakedown_session_id"):
            self._verify_position_manager_shakedown_execution_trust(plan)
        use_acceptance_passive_limit = payload.acceptance_passive_limit
        if use_acceptance_passive_limit:
            if dispatch_mode != "manual":
                raise CommoditySimNowSafetyError("被动限价验收模式只允许人工单次派单")
            if not payload.confirm_acceptance_passive_limit:
                raise CommoditySimNowSafetyError("被动限价验收确认不完整")
            if not self.settings.commodity_simnow_acceptance_passive_limit_enabled:
                raise CommoditySimNowSafetyError("被动限价验收模式未启用")
            if plan["execution_lane"] != "simnow_shakedown":
                raise CommoditySimNowSafetyError("被动限价验收模式只允许 SimNow shakedown")
        execution_day = datetime.fromisoformat(plan["execution_day"]).date()
        current_trading_day = self._current_trading_day(self._plan_symbols(plan))
        if execution_day != current_trading_day:
            raise CommoditySimNowStateError(
                "计划已过执行日，不允许提交委托",
                detail={
                    "execution_day": execution_day.isoformat(),
                    "current_trading_day": current_trading_day.isoformat(),
                },
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
        if plan.get("position_manager_shakedown_session_id"):
            conflicts = self._position_manager_shakedown_external_active_orders(plan)
            if conflicts:
                self._begin_safe_halt(
                    "external_active_order", operator=operator, source_ip=source_ip,
                    phase=payload.phase,
                )
                raise CommoditySimNowStateError("存在外部活动委托，候选测试已安全停机", detail={"active_orders": conflicts})
        orders = list(plan[f"{payload.phase}_orders"])
        if not orders:
            raise CommoditySimNowStateError("该阶段没有待提交委托")

        repriced_orders = [
            self._reprice_order(order, passive=use_acceptance_passive_limit) for order in orders
        ]
        if use_acceptance_passive_limit:
            self._verify_acceptance_passive_limits(repriced_orders)
        self._verify_phase_symbol_position_limit(repriced_orders, self._position_snapshot())
        if payload.phase == "open":
            prices = {order["vt_symbol"]: float(order["price"]) for order in repriced_orders}
            plan["latest_exposure_snapshot"] = self._verify_realtime_exposures(
                plan["targets"],
                plan["expected_final_positions"],
                price_overrides=prices,
                sector_map=(
                    POSITION_MANAGER_SECTOR_MAP_V1
                    if plan.get("risk_sector_map_id") == "POSITION_MANAGER_SECTOR_MAP_V1"
                    else None
                ),
            )

        plan.pop("halt", None)
        plan["status"] = f"SUBMITTING_{payload.phase.upper()}"
        self._persist_active_plan()
        submitted: list[dict[str, Any]] = []
        current_intent: dict[str, Any] | None = None
        try:
            for order, repriced in zip(orders, repriced_orders, strict=True):
                intent = {
                    **repriced,
                    "decision_price": order["price"],
                    "dispatch_mode": dispatch_mode,
                    "price_mode": "acceptance_passive" if use_acceptance_passive_limit else "protected",
                    "intent_status": "PENDING_SEND",
                    "intent_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
                }
                intents = plan.setdefault("send_intents", {}).setdefault(payload.phase, [])
                existing_intent = next(
                    (row for row in intents if row.get("reference") == repriced["reference"]),
                    None,
                )
                if existing_intent is None:
                    intents.append(intent)
                else:
                    existing_intent.clear()
                    existing_intent.update(intent)
                    intent = existing_intent
                current_intent = intent
                self._persist_active_plan()
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
                submitted_row = {
                    **repriced,
                    "decision_price": order["price"],
                    "dispatch_mode": dispatch_mode,
                    "price_mode": "acceptance_passive" if use_acceptance_passive_limit else "protected",
                    **result,
                }
                intent["intent_status"] = "ACKNOWLEDGED"
                intent["acknowledged_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
                intent.update(
                    {
                        key: value
                        for key, value in result.items()
                        if key in {"vt_orderid", "orderid", "accepted"}
                    }
                )
                submitted.append(submitted_row)
                plan["submitted"][payload.phase].append(submitted_row)
                self._persist_active_plan()
                self.order_endpoint_touched = True
        except Exception as exc:
            if current_intent is not None:
                deterministic_rejection = self._is_deterministic_pre_rpc_rejection(exc)
                current_intent["intent_status"] = (
                    "REJECTED_PRE_RPC" if deterministic_rejection else "OUTCOME_UNKNOWN"
                )
                current_intent["error_type"] = exc.__class__.__name__
                current_intent["error_code"] = getattr(exc, "code", None)
                current_intent["failed_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
            plan["status"] = f"{payload.phase.upper()}_SUBMISSION_PARTIAL"
            self._persist_active_plan()
            halt = self._begin_safe_halt(
                "partial_submission",
                operator=operator,
                source_ip=source_ip,
                phase=payload.phase,
            )
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
                result={"submitted": submitted, "status": plan["status"], "halt": halt},
                error=str(exc),
                error_code=getattr(exc, "code", None),
                source_ip=source_ip,
            )
            raise CommoditySimNowStateError(
                (
                    "委托部分提交，必须人工检查并处理"
                    if submitted
                    else "首单提交结果已进入 send-intent outcome 确认"
                ),
                detail={
                    "phase": payload.phase,
                    "submitted_order_ids": [row.get("vt_orderid") for row in submitted],
                    "intent_status": current_intent.get("intent_status") if current_intent else None,
                    "plan_status": plan.get("status"),
                },
            ) from exc

        plan["submitted_at_utc"][payload.phase] = self.clock().astimezone(timezone.utc).isoformat()
        if use_acceptance_passive_limit:
            plan["acceptance_passive"] = {
                "phase": payload.phase,
                "submitted_at_utc": plan["submitted_at_utc"][payload.phase],
                "ttl_seconds": self.settings.commodity_simnow_acceptance_passive_limit_ttl_seconds,
                "max_total_orders": self.settings.commodity_simnow_acceptance_max_total_orders,
                "max_total_lots": self.settings.commodity_simnow_acceptance_max_total_lots,
            }
        plan["status"] = f"{payload.phase.upper()}_SUBMITTED"
        self._persist_active_plan()
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
        plan = self._require_plan(plan_hash)
        halted_reconcile = plan["status"] in {
            "CANCEL_PENDING",
            "HALTED_RECONCILE_REQUIRED",
            "HALTED_RECONCILED",
        }
        if not halted_reconcile:
            self._require_enabled()
        safety = self._safety_snapshot(
            require_trade_enabled=not halted_reconcile,
            allow_emergency_stopped=halted_reconcile,
        )
        if safety["account_hash"] != plan["account_hash"]:
            raise CommoditySimNowSafetyError("SimNow 账户在 preview 后发生变化")
        if plan["status"] not in {
            "CLOSE_SUBMITTED",
            "OPEN_SUBMITTED",
            "CANCEL_PENDING",
            "HALTED_RECONCILE_REQUIRED",
            "HALTED_RECONCILED",
        }:
            raise CommoditySimNowStateError(
                "当前状态不允许对账", detail={"status": plan["status"]}
            )
        if plan.get("position_manager_shakedown_session_id"):
            conflicts = self._position_manager_shakedown_external_active_orders(plan)
            if conflicts:
                self._begin_safe_halt(
                    "external_active_order", operator=operator, source_ip=source_ip
                )
                raise CommoditySimNowStateError(
                    "存在外部活动委托，候选测试已安全停机", detail={"active_orders": conflicts}
                )
        active = [row["vt_orderid"] for row in self._active_plan_orders(plan)]
        observed = self._signed_positions(self._position_snapshot())
        plan["execution"] = self._execution_snapshot(plan)
        if halted_reconcile:
            phase = str(plan.get("halt", {}).get("phase") or self._infer_plan_phase(plan))
        else:
            phase = "close" if plan["status"] == "CLOSE_SUBMITTED" else "open"
        nominal_expected = plan["expected_after_close"] if phase == "close" else plan["expected_final_positions"]
        if halted_reconcile:
            confirmed_expected = self._halt_reconciliation_expected_positions(plan, phase)
            candidates = [candidate for candidate in (confirmed_expected, nominal_expected) if candidate is not None]
            expected = next((candidate for candidate in candidates if observed == candidate), confirmed_expected)
            matched = not active and expected is not None and observed == expected
        else:
            expected = nominal_expected
            matched = not active and observed == expected
        reconciliation_mismatch = False
        if halted_reconcile:
            plan["status"] = "CANCEL_PENDING" if active else (
                "HALTED_RECONCILED" if matched else "HALTED_RECONCILE_REQUIRED"
            )
            if matched:
                halt = plan.setdefault("halt", {})
                halt["reconciliation_expected_positions"] = expected
                pre_phase_expected = self._phase_pre_positions(plan, phase)
                if expected == pre_phase_expected:
                    halt["resume_status"] = f"READY_{phase.upper()}"
                else:
                    halt.pop("resume_status", None)
        elif not matched and not active and dispatch_mode == "auto":
            submitted_at = _parse_datetime(plan["submitted_at_utc"].get(phase))
            age = (
                (self.clock().astimezone(timezone.utc) - submitted_at).total_seconds()
                if submitted_at
                else float("inf")
            )
            if age >= self.settings.commodity_simnow_auto_dispatch_reconcile_grace_seconds:
                self._begin_safe_halt(
                    "reconciliation_mismatch",
                    operator=operator,
                    source_ip=source_ip,
                    phase=phase,
                )
                reconciliation_mismatch = True
        if not halted_reconcile:
            if matched and phase == "close":
                plan["status"] = "READY_OPEN" if plan["open_orders"] else "COMPLETE"
                plan.pop("halt", None)
            elif matched:
                plan["status"] = "COMPLETE"
                plan.pop("halt", None)
        if plan["status"] == "COMPLETE":
            if plan.get("position_manager_shakedown_session_id"):
                self._complete_position_manager_shakedown(plan, result={
                    "phase": phase,
                    "expected_positions": expected,
                    "observed_positions": observed,
                    "active_order_ids": active,
                })
            else:
                self._save_completed_state(plan)
        elif plan.get("position_manager_shakedown_session_id") and plan["status"] == "HALTED_RECONCILED":
            self._archive_position_manager_shakedown_terminal(plan)
        else:
            self._persist_active_plan()
        result = {
            **self.plan(),
            "reconciliation": {
                "phase": phase,
                "matched": matched,
                "active_order_ids": active,
                "expected_positions": expected,
                "observed_positions": observed,
                "mismatch_halted": reconciliation_mismatch,
                "halted_reconcile": halted_reconcile,
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
        if self.current_plan and self.current_plan.get("status") in {
            "CANCEL_PENDING",
            "SUBMISSION_OUTCOME_UNKNOWN",
        }:
            return self._advance_cancel_pending(
                operator=operator,
                source_ip=source_ip,
            )
        risk_status = self.risk.status()
        if (
            self.current_plan
            and self.current_plan.get("status") not in {"COMPLETE", "HALTED_RECONCILED"}
            and risk_status.get("emergency_stopped")
        ):
            halt = self._begin_safe_halt(
                "emergency_stop",
                operator=operator,
                source_ip=source_ip,
            )
            return {"action": "halted", "reason": "emergency_stop", "halt": halt, **self.status()}
        if not self._auto_dispatch_allowed():
            return {"action": "idle", "reason": "auto_dispatch_not_active", **self.status()}
        if not self.current_plan:
            return {"action": "idle", "reason": "no_plan", **self.status()}

        plan = self.current_plan
        status = plan["status"]
        if status in {"CLOSE_SUBMISSION_PARTIAL", "OPEN_SUBMISSION_PARTIAL"}:
            halt = self._begin_safe_halt(
                "partial_submission",
                operator=operator,
                source_ip=source_ip,
                phase="close" if status.startswith("CLOSE") else "open",
            )
            self._event(
                "auto_dispatch_halted",
                plan_hash=plan["plan_hash"],
                result={"reason": "partial_submission", "status": status},
            )
            return {"action": "halted", "reason": "partial_submission", "halt": halt, **self.status()}

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
    def auto_position_manager_shakedown_advance(
        self,
        *,
        operator: str = "commodity-position-manager-shakedown-auto",
        role: str | None = "system",
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        plan = self.current_plan
        if not plan or not plan.get("position_manager_shakedown_session_id"):
            return {"action": "idle", "reason": "no_shakedown_plan"}
        status = str(plan.get("status"))
        if status in {"CANCEL_PENDING", "SUBMISSION_OUTCOME_UNKNOWN"}:
            return self._advance_cancel_pending(operator=operator, source_ip=source_ip)
        if status in {"COMPLETE", "HALTED_RECONCILED", "HALTED_PRE_SUBMIT_SAFE"}:
            return {"action": "idle", "reason": f"shakedown_status_{status.lower()}", **self.position_manager_shakedown_status()}
        if status == "HALTED_RECONCILE_REQUIRED":
            result = self.reconcile(plan["plan_hash"], operator=operator, role=role, source_ip=source_ip, dispatch_mode="auto")
            return {"action": "halted_reconciled" if result["status"] == "HALTED_RECONCILED" else "halted_reconcile_required", **result}
        if self.risk.status().get("emergency_stopped"):
            halt = self._begin_safe_halt("emergency_stop", operator=operator, source_ip=source_ip)
            return {"action": "halted", "reason": "emergency_stop", "halt": halt}
        if not self._position_manager_shakedown_auto_dispatch_allowed():
            halt = self._begin_safe_halt("shakedown_auto_dispatch_not_active", operator=operator, source_ip=source_ip)
            return {"action": "halted", "reason": "shakedown_auto_dispatch_not_active", "halt": halt}
        if status in {"READY_CLOSE", "READY_OPEN"}:
            phase = "close" if status == "READY_CLOSE" else "open"
            try:
                self._verify_position_manager_shakedown_execution_trust(plan)
            except CommoditySimNowSafetyError as exc:
                halt = self._begin_safe_halt("shakedown_execution_trust_failed", operator=operator, source_ip=source_ip, phase=phase)
                return {"action": "halted", "reason": "shakedown_execution_trust_failed", "halt": halt, "error_type": exc.__class__.__name__}
            result = self.execute(
                CommodityPlanExecuteRequestDTO(
                    plan_hash=plan["plan_hash"], phase=phase, confirm=True,
                    confirm_simnow_only=True, confirm_manual_one_shot=True,
                    reason=f"authorized position-manager shakedown {phase} dispatch",
                ),
                operator=operator, role=role, source_ip=source_ip, dispatch_mode="shakedown_auto",
            )
            return {"action": f"{phase}_submitted", **result}
        if status in {"CLOSE_SUBMITTED", "OPEN_SUBMITTED"}:
            phase = "close" if status == "CLOSE_SUBMITTED" else "open"
            result = self.reconcile(plan["plan_hash"], operator=operator, role=role, source_ip=source_ip, dispatch_mode="auto")
            if result["status"] == "READY_OPEN":
                return self.auto_position_manager_shakedown_advance(
                    operator=operator, role=role, source_ip=source_ip
                )
            return {"action": f"{phase}_reconciled", **result}
        halt = self._begin_safe_halt("unexpected_shakedown_plan_status", operator=operator, source_ip=source_ip)
        return {"action": "halted", "halt": halt}

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
        current_trading_day = self._current_trading_day(
            self._plan_symbols(self.current_plan) if self.current_plan else None
        )
        if self.current_plan and self.current_plan.get("status") != "COMPLETE":
            execution_day = datetime.fromisoformat(self.current_plan["execution_day"]).date()
            if execution_day != current_trading_day:
                halt = self._begin_safe_halt(
                    "active_plan_execution_day_expired",
                    operator=operator,
                    source_ip=source_ip,
                )
                result = {
                    "action": "halted",
                    "reason": "active_plan_execution_day_expired",
                    "execution_day": execution_day.isoformat(),
                    "current_trading_day": current_trading_day.isoformat(),
                    "status": self.current_plan.get("status"),
                    "plan_hash": self.current_plan.get("plan_hash"),
                    "halt": halt,
                }
                self._event(
                    "strategy_template_active_plan_expired",
                    plan_hash=self.current_plan.get("plan_hash"),
                    result=result,
                )
                return result
            expiry_halt = self._halt_if_delivery_guard_breached(current_trading_day)
            if expiry_halt:
                return expiry_halt
            return {
                "action": "idle",
                "reason": "plan_active",
                "status": self.current_plan.get("status"),
                "plan_hash": self.current_plan.get("plan_hash"),
            }

        batch = self._load_template_batch()
        batch_trading_day = self._current_trading_day(
            [_exact_to_vt(row.exact_contract) for row in batch.targets]
        )
        if batch.execution_day > batch_trading_day:
            expiry_halt = self._halt_if_delivery_guard_breached(batch_trading_day)
            if expiry_halt:
                return expiry_halt
            return {
                "action": "waiting",
                "reason": "target_execution_day_not_reached",
                "execution_day": batch.execution_day.isoformat(),
            }
        if batch.execution_day < batch_trading_day:
            expiry_halt = self._halt_if_delivery_guard_breached(batch_trading_day)
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
            expiry_halt = self._halt_if_delivery_guard_breached(batch_trading_day)
            if expiry_halt:
                return expiry_halt
            return {
                "action": "idle",
                "reason": "target_already_loaded",
                "status": self.current_plan.get("status"),
                "plan_hash": self.current_plan.get("plan_hash"),
            }
        if self._completed_state.get("last_completed_batch_hash") == batch_hash:
            expiry_halt = self._halt_if_delivery_guard_breached(batch_trading_day)
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
                await asyncio.to_thread(self._acceptance_passive_ttl_advance)
                recovery_pending = bool(
                    self.current_plan
                    and self.current_plan.get("status")
                    in {"CANCEL_PENDING", "SUBMISSION_OUTCOME_UNKNOWN"}
                )
                shakedown_plan = bool(
                    self.current_plan
                    and self.current_plan.get("position_manager_shakedown_session_id")
                )
                if shakedown_plan:
                    await asyncio.to_thread(self.auto_position_manager_shakedown_advance)
                elif recovery_pending:
                    await asyncio.to_thread(self.auto_advance)
                elif self.settings.commodity_simnow_auto_dispatch_enabled and self.template_authorized:
                    await asyncio.to_thread(self.auto_template_advance)
                elif self.settings.commodity_simnow_auto_dispatch_enabled:
                    await asyncio.to_thread(self.auto_advance)
            except Exception:
                logger.exception("commodity SimNow auto-dispatch cycle failed")
            await asyncio.sleep(self.settings.commodity_simnow_auto_dispatch_interval_seconds)

    @_serialized
    def _acceptance_passive_ttl_advance(self) -> dict[str, Any]:
        plan = self.current_plan
        if not plan or plan.get("status") not in {"CLOSE_SUBMITTED", "OPEN_SUBMITTED"}:
            return {"action": "idle", "reason": "no_active_acceptance_passive_plan"}
        acceptance = plan.get("acceptance_passive")
        if not isinstance(acceptance, dict):
            return {"action": "idle", "reason": "not_acceptance_passive"}
        submitted_at = _parse_datetime(acceptance.get("submitted_at_utc"))
        if submitted_at is None:
            raise CommoditySimNowStateError("被动限价验收计划缺少提交时间")
        ttl_seconds = int(acceptance.get("ttl_seconds") or 0)
        if ttl_seconds <= 0:
            raise CommoditySimNowStateError("被动限价验收计划 TTL 无效")
        elapsed = (self.clock().astimezone(timezone.utc) - submitted_at).total_seconds()
        if elapsed < ttl_seconds:
            return {
                "action": "idle",
                "reason": "acceptance_passive_ttl_not_expired",
                "remaining_seconds": max(0.0, round(ttl_seconds - elapsed, 3)),
            }
        phase = str(acceptance.get("phase") or self._infer_plan_phase(plan))
        halt = self._begin_safe_halt(
            "acceptance_passive_ttl_expired",
            operator="commodity-simnow-acceptance-ttl",
            source_ip=None,
            phase=phase,
        )
        self._event(
            "acceptance_passive_ttl_expired",
            plan_hash=plan.get("plan_hash"),
            result={"phase": phase, "ttl_seconds": ttl_seconds, "halt": halt},
        )
        return {"action": "halted", "reason": "acceptance_passive_ttl_expired", "halt": halt}

    def _verify_acceptance_passive_limits(self, orders: list[dict[str, Any]]) -> None:
        total_orders = len(orders)
        total_lots = sum(int(order["volume"]) for order in orders)
        maximum_orders = self.settings.commodity_simnow_acceptance_max_total_orders
        maximum_lots = self.settings.commodity_simnow_acceptance_max_total_lots
        if total_orders > maximum_orders or total_lots > maximum_lots:
            raise CommoditySimNowSafetyError(
                "被动限价验收规模超过硬上限",
                detail={
                    "total_orders": total_orders,
                    "max_total_orders": maximum_orders,
                    "total_lots": total_lots,
                    "max_total_lots": maximum_lots,
                },
            )

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

    @_serialized
    def position_manager_shadow(self) -> dict[str, Any]:
        return self._position_manager_shadow_snapshot(include_targets=True)

    @_serialized
    def position_manager_shakedown_status(self) -> dict[str, Any]:
        """Return the separately persisted candidate test session."""
        session = self._load_position_manager_shakedown_state()
        active = self.current_plan
        if (
            session
            and active
            and active.get("position_manager_shakedown_session_id") == session.get("session_id")
        ):
            session = {
                **session,
                "status": active.get("status"),
                "execution": {
                    "started_at_utc": active.get("started_at_utc"),
                    "submitted": active.get("submitted", {}),
                    "send_intents": active.get("send_intents", {}),
                    "halt": active.get("halt"),
                },
            }
        return {
            "configured": self.settings.commodity_position_manager_simnow_shakedown_enabled,
            "execution_enabled": self._position_manager_shakedown_auto_dispatch_allowed(),
            "auto_dispatch_enabled": self.settings.commodity_position_manager_simnow_auto_dispatch_enabled,
            "execution_lane": "simnow_shakedown",
            "countable_forward": False,
            "session": session,
        }

    @_serialized
    def preview_position_manager_shakedown(
        self,
        selected_products: list[str],
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        """Persist a read-only execution mask; C1 deliberately never creates orders."""
        if not self.settings.commodity_position_manager_simnow_shakedown_enabled:
            raise CommoditySimNowDisabledError(
                detail={"required_setting": "COMMODITY_POSITION_MANAGER_SIMNOW_SHAKEDOWN_ENABLED=true"}
            )
        existing = self._load_position_manager_shakedown_state()
        if (
            self.current_plan
            and self.current_plan.get("position_manager_shakedown_session_id")
            and self.current_plan.get("status") not in {"COMPLETE", "HALTED_RECONCILED"}
        ) or (
            existing
            and existing.get("status") not in {"PREVIEW_READY", "COMPLETE", "HALTED_RECONCILED"}
        ):
            raise CommoditySimNowStateError("存在未收口的候选测试会话，禁止覆盖预览")
        selected = sorted(set(selected_products))
        if (
            len(selected) != len(selected_products)
            or len(selected)
            > self.settings.commodity_position_manager_simnow_max_selected_products
        ):
            raise CommoditySimNowSafetyError("测试品种选择无效")
        shadow = self._position_manager_shadow_snapshot(include_targets=True)
        if (
            not shadow.get("valid")
            or shadow.get("baseline_link_state") not in {"active", "completed"}
            or shadow.get("continuity_state") not in {"genesis", "verified"}
        ):
            raise CommoditySimNowSafetyError("Shadow、baseline 关联或连续性未通过，禁止生成测试预览")
        rows = {str(row["product"]): row for row in shadow.get("targets", [])}
        if set(rows) != set(PRODUCT_SPECS) or any(product not in rows for product in selected):
            raise CommoditySimNowSafetyError("签名候选缺少固定十品种目标")
        safety = self._safety_snapshot(require_trade_enabled=True)
        _, baseline = self._position_manager_linked_baseline(
            str(shadow["baseline_batch_hash"]), require_settled=True
        )
        if baseline is None:
            raise CommoditySimNowSafetyError("已关联 baseline 不可读取")
        conflicts = self._position_manager_shakedown_active_orders(set(PRODUCT_SPECS))
        if conflicts:
            raise CommoditySimNowStateError(
                "存在固定十品种的活动策略委托，禁止启动候选测试",
                detail={"active_orders": conflicts},
            )
        chosen = []
        for product in selected:
            row = rows[product]
            delta = int(row["shadow_target_quantity"]) - int(row["baseline_target_quantity"])
            if not delta:
                raise CommoditySimNowSafetyError("零目标差异品种不可用于候选测试", detail={"product": product})
            chosen.append({
                "product": product,
                "exact_contract": row["exact_contract"],
                "baseline_target_quantity": row["baseline_target_quantity"],
                "shadow_target_quantity": row["shadow_target_quantity"],
                "target_delta": delta,
                "reference_open_price": row["reference_open_price"],
                "multiplier": row["multiplier"],
                "price_tick": row["price_tick"],
            })
        session_id = f"pm-shakedown-{uuid.uuid4().hex}"
        plan = self._build_position_manager_shakedown_plan(
            chosen, baseline=baseline, session_id=session_id
        )
        session_core = {
            "session_id": session_id,
            "execution_lane": "simnow_shakedown",
            "countable_forward": False,
            "candidate_id": "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
            "baseline_scheduler_id": "STATIC_CORE_EQUAL",
            "source_snapshot_hash": shadow["snapshot_hash"],
            "baseline_batch_hash": shadow["baseline_batch_hash"],
            "account_hash": safety["account_hash"],
            "selected_products": selected,
            "targets": chosen,
            "plan": plan,
        }
        plan_hash = _sha256_json(session_core)
        session = {
            "schema_version": "commodity_relative_vol_simnow_shakedown_session_v1",
            **session_core,
            "plan_hash": plan_hash,
            "status": "PREVIEW_READY",
            "started_by": operator,
            "previewed_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
        }
        self._save_position_manager_shakedown_state(session)
        result = {**self.position_manager_shakedown_status(), "preview": session}
        self._event(
            "position_manager_shakedown_previewed",
            plan_hash=plan_hash,
            result={"selected_products": selected},
        )
        self.audit.record(
            action="commodity_position_manager_shakedown_preview",
            user_id=operator,
            role=role,
            request={"selected_products": selected},
            result=result,
            source_ip=source_ip,
        )
        return result

    @_serialized
    def start_position_manager_shakedown(
        self,
        plan_hash: str,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        """Start one pre-previewed SimNow shakedown without per-order approval."""
        if not self.settings.commodity_position_manager_simnow_shakedown_enabled:
            raise CommoditySimNowDisabledError(
                detail={"required_setting": "COMMODITY_POSITION_MANAGER_SIMNOW_SHAKEDOWN_ENABLED=true"}
            )
        self._require_enabled()
        if not self.settings.commodity_position_manager_simnow_auto_dispatch_enabled:
            raise CommoditySimNowDisabledError(
                detail={"required_setting": "COMMODITY_POSITION_MANAGER_SIMNOW_AUTO_DISPATCH_ENABLED=true"}
            )
        session = self._load_position_manager_shakedown_state()
        if not session or session.get("status") != "PREVIEW_READY":
            raise CommoditySimNowStateError("不存在可启动的候选测试预览")
        if session.get("plan_hash") != plan_hash:
            raise CommoditySimNowStateError("候选测试计划哈希不匹配")
        if self.current_plan and self.current_plan.get("status") not in {"COMPLETE", "HALTED_RECONCILED"}:
            raise CommoditySimNowStateError("存在未收口的 SimNow 计划")
        shadow = self._position_manager_shadow_snapshot(include_targets=True)
        if (
            not shadow.get("valid")
            or shadow.get("snapshot_hash") != session.get("source_snapshot_hash")
            or shadow.get("baseline_batch_hash") != session.get("baseline_batch_hash")
            or shadow.get("continuity_state") not in {"genesis", "verified"}
            or shadow.get("baseline_link_state") not in {"active", "completed"}
        ):
            raise CommoditySimNowSafetyError("Shadow 快照或 baseline 在 preview 后发生变化")
        safety = self._safety_snapshot(require_trade_enabled=True)
        if safety["account_hash"] != session.get("account_hash"):
            raise CommoditySimNowSafetyError("SimNow 账户在 preview 后发生变化")
        _, baseline = self._position_manager_linked_baseline(
            str(session["baseline_batch_hash"]), require_settled=True
        )
        if baseline is None:
            raise CommoditySimNowSafetyError("已关联 baseline 不可读取")
        stored_plan = session.get("plan")
        if not isinstance(stored_plan, dict):
            raise CommoditySimNowStateError("候选测试计划无效")
        # Rebuild all preconditions with live RPC/quotes.  The plan hash remains
        # immutable; any changed executable shape requires a new preview.
        rechecked = self._build_position_manager_shakedown_plan(
            list(session.get("targets") or []),
            baseline=baseline,
            session_id=str(session["session_id"]),
        )
        comparable_keys = (
            "close_orders", "open_orders", "expected_after_close", "expected_final_positions",
            "risk_targets", "sector_map_id",
        )
        if any(rechecked.get(key) != stored_plan.get(key) for key in comparable_keys if key not in {"close_orders", "open_orders"}) or any(
            self._position_manager_shakedown_order_shape(rechecked.get(key, []))
            != self._position_manager_shakedown_order_shape(stored_plan.get(key, []))
            for key in ("close_orders", "open_orders")
        ):
            raise CommoditySimNowSafetyError("候选测试预览已失效，请重新生成计划")
        execution_day = self._current_trading_day(self._plan_symbols_from_orders(stored_plan))
        plan = {
            "schema_version": "commodity_simnow_active_plan_v1",
            "position_manager_shakedown_session_id": session["session_id"],
            "plan_hash": plan_hash,
            "account_hash": safety["account_hash"],
            "source_snapshot_hash": session["source_snapshot_hash"],
            "baseline_batch_hash": session["baseline_batch_hash"],
            "execution_lane": "simnow_shakedown",
            "countable_forward": False,
            "execution_day": execution_day.isoformat(),
            "previous_positions": self._signed_positions(self._position_snapshot()),
            "expected_after_close": stored_plan["expected_after_close"],
            "expected_final_positions": stored_plan["expected_final_positions"],
            "close_orders": stored_plan["close_orders"],
            "open_orders": stored_plan["open_orders"],
            "targets": stored_plan["risk_targets"],
            "risk_sector_map_id": stored_plan["sector_map_id"],
            "submitted": {"close": [], "open": []},
            "send_intents": {"close": [], "open": []},
            "submitted_at_utc": {"close": None, "open": None},
            "status": stored_plan["phase_status"],
            "started_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
        }
        self.current_plan = plan
        self._persist_active_plan()
        execution = self.auto_position_manager_shakedown_advance(
            operator=operator, role=role, source_ip=source_ip
        )
        result = {
            **self.position_manager_shakedown_status(),
            "action": execution.get("action"),
            "execution": execution,
        }
        self._event("position_manager_shakedown_started", plan_hash=plan_hash, result=result)
        self.audit.record(
            action="commodity_position_manager_shakedown_start", user_id=operator, role=role,
            request={"plan_hash": plan_hash}, result=result, source_ip=source_ip,
        )
        return result

    @_serialized
    def stop_position_manager_shakedown(
        self, reason: str, *, operator: str, role: str | None, source_ip: str | None
    ) -> dict[str, Any]:
        plan = self.current_plan
        if not plan or not plan.get("position_manager_shakedown_session_id"):
            raise CommoditySimNowStateError("不存在运行中的候选测试会话")
        halt = self._begin_safe_halt(reason, operator=operator, source_ip=source_ip)
        result = {**self.position_manager_shakedown_status(), "halt": halt}
        self.audit.record(
            action="commodity_position_manager_shakedown_stop", user_id=operator, role=role,
            request={"reason": reason}, result=result, source_ip=source_ip,
        )
        return result

    def _build_position_manager_shakedown_plan(
        self,
        targets: list[dict[str, Any]],
        *,
        baseline: dict[str, Any],
        session_id: str,
    ) -> dict[str, Any]:
        """Adapt candidate targets to the verified two-phase plan shape without dispatching."""
        positions = self._position_snapshot()
        contracts = self._contract_snapshot()
        selected = {str(row["product"]) for row in targets}
        active_orders = self._position_manager_shakedown_active_orders(selected)
        if active_orders:
            raise CommoditySimNowStateError(
                "存在活动策略委托，不允许生成候选测试计划",
                detail={"active_order_ids": active_orders},
            )
        baseline_targets = {
            str(row["product"]): row for row in baseline.get("targets", [])
        }
        expected_baseline_positions = {
            _exact_to_vt(str(row["exact_contract"])): int(row["target_quantity"])
            for row in baseline_targets.values()
            if int(row["target_quantity"])
        }
        observed_baseline_positions = self._signed_positions(positions)
        if any(int(row["today_quantity"]) for row in positions.values()):
            raise CommoditySimNowSafetyError(
                "存在今日持仓，无法完整证明属于关联 baseline",
                detail={"observed": observed_baseline_positions},
            )
        if observed_baseline_positions != expected_baseline_positions:
            raise CommoditySimNowSafetyError(
                "账户持仓无法完整证明属于关联 baseline",
                detail={
                    "expected": expected_baseline_positions,
                    "observed": observed_baseline_positions,
                },
            )
        effective_targets = {
            product: dict(row) for product, row in baseline_targets.items()
        }
        by_product: dict[str, list[tuple[str, dict[str, Any]]]] = {
            product: [] for product in selected
        }
        for vt_symbol, row in positions.items():
            symbol, _ = _split_vt(vt_symbol)
            product = _product_from_symbol(symbol)
            if product in selected:
                by_product[product].append((vt_symbol, row))

        close_orders: list[dict[str, Any]] = []
        open_orders: list[dict[str, Any]] = []
        quote_rows: list[dict[str, Any]] = []
        details: list[dict[str, Any]] = []
        for row in sorted(targets, key=lambda item: str(item["product"])):
            product = str(row["product"])
            target_vt = _exact_to_vt(str(row["exact_contract"]))
            target_quantity = int(row["shadow_target_quantity"])
            self._verify_target_delivery(str(row["exact_contract"]), self._current_trading_day([target_vt]))
            self._verify_contract(target_vt, product, contracts)
            baseline_row = baseline_targets.get(product)
            if not isinstance(baseline_row, dict):
                raise CommoditySimNowSafetyError("关联 baseline 缺少测试品种", detail={"product": product})
            baseline_vt = _exact_to_vt(str(baseline_row["exact_contract"]))
            baseline_quantity = int(baseline_row["target_quantity"])
            # The session changes only selected products.  Realtime risk must
            # nevertheless be evaluated against the complete mixed portfolio:
            # selected products at their shadow target and every other product
            # at the settled baseline target.
            effective_targets[product] = {
                **baseline_row,
                "exact_contract": str(row["exact_contract"]),
                "target_quantity": target_quantity,
                "reference_open_price": row["reference_open_price"],
                "multiplier": row["multiplier"],
                "price_tick": row["price_tick"],
            }
            existing = sorted(by_product[product], key=lambda item: item[0])
            current_quantity = sum(int(item[1]["signed_quantity"]) for item in existing)
            if any(int(position["today_quantity"]) for _, position in existing):
                raise CommoditySimNowSafetyError(
                    "存在今日持仓，候选测试预览 fail closed",
                    detail={"product": product},
                )
            if len(existing) > 1 or (existing and (
                existing[0][0] != baseline_vt
                or int(existing[0][1]["signed_quantity"]) != baseline_quantity
            )) or (not existing and baseline_quantity):
                raise CommoditySimNowSafetyError(
                    "所选品种持仓无法证明属于关联 baseline",
                    detail={
                        "product": product,
                        "expected": {baseline_vt: baseline_quantity},
                        "observed": {
                            vt_symbol: int(position["signed_quantity"])
                            for vt_symbol, position in existing
                        },
                    },
                )
            same_contract = next(
                (int(position["signed_quantity"]) for vt_symbol, position in existing if vt_symbol == target_vt),
                0,
            )
            for vt_symbol, position in existing:
                quantity = int(position["signed_quantity"])
                if vt_symbol != target_vt:
                    self._verify_contract(vt_symbol, product, contracts)
                    close_orders.extend(
                        self._orders_for_leg(
                            "position-manager-shakedown",
                            product,
                            vt_symbol,
                            -quantity,
                            "closeyesterday",
                            quote_rows,
                        )
                    )
            delta = target_quantity - same_contract
            if same_contract and target_quantity and same_contract * target_quantity < 0:
                close_orders.extend(
                    self._orders_for_leg(
                        "position-manager-shakedown", product, target_vt, -same_contract,
                        "closeyesterday", quote_rows,
                    )
                )
                open_orders.extend(
                    self._orders_for_leg(
                        "position-manager-shakedown", product, target_vt, target_quantity,
                        "open", quote_rows,
                    )
                )
            elif same_contract and abs(target_quantity) < abs(same_contract):
                close_orders.extend(
                    self._orders_for_leg(
                        "position-manager-shakedown", product, target_vt, delta,
                        "closeyesterday", quote_rows,
                    )
                )
            elif delta:
                open_orders.extend(
                    self._orders_for_leg(
                        "position-manager-shakedown", product, target_vt, delta,
                        "open", quote_rows,
                    )
                )
            details.append({
                **row,
                "current_position": current_quantity,
                "planned_delta": target_quantity - current_quantity,
            })
        close_orders = self._number_position_manager_shakedown_references(
            close_orders, session_id, "close"
        )
        open_orders = self._number_position_manager_shakedown_references(
            open_orders, session_id, "open"
        )
        start = self._signed_positions(positions)
        after_close = self._apply_orders(start, close_orders)
        final_positions = self._apply_orders(after_close, open_orders)
        expected_final_positions = {
            _exact_to_vt(str(row["exact_contract"])): int(row["target_quantity"])
            for row in effective_targets.values()
            if int(row["target_quantity"])
        }
        if final_positions != expected_final_positions:
            raise CommoditySimNowSafetyError(
                "候选测试最终持仓未收敛到完整混合目标",
                detail={
                    "expected": expected_final_positions,
                    "observed": final_positions,
                },
            )
        exposure_snapshot = self._verify_realtime_exposures(
            list(effective_targets.values()),
            final_positions,
            sector_map=POSITION_MANAGER_SECTOR_MAP_V1,
        )
        limit = self.settings.commodity_simnow_max_orders_per_phase
        if len(close_orders) > limit or len(open_orders) > limit:
            raise CommoditySimNowSafetyError(
                "拆单数量超过单阶段上限",
                detail={
                    "close_orders": len(close_orders),
                    "open_orders": len(open_orders),
                    "limit": limit,
                },
            )
        return {
            "phase_status": "READY_CLOSE" if close_orders else "READY_OPEN" if open_orders else "COMPLETE",
            "close_orders": close_orders,
            "open_orders": open_orders,
            "order_count": len(close_orders) + len(open_orders),
            "total_lots": sum(int(order["volume"]) for order in close_orders + open_orders),
            "expected_after_close": after_close,
            "expected_final_positions": final_positions,
            "quote_snapshot_hash": _sha256_json(quote_rows),
            "preview_exposure_snapshot": exposure_snapshot,
            "targets": details,
            "risk_targets": list(effective_targets.values()),
            "sector_map_id": "POSITION_MANAGER_SECTOR_MAP_V1",
        }

    def _plan_symbols_from_orders(self, plan: dict[str, Any]) -> list[str]:
        return [
            str(order["vt_symbol"])
            for phase in ("close", "open")
            for order in plan.get(f"{phase}_orders", [])
        ]

    def _position_manager_shakedown_order_shape(self, orders: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{key: value for key, value in order.items() if key != "price"} for order in orders]

    def _number_position_manager_shakedown_references(
        self, orders: list[dict[str, Any]], session_id: str, phase: str
    ) -> list[dict[str, Any]]:
        nonce = session_id.rsplit("-", 1)[-1][:16]
        for index, order in enumerate(orders, start=1):
            order["reference"] = f"commodity_pm:sh:{nonce}:{phase[0]}:{index}"
        return orders

    def _position_manager_shakedown_active_orders(
        self, selected_products: set[str]
    ) -> list[dict[str, str]]:
        conflicts: list[dict[str, str]] = []
        for order in self.rpc.get_orders():
            if _normalize_status(order.get("status")) not in ACTIVE_ORDER_STATUSES:
                continue
            symbol = str(order.get("symbol") or "")
            if not symbol:
                vt_symbol = str(order.get("vt_symbol") or "")
                symbol = vt_symbol.split(".", 1)[0]
            if _product_from_symbol(symbol) not in selected_products:
                continue
            conflicts.append({
                "vt_orderid": str(order.get("vt_orderid") or order.get("orderid") or "unknown"),
                "reference": str(order.get("reference") or ""),
                "symbol": symbol,
            })
        return sorted(conflicts, key=lambda row: row["vt_orderid"])

    def _position_manager_shakedown_external_active_orders(
        self, plan: dict[str, Any]
    ) -> list[dict[str, str]]:
        session_references = {
            str(order.get("reference") or "")
            for phase in ("close", "open")
            for order in plan.get(f"{phase}_orders", [])
        }
        conflicts: list[dict[str, str]] = []
        for order in self.rpc.get_orders():
            if _normalize_status(order.get("status")) not in ACTIVE_ORDER_STATUSES:
                continue
            symbol = str(order.get("symbol") or str(order.get("vt_symbol") or "").split(".", 1)[0])
            if _product_from_symbol(symbol) not in PRODUCT_SPECS:
                continue
            reference = str(order.get("reference") or "")
            if reference in session_references:
                continue
            conflicts.append({
                "vt_orderid": str(order.get("vt_orderid") or order.get("orderid") or "unknown"),
                "reference": reference,
                "symbol": symbol,
            })
        return sorted(conflicts, key=lambda row: row["vt_orderid"])

    def _verify_position_manager_shakedown_execution_trust(self, plan: dict[str, Any]) -> None:
        shadow = self._position_manager_shadow_snapshot(include_targets=True)
        if (
            not shadow.get("valid")
            or shadow.get("snapshot_hash") != plan.get("source_snapshot_hash")
            or shadow.get("baseline_batch_hash") != plan.get("baseline_batch_hash")
            or shadow.get("continuity_state") not in {"genesis", "verified"}
            or shadow.get("baseline_link_state") not in {"active", "completed"}
        ):
            raise CommoditySimNowSafetyError("候选测试运行时 Shadow 信任链校验失败")
        _, baseline = self._position_manager_linked_baseline(
            str(plan.get("baseline_batch_hash") or ""), require_settled=True
        )
        if baseline is None:
            raise CommoditySimNowSafetyError("候选测试运行时 baseline 不可用")
        safety = self._safety_snapshot(require_trade_enabled=True)
        if safety["account_hash"] != plan.get("account_hash"):
            raise CommoditySimNowSafetyError("候选测试运行时 SimNow 账户发生变化")

    def _complete_position_manager_shakedown(self, plan: dict[str, Any], *, result: dict[str, Any]) -> None:
        session = self._load_position_manager_shakedown_state()
        if not session or session.get("session_id") != plan.get("position_manager_shakedown_session_id"):
            raise CommoditySimNowStateError("候选测试完成时会话证据缺失")
        session["status"] = "COMPLETE"
        session["completed_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
        session["execution"] = {
            "submitted": plan.get("submitted", {}),
            "send_intents": plan.get("send_intents", {}),
            "reconciliation": result,
            "final_positions": self._signed_positions(self._position_snapshot()),
            "execution_snapshot": self._execution_snapshot(plan),
        }
        self._save_position_manager_shakedown_state(session)

    def _archive_position_manager_shakedown_terminal(self, plan: dict[str, Any]) -> None:
        session = self._load_position_manager_shakedown_state()
        if not session or session.get("session_id") != plan.get("position_manager_shakedown_session_id"):
            raise CommoditySimNowStateError("候选测试终态会话证据缺失")
        session["status"] = str(plan["status"])
        session["completed_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
        session["execution"] = {"submitted": plan.get("submitted", {}), "send_intents": plan.get("send_intents", {}), "halt": plan.get("halt"), "final_positions": self._signed_positions(self._position_snapshot())}
        self._save_position_manager_shakedown_state(session)

    def _position_manager_shakedown_state_path(self) -> Path:
        return Path(self.settings.commodity_position_manager_simnow_state_path).expanduser()

    def _load_position_manager_shakedown_state(self) -> dict[str, Any] | None:
        path = self._position_manager_shakedown_state_path()
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or payload.get("schema_version")
                != "commodity_relative_vol_simnow_shakedown_session_v1"
            ):
                raise ValueError("invalid shakedown session")
            core = {
                key: value
                for key, value in payload.items()
                if key
                not in {
                    "schema_version",
                    "plan_hash",
                    "status",
                    "started_by",
                    "previewed_at_utc",
                    "completed_at_utc",
                    "execution",
                }
            }
            if _sha256_json(core) != payload.get("plan_hash"):
                raise ValueError("shakedown plan checksum mismatch")
            return payload
        except Exception as exc:
            return {"status": "RESULT_UNKNOWN", "error_type": exc.__class__.__name__}

    def _save_position_manager_shakedown_state(self, session: dict[str, Any]) -> None:
        path = self._position_manager_shakedown_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(json.dumps(session, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)

    def _position_manager_shadow_snapshot(self, *, include_targets: bool) -> dict[str, Any]:
        path_text = self.settings.commodity_position_manager_shadow_path.strip()
        if not path_text:
            return {
                "configured": False,
                "valid": False,
                "mode": "shadow_only",
                "authority_granted": False,
                "dispatch_allowed": False,
            }
        path = Path(path_text).expanduser()
        try:
            if not path.is_file():
                raise FileNotFoundError(path)
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("shadow snapshot exceeds 2 MiB")
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("shadow snapshot must contain one JSON object")
            snapshot = CommodityPositionManagerShadowDTO.model_validate(raw)
            snapshot_hash = self._verify_position_manager_shadow(snapshot)
            linked_state, baseline = self._position_manager_linked_baseline(
                snapshot.baseline_batch_hash
            )
            if baseline is not None:
                self._verify_position_manager_baseline(snapshot, baseline)
            continuity_state = self._verify_position_manager_continuity(
                snapshot, snapshot_hash
            )
            if baseline is not None:
                self._save_position_manager_shadow_state(
                    snapshot, snapshot_hash, continuity_state
                )
            targets = [row.model_dump(mode="json") for row in snapshot.targets]
            result: dict[str, Any] = {
                "configured": True,
                "valid": True,
                "snapshot_hash": snapshot_hash,
                "snapshot_id": snapshot.snapshot_id,
                "position_manager_id": snapshot.position_manager_id,
                "sector_map_id": snapshot.sector_map_id,
                "mode": snapshot.mode,
                "baseline_scheduler_id": snapshot.baseline_scheduler_id,
                "baseline_batch_hash": snapshot.baseline_batch_hash,
                "baseline_link_state": linked_state,
                "source_month": snapshot.source_month,
                "execution_day": snapshot.execution_day.isoformat(),
                "input_cutoff_day": snapshot.input_cutoff_day.isoformat(),
                "fast_lookback_days": snapshot.fast_lookback_days,
                "slow_lookback_days": snapshot.slow_lookback_days,
                "fast_annual_vol": snapshot.fast_annual_vol,
                "slow_annual_vol": snapshot.slow_annual_vol,
                "raw_scale": snapshot.raw_scale,
                "continuity_mode": snapshot.continuity_mode,
                "previous_snapshot_hash": snapshot.previous_snapshot_hash,
                "continuity_state": continuity_state,
                "continuity_verified": continuity_state in {"genesis", "verified"},
                "previous_smoothed_scale": snapshot.previous_smoothed_scale,
                "smoothed_scale": snapshot.smoothed_scale,
                "target_change_count": sum(
                    row["baseline_target_quantity"] != row["shadow_target_quantity"]
                    for row in targets
                ),
                "maximum_abs_target_quantity_delta": max(
                    abs(row["shadow_target_quantity"] - row["baseline_target_quantity"])
                    for row in targets
                ),
                "authority_granted": False,
                "dispatch_allowed": False,
            }
            if include_targets:
                result["targets"] = targets
            return result
        except Exception as exc:
            return {
                "configured": True,
                "valid": False,
                "mode": "shadow_only",
                "error_type": exc.__class__.__name__,
                "authority_granted": False,
                "dispatch_allowed": False,
            }

    def _position_manager_linked_baseline(
        self, baseline_batch_hash: str, *, require_settled: bool = False
    ) -> tuple[str, dict[str, Any] | None]:
        candidates = (
            ("active", self.current_plan, "batch_hash"),
            ("completed", self._completed_state, "last_completed_batch_hash"),
        )
        for state, candidate, hash_field in candidates:
            if not candidate or candidate.get(hash_field) != baseline_batch_hash:
                continue
            if require_settled and state == "active" and candidate.get("status") != "COMPLETE":
                # A structurally valid plan can still have unsubmitted or live
                # baseline work.  It is not a safe ownership source for a
                # shakedown session until that plan has closed successfully.
                return "unlinked", None
            if self._position_manager_baseline_is_complete(candidate):
                return state, candidate
            return "unlinked", None
        return "unlinked", None

    @staticmethod
    def _position_manager_baseline_is_complete(baseline: dict[str, Any]) -> bool:
        if not all(baseline.get(field) for field in ("source_month", "execution_day")):
            return False
        targets = baseline.get("targets")
        required = {
            "product",
            "exact_contract",
            "target_quantity",
            "source_target_weight",
            "buffered_target_weight",
            "reference_open_price",
            "multiplier",
            "price_tick",
        }
        return bool(
            isinstance(targets, list)
            and len(targets) == len(PRODUCT_SPECS)
            and all(isinstance(row, dict) and required <= row.keys() for row in targets)
        )

    def _verify_position_manager_baseline(
        self,
        snapshot: CommodityPositionManagerShadowDTO,
        baseline: dict[str, Any],
    ) -> None:
        expected_header = {
            "baseline_scheduler_id": self.scheduler_id,
            "source_month": baseline["source_month"],
            "execution_day": baseline["execution_day"],
        }
        observed_header = {
            "baseline_scheduler_id": snapshot.baseline_scheduler_id,
            "source_month": snapshot.source_month,
            "execution_day": snapshot.execution_day.isoformat(),
        }
        for field, expected in expected_header.items():
            if observed_header[field] != expected:
                raise CommoditySimNowBatchError(
                    "仓位管理 shadow baseline 批次头不一致",
                    detail={"field": field, "expected": expected},
                )

        baseline_targets = {row["product"]: row for row in baseline["targets"]}
        for row in snapshot.targets:
            expected = baseline_targets.get(row.product)
            if expected is None:
                raise CommoditySimNowBatchError(
                    "仓位管理 shadow baseline 品种不完整",
                    detail={"product": row.product},
                )
            comparisons = {
                "exact_contract": (row.exact_contract, expected["exact_contract"]),
                "target_quantity": (
                    row.baseline_target_quantity,
                    expected["target_quantity"],
                ),
                "source_target_weight": (
                    row.baseline_source_target_weight,
                    expected["source_target_weight"],
                ),
                "buffered_target_weight": (
                    row.baseline_buffered_target_weight,
                    expected["buffered_target_weight"],
                ),
                "reference_open_price": (
                    row.reference_open_price,
                    expected["reference_open_price"],
                ),
                "multiplier": (row.multiplier, expected["multiplier"]),
                "price_tick": (row.price_tick, expected["price_tick"]),
            }
            for field, (observed, expected_value) in comparisons.items():
                matches = (
                    math.isclose(
                        float(observed),
                        float(expected_value),
                        rel_tol=0,
                        abs_tol=1e-12,
                    )
                    if isinstance(observed, float) or isinstance(expected_value, float)
                    else observed == expected_value
                )
                if not matches:
                    raise CommoditySimNowBatchError(
                        "仓位管理 shadow baseline 目标字段不一致",
                        detail={
                            "product": row.product,
                            "field": field,
                            "expected": expected_value,
                        },
                    )

    @staticmethod
    def _position_manager_month(source_month: str) -> tuple[int, int]:
        try:
            year_text, month_text = source_month.split("-", 1)
            year = int(year_text)
            month = int(month_text)
            if source_month != f"{year:04d}-{month:02d}" or not 1 <= month <= 12:
                raise ValueError("invalid source month")
            date(year, month, 1)
            return year, month
        except (TypeError, ValueError) as exc:
            raise CommoditySimNowBatchError(
                "仓位管理 shadow source month 无效"
            ) from exc

    @staticmethod
    def _position_manager_next_month(source_month: str) -> str:
        year, month = CommoditySimNowService._position_manager_month(source_month)
        if month == 12:
            return f"{year + 1:04d}-01"
        return f"{year:04d}-{month + 1:02d}"

    def _verify_position_manager_continuity(
        self,
        snapshot: CommodityPositionManagerShadowDTO,
        snapshot_hash: str,
    ) -> str:
        previous = self._load_position_manager_shadow_state()
        if previous and previous["snapshot_hash"] == snapshot_hash:
            return str(previous["continuity_state"])

        if snapshot.continuity_mode == "genesis":
            if (
                previous is not None
                or snapshot.source_month != POSITION_MANAGER_GENESIS_SOURCE_MONTH
                or snapshot.previous_snapshot_hash is not None
                or not math.isclose(
                    snapshot.previous_smoothed_scale, 1.0, rel_tol=0, abs_tol=1e-12
                )
            ):
                raise CommoditySimNowBatchError(
                    "仓位管理 shadow genesis 连续性声明无效"
                )
            return "genesis"

        if snapshot.previous_snapshot_hash is None:
            raise CommoditySimNowBatchError(
                "仓位管理 shadow linked 快照缺少 previous snapshot hash"
            )
        if previous is None:
            return "unlinked"
        if snapshot.previous_snapshot_hash != previous["snapshot_hash"]:
            raise CommoditySimNowBatchError(
                "仓位管理 shadow previous snapshot hash 不一致"
            )
        if snapshot.source_month != self._position_manager_next_month(
            str(previous["source_month"])
        ):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow source month 未按月连续"
            )
        if not math.isclose(
            snapshot.previous_smoothed_scale,
            float(previous["smoothed_scale"]),
            rel_tol=0,
            abs_tol=1e-12,
        ):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow previous scale 与上一期不一致"
            )
        return "verified" if previous["continuity_verified"] else "unlinked"

    def _load_position_manager_shadow_state(self) -> dict[str, Any] | None:
        path = Path(
            self.settings.commodity_position_manager_shadow_state_path
        ).expanduser()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("invalid continuity state")
            if raw.get("schema_version") != (
                "commodity_relative_vol_position_manager_shadow_state_v1"
            ):
                raise ValueError("invalid continuity state schema")
            if not re.fullmatch(r"[0-9a-f]{64}", str(raw.get("snapshot_hash", ""))):
                raise ValueError("invalid continuity snapshot hash")
            self._position_manager_month(str(raw.get("source_month", "")))
            smoothed_scale = float(raw.get("smoothed_scale"))
            if not math.isfinite(smoothed_scale) or not 0.8 <= smoothed_scale <= 1.2:
                raise ValueError("invalid continuity scale")
            if raw.get("continuity_state") not in {"genesis", "verified", "unlinked"}:
                raise ValueError("invalid continuity status")
            if not isinstance(raw.get("continuity_verified"), bool):
                raise ValueError("invalid continuity verified flag")
            if raw["continuity_verified"] != (
                raw["continuity_state"] in {"genesis", "verified"}
            ):
                raise ValueError("inconsistent continuity status")
            return raw
        except (
            CommoditySimNowBatchError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return None

    def _save_position_manager_shadow_state(
        self,
        snapshot: CommodityPositionManagerShadowDTO,
        snapshot_hash: str,
        continuity_state: str,
    ) -> None:
        payload = {
            "schema_version": "commodity_relative_vol_position_manager_shadow_state_v1",
            "snapshot_hash": snapshot_hash,
            "source_month": snapshot.source_month,
            "smoothed_scale": snapshot.smoothed_scale,
            "continuity_state": continuity_state,
            "continuity_verified": continuity_state in {"genesis", "verified"},
        }
        path = Path(
            self.settings.commodity_position_manager_shadow_state_path
        ).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    def _verify_position_manager_shadow(
        self, snapshot: CommodityPositionManagerShadowDTO
    ) -> str:
        key = self._trusted_keys().get(snapshot.signer_key_id)
        if key is None:
            raise CommoditySimNowBatchError("仓位管理 shadow 签名 key_id 不在信任集")
        payload = snapshot.model_dump(mode="json", exclude={"signature"})
        canonical = _canonical_json(payload)
        try:
            signature = base64.b64decode(snapshot.signature, validate=True)
            key.verify(signature, canonical)
        except (InvalidSignature, ValueError, binascii.Error) as exc:
            raise CommoditySimNowBatchError("仓位管理 shadow Ed25519 签名无效") from exc

        source_year, source_month = self._position_manager_month(snapshot.source_month)
        expected_cutoff = date(
            source_year,
            source_month,
            calendar.monthrange(source_year, source_month)[1],
        )
        if snapshot.input_cutoff_day != expected_cutoff:
            raise CommoditySimNowBatchError(
                "仓位管理 shadow 输入截止日不符合 source month PIT 边界",
                detail={"expected_input_cutoff_day": expected_cutoff.isoformat()},
            )
        if snapshot.execution_day.strftime("%Y-%m") != self._position_manager_next_month(
            snapshot.source_month
        ):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow execution day 必须位于 source month 下一月"
            )
        numeric_inputs = {
            "fast_annual_vol": snapshot.fast_annual_vol,
            "slow_annual_vol": snapshot.slow_annual_vol,
            "raw_scale": snapshot.raw_scale,
            "previous_smoothed_scale": snapshot.previous_smoothed_scale,
            "smoothed_scale": snapshot.smoothed_scale,
        }
        if not all(math.isfinite(value) for value in numeric_inputs.values()):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow 波动率或 scale 不是有限数"
            )
        expected_raw = float(
            min(
                snapshot.scale_max,
                max(
                    snapshot.scale_min,
                    math.sqrt(snapshot.slow_annual_vol / snapshot.fast_annual_vol),
                ),
            )
        )
        if not math.isclose(snapshot.raw_scale, expected_raw, rel_tol=0, abs_tol=1e-10):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow raw scale 与冻结公式不一致",
                detail={"expected_raw_scale": expected_raw},
            )
        expected_smoothed = float(
            min(
                snapshot.scale_max,
                max(
                    snapshot.scale_min,
                    snapshot.smoothing_alpha * snapshot.raw_scale
                    + (1.0 - snapshot.smoothing_alpha) * snapshot.previous_smoothed_scale,
                ),
            )
        )
        if not math.isclose(
            snapshot.smoothed_scale, expected_smoothed, rel_tol=0, abs_tol=1e-10
        ):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow smoothed scale 与冻结公式不一致",
                detail={"expected_smoothed_scale": expected_smoothed},
            )

        rows = [row.model_dump(mode="json") for row in snapshot.targets]
        products = [row["product"] for row in rows]
        if set(products) != set(PRODUCT_SPECS) or len(products) != len(set(products)):
            raise CommoditySimNowBatchError("仓位管理 shadow 必须且只能包含冻结十品种")
        for row in rows:
            self._verify_position_manager_shadow_target(row)
        baseline_source = {
            row["product"]: float(row["baseline_source_target_weight"])
            for row in rows
        }
        shadow_source = {
            row["product"]: float(row["shadow_source_target_weight"])
            for row in rows
        }
        self._verify_position_manager_source_weights(baseline_source)
        for product in PRODUCT_SPECS:
            expected_shadow_source = baseline_source[product] * snapshot.smoothed_scale
            if not math.isclose(
                shadow_source[product], expected_shadow_source, rel_tol=0, abs_tol=1e-10
            ):
                raise CommoditySimNowBatchError(
                    "仓位管理 shadow source target 未按冻结 scale 生成",
                    detail={"product": product},
                )
        expected_buffers = {
            "baseline": self._position_manager_guardband(baseline_source),
            "shadow": self._position_manager_guardband(shadow_source),
        }
        for prefix, expected in expected_buffers.items():
            for row in rows:
                observed = float(row[f"{prefix}_buffered_target_weight"])
                if not math.isclose(
                    observed, expected[row["product"]], rel_tol=0, abs_tol=1e-10
                ):
                    raise CommoditySimNowBatchError(
                        f"仓位管理 shadow {prefix} buffered target 与冻结 guardband 不一致",
                        detail={"product": row["product"]},
                    )
        for prefix in ("baseline", "shadow"):
            self._verify_position_manager_shadow_portfolio(rows, prefix)
        return hashlib.sha256(canonical).hexdigest()

    def _verify_position_manager_shadow_target(self, row: dict[str, Any]) -> None:
        product = row["product"]
        spec = PRODUCT_SPECS[product]
        finite_fields = (
            "baseline_source_target_weight",
            "shadow_source_target_weight",
            "baseline_buffered_target_weight",
            "shadow_buffered_target_weight",
            "reference_open_price",
            "price_tick",
        )
        if not all(math.isfinite(float(row[field])) for field in finite_fields):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow 权重或价格不是有限数",
                detail={"product": product},
            )
        expected_prefix = f"{spec['exchange']}.{product}"
        if not re.fullmatch(rf"{re.escape(expected_prefix)}\d{{4}}", row["exact_contract"]):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow exact contract 与品种不一致",
                detail={"product": product},
            )
        if row["multiplier"] != spec["multiplier"] or not math.isclose(
            row["price_tick"], spec["price_tick"], rel_tol=0, abs_tol=1e-12
        ):
            raise CommoditySimNowBatchError(
                "仓位管理 shadow 合约规格不一致", detail={"product": product}
            )
        for prefix in ("baseline", "shadow"):
            quantity = int(row[f"{prefix}_target_quantity"])
            weight = float(row[f"{prefix}_buffered_target_weight"])
            if abs(quantity) > 500:
                raise CommoditySimNowBatchError(
                    "仓位管理 shadow 目标手数超过安全上限",
                    detail={"product": product, "path": prefix},
                )
            if not math.isfinite(weight):
                raise CommoditySimNowBatchError(
                    "仓位管理 shadow 权重不是有限数",
                    detail={"product": product, "path": prefix},
                )
            if quantity and (
                not weight or math.copysign(1, quantity) != math.copysign(1, weight)
            ):
                raise CommoditySimNowBatchError(
                    "仓位管理 shadow 整数目标方向与权重不一致",
                    detail={"product": product, "path": prefix},
                )

    def _verify_position_manager_source_weights(
        self, weights: dict[str, float]
    ) -> None:
        if set(weights) != set(PRODUCT_SPECS) or not all(
            math.isfinite(value) for value in weights.values()
        ):
            raise CommoditySimNowBatchError("仓位管理 baseline source target 不完整")
        if max(abs(value) for value in weights.values()) > 0.20 + 1e-12:
            raise CommoditySimNowBatchError("仓位管理 baseline source target 超过产品上限")
        if sum(abs(value) for value in weights.values()) > 1.0 + 1e-12:
            raise CommoditySimNowBatchError("仓位管理 baseline source target 超过 gross 上限")
        if abs(sum(weights.values())) > 1e-10:
            raise CommoditySimNowBatchError("仓位管理 baseline source target 不是净额零")
        for sector in set(POSITION_MANAGER_SECTOR_MAP_V1.values()):
            gross = sum(
                abs(weights[product])
                for product in PRODUCT_SPECS
                if POSITION_MANAGER_SECTOR_MAP_V1[product] == sector
            )
            if gross > 0.35 + 1e-12:
                raise CommoditySimNowBatchError(
                    "仓位管理 baseline source target 超过板块上限",
                    detail={"sector": sector},
                )

    def _position_manager_guardband(
        self, source: dict[str, float]
    ) -> dict[str, float]:
        weights = {
            product: float(min(0.12, max(-0.12, source[product])))
            for product in PRODUCT_SPECS
        }
        for sector in sorted(set(POSITION_MANAGER_SECTOR_MAP_V1.values())):
            members = [
                product
                for product in PRODUCT_SPECS
                if POSITION_MANAGER_SECTOR_MAP_V1[product] == sector
            ]
            sector_gross = sum(abs(weights[product]) for product in members)
            if sector_gross > 0.27:
                scale = 0.27 / sector_gross
                for product in members:
                    weights[product] *= scale
        gross = sum(abs(value) for value in weights.values())
        if gross > 0.80:
            scale = 0.80 / gross
            weights = {product: value * scale for product, value in weights.items()}
        positive = sum(max(value, 0.0) for value in weights.values())
        negative = sum(max(-value, 0.0) for value in weights.values())
        if min(positive, negative) <= 1e-14:
            return {product: 0.0 for product in PRODUCT_SPECS}
        if positive > negative:
            scale = negative / positive
            return {
                product: value * scale if value > 0 else value
                for product, value in weights.items()
            }
        if negative > positive:
            scale = positive / negative
            return {
                product: value * scale if value < 0 else value
                for product, value in weights.items()
            }
        return weights

    def _verify_position_manager_shadow_portfolio(
        self, rows: list[dict[str, Any]], prefix: str
    ) -> None:
        weights = {
            row["product"]: float(row[f"{prefix}_buffered_target_weight"])
            for row in rows
        }
        if max(abs(value) for value in weights.values()) > 0.12 + 1e-12:
            raise CommoditySimNowBatchError(f"仓位管理 shadow {prefix} 超过产品 buffer")
        if sum(abs(value) for value in weights.values()) > 0.8 + 1e-12:
            raise CommoditySimNowBatchError(f"仓位管理 shadow {prefix} 超过 gross buffer")
        if abs(sum(weights.values())) > 1e-10:
            raise CommoditySimNowBatchError(f"仓位管理 shadow {prefix} 不是净额零")
        for sector in set(POSITION_MANAGER_SECTOR_MAP_V1.values()):
            gross = sum(
                abs(weights[product])
                for product in PRODUCT_SPECS
                if POSITION_MANAGER_SECTOR_MAP_V1[product] == sector
            )
            if gross > 0.27 + 1e-12:
                raise CommoditySimNowBatchError(
                    f"仓位管理 shadow {prefix} 超过板块 buffer",
                    detail={"sector": sector},
                )
        exposures = {
            row["product"]: int(row[f"{prefix}_target_quantity"])
            * float(row["reference_open_price"])
            * int(row["multiplier"])
            / self.virtual_nav_cny
            for row in rows
        }
        if max(abs(value) for value in exposures.values()) >= 0.15:
            raise CommoditySimNowBatchError(f"仓位管理 shadow {prefix} 超过产品硬上限")
        if sum(abs(value) for value in exposures.values()) >= 1.0:
            raise CommoditySimNowBatchError(f"仓位管理 shadow {prefix} 超过 gross 硬上限")
        if abs(sum(exposures.values())) >= 0.10:
            raise CommoditySimNowBatchError(f"仓位管理 shadow {prefix} 超过净敞口硬上限")
        for sector in set(POSITION_MANAGER_SECTOR_MAP_V1.values()):
            gross = sum(
                abs(exposures[product])
                for product in PRODUCT_SPECS
                if POSITION_MANAGER_SECTOR_MAP_V1[product] == sector
            )
            if gross >= 0.35:
                raise CommoditySimNowBatchError(
                    f"仓位管理 shadow {prefix} 超过板块硬上限",
                    detail={"sector": sector},
                )

    def _halt_if_delivery_guard_breached(self, trading_day: date) -> dict[str, Any] | None:
        violations: list[dict[str, Any]] = []
        try:
            positions = self._position_snapshot()
        except Exception as exc:
            halt = self._begin_safe_halt(
                "delivery_guard_position_snapshot_failed",
                operator="commodity-simnow-template",
                source_ip=None,
            )
            result = {
                "action": "halted",
                "reason": "delivery_guard_position_snapshot_failed",
                "error_type": exc.__class__.__name__,
                "halt": halt,
            }
            self._event("strategy_template_delivery_guard_halted", result=result)
            return result
        for vt_symbol, row in positions.items():
            if not row.get("signed_quantity"):
                continue
            symbol, exchange = _split_vt(vt_symbol)
            exact_contract = f"{exchange}.{symbol}"
            try:
                self._verify_target_delivery(exact_contract, trading_day)
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
        halt = self._begin_safe_halt(
            "delivery_guard_breached_without_current_roll_target",
            operator="commodity-simnow-template",
            source_ip=None,
        )
        result = {
            "action": "halted",
            "reason": "delivery_guard_breached_without_current_roll_target",
            "violations": violations,
            "halt": halt,
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

    @_serialized
    def _begin_safe_halt(
        self,
        reason: str,
        *,
        operator: str,
        source_ip: str | None,
        phase: str | None = None,
    ) -> dict[str, Any]:
        self._revoke_auto_dispatch()
        plan = self.current_plan
        if not plan or plan.get("status") in {"COMPLETE", "HALTED_RECONCILED"}:
            return {"required": False, "reason": reason, "cancel_requested_order_ids": []}

        previous_status = str(plan.get("status") or "")
        continuing_halt = previous_status in {
            "CANCEL_PENDING",
            "SUBMISSION_OUTCOME_UNKNOWN",
            "HALTED_RECONCILE_REQUIRED",
            "HALTED_RECONCILED",
            "HALTED_PRE_SUBMIT_SAFE",
        }
        if continuing_halt:
            halt = plan.setdefault("halt", {})
        else:
            halt = {}
            plan["halt"] = halt
        if not continuing_halt:
            halt["previous_status"] = previous_status
        halt["reason"] = reason
        halt["phase"] = phase or (halt.get("phase") if continuing_halt else None) or self._infer_plan_phase(plan)
        halt["requested_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
        submission_recovery_status = (
            previous_status
            if self._submission_recovery_phase(previous_status)
            else str(halt.get("previous_status") or "")
        )
        submission_recovery_phase = self._submission_recovery_phase(submission_recovery_status)
        if previous_status in {"READY_CLOSE", "READY_OPEN", "HALTED_PRE_SUBMIT_SAFE"}:
            resume_status = str(halt.get("resume_status") or previous_status)
            if resume_status == "HALTED_PRE_SUBMIT_SAFE":
                resume_status = str(halt.get("previous_status") or "")
            if resume_status not in {"READY_CLOSE", "READY_OPEN"}:
                raise CommoditySimNowStateError(
                    "未提交计划缺少可恢复状态",
                    detail={"status": previous_status, "resume_status": resume_status},
                )
            pre_phase_expected = (
                plan["previous_positions"]
                if resume_status == "READY_CLOSE"
                else plan["expected_after_close"]
            )
            halt["resume_status"] = resume_status
            halt["pre_phase_expected_positions"] = pre_phase_expected
            halt["active_order_ids"] = []
            plan["status"] = "HALTED_PRE_SUBMIT_SAFE"
            self._persist_active_plan()
            result = {
                "required": False,
                "reason": reason,
                "status": plan["status"],
                "phase": halt["phase"],
                "resume_status": resume_status,
                "pre_phase_expected_positions": pre_phase_expected,
                "cancel_requested_order_ids": [],
                "active_order_ids": [],
                "orders_snapshot_available": True,
            }
            self._event("safe_halt_pre_submit", plan_hash=plan.get("plan_hash"), result=result)
            return result

        requested = set(halt.get("cancel_requested_order_ids", []))
        plan["status"] = "CANCEL_PENDING"
        halt["active_order_ids"] = halt.get("active_order_ids", [])
        halt["orders_snapshot_available"] = False
        self._persist_active_plan()

        orders_snapshot: list[dict[str, Any]] | None = None
        try:
            if submission_recovery_phase:
                orders_snapshot = self.rpc.get_orders()
                trades_snapshot = self.rpc.get_trades()
                evidence_references = self._recover_send_intent_evidence(
                    plan,
                    orders_snapshot,
                    trades_snapshot,
                    phases=(submission_recovery_phase,),
                )
                halt["submission_evidence_references"] = evidence_references
                self._persist_active_plan()
                active_before = self._active_plan_orders_from_snapshot(plan, orders_snapshot)
                has_persisted_submission = bool(plan.get("submitted", {}).get(submission_recovery_phase))
                if not evidence_references and not has_persisted_submission and not active_before:
                    pre_phase_expected = self._phase_pre_positions(plan, submission_recovery_phase)
                    observed = self._signed_positions(self._position_snapshot())
                    if observed == pre_phase_expected:
                        intents = plan.get("send_intents", {}).get(submission_recovery_phase, [])
                        deterministic_no_send = not intents or all(
                            intent.get("intent_status") == "REJECTED_PRE_RPC" for intent in intents
                        )
                        now_utc = self.clock().astimezone(timezone.utc)
                        checks = halt.setdefault("empty_submission_snapshots", [])
                        snapshot = {
                            "captured_at_utc": now_utc.isoformat(),
                            "positions_hash": _sha256_json(observed),
                        }
                        if not checks or checks[-1] != snapshot:
                            checks.append(snapshot)
                        halt.setdefault("first_empty_snapshot_at_utc", now_utc.isoformat())
                        first_empty = _parse_datetime(halt["first_empty_snapshot_at_utc"])
                        elapsed = (now_utc - first_empty).total_seconds() if first_empty else 0.0
                        enough_stable_snapshots = (
                            len(checks)
                            >= self.settings.commodity_simnow_submission_outcome_min_empty_snapshots
                            and elapsed
                            >= self.settings.commodity_simnow_submission_outcome_grace_seconds
                            and len({row["positions_hash"] for row in checks}) == 1
                        )
                        if deterministic_no_send or enough_stable_snapshots:
                            for intent in intents:
                                if intent.get("intent_status") != "REJECTED_PRE_RPC":
                                    intent["intent_status"] = "NO_EVIDENCE_STABLE"
                                intent["checked_at_utc"] = now_utc.isoformat()
                            halt.update(
                                {
                                    "phase": submission_recovery_phase,
                                    "resume_status": f"READY_{submission_recovery_phase.upper()}",
                                    "pre_phase_expected_positions": pre_phase_expected,
                                    "active_order_ids": [],
                                    "orders_snapshot_available": True,
                                    "trades_snapshot_available": True,
                                }
                            )
                            plan["status"] = "HALTED_PRE_SUBMIT_SAFE"
                            self._persist_active_plan()
                            result = {
                                "required": False,
                                "reason": reason,
                                "status": plan["status"],
                                "phase": submission_recovery_phase,
                                "resume_status": halt["resume_status"],
                                "pre_phase_expected_positions": pre_phase_expected,
                                "cancel_requested_order_ids": [],
                                "active_order_ids": [],
                                "orders_snapshot_available": True,
                                "trades_snapshot_available": True,
                                "submission_evidence_references": [],
                                "empty_snapshot_count": len(checks),
                                "outcome_grace_elapsed_seconds": elapsed,
                            }
                            self._event(
                                "safe_halt_submitting_without_evidence",
                                plan_hash=plan.get("plan_hash"),
                                result=result,
                            )
                            return result
                        plan["status"] = "SUBMISSION_OUTCOME_UNKNOWN"
                        halt.update(
                            {
                                "phase": submission_recovery_phase,
                                "active_order_ids": [],
                                "orders_snapshot_available": True,
                                "trades_snapshot_available": True,
                            }
                        )
                        self._persist_active_plan()
                        result = {
                            "required": True,
                            "reason": reason,
                            "status": plan["status"],
                            "phase": submission_recovery_phase,
                            "cancel_requested_order_ids": [],
                            "active_order_ids": [],
                            "orders_snapshot_available": True,
                            "trades_snapshot_available": True,
                            "submission_evidence_references": [],
                            "empty_snapshot_count": len(checks),
                            "outcome_grace_elapsed_seconds": elapsed,
                        }
                        self._event(
                            "submission_outcome_unknown",
                            plan_hash=plan.get("plan_hash"),
                            result=result,
                        )
                        return result
            else:
                active_before = self._active_plan_orders(plan)
        except Exception as exc:
            halt["last_rpc_error_type"] = exc.__class__.__name__
            halt["last_rpc_error_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
            self._persist_active_plan()
            result = {
                "required": True,
                "reason": reason,
                "status": "CANCEL_PENDING",
                "phase": halt["phase"],
                "cancel_requested_order_ids": sorted(requested),
                "active_order_ids": list(halt.get("active_order_ids", [])),
                "attempts": [],
                "orders_snapshot_available": False,
                "rpc_error_type": exc.__class__.__name__,
            }
            self._event("safe_halt_rpc_unavailable", plan_hash=plan.get("plan_hash"), result=result)
            return result

        halt["orders_snapshot_available"] = True
        if submission_recovery_phase:
            halt["trades_snapshot_available"] = True
        halt.pop("last_rpc_error_type", None)
        halt.pop("last_rpc_error_at_utc", None)
        candidates = set(self._submitted_order_ids(plan))
        candidates.update(row["vt_orderid"] for row in active_before)
        attempts: list[dict[str, Any]] = []
        for vt_orderid in sorted(candidates - requested):
            try:
                result = self.trade.cancel_order(
                    vt_orderid,
                    source_ip=source_ip,
                    operator=operator,
                    bypass_trade_check=True,
                )
                requested.add(vt_orderid)
                attempts.append({"vt_orderid": vt_orderid, "cancel_requested": True, "result": result})
            except Exception as exc:
                attempts.append(
                    {
                        "vt_orderid": vt_orderid,
                        "cancel_requested": False,
                        "error_type": exc.__class__.__name__,
                    }
                )
        halt["cancel_requested_order_ids"] = sorted(requested)
        halt["cancel_attempts"] = [*halt.get("cancel_attempts", []), *attempts]
        try:
            active = [row["vt_orderid"] for row in self._active_plan_orders(plan)]
        except Exception as exc:
            active = [row["vt_orderid"] for row in active_before]
            halt["orders_snapshot_available"] = False
            halt["last_rpc_error_type"] = exc.__class__.__name__
            halt["last_rpc_error_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
        plan["status"] = (
            "CANCEL_PENDING"
            if active or not halt["orders_snapshot_available"]
            else "HALTED_RECONCILE_REQUIRED"
        )
        halt["active_order_ids"] = active
        result = {
            "required": True,
            "reason": reason,
            "status": plan["status"],
            "phase": halt["phase"],
            "cancel_requested_order_ids": sorted(requested),
            "active_order_ids": active,
            "attempts": attempts,
            "orders_snapshot_available": halt["orders_snapshot_available"],
        }
        self._persist_active_plan()
        self._event("safe_halt", plan_hash=plan.get("plan_hash"), result=result)
        return result

    def _advance_cancel_pending(
        self,
        *,
        operator: str,
        source_ip: str | None,
    ) -> dict[str, Any]:
        plan = self.current_plan
        if not plan:
            return {"action": "idle", "reason": "no_plan"}
        halt = self._begin_safe_halt(
            str(plan.get("halt", {}).get("reason") or "cancel_pending_retry"),
            operator=operator,
            source_ip=source_ip,
        )
        if halt.get("status") == "SUBMISSION_OUTCOME_UNKNOWN":
            return {
                "action": "submission_outcome_unknown",
                "halt": halt,
                **self.status(),
            }
        if halt.get("status") == "CANCEL_PENDING":
            return {
                "action": "cancel_pending",
                "active_order_ids": halt.get("active_order_ids", []),
                "halt": halt,
                **self.status(),
            }
        if halt.get("status") == "HALTED_PRE_SUBMIT_SAFE":
            return {"action": "halted_pre_submit_safe", "halt": halt, **self.status()}
        self._event(
            "safe_halt_cancellations_complete",
            plan_hash=plan.get("plan_hash"),
            result={"operator": operator},
        )
        return {"action": "halted_reconcile_required", **self.status()}

    def _active_plan_orders(self, plan: dict[str, Any]) -> list[dict[str, str]]:
        return self._active_plan_orders_from_snapshot(plan, self.rpc.get_orders())

    def _active_plan_orders_from_snapshot(
        self,
        plan: dict[str, Any],
        orders: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        references = {
            str(order.get("reference") or "")
            for phase in ("close", "open")
            for order in plan.get(f"{phase}_orders", [])
        }
        references.update(
            str(intent.get("reference") or "")
            for phase in ("close", "open")
            for intent in plan.get("send_intents", {}).get(phase, [])
        )
        references.discard("")
        submitted_ids = set(self._submitted_order_ids(plan))
        active: list[dict[str, str]] = []
        for order in orders:
            if _normalize_status(order.get("status")) not in ACTIVE_ORDER_STATUSES:
                continue
            ids = self._order_ids(order)
            reference = str(order.get("reference") or "")
            if not (reference in references or ids.intersection(submitted_ids)):
                continue
            vt_orderid = str(order.get("vt_orderid") or order.get("orderid") or "unknown")
            active.append({"vt_orderid": vt_orderid, "reference": reference})
        return sorted(active, key=lambda row: row["vt_orderid"])

    def _phase_pre_positions(self, plan: dict[str, Any], phase: str) -> dict[str, int]:
        return plan["previous_positions"] if phase == "close" else plan["expected_after_close"]

    def _halt_reconciliation_expected_positions(
        self,
        plan: dict[str, Any],
        phase: str,
    ) -> dict[str, int] | None:
        """Rebuild the halted phase result from confirmed trades, never from submitted size.

        A cancellation can legitimately leave none (or only part) of a phase filled.  Using
        only the signed final target in that case makes a clean cancel impossible to reconcile.
        The caller also permits the exact nominal phase result: that is independently proven by
        the account position snapshot when an exchange trade callback is late or unavailable.
        Any other partial or malformed result remains fail-closed.
        """
        execution = plan.get("execution") or {}
        if not execution.get("available"):
            return None
        phase_orders: list[dict[str, Any]] = []
        for row in execution.get("orders", []):
            if row.get("phase") != phase:
                continue
            filled = float(row.get("filled_volume") or 0)
            expected = float(row.get("expected_volume") or 0)
            if filled < 0 or filled > expected or not filled.is_integer():
                return None
            if filled:
                phase_orders.append(
                    {
                        "vt_symbol": str(row["vt_symbol"]),
                        "direction": str(row["direction"]),
                        "volume": int(filled),
                    }
                )
        return self._apply_orders(self._phase_pre_positions(plan, phase), phase_orders)

    def _is_deterministic_pre_rpc_rejection(self, exc: Exception) -> bool:
        if not isinstance(exc, AppError):
            return False
        code = str(exc.code or "")
        return code.startswith("RISK_") or code in {
            "TRADE_DISABLED",
            "ORDER_CONFIRM_REQUIRED",
            "INVALID_ORDER_REQUEST",
        }

    def _submission_recovery_phase(self, status: str) -> str | None:
        if status in {"SUBMITTING_CLOSE", "CLOSE_SUBMISSION_PARTIAL"}:
            return "close"
        if status in {"SUBMITTING_OPEN", "OPEN_SUBMISSION_PARTIAL"}:
            return "open"
        return None

    def _recover_send_intent_evidence(
        self,
        plan: dict[str, Any],
        orders: list[dict[str, Any]],
        trades: list[dict[str, Any]],
        *,
        phases: tuple[str, ...] = ("close", "open"),
    ) -> list[str]:
        evidence_references: set[str] = set()
        for phase in phases:
            submitted = plan.setdefault("submitted", {}).setdefault(phase, [])
            submitted_references = {
                str(row.get("reference") or "") for row in submitted if row.get("reference")
            }
            for intent in plan.setdefault("send_intents", {}).setdefault(phase, []):
                reference = str(intent.get("reference") or "")
                if not reference:
                    continue
                matching_orders = [
                    order for order in orders if str(order.get("reference") or "") == reference
                ]
                order_ids = {
                    order_id
                    for order in matching_orders
                    for order_id in self._order_ids(order)
                }
                matching_trades = [
                    trade
                    for trade in trades
                    if str(trade.get("reference") or "") == reference
                    or bool(order_ids.intersection(self._order_ids(trade)))
                ]
                if not matching_orders and not matching_trades:
                    continue
                evidence_references.add(reference)
                intent["intent_status"] = "EVIDENCE_RECOVERED"
                intent["evidence_checked_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
                recovered_ids = {
                    order_id
                    for row in [*matching_orders, *matching_trades]
                    for order_id in self._order_ids(row)
                }
                if reference in submitted_references:
                    continue
                primary_order = matching_orders[-1] if matching_orders else matching_trades[-1]
                vt_orderid = str(
                    primary_order.get("vt_orderid")
                    or primary_order.get("orderid")
                    or next(iter(sorted(recovered_ids)), "")
                )
                recovered_row = {
                    key: value
                    for key, value in intent.items()
                    if key
                    not in {
                        "intent_status",
                        "intent_at_utc",
                        "acknowledged_at_utc",
                        "checked_at_utc",
                        "evidence_checked_at_utc",
                        "accepted",
                    }
                }
                if vt_orderid:
                    recovered_row["vt_orderid"] = vt_orderid
                recovered_row["recovered_from_reference"] = True
                submitted.append(recovered_row)
                submitted_references.add(reference)
        return sorted(evidence_references)

    def _submitted_order_ids(self, plan: dict[str, Any]) -> list[str]:
        return sorted(
            {
                str(order_id)
                for phase in ("close", "open")
                for row in plan.get("submitted", {}).get(phase, [])
                for order_id in [row.get("vt_orderid") or row.get("orderid")]
                if order_id
            }
        )

    def _infer_plan_phase(self, plan: dict[str, Any]) -> str:
        current_status = str(plan.get("status") or "")
        status = (
            str(plan.get("halt", {}).get("resume_status") or plan.get("halt", {}).get("previous_status") or "")
            if current_status.startswith("HALTED")
            or current_status in {"CANCEL_PENDING", "SUBMISSION_OUTCOME_UNKNOWN"}
            else current_status
        )
        if "CLOSE" in status:
            return "close"
        if "OPEN" in status:
            return "open"
        if plan.get("submitted", {}).get("open"):
            return "open"
        if plan.get("submitted", {}).get("close"):
            return "close"
        return "open" if plan.get("open_orders") else "close"

    def _auto_dispatch_allowed(self) -> bool:
        return bool(
            self.settings.commodity_simnow_auto_dispatch_enabled
            and self.enabled
            and self.manual_approval
            and self.simnow_mode
            and self.auto_dispatch_authorized
        )

    def _position_manager_shakedown_auto_dispatch_allowed(self) -> bool:
        return bool(
            self.settings.commodity_position_manager_simnow_shakedown_enabled
            and self.settings.commodity_position_manager_simnow_auto_dispatch_enabled
            and self.settings.commodity_simnow_enabled
            and self.enabled
            and self.manual_approval
            and self.simnow_mode
        )

    def _require_enabled(self) -> None:
        if not (self.settings.commodity_simnow_enabled and self.enabled and self.manual_approval and self.simnow_mode):
            raise CommoditySimNowDisabledError()

    def _resume_halted_plan_after_authorization(self) -> None:
        plan = self.current_plan
        if not plan or plan.get("status") not in {"HALTED_RECONCILED", "HALTED_PRE_SUBMIT_SAFE"}:
            return
        if plan["status"] == "HALTED_PRE_SUBMIT_SAFE":
            halt = plan.get("halt", {})
            resume_status = str(halt.get("resume_status") or "")
            expected = halt.get("pre_phase_expected_positions")
            phase = "close" if resume_status == "READY_CLOSE" else "open"
            intents = plan.get("send_intents", {}).get(phase, [])
            uncertain_intents = [
                intent for intent in intents if intent.get("intent_status") != "REJECTED_PRE_RPC"
            ]
            if uncertain_intents:
                try:
                    orders = self.rpc.get_orders()
                    trades = self.rpc.get_trades()
                    evidence = self._recover_send_intent_evidence(
                        plan,
                        orders,
                        trades,
                        phases=(phase,),
                    )
                except Exception as exc:
                    plan["status"] = "SUBMISSION_OUTCOME_UNKNOWN"
                    halt["previous_status"] = f"SUBMITTING_{phase.upper()}"
                    halt["last_rpc_error_type"] = exc.__class__.__name__
                    halt["last_rpc_error_at_utc"] = self.clock().astimezone(timezone.utc).isoformat()
                    self._persist_active_plan()
                    self._revoke_auto_dispatch()
                    self.enabled = False
                    self.manual_approval = False
                    self.simnow_mode = False
                    raise CommoditySimNowStateError(
                        "重新授权前无法确认历史 send intent 结果",
                        detail={"phase": phase, "rpc_error_type": exc.__class__.__name__},
                    ) from exc
                if evidence:
                    halt["previous_status"] = f"SUBMITTING_{phase.upper()}"
                    halt["submission_evidence_references"] = evidence
                    plan["status"] = "CANCEL_PENDING"
                    self._persist_active_plan()
                    halt_result = self._begin_safe_halt(
                        "late_submission_evidence_before_reauthorization",
                        operator="commodity-simnow-reauthorization",
                        source_ip=None,
                        phase=phase,
                    )
                    self.enabled = False
                    self.manual_approval = False
                    self.simnow_mode = False
                    raise CommoditySimNowStateError(
                        "重新授权前发现迟到委托或成交证据，已进入撤单收口",
                        detail={"phase": phase, "evidence_references": evidence, "halt": halt_result},
                    )
            observed = self._signed_positions(self._position_snapshot())
            if resume_status not in {"READY_CLOSE", "READY_OPEN"} or observed != expected:
                plan["status"] = "HALTED_RECONCILE_REQUIRED"
                self._persist_active_plan()
                self._revoke_auto_dispatch()
                self.enabled = False
                self.manual_approval = False
                self.simnow_mode = False
                raise CommoditySimNowStateError(
                    "未提交计划在重新授权前持仓发生变化",
                    detail={
                        "resume_status": resume_status,
                        "expected_positions": expected,
                        "observed_positions": observed,
                    },
                )
            plan["status"] = resume_status
            plan.pop("halt", None)
            self._persist_active_plan()
            self._event(
                "pre_submit_plan_reauthorized",
                plan_hash=plan.get("plan_hash"),
                result={"status": resume_status},
            )
            return
        halt = plan.get("halt", {})
        active = self._active_plan_orders(plan)
        phase = str(halt.get("phase") or self._infer_plan_phase(plan))
        expected = halt.get("reconciliation_expected_positions")
        if expected is None:
            expected = plan["expected_after_close"] if phase == "close" else plan["expected_final_positions"]
        observed = self._signed_positions(self._position_snapshot())
        if active or observed != expected:
            plan["status"] = "CANCEL_PENDING" if active else "HALTED_RECONCILE_REQUIRED"
            self._persist_active_plan()
            self._revoke_auto_dispatch()
            self.enabled = False
            self.manual_approval = False
            self.simnow_mode = False
            raise CommoditySimNowStateError(
                "停机计划状态在重新授权前发生变化",
                detail={
                    "active_order_ids": [row["vt_orderid"] for row in active],
                    "expected_positions": expected,
                    "observed_positions": observed,
                },
            )
        resume_status = str(halt.get("resume_status") or "")
        if resume_status in {"READY_CLOSE", "READY_OPEN"}:
            plan["status"] = resume_status
        elif phase == "close":
            plan["status"] = "READY_OPEN" if plan["open_orders"] else "COMPLETE"
        else:
            plan["status"] = "COMPLETE"
        plan.pop("halt", None)
        if plan["status"] == "COMPLETE":
            self._save_completed_state(plan)
        else:
            self._persist_active_plan()
        self._event(
            "halted_plan_reauthorized",
            plan_hash=plan.get("plan_hash"),
            result={"phase": phase, "status": plan["status"]},
        )

    def _require_plan(self, plan_hash: str) -> dict[str, Any]:
        if not self.current_plan or self.current_plan.get("plan_hash") != plan_hash:
            raise CommoditySimNowStateError("计划不存在或哈希不匹配")
        return self.current_plan

    def _safety_snapshot(
        self,
        *,
        require_trade_enabled: bool,
        allow_emergency_stopped: bool = False,
    ) -> dict[str, Any]:
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
        if risk_status.get("emergency_stopped") and not allow_emergency_stopped:
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
        current_trading_day = self._current_trading_day(
            [_exact_to_vt(row.exact_contract) for row in batch.targets]
        )
        if batch.execution_day != current_trading_day:
            raise CommoditySimNowBatchError(
                "目标批次只能在 execution trading day 预览和执行",
                detail={
                    "execution_day": batch.execution_day.isoformat(),
                    "current_trading_day": current_trading_day.isoformat(),
                },
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
            current_month = current_trading_day.strftime("%Y-%m")
            if batch.source_month > current_month:
                raise CommoditySimNowBatchError(
                    "SimNow shakedown 不得使用未来 source month",
                    detail={"source_month": batch.source_month, "current_month": current_month},
                )
        for row in batch.targets:
            self._verify_target_row(row.model_dump())
            if row.target_quantity:
                self._verify_target_delivery(row.exact_contract, current_trading_day)
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

    def _verify_target_delivery(self, exact_contract: str, trading_day: date) -> None:
        try:
            delivery_year, delivery_month = _delivery_year_month(exact_contract)
        except ValueError as exc:
            raise CommoditySimNowBatchError(
                "目标合约交割月份无法识别",
                detail={"exact_contract": exact_contract},
            ) from exc
        delivery_value = delivery_year * 100 + delivery_month
        current_value = trading_day.year * 100 + trading_day.month
        cutoff = self.settings.commodity_simnow_delivery_month_cutoff_day
        product = _product_from_symbol(exact_contract.split(".", 1)[1])
        if delivery_month == 1:
            preceding_year, preceding_month = delivery_year - 1, 12
        else:
            preceding_year, preceding_month = delivery_year, delivery_month - 1
        sc_cutoff = self.settings.commodity_simnow_sc_pre_delivery_cutoff_day
        if product == "sc" and (trading_day.year, trading_day.month) == (preceding_year, preceding_month) and trading_day.day >= sc_cutoff:
            raise CommoditySimNowBatchError(
                "原油目标合约已进入交割前月到期保护区间",
                detail={
                    "exact_contract": exact_contract,
                    "trading_day": trading_day.isoformat(),
                    "pre_delivery_cutoff_day": sc_cutoff,
                },
            )
        if delivery_value < current_value or (delivery_value == current_value and trading_day.day >= cutoff):
            raise CommoditySimNowBatchError(
                "目标合约已进入交割风险截止区间",
                detail={
                    "exact_contract": exact_contract,
                    "delivery_year_month": delivery_value,
                    "trading_day": trading_day.isoformat(),
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

    def _verify_realtime_exposures(
        self,
        targets: list[dict[str, Any]],
        expected_positions: dict[str, int],
        *,
        price_overrides: dict[str, float] | None = None,
        sector_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        target_by_vt = {
            _exact_to_vt(str(row["exact_contract"])): row
            for row in targets
        }
        weights = {product: 0.0 for product in PRODUCT_SPECS}
        prices: dict[str, float] = {}
        overrides = price_overrides or {}
        for vt_symbol, quantity in sorted(expected_positions.items()):
            row = target_by_vt.get(vt_symbol)
            if row is None:
                raise CommoditySimNowSafetyError(
                    "实时敞口存在未签名目标合约",
                    detail={"vt_symbol": vt_symbol},
                )
            product = str(row["product"])
            tick = float(PRODUCT_SPECS[product]["price_tick"])
            price = overrides.get(vt_symbol)
            if price is None:
                quote = self._quote(vt_symbol, tick)
                direction = "long" if quantity > 0 else "short"
                price = self._protected_price(direction, quote, tick)
            price = float(price)
            prices[vt_symbol] = price
            weights[product] += (
                int(quantity)
                * price
                * float(PRODUCT_SPECS[product]["multiplier"])
                / self.virtual_nav_cny
            )

        self._verify_exposure_weights(
            weights,
            error_type=CommoditySimNowSafetyError,
            prefix="实时",
            sector_map=sector_map,
        )
        return {
            "captured_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
            "prices": prices,
            "weights": weights,
            "snapshot_hash": _sha256_json({"prices": prices, "weights": weights}),
        }

    def _verify_exposure_weights(
        self,
        weights: dict[str, float],
        *,
        error_type: type[CommoditySimNowSafetyError],
        prefix: str,
        sector_map: dict[str, str] | None = None,
    ) -> None:
        if max((abs(value) for value in weights.values()), default=0.0) >= 0.15:
            raise error_type(f"{prefix}整数目标超过严格 15% 产品硬上限")
        if sum(abs(value) for value in weights.values()) >= 1.0:
            raise error_type(f"{prefix}整数目标超过严格 100% gross 硬上限")
        if abs(sum(weights.values())) >= 0.10:
            raise error_type(f"{prefix}整数目标超过严格 10% 净敞口硬上限")
        effective_sector_map = sector_map or {
            product: str(spec["sector"])
            for product, spec in PRODUCT_SPECS.items()
        }
        if set(effective_sector_map) != set(PRODUCT_SPECS):
            raise error_type(f"{prefix}板块映射不完整")
        for sector in set(effective_sector_map.values()):
            gross = sum(
                abs(weights[product])
                for product in PRODUCT_SPECS
                if effective_sector_map[product] == sector
            )
            if gross >= 0.35:
                raise error_type(
                    f"{prefix}整数目标超过严格 35% 板块硬上限",
                    detail={"sector": sector},
                )

    def _verify_phase_symbol_position_limit(
        self,
        orders: list[dict[str, Any]],
        positions: dict[str, dict[str, Any]],
    ) -> None:
        get_rules = getattr(self.risk, "get_rules", None)
        rules = get_rules() if callable(get_rules) else getattr(self.risk, "rules", {})
        maximum = float(rules.get("max_symbol_position") or 0)
        if maximum <= 0:
            return

        pending: dict[str, float] = {}
        for order in orders:
            if order.get("offset") == "open":
                vt_symbol = str(order["vt_symbol"])
                pending[vt_symbol] = pending.get(vt_symbol, 0.0) + float(order["volume"])
        if not pending:
            return

        active_open: dict[str, float] = {}
        for order in self.rpc.get_orders():
            if _normalize_status(order.get("status")) not in ACTIVE_ORDER_STATUSES:
                continue
            if _value(order.get("offset") or "").strip().lower() not in {"open", "开"}:
                continue
            vt_symbol = str(
                order.get("vt_symbol")
                or f"{order.get('symbol')}.{_value(order.get('exchange') or '')}"
            )
            remaining = max(
                float(order.get("volume") or 0) - float(order.get("traded") or order.get("traded_volume") or 0),
                0.0,
            )
            active_open[vt_symbol] = active_open.get(vt_symbol, 0.0) + remaining

        violations = []
        for vt_symbol, pending_volume in sorted(pending.items()):
            current = abs(float(positions.get(vt_symbol, {}).get("signed_quantity") or 0))
            active = active_open.get(vt_symbol, 0.0)
            projected = current + active + pending_volume
            if projected > maximum:
                violations.append(
                    {
                        "vt_symbol": vt_symbol,
                        "current_position": current,
                        "active_open_volume": active,
                        "phase_open_volume": pending_volume,
                        "projected_position": projected,
                        "max_symbol_position": maximum,
                    }
                )
        if violations:
            raise CommoditySimNowSafetyError(
                "本阶段拆单累计量超过单合约持仓上限",
                detail={"violations": violations},
            )

    def _plan_symbols(self, plan: dict[str, Any] | None) -> list[str]:
        if not plan:
            return []
        return sorted(
            {
                _exact_to_vt(str(row["exact_contract"]))
                for row in plan.get("targets", [])
                if row.get("exact_contract")
            }
        )

    def _current_trading_day(self, symbols: list[str] | None = None) -> date:
        status = calendar_service.trading_session_status(self.clock(), symbols or [])
        raw = status.get("trading_day")
        return date.fromisoformat(str(raw)) if raw else self.clock().astimezone(CHINA_TZ).date()

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

    def _reprice_order(self, order: dict[str, Any], *, passive: bool = False) -> dict[str, Any]:
        tick = PRODUCT_SPECS[order["product"]]["price_tick"]
        quote = self._quote(order["vt_symbol"], tick)
        if passive:
            price = quote["bid_price_1"] if order["direction"] == "long" else quote["ask_price_1"]
        else:
            price = self._protected_price(order["direction"], quote, tick)
        return {**order, "price": _round_price(price, tick)}

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

    def _active_state_path(self) -> Path:
        completed_path = Path(self.settings.commodity_simnow_state_path)
        return completed_path.with_name(f"{completed_path.stem}.active{completed_path.suffix}")

    def _load_active_plan(self) -> dict[str, Any] | None:
        path = self._active_state_path()
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("schema_version") != "commodity_simnow_active_plan_v1":
                raise ValueError("invalid active plan schema")
            plan = payload.get("plan")
            if not isinstance(plan, dict):
                raise ValueError("invalid active plan")
            checksum = payload.get("plan_checksum")
            if checksum != _sha256_json(plan):
                raise ValueError("active plan checksum mismatch")
            if not re.fullmatch(r"[0-9a-f]{64}", str(plan.get("plan_hash") or "")):
                raise ValueError("invalid active plan hash")
            if not re.fullmatch(r"[0-9a-f]{64}", str(plan.get("account_hash") or "")):
                raise ValueError("invalid active account hash")
            if not isinstance(plan.get("targets"), list) or not isinstance(plan.get("submitted"), dict):
                raise ValueError("invalid active plan shape")
            return plan
        except Exception as exc:
            self._state_load_error = f"active_plan:{exc.__class__.__name__}"
            return None

    def _persist_active_plan(self) -> None:
        path = self._active_state_path()
        plan = self.current_plan
        if not plan or plan.get("status") in {"COMPLETE", "HALTED_RECONCILED"}:
            path.unlink(missing_ok=True)
            return
        payload = {
            "schema_version": "commodity_simnow_active_plan_v1",
            "updated_at_utc": self.clock().astimezone(timezone.utc).isoformat(),
            "plan_checksum": _sha256_json(plan),
            "plan": plan,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

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
            "targets": plan["targets"],
            "execution": plan.get("execution"),
        }
        path = Path(self.settings.commodity_simnow_state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        self._completed_state = payload
        self._active_state_path().unlink(missing_ok=True)

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
