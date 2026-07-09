from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo

from app.schemas.mak_v2_observer import (
    MakV2DryRunSignalRequestDTO,
    MakV2ObserverDisableRequestDTO,
    MakV2ObserverEnableRequestDTO,
    MakV2SafetyAuditRequestDTO,
)
from app.services.audit_service import AuditService, audit_service
from app.services.mak_v2_testnet_observer.event_store import MakV2ObserverEventStore
from app.services.mak_v2_testnet_observer.risk_gate import MakV2ObserverLimits, MakV2RiskGate
from app.services.mak_v2_testnet_observer.safety_audit import MakV2SafetyAuditService, mak_v2_safety_audit_service
from app.services.risk_service import RiskService, risk_service

CHINA_TZ = ZoneInfo("Asia/Shanghai")
EXACT_CONTRACT_RE = re.compile(r"^GFEX\.(lc|ps)\d{4}$")


class MakV2TestnetObserverService:
    candidate_id = "w900_z1p5_h900_reversal"
    profile_id = "lc50_ps50"
    capacity_status = "L1_CONSTRAINED_WATCH"
    mode = "CONTROLLED_TESTNET_OBSERVER"
    dry_run_only = True
    production_allowed = False

    def __init__(
        self,
        *,
        store: MakV2ObserverEventStore | None = None,
        gate: MakV2RiskGate | None = None,
        risk: RiskService | None = None,
        audit: AuditService | None = None,
        safety_audit: MakV2SafetyAuditService | None = None,
    ) -> None:
        self.store = store or MakV2ObserverEventStore()
        self.gate = gate or MakV2RiskGate()
        self.risk = risk or risk_service
        self.audit = audit or audit_service
        self.safety_audit_service = safety_audit or mak_v2_safety_audit_service
        self.enabled = False
        self.manual_approval = False
        self.testnet_mode = False
        self.order_endpoint_touched = False
        self._daily_order_counts: dict[str, int] = {}
        self._instrument_daily_counts: dict[tuple[str, str], int] = {}
        self._last_order_time: dict[str, datetime] = {}

    @property
    def limits(self) -> MakV2ObserverLimits:
        return self.gate.limits

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "candidate_id": self.candidate_id,
            "profile_id": self.profile_id,
            "capacity_status": self.capacity_status,
            "enabled": self.enabled,
            "manual_approval": self.manual_approval,
            "testnet_mode": self.testnet_mode,
            "dry_run_only": self.dry_run_only,
            "production_allowed": self.production_allowed,
            "max_order_lots": self.limits.max_order_lots,
            "max_testnet_orders_per_day": self.limits.max_testnet_orders_per_day,
            "max_testnet_orders_per_instrument_per_day": self.limits.max_testnet_orders_per_instrument_per_day,
            "max_active_testnet_positions_total": self.limits.max_active_testnet_positions_total,
            "max_active_testnet_position_per_instrument": self.limits.max_active_testnet_position_per_instrument,
            "cooldown_after_testnet_order_seconds": self.limits.cooldown_after_testnet_order_seconds,
            "cooldown_after_reject_seconds": self.limits.cooldown_after_reject_seconds,
            "signals_total": len(self.store.signals),
            "dry_run_intents_total": len(self.store.order_intents),
            "blocked_signals_total": sum(1 for row in self.store.decisions if row.get("decision") == "blocked"),
            "guardrail_events_total": len(self.store.guardrails),
            "order_endpoint_touched": self.order_endpoint_touched,
        }

    def enable(
        self,
        payload: MakV2ObserverEnableRequestDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        confirmations_ok = (
            payload.manual_approval
            and payload.testnet_mode
            and payload.confirm_testnet_only
            and payload.confirm_no_production
            and payload.confirm_max_one_lot
            and payload.confirm_no_auto_promotion
        )
        if not confirmations_ok:
            self._guardrail(
                "manual_waiver_incomplete",
                "high",
                "enable rejected",
                trace_id=None,
                trigger_value=payload.model_dump(),
                threshold="all waiver confirmations true",
            )
            result = {**self.status(), "enabled": False, "enable_rejected": True}
        else:
            self.enabled = True
            self.manual_approval = True
            self.testnet_mode = True
            result = self.status()
        self.audit.record(
            action="mak_v2_observer_enable",
            user_id=operator,
            role=role,
            request=payload.model_dump(),
            result=result,
            source_ip=source_ip,
        )
        return result

    def disable(
        self,
        payload: MakV2ObserverDisableRequestDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        self.enabled = False
        result = {**self.status(), "reason": payload.reason}
        self.audit.record(
            action="mak_v2_observer_disable",
            user_id=operator,
            role=role,
            request=payload.model_dump(),
            result=result,
            source_ip=source_ip,
        )
        return result

    def flatten_testnet(self, *, operator: str, role: str | None, source_ip: str | None, reason: str = "manual flatten") -> dict[str, Any]:
        self.enabled = False
        guardrail = self._guardrail(
            "manual_flatten_requested",
            "warning",
            "observer disabled; no order endpoint called by instrumentation-first packet",
            trace_id=None,
            trigger_value=reason,
            threshold="manual request",
        )
        result = {**self.status(), "flatten_requested": True, "order_endpoint_touched": False, "guardrail": guardrail}
        self.audit.record(
            action="mak_v2_observer_flatten_testnet",
            user_id=operator,
            role=role,
            request={"reason": reason},
            result=result,
            source_ip=source_ip,
        )
        return result

    def dry_run_signal(self, payload: MakV2DryRunSignalRequestDTO, *, operator: str, role: str | None) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        event_time = payload.signal_time_utc or now
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        local_time = event_time.astimezone(CHINA_TZ)
        trace_id = f"makv2-{uuid4().hex}"
        event_id = f"{trace_id}-signal"
        tick_size = _tick_size(payload.instrument)
        exact_contract_valid = _is_valid_exact_contract(payload.instrument, payload.exact_contract)
        day = local_time.date().isoformat()
        risk_status = self.risk.status()
        gate = self.gate.evaluate(
            payload,
            now=now,
            observer_enabled=self.enabled,
            manual_approval=self.manual_approval,
            testnet_mode=self.testnet_mode,
            risk_status=risk_status,
            daily_order_count=self._daily_order_counts.get(day, 0),
            instrument_order_count=self._instrument_daily_counts.get((day, payload.instrument), 0),
            active_position_count=0,
            active_position_count_instrument=0,
            last_order_time=self._last_order_time.get(payload.instrument),
            tick_size=tick_size,
            exact_contract_valid=exact_contract_valid,
        )
        continuous_symbol = f"KQ.m@GFEX.{payload.instrument}"
        signal_row = {
            "event_id": event_id,
            "trace_id": trace_id,
            "candidate_id": self.candidate_id,
            "profile_id": self.profile_id,
            "instrument": payload.instrument,
            "continuous_symbol": continuous_symbol,
            "exact_contract": _normalize_exact_contract(payload.exact_contract),
            "signal_time_utc": event_time.astimezone(timezone.utc).isoformat(),
            "signal_time_local": local_time.isoformat(),
            "local_date": day,
            "side": payload.side,
            "z_score": payload.z_score,
            "rolling_mean": payload.rolling_mean,
            "rolling_std": payload.rolling_std,
            "window_seconds": 900,
            "horizon_seconds": 900,
            "last_price": payload.last_price,
            "bid_price_1": payload.bid_price_1,
            "ask_price_1": payload.ask_price_1,
            "bid_volume_1": payload.bid_volume_1,
            "ask_volume_1": payload.ask_volume_1,
            "spread_ticks": round(float(gate["spread_ticks"]), 6),
            "top_lot": gate["top_lot"],
            "quote_age_ms": payload.quote_age_ms,
            "cluster_id": payload.cluster_id,
            "active_overlap_900s": payload.active_overlap_900s,
            "cooldown_state": payload.cooldown_state,
            "eligible_for_testnet": gate["eligible"],
            "ineligible_reason": ",".join(gate["blockers"]),
            "data_quality_status": payload.data_quality_status,
            "dry_run_only": self.dry_run_only,
        }
        self.store.append_signal(signal_row)
        decision_row = {
            "trace_id": trace_id,
            "event_id": event_id,
            "decision_time": now.isoformat(),
            "local_date": day,
            "decision": "dry_run_intent" if gate["eligible"] else "blocked",
            "decision_reason": "eligible dry-run intent only" if gate["eligible"] else ",".join(gate["blockers"]),
            "manual_approval_state": self.manual_approval,
            "testnet_mode": self.testnet_mode,
            "risk_status": "pass" if not risk_status.get("emergency_stopped") else "blocked",
            "daily_order_count": self._daily_order_counts.get(day, 0),
            "active_position_count": 0,
            "spread_gate_pass": gate["spread_gate_pass"],
            "top_lot_gate_pass": gate["top_lot_gate_pass"],
            "cooldown_gate_pass": gate["cooldown_gate_pass"],
            "lc_watch_gate_pass": gate["lc_watch_gate_pass"],
            "contract_gate_pass": gate["contract_gate_pass"],
            "data_quality_gate_pass": gate["data_quality_gate_pass"],
            "final_allow_order": gate["eligible"],
            "order_endpoint_touched": False,
        }
        self.store.append_decision(decision_row)
        intent_row: dict[str, Any] | None = None
        if gate["eligible"]:
            self._daily_order_counts[day] = self._daily_order_counts.get(day, 0) + 1
            self._instrument_daily_counts[(day, payload.instrument)] = self._instrument_daily_counts.get((day, payload.instrument), 0) + 1
            self._last_order_time[payload.instrument] = now
            limit_price = (
                payload.ask_price_1 + tick_size
                if payload.side == "long"
                else payload.bid_price_1 - tick_size
            )
            intent_row = {
                "trace_id": trace_id,
                "event_id": event_id,
                "intent_id": f"{trace_id}-intent",
                "intent_time": now.isoformat(),
                "local_date": day,
                "instrument": payload.instrument,
                "exact_contract": _normalize_exact_contract(payload.exact_contract),
                "side": payload.side,
                "open_close": "open",
                "order_type": "limit",
                "requested_lots": 1,
                "limit_price": limit_price,
                "price_protection_ticks": 1,
                "source_bid": payload.bid_price_1,
                "source_ask": payload.ask_price_1,
                "source_spread_ticks": round(float(gate["spread_ticks"]), 6),
                "source_top_lot": gate["top_lot"],
                "expected_horizon_exit_time": (now.replace(microsecond=0) + _horizon_delta()).isoformat(),
                "dry_run_only": True,
                "order_endpoint_touched": False,
            }
            self.store.append_order_intent(intent_row)
        daily_summary = self.store.update_daily_summary(day)
        return {
            "signal": signal_row,
            "decision": decision_row,
            "order_intent": intent_row,
            "daily_summary": daily_summary,
            "status": self.status(),
        }

    def list_signals(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.store.list_rows("signals", limit=limit)

    def list_order_intents(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.store.list_rows("order_intents", limit=limit)

    def list_fills(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.store.list_rows("fills", limit=limit)

    def list_guardrails(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.store.list_rows("guardrails", limit=limit)

    def list_safety_audits(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.store.list_rows("safety_audits", limit=limit)

    def latest_safety_audit(self) -> dict[str, Any] | None:
        return self.store.latest_safety_audit()

    def daily_summary(self) -> list[dict[str, Any]]:
        return self.store.latest_daily_summaries()

    def safety_audit(
        self,
        payload: MakV2SafetyAuditRequestDTO,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        result = self.safety_audit_service.audit(payload, self.status())
        self.store.append_safety_audit(result)
        self.audit.record(
            action="mak_v2_safety_audit",
            user_id=operator,
            role=role,
            request=payload.model_dump(),
            result=result,
            source_ip=source_ip,
        )
        return result

    def _guardrail(
        self,
        guard_name: str,
        severity: str,
        action: str,
        *,
        trace_id: str | None,
        trigger_value: Any,
        threshold: Any,
    ) -> dict[str, Any]:
        row = {
            "guard_event_id": f"guard-{uuid4().hex}",
            "trigger_time": datetime.now(timezone.utc).isoformat(),
            "local_date": datetime.now(CHINA_TZ).date().isoformat(),
            "guard_name": guard_name,
            "severity": severity,
            "trigger_value": trigger_value,
            "threshold": threshold,
            "action": action,
            "trace_id": trace_id,
            "manual_ack_required": True,
            "resolved": False,
            "resolved_time": None,
        }
        self.store.append_guardrail(row)
        return row


def _tick_size(instrument: str) -> float:
    return {"lc": 20.0, "ps": 5.0}[instrument]


def _normalize_exact_contract(symbol: str) -> str:
    if symbol.startswith("GFEX."):
        return symbol
    if symbol.endswith(".GFEX"):
        return f"GFEX.{symbol.removesuffix('.GFEX')}"
    return f"GFEX.{symbol}"


def _is_valid_exact_contract(instrument: str, symbol: str) -> bool:
    normalized = _normalize_exact_contract(symbol)
    return bool(EXACT_CONTRACT_RE.fullmatch(normalized)) and normalized.startswith(f"GFEX.{instrument}")


def _horizon_delta():
    from datetime import timedelta

    return timedelta(seconds=900)


mak_v2_observer_service = MakV2TestnetObserverService()
