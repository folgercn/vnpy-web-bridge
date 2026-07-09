from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.schemas.mak_v2_observer import MakV2DryRunSignalRequestDTO


@dataclass(frozen=True)
class MakV2ObserverLimits:
    max_testnet_orders_per_day: int = 20
    max_testnet_orders_per_instrument_per_day: int = 10
    max_active_testnet_positions_total: int = 2
    max_active_testnet_position_per_instrument: int = 1
    max_order_lots: int = 1
    max_quote_age_ms: int = 3_000
    max_spread_ticks: float = 3
    min_top_lot: float = 1
    cooldown_after_testnet_order_seconds: int = 900
    cooldown_after_reject_seconds: int = 1_800


class MakV2RiskGate:
    def __init__(self, limits: MakV2ObserverLimits | None = None) -> None:
        self.limits = limits or MakV2ObserverLimits()

    def evaluate(
        self,
        payload: MakV2DryRunSignalRequestDTO,
        *,
        now: datetime,
        observer_enabled: bool,
        manual_approval: bool,
        testnet_mode: bool,
        risk_status: dict[str, Any],
        daily_order_count: int,
        instrument_order_count: int,
        active_position_count: int,
        active_position_count_instrument: int,
        last_order_time: datetime | None,
        tick_size: float,
        exact_contract_valid: bool,
    ) -> dict[str, Any]:
        spread_ticks = (payload.ask_price_1 - payload.bid_price_1) / tick_size if tick_size > 0 else 999_999
        top_lot = min(payload.bid_volume_1, payload.ask_volume_1)
        blockers: list[str] = []

        if not observer_enabled:
            blockers.append("observer_disabled")
        if not manual_approval:
            blockers.append("manual_approval_missing")
        if not testnet_mode:
            blockers.append("testnet_mode_required")
        if payload.instrument not in {"lc", "ps"}:
            blockers.append("instrument_not_allowed")
        if not exact_contract_valid:
            blockers.append("exact_contract_invalid")
        if payload.quote_age_ms > self.limits.max_quote_age_ms:
            blockers.append("stale_tick")
        if spread_ticks > self.limits.max_spread_ticks:
            blockers.append("spread_too_wide")
        if top_lot < self.limits.min_top_lot:
            blockers.append("top_lot_too_small")
        if active_position_count >= self.limits.max_active_testnet_positions_total:
            blockers.append("active_position_total_cap")
        if active_position_count_instrument >= self.limits.max_active_testnet_position_per_instrument:
            blockers.append("active_position_instrument_cap")
        if daily_order_count >= self.limits.max_testnet_orders_per_day:
            blockers.append("daily_order_cap")
        if instrument_order_count >= self.limits.max_testnet_orders_per_instrument_per_day:
            blockers.append("instrument_daily_order_cap")
        if last_order_time and now - last_order_time < timedelta(seconds=self.limits.cooldown_after_testnet_order_seconds):
            blockers.append("cooldown_active")
        if payload.data_quality_status != "pass":
            blockers.append("data_quality_not_pass")
        if risk_status.get("emergency_stopped"):
            blockers.append("risk_emergency_stopped")
        if not risk_status.get("risk_enabled", True):
            blockers.append("risk_disabled")

        return {
            "eligible": not blockers,
            "blockers": blockers,
            "spread_ticks": spread_ticks,
            "top_lot": top_lot,
            "spread_gate_pass": spread_ticks <= self.limits.max_spread_ticks,
            "top_lot_gate_pass": top_lot >= self.limits.min_top_lot,
            "cooldown_gate_pass": "cooldown_active" not in blockers,
            "lc_watch_gate_pass": payload.instrument != "lc" or self.limits.max_order_lots <= 1,
            "contract_gate_pass": exact_contract_valid,
            "data_quality_gate_pass": payload.data_quality_status == "pass",
        }
