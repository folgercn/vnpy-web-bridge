"""Import-only DTOs shared by gateway consumers.

This module intentionally contains no gateway transport, mutation, lifecycle,
or execution-owner dependency.  It lets offline consumers use the read-only
gateway snapshot contract without packaging a mutation-capable gateway.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .models import ZERO_HASH, format_utc, utc_now


@dataclass(frozen=True, slots=True)
class GatewaySnapshot:
    snapshot_id: str
    generation: int
    connected: bool
    active_order_count: int = 0
    position_snapshot_hash: str = ZERO_HASH
    observed_at: str = field(default_factory=lambda: format_utc(utc_now()))
    # ``orders`` is an opaque broker-facts mapping.  It is intentionally not
    # accepted as an order capability by the orchestrator.
    orders: Mapping[str, Any] = field(default_factory=dict)
    positions: Mapping[str, Any] = field(default_factory=dict)
    account_scope: str = ""
    environment: str = ""
    fresh: bool = True
    # Final-validation snapshots carry the Windows durable admission
    # high-water marks.  They are intentionally internal DTO metadata: normal
    # gateway snapshots do not provide them and public status remains unchanged.
    fence_high_water_epoch: int | None = None
    fence_high_water_fencing_token: int | None = None
    # Authoritative CTP trading day from the final-validation Windows runtime.
    # This stays internal and is deliberately omitted from ``as_dict()``.
    broker_trading_day: str | None = None
    # The pinned vnpy_ctp LIMIT mapping uses THOST_FTDC_TC_GFD.  Rollover
    # recovery requires this explicit Windows-side transport binding.
    broker_limit_time_condition: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "generation": self.generation,
            "connected": self.connected,
            "active_order_count": self.active_order_count,
            "position_snapshot_hash": self.position_snapshot_hash,
            "observed_at": self.observed_at,
            "orders": dict(self.orders),
            "positions": dict(self.positions),
            "account_scope": self.account_scope,
            "environment": self.environment,
            "fresh": self.fresh,
            **(
                {
                    "fence_high_water_epoch": self.fence_high_water_epoch,
                    "fence_high_water_fencing_token": (
                        self.fence_high_water_fencing_token
                    ),
                }
                if self.fence_high_water_epoch is not None
                or self.fence_high_water_fencing_token is not None
                else {}
            ),
        }
