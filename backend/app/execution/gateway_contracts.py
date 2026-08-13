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
        }
