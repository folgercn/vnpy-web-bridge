"""Ephemeral smoke-only publisher for the real vn.py list/TickData wire."""

from __future__ import annotations

import pickle
import sys
import time
import types
from datetime import datetime, timezone

import zmq


def _tick_wire() -> bytes:
    """Create the exact import-global shape accepted by the restricted reader."""

    vnpy = types.ModuleType("vnpy")
    trader = types.ModuleType("vnpy.trader")
    objects = types.ModuleType("vnpy.trader.object")
    tick_type = type("TickData", (), {})
    tick_type.__module__ = "vnpy.trader.object"
    objects.TickData = tick_type
    sys.modules.update(
        {"vnpy": vnpy, "vnpy.trader": trader, "vnpy.trader.object": objects}
    )
    tick = tick_type()
    tick.vt_symbol = "RB2601.SHFE"
    tick.symbol = "RB2601"
    tick.exchange = "SHFE"
    # Fixed, timezone-aware time keeps every replay byte-identical market
    # content; this smoke must prove dedup rather than merely early ingestion.
    tick.datetime = datetime(2026, 8, 8, 1, 2, 3, tzinfo=timezone.utc)
    tick.last_price = 3500.0
    tick.last_volume = 1.0
    tick.bid_price_1 = 3499.0
    tick.ask_price_1 = 3501.0
    tick.bid_volume_1 = 2.0
    tick.ask_volume_1 = 3.0
    return pickle.dumps(["eTick.RB2601.SHFE", tick], protocol=4)


def main() -> None:
    socket = zmq.Context.instance().socket(zmq.PUB)
    socket.bind("tcp://*:5555")
    wire = _tick_wire()
    # PUB/SUB needs a short subscription handshake; repeated identical frames
    # prove content dedup/replay without creating a broker capability.
    time.sleep(1.5)
    for _ in range(20):
        socket.send(wire)
        time.sleep(0.2)
    time.sleep(3)


if __name__ == "__main__":
    main()
