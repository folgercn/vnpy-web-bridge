"""Ephemeral smoke-only publisher for the eTick.v1 JSON multipart wire."""

from __future__ import annotations

import json
import time

import zmq


def _tick_wire() -> tuple[bytes, bytes]:
    # Fixed, timezone-aware time keeps every replay byte-identical market
    # content; this smoke must prove dedup rather than merely early ingestion.
    payload = {
        "schema_version": "eTick.v1",
        "type": "tick",
        "vt_symbol": "RB2601.SHFE",
        "event_time_utc": "2026-08-08T01:02:03Z",
        "last_price": 3500.0,
        "last_volume": 1.0,
        "bid_price": 3499.0,
        "ask_price": 3501.0,
        "bid_volume": 2.0,
        "ask_volume": 3.0,
    }
    return b"eTick.v1.RB2601.SHFE", json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def main() -> None:
    socket = zmq.Context.instance().socket(zmq.PUB)
    socket.bind("tcp://*:5555")
    wire = _tick_wire()
    # PUB/SUB needs a short subscription handshake; repeated identical frames
    # prove content dedup/replay without creating a broker capability.
    time.sleep(1.5)
    for _ in range(20):
        socket.send_multipart(wire)
        time.sleep(0.2)
    time.sleep(3)


if __name__ == "__main__":
    main()
