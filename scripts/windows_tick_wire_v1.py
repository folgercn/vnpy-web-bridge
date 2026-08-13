"""Fixed, tick-only JSON PUB adapter for the Windows CTP process.

This is deliberately independent of vn.py's mixed RpcServer PUB channel.  It
never serializes Python objects: subscribers receive exactly ``(topic, JSON)``
on the dedicated TCP/4103 listener.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from types import MethodType
from typing import Any

TICK_WIRE_VERSION = "eTick.v1"
TICK_WIRE_PREFIX = f"{TICK_WIRE_VERSION}."
TICK_WIRE_BIND_ADDRESS = "tcp://*:4103"
MAX_TOPIC_BYTES = 192
MAX_PAYLOAD_BYTES = 4096
_VT_SYMBOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_NUMBER_FIELDS = frozenset(
    {"last_price", "last_volume", "bid_price", "ask_price", "bid_volume", "ask_volume"}
)
_PAYLOAD_FIELDS = frozenset(
    {"schema_version", "type", "vt_symbol", "event_time_utc", *_NUMBER_FIELDS}
)


class TickWireError(ValueError):
    """The tick-only wire is malformed or outside its bounded contract."""


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise TickWireError("tick wire JSON is not canonical") from exc


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise TickWireError(f"tick wire {field} is invalid")
    return value


def _number(value: Any, field: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TickWireError(f"tick wire {field} is invalid")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0 or normalized > 1_000_000_000_000:
        raise TickWireError(f"tick wire {field} is invalid")
    return normalized


def _event_time(value: Any) -> str:
    text = _text(value, "event_time_utc")
    if not text.endswith("Z"):
        raise TickWireError("tick wire event_time_utc is invalid")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise TickWireError("tick wire event_time_utc is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TickWireError("tick wire event_time_utc is invalid")
    return text


def tick_wire_payload(value: Any) -> dict[str, Any]:
    """Project a TickData/mapping into the only values permitted on this wire."""

    def field(name: str) -> Any:
        return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)

    vt_symbol = field("vt_symbol")
    if not isinstance(vt_symbol, str) or not _VT_SYMBOL.fullmatch(vt_symbol):
        symbol, exchange = field("symbol"), field("exchange")
        exchange_value = getattr(exchange, "value", exchange)
        if not isinstance(symbol, str) or not isinstance(exchange_value, str):
            raise TickWireError("tick wire vt_symbol is invalid")
        vt_symbol = f"{symbol}.{exchange_value}"
    if not _VT_SYMBOL.fullmatch(vt_symbol):
        raise TickWireError("tick wire vt_symbol is invalid")
    observed_at = field("datetime")
    if isinstance(observed_at, datetime):
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise TickWireError("tick wire datetime is naive")
        event_time_utc = observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    elif isinstance(observed_at, str):
        event_time_utc = _event_time(observed_at)
    else:
        raise TickWireError("tick wire datetime is invalid")
    payload: dict[str, Any] = {
        "schema_version": TICK_WIRE_VERSION,
        "type": "tick",
        "vt_symbol": vt_symbol,
        "event_time_utc": event_time_utc,
        "last_price": _number(field("last_price"), "last_price"),
        "last_volume": _number(field("last_volume"), "last_volume"),
        "bid_price": _number(field("bid_price_1"), "bid_price"),
        "ask_price": _number(field("ask_price_1"), "ask_price"),
        "bid_volume": _number(field("bid_volume_1"), "bid_volume"),
        "ask_volume": _number(field("ask_volume_1"), "ask_volume"),
    }
    return payload


def decode_tick_wire_v1(topic: bytes, raw: bytes) -> dict[str, Any]:
    """Strictly validate the two-frame eTick.v1 wire without pickle fallback."""

    if not isinstance(topic, bytes) or not 0 < len(topic) <= MAX_TOPIC_BYTES:
        raise TickWireError("tick wire topic size is invalid")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PAYLOAD_BYTES:
        raise TickWireError("tick wire payload size is invalid")
    try:
        topic_text = topic.decode("ascii", errors="strict")
        value = json.loads(raw.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TickWireError("tick wire is not ASCII JSON") from exc
    if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS:
        raise TickWireError("tick wire fields are not exact")
    if raw != _canonical_json_bytes(value):
        raise TickWireError("tick wire JSON is not canonical")
    if value.get("schema_version") != TICK_WIRE_VERSION or value.get("type") != "tick":
        raise TickWireError("tick wire version/type is invalid")
    vt_symbol = _text(value.get("vt_symbol"), "vt_symbol")
    if not _VT_SYMBOL.fullmatch(vt_symbol) or topic_text != f"{TICK_WIRE_PREFIX}{vt_symbol}":
        raise TickWireError("tick wire topic/symbol mismatch")
    value["event_time_utc"] = _event_time(value.get("event_time_utc"))
    for field in _NUMBER_FIELDS:
        value[field] = _number(value.get(field), field)
    return value


class WindowsTickWirePublisherV1:
    """One dedicated PUB socket, owned by the Windows CTP process."""

    def __init__(self, *, context: Any, zmq_module: Any, bind_address: str = TICK_WIRE_BIND_ADDRESS) -> None:
        if bind_address != TICK_WIRE_BIND_ADDRESS:
            raise TickWireError("tick wire bind address must be fixed TCP/4103")
        self._socket = context.socket(zmq_module.PUB)
        self._socket.bind(bind_address)

    def publish_tick(self, tick: Any) -> None:
        payload = tick_wire_payload(tick)
        raw = _canonical_json_bytes(payload)
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise TickWireError("tick wire payload exceeds limit")
        topic = f"{TICK_WIRE_PREFIX}{payload['vt_symbol']}".encode("ascii")
        if len(topic) > MAX_TOPIC_BYTES:
            raise TickWireError("tick wire topic exceeds limit")
        self._socket.send_multipart((topic, raw), copy=True)

    def close(self) -> None:
        self._socket.close(linger=0)


def attach_windows_tick_wire_v1(gateway: Any) -> WindowsTickWirePublisherV1:
    """Attach before service start: ``attach_windows_tick_wire_v1(ctp_gateway)``."""

    if getattr(gateway, "_windows_tick_wire_v1", None) is not None:
        raise TickWireError("tick wire is already attached")
    try:
        import zmq
    except ImportError as exc:  # pragma: no cover - Windows deployment prerequisite
        raise RuntimeError("pyzmq is required for the eTick.v1 adapter") from exc
    on_tick = getattr(gateway, "on_tick", None)
    if not callable(on_tick):
        raise TickWireError("CTP gateway has no on_tick callback")
    publisher = WindowsTickWirePublisherV1(context=zmq.Context.instance(), zmq_module=zmq)

    def wrapped(subject: Any, tick: Any) -> Any:
        # The native gateway callback is authoritative.  A telemetry wire
        # failure must never make it lose a broker tick or hide its exception.
        result = on_tick(tick)
        try:
            publisher.publish_tick(tick)
        except Exception as exc:  # noqa: BLE001 - isolated best-effort sidecar
            gateway._windows_tick_wire_v1_last_error = type(exc).__name__
        return result

    gateway.on_tick = MethodType(wrapped, gateway)
    gateway._windows_tick_wire_v1 = publisher
    gateway._windows_tick_wire_v1_original_on_tick = on_tick
    return publisher


def detach_windows_tick_wire_v1(gateway: Any) -> None:
    """Explicit rollback hook; closes only the dedicated TCP/4103 publisher."""

    publisher = getattr(gateway, "_windows_tick_wire_v1", None)
    if not isinstance(publisher, WindowsTickWirePublisherV1):
        raise TickWireError("tick wire is not attached")
    original = getattr(gateway, "_windows_tick_wire_v1_original_on_tick", None)
    if not callable(original):
        raise TickWireError("tick wire original callback is unavailable")
    gateway.on_tick = original
    publisher.close()
    delattr(gateway, "_windows_tick_wire_v1")
    delattr(gateway, "_windows_tick_wire_v1_original_on_tick")
    if hasattr(gateway, "_windows_tick_wire_v1_last_error"):
        delattr(gateway, "_windows_tick_wire_v1_last_error")
