"""Minimal fixed-endpoint NTP client for live scheduler clock evidence."""

from __future__ import annotations

import socket
import struct
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from .clock_quality import TrustedClockSample, validate_live_clock_sample
from .errors import RegistryError

NTP_SERVER = "time.apple.com"
NTP_PORT = 123
NTP_EPOCH = 2_208_988_800
PACKET_BYTES = 48


def _encode_timestamp(value: float) -> bytes:
    seconds = value + NTP_EPOCH
    whole = int(seconds)
    fraction = int((seconds - whole) * 2**32)
    return struct.pack("!II", whole, fraction)


def _decode_timestamp(raw: bytes) -> float:
    whole, fraction = struct.unpack("!II", raw)
    return whole - NTP_EPOCH + fraction / 2**32


def query_trusted_clock(
    *,
    timeout_seconds: float = 5.0,
    wall_clock: Callable[[], float] = time.time,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> TrustedClockSample:
    try:
        addresses = socket.getaddrinfo(
            NTP_SERVER,
            NTP_PORT,
            type=socket.SOCK_DGRAM,
        )
    except OSError as exc:
        raise RegistryError("trusted NTP endpoint cannot be resolved") from exc
    response = None
    last_error = None
    sent_unix = None
    received_unix = None
    elapsed = None
    request = None
    for family, socktype, protocol, _canonname, address in addresses:
        attempt = bytearray(PACKET_BYTES)
        attempt[0] = 0x23
        attempt_sent_unix = wall_clock()
        attempt[40:48] = _encode_timestamp(attempt_sent_unix)
        attempt_started = monotonic_clock()
        try:
            with socket.socket(family, socktype, protocol) as client:
                client.settimeout(timeout_seconds)
                client.connect(address)
                client.send(attempt)
                response = client.recv(512)
                received_unix = wall_clock()
                elapsed = monotonic_clock() - attempt_started
                sent_unix = attempt_sent_unix
                request = attempt
                break
        except OSError as exc:
            last_error = exc
    if (
        response is None
        or sent_unix is None
        or received_unix is None
        or elapsed is None
        or request is None
    ):
        raise RegistryError("trusted NTP query failed") from last_error
    if len(response) != PACKET_BYTES or elapsed < 0 or elapsed > timeout_seconds:
        raise RegistryError("trusted NTP response timing/size is invalid")
    leap = response[0] >> 6
    mode = response[0] & 0x07
    stratum = response[1]
    if leap == 3 or mode not in (4, 5) or not 1 <= stratum <= 15:
        raise RegistryError("trusted NTP response quality is invalid")
    if response[24:32] != request[40:48]:
        raise RegistryError("trusted NTP response request binding mismatch")
    server_received = _decode_timestamp(response[32:40])
    server_transmitted = _decode_timestamp(response[40:48])
    round_trip = (received_unix - sent_unix) - (
        server_transmitted - server_received
    )
    if (
        server_transmitted < server_received
        or round_trip < 0
        or round_trip > timeout_seconds
    ):
        raise RegistryError("trusted NTP response delay is invalid")
    offset_seconds = (
        (server_received - sent_unix) + (server_transmitted - received_unix)
    ) / 2
    offset_milliseconds = round(offset_seconds * 1000)
    local_received = datetime.fromtimestamp(received_unix, timezone.utc)
    trusted_now = local_received + timedelta(seconds=offset_seconds)
    sample = TrustedClockSample(
        trusted_now=trusted_now,
        sampled_at=trusted_now,
        ntp_offset_milliseconds=offset_milliseconds,
    )
    validate_live_clock_sample(sample, local_now=local_received)
    return sample
