"""Create-only evidence receipts for calendar-authorized HTTP 404 absence."""

from __future__ import annotations

from pathlib import Path

from .canonical import canonical_json, canonical_json_line, sha256
from .filesystem import WarehousePaths, create_only_bytes, custody_lock
from .timeutil import format_utc

ABSENCE_SCHEMA = "vnpy_research_authoritative_absence_v1"
ABSENCE_AUTHORITY = "CALENDAR_CLASSIFIED_SOURCE_ABSENCE_ONLY"


def create_absence_receipt(
    *,
    paths: WarehousePaths,
    source_id: str,
    exchange: str,
    trade_day: str,
    request_url: str,
    source_url: str,
    request_started_at,
    response_received_at,
    ntp_sampled_at,
    ntp_offset_milliseconds: int,
    http_metadata: dict[str, str | None],
    calendar_raw_sha256: str,
    registry_raw_sha256: str,
    collector_version: str,
) -> tuple[str, Path]:
    payload = {
        "schema_version": ABSENCE_SCHEMA,
        "absence_id": "",
        "source_id": source_id,
        "exchange": exchange,
        "trade_day": trade_day,
        "request_url": request_url,
        "source_url": source_url,
        "http_status": 404,
        "request_started_at": format_utc(
            request_started_at,
            "absence request_started_at",
        ),
        "response_received_at": format_utc(
            response_received_at,
            "absence response_received_at",
        ),
        "ntp_sampled_at": format_utc(
            ntp_sampled_at,
            "absence NTP sampled_at",
        ),
        "ntp_offset_milliseconds": ntp_offset_milliseconds,
        "http_metadata": http_metadata,
        "calendar_raw_sha256": calendar_raw_sha256,
        "registry_raw_sha256": registry_raw_sha256,
        "collector_version": collector_version,
        "authority": ABSENCE_AUTHORITY,
    }
    unsigned = {key: value for key, value in payload.items() if key != "absence_id"}
    payload["absence_id"] = "absence-" + sha256(canonical_json(unsigned))
    with custody_lock(paths, f"absence-{exchange.lower()}-{trade_day}-{source_id}"):
        parent = paths.private_subdir(
            paths.observations,
            "absence",
            exchange.lower(),
            trade_day,
            source_id,
        )
        receipt = parent / f"{payload['absence_id']}.json"
        create_only_bytes(
            receipt,
            canonical_json_line(payload),
            "authoritative absence receipt",
            temporary_dir=paths.temporary,
        )
    return payload["absence_id"], receipt
