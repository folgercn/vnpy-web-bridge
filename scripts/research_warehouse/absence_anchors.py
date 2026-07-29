"""Externally hash-pinned availability for durable 404 receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from .absence_receipts import ABSENCE_AUTHORITY, ABSENCE_SCHEMA
from .calendar_anchors import CalendarAvailabilityAnchor
from .calendar_models import OfficialCalendar
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import ID_PATTERN, SHA256_PATTERN
from .models import SourceRegistry
from .official_calendar import revalidate_official_calendar_evidence
from .policy import render_endpoint, validate_redirect
from .source_availability import classify_http_status
from .timeutil import parse_utc, require_utc

ANCHOR_SCHEMA = "vnpy_research_absence_availability_anchor_v1"
ANCHOR_KEYS = {
    "schema_version",
    "absence_id",
    "receipt_sha256",
    "calendar_raw_sha256",
    "registry_raw_sha256",
    "available_at",
}
RECEIPT_KEYS = {
    "schema_version",
    "absence_id",
    "source_id",
    "exchange",
    "trade_day",
    "request_url",
    "source_url",
    "http_status",
    "request_started_at",
    "response_received_at",
    "ntp_sampled_at",
    "ntp_offset_milliseconds",
    "http_metadata",
    "calendar_raw_sha256",
    "registry_raw_sha256",
    "collector_version",
    "authority",
}
EXCHANGE_HOSTS = {
    "INE": "www.ine.cn",
    "SHFE": "www.shfe.com.cn",
}
HTTP_METADATA_KEYS = {
    "content-length",
    "content-type",
    "etag",
    "last-modified",
}


@dataclass(frozen=True)
class AbsenceAvailabilityAnchor:
    raw_sha256: str
    absence_id: str
    receipt_sha256: str
    calendar_raw_sha256: str
    registry_raw_sha256: str
    response_received_at: datetime
    available_at: datetime

    def require_available(self, *, cutoff_at: datetime) -> None:
        if self.available_at > require_utc(cutoff_at, "absence PIT cutoff"):
            raise RegistryError("absence receipt was unavailable at PIT cutoff")


def _load_receipt(path: Path) -> tuple[dict, str]:
    raw = read_regular_strict(path, "authoritative absence receipt")
    payload = parse_json_strict(raw, "authoritative absence receipt")
    if (
        not isinstance(payload, dict)
        or set(payload) != RECEIPT_KEYS
        or payload["schema_version"] != ABSENCE_SCHEMA
        or payload["authority"] != ABSENCE_AUTHORITY
        or payload["http_status"] != 404
        or raw != canonical_json_line(payload)
    ):
        raise RegistryError("authoritative absence receipt contract mismatch")
    absence_id = payload["absence_id"]
    if (
        not isinstance(absence_id, str)
        or not absence_id.startswith("absence-")
        or SHA256_PATTERN.fullmatch(absence_id.removeprefix("absence-")) is None
    ):
        raise RegistryError("authoritative absence ID is invalid")
    unsigned = {key: value for key, value in payload.items() if key != "absence_id"}
    if absence_id != "absence-" + sha256(canonical_json(unsigned)):
        raise RegistryError("authoritative absence ID binding mismatch")
    request_started = parse_utc(
        payload["request_started_at"],
        "absence request_started_at",
    )
    response_received = parse_utc(
        payload["response_received_at"],
        "absence response_received_at",
    )
    sampled_at = parse_utc(payload["ntp_sampled_at"], "absence NTP sampled_at")
    sample_age = request_started - sampled_at
    if (
        sample_age < timedelta(0)
        or sample_age > timedelta(seconds=300)
        or response_received < request_started
    ):
        raise RegistryError("authoritative absence time ordering is invalid")
    try:
        trade_day = date.fromisoformat(payload["trade_day"])
    except (TypeError, ValueError) as exc:
        raise RegistryError("authoritative absence trade day is invalid") from exc
    if trade_day.isoformat() != payload["trade_day"]:
        raise RegistryError("authoritative absence trade day is not canonical")
    exchange = payload["exchange"]
    source_url = payload["source_url"]
    if (
        exchange not in EXCHANGE_HOSTS
        or not isinstance(source_url, str)
        or urlsplit(source_url).scheme != "https"
        or urlsplit(source_url).hostname != EXCHANGE_HOSTS[exchange]
        or urlsplit(source_url).username is not None
        or urlsplit(source_url).password is not None
    ):
        raise RegistryError("authoritative absence source authority is invalid")
    offset = payload["ntp_offset_milliseconds"]
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or abs(offset) > 1_000
    ):
        raise RegistryError("authoritative absence NTP offset is invalid")
    metadata = payload["http_metadata"]
    if (
        not isinstance(metadata, dict)
        or set(metadata) != HTTP_METADATA_KEYS
        or any(
            value is not None and not isinstance(value, str)
            for value in metadata.values()
        )
    ):
        raise RegistryError("authoritative absence HTTP metadata is invalid")
    calendar_digest = payload["calendar_raw_sha256"]
    if (
        not isinstance(calendar_digest, str)
        or SHA256_PATTERN.fullmatch(calendar_digest) is None
    ):
        raise RegistryError("authoritative absence calendar SHA256 is invalid")
    registry_digest = payload["registry_raw_sha256"]
    if (
        not isinstance(registry_digest, str)
        or SHA256_PATTERN.fullmatch(registry_digest) is None
    ):
        raise RegistryError("authoritative absence registry SHA256 is invalid")
    if (
        not isinstance(payload["source_id"], str)
        or ID_PATTERN.fullmatch(payload["source_id"]) is None
    ):
        raise RegistryError("authoritative absence source ID is invalid")
    return payload, sha256(raw)


def load_absence_availability_anchor(
    path: Path,
    *,
    expected_raw_sha256: str,
    receipt_path: Path,
    calendar: OfficialCalendar,
    calendar_anchor: CalendarAvailabilityAnchor,
    registry: SourceRegistry,
) -> AbsenceAvailabilityAnchor:
    if (
        not isinstance(expected_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_raw_sha256) is None
    ):
        raise RegistryError("trusted absence anchor SHA256 is invalid")
    receipt, receipt_sha = _load_receipt(receipt_path)
    revalidate_official_calendar_evidence(calendar)
    if receipt["calendar_raw_sha256"] != calendar.raw_sha256:
        raise RegistryError("absence receipt calendar binding mismatch")
    if receipt["registry_raw_sha256"] != registry.raw_sha256:
        raise RegistryError("absence receipt registry binding mismatch")
    try:
        source = registry.source(receipt["source_id"])
    except KeyError as exc:
        raise RegistryError("absence receipt source is not in registry") from exc
    if source.exchange != receipt["exchange"]:
        raise RegistryError("absence receipt source/exchange binding mismatch")
    expected_request_url = render_endpoint(
        source.endpoint_template,
        receipt["trade_day"].replace("-", ""),
    )
    if receipt["request_url"] != expected_request_url:
        raise RegistryError("absence receipt request endpoint binding mismatch")
    validate_redirect(receipt["source_url"], source.allowed_hosts)
    request_started = parse_utc(
        receipt["request_started_at"],
        "absence request_started_at",
    )
    calendar_anchor.require_available(
        calendar,
        cutoff_at=request_started,
    )
    availability = classify_http_status(
        calendar=calendar,
        exchange=receipt["exchange"],
        requested_day=date.fromisoformat(receipt["trade_day"]),
        status=receipt["http_status"],
    )
    if availability != "CALENDAR_AUTHORIZED_ABSENCE_AWAITING_EXTERNAL_ANCHOR":
        raise RegistryError("absence receipt is not calendar-authorized")
    raw = read_regular_strict(path, "absence availability anchor")
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("absence availability anchor hash mismatch")
    payload = parse_json_strict(raw, "absence availability anchor")
    if (
        not isinstance(payload, dict)
        or set(payload) != ANCHOR_KEYS
        or payload["schema_version"] != ANCHOR_SCHEMA
        or raw != canonical_json_line(payload)
    ):
        raise RegistryError("absence availability anchor contract mismatch")
    if (
        payload["absence_id"] != receipt["absence_id"]
        or payload["receipt_sha256"] != receipt_sha
        or payload["calendar_raw_sha256"] != receipt["calendar_raw_sha256"]
        or payload["registry_raw_sha256"] != registry.raw_sha256
    ):
        raise RegistryError("absence availability anchor binding mismatch")
    available_at = parse_utc(
        payload["available_at"],
        "absence anchor available_at",
    )
    response_received = parse_utc(
        receipt["response_received_at"],
        "absence response_received_at",
    )
    earliest_valid = max(
        response_received,
        calendar.issued_at,
        calendar_anchor.available_at,
        *(item.observed_at for item in calendar.source_evidence),
    )
    if available_at < earliest_valid:
        raise RegistryError("absence anchor predates its authority or response")
    return AbsenceAvailabilityAnchor(
        raw_sha256=expected_raw_sha256,
        absence_id=receipt["absence_id"],
        receipt_sha256=receipt_sha,
        calendar_raw_sha256=receipt["calendar_raw_sha256"],
        registry_raw_sha256=registry.raw_sha256,
        response_received_at=response_received,
        available_at=available_at,
    )
