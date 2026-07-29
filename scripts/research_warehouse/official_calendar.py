"""Load a signed, explicit, raw-evidence-bound official-day calendar."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .calendar_models import (
    CalendarDay,
    CalendarSourceEvidence,
    OfficialCalendar,
)
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .custody_paths import normalized_absolute, require_private_dir
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import ID_PATTERN, SHA256_PATTERN
from .policy import validate_https_url
from .signing import public_key_sha256, verify_payload
from .timeutil import parse_utc

CALENDAR_SCHEMA = "vnpy_research_official_calendar_v1"
CALENDAR_AUTHORITY = "SIGNED_SHFE_INE_OFFICIAL_DAY_EVIDENCE_ONLY"
CALENDAR_KEYS = {
    "schema_version",
    "calendar_id",
    "timezone",
    "timestamp_storage",
    "valid_from",
    "valid_to",
    "issued_at",
    "exchanges",
    "source_evidence",
    "days",
    "authority",
    "signer_key_id",
    "signer_public_key_sha256",
    "signature",
}
EVIDENCE_KEYS = {
    "exchange",
    "owner",
    "source_url",
    "source_type",
    "observed_at",
    "raw_sha256",
    "raw_bytes",
    "raw_relative_path",
}
DAY_KEYS = {"date", "status", "evening_session_natural_date"}
EXCHANGES = ("INE", "SHFE")
SOURCE_CONTRACTS = {
    "INE": ("Shanghai International Energy Exchange", "www.ine.cn"),
    "SHFE": ("Shanghai Futures Exchange", "www.shfe.com.cn"),
}
SOURCE_TYPE = "OFFICIAL_TRADING_CALENDAR_EXPORT_OR_CLOSURE_NOTICE"
STATUSES = {"OFFICIAL_DAY", "CLOSED"}


def _canonical_date(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise RegistryError(f"{label} must be YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise RegistryError(f"{label} is not canonical")
    return parsed


def _calendar_base(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"calendar_id", "signature"}
    }


def _safe_evidence_path(root: Path, relative: object) -> Path:
    if not isinstance(relative, str):
        raise RegistryError("calendar source evidence path must be a string")
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or len(pure.parts) != 3
        or pure.parts[0] != "calendar-sources"
    ):
        raise RegistryError("calendar source evidence path is unsafe")
    absolute = normalized_absolute(root)
    require_private_dir(absolute, "calendar source evidence root")
    current = absolute
    for component in pure.parts[:-1]:
        current /= component
        require_private_dir(current, "calendar source evidence parent")
    return absolute.joinpath(*pure.parts)


def _load_evidence(
    root: Path,
    value: object,
    *,
    issued_at,
) -> CalendarSourceEvidence:
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        raise RegistryError("calendar source evidence fields do not match v1")
    exchange = value["exchange"]
    if exchange not in SOURCE_CONTRACTS:
        raise RegistryError("calendar evidence exchange is not trusted")
    owner, host = SOURCE_CONTRACTS[exchange]
    if value["owner"] != owner or value["source_type"] != SOURCE_TYPE:
        raise RegistryError("calendar evidence owner/type mismatch")
    source_url = value["source_url"]
    if not isinstance(source_url, str):
        raise RegistryError("calendar evidence URL must be a string")
    validate_https_url(
        source_url,
        allowed_hosts=(host,),
        label="calendar evidence URL",
    )
    observed_at = parse_utc(value["observed_at"], "calendar evidence observed_at")
    if observed_at > issued_at:
        raise RegistryError("calendar evidence was observed after calendar issuance")
    digest = value["raw_sha256"]
    size = value["raw_bytes"]
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise RegistryError("calendar evidence SHA256 is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise RegistryError("calendar evidence byte count is invalid")
    path = _safe_evidence_path(root, value["raw_relative_path"])
    expected_relative = f"calendar-sources/{exchange.lower()}/{digest}.raw"
    if value["raw_relative_path"] != expected_relative:
        raise RegistryError("calendar evidence path/hash binding mismatch")
    raw = read_regular_strict(path, "calendar official source evidence")
    if len(raw) != size or sha256(raw) != digest:
        raise RegistryError("calendar official source evidence changed")
    return CalendarSourceEvidence(
        exchange=exchange,
        owner=owner,
        source_url=source_url,
        source_type=SOURCE_TYPE,
        observed_at=observed_at,
        raw_sha256=digest,
        raw_bytes=size,
        raw_relative_path=expected_relative,
    )


def revalidate_official_calendar_evidence(calendar: OfficialCalendar) -> None:
    """Prove the exact signed source bytes still exist at evaluation time."""
    for evidence in calendar.source_evidence:
        path = _safe_evidence_path(
            calendar.source_evidence_root,
            evidence.raw_relative_path,
        )
        raw = read_regular_strict(path, "calendar official source evidence")
        if len(raw) != evidence.raw_bytes or sha256(raw) != evidence.raw_sha256:
            raise RegistryError("calendar official source evidence changed")


def _load_days(
    values: object,
    *,
    valid_from: date,
    valid_to: date,
) -> dict[date, CalendarDay]:
    if not isinstance(values, list) or not values:
        raise RegistryError("calendar days must be a non-empty list")
    result = {}
    for value in values:
        if not isinstance(value, dict) or set(value) != DAY_KEYS:
            raise RegistryError("calendar day fields do not match v1")
        day = _canonical_date(value["date"], "calendar day")
        status = value["status"]
        evening_value = value["evening_session_natural_date"]
        evening_day = (
            None
            if evening_value is None
            else _canonical_date(evening_value, "evening session natural date")
        )
        if status not in STATUSES:
            raise RegistryError("calendar day status is invalid")
        if status == "CLOSED" and evening_day is not None:
            raise RegistryError("closed calendar day cannot have a night session")
        if evening_day is not None and evening_day >= day:
            raise RegistryError("evening session date must precede its trade day")
        if day in result:
            raise RegistryError("calendar repeats a natural day")
        result[day] = CalendarDay(
            day=day,
            status=status,
            evening_session_natural_date=evening_day,
        )
    expected = []
    current = valid_from
    while current <= valid_to:
        expected.append(current)
        current += timedelta(days=1)
    if list(result) != expected:
        raise RegistryError("calendar must classify every natural day in order")
    if sum(item.is_official for item in result.values()) < 186:
        raise RegistryError("calendar must cover at least 186 official days")
    session_days = [
        item.evening_session_natural_date
        for item in result.values()
        if item.evening_session_natural_date is not None
    ]
    if len(session_days) != len(set(session_days)):
        raise RegistryError("calendar repeats an evening-session natural date")
    previous_official = None
    for day, item in result.items():
        evening_day = item.evening_session_natural_date
        if evening_day is not None and evening_day != previous_official:
            raise RegistryError(
                "evening session date must be the previous official workday"
            )
        if item.is_official:
            previous_official = day
    return result


def load_official_calendar(
    path: Path,
    *,
    public_key: Ed25519PublicKey,
    expected_raw_sha256: str,
    source_evidence_root: Path,
) -> OfficialCalendar:
    if (
        not isinstance(expected_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_raw_sha256) is None
    ):
        raise RegistryError("trusted calendar SHA256 is invalid")
    raw = read_regular_strict(path, "signed official calendar", limit=8 * 1024 * 1024)
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("signed official calendar hash mismatch")
    payload = parse_json_strict(raw, "signed official calendar")
    if not isinstance(payload, dict) or set(payload) != CALENDAR_KEYS:
        raise RegistryError("signed official calendar fields do not match v1")
    if raw != canonical_json_line(payload):
        raise RegistryError("signed official calendar is not canonical JSON")
    if payload["schema_version"] != CALENDAR_SCHEMA:
        raise RegistryError("official calendar schema mismatch")
    if payload["timezone"] != "Asia/Shanghai" or payload["timestamp_storage"] != "UTC":
        raise RegistryError("official calendar timezone contract mismatch")
    if payload["authority"] != CALENDAR_AUTHORITY:
        raise RegistryError("official calendar authority mismatch")
    if payload["exchanges"] != list(EXCHANGES):
        raise RegistryError("official calendar must bind exact SHFE/INE exchanges")
    if (
        not isinstance(payload["signer_key_id"], str)
        or ID_PATTERN.fullmatch(payload["signer_key_id"]) is None
        or payload["signer_public_key_sha256"] != public_key_sha256(public_key)
    ):
        raise RegistryError("official calendar signer binding mismatch")
    unsigned = verify_payload(payload, public_key)
    valid_from = _canonical_date(payload["valid_from"], "calendar valid_from")
    valid_to = _canonical_date(payload["valid_to"], "calendar valid_to")
    if valid_to < valid_from:
        raise RegistryError("official calendar validity range is reversed")
    issued_at = parse_utc(payload["issued_at"], "calendar issued_at")
    expected_id = "calendar-" + sha256(canonical_json(_calendar_base(unsigned)))
    if payload["calendar_id"] != expected_id:
        raise RegistryError("official calendar ID binding mismatch")
    evidence_values = payload["source_evidence"]
    if not isinstance(evidence_values, list) or len(evidence_values) != 2:
        raise RegistryError("calendar must bind exact SHFE/INE source evidence")
    evidence = tuple(
        _load_evidence(
            source_evidence_root,
            value,
            issued_at=issued_at,
        )
        for value in evidence_values
    )
    if tuple(item.exchange for item in evidence) != EXCHANGES:
        raise RegistryError("calendar source evidence order/set mismatch")
    days = _load_days(
        payload["days"],
        valid_from=valid_from,
        valid_to=valid_to,
    )
    return OfficialCalendar.create(
        calendar_id=payload["calendar_id"],
        raw_sha256=expected_raw_sha256,
        valid_from=valid_from,
        valid_to=valid_to,
        issued_at=issued_at,
        exchanges=EXCHANGES,
        days=days,
        source_evidence=evidence,
        source_evidence_root=normalized_absolute(source_evidence_root),
    )
