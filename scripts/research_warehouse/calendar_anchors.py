"""Externally hash-pinned calendar availability authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .calendar_models import OfficialCalendar
from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN
from .timeutil import parse_utc, require_utc

ANCHOR_SCHEMA = "vnpy_research_calendar_availability_anchor_v1"
ANCHOR_KEYS = {
    "schema_version",
    "calendar_raw_sha256",
    "source_evidence_sha256",
    "available_at",
}


@dataclass(frozen=True)
class CalendarAvailabilityAnchor:
    raw_sha256: str
    calendar_raw_sha256: str
    source_evidence_sha256: tuple[tuple[str, str], ...]
    available_at: datetime

    def require_available(
        self,
        calendar: OfficialCalendar,
        *,
        cutoff_at: datetime,
    ) -> None:
        cutoff = require_utc(cutoff_at, "calendar PIT cutoff")
        expected_evidence = calendar_evidence_anchor_bindings(calendar)
        if (
            self.calendar_raw_sha256 != calendar.raw_sha256
            or self.source_evidence_sha256 != expected_evidence
        ):
            raise RegistryError("calendar availability anchor binding mismatch")
        earliest_valid = max(
            calendar.issued_at,
            *(item.observed_at for item in calendar.source_evidence),
        )
        if self.available_at < earliest_valid:
            raise RegistryError("calendar anchor predates its signed evidence")
        if self.available_at > cutoff:
            raise RegistryError("official calendar was unavailable at PIT cutoff")


def calendar_evidence_anchor_bindings(
    calendar: OfficialCalendar,
) -> tuple[tuple[str, str], ...]:
    """Bind one or more annual official notices per frozen exchange."""
    result = []
    for exchange in calendar.exchanges:
        hashes = [
            item.raw_sha256
            for item in calendar.source_evidence
            if item.exchange == exchange
        ]
        if not hashes:
            raise RegistryError("calendar anchor evidence exchange is missing")
        digest = (
            hashes[0]
            if len(hashes) == 1
            else sha256(
                canonical_json_line(
                    {
                        "schema_version": (
                            "vnpy_research_calendar_evidence_bundle_v1"
                        ),
                        "exchange": exchange,
                        "raw_sha256": hashes,
                    }
                )
            )
        )
        result.append((exchange, digest))
    return tuple(result)


def load_calendar_availability_anchor(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> CalendarAvailabilityAnchor:
    if (
        not isinstance(expected_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_raw_sha256) is None
    ):
        raise RegistryError("trusted calendar anchor SHA256 is invalid")
    raw = read_regular_strict(path, "calendar availability anchor")
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("calendar availability anchor hash mismatch")
    payload = parse_json_strict(raw, "calendar availability anchor")
    if (
        not isinstance(payload, dict)
        or set(payload) != ANCHOR_KEYS
        or payload["schema_version"] != ANCHOR_SCHEMA
        or raw != canonical_json_line(payload)
    ):
        raise RegistryError("calendar availability anchor contract mismatch")
    calendar_digest = payload["calendar_raw_sha256"]
    if (
        not isinstance(calendar_digest, str)
        or SHA256_PATTERN.fullmatch(calendar_digest) is None
    ):
        raise RegistryError("calendar anchor calendar SHA256 is invalid")
    evidence = payload["source_evidence_sha256"]
    if not isinstance(evidence, dict) or list(evidence) != ["INE", "SHFE"]:
        raise RegistryError("calendar anchor evidence set/order mismatch")
    normalized = []
    for exchange, digest in evidence.items():
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise RegistryError("calendar anchor evidence SHA256 is invalid")
        normalized.append((exchange, digest))
    return CalendarAvailabilityAnchor(
        raw_sha256=expected_raw_sha256,
        calendar_raw_sha256=calendar_digest,
        source_evidence_sha256=tuple(normalized),
        available_at=parse_utc(
            payload["available_at"],
            "calendar anchor available_at",
        ),
    )
