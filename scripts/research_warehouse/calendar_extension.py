"""Issue a signed 2025-2026 calendar from retained and newly observed evidence."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .calendar_anchors import (
    ANCHOR_SCHEMA,
    calendar_evidence_anchor_bindings,
    load_calendar_availability_anchor,
)
from .calendar_models import CalendarSourceEvidence
from .calendar_schedule import VALID_FROM, VALID_TO, official_calendar_days
from .canonical import canonical_json, canonical_json_line, sha256
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict, write_all
from .official_calendar import (
    CALENDAR_AUTHORITY,
    CALENDAR_SCHEMA,
    SOURCE_TYPE,
    load_official_calendar,
)
from .signing import public_key_sha256, sign_payload
from .timeutil import format_utc, require_utc

CALENDAR_SIGNER_KEY_ID = "m2-calendar-prod-20260730"
OWNER = {
    "INE": "Shanghai International Energy Exchange",
    "SHFE": "Shanghai Futures Exchange",
}
TITLE = {
    "INE": "上海国际能源交易中心关于2025年休市安排的公告",
    "SHFE": "上海期货交易所关于2025年休市安排的公告",
}


@dataclass(frozen=True)
class NewCalendarEvidence:
    exchange: str
    source_url: str
    capture_path: Path


def _write_create_only(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        write_all(descriptor, raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    except FileExistsError:
        if read_regular_strict(path, "calendar create-only object") != raw:
            raise RegistryError("calendar create-only object conflicts")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    fsync_dir(path.parent)


def _retained_value(item: CalendarSourceEvidence) -> dict[str, object]:
    return {
        "exchange": item.exchange,
        "owner": item.owner,
        "source_url": item.source_url,
        "source_type": item.source_type,
        "observed_at": format_utc(item.observed_at),
        "raw_sha256": item.raw_sha256,
        "raw_bytes": item.raw_bytes,
        "raw_relative_path": item.raw_relative_path,
    }


def issue_extended_calendar(
    *,
    context,
    private_key: Ed25519PrivateKey,
    new_evidence: tuple[NewCalendarEvidence, NewCalendarEvidence],
    observed_at: datetime,
    issued_at: datetime,
) -> dict[str, object]:
    """Create immutable service-owned calendar objects; never mutate old inputs."""
    observed = require_utc(observed_at, "new calendar evidence observed_at")
    issued = require_utc(issued_at, "extended calendar issued_at")
    if issued < observed:
        raise RegistryError("extended calendar issuance predates observation")
    if public_key_sha256(private_key.public_key()) != context.runtime_input.payload[
        "expected_calendar_public_key_sha256"
    ]:
        raise RegistryError("calendar private/public key binding mismatch")
    if len(context.calendar.source_evidence) != 2:
        raise RegistryError("calendar extension requires one retained notice per exchange")
    supplied = {item.exchange: item for item in new_evidence}
    if set(supplied) != {"INE", "SHFE"}:
        raise RegistryError("calendar extension requires exact INE/SHFE evidence")

    values: list[dict[str, object]] = []
    evidence_root = Path(
        context.runtime_input.payload["calendar_source_evidence_root"]
    )
    for exchange in ("INE", "SHFE"):
        fresh = supplied[exchange]
        raw = read_regular_strict(
            fresh.capture_path,
            f"{exchange} 2025 official capture",
        )
        if TITLE[exchange].encode() not in raw:
            raise RegistryError(f"{exchange} capture lacks the official 2025 title")
        digest = sha256(raw)
        relative = f"calendar-sources/{exchange.lower()}/{digest}.raw"
        _write_create_only(evidence_root / relative, raw)
        retained = next(
            item
            for item in context.calendar.source_evidence
            if item.exchange == exchange
        )
        values.extend(
            (
                {
                    "exchange": exchange,
                    "owner": OWNER[exchange],
                    "source_url": fresh.source_url,
                    "source_type": SOURCE_TYPE,
                    "observed_at": format_utc(observed),
                    "raw_sha256": digest,
                    "raw_bytes": len(raw),
                    "raw_relative_path": relative,
                },
                _retained_value(retained),
            )
        )
    values.sort(key=lambda value: (value["exchange"], value["source_url"]))
    payload = {
        "schema_version": CALENDAR_SCHEMA,
        "calendar_id": "",
        "timezone": "Asia/Shanghai",
        "timestamp_storage": "UTC",
        "valid_from": VALID_FROM.isoformat(),
        "valid_to": VALID_TO.isoformat(),
        "issued_at": format_utc(issued),
        "exchanges": ["INE", "SHFE"],
        "source_evidence": values,
        "days": official_calendar_days(),
        "authority": CALENDAR_AUTHORITY,
        "signer_key_id": CALENDAR_SIGNER_KEY_ID,
        "signer_public_key_sha256": public_key_sha256(private_key.public_key()),
    }
    base = dict(payload)
    base.pop("calendar_id")
    payload["calendar_id"] = "calendar-" + sha256(canonical_json(base))
    calendar_raw = canonical_json_line(sign_payload(payload, private_key))
    calendar_sha = sha256(calendar_raw)
    input_root = Path(context.runtime_input.payload["calendar_path"]).parent
    calendar_path = input_root / f"official-calendar-{calendar_sha}.json"
    _write_create_only(calendar_path, calendar_raw)
    calendar = load_official_calendar(
        calendar_path,
        public_key=private_key.public_key(),
        expected_raw_sha256=calendar_sha,
        source_evidence_root=evidence_root,
    )
    anchor_raw = canonical_json_line(
        {
            "schema_version": ANCHOR_SCHEMA,
            "calendar_raw_sha256": calendar_sha,
            "source_evidence_sha256": dict(
                calendar_evidence_anchor_bindings(calendar)
            ),
            "available_at": format_utc(issued),
        }
    )
    anchor_sha = sha256(anchor_raw)
    anchor_path = input_root / f"calendar-anchor-{anchor_sha}.json"
    _write_create_only(anchor_path, anchor_raw)
    anchor = load_calendar_availability_anchor(
        anchor_path,
        expected_raw_sha256=anchor_sha,
    )
    anchor.require_available(calendar, cutoff_at=issued)
    return {
        "calendar_path": str(calendar_path),
        "calendar_raw_sha256": calendar_sha,
        "calendar_availability_anchor_path": str(anchor_path),
        "calendar_availability_anchor_raw_sha256": anchor_sha,
        "available_at": format_utc(issued),
        "new_evidence_sha256": {
            item.exchange: sha256(
                read_regular_strict(
                    item.capture_path,
                    f"{item.exchange} 2025 official capture",
                )
            )
            for item in new_evidence
        },
    }
