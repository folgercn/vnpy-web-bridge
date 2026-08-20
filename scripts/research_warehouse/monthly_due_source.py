"""Pure current-root resolver for delayed monthly STATIC_CORE_EQUAL work.

The resolver deliberately starts from a :class:`CurrentCatalogHeadProof` and
the already verified signed calendar/availability objects.  It does not accept
a caller-selected day, source month, path, or clock.  The only possible due
day is the catalog root's exact ``last_trade_day`` and the month boundary is
classified by the same helper used by the historical baseline replay.

This module performs no filesystem, network, custody, event, cursor, account,
or execution operation.  Its results are Research-Plane classifications with
all authority permanently false.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Literal

from .calendar_anchors import CalendarAvailabilityAnchor
from .calendar_models import OfficialCalendar
from .canonical import canonical_json_line, parse_json_strict, sha256
from .daily_roll_predecessor_catalog import (
    CurrentCatalogHeadProof,
    MAX_ARTIFACT_RAW_BYTES,
    MAX_RECEIPT_RAW_BYTES,
    RECEIPT_KEYS,
    _receipt_id,
)
from .errors import RegistryError
from .m2_isolation_contracts import false_authority
from .m2_runtime_input import require_day, require_sha
from .pit_source_view import PitSourceViewError, _official_month_boundary
from .timeutil import format_utc, require_utc
from .verified_daily_pit_main_roll_source import (
    ROOT_KEYS as ARTIFACT_KEYS,
    SCHEMA_VERSION as ARTIFACT_SCHEMA,
    _artifact_id,
)

NO_MONTHLY_DUE = "NO_MONTHLY_DUE"
MONTHLY_DUE = "MONTHLY_DUE"
_RECEIPT_SCHEMA = "vnpy_research_daily_roll_predecessor_catalog_receipt_v1"


class MonthlyDueSourceError(RegistryError):
    """The supplied current-root evidence cannot classify monthly work."""


@dataclass(frozen=True, slots=True)
class MonthlyRootPins:
    """Exact no-authority pins common to either classifier outcome."""

    current_official_day: str
    calendar_id: str
    calendar_raw_sha256: str
    calendar_availability_anchor_raw_sha256: str
    calendar_available_at: str
    current_catalog_receipt_raw_sha256: str
    current_catalog_artifact_raw_sha256: str
    operator_state_raw_sha256: str
    operator_manifest_sequence: int
    manifest_genesis_seal_sha256: str
    manifest_head_seal_sha256: str
    manifest_head_commit_seal_sha256: str
    commit_anchor_ledger_raw_sha256: str


@dataclass(frozen=True, slots=True)
class NoMonthlyDue:
    """The current catalog root is valid but is not a monthly execution day."""

    status: Literal["NO_MONTHLY_DUE"]
    pins: MonthlyRootPins
    authority: dict[str, bool]


@dataclass(frozen=True, slots=True)
class MonthlyDueSource:
    """The unique delayed monthly source bound to the current catalog root."""

    status: Literal["MONTHLY_DUE"]
    source_month: str
    research_as_of_official_day: str
    execution_day: str
    pins: MonthlyRootPins
    authority: dict[str, bool]


MonthlyDueResolution = NoMonthlyDue | MonthlyDueSource


def _previous_month(value: date) -> str:
    previous_day = value.replace(day=1) - timedelta(days=1)
    return previous_day.strftime("%Y-%m")


def _validate_calendar_shape(calendar: OfficialCalendar) -> None:
    """Defend the pure boundary classifier from hand-built partial calendars.

    Production ``OfficialCalendar`` values have already passed the signed
    loader.  Rechecking the small canonical field set here keeps this pure
    function fail-closed if a caller constructs the public dataclass directly.
    It intentionally does not re-read the signed calendar or source files.
    """

    if (
        not isinstance(calendar, OfficialCalendar)
        or not isinstance(calendar.calendar_id, str)
        or not calendar.calendar_id
        or calendar.valid_to < calendar.valid_from
        or set(calendar.exchanges) != {"INE", "SHFE"}
        or len(calendar.exchanges) != 2
    ):
        raise MonthlyDueSourceError("signed calendar context is invalid")
    require_sha(calendar.raw_sha256, "monthly due calendar")
    require_utc(calendar.issued_at, "monthly due calendar issued_at")
    expected: list[date] = []
    current = calendar.valid_from
    while current <= calendar.valid_to:
        expected.append(current)
        current += timedelta(days=1)
    if list(calendar.days) != expected:
        raise MonthlyDueSourceError(
            "signed calendar does not canonically classify every natural day"
        )
    for day, row in calendar.days.items():
        if (
            row.day != day
            or row.status not in {"OFFICIAL_DAY", "CLOSED"}
            or (row.status == "CLOSED" and row.evening_session_natural_date is not None)
            or (
                row.evening_session_natural_date is not None
                and row.evening_session_natural_date >= day
            )
        ):
            raise MonthlyDueSourceError("signed calendar day is noncanonical")


def _validated_root(
    proof: CurrentCatalogHeadProof,
    *,
    calendar: OfficialCalendar,
    availability: CalendarAvailabilityAnchor,
) -> tuple[date, MonthlyRootPins]:
    if not isinstance(proof, CurrentCatalogHeadProof):
        raise MonthlyDueSourceError(
            "monthly due source requires CurrentCatalogHeadProof"
        )
    if not isinstance(availability, CalendarAvailabilityAnchor):
        raise MonthlyDueSourceError(
            "monthly due source requires verified calendar availability"
        )
    _validate_calendar_shape(calendar)
    try:
        require_sha(
            availability.raw_sha256,
            "monthly due calendar availability anchor",
        )
        require_sha(proof.receipt_raw_sha256, "monthly due catalog receipt")
        require_sha(proof.artifact_raw_sha256, "monthly due catalog artifact")
        require_sha(proof.operator_state_raw_sha256, "monthly due operator state")
        require_sha(
            proof.manifest_genesis_seal_sha256,
            "monthly due manifest genesis",
        )
        require_sha(proof.manifest_head_seal_sha256, "monthly due manifest head")
        require_sha(
            proof.manifest_head_commit_seal_sha256,
            "monthly due manifest head commit",
        )
        require_sha(
            proof.commit_anchor_ledger_raw_sha256,
            "monthly due commit anchor ledger",
        )
        if (
            not isinstance(proof.receipt_raw, bytes)
            or not proof.receipt_raw
            or len(proof.receipt_raw) > MAX_RECEIPT_RAW_BYTES
            or not isinstance(proof.artifact_raw, bytes)
            or not proof.artifact_raw
            or len(proof.artifact_raw) > MAX_ARTIFACT_RAW_BYTES
            or sha256(proof.receipt_raw) != proof.receipt_raw_sha256
            or sha256(proof.artifact_raw) != proof.artifact_raw_sha256
            or isinstance(proof.operator_manifest_sequence, bool)
            or not isinstance(proof.operator_manifest_sequence, int)
            or proof.operator_manifest_sequence < 1
            or proof.authority != false_authority()
        ):
            raise MonthlyDueSourceError("current catalog proof is noncanonical")

        receipt = parse_json_strict(
            proof.receipt_raw,
            "monthly due current catalog receipt",
        )
        artifact = parse_json_strict(
            proof.artifact_raw,
            "monthly due current catalog artifact",
        )
        if (
            not isinstance(receipt, dict)
            or not isinstance(artifact, dict)
            or set(receipt) != RECEIPT_KEYS
            or set(artifact) != ARTIFACT_KEYS
            or canonical_json_line(receipt) != proof.receipt_raw
            or canonical_json_line(artifact) != proof.artifact_raw
            or receipt.get("schema_version") != _RECEIPT_SCHEMA
            or artifact.get("schema_version") != ARTIFACT_SCHEMA
            or receipt.get("receipt_id") != _receipt_id(receipt)
            or artifact.get("artifact_id") != _artifact_id(artifact)
            or receipt.get("authority") != false_authority()
            or artifact.get("authority") != false_authority()
            or any(
                artifact.get(field) is not False
                for field in (
                    "installable",
                    "event_ready",
                    "production_allowed",
                    "live_trading_authorized",
                    "countable_forward",
                    "official_forward_claimed",
                    "dispatch_authorized",
                    "order_authorized",
                )
            )
        ):
            raise MonthlyDueSourceError("current catalog raw proof is noncanonical")

        root_day = require_day(proof.last_trade_day, "monthly due current root day")
        artifact_lineage = artifact["verified_lineage"]
        artifact_operator = artifact_lineage["operator_state"]
        artifact_manifest = artifact_lineage["manifest"]
        artifact_calendar = artifact_lineage["calendar"]
        if (
            receipt.get("official_day") != proof.last_trade_day
            or artifact.get("official_day") != proof.last_trade_day
            or receipt.get("artifact_id") != artifact.get("artifact_id")
            or receipt.get("artifact_raw_sha256") != proof.artifact_raw_sha256
            or receipt.get("artifact_raw_bytes") != len(proof.artifact_raw)
            or receipt.get("operator_state_raw_sha256")
            != proof.operator_state_raw_sha256
            or receipt.get("operator_manifest_sequence")
            != proof.operator_manifest_sequence
            or receipt.get("manifest_head_seal_sha256")
            != proof.manifest_head_seal_sha256
            or receipt.get("manifest_head_commit_seal_sha256")
            != proof.manifest_head_commit_seal_sha256
            or artifact_operator.get("raw_sha256") != proof.operator_state_raw_sha256
            or artifact_operator.get("manifest_sequence")
            != proof.operator_manifest_sequence
            or artifact_operator.get("manifest_genesis_seal_sha256")
            != proof.manifest_genesis_seal_sha256
            or artifact_operator.get("manifest_head_seal_sha256")
            != proof.manifest_head_seal_sha256
            or artifact_operator.get("manifest_head_commit_seal_sha256")
            != proof.manifest_head_commit_seal_sha256
            or artifact_operator.get("commit_anchor_ledger_raw_sha256")
            != proof.commit_anchor_ledger_raw_sha256
            or artifact_manifest.get("trade_day") != proof.last_trade_day
            or artifact_manifest.get("batch_seal_sha256")
            != proof.manifest_head_seal_sha256
            or artifact_manifest.get("commit_seal_sha256")
            != proof.manifest_head_commit_seal_sha256
        ):
            raise MonthlyDueSourceError(
                "current catalog receipt/artifact/root cross-splice"
            )
        if (
            artifact_calendar.get("calendar_id") != calendar.calendar_id
            or artifact_calendar.get("calendar_raw_sha256") != calendar.raw_sha256
            or artifact_calendar.get("calendar_availability_anchor_raw_sha256")
            != availability.raw_sha256
            or artifact_calendar.get("calendar_available_at")
            != format_utc(
                availability.available_at,
                "monthly due calendar available_at",
            )
        ):
            raise MonthlyDueSourceError(
                "current catalog root and calendar context are cross-spliced"
            )
        if not calendar.require_day(root_day).is_official:
            raise MonthlyDueSourceError(
                "current catalog root day is not an official calendar day"
            )
        availability.require_available(
            calendar,
            cutoff_at=availability.available_at,
        )
    except MonthlyDueSourceError:
        raise
    except (KeyError, TypeError, ValueError, RegistryError) as exc:
        raise MonthlyDueSourceError(
            "monthly due current-root verification failed"
        ) from exc

    return root_day, MonthlyRootPins(
        current_official_day=proof.last_trade_day,
        calendar_id=calendar.calendar_id,
        calendar_raw_sha256=calendar.raw_sha256,
        calendar_availability_anchor_raw_sha256=availability.raw_sha256,
        calendar_available_at=format_utc(
            availability.available_at,
            "monthly due calendar available_at",
        ),
        current_catalog_receipt_raw_sha256=proof.receipt_raw_sha256,
        current_catalog_artifact_raw_sha256=proof.artifact_raw_sha256,
        operator_state_raw_sha256=proof.operator_state_raw_sha256,
        operator_manifest_sequence=proof.operator_manifest_sequence,
        manifest_genesis_seal_sha256=proof.manifest_genesis_seal_sha256,
        manifest_head_seal_sha256=proof.manifest_head_seal_sha256,
        manifest_head_commit_seal_sha256=proof.manifest_head_commit_seal_sha256,
        commit_anchor_ledger_raw_sha256=proof.commit_anchor_ledger_raw_sha256,
    )


def _due_boundaries(
    calendar: OfficialCalendar,
    *,
    root_day: date,
) -> tuple[tuple[str, date, date], ...]:
    """Return all existing monthly boundaries whose execution is ``root_day``."""

    source_months = sorted(
        {
            day.strftime("%Y-%m")
            for day, row in calendar.days.items()
            if row.is_official and day < root_day.replace(day=1)
        }
    )
    candidates: list[tuple[str, date, date]] = []
    for source_month in source_months:
        try:
            research_day, execution_day, cutoff_day = _official_month_boundary(
                calendar,
                source_month=source_month,
            )
        except PitSourceViewError as exc:
            raise MonthlyDueSourceError(
                "signed calendar cannot classify a completed source month"
            ) from exc
        if execution_day == root_day:
            candidates.append((source_month, research_day, cutoff_day))
    return tuple(candidates)


def resolve_monthly_due_source(
    *,
    current_catalog_head: CurrentCatalogHeadProof,
    calendar: OfficialCalendar,
    calendar_availability: CalendarAvailabilityAnchor,
) -> MonthlyDueResolution:
    """Classify the one delayed monthly source, if any, at the current root.

    ``NO_MONTHLY_DUE`` is a normal exact outcome.  Ambiguous boundaries,
    calendar gaps spanning a whole source month, malformed inputs, and any
    catalog/calendar/root splice raise :class:`MonthlyDueSourceError` instead
    of being silently treated as no work.
    """

    root_day, pins = _validated_root(
        current_catalog_head,
        calendar=calendar,
        availability=calendar_availability,
    )
    candidates = _due_boundaries(calendar, root_day=root_day)
    if not candidates:
        return NoMonthlyDue(
            status=NO_MONTHLY_DUE,
            pins=pins,
            authority=false_authority(),
        )
    if len(candidates) != 1:
        raise MonthlyDueSourceError(
            "current catalog root maps to multiple monthly source boundaries"
        )
    source_month, research_day, cutoff_day = candidates[0]
    if source_month != _previous_month(root_day):
        raise MonthlyDueSourceError(
            "monthly boundary crosses an unclassified whole-month gap"
        )
    if research_day.strftime("%Y-%m") != source_month or research_day > cutoff_day:
        raise MonthlyDueSourceError("monthly source boundary is noncanonical")
    return MonthlyDueSource(
        status=MONTHLY_DUE,
        source_month=source_month,
        research_as_of_official_day=research_day.isoformat(),
        execution_day=root_day.isoformat(),
        pins=pins,
        authority=false_authority(),
    )
