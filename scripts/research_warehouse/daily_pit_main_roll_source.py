"""Deterministic, no-authority daily PIT-main foundation for roll research.

The producer accepts one completed official day's exact SHFE/INE raw bytes and
caller-claimed lineage.  It does not acquire data, prove lineage continuity,
inspect an account, calculate quantities, publish files, install targets, or
dispatch an order.  The returned canonical bytes are foundation-only.

The caller-supplied predecessor exact-contract map is deliberately treated as
unverified input.  ``changed_products`` and ``roll_change_detected`` describe
only the comparison against that input; they are not an executable event,
trigger, authorization, or dispatch decision.  No installer, scheduler, event
producer, or execution consumer may consume this v1 artifact.  Only a future
verified v2 contract that independently reconstructs and verifies all input
lineage may become consumable.  ``execution_lane=simnow_shakedown`` is a
classification, not permission to enter that lane.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import math
from pathlib import PurePosixPath
import re
from typing import Any

import commodity_c_fast_pure_producer_kernel as frozen

from .calendar_models import OfficialCalendar
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .m2_isolation_contracts import false_authority
from .m2_receipts import validate_run_receipt
from .m2_runtime_input import require_sha
from .manifest_contracts import ID_PATTERN
from .pit_source_view import _pit_main, contract_rows_from_daily_raw
from .static_core_baseline import _last_trading_day, _registry
from .timeutil import parse_utc

SCHEMA_VERSION = "vnpy_research_commodity_daily_pit_main_roll_source_v1"
SOURCE_KIND = "DAILY_PIT_MAIN_ROLL_ONLY"
DERIVATION_ID = "FROZEN_OI_DESC_DELIVERY_ASC_EXACT_ASC_ROLL_SOURCE_V1"
INPUT_LINEAGE_STATUS = "UNVERIFIED_FOUNDATION_ONLY"
EXECUTION_LANE = "simnow_shakedown"
MIN_DTE_CALENDAR_DAYS = 11
MAX_ELIGIBLE_CONTRACT_COUNT = 64
MAX_SOURCE_ID_CHARS = 256
MAX_RAW_RELATIVE_PATH_CHARS = 1024
MAX_CALENDAR_ID_CHARS = 128
MAX_SOURCE_RAW_BYTES = 16 * 1024 * 1024
MAX_AGGREGATE_SOURCE_RAW_BYTES = 32 * 1024 * 1024
MAX_RUN_RECEIPT_RAW_BYTES = 1024 * 1024
MAX_CONTRACT_REGISTRY_RAW_BYTES = 1024 * 1024
MAX_ARTIFACT_RAW_BYTES = 4 * 1024 * 1024
EXCHANGES = ("SHFE", "INE")
RAW_RELATIVE_PATH_PATTERN = re.compile(
    r"^raw/(?!\.\.(?:/|$))(?!.*\/\.\.(?:/|$))"
    r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
)

ROOT_KEYS = {
    "schema_version",
    "artifact_id",
    "source_kind",
    "derivation_id",
    "official_day",
    "execution_day",
    "following_official_day",
    "roll_change_detected",
    "changed_products",
    "input_lineage_status",
    "installable",
    "event_ready",
    "execution_lane",
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
    "official_forward_claimed",
    "mains",
    "claimed_lineage",
    "authority",
}
MAIN_KEYS = {
    "product",
    "exchange",
    "previous_exact_contract",
    "exact_contract",
    "changed",
    "delivery_yyyymm",
    "settlement",
    "open_interest",
    "eligible_contract_count",
    "ranked_contracts_sha256",
    "official_last_trading_day",
    "execution_day_dte",
    "following_official_day_dte",
}
CLAIMED_LINEAGE_KEYS = {
    "run_receipt",
    "sources",
    "manifest",
    "calendar",
    "policy",
    "contract_registry_raw_sha256",
    "predecessor_exact_contract_map_sha256",
    "producer_kernel_id",
    "frozen_rule_id",
    "frozen_rule_sha256",
}
RUN_RECEIPT_CLAIM_KEYS = {
    "receipt_id",
    "completed_at",
    "raw_sha256",
    "raw_bytes",
    "registry_raw_sha256",
}
SOURCE_CLAIM_KEYS = {
    "source_id",
    "exchange",
    "object_id",
    "observation_id",
    "revision_id",
    "raw_sha256",
    "raw_bytes",
    "raw_relative_path",
}
MANIFEST_KEYS = {
    "trade_day",
    "batch_id",
    "batch_seal_sha256",
    "commit_seal_sha256",
    "manifest_raw_sha256",
    "commit_receipt_raw_sha256",
    "operator_state_raw_sha256",
    "manifest_genesis_seal_sha256",
    "manifest_head_seal_sha256",
    "manifest_head_commit_seal_sha256",
    "commit_anchor_ledger_raw_sha256",
    "sources",
}
MANIFEST_SOURCE_KEYS = {
    "source_id",
    "exchange",
    "revision_id",
    "raw_sha256",
    "raw_bytes",
    "raw_relative_path",
}
CALENDAR_KEYS = {
    "calendar_id",
    "calendar_raw_sha256",
    "calendar_availability_anchor_raw_sha256",
}
POLICY_KEYS = {
    "isolation_policy_raw_sha256",
    "runtime_input_raw_sha256",
    "release_tree_manifest_raw_sha256",
}


class DailyPitMainRollSourceError(RegistryError):
    """Fail-closed daily roll-source construction error."""


@dataclass(frozen=True)
class BuiltDailyPitMainRollSource:
    artifact_raw: bytes
    artifact_id: str
    artifact_raw_sha256: str


def _exact_dict(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise DailyPitMainRollSourceError(f"{label} fields do not match v1")
    return value


def _positive_int(value: object, label: str, *, maximum: int | None = None) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or (maximum is not None and value > maximum)
    ):
        raise DailyPitMainRollSourceError(f"{label} is outside the admitted range")
    return value


def _bounded_bytes(raw: object, label: str, maximum: int) -> bytes:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise DailyPitMainRollSourceError(f"{label} resource limit exceeded")
    return raw


def _bounded_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise DailyPitMainRollSourceError(f"{label} is outside the admitted range")
    return value


def _canonical_day(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise DailyPitMainRollSourceError(f"{label} must be canonical YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise DailyPitMainRollSourceError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise DailyPitMainRollSourceError(f"{label} is not canonical")
    return parsed


def _exact_contract(value: object, product: str, exchange: str, label: str) -> str:
    if not isinstance(value, str):
        raise DailyPitMainRollSourceError(f"{label} exact contract is invalid")
    match = frozen.CONTRACT_PATTERN.fullmatch(value)
    if (
        match is None
        or match.group(1) != exchange
        or match.group(2) != product
        or not 1 <= int(value[-2:]) <= 12
    ):
        raise DailyPitMainRollSourceError(f"{label} exact contract is invalid")
    return value


def _following_official_days(
    calendar: OfficialCalendar,
    official_day: date,
) -> tuple[date, date]:
    try:
        classified = calendar.require_day(official_day)
    except RegistryError as exc:
        raise DailyPitMainRollSourceError(str(exc)) from exc
    if not classified.is_official:
        raise DailyPitMainRollSourceError("daily roll official_day is not official")
    following = sorted(
        day
        for day, row in calendar.days.items()
        if row.is_official and day > official_day
    )
    if len(following) < 2:
        raise DailyPitMainRollSourceError(
            "calendar lacks execution and following official days"
        )
    return following[0], following[1]


def _validate_policy_lineage(value: object) -> dict[str, str]:
    policy = _exact_dict(value, POLICY_KEYS, "daily roll policy lineage")
    return {
        field: require_sha(policy[field], f"daily roll {field}")
        for field in sorted(POLICY_KEYS)
    }


def _validate_manifest_lineage(
    value: object,
    *,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    manifest = _exact_dict(value, MANIFEST_KEYS, "daily roll manifest lineage")
    if manifest["trade_day"] != receipt["trade_day"]:
        raise DailyPitMainRollSourceError("manifest/receipt trade day mismatch")
    batch_id = manifest["batch_id"]
    if not isinstance(batch_id, str) or ID_PATTERN.fullmatch(batch_id) is None:
        raise DailyPitMainRollSourceError("daily roll manifest batch ID is invalid")
    for field in MANIFEST_KEYS - {"trade_day", "batch_id", "sources"}:
        require_sha(manifest[field], f"daily roll manifest {field}")
    if (
        manifest["manifest_head_seal_sha256"] != manifest["batch_seal_sha256"]
        or manifest["manifest_head_commit_seal_sha256"]
        != manifest["commit_seal_sha256"]
    ):
        raise DailyPitMainRollSourceError("daily roll manifest is not the pinned head")
    sources = manifest["sources"]
    receipt_sources = receipt["sources"]
    if (
        not isinstance(sources, list)
        or len(sources) != len(EXCHANGES)
        or any(not isinstance(item, dict) for item in sources)
    ):
        raise DailyPitMainRollSourceError(
            "daily roll manifest must bind exact SHFE/INE sources"
        )
    normalized_sources = []
    for index, exchange in enumerate(EXCHANGES):
        item = _exact_dict(
            sources[index],
            MANIFEST_SOURCE_KEYS,
            f"daily roll manifest {exchange} source",
        )
        receipt_item = receipt_sources[index]
        if item["exchange"] != exchange or any(
            item[field] != receipt_item[field] for field in MANIFEST_SOURCE_KEYS
        ):
            raise DailyPitMainRollSourceError(
                "daily roll manifest/receipt source binding mismatch"
            )
        normalized_sources.append(dict(item))
    return {
        key: (normalized_sources if key == "sources" else manifest[key])
        for key in sorted(MANIFEST_KEYS)
    }


def _validate_predecessor_map(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or tuple(sorted(value)) != frozen.PRODUCTS:
        raise DailyPitMainRollSourceError(
            "predecessor exact-contract map must cover exact ten products"
        )
    result: dict[str, str] = {}
    for product in frozen.PRODUCTS:
        exchange = str(frozen.PRODUCT_SPECS[product]["exchange"])
        result[product] = _exact_contract(
            value[product],
            product,
            exchange,
            f"predecessor {product}",
        )
    return result


def _artifact_id(payload: dict[str, Any]) -> str:
    return "daily-roll-" + sha256(canonical_json({**payload, "artifact_id": ""}))


def _validate_artifact_payload(payload: object) -> dict[str, Any]:
    value = _exact_dict(payload, ROOT_KEYS, "daily PIT-main roll source")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["source_kind"] != SOURCE_KIND
        or value["derivation_id"] != DERIVATION_ID
        or value["input_lineage_status"] != INPUT_LINEAGE_STATUS
        or value["installable"] is not False
        or value["event_ready"] is not False
        or value["execution_lane"] != EXECUTION_LANE
        or value["production_allowed"] is not False
        or value["live_trading_authorized"] is not False
        or value["countable_forward"] is not False
        or value["official_forward_claimed"] is not False
        or value["authority"] != false_authority()
    ):
        raise DailyPitMainRollSourceError(
            "daily PIT-main roll source identity mismatch"
        )
    official_day = _canonical_day(value["official_day"], "daily roll official_day")
    execution_day = _canonical_day(value["execution_day"], "daily roll execution_day")
    following_day = _canonical_day(
        value["following_official_day"],
        "daily roll following_official_day",
    )
    if not official_day < execution_day < following_day:
        raise DailyPitMainRollSourceError("daily roll day ordering is invalid")

    mains = value["mains"]
    if not isinstance(mains, list) or len(mains) != len(frozen.PRODUCTS):
        raise DailyPitMainRollSourceError("daily roll mains must cover ten products")
    changed: list[str] = []
    for index, product in enumerate(frozen.PRODUCTS):
        row = _exact_dict(mains[index], MAIN_KEYS, f"daily roll {product} main")
        spec = frozen.PRODUCT_SPECS[product]
        exchange = str(spec["exchange"])
        if row["product"] != product or row["exchange"] != exchange:
            raise DailyPitMainRollSourceError(
                "daily roll main product order/set mismatch"
            )
        previous = _exact_contract(
            row["previous_exact_contract"],
            product,
            exchange,
            f"daily roll {product} previous",
        )
        current = _exact_contract(
            row["exact_contract"],
            product,
            exchange,
            f"daily roll {product} current",
        )
        if row["changed"] is not (previous != current):
            raise DailyPitMainRollSourceError("daily roll changed flag mismatch")
        if row["changed"]:
            changed.append(product)
        delivery = _positive_int(
            row["delivery_yyyymm"],
            f"daily roll {product} delivery",
        )
        if delivery != 200000 + int(current[-4:]):
            raise DailyPitMainRollSourceError(
                "daily roll delivery does not match exact contract"
            )
        for field in ("settlement", "open_interest"):
            metric = row[field]
            if (
                isinstance(metric, bool)
                or not isinstance(metric, (int, float))
                or not math.isfinite(metric)
                or metric <= 0
            ):
                raise DailyPitMainRollSourceError(
                    f"daily roll {product} {field} is invalid"
                )
        _positive_int(
            row["eligible_contract_count"],
            f"daily roll {product} eligible count",
            maximum=MAX_ELIGIBLE_CONTRACT_COUNT,
        )
        if row["eligible_contract_count"] < 3:
            raise DailyPitMainRollSourceError(
                "daily roll main has fewer than three eligible contracts"
            )
        require_sha(
            row["ranked_contracts_sha256"],
            f"daily roll {product} ranking",
        )
        last_day = _canonical_day(
            row["official_last_trading_day"],
            f"daily roll {product} last trading day",
        )
        if (
            not isinstance(row["execution_day_dte"], int)
            or isinstance(row["execution_day_dte"], bool)
            or not isinstance(row["following_official_day_dte"], int)
            or isinstance(row["following_official_day_dte"], bool)
            or row["execution_day_dte"] != (last_day - execution_day).days
            or row["following_official_day_dte"] != (last_day - following_day).days
            or row["execution_day_dte"] < MIN_DTE_CALENDAR_DAYS
            or row["following_official_day_dte"] < MIN_DTE_CALENDAR_DAYS
        ):
            raise DailyPitMainRollSourceError(
                f"{product} PIT main is inside the DTE safety boundary"
            )

    if value["changed_products"] != changed or value[
        "roll_change_detected"
    ] is not bool(changed):
        raise DailyPitMainRollSourceError(
            "daily roll detection/change summary mismatch"
        )
    claimed_lineage = _exact_dict(
        value["claimed_lineage"],
        CLAIMED_LINEAGE_KEYS,
        "daily roll claimed lineage",
    )
    run_receipt = _exact_dict(
        claimed_lineage["run_receipt"],
        RUN_RECEIPT_CLAIM_KEYS,
        "daily roll run receipt claim",
    )
    for field in ("raw_sha256", "registry_raw_sha256"):
        require_sha(run_receipt[field], f"daily roll receipt {field}")
    receipt_id = run_receipt["receipt_id"]
    if (
        not isinstance(receipt_id, str)
        or not receipt_id.startswith("run-")
        or len(receipt_id) != 68
    ):
        raise DailyPitMainRollSourceError("daily roll receipt ID is invalid")
    require_sha(receipt_id.removeprefix("run-"), "daily roll receipt ID")
    parse_utc(run_receipt["completed_at"], "daily roll receipt completed_at")
    _positive_int(
        run_receipt["raw_bytes"],
        "daily roll receipt raw bytes",
        maximum=MAX_RUN_RECEIPT_RAW_BYTES,
    )
    source_rows = claimed_lineage["sources"]
    if (
        not isinstance(source_rows, list)
        or len(source_rows) != len(EXCHANGES)
        or any(not isinstance(row, dict) for row in source_rows)
    ):
        raise DailyPitMainRollSourceError("daily roll claimed source set mismatch")
    for index, exchange in enumerate(EXCHANGES):
        source = _exact_dict(
            source_rows[index],
            SOURCE_CLAIM_KEYS,
            f"daily roll {exchange} claimed source",
        )
        if source["exchange"] != exchange:
            raise DailyPitMainRollSourceError("daily roll source order mismatch")
        expected_source_id = f"{exchange.lower()}-daily-market-data-v1"
        if source["source_id"] != expected_source_id:
            raise DailyPitMainRollSourceError("daily roll source identity is invalid")
        for field in ("object_id", "observation_id", "revision_id"):
            _bounded_text(
                source[field],
                f"daily roll source {field}",
                MAX_SOURCE_ID_CHARS,
            )
        require_sha(source["raw_sha256"], f"daily roll {exchange} source")
        _positive_int(
            source["raw_bytes"],
            f"daily roll {exchange} source bytes",
            maximum=MAX_SOURCE_RAW_BYTES,
        )
        relative = source["raw_relative_path"]
        pure = PurePosixPath(relative) if isinstance(relative, str) else None
        if (
            pure is None
            or not relative
            or len(relative) > MAX_RAW_RELATIVE_PATH_CHARS
            or RAW_RELATIVE_PATH_PATTERN.fullmatch(relative) is None
            or pure.is_absolute()
            or not pure.parts
            or pure.parts[0] != "raw"
            or ".." in pure.parts
        ):
            raise DailyPitMainRollSourceError("daily roll source path is unsafe")

    manifest = _exact_dict(
        claimed_lineage["manifest"],
        MANIFEST_KEYS,
        "daily roll manifest claim",
    )
    if (
        manifest["trade_day"] != value["official_day"]
        or not isinstance(manifest["batch_id"], str)
        or ID_PATTERN.fullmatch(manifest["batch_id"]) is None
    ):
        raise DailyPitMainRollSourceError("daily roll manifest identity is invalid")
    for field in MANIFEST_KEYS - {"trade_day", "batch_id", "sources"}:
        require_sha(manifest[field], f"daily roll manifest {field}")
    if (
        manifest["manifest_head_seal_sha256"] != manifest["batch_seal_sha256"]
        or manifest["manifest_head_commit_seal_sha256"]
        != manifest["commit_seal_sha256"]
    ):
        raise DailyPitMainRollSourceError("daily roll manifest is not the pinned head")
    manifest_sources = manifest["sources"]
    if (
        not isinstance(manifest_sources, list)
        or len(manifest_sources) != len(EXCHANGES)
        or any(not isinstance(row, dict) for row in manifest_sources)
    ):
        raise DailyPitMainRollSourceError("daily roll manifest source set mismatch")
    for index, exchange in enumerate(EXCHANGES):
        manifest_source = _exact_dict(
            manifest_sources[index],
            MANIFEST_SOURCE_KEYS,
            f"daily roll manifest {exchange} claimed source",
        )
        source = source_rows[index]
        if manifest_source["exchange"] != exchange or any(
            manifest_source[field] != source[field] for field in MANIFEST_SOURCE_KEYS
        ):
            raise DailyPitMainRollSourceError(
                "daily roll manifest/source claim mismatch"
            )

    calendar = _exact_dict(
        claimed_lineage["calendar"],
        CALENDAR_KEYS,
        "daily roll calendar claim",
    )
    _bounded_text(
        calendar["calendar_id"],
        "daily roll calendar ID",
        MAX_CALENDAR_ID_CHARS,
    )
    for field in (
        "calendar_raw_sha256",
        "calendar_availability_anchor_raw_sha256",
    ):
        require_sha(calendar[field], f"daily roll {field}")
    _validate_policy_lineage(claimed_lineage["policy"])
    for field in (
        "contract_registry_raw_sha256",
        "predecessor_exact_contract_map_sha256",
        "frozen_rule_sha256",
    ):
        require_sha(claimed_lineage[field], f"daily roll {field}")
    if (
        claimed_lineage["producer_kernel_id"] != frozen.KERNEL_ID
        or claimed_lineage["frozen_rule_id"] != frozen.FROZEN_RULE_ID
        or claimed_lineage["frozen_rule_sha256"] != frozen.FROZEN_RULE_SHA256
    ):
        raise DailyPitMainRollSourceError("daily roll frozen producer lineage mismatch")
    expected_predecessor_sha = sha256(
        canonical_json(
            [
                {
                    "product": row["product"],
                    "exact_contract": row["previous_exact_contract"],
                }
                for row in mains
            ]
        )
    )
    if (
        claimed_lineage["predecessor_exact_contract_map_sha256"]
        != expected_predecessor_sha
    ):
        raise DailyPitMainRollSourceError("daily roll predecessor map hash mismatch")
    if value["artifact_id"] != _artifact_id(value):
        raise DailyPitMainRollSourceError("daily PIT-main roll source ID mismatch")
    return value


def verify_daily_pit_main_roll_source(raw: bytes) -> dict[str, Any]:
    """Validate foundation bytes without making v1 consumable or verified."""

    bounded = _bounded_bytes(raw, "daily PIT-main roll source", MAX_ARTIFACT_RAW_BYTES)
    payload = parse_json_strict(bounded, "daily PIT-main roll source")
    try:
        validated = _validate_artifact_payload(payload)
    except RegistryError as exc:
        if isinstance(exc, DailyPitMainRollSourceError):
            raise
        raise DailyPitMainRollSourceError(str(exc)) from exc
    if bounded != canonical_json_line(validated):
        raise DailyPitMainRollSourceError(
            "daily PIT-main roll source is not canonical JSON"
        )
    return validated


def build_daily_pit_main_roll_source(
    *,
    calendar: OfficialCalendar,
    calendar_availability_anchor_raw_sha256: str,
    daily_source_raw: dict[str, bytes],
    run_receipt_raw: bytes,
    manifest_lineage: dict[str, Any],
    policy_lineage: dict[str, str],
    contract_registry_raw: bytes,
    predecessor_exact_contracts: dict[str, str],
) -> BuiltDailyPitMainRollSource:
    """Build a no-authority comparison against an unverified predecessor map.

    The comparison does not prove any input lineage or predecessor continuity.
    No installer or execution component may consume v1.  A future verified v2
    must independently reconstruct and verify lineage before it can expose an
    installable artifact or executable event.
    """

    try:
        receipt_raw = _bounded_bytes(
            run_receipt_raw,
            "daily roll run receipt",
            MAX_RUN_RECEIPT_RAW_BYTES,
        )
        receipt = validate_run_receipt(
            parse_json_strict(receipt_raw, "daily roll run receipt")
        )
        if receipt_raw != canonical_json_line(receipt):
            raise DailyPitMainRollSourceError(
                "daily roll run receipt is not canonical JSON"
            )
        official_day = _canonical_day(receipt["trade_day"], "daily roll official_day")
        execution_day, following_day = _following_official_days(
            calendar,
            official_day,
        )
        calendar_anchor_sha = require_sha(
            calendar_availability_anchor_raw_sha256,
            "daily roll calendar availability anchor",
        )
        if (
            receipt["calendar_raw_sha256"] != calendar.raw_sha256
            or receipt["calendar_availability_anchor_raw_sha256"] != calendar_anchor_sha
        ):
            raise DailyPitMainRollSourceError(
                "daily roll receipt/calendar lineage mismatch"
            )
        _bounded_text(
            calendar.calendar_id,
            "daily roll calendar ID",
            MAX_CALENDAR_ID_CHARS,
        )
        require_sha(calendar.raw_sha256, "daily roll calendar")

        if not isinstance(daily_source_raw, dict) or set(daily_source_raw) != set(
            EXCHANGES
        ):
            raise DailyPitMainRollSourceError(
                "daily roll raw source set must be exact SHFE/INE"
            )
        normalized_raw = {
            exchange: _bounded_bytes(
                daily_source_raw[exchange],
                f"daily roll {exchange} raw",
                MAX_SOURCE_RAW_BYTES,
            )
            for exchange in EXCHANGES
        }
        if sum(map(len, normalized_raw.values())) > MAX_AGGREGATE_SOURCE_RAW_BYTES:
            raise DailyPitMainRollSourceError(
                "daily roll aggregate raw resource limit exceeded"
            )
        for index, exchange in enumerate(EXCHANGES):
            source = receipt["sources"][index]
            raw = normalized_raw[exchange]
            if (
                source["exchange"] != exchange
                or source["raw_sha256"] != sha256(raw)
                or source["raw_bytes"] != len(raw)
            ):
                raise DailyPitMainRollSourceError(
                    "daily roll receipt/raw byte binding mismatch"
                )

        manifest = _validate_manifest_lineage(manifest_lineage, receipt=receipt)
        policy = _validate_policy_lineage(policy_lineage)
        predecessor = _validate_predecessor_map(predecessor_exact_contracts)
        registry_raw = _bounded_bytes(
            contract_registry_raw,
            "daily roll contract registry",
            MAX_CONTRACT_REGISTRY_RAW_BYTES,
        )
        registry, contract_registry_sha = _registry(registry_raw)

        extracted = {
            exchange: contract_rows_from_daily_raw(
                raw=normalized_raw[exchange],
                exchange=exchange,
                official_day=official_day.isoformat(),
            )
            for exchange in EXCHANGES
        }
        mains: list[dict[str, Any]] = []
        changed_products: list[str] = []
        for product in frozen.PRODUCTS:
            spec = frozen.PRODUCT_SPECS[product]
            exchange = str(spec["exchange"])
            main, ranked = _pit_main(
                product,
                official_day,
                extracted[exchange][product],
            )
            exact = str(main["exact_contract"])
            previous = predecessor[product]
            changed = previous != exact
            if changed:
                changed_products.append(product)
            last_day = _last_trading_day(
                calendar,
                delivery_yyyymm=int(main["delivery_yyyymm"]),
                rule=str(registry[product]["last_trading_day_rule"]),
            )
            execution_dte = (last_day - execution_day).days
            following_dte = (last_day - following_day).days
            if (
                execution_dte < MIN_DTE_CALENDAR_DAYS
                or following_dte < MIN_DTE_CALENDAR_DAYS
            ):
                raise DailyPitMainRollSourceError(
                    f"{product} PIT main is inside the DTE safety boundary"
                )
            mains.append(
                {
                    "product": product,
                    "exchange": exchange,
                    "previous_exact_contract": previous,
                    "exact_contract": exact,
                    "changed": changed,
                    "delivery_yyyymm": int(main["delivery_yyyymm"]),
                    "settlement": float(main["settlement"]),
                    "open_interest": float(main["open_interest"]),
                    "eligible_contract_count": len(ranked),
                    "ranked_contracts_sha256": sha256(canonical_json(ranked)),
                    "official_last_trading_day": last_day.isoformat(),
                    "execution_day_dte": execution_dte,
                    "following_official_day_dte": following_dte,
                }
            )

        predecessor_sha = sha256(
            canonical_json(
                [
                    {
                        "product": product,
                        "exact_contract": predecessor[product],
                    }
                    for product in frozen.PRODUCTS
                ]
            )
        )
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "artifact_id": "",
            "source_kind": SOURCE_KIND,
            "derivation_id": DERIVATION_ID,
            "official_day": official_day.isoformat(),
            "execution_day": execution_day.isoformat(),
            "following_official_day": following_day.isoformat(),
            "roll_change_detected": bool(changed_products),
            "changed_products": changed_products,
            "input_lineage_status": INPUT_LINEAGE_STATUS,
            "installable": False,
            "event_ready": False,
            "execution_lane": EXECUTION_LANE,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "official_forward_claimed": False,
            "mains": mains,
            "claimed_lineage": {
                "run_receipt": {
                    "receipt_id": receipt["receipt_id"],
                    "completed_at": receipt["completed_at"],
                    "raw_sha256": sha256(receipt_raw),
                    "raw_bytes": len(receipt_raw),
                    "registry_raw_sha256": receipt["registry_raw_sha256"],
                },
                "sources": [dict(source) for source in receipt["sources"]],
                "manifest": manifest,
                "calendar": {
                    "calendar_id": calendar.calendar_id,
                    "calendar_raw_sha256": calendar.raw_sha256,
                    "calendar_availability_anchor_raw_sha256": calendar_anchor_sha,
                },
                "policy": policy,
                "contract_registry_raw_sha256": contract_registry_sha,
                "predecessor_exact_contract_map_sha256": predecessor_sha,
                "producer_kernel_id": frozen.KERNEL_ID,
                "frozen_rule_id": frozen.FROZEN_RULE_ID,
                "frozen_rule_sha256": frozen.FROZEN_RULE_SHA256,
            },
            "authority": false_authority(),
        }
        payload["artifact_id"] = _artifact_id(payload)
        validated = _validate_artifact_payload(payload)
        artifact_raw = canonical_json_line(validated)
        return BuiltDailyPitMainRollSource(
            artifact_raw=artifact_raw,
            artifact_id=validated["artifact_id"],
            artifact_raw_sha256=sha256(artifact_raw),
        )
    except RegistryError as exc:
        if isinstance(exc, DailyPitMainRollSourceError):
            raise
        raise DailyPitMainRollSourceError(str(exc)) from exc
