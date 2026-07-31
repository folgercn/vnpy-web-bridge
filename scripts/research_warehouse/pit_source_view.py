"""Root-pinned Research Warehouse to sealed relative-vol PIT source view."""

from __future__ import annotations

import base64
import binascii
import calendar as month_calendar
import math
import os
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from zoneinfo import ZoneInfo

import commodity_c_fast_pure_producer_kernel as frozen
import commodity_relative_vol_snapshot_producer as snapshot_producer
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .calendar_models import OfficialCalendar
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .commit_anchors import load_commit_anchor_ledger
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .history_backfill_receipts import load_backfill_receipt
from .m2_isolation_contracts import false_authority
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_operator_state import OperatorState
from .m2_receipts import load_run_receipt
from .m2_runtime_input import require_sha
from .m2_runtime_loader import RuntimeContext
from .manifests import verify_manifest_chain
from .signing import load_public_key, public_key_sha256
from .timeutil import parse_utc

SOURCE_VIEW_FILENAME = "source-view.json"
RECEIPT_FILENAME = "source-view-receipt.json"
RECEIPT_SCHEMA = "vnpy_research_commodity_relative_vol_pit_source_receipt_v1"
DERIVATION_ID = "SIGNED_BASELINE_BUFFERED_WEIGHTED_ROLL_SAFE_LOG_RETURN_V1"
CHINA_TZ = ZoneInfo("Asia/Shanghai")
UTC = timezone.utc
TARGET_PRODUCTS = tuple(frozen.PRODUCTS)
MAX_SOURCE_RAW_BYTES = 16 * 1024 * 1024
MAX_AGGREGATE_RAW_BYTES = 512 * 1024 * 1024


class PitSourceViewError(RegistryError):
    """Fail-closed source-view construction error."""


@dataclass(frozen=True)
class SourcePins:
    history_receipt_raw_sha256: str
    operator_state_raw_sha256: str
    manifest_public_key_raw_sha256: str
    baseline_public_key_raw_sha256: str


@dataclass(frozen=True)
class BuiltSourceView:
    source_view_raw: bytes
    receipt_raw: bytes
    source_view_id: str
    receipt_id: str


def verify_built_source_view(
    source_view_raw: bytes,
    receipt_raw: bytes,
    *,
    expected_receipt_raw_sha256: str,
) -> dict[str, Any]:
    """Independently validate canonical bytes and replay the pure producer."""

    if sha256(receipt_raw) != require_sha(
        expected_receipt_raw_sha256,
        "expected PIT receipt",
    ):
        raise PitSourceViewError("PIT receipt SHA256 mismatch")
    source = parse_json_strict(source_view_raw, "sealed PIT source view")
    receipt = parse_json_strict(receipt_raw, "sealed PIT source-view receipt")
    receipt_fields = {
        "schema_version",
        "receipt_id",
        "source_view_id",
        "source_view_filename",
        "source_view_raw_sha256",
        "source_view_raw_bytes",
        "source_month",
        "research_as_of_official_day",
        "execution_day",
        "derivation_id",
        "pins",
        "daily_receipts",
        "used_daily_sources",
        "producer_replay",
        "authority",
    }
    if (
        not isinstance(source, dict)
        or snapshot_producer.canonical_json(source) != source_view_raw
        or not isinstance(receipt, dict)
        or set(receipt) != receipt_fields
        or canonical_json_line(receipt) != receipt_raw
        or receipt["schema_version"] != RECEIPT_SCHEMA
        or receipt["source_view_filename"] != SOURCE_VIEW_FILENAME
        or receipt["derivation_id"] != DERIVATION_ID
        or receipt["authority"] != false_authority()
    ):
        raise PitSourceViewError("sealed PIT receipt/source contract mismatch")
    if (
        source.get("source_view_id") != receipt["source_view_id"]
        or sha256(source_view_raw) != receipt["source_view_raw_sha256"]
        or len(source_view_raw) != receipt["source_view_raw_bytes"]
    ):
        raise PitSourceViewError("sealed PIT source byte binding mismatch")
    expected_id = "pit-receipt-" + sha256(
        canonical_json({**receipt, "receipt_id": ""})
    )
    if receipt["receipt_id"] != expected_id:
        raise PitSourceViewError("sealed PIT receipt ID mismatch")
    replay = snapshot_producer.produce_snapshot(source_view_raw)
    if (
        replay.source_view_canonical_sha256 != receipt["source_view_raw_sha256"]
        or sha256(replay.snapshot_draft)
        != receipt["producer_replay"]["snapshot_draft_raw_sha256"]
        or sha256(replay.evidence)
        != receipt["producer_replay"]["producer_evidence_raw_sha256"]
        or receipt["producer_replay"]["status"]
        != "EXACT_SOURCE_VIEW_REPLAY_VERIFIED"
    ):
        raise PitSourceViewError("sealed PIT producer replay mismatch")
    return receipt


def _safe_relative_path(root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str):
        raise PitSourceViewError(f"{label} path must be a string")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise PitSourceViewError(f"{label} path is unsafe")
    return root.joinpath(*pure.parts)


def _strict_number(value: object, label: str, *, nonnegative: bool = False) -> float:
    if isinstance(value, bool):
        raise PitSourceViewError(f"{label} is not a number")
    if isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str) and value and value.strip() == value:
        try:
            result = float(value)
        except ValueError as exc:
            raise PitSourceViewError(f"{label} is not a number") from exc
    else:
        raise PitSourceViewError(f"{label} is not a number")
    if not math.isfinite(result) or (result < 0 if nonnegative else result <= 0):
        raise PitSourceViewError(f"{label} is outside the admitted range")
    return result


def _delivery_yyyymm(value: object, label: str) -> int:
    if not isinstance(value, str) or len(value) != 4 or not value.isascii():
        raise PitSourceViewError(f"{label} delivery month is invalid")
    try:
        compact = int(value)
    except ValueError as exc:
        raise PitSourceViewError(f"{label} delivery month is invalid") from exc
    month = compact % 100
    if not 1 <= month <= 12:
        raise PitSourceViewError(f"{label} delivery month is invalid")
    return 200000 + compact


def _pit_main(
    product: str,
    official_day: date,
    rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        return frozen._pit_main(product, official_day, rows)
    except frozen.ProducerKernelError as exc:
        raise PitSourceViewError(str(exc)) from exc


def contract_rows_from_daily_raw(
    *,
    raw: bytes,
    exchange: str,
    official_day: str,
) -> dict[str, list[dict[str, Any]]]:
    """Extract exact target-contract OHLC/OI without accepting summary rows."""

    payload = parse_json_strict(raw, f"{exchange} official daily raw")
    if not isinstance(payload, dict) or payload.get("report_date") != official_day.replace(
        "-", ""
    ):
        raise PitSourceViewError("official raw report date mismatch")
    rows = payload.get("o_curinstrument")
    if not isinstance(rows, list) or not rows:
        raise PitSourceViewError("official raw contract rows are missing")
    result = {product: [] for product in TARGET_PRODUCTS}
    expected_products = {
        product
        for product, spec in frozen.PRODUCT_SPECS.items()
        if spec["exchange"] == exchange
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise PitSourceViewError("official raw row is not an object")
        raw_product = row.get("PRODUCTID")
        if not isinstance(raw_product, str):
            raise PitSourceViewError("official raw PRODUCTID is not a string")
        product = raw_product.strip().lower()
        if product not in expected_products:
            continue
        delivery = _delivery_yyyymm(
            row.get("DELIVERYMONTH"),
            f"{exchange} row {index}",
        )
        compact = delivery % 10000
        exact_contract = f"{exchange}.{product}{compact:04d}"
        observation = {
            "exact_contract": exact_contract,
            "delivery_yyyymm": delivery,
            "open": _strict_number(row.get("OPENPRICE"), f"{exact_contract} open"),
            "high": _strict_number(row.get("HIGHESTPRICE"), f"{exact_contract} high"),
            "low": _strict_number(row.get("LOWESTPRICE"), f"{exact_contract} low"),
            "settlement": _strict_number(
                row.get("SETTLEMENTPRICE"),
                f"{exact_contract} settlement",
            ),
            "open_interest": _strict_number(
                row.get("OPENINTEREST"),
                f"{exact_contract} open interest",
                nonnegative=True,
            ),
        }
        if not (
            observation["low"]
            <= min(observation["open"], observation["settlement"])
            <= max(observation["open"], observation["settlement"])
            <= observation["high"]
        ):
            raise PitSourceViewError(f"{exact_contract} OHLC range is invalid")
        result[product].append(observation)
    for product in expected_products:
        rows_for_product = result[product]
        if len({row["exact_contract"] for row in rows_for_product}) != len(
            rows_for_product
        ):
            raise PitSourceViewError(f"{product} repeats an exact contract")
        _pit_main(product, date.fromisoformat(official_day), rows_for_product)
    return result


def _roll_safe_returns(
    daily_contracts: dict[str, dict[str, list[dict[str, Any]]]],
    official_days: list[str],
) -> dict[str, dict[str, float]]:
    result = {product: {} for product in TARGET_PRODUCTS}
    for product in TARGET_PRODUCTS:
        previous_main: dict[str, Any] | None = None
        for raw_day in official_days:
            rows = daily_contracts[raw_day][product]
            main, _ranked = _pit_main(
                product,
                date.fromisoformat(raw_day),
                rows,
            )
            if previous_main is not None:
                comparable = {
                    row["exact_contract"]: row for row in rows
                }.get(previous_main["exact_contract"])
                if comparable is None:
                    raise PitSourceViewError(
                        f"{product} {raw_day} lacks old-main comparable settlement"
                    )
                value = math.log(
                    float(comparable["settlement"])
                    / float(previous_main["settlement"])
                )
                if not math.isfinite(value):
                    raise PitSourceViewError("roll-safe return is not finite")
                result[product][raw_day] = value
            previous_main = main
    return result


def _unsigned_hash(payload: dict[str, Any]) -> str:
    return sha256(canonical_json({k: v for k, v in payload.items() if k != "signature"}))


def _verify_business_signature(
    payload: dict[str, Any],
    *,
    public_key: Ed25519PublicKey,
    label: str,
) -> None:
    signature = payload.get("signature")
    if not isinstance(signature, str):
        raise PitSourceViewError(f"{label} signature is missing")
    try:
        decoded = base64.b64decode(signature, validate=True)
        public_key.verify(
            decoded,
            canonical_json({k: v for k, v in payload.items() if k != "signature"}),
        )
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise PitSourceViewError(f"{label} signature is invalid") from exc


def _official_month_boundary(
    calendar: OfficialCalendar,
    *,
    source_month: str,
) -> tuple[date, date, date]:
    try:
        year, month = (int(part) for part in source_month.split("-"))
        cutoff_day = date(year, month, month_calendar.monthrange(year, month)[1])
    except (TypeError, ValueError) as exc:
        raise PitSourceViewError("source month is invalid") from exc
    official = sorted(
        day
        for day, row in calendar.days.items()
        if row.is_official
    )
    source_days = [day for day in official if (day.year, day.month) == (year, month)]
    following = [day for day in official if day > cutoff_day]
    if not source_days or not following:
        raise PitSourceViewError("calendar lacks source-month or following official day")
    return source_days[-1], following[0], cutoff_day


def _calendar_binding(
    calendar: OfficialCalendar,
    *,
    history_receipt_sha256: str,
    calendar_anchor_sha256: str,
    source_month: str,
    research_as_of: date,
    cutoff_day: date,
) -> tuple[dict[str, Any], list[str]]:
    completed = sorted(
        day
        for day, row in calendar.days.items()
        if row.is_official and day <= research_as_of
    )
    if len(completed) < snapshot_producer.SLOW_LOOKBACK_DAYS:
        raise PitSourceViewError("calendar has fewer than 126 completed official days")
    selected = completed[-snapshot_producer.SLOW_LOOKBACK_DAYS :]
    query_start = selected[0]
    rows = []
    current = query_start
    while current <= cutoff_day:
        calendar_row = calendar.require_day(current)
        rows.append(
            {
                "calendar_day": current.isoformat(),
                "is_official_day": calendar_row.is_official,
            }
        )
        current = date.fromordinal(current.toordinal() + 1)
    rows_sha = sha256(canonical_json(rows))
    lineage = sha256(
        canonical_json(
            {
                "calendar_raw_sha256": calendar.raw_sha256,
                "calendar_availability_anchor_raw_sha256": calendar_anchor_sha256,
                "calendar_rows_sha256": rows_sha,
                "history_receipt_raw_sha256": history_receipt_sha256,
                "source_month": source_month,
            }
        )
    )
    binding_id = f"calendar-{lineage[:32]}"
    return (
        {
            "binding_id": binding_id,
            "source_class": "OFFICIAL_TRADING_CALENDAR",
            "source_identity": calendar.calendar_id,
            "exchange_scope": "SHFE_INE",
            "query_start": query_start.isoformat(),
            "query_end": cutoff_day.isoformat(),
            "research_as_of_official_day": research_as_of.isoformat(),
            "calendar_rows": rows,
            "calendar_rows_sha256": rows_sha,
            "lineage_sha256": lineage,
            "claimed_receipt_sha256": history_receipt_sha256,
        },
        [day.isoformat() for day in selected],
    )


def build_source_view(
    *,
    calendar: OfficialCalendar,
    calendar_anchor_sha256: str,
    history_receipt: dict[str, Any],
    history_receipt_sha256: str,
    operator_state: OperatorState,
    daily_source_raw: dict[str, dict[str, bytes]],
    baseline_batch: dict[str, Any],
    business_public_key: Ed25519PublicKey,
    source_month: str,
    previous_snapshot: dict[str, Any] | None,
) -> BuiltSourceView:
    """Build and independently replay one deterministic canonical source view."""

    _verify_business_signature(
        baseline_batch,
        public_key=business_public_key,
        label="baseline batch",
    )
    research_as_of, execution_day, cutoff_day = _official_month_boundary(
        calendar,
        source_month=source_month,
    )
    cutoff_instant = datetime.combine(
        cutoff_day,
        time(23, 59, 59, 999999),
        tzinfo=CHINA_TZ,
    ).astimezone(UTC)
    if parse_utc(
        history_receipt.get("completed_at"),
        "history receipt completed_at",
    ) > cutoff_instant:
        raise PitSourceViewError("history receipt was unavailable at PIT cutoff")
    if (
        baseline_batch.get("source_month") != source_month
        or baseline_batch.get("execution_day") != execution_day.isoformat()
    ):
        raise PitSourceViewError("baseline month/execution-day binding mismatch")
    history_days = history_receipt.get("official_days")
    if (
        history_receipt.get("required_official_days") != 186
        or not isinstance(history_days, list)
        or len(history_days) != 186
        or history_days != sorted(set(history_days))
    ):
        raise PitSourceViewError("history receipt is not the exact 186-day plan")
    required_days = sorted(
        {
            *history_days,
            research_as_of.isoformat(),
        }
    )
    missing = set(required_days) - set(daily_source_raw)
    if missing:
        raise PitSourceViewError(
            "daily source evidence is missing: " + ", ".join(sorted(missing))
        )
    daily_contracts: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for raw_day in required_days:
        by_product = {product: [] for product in TARGET_PRODUCTS}
        sources = daily_source_raw[raw_day]
        if set(sources) != {"SHFE", "INE"}:
            raise PitSourceViewError("daily exact SHFE/INE source set mismatch")
        for exchange in ("SHFE", "INE"):
            extracted = contract_rows_from_daily_raw(
                raw=sources[exchange],
                exchange=exchange,
                official_day=raw_day,
            )
            for product in TARGET_PRODUCTS:
                by_product[product].extend(extracted[product])
        daily_contracts[raw_day] = by_product
    calendar_binding, selected_days = _calendar_binding(
        calendar,
        history_receipt_sha256=history_receipt_sha256,
        calendar_anchor_sha256=calendar_anchor_sha256,
        source_month=source_month,
        research_as_of=research_as_of,
        cutoff_day=cutoff_day,
    )
    if not set(selected_days).issubset(daily_contracts):
        raise PitSourceViewError("latest 126 calendar days are not in verified custody")
    calculation_days = sorted(
        set(selected_days)
        | {
            max(
                day
                for day in daily_contracts
                if day < selected_days[0]
            )
        }
    )
    product_returns = _roll_safe_returns(daily_contracts, calculation_days)
    baseline_targets = baseline_batch.get("targets")
    if (
        not isinstance(baseline_targets, list)
        or [row.get("product") for row in baseline_targets] != list(TARGET_PRODUCTS)
    ):
        raise PitSourceViewError("baseline target product order/set mismatch")
    weights: dict[str, float] = {}
    source_day_contracts = daily_contracts[research_as_of.isoformat()]
    for row in baseline_targets:
        product = row["product"]
        spec = frozen.PRODUCT_SPECS[product]
        if (
            row.get("multiplier") != spec["multiplier"]
            or not math.isclose(
                float(row.get("price_tick", 0)),
                float(spec["price_tick"]),
                rel_tol=0,
                abs_tol=1e-12,
            )
        ):
            raise PitSourceViewError(f"{product} baseline contract spec mismatch")
        pit_main, _ranked = _pit_main(
            product,
            research_as_of,
            source_day_contracts[product],
        )
        if row.get("exact_contract") != pit_main["exact_contract"]:
            raise PitSourceViewError(f"{product} baseline PIT-main contract mismatch")
        weight = row.get("buffered_target_weight")
        if isinstance(weight, bool) or not isinstance(weight, (int, float)):
            raise PitSourceViewError(f"{product} baseline weight is invalid")
        weights[product] = float(weight)
    daily_returns = []
    for raw_day in selected_days:
        value = math.fsum(
            weights[product] * product_returns[product][raw_day]
            for product in TARGET_PRODUCTS
        )
        if not math.isfinite(value):
            raise PitSourceViewError("baseline portfolio return is not finite")
        daily_returns.append({"official_day": raw_day, "daily_return": value})
    baseline_hash = _unsigned_hash(baseline_batch)
    if previous_snapshot is None:
        continuity = {
            "mode": "genesis",
            "previous_snapshot_hash": None,
            "previous_snapshot": None,
        }
    else:
        _verify_business_signature(
            previous_snapshot,
            public_key=business_public_key,
            label="previous snapshot",
        )
        previous_hash = _unsigned_hash(previous_snapshot)
        continuity = {
            "mode": "linked",
            "previous_snapshot_hash": previous_hash,
            "previous_snapshot": previous_snapshot,
        }
    state = operator_state.payload
    identity = {
        "history_receipt_raw_sha256": history_receipt_sha256,
        "calendar_raw_sha256": calendar.raw_sha256,
        "calendar_anchor_raw_sha256": calendar_anchor_sha256,
        "registry_raw_sha256": history_receipt["registry_raw_sha256"],
        "operator_state_raw_sha256": operator_state.raw_sha256,
        "manifest_genesis_seal_sha256": state["manifest_genesis_seal_sha256"],
        "manifest_head_seal_sha256": state["manifest_head_seal_sha256"],
        "manifest_head_commit_seal_sha256": state[
            "manifest_head_commit_seal_sha256"
        ],
        "commit_anchor_ledger_raw_sha256": state[
            "commit_anchor_ledger_raw_sha256"
        ],
        "baseline_batch_hash": baseline_hash,
        "source_month": source_month,
        "derivation_id": DERIVATION_ID,
    }
    identity_hash = sha256(canonical_json(identity))
    source_view = {
        "schema_version": snapshot_producer.SOURCE_SCHEMA_VERSION,
        "purpose": snapshot_producer.SOURCE_PURPOSE,
        "status": snapshot_producer.SOURCE_STATUS,
        "source_view_id": f"warehouse-pit-{source_month.replace('-', '')}-{identity_hash[:24]}",
        "snapshot_id": f"relative-vol-{source_month.replace('-', '')}-{identity_hash[:24]}",
        "generated_at": datetime.combine(
            execution_day,
            time(0, 0),
            tzinfo=CHINA_TZ,
        )
        .astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "cutoff_at": cutoff_instant
        .astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "official_calendar": calendar_binding,
        "official_days": selected_days,
        "baseline_daily_returns": daily_returns,
        "baseline_batch_hash": baseline_hash,
        "baseline_batch": baseline_batch,
        "continuity": continuity,
    }
    source_raw = snapshot_producer.canonical_json(source_view)
    replay = snapshot_producer.produce_snapshot(source_raw)
    if replay.source_view_canonical_sha256 != sha256(source_raw):
        raise PitSourceViewError("relative-vol producer normalized source bytes diverged")
    source_raw_sha = sha256(source_raw)
    receipt_base = {
        "schema_version": RECEIPT_SCHEMA,
        "receipt_id": "",
        "source_view_id": source_view["source_view_id"],
        "source_view_filename": SOURCE_VIEW_FILENAME,
        "source_view_raw_sha256": source_raw_sha,
        "source_view_raw_bytes": len(source_raw),
        "source_month": source_month,
        "research_as_of_official_day": research_as_of.isoformat(),
        "execution_day": execution_day.isoformat(),
        "derivation_id": DERIVATION_ID,
        "pins": identity,
        "daily_receipts": history_receipt["daily_receipts"],
        "used_daily_sources": [
            {
                "official_day": raw_day,
                "sources": [
                    {
                        "exchange": exchange,
                        "raw_sha256": sha256(daily_source_raw[raw_day][exchange]),
                        "raw_bytes": len(daily_source_raw[raw_day][exchange]),
                    }
                    for exchange in ("SHFE", "INE")
                ],
            }
            for raw_day in calculation_days
        ],
        "producer_replay": {
            "status": "EXACT_SOURCE_VIEW_REPLAY_VERIFIED",
            "snapshot_draft_raw_sha256": sha256(replay.snapshot_draft),
            "producer_evidence_raw_sha256": sha256(replay.evidence),
        },
        "authority": false_authority(),
    }
    receipt_id = "pit-receipt-" + sha256(
        canonical_json({**receipt_base, "receipt_id": ""})
    )
    receipt = {**receipt_base, "receipt_id": receipt_id}
    return BuiltSourceView(
        source_view_raw=source_raw,
        receipt_raw=canonical_json_line(receipt),
        source_view_id=source_view["source_view_id"],
        receipt_id=receipt_id,
    )


def _read_signed_payload(path: Path, label: str) -> dict[str, Any]:
    raw = read_regular_strict(path, label, limit=4 * 1024 * 1024)
    payload = parse_json_strict(raw, label)
    if not isinstance(payload, dict):
        raise PitSourceViewError(f"{label} must be a JSON object")
    return payload


def verified_daily_raw(
    *,
    context: RuntimeContext,
    history: dict[str, Any],
    chain: list[dict[str, Any]],
) -> dict[str, dict[str, bytes]]:
    """Verify receipt/raw/manifest bindings and return stable exact source bytes."""

    manifests = {item["trade_day"]: item for item in chain}
    result: dict[str, dict[str, bytes]] = {}
    aggregate = 0
    for expected in history["daily_receipts"]:
        raw_day = expected["trade_day"]
        receipt_path = context.runtime.root / expected["run_receipt_relative_path"]
        receipt_raw = read_regular_strict(receipt_path, "PIT daily run receipt")
        if sha256(receipt_raw) != expected["run_receipt_raw_sha256"]:
            raise PitSourceViewError("PIT daily receipt SHA256 mismatch")
        receipt = load_run_receipt(receipt_path)
        verify_daily_run_receipt(
            receipt,
            paths=context.paths,
            registry=context.registry,
            calendar=context.calendar,
            calendar_availability_raw_sha256=context.availability.raw_sha256,
        )
        manifest = manifests.get(raw_day)
        if manifest is None or manifest["commit_receipt"] is None:
            raise PitSourceViewError("PIT daily manifest is missing or uncommitted")
        by_revision = {
            item["revision_id"]: item for item in manifest["revisions"]
        }
        sources: dict[str, bytes] = {}
        for index, source in enumerate(receipt["sources"]):
            if (
                source["raw_sha256"] != expected["source_raw_sha256"][index]
                or source["raw_bytes"] != expected["source_raw_bytes"][index]
            ):
                raise PitSourceViewError("PIT exact source binding mismatch")
            revision = by_revision.get(source["revision_id"])
            if revision is None or any(
                revision[field] != source[field]
                for field in ("raw_sha256", "raw_bytes", "raw_relative_path")
            ):
                raise PitSourceViewError("PIT manifest/receipt revision mismatch")
            raw_path = _safe_relative_path(
                context.paths.root,
                source["raw_relative_path"],
                "PIT raw",
            )
            raw = read_regular_strict(raw_path, "PIT exact raw", limit=MAX_SOURCE_RAW_BYTES)
            if len(raw) != source["raw_bytes"] or sha256(raw) != source["raw_sha256"]:
                raise PitSourceViewError("PIT raw bytes drifted")
            aggregate += len(raw)
            if aggregate > MAX_AGGREGATE_RAW_BYTES:
                raise PitSourceViewError("PIT aggregate raw resource limit exceeded")
            sources[source["exchange"]] = raw
        result[raw_day] = sources
    return result


def verified_supplemental_daily_raw(
    *,
    context: RuntimeContext,
    history: dict[str, Any],
    chain: list[dict[str, Any]],
    source_month: str,
) -> dict[str, dict[str, bytes]]:
    """Verify root-pinned normal daily receipts after the fixed backfill."""

    research_as_of, _execution_day, _cutoff_day = _official_month_boundary(
        context.calendar,
        source_month=source_month,
    )
    last_history_day = date.fromisoformat(history["official_days"][-1])
    supplemental_days = [
        day
        for day, row in context.calendar.days.items()
        if row.is_official and last_history_day < day <= research_as_of
    ]
    if not supplemental_days:
        return {}
    manifests = {item["trade_day"]: item for item in chain}
    result: dict[str, dict[str, bytes]] = {}
    for day in supplemental_days:
        raw_day = day.isoformat()
        receipt_path = context.runtime.run_receipts / f"{raw_day}.json"
        receipt = load_run_receipt(receipt_path)
        cutoff_instant = datetime.combine(
            _cutoff_day,
            time(23, 59, 59, 999999),
            tzinfo=CHINA_TZ,
        ).astimezone(UTC)
        if parse_utc(receipt["completed_at"], "supplemental receipt completed_at") > (
            cutoff_instant
        ):
            raise PitSourceViewError(
                "supplemental receipt was unavailable at PIT cutoff"
            )
        verify_daily_run_receipt(
            receipt,
            paths=context.paths,
            registry=context.registry,
            calendar=context.calendar,
            calendar_availability_raw_sha256=context.availability.raw_sha256,
        )
        manifest = manifests.get(raw_day)
        if manifest is None or manifest["commit_receipt"] is None:
            raise PitSourceViewError("supplemental daily manifest is uncommitted")
        revisions = {item["revision_id"]: item for item in manifest["revisions"]}
        sources: dict[str, bytes] = {}
        for source in receipt["sources"]:
            revision = revisions.get(source["revision_id"])
            if revision is None or any(
                revision[field] != source[field]
                for field in ("raw_sha256", "raw_bytes", "raw_relative_path")
            ):
                raise PitSourceViewError(
                    "supplemental manifest/receipt revision mismatch"
                )
            raw_path = _safe_relative_path(
                context.paths.root,
                source["raw_relative_path"],
                "supplemental PIT raw",
            )
            raw = read_regular_strict(
                raw_path,
                "supplemental PIT exact raw",
                limit=MAX_SOURCE_RAW_BYTES,
            )
            if len(raw) != source["raw_bytes"] or sha256(raw) != source["raw_sha256"]:
                raise PitSourceViewError("supplemental PIT raw bytes drifted")
            sources[source["exchange"]] = raw
        if set(sources) != {"SHFE", "INE"}:
            raise PitSourceViewError("supplemental daily exact source set mismatch")
        result[raw_day] = sources
    return result


def verify_root_pins(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    history_receipt_path: Path,
    pins: SourcePins,
    manifest_public_key_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if operator_state.raw_sha256 != require_sha(
        pins.operator_state_raw_sha256,
        "expected operator state",
    ):
        raise PitSourceViewError("operator state root pin changed")
    manifest_key = load_public_key(manifest_public_key_path)
    if public_key_sha256(manifest_key) != require_sha(
        pins.manifest_public_key_raw_sha256,
        "expected manifest public key",
    ):
        raise PitSourceViewError("manifest public key pin mismatch")
    history = load_backfill_receipt(
        history_receipt_path,
        expected_raw_sha256=pins.history_receipt_raw_sha256,
    )
    if (
        history["calendar_raw_sha256"] != context.calendar.raw_sha256
        or history["calendar_availability_anchor_raw_sha256"]
        != context.availability.raw_sha256
        or history["registry_raw_sha256"] != context.registry.raw_sha256
    ):
        raise PitSourceViewError("history receipt authority pins diverged")
    state = operator_state.payload
    chain = verify_manifest_chain(
        paths=context.paths,
        public_key_path=manifest_public_key_path,
        registry=context.registry,
        expected_genesis_seal_sha256=state["manifest_genesis_seal_sha256"],
        expected_head_seal_sha256=state["manifest_head_seal_sha256"],
        expected_head_commit_seal_sha256=state["manifest_head_commit_seal_sha256"],
        offline=True,
    )
    if len(chain) != state["manifest_sequence"]:
        raise PitSourceViewError("manifest sequence/root-pinned chain length mismatch")
    ledger = load_commit_anchor_ledger(
        Path(state["commit_anchor_ledger_path"]),
        expected_raw_sha256=state["commit_anchor_ledger_raw_sha256"],
        private=False,
    )
    ledger.require_chain(chain)
    return history, chain


def validate_business_key(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> Ed25519PublicKey:
    key = load_public_key(path)
    if public_key_sha256(key) != require_sha(
        expected_raw_sha256,
        "expected baseline public key",
    ):
        raise PitSourceViewError("baseline public key pin mismatch")
    return key


def require_separate_paths(
    *,
    output_root: Path,
    context: RuntimeContext,
    protected_inputs: tuple[Path, ...],
) -> None:
    try:
        output = output_root.resolve(strict=True)
        protected = (
            context.paths.root.resolve(strict=True),
            context.runtime.root.resolve(strict=True),
            *(path.resolve(strict=True) for path in protected_inputs),
        )
    except OSError as exc:
        raise PitSourceViewError("PIT source-view path is unavailable") from exc
    for candidate in protected:
        if (
            output == candidate
            or output.is_relative_to(candidate)
            or candidate.is_relative_to(output)
        ):
            raise PitSourceViewError("PIT output/input path overlap is forbidden")
    info = output.lstat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PitSourceViewError("PIT output root must be private and current-user-owned")
