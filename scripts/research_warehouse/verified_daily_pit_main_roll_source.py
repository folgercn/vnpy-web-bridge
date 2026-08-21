"""Verified, no-authority daily PIT-main roll-change source v2.

This module is the verified wrapper around the frozen daily PIT-main rule.  It
loads one completed normal Warehouse day through the existing root-pinned
runtime, receipt, manifest-chain, calendar and registry verifiers.  This
foundation permits only a signed delayed ``STATIC_CORE_EQUAL`` genesis batch:
the baseline execution day and artifact official day must be in the same month,
with the baseline execution day no later than the artifact official day, after
the month-end research panel and execution-day official open are both sealed
in the current Warehouse root.  Linked-day construction reads the immediately
preceding artifact only from the root-managed immutable predecessor catalog;
caller-supplied artifact bytes and IDs are never accepted.

The result remains Research-Plane source evidence.  It cannot install a
target, create an executable event, dispatch, submit an order, or authorize
SimNow/production/live trading.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time
import math
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import commodity_c_fast_pure_producer_kernel as frozen
import commodity_relative_vol_snapshot_producer as monthly_producer
import commodity_static_core_equal_pure_producer as static_producer
from jsonschema import Draft202012Validator, FormatChecker

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import false_authority
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_operator_state import (
    OperatorState,
    load_operator_state,
    operator_state_lock,
)
from .m2_receipts import RUN_SOURCE_KEYS, load_run_receipt, validate_run_receipt
from .m2_runtime_input import require_sha
from .m2_runtime_loader import RuntimeContext
from .manifest_commits import commit_receipt_path
from .pit_source_view import (
    SourcePins,
    _official_month_boundary,
    _verify_business_signature,
    contract_rows_from_daily_raw,
    validate_business_key,
    verify_root_pins,
)
from .static_core_baseline import (
    BuiltBaseline,
    PLACEHOLDER_SIGNATURE,
    RECEIPT_SCHEMA as BASELINE_EVIDENCE_SCHEMA,
    _last_trading_day,
    _registry,
    _unsigned_batch,
    build_historical_baseline,
    verified_static_baseline_daily_sources,
    verify_built_baseline,
)
from .timeutil import format_utc, parse_utc

SCHEMA_VERSION = "vnpy_research_commodity_verified_daily_pit_main_roll_source_v2"
SOURCE_KIND = "DAILY_PIT_MAIN_ROLL_ONLY"
DERIVATION_ID = "VERIFIED_FROZEN_OI_DESC_DELIVERY_ASC_EXACT_ASC_ROLL_SOURCE_V2"
INPUT_LINEAGE_STATUS = "VERIFIED_AT_CONSTRUCTION_V2"
EXECUTION_LANE = "simnow_shakedown"
MIN_DTE_CALENDAR_DAYS = 11
MAX_ARTIFACT_RAW_BYTES = 4 * 1024 * 1024
MAX_SOURCE_RAW_BYTES = 16 * 1024 * 1024
MAX_RECEIPT_RAW_BYTES = 1024 * 1024
MAX_CONTRACT_REGISTRY_RAW_BYTES = 1024 * 1024
MAX_BASELINE_RAW_BYTES = 4 * 1024 * 1024
MAX_BASELINE_SOURCE_VIEW_RAW_BYTES = 16 * 1024 * 1024
MAX_BASELINE_EVIDENCE_RAW_BYTES = 1024 * 1024
MAX_BASELINE_UNSIGNED_RAW_BYTES = 1024 * 1024
MAX_BASELINE_ARTIFACT_RAW_BYTES = 4 * 1024 * 1024
MAX_BASELINE_AGGREGATE_RAW_BYTES = 32 * 1024 * 1024
CHINA_TZ = ZoneInfo("Asia/Shanghai")
EXCHANGES = ("SHFE", "INE")
SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "deployments/research-warehouse/verified-daily-pit-main-roll-source-v2.schema.json"
)
SCHEMA_RAW_SHA256 = "7457bda8f9541fa2445ef23e3be6f4908c66752812fa9c3a84bc72336d7c9683"

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
    "dispatch_authorized",
    "order_authorized",
    "mains",
    "verified_lineage",
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
LINEAGE_KEYS = {
    "runtime",
    "calendar",
    "operator_state",
    "run_receipt",
    "manifest",
    "sources",
    "contract_registry",
    "continuity",
    "producer",
}
RUNTIME_KEYS = {
    "runtime_input_raw_sha256",
    "isolation_policy_raw_sha256",
    "warehouse_registry_raw_sha256",
}
CALENDAR_KEYS = {
    "calendar_id",
    "calendar_raw_sha256",
    "calendar_availability_anchor_raw_sha256",
    "calendar_available_at",
}
OPERATOR_KEYS = {
    "raw_sha256",
    "manifest_sequence",
    "manifest_genesis_seal_sha256",
    "manifest_head_seal_sha256",
    "manifest_head_commit_seal_sha256",
    "commit_anchor_ledger_raw_sha256",
}
RECEIPT_KEYS = {"receipt_id", "completed_at", "raw_sha256", "raw_bytes"}
MANIFEST_LINEAGE_KEYS = {
    "trade_day",
    "batch_id",
    "batch_seal_sha256",
    "commit_seal_sha256",
    "manifest_raw_sha256",
    "commit_receipt_raw_sha256",
    "parent_batch_seal_sha256",
    "parent_commit_seal_sha256",
}
CONTRACT_REGISTRY_KEYS = {"raw_sha256", "raw_bytes", "expected_raw_sha256"}
PRODUCER_KEYS = {"producer_kernel_id", "frozen_rule_id", "frozen_rule_sha256"}
BASELINE_EVIDENCE_KEYS = {
    "schema_version",
    "derivation_id",
    "source_month",
    "research_as_of_official_day",
    "execution_day",
    "execution_lane",
    "historical_backfill_completed_at",
    "logical_replay_generated_at",
    "logical_replay_is_not_acquisition_time",
    "pins",
    "source_view_raw_sha256",
    "source_view_raw_bytes",
    "artifact_digests",
    "unsigned_batch_raw_sha256",
    "unsigned_batch_raw_bytes",
    "producer_replay",
    "authority",
}
BASELINE_PIN_KEYS = {
    "history_receipt_raw_sha256",
    "calendar_raw_sha256",
    "calendar_anchor_raw_sha256",
    "warehouse_registry_raw_sha256",
    "contract_registry_raw_sha256",
    "operator_pins",
    "supplemental_daily_receipts",
    "source_month",
    "derivation_id",
}
BASELINE_OPERATOR_PIN_KEYS = {
    "operator_state_raw_sha256",
    "manifest_genesis_seal_sha256",
    "manifest_head_seal_sha256",
    "manifest_head_commit_seal_sha256",
    "commit_anchor_ledger_raw_sha256",
}
GENESIS_CONTINUITY_KEYS = {
    "mode",
    "baseline_batch_id",
    "baseline_batch_raw_sha256",
    "baseline_batch_raw_bytes",
    "baseline_unsigned_sha256",
    "baseline_source_view_raw_sha256",
    "baseline_unsigned_batch_raw_sha256",
    "baseline_replay_evidence_raw_sha256",
    "baseline_source_month",
    "baseline_execution_day",
    "baseline_signer_key_id",
    "baseline_public_key_sha256",
    "predecessor_exact_contract_map_sha256",
}
LINKED_CONTINUITY_KEYS = {
    "mode",
    "catalog_receipt_id",
    "catalog_receipt_raw_sha256",
    "catalog_sequence",
    "predecessor_artifact_id",
    "predecessor_artifact_raw_sha256",
    "predecessor_artifact_raw_bytes",
    "predecessor_official_day",
    "predecessor_execution_day",
    "predecessor_exact_contract_map_sha256",
}


class VerifiedDailyPitMainRollSourceError(RegistryError):
    """Fail-closed verified daily roll-source construction error."""


@dataclass(frozen=True)
class GenesisContinuity:
    source_month: str
    built_baseline: BuiltBaseline
    signed_baseline_batch_raw: bytes
    business_public_key_path: Path
    expected_business_signer_key_id: str


@dataclass(frozen=True)
class PredecessorContinuity:
    """Request linked continuity from the fixed root-managed catalog."""


@dataclass(frozen=True)
class BuiltVerifiedDailyPitMainRollSource:
    artifact_raw: bytes
    artifact_id: str
    artifact_raw_sha256: str


@dataclass(frozen=True)
class _VerifiedDailyInput:
    receipt_raw: bytes
    receipt: dict[str, Any]
    daily_source_raw: dict[str, bytes]
    manifest: dict[str, Any]
    manifest_raw_sha256: str
    commit_receipt_raw_sha256: str
    expected_genesis_baseline: BuiltBaseline | None
    predecessor_entry: Any | None


def _bounded_bytes(raw: object, label: str, maximum: int) -> bytes:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise VerifiedDailyPitMainRollSourceError(f"{label} resource limit exceeded")
    return raw


def _operator_root_pins(operator_state: OperatorState) -> dict[str, str]:
    return {
        "operator_state_raw_sha256": operator_state.raw_sha256,
        "manifest_genesis_seal_sha256": operator_state.payload[
            "manifest_genesis_seal_sha256"
        ],
        "manifest_head_seal_sha256": operator_state.payload[
            "manifest_head_seal_sha256"
        ],
        "manifest_head_commit_seal_sha256": operator_state.payload[
            "manifest_head_commit_seal_sha256"
        ],
        "commit_anchor_ledger_raw_sha256": operator_state.payload[
            "commit_anchor_ledger_raw_sha256"
        ],
    }


def _day(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise VerifiedDailyPitMainRollSourceError(f"{label} is not canonical")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise VerifiedDailyPitMainRollSourceError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise VerifiedDailyPitMainRollSourceError(f"{label} is not canonical")
    return parsed


def _source_month(value: object) -> str:
    if not isinstance(value, str) or len(value) != 7:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 Genesis source month is not canonical"
        )
    try:
        parsed = date.fromisoformat(f"{value}-01")
    except ValueError as exc:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 Genesis source month is invalid"
        ) from exc
    if parsed.strftime("%Y-%m") != value:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 Genesis source month is not canonical"
        )
    return value


def _following_days(context: RuntimeContext, official_day: date) -> tuple[date, date]:
    if not context.calendar.require_day(official_day).is_official:
        raise VerifiedDailyPitMainRollSourceError("daily v2 day is not official")
    following = sorted(
        day
        for day, row in context.calendar.days.items()
        if row.is_official and day > official_day
    )
    if len(following) < 2:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 calendar lacks execution/following day"
        )
    return following[0], following[1]


def _exact_contract_map(rows: list[dict[str, Any]], field: str) -> dict[str, str]:
    if len(rows) != len(frozen.PRODUCTS):
        raise VerifiedDailyPitMainRollSourceError("daily v2 contract map is incomplete")
    result: dict[str, str] = {}
    for index, product in enumerate(frozen.PRODUCTS):
        row = rows[index]
        if not isinstance(row, dict) or row.get("product") != product:
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 product order/set mismatch"
            )
        contract = row.get(field)
        spec = frozen.PRODUCT_SPECS[product]
        match = (
            frozen.CONTRACT_PATTERN.fullmatch(contract)
            if isinstance(contract, str)
            else None
        )
        if (
            match is None
            or match.group(1) != spec["exchange"]
            or match.group(2) != product
            or not 1 <= int(contract[-2:]) <= 12
        ):
            raise VerifiedDailyPitMainRollSourceError(
                f"daily v2 {product} exact contract is invalid"
            )
        result[product] = contract
    return result


def _artifact_id(payload: dict[str, Any]) -> str:
    return "verified-daily-roll-" + sha256(
        canonical_json({**payload, "artifact_id": ""})
    )


def _validate_against_root_pinned_schema(payload: dict[str, Any]) -> None:
    schema_raw = read_regular_strict(
        SCHEMA_PATH,
        "daily v2 root-pinned JSON schema",
        limit=512 * 1024,
        private=False,
    )
    if sha256(schema_raw) != SCHEMA_RAW_SHA256:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 JSON schema root pin mismatch"
        )
    schema = parse_json_strict(schema_raw, "daily v2 root-pinned JSON schema")
    if not isinstance(schema, dict):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 JSON schema must be one object"
        )
    try:
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            ).iter_errors(payload),
            key=lambda error: tuple(str(item) for item in error.absolute_path),
        )
    except Exception as exc:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 JSON schema validation unavailable"
        ) from exc
    if errors:
        raise VerifiedDailyPitMainRollSourceError(
            f"daily v2 JSON schema validation failed: {errors[0].message}"
        )


def _bounded_verified_baseline(
    built: BuiltBaseline,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_raw = _bounded_bytes(
        built.source_view_raw,
        "daily v2 baseline source view",
        MAX_BASELINE_SOURCE_VIEW_RAW_BYTES,
    )
    evidence_raw = _bounded_bytes(
        built.evidence_raw,
        "daily v2 baseline evidence",
        MAX_BASELINE_EVIDENCE_RAW_BYTES,
    )
    unsigned_raw = _bounded_bytes(
        built.unsigned_batch_raw,
        "daily v2 baseline unsigned batch",
        MAX_BASELINE_UNSIGNED_RAW_BYTES,
    )
    if not isinstance(built.artifacts, dict) or set(built.artifacts) != set(
        static_producer.ARTIFACT_ROLES
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 baseline artifact role set mismatch"
        )
    artifacts = {
        role: _bounded_bytes(
            built.artifacts[role],
            f"daily v2 baseline {role}",
            MAX_BASELINE_ARTIFACT_RAW_BYTES,
        )
        for role in static_producer.ARTIFACT_ROLES
    }
    aggregate = (
        len(source_raw)
        + len(evidence_raw)
        + len(unsigned_raw)
        + sum(len(raw) for raw in artifacts.values())
    )
    if aggregate > MAX_BASELINE_AGGREGATE_RAW_BYTES:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 baseline aggregate resource limit exceeded"
        )
    verify_built_baseline(built)
    evidence = parse_json_strict(evidence_raw, "daily v2 baseline evidence")
    source_view = parse_json_strict(source_raw, "daily v2 baseline source view")
    target = parse_json_strict(
        artifacts["target_evidence"],
        "daily v2 baseline target evidence",
    )
    if (
        not isinstance(evidence, dict)
        or set(evidence) != BASELINE_EVIDENCE_KEYS
        or evidence["schema_version"] != BASELINE_EVIDENCE_SCHEMA
        or evidence["authority"] != false_authority()
        or evidence["producer_replay"] != "EXACT_BYTES_VERIFIED"
        or evidence["source_view_raw_sha256"] != sha256(source_raw)
        or evidence["source_view_raw_bytes"] != len(source_raw)
        or evidence["unsigned_batch_raw_sha256"] != sha256(unsigned_raw)
        or evidence["unsigned_batch_raw_bytes"] != len(unsigned_raw)
        or evidence["artifact_digests"]
        != [
            {
                "role": role,
                "raw_sha256": sha256(artifacts[role]),
                "raw_bytes": len(artifacts[role]),
            }
            for role in static_producer.ARTIFACT_ROLES
        ]
        or not isinstance(source_view, dict)
        or not isinstance(target, dict)
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 baseline replay evidence contract mismatch"
        )
    pins = evidence["pins"]
    if (
        not isinstance(pins, dict)
        or set(pins) != BASELINE_PIN_KEYS
        or not isinstance(pins["operator_pins"], dict)
        or set(pins["operator_pins"]) != BASELINE_OPERATOR_PIN_KEYS
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 baseline replay pin contract mismatch"
        )
    return evidence, source_view, target


def _root_replayed_genesis_baseline(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    history: dict[str, Any],
    chain: list[dict[str, Any]],
    pins: SourcePins,
    contract_registry_raw: bytes,
    source_month: str,
    signer_key_id: str,
) -> BuiltBaseline:
    """Rebuild the monthly baseline only from the verified Warehouse root."""

    baseline_sources = verified_static_baseline_daily_sources(
        context=context,
        history=history,
        chain=chain,
        source_month=source_month,
    )
    return build_historical_baseline(
        calendar=context.calendar,
        calendar_anchor_raw_sha256=context.availability.raw_sha256,
        warehouse_registry_raw_sha256=context.registry.raw_sha256,
        history_receipt=history,
        history_receipt_raw_sha256=pins.history_receipt_raw_sha256,
        operator_pins=_operator_root_pins(operator_state),
        daily_source_raw=baseline_sources.daily_raw,
        contract_registry_raw=contract_registry_raw,
        source_month=source_month,
        signer_key_id=signer_key_id,
        execution_lane=EXECUTION_LANE,
        supplemental_daily_receipts=baseline_sources.supplemental_daily_receipts,
    )


def _verify_daily_input_locked(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    history_receipt_path: Path,
    pins: SourcePins,
    manifest_public_key_path: Path,
    official_day: date,
    execution_day: date,
    contract_registry_raw: bytes,
    contract_registry_raw_sha256: str,
    genesis_signer_key_id: str | None,
    baseline_source_month: str | None,
    linked: bool,
) -> _VerifiedDailyInput:
    history, chain = verify_root_pins(
        context=context,
        operator_state=operator_state,
        history_receipt_path=history_receipt_path,
        pins=pins,
        manifest_public_key_path=manifest_public_key_path,
    )
    state = operator_state.payload
    matches = [
        item for item in chain if item.get("trade_day") == official_day.isoformat()
    ]
    if len(matches) != 1:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 chain lacks one exact official-day manifest"
        )
    manifest = matches[0]
    if (
        state.get("last_trade_day") != official_day.isoformat()
        or not chain
        or manifest is not chain[-1]
        or manifest.get("batch_seal_sha256") != state.get("manifest_head_seal_sha256")
        or manifest.get("commit_seal_sha256")
        != state.get("manifest_head_commit_seal_sha256")
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 input must be the root-pinned manifest head"
        )
    if manifest.get("commit_receipt") is None:
        raise VerifiedDailyPitMainRollSourceError("daily v2 manifest is uncommitted")

    receipt_path = context.runtime.run_receipts / f"{official_day.isoformat()}.json"
    receipt_raw = read_regular_strict(
        receipt_path,
        "daily v2 run receipt",
        limit=MAX_RECEIPT_RAW_BYTES,
    )
    receipt = load_run_receipt(receipt_path)
    if receipt_raw != canonical_json_line(receipt):
        raise VerifiedDailyPitMainRollSourceError("daily v2 receipt bytes drifted")
    completed = verify_daily_run_receipt(
        receipt,
        paths=context.paths,
        registry=context.registry,
        calendar=context.calendar,
        calendar_availability_raw_sha256=context.availability.raw_sha256,
    )
    context.availability.require_available(context.calendar, cutoff_at=completed)
    cutoff = datetime.combine(execution_day, time(0, 0), tzinfo=CHINA_TZ)
    sealed = parse_utc(manifest["sealed_at"], "daily v2 manifest sealed_at")
    committed = parse_utc(
        manifest["commit_receipt"]["committed_at"],
        "daily v2 manifest committed_at",
    )
    if not completed <= sealed <= committed < cutoff:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 evidence was unavailable at the execution cutoff"
        )

    revisions = {item["revision_id"]: item for item in manifest["revisions"]}
    raw_by_exchange: dict[str, bytes] = {}
    for source in receipt["sources"]:
        revision = revisions.get(source["revision_id"])
        if revision is None or any(
            revision[field] != source[field]
            for field in ("raw_sha256", "raw_bytes", "raw_relative_path")
        ):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 manifest/receipt revision mismatch"
            )
        raw = read_regular_strict(
            context.paths.root / source["raw_relative_path"],
            "daily v2 exact source raw",
            limit=MAX_SOURCE_RAW_BYTES,
        )
        if len(raw) != source["raw_bytes"] or sha256(raw) != source["raw_sha256"]:
            raise VerifiedDailyPitMainRollSourceError("daily v2 source raw drifted")
        raw_by_exchange[source["exchange"]] = raw
    if set(raw_by_exchange) != set(EXCHANGES):
        raise VerifiedDailyPitMainRollSourceError("daily v2 source set mismatch")

    manifest_path = (
        context.paths.manifests
        / official_day.isoformat()
        / f"{manifest['batch_id']}.json"
    )
    manifest_raw = read_regular_strict(
        manifest_path,
        "daily v2 manifest bytes",
        limit=16 * 1024 * 1024,
    )
    manifest_payload = {
        key: value
        for key, value in manifest.items()
        if key not in {"commit_receipt", "commit_seal_sha256"}
    }
    if manifest_raw != canonical_json_line(manifest_payload):
        raise VerifiedDailyPitMainRollSourceError("daily v2 manifest bytes drifted")
    commit_path = commit_receipt_path(manifest_path, manifest["batch_id"])
    commit_raw = read_regular_strict(
        commit_path,
        "daily v2 commit receipt bytes",
        limit=2 * 1024 * 1024,
    )
    if commit_raw != canonical_json_line(manifest["commit_receipt"]):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 commit receipt bytes drifted"
        )
    expected_genesis_baseline = None
    predecessor_entry = None
    if linked:
        from .daily_roll_predecessor_catalog import _load_linked_predecessor_locked

        predecessor_entry = _load_linked_predecessor_locked(
            operator_state=operator_state,
            current_official_day=official_day,
            current_execution_day=execution_day,
            current_manifest=manifest,
            runtime_input_raw_sha256=context.runtime_input.raw_sha256,
            calendar_raw_sha256=context.calendar.raw_sha256,
            calendar_availability_anchor_raw_sha256=context.availability.raw_sha256,
            isolation_policy_raw_sha256=context.policy.raw_sha256,
            warehouse_registry_raw_sha256=context.registry.raw_sha256,
            contract_registry_raw_sha256=contract_registry_raw_sha256,
        )
    else:
        if baseline_source_month is None or genesis_signer_key_id is None:
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 Genesis replay inputs are incomplete"
            )
        expected_genesis_baseline = _root_replayed_genesis_baseline(
            context=context,
            operator_state=operator_state,
            history=history,
            chain=chain,
            pins=pins,
            contract_registry_raw=contract_registry_raw,
            source_month=baseline_source_month,
            signer_key_id=genesis_signer_key_id,
        )
    return _VerifiedDailyInput(
        receipt_raw=receipt_raw,
        receipt=receipt,
        daily_source_raw=raw_by_exchange,
        manifest=manifest,
        manifest_raw_sha256=sha256(manifest_raw),
        commit_receipt_raw_sha256=sha256(commit_raw),
        expected_genesis_baseline=expected_genesis_baseline,
        predecessor_entry=predecessor_entry,
    )


def _verify_daily_input(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    history_receipt_path: Path,
    pins: SourcePins,
    manifest_public_key_path: Path,
    official_day: date,
    execution_day: date,
    contract_registry_raw: bytes,
    contract_registry_raw_sha256: str,
    genesis_signer_key_id: str | None,
    baseline_source_month: str | None,
    linked: bool,
) -> _VerifiedDailyInput:
    """Hold the operator-state lock across daily and baseline root replay."""

    with operator_state_lock(operator_state.path, exclusive=False):
        current = load_operator_state(operator_state.path)
        if (
            current.raw_sha256 != operator_state.raw_sha256
            or current.payload != operator_state.payload
        ):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 operator state changed before verification"
            )
        return _verify_daily_input_locked(
            context=context,
            operator_state=current,
            history_receipt_path=history_receipt_path,
            pins=pins,
            manifest_public_key_path=manifest_public_key_path,
            official_day=official_day,
            execution_day=execution_day,
            contract_registry_raw=contract_registry_raw,
            contract_registry_raw_sha256=contract_registry_raw_sha256,
            genesis_signer_key_id=genesis_signer_key_id,
            baseline_source_month=baseline_source_month,
            linked=linked,
        )


def _genesis_map(
    *,
    genesis: GenesisContinuity,
    expected_built: BuiltBaseline,
    context: RuntimeContext,
    operator_state: OperatorState,
    pins: SourcePins,
    official_day: date,
    contract_registry_sha256: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    built = genesis.built_baseline
    if not isinstance(built, BuiltBaseline):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 genesis requires one complete BuiltBaseline"
        )
    evidence, source_view, target_evidence = _bounded_verified_baseline(built)
    _bounded_verified_baseline(expected_built)
    if built != expected_built:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 caller baseline does not match independently root-replayed bytes"
        )
    raw = _bounded_bytes(
        genesis.signed_baseline_batch_raw,
        "daily v2 signed genesis baseline",
        MAX_BASELINE_RAW_BYTES,
    )
    baseline = parse_json_strict(raw, "daily v2 signed baseline")
    if not isinstance(baseline, dict):
        raise VerifiedDailyPitMainRollSourceError("daily v2 baseline is not an object")
    key = validate_business_key(
        genesis.business_public_key_path,
        expected_raw_sha256=pins.baseline_public_key_raw_sha256,
    )
    _verify_business_signature(
        baseline,
        public_key=key,
        expected_signer_key_id=genesis.expected_business_signer_key_id,
        label="daily v2 STATIC_CORE_EQUAL baseline",
    )
    unsigned_hash = sha256(
        canonical_json(
            {key: value for key, value in baseline.items() if key != "signature"}
        )
    )
    built_unsigned_raw = built.unsigned_batch_raw
    built_unsigned = parse_json_strict(
        built_unsigned_raw,
        "daily v2 replayed unsigned baseline",
    )
    evidence_pins = evidence.get("pins")
    expected_operator_pins = _operator_root_pins(operator_state)
    baseline_execution_day = _day(
        evidence.get("execution_day"), "daily v2 Genesis baseline execution day"
    )
    if (
        baseline_execution_day.strftime("%Y-%m") != official_day.strftime("%Y-%m")
        or baseline_execution_day > official_day
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 Genesis baseline must execute in the artifact month no later than the artifact official day"
        )
    spec_bindings = [
        row
        for row in source_view.get("source_bindings", [])
        if isinstance(row, dict) and row.get("source_class") == "CONTRACT_SPEC"
    ]
    if (
        not isinstance(evidence_pins, dict)
        or evidence_pins.get("history_receipt_raw_sha256")
        != pins.history_receipt_raw_sha256
        or evidence_pins.get("calendar_raw_sha256") != context.calendar.raw_sha256
        or evidence_pins.get("calendar_anchor_raw_sha256")
        != context.availability.raw_sha256
        or evidence_pins.get("warehouse_registry_raw_sha256")
        != context.registry.raw_sha256
        or evidence_pins.get("operator_pins") != expected_operator_pins
        or evidence_pins.get("contract_registry_raw_sha256") != contract_registry_sha256
        or evidence_pins.get("source_month") != genesis.source_month
        or evidence_pins.get("derivation_id") != evidence.get("derivation_id")
        or len(spec_bindings) != 2
        or {row.get("scope") for row in spec_bindings} != set(EXCHANGES)
        or any(
            row.get("raw_sha256") != contract_registry_sha256 for row in spec_bindings
        )
        or evidence.get("source_month") != genesis.source_month
        or evidence.get("execution_day") != baseline_execution_day.isoformat()
        or evidence.get("execution_lane") != EXECUTION_LANE
        or source_view.get("claimed_receipt_sha256") != pins.history_receipt_raw_sha256
        or any(
            not isinstance(row, dict)
            or row.get("claimed_receipt_sha256") != pins.history_receipt_raw_sha256
            for row in source_view.get("source_bindings", [])
        )
        or source_view.get("research_as_of_official_day")
        != evidence.get("research_as_of_official_day")
        or source_view.get("execution_day") != baseline_execution_day.isoformat()
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 baseline replay/contract-registry lineage mismatch"
        )
    try:
        validated, by_product, _allocation = monthly_producer._validate_baseline_batch(
            baseline,
            claimed_hash=unsigned_hash,
        )
    except (ValueError, monthly_producer.SnapshotProducerError) as exc:
        raise VerifiedDailyPitMainRollSourceError(str(exc)) from exc
    if (
        validated["source_month"] != genesis.source_month
        or validated["execution_day"] != baseline_execution_day.isoformat()
        or validated["execution_lane"] != evidence["execution_lane"]
        or validated["signer_key_id"] != genesis.expected_business_signer_key_id
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 genesis baseline frozen-field binding mismatch"
        )
    expected_unsigned_raw = canonical_json(
        _unsigned_batch(
            target_evidence,
            source_month=evidence["source_month"],
            execution_day=date.fromisoformat(evidence["execution_day"]),
            signer_key_id=genesis.expected_business_signer_key_id,
            execution_lane=EXECUTION_LANE,
        )
    )
    if (
        not isinstance(built_unsigned, dict)
        or canonical_json(built_unsigned) != built_unsigned_raw
        or built_unsigned.get("signature") != PLACEHOLDER_SIGNATURE
        or expected_unsigned_raw != built_unsigned_raw
        or canonical_json({**baseline, "signature": PLACEHOLDER_SIGNATURE})
        != expected_unsigned_raw
        or canonical_json(
            {key: value for key, value in baseline.items() if key != "signature"}
        )
        != canonical_json(
            {key: value for key, value in built_unsigned.items() if key != "signature"}
        )
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 signed baseline does not match deterministic replayed target bytes"
        )
    predecessor = {
        product: by_product[product]["exact_contract"] for product in frozen.PRODUCTS
    }
    return predecessor, {
        "mode": "GENESIS_STATIC_CORE_EQUAL",
        "baseline_batch_id": validated["batch_id"],
        "baseline_batch_raw_sha256": sha256(raw),
        "baseline_batch_raw_bytes": len(raw),
        "baseline_unsigned_sha256": unsigned_hash,
        "baseline_source_view_raw_sha256": sha256(built.source_view_raw),
        "baseline_unsigned_batch_raw_sha256": sha256(built.unsigned_batch_raw),
        "baseline_replay_evidence_raw_sha256": sha256(built.evidence_raw),
        "baseline_source_month": validated["source_month"],
        "baseline_execution_day": validated["execution_day"],
        "baseline_signer_key_id": validated["signer_key_id"],
        "baseline_public_key_sha256": pins.baseline_public_key_raw_sha256,
        "predecessor_exact_contract_map_sha256": _map_sha(predecessor),
    }


def _linked_map(entry: Any) -> tuple[dict[str, str], dict[str, Any]]:
    if entry is None:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 linked predecessor catalog entry is unavailable"
        )
    try:
        artifact = entry.artifact
        artifact_raw = entry.artifact_raw
        receipt = entry.receipt
        receipt_raw = entry.receipt_raw
    except AttributeError as exc:
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 linked predecessor catalog entry is invalid"
        ) from exc
    predecessor = _exact_contract_map(artifact["mains"], "exact_contract")
    return predecessor, {
        "mode": "LINKED_ROOT_CATALOG",
        "catalog_receipt_id": receipt["receipt_id"],
        "catalog_receipt_raw_sha256": sha256(receipt_raw),
        "catalog_sequence": receipt["sequence"],
        "predecessor_artifact_id": artifact["artifact_id"],
        "predecessor_artifact_raw_sha256": sha256(artifact_raw),
        "predecessor_artifact_raw_bytes": len(artifact_raw),
        "predecessor_official_day": artifact["official_day"],
        "predecessor_execution_day": artifact["execution_day"],
        "predecessor_exact_contract_map_sha256": _map_sha(predecessor),
    }


def _map_sha(value: dict[str, str]) -> str:
    return sha256(
        canonical_json(
            [
                {"product": product, "exact_contract": value[product]}
                for product in frozen.PRODUCTS
            ]
        )
    )


def _recheck_verified_input(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    official_day: date,
    value: _VerifiedDailyInput,
) -> None:
    receipt = validate_run_receipt(
        parse_json_strict(value.receipt_raw, "daily v2 verified receipt")
    )
    if receipt != value.receipt or value.receipt_raw != canonical_json_line(receipt):
        raise VerifiedDailyPitMainRollSourceError("daily v2 receipt bytes drifted")
    if (
        receipt["trade_day"] != official_day.isoformat()
        or receipt["registry_raw_sha256"] != context.registry.raw_sha256
        or receipt["calendar_raw_sha256"] != context.calendar.raw_sha256
        or receipt["calendar_availability_anchor_raw_sha256"]
        != context.availability.raw_sha256
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 receipt runtime/calendar binding mismatch"
        )
    if set(value.daily_source_raw) != set(EXCHANGES):
        raise VerifiedDailyPitMainRollSourceError("daily v2 source set mismatch")
    for index, exchange in enumerate(EXCHANGES):
        source = receipt["sources"][index]
        raw = value.daily_source_raw[exchange]
        if (
            source["exchange"] != exchange
            or len(raw) != source["raw_bytes"]
            or sha256(raw) != source["raw_sha256"]
        ):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 receipt/source raw binding mismatch"
            )
    manifest = value.manifest
    revisions = {
        row.get("revision_id"): row
        for row in manifest.get("revisions", [])
        if isinstance(row, dict)
    }
    if (
        manifest.get("trade_day") != official_day.isoformat()
        or manifest.get("batch_seal_sha256")
        != operator_state.payload.get("manifest_head_seal_sha256")
        or manifest.get("commit_seal_sha256")
        != operator_state.payload.get("manifest_head_commit_seal_sha256")
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 manifest/operator binding mismatch"
        )
    for source in receipt["sources"]:
        revision = revisions.get(source["revision_id"])
        if revision is None or any(
            revision.get(field) != source[field]
            for field in ("raw_sha256", "raw_bytes", "raw_relative_path")
        ):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 manifest/receipt revision mismatch"
            )


def _mains(
    *,
    context: RuntimeContext,
    official_day: date,
    execution_day: date,
    following_day: date,
    daily_source_raw: dict[str, bytes],
    contract_registry: dict[str, dict[str, Any]],
    predecessor: dict[str, str],
) -> list[dict[str, Any]]:
    extracted = {
        exchange: contract_rows_from_daily_raw(
            raw=daily_source_raw[exchange],
            exchange=exchange,
            official_day=official_day.isoformat(),
        )
        for exchange in EXCHANGES
    }
    result = []
    for product in frozen.PRODUCTS:
        spec = frozen.PRODUCT_SPECS[product]
        exchange = str(spec["exchange"])
        try:
            main, ranked = frozen._pit_main(
                product,
                official_day,
                extracted[exchange][product],
            )
        except frozen.ProducerKernelError as exc:
            raise VerifiedDailyPitMainRollSourceError(str(exc)) from exc
        exact = str(main["exact_contract"])
        last_day = _last_trading_day(
            context.calendar,
            delivery_yyyymm=int(main["delivery_yyyymm"]),
            rule=str(contract_registry[product]["last_trading_day_rule"]),
        )
        execution_dte = (last_day - execution_day).days
        following_dte = (last_day - following_day).days
        if (
            execution_dte < MIN_DTE_CALENDAR_DAYS
            or following_dte < MIN_DTE_CALENDAR_DAYS
        ):
            raise VerifiedDailyPitMainRollSourceError(
                f"{product} PIT main is inside the DTE safety boundary"
            )
        result.append(
            {
                "product": product,
                "exchange": exchange,
                "previous_exact_contract": predecessor[product],
                "exact_contract": exact,
                "changed": predecessor[product] != exact,
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
    return result


def build_verified_daily_pit_main_roll_source(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    history_receipt_path: Path,
    pins: SourcePins,
    manifest_public_key_path: Path,
    official_day: str,
    contract_registry_raw: bytes,
    expected_contract_registry_raw_sha256: str,
    genesis: GenesisContinuity | None = None,
    predecessor: PredecessorContinuity | None = None,
) -> BuiltVerifiedDailyPitMainRollSource:
    """Construct one Genesis or root-catalog-linked no-authority artifact."""

    try:
        if (genesis is None) == (predecessor is None):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 requires exactly one continuity mode"
            )
        source_month = None
        if genesis is not None:
            if not isinstance(genesis.built_baseline, BuiltBaseline):
                raise VerifiedDailyPitMainRollSourceError(
                    "daily v2 genesis requires one complete BuiltBaseline"
                )
            _bounded_verified_baseline(genesis.built_baseline)
            source_month = _source_month(genesis.source_month)
        registry_raw = _bounded_bytes(
            contract_registry_raw,
            "daily v2 contract registry",
            MAX_CONTRACT_REGISTRY_RAW_BYTES,
        )
        contract_registry, registry_sha = _registry(registry_raw)
        if registry_sha != require_sha(
            expected_contract_registry_raw_sha256,
            "daily v2 expected contract registry",
        ):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 contract registry root pin mismatch"
            )
        day = _day(official_day, "daily v2 official day")
        if genesis is not None:
            _baseline_research_day, baseline_execution_day, _baseline_cutoff_day = (
                _official_month_boundary(
                    context.calendar,
                    source_month=source_month,
                )
            )
            if (
                baseline_execution_day.strftime("%Y-%m")
                != day.strftime("%Y-%m")
                or baseline_execution_day > day
            ):
                raise VerifiedDailyPitMainRollSourceError(
                    "daily v2 Genesis baseline must execute in the artifact month no later than the artifact official day"
                )
        execution_day, following_day = _following_days(context, day)
        verified = _verify_daily_input(
            context=context,
            operator_state=operator_state,
            history_receipt_path=history_receipt_path,
            pins=pins,
            manifest_public_key_path=manifest_public_key_path,
            official_day=day,
            execution_day=execution_day,
            contract_registry_raw=registry_raw,
            contract_registry_raw_sha256=registry_sha,
            genesis_signer_key_id=(
                genesis.expected_business_signer_key_id if genesis is not None else None
            ),
            baseline_source_month=source_month,
            linked=predecessor is not None,
        )
        _recheck_verified_input(
            context=context,
            operator_state=operator_state,
            official_day=day,
            value=verified,
        )
        if genesis is not None:
            if verified.expected_genesis_baseline is None:
                raise VerifiedDailyPitMainRollSourceError(
                    "daily v2 Genesis root replay is unavailable"
                )
            predecessor_map, continuity = _genesis_map(
                genesis=genesis,
                expected_built=verified.expected_genesis_baseline,
                context=context,
                operator_state=operator_state,
                pins=pins,
                official_day=day,
                contract_registry_sha256=registry_sha,
            )
        else:
            predecessor_map, continuity = _linked_map(verified.predecessor_entry)
        mains = _mains(
            context=context,
            official_day=day,
            execution_day=execution_day,
            following_day=following_day,
            daily_source_raw=verified.daily_source_raw,
            contract_registry=contract_registry,
            predecessor=predecessor_map,
        )
        changed = [row["product"] for row in mains if row["changed"]]
        receipt = verified.receipt
        manifest = verified.manifest
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "artifact_id": "",
            "source_kind": SOURCE_KIND,
            "derivation_id": DERIVATION_ID,
            "official_day": day.isoformat(),
            "execution_day": execution_day.isoformat(),
            "following_official_day": following_day.isoformat(),
            "roll_change_detected": bool(changed),
            "changed_products": changed,
            "input_lineage_status": INPUT_LINEAGE_STATUS,
            "installable": False,
            "event_ready": False,
            "execution_lane": EXECUTION_LANE,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "official_forward_claimed": False,
            "dispatch_authorized": False,
            "order_authorized": False,
            "mains": mains,
            "verified_lineage": {
                "runtime": {
                    "runtime_input_raw_sha256": context.runtime_input.raw_sha256,
                    "isolation_policy_raw_sha256": context.policy.raw_sha256,
                    "warehouse_registry_raw_sha256": context.registry.raw_sha256,
                },
                "calendar": {
                    "calendar_id": context.calendar.calendar_id,
                    "calendar_raw_sha256": context.calendar.raw_sha256,
                    "calendar_availability_anchor_raw_sha256": context.availability.raw_sha256,
                    "calendar_available_at": format_utc(
                        context.availability.available_at,
                        "daily v2 calendar available_at",
                    ),
                },
                "operator_state": {
                    "raw_sha256": operator_state.raw_sha256,
                    "manifest_sequence": operator_state.payload["manifest_sequence"],
                    "manifest_genesis_seal_sha256": operator_state.payload[
                        "manifest_genesis_seal_sha256"
                    ],
                    "manifest_head_seal_sha256": operator_state.payload[
                        "manifest_head_seal_sha256"
                    ],
                    "manifest_head_commit_seal_sha256": operator_state.payload[
                        "manifest_head_commit_seal_sha256"
                    ],
                    "commit_anchor_ledger_raw_sha256": operator_state.payload[
                        "commit_anchor_ledger_raw_sha256"
                    ],
                },
                "run_receipt": {
                    "receipt_id": receipt["receipt_id"],
                    "completed_at": receipt["completed_at"],
                    "raw_sha256": sha256(verified.receipt_raw),
                    "raw_bytes": len(verified.receipt_raw),
                },
                "manifest": {
                    "trade_day": manifest["trade_day"],
                    "batch_id": manifest["batch_id"],
                    "batch_seal_sha256": manifest["batch_seal_sha256"],
                    "commit_seal_sha256": manifest["commit_seal_sha256"],
                    "manifest_raw_sha256": verified.manifest_raw_sha256,
                    "commit_receipt_raw_sha256": verified.commit_receipt_raw_sha256,
                    "parent_batch_seal_sha256": manifest["parent_batch_seal_sha256"],
                    "parent_commit_seal_sha256": manifest["parent_commit_seal_sha256"],
                },
                "sources": [dict(source) for source in receipt["sources"]],
                "contract_registry": {
                    "raw_sha256": registry_sha,
                    "raw_bytes": len(registry_raw),
                    "expected_raw_sha256": expected_contract_registry_raw_sha256,
                },
                "continuity": continuity,
                "producer": {
                    "producer_kernel_id": frozen.KERNEL_ID,
                    "frozen_rule_id": frozen.FROZEN_RULE_ID,
                    "frozen_rule_sha256": frozen.FROZEN_RULE_SHA256,
                },
            },
            "authority": false_authority(),
        }
        payload["artifact_id"] = _artifact_id(payload)
        raw = canonical_json_line(payload)
        validate_structural_daily_pit_main_roll_source(raw)
        return BuiltVerifiedDailyPitMainRollSource(
            artifact_raw=raw,
            artifact_id=payload["artifact_id"],
            artifact_raw_sha256=sha256(raw),
        )
    except RegistryError as exc:
        if isinstance(exc, VerifiedDailyPitMainRollSourceError):
            raise
        raise VerifiedDailyPitMainRollSourceError(str(exc)) from exc


def _validate_structural_daily_pit_main_roll_source(raw: bytes) -> dict[str, Any]:
    bounded = _bounded_bytes(raw, "daily v2 artifact", MAX_ARTIFACT_RAW_BYTES)
    payload = parse_json_strict(bounded, "daily v2 artifact")
    if not isinstance(payload, dict) or set(payload) != ROOT_KEYS:
        raise VerifiedDailyPitMainRollSourceError("daily v2 root fields mismatch")
    if bounded != canonical_json_line(payload):
        raise VerifiedDailyPitMainRollSourceError("daily v2 artifact is not canonical")
    _validate_against_root_pinned_schema(payload)
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["source_kind"] != SOURCE_KIND
        or payload["derivation_id"] != DERIVATION_ID
        or payload["input_lineage_status"] != INPUT_LINEAGE_STATUS
        or payload["execution_lane"] != EXECUTION_LANE
        or any(
            payload[field] is not False
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
        or payload["authority"] != false_authority()
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 authority/identity mismatch"
        )
    official = _day(payload["official_day"], "daily v2 official day")
    execution = _day(payload["execution_day"], "daily v2 execution day")
    following = _day(payload["following_official_day"], "daily v2 following day")
    if not official < execution < following:
        raise VerifiedDailyPitMainRollSourceError("daily v2 day ordering mismatch")
    mains = payload["mains"]
    previous_map = _exact_contract_map(mains, "previous_exact_contract")
    current_map = _exact_contract_map(mains, "exact_contract")
    changed = []
    for index, product in enumerate(frozen.PRODUCTS):
        row = mains[index]
        if (
            set(row) != MAIN_KEYS
            or row["exchange"] != frozen.PRODUCT_SPECS[product]["exchange"]
        ):
            raise VerifiedDailyPitMainRollSourceError("daily v2 main fields mismatch")
        if row["changed"] is not (previous_map[product] != current_map[product]):
            raise VerifiedDailyPitMainRollSourceError("daily v2 changed flag mismatch")
        if row["changed"]:
            changed.append(product)
        if (
            isinstance(row["eligible_contract_count"], bool)
            or not isinstance(row["eligible_contract_count"], int)
            or not 3 <= row["eligible_contract_count"] <= 64
            or any(
                isinstance(row[field], bool)
                or not isinstance(row[field], (int, float))
                or not math.isfinite(float(row[field]))
                or row[field] <= 0
                for field in ("settlement", "open_interest")
            )
        ):
            raise VerifiedDailyPitMainRollSourceError("daily v2 main metric mismatch")
        require_sha(row["ranked_contracts_sha256"], "daily v2 ranking")
        last_day = _day(row["official_last_trading_day"], "daily v2 last day")
        if (
            row["delivery_yyyymm"] != 200000 + int(current_map[product][-4:])
            or row["execution_day_dte"] != (last_day - execution).days
            or row["following_official_day_dte"] != (last_day - following).days
            or row["execution_day_dte"] < MIN_DTE_CALENDAR_DAYS
            or row["following_official_day_dte"] < MIN_DTE_CALENDAR_DAYS
        ):
            raise VerifiedDailyPitMainRollSourceError("daily v2 DTE/delivery mismatch")
    if payload["changed_products"] != changed or payload[
        "roll_change_detected"
    ] is not bool(changed):
        raise VerifiedDailyPitMainRollSourceError("daily v2 change summary mismatch")
    lineage = payload["verified_lineage"]
    if not isinstance(lineage, dict) or set(lineage) != LINEAGE_KEYS:
        raise VerifiedDailyPitMainRollSourceError("daily v2 lineage fields mismatch")
    expected_sections = {
        "runtime": RUNTIME_KEYS,
        "calendar": CALENDAR_KEYS,
        "operator_state": OPERATOR_KEYS,
        "run_receipt": RECEIPT_KEYS,
        "manifest": MANIFEST_LINEAGE_KEYS,
        "contract_registry": CONTRACT_REGISTRY_KEYS,
        "producer": PRODUCER_KEYS,
    }
    for section, keys in expected_sections.items():
        if not isinstance(lineage[section], dict) or set(lineage[section]) != keys:
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 lineage section mismatch"
            )
    sources = lineage["sources"]
    if (
        not isinstance(sources, list)
        or len(sources) != 2
        or [row.get("exchange") if isinstance(row, dict) else None for row in sources]
        != list(EXCHANGES)
        or any(set(row) != RUN_SOURCE_KEYS for row in sources)
    ):
        raise VerifiedDailyPitMainRollSourceError(
            "daily v2 lineage source set mismatch"
        )
    for field in (
        lineage["runtime"]["runtime_input_raw_sha256"],
        lineage["runtime"]["isolation_policy_raw_sha256"],
        lineage["runtime"]["warehouse_registry_raw_sha256"],
        lineage["calendar"]["calendar_raw_sha256"],
        lineage["calendar"]["calendar_availability_anchor_raw_sha256"],
        lineage["operator_state"]["raw_sha256"],
        lineage["operator_state"]["manifest_genesis_seal_sha256"],
        lineage["operator_state"]["manifest_head_seal_sha256"],
        lineage["operator_state"]["manifest_head_commit_seal_sha256"],
        lineage["operator_state"]["commit_anchor_ledger_raw_sha256"],
        lineage["run_receipt"]["raw_sha256"],
        lineage["manifest"]["batch_seal_sha256"],
        lineage["manifest"]["commit_seal_sha256"],
        lineage["manifest"]["manifest_raw_sha256"],
        lineage["manifest"]["commit_receipt_raw_sha256"],
        lineage["contract_registry"]["raw_sha256"],
        lineage["contract_registry"]["expected_raw_sha256"],
        lineage["producer"]["frozen_rule_sha256"],
    ):
        require_sha(field, "daily v2 lineage")
    if (
        lineage["manifest"]["trade_day"] != payload["official_day"]
        or lineage["operator_state"]["manifest_head_seal_sha256"]
        != lineage["manifest"]["batch_seal_sha256"]
        or lineage["operator_state"]["manifest_head_commit_seal_sha256"]
        != lineage["manifest"]["commit_seal_sha256"]
        or lineage["contract_registry"]["raw_sha256"]
        != lineage["contract_registry"]["expected_raw_sha256"]
        or lineage["producer"]
        != {
            "producer_kernel_id": frozen.KERNEL_ID,
            "frozen_rule_id": frozen.FROZEN_RULE_ID,
            "frozen_rule_sha256": frozen.FROZEN_RULE_SHA256,
        }
    ):
        raise VerifiedDailyPitMainRollSourceError("daily v2 lineage binding mismatch")
    continuity = lineage["continuity"]
    if not isinstance(continuity, dict):
        raise VerifiedDailyPitMainRollSourceError("daily v2 continuity mode mismatch")
    if continuity.get("mode") == "GENESIS_STATIC_CORE_EQUAL":
        if set(continuity) != GENESIS_CONTINUITY_KEYS:
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 continuity mode mismatch"
            )
        continuity_hash_fields = (
            "baseline_batch_raw_sha256",
            "baseline_unsigned_sha256",
            "baseline_public_key_sha256",
            "baseline_source_view_raw_sha256",
            "baseline_unsigned_batch_raw_sha256",
            "baseline_replay_evidence_raw_sha256",
            "predecessor_exact_contract_map_sha256",
        )
        for field in continuity_hash_fields:
            require_sha(continuity[field], f"daily v2 continuity {field}")
        baseline_execution_day = _day(
            continuity.get("baseline_execution_day"),
            "daily v2 Genesis baseline execution day",
        )
        if (
            baseline_execution_day.strftime("%Y-%m")
            != official.strftime("%Y-%m")
            or baseline_execution_day > official
            or continuity.get("predecessor_exact_contract_map_sha256")
            != _map_sha(previous_map)
        ):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 Genesis continuity binding mismatch"
            )
    elif continuity.get("mode") == "LINKED_ROOT_CATALOG":
        if set(continuity) != LINKED_CONTINUITY_KEYS:
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 continuity mode mismatch"
            )
        for field in (
            "catalog_receipt_raw_sha256",
            "predecessor_artifact_raw_sha256",
            "predecessor_exact_contract_map_sha256",
        ):
            require_sha(continuity[field], f"daily v2 continuity {field}")
        predecessor_day = _day(
            continuity["predecessor_official_day"],
            "daily v2 predecessor official day",
        )
        predecessor_execution = _day(
            continuity["predecessor_execution_day"],
            "daily v2 predecessor execution day",
        )
        if (
            not isinstance(continuity["catalog_receipt_id"], str)
            or not continuity["catalog_receipt_id"].startswith(
                "daily-roll-catalog-receipt-"
            )
            or len(continuity["catalog_receipt_id"])
            != len("daily-roll-catalog-receipt-") + 64
            or not isinstance(continuity["predecessor_artifact_id"], str)
            or not continuity["predecessor_artifact_id"].startswith(
                "verified-daily-roll-"
            )
            or len(continuity["predecessor_artifact_id"])
            != len("verified-daily-roll-") + 64
            or isinstance(continuity["catalog_sequence"], bool)
            or not isinstance(continuity["catalog_sequence"], int)
            or continuity["catalog_sequence"] < 1
            or isinstance(continuity["predecessor_artifact_raw_bytes"], bool)
            or not isinstance(continuity["predecessor_artifact_raw_bytes"], int)
            or not 1
            <= continuity["predecessor_artifact_raw_bytes"]
            <= MAX_ARTIFACT_RAW_BYTES
            or not predecessor_day < predecessor_execution
            or predecessor_execution != official
            or continuity["predecessor_exact_contract_map_sha256"]
            != _map_sha(previous_map)
        ):
            raise VerifiedDailyPitMainRollSourceError(
                "daily v2 linked continuity binding mismatch"
            )
        require_sha(
            continuity["catalog_receipt_id"].removeprefix(
                "daily-roll-catalog-receipt-"
            ),
            "daily v2 catalog receipt ID",
        )
        require_sha(
            continuity["predecessor_artifact_id"].removeprefix("verified-daily-roll-"),
            "daily v2 predecessor artifact ID",
        )
    else:
        raise VerifiedDailyPitMainRollSourceError("daily v2 continuity mode mismatch")
    if payload["artifact_id"] != _artifact_id(payload):
        raise VerifiedDailyPitMainRollSourceError("daily v2 artifact ID mismatch")
    return payload


def validate_structural_daily_pit_main_roll_source(raw: bytes) -> dict[str, Any]:
    """Validate schema/canonical/semantic shape only; prove no current root.

    Only :func:`build_verified_daily_pit_main_roll_source` performs current
    Warehouse root verification.  A structurally valid artifact grants no
    authority and is not a predecessor custody pin.
    """

    try:
        return _validate_structural_daily_pit_main_roll_source(raw)
    except VerifiedDailyPitMainRollSourceError:
        raise
    except (KeyError, TypeError, ValueError, RegistryError) as exc:
        raise VerifiedDailyPitMainRollSourceError(str(exc)) from exc
