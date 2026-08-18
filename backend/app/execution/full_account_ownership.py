"""Pure completion-aware ownership classification for Issue #362.

The module consumes detached Control projections and caller-carried immutable
source bindings. It performs no I/O, network access, mutation, custody
publication, event installation, recovery, or authority decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any

from shared.commodity_execution import (
    CommodityExecutionContractError,
    sha256_json,
    target_position_projection_hash,
)

from ..core.commodity_strategy_identity import COMMODITY_FROZEN_SECTOR_MAP_V1
from ..schemas.control_execution import (
    ExecutionAccountFactsProjectionV2,
    ExecutionCompletionProjection,
)
from .clock import FUTURE_SKEW_SECONDS, SNAPSHOT_STALE_SECONDS


_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_STABLE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_CONTRACT_RE = re.compile(r"^(CFFEX|CZCE|DCE|GFEX|INE|SHFE)\.([A-Za-z]+)([0-9]{4})$")
_PRODUCTS = tuple(COMMODITY_FROZEN_SECTOR_MAP_V1)
_EXPECTED_EXCHANGE = {
    product: "INE" if product == "sc" else "SHFE" for product in _PRODUCTS
}
_ACCOUNT_SCOPE = "account:windows"
_ENVIRONMENT = "SIMNOW"
_MAX_RAW_BYTES = 4 * 1024 * 1024
_AUTHORITY_FIELDS = frozenset(
    {
        "account_data_read",
        "control_authorized",
        "deployment_authorized",
        "execution_authorized",
        "network_beyond_allowlist_authorized",
        "order_authorized",
        "permit_authorized",
        "position_mutation_authorized",
        "production_authorized",
        "rpc_authorized",
        "trading_authorized",
    }
)
_FINAL_TARGET_FIELDS = frozenset(
    {
        "schema_version",
        "strategy_id",
        "baseline_scheduler_id",
        "execution_lane",
        "candidate_weights",
        "c_sleeve_id",
        "c_map_rule_id",
        "d_sleeve_id",
        "sector_map_id",
        "position_manager_id",
        "source_month",
        "execution_day",
        "authority_granted",
        "dispatch_allowed",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "targets",
    }
)
_FINAL_TARGET_ROW_FIELDS = frozenset(
    {
        "product",
        "sector",
        "exact_contract",
        "target_quantity",
        "reference_open_price",
        "multiplier",
        "price_tick",
    }
)
_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "selection_id",
        "selection_sha256",
        "candidate_set_sha256",
        "candidate",
        "verification_status",
        "event_ready",
        "installable",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "official_forward_claimed",
        "dispatch_authorized",
        "order_authorized",
        "position_mutation_authorized",
        "authority",
    }
)
_CANDIDATE_FIELDS = frozenset(
    {
        "candidate_id",
        "trigger_kind",
        "strategy_id",
        "execution_lane",
        "execution_day",
        "source_month",
        "verified_daily_artifact_id",
        "verified_daily_artifact_raw_sha256",
        "verified_daily_continuity_mode",
        "static_core_equal_sha256",
        "position_manager_sha256",
        "monthly_final_target_sha256",
        "baseline_batch_raw_sha256",
        "quantity_vector_sha256",
        "monthly_target_exact_contract_map_sha256",
        "previous_exact_contract_map_sha256",
        "exact_contract_map_sha256",
        "roll_preserves_integer_lots",
        "predecessor_terminal_target_id",
        "predecessor_terminal_target_raw_sha256",
        "targets",
    }
)
_CANDIDATE_TARGET_FIELDS = frozenset(
    {
        "product",
        "monthly_target_exact_contract",
        "previous_exact_contract",
        "exact_contract",
        "previous_target_quantity",
        "target_quantity",
        "exact_contract_changed",
    }
)


class FullAccountOwnershipDisposition(str, Enum):
    NEW_TARGET = "NEW_TARGET"
    ALREADY_SATISFIED = "ALREADY_SATISFIED"
    ALREADY_COMPLETED_MATCHED = "ALREADY_COMPLETED_MATCHED"
    RESUME_AFTER_CLOSE = "RESUME_AFTER_CLOSE"
    STOP = "STOP"


class FullAccountPredecessorMode(str, Enum):
    GENESIS_FLAT = "GENESIS_FLAT"
    COMPLETION = "COMPLETION"


class FullAccountOwnershipReason(str, Enum):
    ACCOUNT_FACTS_INVALID = "ACCOUNT_FACTS_INVALID"
    ACCOUNT_FACTS_V2_REQUIRED = "ACCOUNT_FACTS_V2_REQUIRED"
    ACCOUNT_SCOPE_MISMATCH = "ACCOUNT_SCOPE_MISMATCH"
    ACCOUNT_NOT_READY = "ACCOUNT_NOT_READY"
    ACCOUNT_NOT_RECONCILED = "ACCOUNT_NOT_RECONCILED"
    ACCOUNT_UNKNOWN_OUTCOMES = "ACCOUNT_UNKNOWN_OUTCOMES"
    ACCOUNT_ACTIVE_ORDERS = "ACCOUNT_ACTIVE_ORDERS"
    ACCOUNT_PLAN_NOT_TERMINAL = "ACCOUNT_PLAN_NOT_TERMINAL"
    ACCOUNT_SEND_INTENTS_PENDING = "ACCOUNT_SEND_INTENTS_PENDING"
    ACCOUNT_FACTS_STALE = "ACCOUNT_FACTS_STALE"
    ACCOUNT_FACTS_FROM_FUTURE = "ACCOUNT_FACTS_FROM_FUTURE"
    ACCOUNT_POSITION_OUTSIDE_FROZEN_UNIVERSE = (
        "ACCOUNT_POSITION_OUTSIDE_FROZEN_UNIVERSE"
    )
    DESIRED_TARGET_BINDING_INVALID = "DESIRED_TARGET_BINDING_INVALID"
    PREDECESSOR_MODE_INVALID = "PREDECESSOR_MODE_INVALID"
    ROLL_ONLY_REQUIRES_COMPLETION = "ROLL_ONLY_REQUIRES_COMPLETION"
    EXPECTED_PREDECESSOR_INVALID = "EXPECTED_PREDECESSOR_INVALID"
    PREDECESSOR_TERMINAL_PIN_MISMATCH = "PREDECESSOR_TERMINAL_PIN_MISMATCH"
    COMPLETION_MISSING = "COMPLETION_MISSING"
    COMPLETION_UNEXPECTED_AT_GENESIS = "COMPLETION_UNEXPECTED_AT_GENESIS"
    COMPLETION_INVALID = "COMPLETION_INVALID"
    COMPLETION_BINDING_MISMATCH = "COMPLETION_BINDING_MISMATCH"
    CLOSE_COMPLETION_LINEAGE_MISMATCH = "CLOSE_COMPLETION_LINEAGE_MISMATCH"
    COMPLETED_TARGET_POSITION_MISMATCH = "COMPLETED_TARGET_POSITION_MISMATCH"
    GENESIS_ACCOUNT_NOT_FLAT = "GENESIS_ACCOUNT_NOT_FLAT"
    GENESIS_FLAT_NEW_TARGET = "GENESIS_FLAT_NEW_TARGET"
    GENESIS_FLAT_ALREADY_SATISFIED = "GENESIS_FLAT_ALREADY_SATISFIED"
    PREDECESSOR_TARGET_MATCHED = "PREDECESSOR_TARGET_MATCHED"
    COMPLETED_TARGET_ALREADY_MATCHED = "COMPLETED_TARGET_ALREADY_MATCHED"
    PREDECESSOR_POSITION_ALREADY_SATISFIES_TARGET = (
        "PREDECESSOR_POSITION_ALREADY_SATISFIES_TARGET"
    )
    CLOSE_COMPLETION_BOUNDARY_MATCHED = "CLOSE_COMPLETION_BOUNDARY_MATCHED"
    CLOSE_COMPLETION_TARGET_ALREADY_SATISFIED = (
        "CLOSE_COMPLETION_TARGET_ALREADY_SATISFIED"
    )


@dataclass(frozen=True, slots=True)
class ExpectedPredecessorCompletionBinding:
    """Exact expected identity of the one completion lookup result."""

    canonical_completion_sha256: str
    plan_id: str
    plan_hash: str
    phase: str
    static_core_equal_sha256: str
    position_manager_sha256: str
    final_target_sha256: str
    target_position_hash: str
    terminal_target_id: str | None
    terminal_target_raw_sha256: str | None

    def validates(self) -> bool:
        hashes = (
            self.canonical_completion_sha256,
            self.plan_hash,
            self.static_core_equal_sha256,
            self.position_manager_sha256,
            self.final_target_sha256,
            self.target_position_hash,
        )
        terminal_pin_valid = (
            isinstance(self.terminal_target_id, str)
            and _STABLE_ID_RE.fullmatch(self.terminal_target_id) is not None
            and isinstance(self.terminal_target_raw_sha256, str)
            and _SHA_RE.fullmatch(self.terminal_target_raw_sha256) is not None
        )
        return bool(
            all(isinstance(value, str) and _SHA_RE.fullmatch(value) for value in hashes)
            and isinstance(self.plan_id, str)
            and _ID_RE.fullmatch(self.plan_id)
            and isinstance(self.phase, str)
            and self.phase in {"CLOSE", "OPEN"}
            and terminal_pin_valid
        )

    def matches(self, completion: Mapping[str, Any]) -> bool:
        lineage = completion["lineage"]
        return bool(
            self.validates()
            and sha256_json(dict(completion)) == self.canonical_completion_sha256
            and completion["plan_id"] == self.plan_id
            and completion["plan_hash"] == self.plan_hash
            and completion["phase"] == self.phase
            and lineage["static_core_equal_sha256"] == self.static_core_equal_sha256
            and lineage["position_manager_sha256"] == self.position_manager_sha256
            and lineage["final_target_sha256"] == self.final_target_sha256
            and completion["target_position_hash"] == self.target_position_hash
        )


@dataclass(frozen=True, slots=True)
class DesiredContinuousTargetBinding:
    """Exact source-event and independently replayed monthly target binding."""

    event_id: str
    source_event_raw: bytes
    source_event_raw_sha256: str
    selection_sha256: str
    final_target_raw: bytes
    final_target_sha256: str
    static_core_equal_sha256: str
    position_manager_sha256: str
    lineage_final_target_sha256: str


@dataclass(frozen=True, slots=True)
class _ValidatedDesiredTarget:
    positions: dict[str, Any]
    trigger_kind: str
    predecessor_terminal_target_id: str | None
    predecessor_terminal_target_raw_sha256: str | None


@dataclass(frozen=True, slots=True)
class FullAccountOwnershipClassification:
    disposition: FullAccountOwnershipDisposition
    reason_code: FullAccountOwnershipReason
    current_target_position_hash: str | None
    desired_target_position_hash: str | None
    predecessor_target_position_hash: str | None


def _result(
    disposition: FullAccountOwnershipDisposition,
    reason: FullAccountOwnershipReason,
    *,
    current: str | None = None,
    desired: str | None = None,
    predecessor: str | None = None,
) -> FullAccountOwnershipClassification:
    return FullAccountOwnershipClassification(
        disposition, reason, current, desired, predecessor
    )


def _detached_mapping(value: Any) -> dict[str, Any]:
    if isinstance(
        value, (ExecutionAccountFactsProjectionV2, ExecutionCompletionProjection)
    ):
        value = value.as_dict()
    if not isinstance(value, Mapping):
        raise TypeError("value must be an object")
    detached = json.loads(
        json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    )
    if not isinstance(detached, dict):  # pragma: no cover
        raise TypeError("value must be an object")
    return detached


def _canonical_line(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _parse_canonical_raw(value: Any) -> dict[str, Any]:
    if not isinstance(value, bytes) or not value or len(value) > _MAX_RAW_BYTES:
        raise ValueError("raw bytes are invalid")
    payload = json.loads(value.decode("utf-8"))
    if not isinstance(payload, dict) or _canonical_line(payload) != value:
        raise ValueError("raw bytes are not one canonical JSON line")
    return payload


def _require_sha(value: Any) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise ValueError("SHA-256 is invalid")
    return value


def _require_day(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("day is invalid")
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise ValueError("day is not canonical")
    return value


def _require_month(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 7:
        raise ValueError("month is invalid")
    if date.fromisoformat(f"{value}-01").strftime("%Y-%m") != value:
        raise ValueError("month is not canonical")
    return value


def _exact_contract(value: Any, *, product: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ValueError("exact contract is invalid")
    match = _CONTRACT_RE.fullmatch(value)
    if (
        match is None
        or match.group(1) != _EXPECTED_EXCHANGE[product]
        or match.group(2).lower() != product
        or not 1 <= int(match.group(3)[-2:]) <= 12
    ):
        raise ValueError("exact contract is outside frozen universe")
    return match.group(1), f"{match.group(2)}{match.group(3)}"


def _map_sha(values: Mapping[str, str]) -> str:
    return sha256_json(
        [
            {"product": product, "exact_contract": values[product]}
            for product in _PRODUCTS
        ]
    )


def _quantity_sha(values: Mapping[str, int]) -> str:
    return sha256_json(
        [
            {"product": product, "target_quantity": values[product]}
            for product in _PRODUCTS
        ]
    )


def _validate_final_target(raw: bytes) -> tuple[dict[str, Any], dict[str, Any], str]:
    payload = _parse_canonical_raw(raw)
    if (
        set(payload) != _FINAL_TARGET_FIELDS
        or payload["schema_version"]
        != "commodity_static_core_equal_final_target_projection_v1"
        or payload["strategy_id"] != "STATIC_CORE_EQUAL"
        or payload["baseline_scheduler_id"] != "STATIC_CORE_EQUAL"
        or payload["execution_lane"] != "simnow_shakedown"
        or payload["candidate_weights"] != {"C": 0.5, "D": 0.5}
        or payload["c_sleeve_id"] != "C_FAST_CROSS_SECTION_NEUTRAL"
        or payload["c_map_rule_id"] != "commodity_fast_tsmom_forward_freeze_v1"
        or payload["d_sleeve_id"] != "D_DONCHIAN20_EXIT10_NEUTRAL"
        or payload["sector_map_id"] != "COMMODITY_FROZEN_SECTOR_MAP_V1"
        or payload["position_manager_id"] != "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1"
        or any(
            payload[field] is not False
            for field in (
                "authority_granted",
                "dispatch_allowed",
                "production_allowed",
                "live_trading_authorized",
                "countable_forward",
            )
        )
    ):
        raise ValueError("final target identity is invalid")
    _require_month(payload["source_month"])
    _require_day(payload["execution_day"])
    rows = payload["targets"]
    if not isinstance(rows, list) or len(rows) != len(_PRODUCTS):
        raise ValueError("final target is not the frozen ten products")
    by_product: dict[str, Any] = {}
    for index, product in enumerate(_PRODUCTS):
        row = rows[index]
        if (
            not isinstance(row, dict)
            or set(row) != _FINAL_TARGET_ROW_FIELDS
            or row["product"] != product
            or row["sector"] != COMMODITY_FROZEN_SECTOR_MAP_V1[product]
        ):
            raise ValueError("final target products are incomplete or reordered")
        _exact_contract(row["exact_contract"], product=product)
        quantity = row["target_quantity"]
        if (
            isinstance(quantity, bool)
            or not isinstance(quantity, int)
            or abs(quantity) > 500
        ):
            raise ValueError("final target quantity is invalid")
        for field in ("reference_open_price", "multiplier", "price_tick"):
            number = row[field]
            if (
                isinstance(number, bool)
                or not isinstance(number, (int, float))
                or number <= 0
            ):
                raise ValueError("final target contract economics are invalid")
        by_product[product] = row
    return payload, by_product, sha256_json(payload)


def _desired_positions(
    binding: DesiredContinuousTargetBinding,
) -> _ValidatedDesiredTarget:
    if not isinstance(binding, DesiredContinuousTargetBinding):
        raise ValueError("desired target binding type is invalid")
    for value in (
        binding.source_event_raw_sha256,
        binding.selection_sha256,
        binding.final_target_sha256,
        binding.static_core_equal_sha256,
        binding.position_manager_sha256,
        binding.lineage_final_target_sha256,
    ):
        _require_sha(value)
    if (
        not isinstance(binding.event_id, str)
        or _ID_RE.fullmatch(binding.event_id) is None
    ):
        raise ValueError("desired event ID is invalid")
    if hashlib.sha256(binding.source_event_raw).hexdigest() != (
        binding.source_event_raw_sha256
    ):
        raise ValueError("desired source event raw hash mismatches")
    event = _parse_canonical_raw(binding.source_event_raw)
    candidate = event.get("candidate")
    false_fields = (
        "event_ready",
        "installable",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "official_forward_claimed",
        "dispatch_authorized",
        "order_authorized",
        "position_mutation_authorized",
    )
    authority = event.get("authority")
    if (
        set(event) != _EVENT_FIELDS
        or event["schema_version"] != "vnpy_continuous_event_candidate_v1"
        or event["event_id"] != binding.event_id
        or event["selection_sha256"] != binding.selection_sha256
        or event["selection_id"] != f"continuous-selection-{binding.selection_sha256}"
        or event["verification_status"]
        != "STRUCTURAL_ONLY_CURRENT_ROOT_AND_COMPLETION_PROOF_REQUIRED"
        or any(event[field] is not False for field in false_fields)
        or not isinstance(authority, dict)
        or set(authority) != _AUTHORITY_FIELDS
        or any(value is not False for value in authority.values())
        or event["event_id"]
        != f"continuous-event-{sha256_json({**event, 'event_id': ''})}"
        or not isinstance(candidate, dict)
        or set(candidate) != _CANDIDATE_FIELDS
    ):
        raise ValueError("desired source event identity is invalid")
    _require_sha(event["candidate_set_sha256"])
    if (
        candidate["candidate_id"]
        != f"continuous-candidate-{sha256_json({**candidate, 'candidate_id': ''})}"
        or candidate["trigger_kind"] not in {"MONTHLY_REBALANCE", "ROLL_ONLY"}
        or candidate["strategy_id"] != "STATIC_CORE_EQUAL"
        or candidate["execution_lane"] != "simnow_shakedown"
    ):
        raise ValueError("desired candidate identity is invalid")
    _require_month(candidate["source_month"])
    _require_day(candidate["execution_day"])
    if (
        not isinstance(candidate["verified_daily_artifact_id"], str)
        or _ID_RE.fullmatch(candidate["verified_daily_artifact_id"]) is None
        or candidate["verified_daily_continuity_mode"]
        not in {"GENESIS_STATIC_CORE_EQUAL", "LINKED_ROOT_CATALOG"}
        or candidate["roll_preserves_integer_lots"]
        is not (candidate["trigger_kind"] == "ROLL_ONLY")
    ):
        raise ValueError("desired candidate source binding is invalid")
    for field in (
        "verified_daily_artifact_raw_sha256",
        "static_core_equal_sha256",
        "position_manager_sha256",
        "monthly_final_target_sha256",
        "baseline_batch_raw_sha256",
        "quantity_vector_sha256",
        "monthly_target_exact_contract_map_sha256",
        "previous_exact_contract_map_sha256",
        "exact_contract_map_sha256",
    ):
        _require_sha(candidate[field])

    final_payload, final_rows, actual_final_sha = _validate_final_target(
        binding.final_target_raw
    )
    if (
        actual_final_sha != binding.final_target_sha256
        or binding.final_target_sha256 != binding.lineage_final_target_sha256
        or candidate["monthly_final_target_sha256"] != binding.final_target_sha256
        or candidate["static_core_equal_sha256"] != binding.static_core_equal_sha256
        or candidate["position_manager_sha256"] != binding.position_manager_sha256
    ):
        raise ValueError("desired final target lineage mismatches")
    final_execution_day = date.fromisoformat(final_payload["execution_day"])
    candidate_execution_day = date.fromisoformat(candidate["execution_day"])
    if (
        candidate["source_month"] != final_payload["source_month"]
        or final_execution_day >= candidate_execution_day
    ):
        raise ValueError("desired monthly target/daily routing date binding mismatches")

    target_rows = candidate["targets"]
    if not isinstance(target_rows, list) or len(target_rows) != len(_PRODUCTS):
        raise ValueError("desired daily-routed target is incomplete")
    monthly_map: dict[str, str] = {}
    previous_map: dict[str, str] = {}
    current_map: dict[str, str] = {}
    quantities: dict[str, int] = {}
    positions: dict[str, Any] = {}
    roll_only = candidate["trigger_kind"] == "ROLL_ONLY"
    changed_count = 0
    for index, product in enumerate(_PRODUCTS):
        row = target_rows[index]
        if (
            not isinstance(row, dict)
            or set(row) != _CANDIDATE_TARGET_FIELDS
            or row["product"] != product
            or isinstance(row["target_quantity"], bool)
            or not isinstance(row["target_quantity"], int)
            or abs(row["target_quantity"]) > 500
        ):
            raise ValueError("desired daily-routed target is invalid")
        monthly = row["monthly_target_exact_contract"]
        previous = row["previous_exact_contract"]
        current = row["exact_contract"]
        _exact_contract(monthly, product=product)
        _exact_contract(previous, product=product)
        exchange, symbol = _exact_contract(current, product=product)
        quantity = row["target_quantity"]
        if (
            final_rows[product]["target_quantity"] != quantity
            or final_rows[product]["exact_contract"] != monthly
            or row["exact_contract_changed"] is not (previous != current)
            or row["previous_target_quantity"] != (quantity if roll_only else None)
        ):
            raise ValueError("desired monthly/daily target cross-splice")
        monthly_map[product] = monthly
        previous_map[product] = previous
        current_map[product] = current
        quantities[product] = quantity
        changed_count += int(previous != current)
        if quantity:
            direction = "LONG" if quantity > 0 else "SHORT"
            positions[f"{symbol}.{exchange}.{direction}.CTP.continuous-target-v1"] = {
                "gateway_name": "CTP",
                "symbol": symbol,
                "exchange": exchange,
                "direction": direction,
                "volume": abs(quantity),
            }
    if (
        candidate["quantity_vector_sha256"] != _quantity_sha(quantities)
        or candidate["monthly_target_exact_contract_map_sha256"]
        != _map_sha(monthly_map)
        or candidate["previous_exact_contract_map_sha256"] != _map_sha(previous_map)
        or candidate["exact_contract_map_sha256"] != _map_sha(current_map)
    ):
        raise ValueError("desired target vector/map hashes do not close")
    predecessor_id = candidate["predecessor_terminal_target_id"]
    predecessor_sha = candidate["predecessor_terminal_target_raw_sha256"]
    if roll_only:
        if (
            candidate["verified_daily_continuity_mode"] != "LINKED_ROOT_CATALOG"
            or changed_count == 0
            or not isinstance(predecessor_id, str)
            or _STABLE_ID_RE.fullmatch(predecessor_id) is None
        ):
            raise ValueError("ROLL_ONLY predecessor/continuity binding is invalid")
        _require_sha(predecessor_sha)
    elif predecessor_id is not None or predecessor_sha is not None:
        raise ValueError("MONTHLY_REBALANCE carries a foreign predecessor")
    return _ValidatedDesiredTarget(
        positions=positions,
        trigger_kind=candidate["trigger_kind"],
        predecessor_terminal_target_id=predecessor_id,
        predecessor_terminal_target_raw_sha256=predecessor_sha,
    )


def _positions_in_frozen_universe(positions: Any) -> bool:
    if not isinstance(positions, Mapping):
        return False
    for key, row in positions.items():
        if not isinstance(key, str) or not isinstance(row, Mapping):
            return False
        volume = row.get("volume")
        if (
            row.get("gateway_name") != "CTP"
            or row.get("direction") not in {"LONG", "SHORT"}
            or isinstance(volume, bool)
            or not isinstance(volume, int)
            or volume < 0
            or not isinstance(row.get("symbol"), str)
            or not isinstance(row.get("exchange"), str)
        ):
            return False
        match = re.fullmatch(r"([A-Za-z]+)[0-9]{4}", row["symbol"])
        if match is None or (
            _EXPECTED_EXCHANGE.get(match.group(1).lower()) != row["exchange"].upper()
        ):
            return False
    return True


def _obvious_facts_failure(
    raw: Mapping[str, Any], *, now: datetime
) -> FullAccountOwnershipReason | None:
    if raw.get("schema_version") != "web_bridge_execution_account_facts_v2":
        return FullAccountOwnershipReason.ACCOUNT_FACTS_V2_REQUIRED
    status = raw.get("status_binding")
    if isinstance(status, Mapping):
        if status.get("lifecycle") != "READY":
            return FullAccountOwnershipReason.ACCOUNT_NOT_READY
        reconciliation = status.get("reconciliation")
        if isinstance(reconciliation, Mapping):
            if reconciliation.get("state") != "RECONCILED":
                return FullAccountOwnershipReason.ACCOUNT_NOT_RECONCILED
            if reconciliation.get("unknown_outcomes") != 0:
                return FullAccountOwnershipReason.ACCOUNT_UNKNOWN_OUTCOMES
    execution = raw.get("execution_binding")
    if isinstance(execution, Mapping):
        if execution.get("plan_state") not in {"IDLE", "TERMINAL"}:
            return FullAccountOwnershipReason.ACCOUNT_PLAN_NOT_TERMINAL
        if execution.get("nonterminal_send_intent_count") != 0:
            return FullAccountOwnershipReason.ACCOUNT_SEND_INTENTS_PENDING
    if raw.get("active_order_count") != 0 or raw.get("active_orders") != {}:
        return FullAccountOwnershipReason.ACCOUNT_ACTIVE_ORDERS
    observed_at = raw.get("observed_at")
    if isinstance(observed_at, str) and observed_at.endswith("Z"):
        try:
            observed = datetime.fromisoformat(observed_at[:-1] + "+00:00")
        except ValueError:
            return None
        age = (now - observed).total_seconds()
        if age > SNAPSHOT_STALE_SECONDS:
            return FullAccountOwnershipReason.ACCOUNT_FACTS_STALE
        if age < -FUTURE_SKEW_SECONDS:
            return FullAccountOwnershipReason.ACCOUNT_FACTS_FROM_FUTURE
    return None


def _completion_mapping(
    value: ExecutionCompletionProjection | Mapping[str, Any],
) -> dict[str, Any]:
    raw = _detached_mapping(value)
    return ExecutionCompletionProjection.from_mapping(raw).as_dict()


def classify_full_account_ownership(
    *,
    account_facts: ExecutionAccountFactsProjectionV2 | Mapping[str, Any],
    predecessor_mode: FullAccountPredecessorMode,
    expected_predecessor: ExpectedPredecessorCompletionBinding | None,
    completion: ExecutionCompletionProjection | Mapping[str, Any] | None,
    desired_target: DesiredContinuousTargetBinding,
    now: datetime,
) -> FullAccountOwnershipClassification:
    """Classify ownership only after one exact, planner-ready account read."""

    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timezone.utc.utcoffset(now)
    ):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.ACCOUNT_FACTS_INVALID,
        )
    try:
        raw_facts = _detached_mapping(account_facts)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.ACCOUNT_FACTS_INVALID,
        )
    facts_failure = _obvious_facts_failure(raw_facts, now=now)
    try:
        facts = ExecutionAccountFactsProjectionV2.from_mapping(raw_facts).as_dict()
    except (TypeError, ValueError, json.JSONDecodeError):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            facts_failure or FullAccountOwnershipReason.ACCOUNT_FACTS_INVALID,
        )
    if facts_failure is not None:
        return _result(FullAccountOwnershipDisposition.STOP, facts_failure)
    if facts["account_scope"] != _ACCOUNT_SCOPE or facts["environment"] != _ENVIRONMENT:
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.ACCOUNT_SCOPE_MISMATCH,
        )
    if not _positions_in_frozen_universe(facts["positions"]):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.ACCOUNT_POSITION_OUTSIDE_FROZEN_UNIVERSE,
        )
    current_hash: str | None = None
    try:
        current_hash = target_position_projection_hash(
            facts["positions"],
            account_scope=_ACCOUNT_SCOPE,
            environment=_ENVIRONMENT,
        )
        validated_desired = _desired_positions(desired_target)
        desired_hash = target_position_projection_hash(
            validated_desired.positions,
            account_scope=_ACCOUNT_SCOPE,
            environment=_ENVIRONMENT,
        )
        flat_hash = target_position_projection_hash(
            {}, account_scope=_ACCOUNT_SCOPE, environment=_ENVIRONMENT
        )
    except (
        CommodityExecutionContractError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.DESIRED_TARGET_BINDING_INVALID,
            current=current_hash,
        )

    if not isinstance(predecessor_mode, FullAccountPredecessorMode):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.PREDECESSOR_MODE_INVALID,
            current=current_hash,
            desired=desired_hash,
        )
    if predecessor_mode is FullAccountPredecessorMode.GENESIS_FLAT:
        if validated_desired.trigger_kind == "ROLL_ONLY":
            return _result(
                FullAccountOwnershipDisposition.STOP,
                FullAccountOwnershipReason.ROLL_ONLY_REQUIRES_COMPLETION,
                current=current_hash,
                desired=desired_hash,
            )
        if expected_predecessor is not None:
            return _result(
                FullAccountOwnershipDisposition.STOP,
                FullAccountOwnershipReason.EXPECTED_PREDECESSOR_INVALID,
                current=current_hash,
                desired=desired_hash,
            )
        if completion is not None:
            return _result(
                FullAccountOwnershipDisposition.STOP,
                FullAccountOwnershipReason.COMPLETION_UNEXPECTED_AT_GENESIS,
                current=current_hash,
                desired=desired_hash,
            )
        if current_hash != flat_hash:
            return _result(
                FullAccountOwnershipDisposition.STOP,
                FullAccountOwnershipReason.GENESIS_ACCOUNT_NOT_FLAT,
                current=current_hash,
                desired=desired_hash,
            )
        if desired_hash == flat_hash:
            return _result(
                FullAccountOwnershipDisposition.ALREADY_SATISFIED,
                FullAccountOwnershipReason.GENESIS_FLAT_ALREADY_SATISFIED,
                current=current_hash,
                desired=desired_hash,
            )
        return _result(
            FullAccountOwnershipDisposition.NEW_TARGET,
            FullAccountOwnershipReason.GENESIS_FLAT_NEW_TARGET,
            current=current_hash,
            desired=desired_hash,
        )

    if (
        not isinstance(expected_predecessor, ExpectedPredecessorCompletionBinding)
        or not expected_predecessor.validates()
    ):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.EXPECTED_PREDECESSOR_INVALID,
            current=current_hash,
            desired=desired_hash,
        )
    if validated_desired.trigger_kind == "ROLL_ONLY" and (
        expected_predecessor.terminal_target_id
        != validated_desired.predecessor_terminal_target_id
        or expected_predecessor.terminal_target_raw_sha256
        != validated_desired.predecessor_terminal_target_raw_sha256
    ):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.PREDECESSOR_TERMINAL_PIN_MISMATCH,
            current=current_hash,
            desired=desired_hash,
            predecessor=expected_predecessor.target_position_hash,
        )
    if completion is None:
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.COMPLETION_MISSING,
            current=current_hash,
            desired=desired_hash,
            predecessor=expected_predecessor.target_position_hash,
        )
    try:
        completed = _completion_mapping(completion)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.COMPLETION_INVALID,
            current=current_hash,
            desired=desired_hash,
            predecessor=expected_predecessor.target_position_hash,
        )
    if not expected_predecessor.matches(completed):
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.COMPLETION_BINDING_MISMATCH,
            current=current_hash,
            desired=desired_hash,
            predecessor=expected_predecessor.target_position_hash,
        )
    predecessor_hash = completed["target_position_hash"]
    if current_hash != predecessor_hash:
        return _result(
            FullAccountOwnershipDisposition.STOP,
            FullAccountOwnershipReason.COMPLETED_TARGET_POSITION_MISMATCH,
            current=current_hash,
            desired=desired_hash,
            predecessor=predecessor_hash,
        )
    completion_lineage = completed["lineage"]
    matches_desired_lineage = (
        completion_lineage["static_core_equal_sha256"]
        == desired_target.static_core_equal_sha256
        and completion_lineage["position_manager_sha256"]
        == desired_target.position_manager_sha256
        and completion_lineage["final_target_sha256"]
        == desired_target.lineage_final_target_sha256
    )
    if completed["phase"] == "CLOSE":
        if not matches_desired_lineage:
            return _result(
                FullAccountOwnershipDisposition.STOP,
                FullAccountOwnershipReason.CLOSE_COMPLETION_LINEAGE_MISMATCH,
                current=current_hash,
                desired=desired_hash,
                predecessor=predecessor_hash,
            )
        if current_hash == desired_hash:
            return _result(
                FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED,
                FullAccountOwnershipReason.CLOSE_COMPLETION_TARGET_ALREADY_SATISFIED,
                current=current_hash,
                desired=desired_hash,
                predecessor=predecessor_hash,
            )
        return _result(
            FullAccountOwnershipDisposition.RESUME_AFTER_CLOSE,
            FullAccountOwnershipReason.CLOSE_COMPLETION_BOUNDARY_MATCHED,
            current=current_hash,
            desired=desired_hash,
            predecessor=predecessor_hash,
        )
    if current_hash == desired_hash:
        if not matches_desired_lineage:
            return _result(
                FullAccountOwnershipDisposition.ALREADY_SATISFIED,
                FullAccountOwnershipReason.PREDECESSOR_POSITION_ALREADY_SATISFIES_TARGET,
                current=current_hash,
                desired=desired_hash,
                predecessor=predecessor_hash,
            )
        return _result(
            FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED,
            FullAccountOwnershipReason.COMPLETED_TARGET_ALREADY_MATCHED,
            current=current_hash,
            desired=desired_hash,
            predecessor=predecessor_hash,
        )
    return _result(
        FullAccountOwnershipDisposition.NEW_TARGET,
        FullAccountOwnershipReason.PREDECESSOR_TARGET_MATCHED,
        current=current_hash,
        desired=desired_hash,
        predecessor=predecessor_hash,
    )


__all__ = [
    "DesiredContinuousTargetBinding",
    "ExpectedPredecessorCompletionBinding",
    "FullAccountOwnershipClassification",
    "FullAccountOwnershipDisposition",
    "FullAccountOwnershipReason",
    "FullAccountPredecessorMode",
    "classify_full_account_ownership",
]
