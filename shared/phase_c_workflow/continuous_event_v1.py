"""Strict, authority-negative custody contract for one continuous SIMNOW event.

The contract deliberately carries verification *evidence*, not execution
authority.  Research does not import this module and this module performs no
I/O.  A Control-side verifier must first replay the Warehouse roots and read
fresh Execution facts; ArtifactCustody then independently checks that the
resulting immutable bundle is internally closed before it can be published.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Mapping

from shared.commodity_execution import target_position_projection_hash


CONTINUOUS_EVENT_SCHEMA_VERSION = "web-bridge-simnow-continuous-event-v1"
CONTINUOUS_EVENT_ARTIFACT_TYPE = "simnow-continuous-event"
CONTINUOUS_EVENT_TRUST_DOMAIN = "runtime_authorization"
CONTINUOUS_EVENT_SCOPE = {
    "account_scope": "account:windows",
    "environment": "SIMNOW",
    "execution_lane": "simnow_shakedown",
    "strategy_id": "STATIC_CORE_EQUAL",
}
STRUCTURAL_EVENT_SCHEMA_VERSION = "vnpy_continuous_event_candidate_v1"
STRUCTURAL_SELECTION_SCHEMA_VERSION = "vnpy_continuous_event_selection_v1"
FINAL_TARGET_SCHEMA_VERSION = "commodity_static_core_equal_final_target_projection_v1"
PRECEDENCE_RULE_ID = "MONTHLY_OVER_SAME_DAY_ROLL_V1"
VERIFICATION_STATUS = "STRUCTURAL_ONLY_CURRENT_ROOT_AND_COMPLETION_PROOF_REQUIRED"
MAX_RAW_BYTES = 4 * 1024 * 1024
SNAPSHOT_STALE_SECONDS = 60
FUTURE_SKEW_SECONDS = 2

PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
SECTORS = {
    "ag": "precious",
    "al": "nonferrous",
    "au": "precious",
    "bu": "energy_chemical",
    "cu": "nonferrous",
    "rb": "ferrous",
    "ru": "energy_chemical",
    "sc": "energy",
    "sp": "light_industry",
    "zn": "nonferrous",
}
EXCHANGES = {product: ("INE" if product == "sc" else "SHFE") for product in PRODUCTS}

_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,191}$")
_STRUCTURAL_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_CONTRACT = re.compile(r"^(CFFEX|CZCE|DCE|GFEX|INE|SHFE)\.([A-Za-z]+)([0-9]{4})$")
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
_FALSE_TOP_LEVEL = (
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
    "official_forward_claimed",
    "target_plan_authorized",
    "dispatch_authorized",
    "order_authorized",
    "position_mutation_authorized",
)
_STRUCTURAL_FALSE_TOP_LEVEL = (
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
    "official_forward_claimed",
    "dispatch_authorized",
    "order_authorized",
    "position_mutation_authorized",
)


class ContinuousEventContractError(ValueError):
    """The continuous event cannot be admitted to create-only custody."""


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContinuousEventContractError("event value is not canonical JSON") from exc


def canonical_json_line(value: Any) -> bytes:
    return canonical_json(value) + b"\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _object(
    value: Any, fields: set[str] | frozenset[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ContinuousEventContractError(f"{label} fields are not exact")
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ContinuousEventContractError(f"{label} is not a SHA-256")
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ContinuousEventContractError(f"{label} is invalid")
    return value


def _structural_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _STRUCTURAL_ID.fullmatch(value) is None:
        raise ContinuousEventContractError(f"{label} is invalid")
    return value


def _day(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ContinuousEventContractError(f"{label} is invalid")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ContinuousEventContractError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise ContinuousEventContractError(f"{label} is not canonical")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContinuousEventContractError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ContinuousEventContractError(f"{label} is invalid") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ContinuousEventContractError(f"{label} is not UTC")
    return parsed


def _raw(value: Any, label: str) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(value, str):
        raise ContinuousEventContractError(f"{label} raw value is invalid")
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > MAX_RAW_BYTES:
        raise ContinuousEventContractError(f"{label} resource limit exceeded")
    try:
        decoded = json.loads(encoded)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ContinuousEventContractError(f"{label} is invalid JSON") from exc
    if not isinstance(decoded, dict) or canonical_json_line(decoded) != encoded:
        raise ContinuousEventContractError(f"{label} is not one canonical JSON line")
    return encoded, decoded


def _false_authority(value: Any, label: str) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != _AUTHORITY_FIELDS
        or any(flag is not False for flag in value.values())
    ):
        raise ContinuousEventContractError(f"{label} attempts to grant authority")


def _contract(value: Any, *, product: str) -> str:
    if not isinstance(value, str):
        raise ContinuousEventContractError("exact contract is invalid")
    match = _CONTRACT.fullmatch(value)
    if (
        match is None
        or match.group(1) != EXCHANGES[product]
        or match.group(2) != product
        or not 1 <= int(match.group(3)[-2:]) <= 12
    ):
        raise ContinuousEventContractError("exact contract is outside frozen universe")
    return value


def _quantity_sha(values: Mapping[str, int]) -> str:
    return sha256_json(
        [
            {"product": product, "target_quantity": values[product]}
            for product in PRODUCTS
        ]
    )


def _map_sha(values: Mapping[str, str]) -> str:
    return sha256_json(
        [
            {"product": product, "exact_contract": values[product]}
            for product in PRODUCTS
        ]
    )


def _candidate_id(value: Mapping[str, Any]) -> str:
    return "continuous-candidate-" + sha256_json({**value, "candidate_id": ""})


def _event_id(value: Mapping[str, Any]) -> str:
    return "continuous-event-" + sha256_json({**value, "event_id": ""})


_CANDIDATE_FIELDS = {
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
_CANDIDATE_TARGET_FIELDS = {
    "product",
    "monthly_target_exact_contract",
    "previous_exact_contract",
    "exact_contract",
    "previous_target_quantity",
    "target_quantity",
    "exact_contract_changed",
}


def _validate_candidate(value: Any) -> dict[str, Any]:
    candidate = _object(value, _CANDIDATE_FIELDS, "candidate")
    trigger = candidate["trigger_kind"]
    if (
        trigger not in {"MONTHLY_REBALANCE", "ROLL_ONLY"}
        or candidate["strategy_id"] != "STATIC_CORE_EQUAL"
        or candidate["execution_lane"] != "simnow_shakedown"
        or candidate["verified_daily_continuity_mode"]
        not in {"GENESIS_STATIC_CORE_EQUAL", "LINKED_ROOT_CATALOG"}
        or candidate["candidate_id"] != _candidate_id(candidate)
    ):
        raise ContinuousEventContractError("candidate identity mismatch")
    _structural_id(candidate["candidate_id"], "candidate ID")
    _structural_id(candidate["verified_daily_artifact_id"], "daily artifact ID")
    _day(candidate["execution_day"], "candidate execution day")
    source_month = candidate["source_month"]
    if (
        not isinstance(source_month, str)
        or len(source_month) != 7
        or date.fromisoformat(f"{source_month}-01").strftime("%Y-%m") != source_month
    ):
        raise ContinuousEventContractError("candidate source month is invalid")
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
        _sha(candidate[field], f"candidate {field}")
    rows = candidate["targets"]
    if not isinstance(rows, list) or len(rows) != len(PRODUCTS):
        raise ContinuousEventContractError("candidate target set is incomplete")
    quantities: dict[str, int] = {}
    monthly: dict[str, str] = {}
    previous: dict[str, str] = {}
    current: dict[str, str] = {}
    changed = 0
    roll = trigger == "ROLL_ONLY"
    for index, product in enumerate(PRODUCTS):
        row = _object(rows[index], _CANDIDATE_TARGET_FIELDS, "candidate target")
        if row["product"] != product:
            raise ContinuousEventContractError("candidate products are reordered")
        monthly[product] = _contract(
            row["monthly_target_exact_contract"], product=product
        )
        previous[product] = _contract(row["previous_exact_contract"], product=product)
        current[product] = _contract(row["exact_contract"], product=product)
        quantity = row["target_quantity"]
        if (
            isinstance(quantity, bool)
            or not isinstance(quantity, int)
            or abs(quantity) > 500
        ):
            raise ContinuousEventContractError("candidate quantity is invalid")
        quantities[product] = quantity
        is_changed = previous[product] != current[product]
        if row["exact_contract_changed"] is not is_changed:
            raise ContinuousEventContractError("candidate changed flag mismatches")
        changed += int(is_changed)
        if (roll and row["previous_target_quantity"] != quantity) or (
            not roll and row["previous_target_quantity"] is not None
        ):
            raise ContinuousEventContractError(
                "candidate quantity continuity is invalid"
            )
    if (
        candidate["quantity_vector_sha256"] != _quantity_sha(quantities)
        or candidate["monthly_target_exact_contract_map_sha256"] != _map_sha(monthly)
        or candidate["previous_exact_contract_map_sha256"] != _map_sha(previous)
        or candidate["exact_contract_map_sha256"] != _map_sha(current)
    ):
        raise ContinuousEventContractError("candidate vector/map hashes do not close")
    if roll:
        if (
            not changed
            or candidate["verified_daily_continuity_mode"] != "LINKED_ROOT_CATALOG"
            or candidate["roll_preserves_integer_lots"] is not True
        ):
            raise ContinuousEventContractError("ROLL_ONLY continuity is invalid")
        _structural_id(
            candidate["predecessor_terminal_target_id"], "terminal target ID"
        )
        _sha(candidate["predecessor_terminal_target_raw_sha256"], "terminal target raw")
    elif (
        candidate["roll_preserves_integer_lots"] is not False
        or candidate["predecessor_terminal_target_id"] is not None
        or candidate["predecessor_terminal_target_raw_sha256"] is not None
    ):
        raise ContinuousEventContractError("MONTHLY_REBALANCE carries ROLL pins")
    return candidate


_SELECTION_FIELDS = {
    "schema_version",
    "selection_id",
    "selection_sha256",
    "strategy_id",
    "execution_lane",
    "execution_day",
    "precedence_rule_id",
    "verified_daily_artifact_id",
    "verified_daily_artifact_raw_sha256",
    "candidate_set_sha256",
    "candidate_ids",
    "observed_trigger_kinds",
    "selected_candidate_id",
    "selected_trigger_kind",
    "suppressed_trigger_kinds",
    "monthly_precedence_applied",
    "candidates",
    "event_candidate_id",
    "event_candidate_raw_sha256",
    "verification_status",
    "event_ready",
    "installable",
    *_STRUCTURAL_FALSE_TOP_LEVEL,
    "authority",
}
_STRUCTURAL_EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "selection_id",
    "selection_sha256",
    "candidate_set_sha256",
    "candidate",
    "verification_status",
    "event_ready",
    "installable",
    *_STRUCTURAL_FALSE_TOP_LEVEL,
    "authority",
}


def _validate_structural_pair(
    selection_raw: bytes,
    selection: dict[str, Any],
    event_raw: bytes,
    event: dict[str, Any],
) -> dict[str, Any]:
    selection = _object(selection, _SELECTION_FIELDS, "structural selection")
    if (
        selection["schema_version"] != STRUCTURAL_SELECTION_SCHEMA_VERSION
        or selection["strategy_id"] != "STATIC_CORE_EQUAL"
        or selection["execution_lane"] != "simnow_shakedown"
        or selection["precedence_rule_id"] != PRECEDENCE_RULE_ID
        or selection["verification_status"] != VERIFICATION_STATUS
        or selection["event_ready"] is not False
        or selection["installable"] is not False
        or any(selection[field] is not False for field in _STRUCTURAL_FALSE_TOP_LEVEL)
    ):
        raise ContinuousEventContractError("structural selection boundary is invalid")
    _false_authority(selection["authority"], "structural selection")
    _structural_id(selection["selection_id"], "selection ID")
    _structural_id(selection["verified_daily_artifact_id"], "selection daily ID")
    _structural_id(selection["event_candidate_id"], "selected event candidate ID")
    candidates = selection["candidates"]
    if not isinstance(candidates, list) or len(candidates) != 1:
        raise ContinuousEventContractError("selection must contain one candidate")
    candidate = _validate_candidate(candidates[0])
    _day(selection["execution_day"], "selection execution day")
    candidate_set_sha = sha256_json(candidates)
    candidate_ids = [candidate["candidate_id"]]
    same_day_roll = any(row["exact_contract_changed"] for row in candidate["targets"])
    if candidate["trigger_kind"] == "MONTHLY_REBALANCE":
        observed = (
            ["MONTHLY_REBALANCE", "ROLL_ONLY"]
            if same_day_roll
            else ["MONTHLY_REBALANCE"]
        )
        suppressed = ["ROLL_ONLY"] if same_day_roll else []
        precedence = same_day_roll
    else:
        observed, suppressed, precedence = ["ROLL_ONLY"], [], False
    core = {
        "strategy_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "execution_day": selection["execution_day"],
        "precedence_rule_id": PRECEDENCE_RULE_ID,
        "verified_daily_artifact_id": selection["verified_daily_artifact_id"],
        "verified_daily_artifact_raw_sha256": selection[
            "verified_daily_artifact_raw_sha256"
        ],
        "candidate_set_sha256": candidate_set_sha,
        "candidate_ids": candidate_ids,
        "observed_trigger_kinds": observed,
        "selected_candidate_id": candidate["candidate_id"],
        "selected_trigger_kind": candidate["trigger_kind"],
        "suppressed_trigger_kinds": suppressed,
        "monthly_precedence_applied": precedence,
    }
    selection_sha = sha256_json(core)
    if (
        selection["selection_sha256"] != selection_sha
        or selection["selection_id"] != f"continuous-selection-{selection_sha}"
        or selection["candidate_set_sha256"] != candidate_set_sha
        or selection["candidate_ids"] != candidate_ids
        or selection["execution_day"] != candidate["execution_day"]
        or selection["selected_candidate_id"] != candidate["candidate_id"]
        or selection["selected_trigger_kind"] != candidate["trigger_kind"]
        or selection["observed_trigger_kinds"] != observed
        or selection["suppressed_trigger_kinds"] != suppressed
        or selection["monthly_precedence_applied"] is not precedence
        or selection["verified_daily_artifact_id"]
        != candidate["verified_daily_artifact_id"]
        or selection["verified_daily_artifact_raw_sha256"]
        != candidate["verified_daily_artifact_raw_sha256"]
    ):
        raise ContinuousEventContractError("selection identity does not close")

    event = _object(event, _STRUCTURAL_EVENT_FIELDS, "structural event")
    if (
        event["schema_version"] != STRUCTURAL_EVENT_SCHEMA_VERSION
        or event["verification_status"] != VERIFICATION_STATUS
        or event["event_ready"] is not False
        or event["installable"] is not False
        or any(event[field] is not False for field in _STRUCTURAL_FALSE_TOP_LEVEL)
        or event["event_id"] != _event_id(event)
        or event["selection_id"] != selection["selection_id"]
        or event["selection_sha256"] != selection_sha
        or event["candidate_set_sha256"] != candidate_set_sha
        or event["candidate"] != candidate
        or selection["event_candidate_id"] != event["event_id"]
        or selection["event_candidate_raw_sha256"] != sha256_bytes(event_raw)
    ):
        raise ContinuousEventContractError("structural event/selection splice")
    _false_authority(event["authority"], "structural event")
    _structural_id(event["event_id"], "event ID")
    _structural_id(event["selection_id"], "event selection ID")
    if (
        canonical_json_line(selection) != selection_raw
        or canonical_json_line(event) != event_raw
    ):
        raise ContinuousEventContractError("structural raw bytes changed")
    return candidate


_FINAL_TARGET_FIELDS = {
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
_FINAL_TARGET_ROW_FIELDS = {
    "product",
    "sector",
    "exact_contract",
    "target_quantity",
    "reference_open_price",
    "multiplier",
    "price_tick",
}


def _validate_final_target(value: str) -> tuple[bytes, dict[str, Any], str, str, str]:
    raw, payload = _raw(value, "monthly final target")
    payload = _object(payload, _FINAL_TARGET_FIELDS, "monthly final target")
    if (
        payload["schema_version"] != FINAL_TARGET_SCHEMA_VERSION
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
        raise ContinuousEventContractError("monthly final target identity is invalid")
    _day(payload["execution_day"], "monthly final target execution day")
    rows = payload["targets"]
    if not isinstance(rows, list) or len(rows) != len(PRODUCTS):
        raise ContinuousEventContractError("monthly final target is incomplete")
    quantities: dict[str, int] = {}
    contracts: dict[str, str] = {}
    for index, product in enumerate(PRODUCTS):
        row = _object(rows[index], _FINAL_TARGET_ROW_FIELDS, "monthly target row")
        if row["product"] != product or row["sector"] != SECTORS[product]:
            raise ContinuousEventContractError("monthly target products are reordered")
        contracts[product] = _contract(row["exact_contract"], product=product)
        quantity = row["target_quantity"]
        if (
            isinstance(quantity, bool)
            or not isinstance(quantity, int)
            or abs(quantity) > 500
        ):
            raise ContinuousEventContractError("monthly target quantity is invalid")
        quantities[product] = quantity
        for field in ("reference_open_price", "multiplier", "price_tick"):
            number = row[field]
            if (
                isinstance(number, bool)
                or not isinstance(number, (int, float))
                or number <= 0
            ):
                raise ContinuousEventContractError(
                    "monthly contract economics are invalid"
                )
    return (
        raw,
        payload,
        sha256_json(payload),
        _quantity_sha(quantities),
        _map_sha(contracts),
    )


_MONTHLY_FIELDS = {
    "final_target_raw",
    "final_target_raw_sha256",
    "final_target_sha256",
    "static_core_equal_sha256",
    "position_manager_sha256",
    "baseline_batch_raw_sha256",
    "source_month",
    "execution_day",
    "quantity_vector_sha256",
    "monthly_exact_contract_map_sha256",
}
_DAILY_FIELDS = {
    "artifact_id",
    "artifact_raw_sha256",
    "official_day",
    "execution_day",
    "continuity_mode",
    "previous_exact_contract_map_sha256",
    "exact_contract_map_sha256",
    "catalog_receipt_raw_sha256",
    "catalog_artifact_raw_sha256",
    "operator_state_raw_sha256",
    "operator_manifest_sequence",
    "manifest_genesis_seal_sha256",
    "manifest_head_seal_sha256",
    "manifest_head_commit_seal_sha256",
    "commit_anchor_ledger_raw_sha256",
    "catalog_last_trade_day",
}
_DESIRED_FIELDS = {
    "target_position_hash",
    "quantity_vector_sha256",
    "exact_contract_map_sha256",
}
_FACTS_FIELDS = {
    "account_facts_raw",
    "account_facts_raw_sha256",
    "snapshot_id",
    "account_facts_sha256",
    "observed_at",
    "state_version",
    "position_snapshot_hash",
    "current_target_position_hash",
    "active_order_count",
    "active_orders_sha256",
    "lifecycle",
    "reconciliation_state",
    "unknown_outcomes",
    "plan_state",
    "nonterminal_send_intent_count",
}
_PREDECESSOR_FIELDS = {
    "mode",
    "completion_raw",
    "completion_raw_sha256",
    "completion_plan_id",
    "completion_plan_hash",
    "completion_phase",
    "completion_target_position_hash",
    "terminal_target_id",
    "terminal_target_raw_sha256",
    "static_core_equal_sha256",
    "position_manager_sha256",
    "final_target_sha256",
}

_EXECUTION_ACCOUNT_FACT_FIELDS = {
    "schema_version",
    "service",
    "service_version",
    "account_scope",
    "environment",
    "snapshot_id",
    "generation",
    "observed_at",
    "connected",
    "fresh",
    "position_snapshot_hash",
    "positions",
    "active_order_count",
    "active_orders_sha256",
    "active_orders",
    "status_binding",
    "execution_binding",
    "account_facts_sha256",
}
_STATUS_BINDING_FIELDS = {
    "status_schema_version",
    "state_version",
    "status_observed_at",
    "lifecycle",
    "reconciliation",
    "broker",
    "durable_active_orders_sha256",
    "durable_positions_sha256",
    "snapshot_identity_mode",
}
_RECONCILIATION_FIELDS = {
    "state",
    "run_id",
    "last_completed_at",
    "unknown_outcomes",
    "fresh_snapshot_id",
}
_BROKER_FIELDS = {
    "connected",
    "generation",
    "active_order_count",
    "position_snapshot_hash",
    "last_snapshot_at",
}
_EXECUTION_BINDING_FIELDS = {
    "state_version",
    "plan_state",
    "send_intents",
    "send_intents_sha256",
    "nonterminal_send_intent_count",
}
_SEND_INTENT_REQUIRED_FIELDS = {
    "intent_id",
    "idempotency_key",
    "state",
    "plan_id",
    "plan_hash",
    "leader_epoch",
    "fencing_token",
    "created_at",
}
_SEND_INTENT_OPTIONAL_FIELDS = {
    "action",
    "request_hash",
    "target_intent_id",
    "receipt_id",
    "receipt_hash",
    "broker_order_id",
    "unknown_reason",
}
_TERMINAL_SEND_INTENT_STATES = {"RECONCILED", "CANCELLED", "TERMINAL"}
_COMPLETION_FIELDS = {
    "plan_id",
    "plan_hash",
    "schema_version",
    "phase",
    "lineage",
    "expected_after_position_hash",
    "target_position_hash",
    "archived_at",
}
_COMPLETION_LINEAGE_FIELDS = {
    "static_core_equal_sha256",
    "position_manager_sha256",
    "final_target_sha256",
}
_PAYLOAD_FIELDS = {
    "schema_version",
    "event_id",
    "source_event_raw",
    "source_event_raw_sha256",
    "selection_id",
    "selection_sha256",
    "selection_raw",
    "selection_raw_sha256",
    "candidate_id",
    "trigger_kind",
    "strategy_id",
    "execution_lane",
    "precedence_rule_id",
    "monthly_precedence_applied",
    "verified_at",
    "monthly",
    "daily",
    "desired_target",
    "account_facts",
    "predecessor",
    "event_ready",
    "installable",
    *_FALSE_TOP_LEVEL,
    "authority",
}


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContinuousEventContractError(f"{label} is invalid")
    return value


def _execution_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_Z.fullmatch(value) is None:
        raise ContinuousEventContractError(f"{label} is invalid")
    return _utc(value, label)


def _execution_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _EXECUTION_ID.fullmatch(value) is None:
        raise ContinuousEventContractError(f"{label} is invalid")
    return value


def _candidate_target_positions(candidate: Mapping[str, Any]) -> dict[str, Any]:
    positions: dict[str, Any] = {}
    for row in candidate["targets"]:
        quantity = row["target_quantity"]
        if quantity == 0:
            continue
        exchange, symbol = row["exact_contract"].split(".", 1)
        direction = "LONG" if quantity > 0 else "SHORT"
        positions[f"{symbol}.{exchange}.{direction}.CTP.continuous-target-v1"] = {
            "gateway_name": "CTP",
            "symbol": symbol,
            "exchange": exchange,
            "direction": direction,
            "volume": abs(quantity),
        }
    return positions


def _validate_fact_positions(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContinuousEventContractError("execution position facts are invalid")
    positions = json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    for key, row in positions.items():
        if not isinstance(key, str) or not isinstance(row, Mapping):
            raise ContinuousEventContractError("execution position facts are invalid")
        volume = row.get("volume")
        symbol = row.get("symbol")
        exchange = row.get("exchange")
        match = re.fullmatch(r"([A-Za-z]+)[0-9]{4}", str(symbol))
        if (
            row.get("gateway_name") != "CTP"
            or row.get("direction") not in {"LONG", "SHORT"}
            or isinstance(volume, bool)
            or not isinstance(volume, int)
            or volume < 0
            or not isinstance(exchange, str)
            or match is None
            or EXCHANGES.get(match.group(1).lower()) != exchange.upper()
        ):
            raise ContinuousEventContractError(
                "execution position facts are outside frozen universe"
            )
    return positions


def _validate_execution_account_facts_v2(
    value: str,
) -> tuple[bytes, dict[str, Any], str]:
    raw, facts = _raw(value, "Execution account facts v2")
    facts = _object(facts, _EXECUTION_ACCOUNT_FACT_FIELDS, "Execution account facts v2")
    if (
        facts["schema_version"] != "web_bridge_execution_account_facts_v2"
        or facts["service"] != "execution-orchestrator"
        or not isinstance(facts["service_version"], str)
        or not facts["service_version"]
        or facts["account_scope"] != "account:windows"
        or facts["environment"] != "SIMNOW"
        or facts["connected"] is not True
        or facts["fresh"] is not True
    ):
        raise ContinuousEventContractError(
            "Execution account facts identity is invalid"
        )
    _execution_identifier(facts["snapshot_id"], "Execution snapshot ID")
    _nonnegative_int(facts["generation"], "Execution generation")
    observed_at = _execution_utc(facts["observed_at"], "Execution observed_at")
    for field in (
        "position_snapshot_hash",
        "active_orders_sha256",
        "account_facts_sha256",
    ):
        _sha(facts[field], f"Execution account facts {field}")
    positions = _validate_fact_positions(facts["positions"])
    orders = facts["active_orders"]
    if not isinstance(orders, Mapping) or any(
        not isinstance(key, str) or not isinstance(row, Mapping)
        for key, row in orders.items()
    ):
        raise ContinuousEventContractError("Execution active-order facts are invalid")
    _nonnegative_int(facts["active_order_count"], "Execution active-order count")
    if (
        facts["active_order_count"] != len(orders)
        or facts["position_snapshot_hash"] != sha256_json(positions)
        or facts["active_orders_sha256"] != sha256_json(dict(orders))
    ):
        raise ContinuousEventContractError("Execution account fact hashes do not close")

    status = _object(
        facts["status_binding"], _STATUS_BINDING_FIELDS, "Execution status"
    )
    if (
        status["status_schema_version"] != "web_bridge_execution_status_v1"
        or not isinstance(status["lifecycle"], str)
        or not status["lifecycle"]
        or status["snapshot_identity_mode"]
        not in {"EXACT", "GENERATION_FACT_HASH_EQUIVALENT"}
    ):
        raise ContinuousEventContractError("Execution status identity is invalid")
    _nonnegative_int(status["state_version"], "Execution state version")
    _execution_utc(status["status_observed_at"], "Execution status observed_at")
    _sha(status["durable_active_orders_sha256"], "durable active-order hash")
    _sha(status["durable_positions_sha256"], "durable position hash")
    reconciliation = _object(
        status["reconciliation"], _RECONCILIATION_FIELDS, "Execution reconciliation"
    )
    broker = _object(status["broker"], _BROKER_FIELDS, "Execution broker")
    for field in ("state", "run_id", "fresh_snapshot_id"):
        if not isinstance(reconciliation[field], str):
            raise ContinuousEventContractError("Execution reconciliation is invalid")
    _execution_utc(
        reconciliation["last_completed_at"], "Execution reconciliation completed_at"
    )
    _nonnegative_int(reconciliation["unknown_outcomes"], "Execution unknown outcomes")
    if not isinstance(broker["connected"], bool):
        raise ContinuousEventContractError("Execution broker connected is invalid")
    _nonnegative_int(broker["generation"], "Execution broker generation")
    _nonnegative_int(broker["active_order_count"], "Execution broker order count")
    _sha(broker["position_snapshot_hash"], "Execution broker position hash")
    durable_observed_at = _execution_utc(
        broker["last_snapshot_at"], "Execution broker observed_at"
    )
    stable_id = facts["snapshot_id"].startswith("snapshot-peek-")
    if stable_id:
        _sha(
            facts["snapshot_id"].removeprefix("snapshot-peek-"),
            "Execution stable snapshot hash",
        )
    if (
        reconciliation["state"] != "RECONCILED"
        or reconciliation["unknown_outcomes"] != 0
        or broker["connected"] is not True
        or broker["generation"] != facts["generation"]
        or broker["position_snapshot_hash"] != facts["position_snapshot_hash"]
        or status["durable_positions_sha256"] != facts["position_snapshot_hash"]
        or broker["active_order_count"] != facts["active_order_count"]
        or status["durable_active_orders_sha256"] != facts["active_orders_sha256"]
        or status["snapshot_identity_mode"]
        != ("EXACT" if stable_id else "GENERATION_FACT_HASH_EQUIVALENT")
        or (stable_id and reconciliation["fresh_snapshot_id"] != facts["snapshot_id"])
        or durable_observed_at > observed_at
    ):
        raise ContinuousEventContractError(
            "Execution account facts are not bound to durable status"
        )

    execution = _object(
        facts["execution_binding"], _EXECUTION_BINDING_FIELDS, "Execution binding"
    )
    _nonnegative_int(execution["state_version"], "Execution binding state version")
    _nonnegative_int(
        execution["nonterminal_send_intent_count"],
        "Execution nonterminal intent count",
    )
    _sha(execution["send_intents_sha256"], "Execution send-intent hash")
    intents = execution["send_intents"]
    if not isinstance(intents, Mapping) or any(
        not isinstance(intent_id, str)
        or not isinstance(row, Mapping)
        or not _SEND_INTENT_REQUIRED_FIELDS.issubset(row)
        or not set(row).issubset(
            _SEND_INTENT_REQUIRED_FIELDS | _SEND_INTENT_OPTIONAL_FIELDS
        )
        or row.get("intent_id") != intent_id
        or not isinstance(row.get("state"), str)
        or not isinstance(row.get("idempotency_key"), str)
        or not row.get("idempotency_key")
        or _EXECUTION_ID.fullmatch(str(row.get("plan_id"))) is None
        or _SHA.fullmatch(str(row.get("plan_hash"))) is None
        or any(
            isinstance(row.get(field), bool)
            or not isinstance(row.get(field), int)
            or row[field] < 1
            for field in ("leader_epoch", "fencing_token")
        )
        or _UTC_Z.fullmatch(str(row.get("created_at"))) is None
        for intent_id, row in intents.items()
    ):
        raise ContinuousEventContractError("Execution send intents are invalid")
    nonterminal_count = sum(
        row["state"] not in _TERMINAL_SEND_INTENT_STATES for row in intents.values()
    )
    if (
        execution["state_version"] != status["state_version"]
        or execution["plan_state"] not in {"IDLE", "TERMINAL"}
        or execution["send_intents_sha256"] != sha256_json(dict(intents))
        or execution["nonterminal_send_intent_count"] != nonterminal_count
        or nonterminal_count != 0
        or status["lifecycle"] != "READY"
        or facts["active_order_count"] != 0
        or facts["active_orders"] != {}
    ):
        raise ContinuousEventContractError("Execution account facts are not ready")
    preimage = {key: facts[key] for key in facts if key != "account_facts_sha256"}
    if facts["account_facts_sha256"] != sha256_json(preimage):
        raise ContinuousEventContractError(
            "Execution account facts hash does not close"
        )
    return (
        raw,
        facts,
        target_position_projection_hash(
            positions, account_scope="account:windows", environment="SIMNOW"
        ),
    )


def _validate_completion(value: str) -> tuple[bytes, dict[str, Any]]:
    raw, completion = _raw(value, "Execution completion")
    completion = _object(completion, _COMPLETION_FIELDS, "Execution completion")
    if completion[
        "schema_version"
    ] != "web-bridge-simnow-keyless-target-plan-v2" or completion["phase"] not in {
        "CLOSE",
        "OPEN",
    }:
        raise ContinuousEventContractError("Execution completion identity is invalid")
    _execution_identifier(completion["plan_id"], "Execution completion plan ID")
    for field in (
        "plan_hash",
        "expected_after_position_hash",
        "target_position_hash",
    ):
        _sha(completion[field], f"Execution completion {field}")
    lineage = _object(
        completion["lineage"],
        _COMPLETION_LINEAGE_FIELDS,
        "Execution completion lineage",
    )
    for field in _COMPLETION_LINEAGE_FIELDS:
        _sha(lineage[field], f"Execution completion lineage {field}")
    _execution_utc(completion["archived_at"], "Execution completion archived_at")
    if completion["target_position_hash"] != completion["expected_after_position_hash"]:
        raise ContinuousEventContractError("Execution completion target does not close")
    return raw, completion


def validate_simnow_continuous_event_v1(value: Any) -> dict[str, Any]:
    """Return a detached, internally closed continuous event payload."""

    payload = _object(value, _PAYLOAD_FIELDS, "continuous event")
    if (
        payload["schema_version"] != CONTINUOUS_EVENT_SCHEMA_VERSION
        or payload["strategy_id"] != "STATIC_CORE_EQUAL"
        or payload["execution_lane"] != "simnow_shakedown"
        or payload["precedence_rule_id"] != PRECEDENCE_RULE_ID
        or payload["event_ready"] is not True
        or payload["installable"] is not True
        or any(payload[field] is not False for field in _FALSE_TOP_LEVEL)
    ):
        raise ContinuousEventContractError("continuous event boundary is invalid")
    _false_authority(payload["authority"], "continuous event")

    selection_raw, selection = _raw(payload["selection_raw"], "structural selection")
    event_raw, event = _raw(payload["source_event_raw"], "structural event")
    candidate = _validate_structural_pair(selection_raw, selection, event_raw, event)
    if (
        payload["event_id"] != event["event_id"]
        or payload["source_event_raw_sha256"] != sha256_bytes(event_raw)
        or payload["selection_id"] != selection["selection_id"]
        or payload["selection_sha256"] != selection["selection_sha256"]
        or payload["selection_raw_sha256"] != sha256_bytes(selection_raw)
        or payload["candidate_id"] != candidate["candidate_id"]
        or payload["trigger_kind"] != candidate["trigger_kind"]
        or payload["monthly_precedence_applied"]
        is not selection["monthly_precedence_applied"]
    ):
        raise ContinuousEventContractError("continuous event source binding mismatches")

    monthly = _object(payload["monthly"], _MONTHLY_FIELDS, "monthly proof")
    final_raw, final, final_sha, quantity_sha, monthly_map_sha = _validate_final_target(
        monthly["final_target_raw"]
    )
    for field in (
        "final_target_raw_sha256",
        "final_target_sha256",
        "static_core_equal_sha256",
        "position_manager_sha256",
        "baseline_batch_raw_sha256",
        "quantity_vector_sha256",
        "monthly_exact_contract_map_sha256",
    ):
        _sha(monthly[field], f"monthly {field}")
    if (
        monthly["final_target_raw_sha256"] != sha256_bytes(final_raw)
        or monthly["final_target_sha256"] != final_sha
        or monthly["source_month"] != final["source_month"]
        or monthly["execution_day"] != final["execution_day"]
        or monthly["quantity_vector_sha256"] != quantity_sha
        or monthly["monthly_exact_contract_map_sha256"] != monthly_map_sha
        or candidate["source_month"] != monthly["source_month"]
        or candidate["static_core_equal_sha256"] != monthly["static_core_equal_sha256"]
        or candidate["position_manager_sha256"] != monthly["position_manager_sha256"]
        or candidate["monthly_final_target_sha256"] != final_sha
        or candidate["baseline_batch_raw_sha256"]
        != monthly["baseline_batch_raw_sha256"]
        or candidate["quantity_vector_sha256"] != quantity_sha
        or candidate["monthly_target_exact_contract_map_sha256"] != monthly_map_sha
    ):
        raise ContinuousEventContractError(
            "monthly replay/candidate binding mismatches"
        )

    daily = _object(payload["daily"], _DAILY_FIELDS, "daily proof")
    for field in (
        "artifact_raw_sha256",
        "previous_exact_contract_map_sha256",
        "exact_contract_map_sha256",
        "catalog_receipt_raw_sha256",
        "catalog_artifact_raw_sha256",
        "operator_state_raw_sha256",
        "manifest_genesis_seal_sha256",
        "manifest_head_seal_sha256",
        "manifest_head_commit_seal_sha256",
        "commit_anchor_ledger_raw_sha256",
    ):
        _sha(daily[field], f"daily {field}")
    if (
        isinstance(daily["operator_manifest_sequence"], bool)
        or not isinstance(daily["operator_manifest_sequence"], int)
        or daily["operator_manifest_sequence"] < 1
        or daily["artifact_id"] != candidate["verified_daily_artifact_id"]
        or daily["artifact_raw_sha256"]
        != candidate["verified_daily_artifact_raw_sha256"]
        or daily["execution_day"] != candidate["execution_day"]
        or daily["continuity_mode"] != candidate["verified_daily_continuity_mode"]
        or daily["previous_exact_contract_map_sha256"]
        != candidate["previous_exact_contract_map_sha256"]
        or daily["exact_contract_map_sha256"] != candidate["exact_contract_map_sha256"]
    ):
        raise ContinuousEventContractError("daily/catalog binding mismatches")
    _structural_id(daily["artifact_id"], "daily artifact ID")
    official_day = _day(daily["official_day"], "daily official day")
    execution_day = _day(daily["execution_day"], "daily execution day")
    _day(daily["catalog_last_trade_day"], "catalog last trade day")
    if monthly["execution_day"] != official_day or not official_day < execution_day:
        raise ContinuousEventContractError(
            "monthly/daily official execution-day ordering mismatches"
        )

    desired = _object(payload["desired_target"], _DESIRED_FIELDS, "desired target")
    for field in _DESIRED_FIELDS:
        _sha(desired[field], f"desired target {field}")
    desired_position_hash = target_position_projection_hash(
        _candidate_target_positions(candidate),
        account_scope="account:windows",
        environment="SIMNOW",
    )
    if (
        desired["target_position_hash"] != desired_position_hash
        or desired["quantity_vector_sha256"] != candidate["quantity_vector_sha256"]
        or desired["exact_contract_map_sha256"]
        != candidate["exact_contract_map_sha256"]
    ):
        raise ContinuousEventContractError("desired target vector/map splice")

    facts = _object(payload["account_facts"], _FACTS_FIELDS, "account facts")
    facts_raw, execution_facts, current_position_hash = (
        _validate_execution_account_facts_v2(facts["account_facts_raw"])
    )
    for field in (
        "account_facts_raw_sha256",
        "account_facts_sha256",
        "position_snapshot_hash",
        "current_target_position_hash",
        "active_orders_sha256",
    ):
        _sha(facts[field], f"account facts {field}")
    _id(facts["snapshot_id"], "account facts snapshot ID")
    verified_at = _utc(payload["verified_at"], "event verified_at")
    observed_at = _utc(facts["observed_at"], "account facts observed_at")
    age = (verified_at - observed_at).total_seconds()
    if (
        facts["account_facts_raw_sha256"] != sha256_bytes(facts_raw)
        or facts["snapshot_id"] != execution_facts["snapshot_id"]
        or facts["account_facts_sha256"] != execution_facts["account_facts_sha256"]
        or facts["observed_at"] != execution_facts["observed_at"]
        or facts["state_version"]
        != execution_facts["execution_binding"]["state_version"]
        or facts["position_snapshot_hash"] != execution_facts["position_snapshot_hash"]
        or facts["current_target_position_hash"] != current_position_hash
        or facts["active_order_count"] != execution_facts["active_order_count"]
        or facts["active_orders_sha256"] != execution_facts["active_orders_sha256"]
        or facts["lifecycle"] != execution_facts["status_binding"]["lifecycle"]
        or facts["reconciliation_state"]
        != execution_facts["status_binding"]["reconciliation"]["state"]
        or facts["unknown_outcomes"]
        != execution_facts["status_binding"]["reconciliation"]["unknown_outcomes"]
        or facts["plan_state"] != execution_facts["execution_binding"]["plan_state"]
        or facts["nonterminal_send_intent_count"]
        != execution_facts["execution_binding"]["nonterminal_send_intent_count"]
        or age > SNAPSHOT_STALE_SECONDS
        or age < -FUTURE_SKEW_SECONDS
        or isinstance(facts["state_version"], bool)
        or not isinstance(facts["state_version"], int)
        or facts["state_version"] < 0
        or facts["active_order_count"] != 0
        or facts["active_orders_sha256"] != sha256_json({})
        or facts["lifecycle"] != "READY"
        or facts["reconciliation_state"] != "RECONCILED"
        or facts["unknown_outcomes"] != 0
        or facts["plan_state"] not in {"IDLE", "TERMINAL"}
        or facts["nonterminal_send_intent_count"] != 0
    ):
        raise ContinuousEventContractError("account facts are not fresh and quiescent")

    predecessor = _object(payload["predecessor"], _PREDECESSOR_FIELDS, "predecessor")
    mode = predecessor["mode"]
    nullable = tuple(field for field in _PREDECESSOR_FIELDS if field != "mode")
    if mode == "GENESIS_FLAT":
        if (
            payload["trigger_kind"] != "MONTHLY_REBALANCE"
            or any(predecessor[field] is not None for field in nullable)
            or facts["current_target_position_hash"]
            != target_position_projection_hash(
                {}, account_scope="account:windows", environment="SIMNOW"
            )
        ):
            raise ContinuousEventContractError("Genesis predecessor is invalid")
    elif mode == "COMPLETION":
        if any(predecessor[field] is None for field in nullable):
            raise ContinuousEventContractError("completion predecessor is incomplete")
        completion_raw, completion = _validate_completion(predecessor["completion_raw"])
        for field in (
            "completion_raw_sha256",
            "completion_plan_hash",
            "completion_target_position_hash",
            "terminal_target_raw_sha256",
            "static_core_equal_sha256",
            "position_manager_sha256",
            "final_target_sha256",
        ):
            _sha(predecessor[field], f"predecessor {field}")
        _id(predecessor["completion_plan_id"], "predecessor completion plan ID")
        _structural_id(
            predecessor["terminal_target_id"], "predecessor terminal target ID"
        )
        completion_lineage = completion["lineage"]
        if (
            predecessor["completion_raw_sha256"] != sha256_bytes(completion_raw)
            or predecessor["completion_plan_id"] != completion["plan_id"]
            or predecessor["completion_plan_hash"] != completion["plan_hash"]
            or predecessor["completion_phase"] != completion["phase"]
            or predecessor["completion_target_position_hash"]
            != completion["target_position_hash"]
            or predecessor["completion_target_position_hash"]
            != facts["current_target_position_hash"]
            or predecessor["static_core_equal_sha256"]
            != completion_lineage["static_core_equal_sha256"]
            or predecessor["position_manager_sha256"]
            != completion_lineage["position_manager_sha256"]
            or predecessor["final_target_sha256"]
            != completion_lineage["final_target_sha256"]
            or (
                completion["phase"] == "CLOSE"
                and completion["target_position_hash"] != desired_position_hash
            )
        ):
            raise ContinuousEventContractError("predecessor is not terminal/current")
    else:
        raise ContinuousEventContractError("predecessor mode is invalid")
    if (
        mode == "COMPLETION"
        and predecessor["completion_phase"] == "CLOSE"
        and (
            predecessor["static_core_equal_sha256"]
            != monthly["static_core_equal_sha256"]
            or predecessor["position_manager_sha256"]
            != monthly["position_manager_sha256"]
            or predecessor["final_target_sha256"] != monthly["final_target_sha256"]
        )
    ):
        raise ContinuousEventContractError(
            "predecessor lineage/root binding mismatches"
        )
    if payload["trigger_kind"] == "ROLL_ONLY":
        if (
            mode != "COMPLETION"
            or predecessor["terminal_target_id"]
            != candidate["predecessor_terminal_target_id"]
            or predecessor["terminal_target_raw_sha256"]
            != candidate["predecessor_terminal_target_raw_sha256"]
            or predecessor["static_core_equal_sha256"]
            != monthly["static_core_equal_sha256"]
            or predecessor["position_manager_sha256"]
            != monthly["position_manager_sha256"]
            or predecessor["final_target_sha256"] != monthly["final_target_sha256"]
        ):
            raise ContinuousEventContractError(
                "ROLL_ONLY predecessor binding mismatches"
            )
    return payload


__all__ = [
    "CONTINUOUS_EVENT_ARTIFACT_TYPE",
    "CONTINUOUS_EVENT_SCHEMA_VERSION",
    "CONTINUOUS_EVENT_SCOPE",
    "CONTINUOUS_EVENT_TRUST_DOMAIN",
    "ContinuousEventContractError",
    "canonical_json",
    "canonical_json_line",
    "sha256_bytes",
    "sha256_json",
    "validate_simnow_continuous_event_v1",
]
