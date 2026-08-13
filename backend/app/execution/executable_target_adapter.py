"""Offline MAP/C_FAST to TargetPlan v1 adapter.

This module deliberately has no RPC, gateway client, signer, custody writer,
or Execution lifecycle dependency.  A caller must hand it a fresh, already
read-only ``GatewaySnapshot`` and a reconciled Execution state.  Its output is
an immutable TargetPlan plus the existing artifact-envelope input which an
offline signing ceremony may sign and install through custody.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from shared.artifact_contracts.v1 import (
    ContractError as ArtifactContractError,
)
from shared.artifact_contracts.v1 import (
    new_artifact_envelope,
    validate_artifact_envelope,
)
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    TARGET_PLAN_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    CommodityExecutionContractError,
    VerifiedCustodyReceipt,
    before_position_projection_hash,
    build_target_plan,
    build_trusted_keyless_target_plan,
    canonical_before_position_projection,
    canonical_target_position_projection,
    sha256_json,
    target_position_projection_hash,
)
from shared.commodity_execution.v1 import canonical_json, utc_now

from .gateway_contracts import GatewaySnapshot


class ExecutableTargetAdapterError(ValueError):
    """The offline inputs cannot safely produce a one-lot TargetPlan."""


_EXACT_CONTRACT = re.compile(r"^(CFFEX|CZCE|DCE|GFEX|INE|SHFE)\.([A-Za-z]+[0-9]{4})$")
_CLOSE_ORDER_OFFSETS = frozenset({"CLOSE", "CLOSETODAY", "CLOSEYESTERDAY"})
_CLOSE_OFFSET_EXCHANGES = frozenset({"INE", "SHFE"})
_FALSE_AUTHORITY_FIELDS = frozenset(
    {
        "control_authorized",
        "deployment_authorized",
        "execution_authorized",
        "simnow_execution_authorized",
        "runtime_activation_authorized",
        "network_authorized",
        "web_bridge_rpc_authorized",
        "order_authorized",
        "order_submission_authorized",
        "position_mutation_authorized",
        "dispatch_authorized",
        "trading_authorized",
        "production_authorized",
        "automatic_promotion_authorized",
        "production_allowed",
        "live_allowed",
        "countable_forward",
        "authority_granted",
        "signing_requested",
        "custody_published",
    }
)
_AUTHORITY_SUFFIX = "_authorized"
_AUTHORITY_LIKE_FIELDS = (
    "production_allowed",
    "live_allowed",
    "countable_forward",
    "authority_granted",
    "execution_authorized",
    "simnow_execution_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "signing_requested",
    "custody_published",
)


@dataclass(frozen=True, slots=True)
class ExecutableTargetPlanHandoff:
    """A plan and the immutable envelope material for existing offline signing.

    TargetPlan v1 intentionally has no free-form lineage fields.  Lineage is
    retained in the existing artifact envelope, while its scope and expiry are
    also retained in the strict TargetPlan fields consumed by Execution.
    """

    target_plan: dict[str, Any]
    lineage: tuple[str, str]
    scope: dict[str, Any]
    expires_at: str

    def artifact_envelope(
        self, *, generated_at: str, authority_artifact: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Build an unsigned envelope for the existing offline signer/custody path."""

        predecessor_ref, custody_lineage = _authority_custody_closure(
            authority_artifact,
            artifact_id=str(self.target_plan["authority_artifact_id"]),
            artifact_raw_sha256=str(self.target_plan["authority_artifact_sha256"]),
            scope=self.scope,
        )

        return new_artifact_envelope(
            artifact_type="simnow-target-plan",
            trust_domain="runtime_authorization",
            producer_id="c-fast-executable-target-adapter",
            producer_version="v1",
            schema_ref=TARGET_PLAN_SCHEMA_VERSION,
            payload=self.target_plan,
            generated_at=generated_at,
            scope=self.scope,
            predecessor_refs=[predecessor_ref],
            lineage=list(custody_lineage),
        )

    def trusted_keyless_custody_artifact(self) -> dict[str, Any]:
        """Return the exact unsigned, create-only custody artifact.

        MAP/C_FAST lineage remains inside the immutable TargetPlan.  It is not
        projected into ArtifactCustody's predecessor graph because this mode
        never publishes the candidates as custody artifacts.
        """

        if self.target_plan.get("schema_version") != KEYLESS_TARGET_PLAN_SCHEMA_VERSION:
            raise ExecutableTargetAdapterError("target plan is not trusted keyless")
        return new_artifact_envelope(
            artifact_type="simnow-target-plan",
            trust_domain="runtime_authorization",
            producer_id="c-fast-executable-target-adapter",
            producer_version="v1",
            schema_ref=KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
            payload=self.target_plan,
            generated_at=str(self.target_plan["generated_at"]),
            scope=self.scope,
            predecessor_refs=[],
            lineage=[],
        )


@dataclass(frozen=True, slots=True)
class PeekCurrentFacts:
    """Strict local conversion of the validation-only Windows peek result."""

    snapshot: GatewaySnapshot
    gateway_name: str


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutableTargetAdapterError(f"{label} must be an object")
    try:
        detached = json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ExecutableTargetAdapterError(f"{label} is not canonical JSON") from exc
    if not isinstance(detached, dict):  # pragma: no cover - JSON object round trip
        raise ExecutableTargetAdapterError(f"{label} must be an object")
    return detached


def _require_false_authority(payload: Mapping[str, Any], label: str) -> None:
    fields = {
        key
        for key in payload
        if isinstance(key, str)
        and (key.endswith(_AUTHORITY_SUFFIX) or key in _AUTHORITY_LIKE_FIELDS)
    }
    if fields != _FALSE_AUTHORITY_FIELDS:
        raise ExecutableTargetAdapterError(
            f"{label} authority field set is incomplete or has extra fields"
        )
    if any(payload[field] is not False for field in _FALSE_AUTHORITY_FIELDS):
        raise ExecutableTargetAdapterError(f"{label} attempts to grant authority")


def _authority_custody_closure(
    value: Mapping[str, Any],
    *,
    artifact_id: str,
    artifact_raw_sha256: str,
    scope: Mapping[str, Any],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Bind the output to the already-custodied authority artifact only."""

    try:
        artifact = validate_artifact_envelope(value)
    except ArtifactContractError as exc:
        raise ExecutableTargetAdapterError(
            "authority artifact envelope is invalid"
        ) from exc
    if (
        artifact["artifact_id"] != artifact_id
        or artifact["raw_sha256"] != artifact_raw_sha256
        or artifact["artifact_type"] != "runtime-authorization"
        or artifact["trust_domain"] != "runtime_authorization"
        or artifact["schema_ref"] != "phase-c-runtime-authorization-v1"
        or artifact["scope"] != dict(scope)
    ):
        raise ExecutableTargetAdapterError(
            "authority artifact does not match custody receipt/scope"
        )
    canonical_sha256 = str(artifact["canonical_sha256"])
    return (
        {
            "artifact_id": str(artifact["artifact_id"]),
            "canonical_sha256": canonical_sha256,
        },
        tuple(sorted({canonical_sha256, *artifact["lineage"]})),
    )


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ExecutableTargetAdapterError(f"{label} is not a SHA-256")
    return value


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExecutableTargetAdapterError(f"{label} is invalid")
    return value.strip()


def _contract(value: Any) -> tuple[str, str]:
    contract = _require_text(value, "C_FAST exact_contract")
    match = _EXACT_CONTRACT.fullmatch(contract)
    if match is None:
        raise ExecutableTargetAdapterError("C_FAST exact_contract is invalid")
    # vn.py's CTP contract registry is keyed by the native symbol spelling
    # carried in exact_contract (for example, ``ru2609``), not an uppercased
    # equivalent.  Keep that spelling for the outbound TargetPlan order.
    return match.group(1), match.group(2)


def _validate_lineage(
    map_candidate: Mapping[str, Any], c_fast_candidate: Mapping[str, Any]
) -> tuple[str, str]:
    map_payload = _mapping(map_candidate, "MAP candidate")
    c_fast_payload = _mapping(c_fast_candidate, "C_FAST candidate")
    if (
        map_payload.get("schema_version") != "commodity_map_signal_candidate_v1"
        or map_payload.get("artifact_role") != "unsigned_map_signal_candidate"
        or map_payload.get("status") != "UNSIGNED_MAP_SIGNAL_CANDIDATE"
        or c_fast_payload.get("schema_version")
        != "commodity_c_fast_target_candidate_v1"
        or c_fast_payload.get("artifact_role") != "unsigned_c_fast_target_candidate"
        or c_fast_payload.get("status") != "UNSIGNED_C_FAST_TARGET_CANDIDATE"
    ):
        raise ExecutableTargetAdapterError("MAP/C_FAST candidate roles are invalid")
    _require_false_authority(map_payload, "MAP candidate")
    _require_false_authority(c_fast_payload, "C_FAST candidate")
    map_hash = sha256_json(map_payload)
    c_fast_hash = sha256_json(c_fast_payload)
    predecessor = c_fast_payload.get("predecessor")
    lineage = c_fast_payload.get("lineage")
    map_lineage = map_payload.get("lineage")
    if (
        not isinstance(predecessor, Mapping)
        or not isinstance(lineage, Mapping)
        or not isinstance(map_lineage, Mapping)
    ):
        raise ExecutableTargetAdapterError("C_FAST predecessor/lineage is invalid")
    if (
        predecessor.get("artifact_sha256") != map_hash
        or predecessor.get("candidate_id") != map_payload.get("candidate_id")
        or lineage.get("map_predecessor_sha256") != map_hash
        or lineage.get("map_candidate_id") != map_payload.get("candidate_id")
        or lineage.get("source_view_canonical_sha256")
        != map_lineage.get("source_view_canonical_sha256")
        or lineage.get("source_receipt_sha256")
        != map_lineage.get("source_receipt_sha256")
    ):
        raise ExecutableTargetAdapterError("C_FAST lineage does not bind MAP")
    _sha(map_hash, "MAP canonical hash")
    _sha(c_fast_hash, "C_FAST canonical hash")
    return map_hash, c_fast_hash


def _selected_target(
    candidate: Mapping[str, Any], *, product: str
) -> tuple[dict[str, Any], str, str, float]:
    targets = candidate.get("targets")
    if not isinstance(targets, list):
        raise ExecutableTargetAdapterError("C_FAST targets are invalid")
    rows = [
        row
        for row in targets
        if isinstance(row, Mapping) and row.get("product") == product
    ]
    if len(rows) != 1:
        raise ExecutableTargetAdapterError("selected C_FAST product is not unique")
    row = _mapping(rows[0], "selected C_FAST target")
    target_quantity = row.get("target_quantity")
    if isinstance(target_quantity, bool) or not isinstance(target_quantity, int):
        raise ExecutableTargetAdapterError("C_FAST target quantity is invalid")
    exchange, symbol = _contract(row.get("exact_contract"))
    price = row.get("reference_open_price")
    if isinstance(price, bool) or not isinstance(price, (int, float)):
        raise ExecutableTargetAdapterError("C_FAST reference price is invalid")
    normalized_price = float(price)
    if not math.isfinite(normalized_price) or normalized_price <= 0:
        raise ExecutableTargetAdapterError("C_FAST reference price is invalid")
    return row, exchange, symbol, normalized_price


def _reduce_only_limit_price(value: Any, *, price_tick: Any) -> float:
    """Validate one operator-supplied close price against signed C_FAST tick size."""

    def decimal(value: Any, label: str) -> Decimal:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ExecutableTargetAdapterError(f"{label} is invalid")
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise ExecutableTargetAdapterError(f"{label} is invalid") from exc
        if not parsed.is_finite() or parsed <= 0:
            raise ExecutableTargetAdapterError(f"{label} is invalid")
        return parsed

    limit_price = decimal(value, "reduce-only close limit price")
    tick = decimal(price_tick, "C_FAST price tick")
    if limit_price % tick != 0:
        raise ExecutableTargetAdapterError(
            "reduce-only close limit price is not aligned to C_FAST price tick"
        )
    return float(limit_price)


def _validate_snapshot(
    snapshot: GatewaySnapshot,
    *,
    account_scope: str,
    environment: str,
    reconciliation: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(snapshot, GatewaySnapshot):
        raise ExecutableTargetAdapterError("current facts must be a GatewaySnapshot")
    if (
        not snapshot.connected
        or not snapshot.fresh
        or snapshot.account_scope != account_scope
        or snapshot.environment != environment
    ):
        raise ExecutableTargetAdapterError("current facts scope/freshness is invalid")
    if snapshot.active_order_count != 0 or snapshot.orders:
        raise ExecutableTargetAdapterError("active orders block target adaptation")
    if (
        reconciliation.get("state") != "RECONCILED"
        or reconciliation.get("unknown_outcomes") != 0
    ):
        raise ExecutableTargetAdapterError(
            "unknown or unreconciled outcomes block target adaptation"
        )
    positions = _mapping(snapshot.positions, "current positions")
    full_hash = sha256_json(positions)
    if snapshot.position_snapshot_hash != full_hash:
        raise ExecutableTargetAdapterError("current facts full position hash mismatch")
    try:
        canonical_target_position_projection(
            positions, account_scope=account_scope, environment=environment
        )
        canonical_before_position_projection(
            positions, account_scope=account_scope, environment=environment
        )
    except CommodityExecutionContractError as exc:
        raise ExecutableTargetAdapterError(
            f"current position semantics are invalid: {exc}"
        ) from exc
    return positions


def peek_current_facts_to_snapshot(
    value: Mapping[str, Any],
    *,
    account_scope: str,
) -> PeekCurrentFacts:
    """Convert one exact ``peek_current_facts_v1`` result without any RPC call.

    The final Windows bridge reports ``simnow`` while TargetPlan v1 and
    Execution use ``SIMNOW``.  This is the only deliberate normalization.
    Any active or historical Windows execution order blocks adaptation.
    """

    facts = _mapping(value, "peek current facts")
    required = {
        "schema_version",
        "position_query_complete",
        "account",
        "positions",
        "active_orders",
        "gateway",
        "execution",
        "admission",
    }
    if (
        set(facts) != required
        or facts["schema_version"] != "windows_execution_current_facts_v1"
        or facts["position_query_complete"] is not True
    ):
        raise ExecutableTargetAdapterError("peek current facts schema is invalid")
    for field in ("account", "positions", "active_orders"):
        if not isinstance(facts[field], Mapping) or any(
            not isinstance(key, str) or not isinstance(row, Mapping)
            for key, row in facts[field].items()
        ):
            raise ExecutableTargetAdapterError(f"peek {field} facts are invalid")
    account = facts["account"]
    if not account:
        raise ExecutableTargetAdapterError("peek account facts are empty")
    gateway = facts["gateway"]
    if not isinstance(gateway, Mapping) or set(gateway) != {
        "gateway_name",
        "account_scope",
        "environment",
        "connected",
    }:
        raise ExecutableTargetAdapterError("peek gateway facts are invalid")
    gateway_name = _require_text(gateway.get("gateway_name"), "peek gateway name")
    if (
        gateway_name != "CTP"
        or gateway.get("account_scope") != account_scope
        or gateway.get("environment") != "simnow"
        or gateway.get("connected") is not True
        or gateway["connected"] != bool(account)
    ):
        raise ExecutableTargetAdapterError("peek gateway binding is invalid")
    execution = facts["execution"]
    if (
        not isinstance(execution, Mapping)
        or set(execution) != {"orders"}
        or not isinstance(execution["orders"], Mapping)
    ):
        raise ExecutableTargetAdapterError("peek execution facts are invalid")
    if facts["active_orders"]:
        raise ExecutableTargetAdapterError(
            "peek active or execution orders block adaptation"
        )
    if execution["orders"]:
        raise ExecutableTargetAdapterError(
            "peek active or execution orders block adaptation"
        )
    admission = facts["admission"]
    admission_fields = {
        "account_scope",
        "environment",
        "durable_state_version",
        "durable_state_hash",
        "snapshot_generation",
        "fence",
        "receipt_intents",
    }
    if not isinstance(admission, Mapping) or set(admission) != admission_fields:
        raise ExecutableTargetAdapterError("peek admission facts are invalid")
    if (
        admission.get("account_scope") != account_scope
        or admission.get("environment") != "simnow"
        or isinstance(admission.get("durable_state_version"), bool)
        or not isinstance(admission.get("durable_state_version"), int)
        or admission["durable_state_version"] < 0
        or isinstance(admission.get("snapshot_generation"), bool)
        or not isinstance(admission.get("snapshot_generation"), int)
        or admission["snapshot_generation"] < 0
    ):
        raise ExecutableTargetAdapterError("peek admission scope is invalid")
    _sha(admission.get("durable_state_hash"), "peek durable state hash")
    fence = admission.get("fence")
    if not isinstance(fence, Mapping) or set(fence) != {
        "active",
        "current_epoch",
        "current_fencing_token",
        "high_water_epoch",
        "high_water_fencing_token",
    }:
        raise ExecutableTargetAdapterError("peek fence is invalid")
    if not isinstance(fence.get("active"), bool) or any(
        isinstance(fence.get(field), bool)
        or not isinstance(fence.get(field), int)
        or fence[field] < 0
        for field in (
            "current_epoch",
            "current_fencing_token",
            "high_water_epoch",
            "high_water_fencing_token",
        )
    ):
        raise ExecutableTargetAdapterError("peek fence is invalid")
    intents = admission.get("receipt_intents")
    if (
        not isinstance(intents, list)
        or any(not isinstance(item, str) for item in intents)
        or intents != sorted(set(intents))
    ):
        raise ExecutableTargetAdapterError("peek receipt intents are invalid")
    raw_hash = sha256_json(facts)
    positions = _mapping(facts["positions"], "peek positions")
    return PeekCurrentFacts(
        snapshot=GatewaySnapshot(
            snapshot_id=f"snapshot-peek-{raw_hash}",
            generation=admission["snapshot_generation"],
            connected=gateway["connected"],
            active_order_count=0,
            position_snapshot_hash=sha256_json(positions),
            orders={},
            positions=positions,
            account_scope=account_scope,
            environment="SIMNOW",
            fresh=True,
        ),
        gateway_name=gateway_name,
    )


def _current_contract_positions(
    positions: Mapping[str, Any], *, exchange: str, symbol: str, gateway_name: str
) -> tuple[int, int, list[tuple[str, dict[str, Any]]]]:
    long_volume = 0
    short_volume = 0
    matching: list[tuple[str, dict[str, Any]]] = []
    for key, raw in positions.items():
        if not isinstance(key, str) or not isinstance(raw, Mapping):
            raise ExecutableTargetAdapterError("current position row is invalid")
        row = _mapping(raw, "current position row")
        volume = row.get("volume")
        if isinstance(volume, bool) or not isinstance(volume, int) or volume < 0:
            raise ExecutableTargetAdapterError("current position volume is invalid")
        if (
            str(row.get("symbol", "")).upper() != symbol.upper()
            or str(row.get("exchange", "")).upper() != exchange
        ):
            continue
        if str(row.get("gateway_name", "")).upper() != gateway_name.upper():
            raise ExecutableTargetAdapterError("current position gateway mismatch")
        direction = str(row.get("direction", "")).upper()
        if direction not in {"LONG", "SHORT"}:
            raise ExecutableTargetAdapterError("current position direction is invalid")
        matching.append((key, row))
        if direction == "LONG":
            long_volume += volume
        else:
            short_volume += volume
    return long_volume, short_volume, matching


def _after_positions(
    positions: Mapping[str, Any],
    matching: list[tuple[str, dict[str, Any]]],
    *,
    exchange: str,
    symbol: str,
    gateway_name: str,
    direction: str,
    offset: str,
) -> dict[str, Any]:
    result = _mapping(positions, "current positions")
    if offset in _CLOSE_ORDER_OFFSETS:
        closing_direction = "SHORT" if direction == "LONG" else "LONG"
        candidates = sorted(
            (
                item
                for item in matching
                if item[1]["direction"].upper() == closing_direction
                and item[1]["volume"] > 0
            ),
            key=lambda item: item[0],
        )
        if not candidates:
            raise ExecutableTargetAdapterError(
                "close direction has no current position"
            )
        key, row = candidates[0]
        row["volume"] -= 1
        result[key] = row
        return result
    candidates = sorted(
        (item for item in matching if item[1]["direction"].upper() == direction),
        key=lambda item: item[0],
    )
    if candidates:
        key, row = candidates[0]
        row["volume"] += 1
        result[key] = row
        return result
    key = f"{symbol}.{exchange}.{direction}.{gateway_name}.target-v1"
    if key in result:
        raise ExecutableTargetAdapterError("new target position key collides")
    result[key] = {
        "gateway_name": gateway_name,
        "symbol": symbol,
        "exchange": exchange,
        "direction": direction,
        "volume": 1,
    }
    return result


def _close_order_offset(
    matching: list[tuple[str, dict[str, Any]]], *, exchange: str, direction: str
) -> str:
    """Choose an exact one-lot close offset from authoritative position facts."""

    if exchange not in _CLOSE_OFFSET_EXCHANGES:
        return "CLOSE"
    closing_direction = "SHORT" if direction == "LONG" else "LONG"
    candidates = [
        row
        for _key, row in matching
        if row["direction"].upper() == closing_direction and row["volume"] > 0
    ]
    if not candidates:
        raise ExecutableTargetAdapterError("close direction has no current position")
    volume = 0
    yd_volume = 0
    for row in candidates:
        raw_yd_volume = row.get("yd_volume")
        if (
            isinstance(raw_yd_volume, bool)
            or not isinstance(raw_yd_volume, int)
            or raw_yd_volume < 0
            or raw_yd_volume > row["volume"]
        ):
            raise ExecutableTargetAdapterError(
                "SHFE/INE current position yd_volume is missing or inconsistent"
            )
        volume += row["volume"]
        yd_volume += raw_yd_volume
    if volume - yd_volume >= 1:
        return "CLOSETODAY"
    if yd_volume >= 1:
        return "CLOSEYESTERDAY"
    raise ExecutableTargetAdapterError(
        "SHFE/INE current position yd_volume is missing or inconsistent"
    )


def _require_single_reduce_only_position(
    positions: Mapping[str, Any],
    matching: list[tuple[str, dict[str, Any]]],
    *,
    long_volume: int,
    short_volume: int,
) -> None:
    """Prove that a close can only remove the one peeked C_FAST position."""

    if len(positions) != 1 or len(matching) != 1:
        raise ExecutableTargetAdapterError(
            "reduce-only close requires exactly one C_FAST contract position"
        )
    if (long_volume, short_volume) not in {(1, 0), (0, 1)}:
        raise ExecutableTargetAdapterError(
            "reduce-only close requires exactly one one-lot position"
        )


def build_executable_target_plan(
    *,
    map_candidate: Mapping[str, Any],
    c_fast_candidate: Mapping[str, Any],
    authority_receipt: Mapping[str, Any] | None,
    current_facts: GatewaySnapshot,
    reconciliation: Mapping[str, Any],
    product: str,
    account_scope: str,
    environment: str,
    gateway_name: str,
    reduce_only_close: bool = False,
    reduce_only_close_limit_price: float | None = None,
    trusted_keyless_expires_at: str | None = None,
    now: datetime | None = None,
) -> ExecutableTargetPlanHandoff:
    """Convert one explicit MAP/C_FAST target delta into one TargetPlan v1.

    It only permits an exact one-lot ``target - current`` delta.  The explicit
    reduce-only path is narrower still: it accepts the existing C_FAST -1
    target only as lineage, replaces its effective target with zero, and can
    close exactly one current position.  A zero or multi-lot delta, active
    order, unknown outcome, scope/gateway mismatch, or malformed current fact
    fails closed.  The returned plan must still follow the existing offline
    signing, custody install, preview, reconcile, enable, fencing and local
    opt-in flow before Execution can submit it.
    """

    normalized_scope = _require_text(account_scope, "account scope")
    normalized_environment = _require_text(environment, "environment").upper()
    normalized_gateway = _require_text(gateway_name, "gateway name")
    if normalized_environment != "SIMNOW":
        raise ExecutableTargetAdapterError("only SIMNOW target plans are supported")
    if not reduce_only_close and reduce_only_close_limit_price is not None:
        raise ExecutableTargetAdapterError(
            "reduce-only close limit price requires reduce-only close mode"
        )
    normalized_product = _require_text(product, "product").lower()
    map_hash, c_fast_hash = _validate_lineage(map_candidate, c_fast_candidate)
    candidate = _mapping(c_fast_candidate, "C_FAST candidate")
    _target, exchange, symbol, price = _selected_target(
        candidate, product=normalized_product
    )
    current_time = utc_now() if now is None else now
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ExecutableTargetAdapterError("adapter clock must be timezone-aware")
    keyless = authority_receipt is None
    if keyless:
        if (
            normalized_scope != "account:windows"
            or normalized_environment != "SIMNOW"
            or normalized_gateway != "CTP"
            or trusted_keyless_expires_at is None
        ):
            raise ExecutableTargetAdapterError("trusted keyless tuple is invalid")
        scope = dict(TRUSTED_KEYLESS_SIMNOW_SCOPE)
        try:
            expires_at = datetime.fromisoformat(trusted_keyless_expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ExecutableTargetAdapterError("trusted keyless expiry is invalid") from exc
        if expires_at.tzinfo is None or expires_at <= current_time:
            raise ExecutableTargetAdapterError("trusted keyless expiry is invalid")
    else:
        if trusted_keyless_expires_at is not None:
            raise ExecutableTargetAdapterError("signed target plan cannot set keyless expiry")
        try:
            receipt = VerifiedCustodyReceipt.from_mapping(authority_receipt)
        except CommodityExecutionContractError as exc:
            raise ExecutableTargetAdapterError("authority custody receipt is invalid") from exc
        if (
            receipt.raw["artifact_type"] != "runtime-authorization"
            or receipt.raw["trust_domain"] != "runtime_authorization"
            or receipt.raw["schema_ref"] != "phase-c-runtime-authorization-v1"
        ):
            raise ExecutableTargetAdapterError("authority receipt type is invalid")
        scope = receipt.scope
        if (
            scope.get("account_scope") != normalized_scope
            or scope.get("environment") != normalized_environment
            or scope.get("gateway_name") != normalized_gateway
        ):
            raise ExecutableTargetAdapterError("authority scope/gateway does not match target")
        if receipt.expires_at() <= current_time:
            raise ExecutableTargetAdapterError("authority receipt is expired")
    positions = _validate_snapshot(
        current_facts,
        account_scope=normalized_scope,
        environment=normalized_environment,
        reconciliation=reconciliation,
    )
    long_volume, short_volume, matching = _current_contract_positions(
        positions,
        exchange=exchange,
        symbol=symbol,
        gateway_name=normalized_gateway,
    )
    target_quantity = int(_target["target_quantity"])
    order_price = price
    if reduce_only_close:
        if target_quantity != -1:
            raise ExecutableTargetAdapterError(
                "reduce-only close requires the existing C_FAST target to be -1"
            )
        _require_single_reduce_only_position(
            positions,
            matching,
            long_volume=long_volume,
            short_volume=short_volume,
        )
        order_price = _reduce_only_limit_price(
            reduce_only_close_limit_price,
            price_tick=_target.get("price_tick"),
        )
        target_quantity = 0
    current_quantity = long_volume - short_volume
    delta = target_quantity - current_quantity
    if delta == 0:
        raise ExecutableTargetAdapterError("target-current delta is zero")
    if abs(delta) != 1:
        raise ExecutableTargetAdapterError(
            "only one-lot target-current deltas are allowed"
        )
    direction = "LONG" if delta > 0 else "SHORT"
    closes_position = (delta > 0 and short_volume > 0) or (
        delta < 0 and long_volume > 0
    )
    offset = (
        _close_order_offset(matching, exchange=exchange, direction=direction)
        if closes_position
        else "OPEN"
    )
    if (
        reduce_only_close and offset not in _CLOSE_ORDER_OFFSETS
    ):  # defensive: never open here
        raise ExecutableTargetAdapterError("reduce-only close would not close")
    expected_before = before_position_projection_hash(
        positions,
        account_scope=normalized_scope,
        environment=normalized_environment,
    )
    after_positions = _after_positions(
        positions,
        matching,
        exchange=exchange,
        symbol=symbol,
        gateway_name=normalized_gateway,
        direction=direction,
        offset=offset,
    )
    expected_after = target_position_projection_hash(
        after_positions,
        account_scope=normalized_scope,
        environment=normalized_environment,
    )
    identity = sha256_json(
        {
            "map_sha256": map_hash,
            "c_fast_sha256": c_fast_hash,
            "expected_before_position_hash": expected_before,
            "product": normalized_product,
            "gateway_name": normalized_gateway,
        }
    )
    shared_fields = {
        "plan_id": f"cfast-target-plan-v1-{identity}",
        "account_scope": normalized_scope,
        "environment": normalized_environment,
        "scope": scope,
        "expires_at": trusted_keyless_expires_at if keyless else str(receipt.raw["expires_at"]),
        "phase": "CLOSE" if offset in _CLOSE_ORDER_OFFSETS else "OPEN",
        "expected_before_position_hash": expected_before,
        "expected_after_position_hash": expected_after,
        "orders": [
            {
                "symbol": symbol,
                "exchange": exchange,
                "direction": direction,
                "type": "LIMIT",
                "volume": 1,
                "price": order_price,
                "offset": offset,
                # The Windows typed fence accepts at most 64 characters.  The
                # full SHA-256 identity is already deterministic and binds the
                # order to its MAP/C_FAST and expected-position inputs.
                "reference": identity,
                "gateway_name": normalized_gateway,
            }
        ],
    }
    if keyless:
        plan = build_trusted_keyless_target_plan(
            **shared_fields,
            gateway_name="CTP",
            lineage={"map_sha256": map_hash, "c_fast_sha256": c_fast_hash},
            generated_at=current_time.isoformat().replace("+00:00", "Z"),
        )
    else:
        plan = build_target_plan(
            **shared_fields,
            authority_artifact_id=receipt.artifact_id,
            authority_artifact_sha256=receipt.artifact_sha256,
            authority_receipt_id=receipt.receipt_id,
            authority_receipt_sha256=receipt.receipt_sha256,
            signer_key_id=str(receipt.raw["signer_key_id"]),
            signer_key_version=str(receipt.raw["signer_key_version"]),
            keyring_raw_sha256=str(receipt.raw["keyring_raw_sha256"]),
        )
    return ExecutableTargetPlanHandoff(
        target_plan=plan,
        lineage=(map_hash, c_fast_hash),
        scope=scope,
        expires_at=str(plan["expires_at"]),
    )


def build_trusted_keyless_executable_target_plan(
    *,
    map_candidate: Mapping[str, Any],
    c_fast_candidate: Mapping[str, Any],
    current_facts: GatewaySnapshot,
    reconciliation: Mapping[str, Any],
    product: str,
    expires_at: str,
    reduce_only_close: bool = False,
    reduce_only_close_limit_price: float | None = None,
    now: datetime | None = None,
) -> ExecutableTargetPlanHandoff:
    """Build the sole unsigned target path, pinned to the fixed SIMNOW tuple."""

    return build_executable_target_plan(
        map_candidate=map_candidate,
        c_fast_candidate=c_fast_candidate,
        authority_receipt=None,
        current_facts=current_facts,
        reconciliation=reconciliation,
        product=product,
        account_scope="account:windows",
        environment="SIMNOW",
        gateway_name="CTP",
        reduce_only_close=reduce_only_close,
        reduce_only_close_limit_price=reduce_only_close_limit_price,
        trusted_keyless_expires_at=expires_at,
        now=now,
    )


__all__ = [
    "ExecutableTargetAdapterError",
    "ExecutableTargetPlanHandoff",
    "PeekCurrentFacts",
    "build_executable_target_plan",
    "build_trusted_keyless_executable_target_plan",
    "peek_current_facts_to_snapshot",
]
