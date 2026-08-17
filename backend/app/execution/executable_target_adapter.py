"""Offline commodity target adapters for trusted SIMNOW execution.

This module deliberately has no RPC, gateway client, signer, custody writer,
or Execution lifecycle dependency.  A caller must hand it a fresh, already
read-only ``GatewaySnapshot`` and a reconciled Execution state.  Its output is
an immutable TargetPlan handoff for the existing custody and Execution path.
The historical MAP/C_FAST v1 adapter remains byte-compatible; the v2 adapter
binds the complete STATIC_CORE_EQUAL plus thermostat replay before masking.
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
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    TARGET_PLAN_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    CommodityExecutionContractError,
    VerifiedCustodyReceipt,
    before_position_projection_hash,
    build_target_plan,
    build_trusted_keyless_target_plan,
    build_trusted_keyless_target_plan_v2,
    canonical_before_position_projection,
    canonical_target_position_projection,
    sha256_json,
    target_position_projection_hash,
)
from shared.commodity_execution.v1 import canonical_json, utc_now

from ..core.commodity_strategy_identity import (
    COMMODITY_C_FAST_ALLOCATION_POLICY_IDENTITY_V1,
    COMMODITY_FROZEN_SECTOR_MAP_V1,
    COMMODITY_FROZEN_SECTOR_MAP_V1_ID,
    COMMODITY_MAP_STRATEGY_IDENTITY_V1,
)
from .gateway_contracts import GatewaySnapshot


class ExecutableTargetAdapterError(ValueError):
    """The offline inputs cannot safely produce a TargetPlan."""


_EXACT_CONTRACT = re.compile(r"^(CFFEX|CZCE|DCE|GFEX|INE|SHFE)\.([A-Za-z]+[0-9]{4})$")
_RUN_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_CLOSE_ORDER_OFFSETS = frozenset({"CLOSE", "CLOSETODAY", "CLOSEYESTERDAY"})
_CLOSE_OFFSET_EXCHANGES = frozenset({"INE", "SHFE"})
_TERMINAL_EXECUTION_ORDER_STATUSES = frozenset(
    {"ALLTRADED", "CANCELLED", "CANCELED", "REJECTED"}
)
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
_STATIC_CORE_EQUAL_STATUS = "PURE_RESEARCH_PRODUCER_ONLY_NOT_REAL_ARTIFACT"
_STATIC_CORE_EQUAL_KERNEL_ID = "commodity_static_core_equal_pure_producer_v1"
_STATIC_CORE_EQUAL_PRODUCTS = tuple(COMMODITY_FROZEN_SECTOR_MAP_V1)
_STATIC_CORE_EQUAL_ARTIFACT_ROLES = (
    "freeze_contract",
    "research_manifest",
    "signal_evidence",
    "target_evidence",
    "allocation_evidence",
    "daily_roll_evidence",
    "reference_price_evidence",
    "calendar_authority",
    "contract_spec_evidence",
)
_STATIC_CORE_EQUAL_AUTHORITY_FIELDS = frozenset(
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
    }
)


def _without_terminal_execution_orders(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy with only explicitly terminal broker readback removed."""

    if not isinstance(value, Mapping):
        raise ExecutableTargetAdapterError("peek current facts are invalid")
    execution = value.get("execution")
    if (
        not isinstance(execution, Mapping)
        or set(execution) != {"orders"}
        or not isinstance(execution["orders"], Mapping)
    ):
        raise ExecutableTargetAdapterError("peek execution facts are invalid")
    for order_id, row in execution["orders"].items():
        if not isinstance(order_id, str) or not isinstance(row, Mapping):
            raise ExecutableTargetAdapterError("peek execution order is invalid")
        status = row.get("status")
        normalized_status = (
            status.upper().replace("_", "").replace(" ", "")
            if isinstance(status, str)
            else ""
        )
        if normalized_status not in _TERMINAL_EXECUTION_ORDER_STATUSES:
            raise ExecutableTargetAdapterError(
                "peek execution order is not explicitly terminal"
            )
    sanitized = dict(value)
    sanitized["execution"] = {"orders": {}}
    return sanitized


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
    lineage: tuple[str, ...]
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

        schema_version = self.target_plan.get("schema_version")
        if schema_version not in {
            KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
            KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        }:
            raise ExecutableTargetAdapterError("target plan is not trusted keyless")
        return new_artifact_envelope(
            artifact_type="simnow-target-plan",
            trust_domain="runtime_authorization",
            producer_id=(
                "static-core-equal-final-target-adapter"
                if schema_version == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
                else "c-fast-executable-target-adapter"
            ),
            producer_version=(
                "v2"
                if schema_version == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
                else "v1"
            ),
            schema_ref=str(schema_version),
            payload=self.target_plan,
            generated_at=str(self.target_plan["generated_at"]),
            scope=self.scope,
            predecessor_refs=[],
            lineage=[],
        )


@dataclass(frozen=True, slots=True)
class StaticCoreEqualKeylessDecision:
    """Fully replay-bound ten-product target, optionally masked to one order.

    ``final_target_projection`` and ``final_target_sha256`` are calculated
    before the one-product execution mask.  A ``None`` handoff is either a
    fully validated NOOP or a structured no-eligible-target STOP; neither may
    enter custody or mutate Execution.
    """

    handoff: ExecutableTargetPlanHandoff | None
    static_core_equal_sha256: str
    position_manager_sha256: str
    final_target_sha256: str
    final_target_projection: dict[str, Any]
    selected_product: str
    selected_target_quantity: int
    current_quantity: int | None
    stop_reason: str | None

    @property
    def noop(self) -> bool:
        return self.handoff is None and self.stop_reason is None

    @property
    def stopped(self) -> bool:
        return self.stop_reason is not None


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


def _require_static_core_false_authority(
    payload: Mapping[str, Any], label: str
) -> None:
    if any(
        field not in payload or payload[field] is not False
        for field in _STATIC_CORE_EQUAL_AUTHORITY_FIELDS
    ):
        raise ExecutableTargetAdapterError(f"{label} attempts to grant authority")
    if any(
        isinstance(field, str) and field.endswith("_authorized") and value is not False
        for field, value in payload.items()
    ):
        raise ExecutableTargetAdapterError(f"{label} attempts to grant authority")


def _static_core_equal_outputs(
    *,
    producer_projection: Mapping[str, Any],
    freeze_contract: Mapping[str, Any],
    target_evidence: Mapping[str, Any],
) -> tuple[str, dict[str, dict[str, Any]], str]:
    projection = _mapping(producer_projection, "STATIC_CORE_EQUAL projection")
    freeze = _mapping(freeze_contract, "STATIC_CORE_EQUAL freeze contract")
    target = _mapping(target_evidence, "STATIC_CORE_EQUAL target evidence")
    if set(projection) != {
        "projection_type",
        "status",
        "scheduler_id",
        "producer_kernel_id",
        "source_view_canonical_sha256",
        "artifact_roles",
        "artifact_digests",
    }:
        raise ExecutableTargetAdapterError(
            "STATIC_CORE_EQUAL projection fields are invalid"
        )
    if (
        projection["projection_type"] != "research_evidence_projection_v1"
        or projection["status"] != _STATIC_CORE_EQUAL_STATUS
        or projection["scheduler_id"] != "STATIC_CORE_EQUAL"
        or projection["producer_kernel_id"] != _STATIC_CORE_EQUAL_KERNEL_ID
        or projection["artifact_roles"] != list(_STATIC_CORE_EQUAL_ARTIFACT_ROLES)
    ):
        raise ExecutableTargetAdapterError(
            "STATIC_CORE_EQUAL projection identity is invalid"
        )
    _sha(
        projection["source_view_canonical_sha256"],
        "STATIC_CORE_EQUAL source hash",
    )
    digests = projection["artifact_digests"]
    if not isinstance(digests, list) or len(digests) != len(
        _STATIC_CORE_EQUAL_ARTIFACT_ROLES
    ):
        raise ExecutableTargetAdapterError(
            "STATIC_CORE_EQUAL artifact digests are invalid"
        )
    digest_by_role: dict[str, str] = {}
    for index, item in enumerate(digests):
        if (
            not isinstance(item, Mapping)
            or set(item) != {"role", "sha256"}
            or item.get("role") != _STATIC_CORE_EQUAL_ARTIFACT_ROLES[index]
        ):
            raise ExecutableTargetAdapterError(
                "STATIC_CORE_EQUAL artifact digests are invalid"
            )
        digest_by_role[str(item["role"])] = _sha(
            item.get("sha256"), "STATIC_CORE_EQUAL artifact digest"
        )
    if digest_by_role["freeze_contract"] != sha256_json(freeze) or digest_by_role[
        "target_evidence"
    ] != sha256_json(target):
        raise ExecutableTargetAdapterError(
            "STATIC_CORE_EQUAL replay artifacts are cross-spliced"
        )
    for payload, role in ((freeze, "freeze contract"), (target, "target evidence")):
        if (
            payload.get("status") != _STATIC_CORE_EQUAL_STATUS
            or payload.get("scheduler_id") != "STATIC_CORE_EQUAL"
            or payload.get("producer_kernel_id") != _STATIC_CORE_EQUAL_KERNEL_ID
            or payload.get("artifact_role") != role.replace(" ", "_")
            or payload.get("source_view_canonical_sha256")
            != projection["source_view_canonical_sha256"]
            or payload.get("research_evidence_only") is not True
        ):
            raise ExecutableTargetAdapterError(
                f"STATIC_CORE_EQUAL {role} identity is invalid"
            )
        _require_static_core_false_authority(payload, f"STATIC_CORE_EQUAL {role}")
    if (
        freeze.get("candidate_weights") != {"C": 0.5, "D": 0.5}
        or freeze.get("C_candidate_id")
        != COMMODITY_C_FAST_ALLOCATION_POLICY_IDENTITY_V1
        or freeze.get("D_candidate_id") != "D_DONCHIAN20_EXIT10_NEUTRAL"
        or freeze.get("sector_map_id") != COMMODITY_FROZEN_SECTOR_MAP_V1_ID
        or freeze.get("sector_map") != dict(COMMODITY_FROZEN_SECTOR_MAP_V1)
    ):
        raise ExecutableTargetAdapterError(
            "STATIC_CORE_EQUAL frozen identity is invalid"
        )
    rows = target.get("targets")
    if not isinstance(rows, list) or len(rows) != len(_STATIC_CORE_EQUAL_PRODUCTS):
        raise ExecutableTargetAdapterError(
            "STATIC_CORE_EQUAL must contain the frozen ten targets"
        )
    by_product: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        row = _mapping(raw, f"STATIC_CORE_EQUAL target[{index}]")
        product = row.get("product")
        if product != _STATIC_CORE_EQUAL_PRODUCTS[index] or product in by_product:
            raise ExecutableTargetAdapterError(
                "STATIC_CORE_EQUAL targets are incomplete or reordered"
            )
        if row.get("sector") != COMMODITY_FROZEN_SECTOR_MAP_V1[product]:
            raise ExecutableTargetAdapterError(
                "STATIC_CORE_EQUAL target sector map is invalid"
            )
        quantity = row.get("target_quantity")
        if isinstance(quantity, bool) or not isinstance(quantity, int):
            raise ExecutableTargetAdapterError(
                "STATIC_CORE_EQUAL target quantity is invalid"
            )
        _contract(row.get("exact_contract"))
        by_product[product] = row
    execution_day = _require_text(
        target.get("execution_day"), "STATIC_CORE_EQUAL execution day"
    )
    return sha256_json(projection), by_product, execution_day


def _position_manager_final_projection(
    *,
    snapshot: Mapping[str, Any],
    expected_sha256: str,
    static_rows: Mapping[str, Mapping[str, Any]],
    static_execution_day: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    value = _mapping(snapshot, "position-manager snapshot")
    normalized_expected_sha256 = _sha(expected_sha256, "position-manager snapshot hash")
    if sha256_json(value) != normalized_expected_sha256:
        raise ExecutableTargetAdapterError("position-manager snapshot hash mismatch")
    if (
        value.get("schema_version")
        != "commodity_relative_vol_position_manager_shadow_v2"
        or value.get("position_manager_id") != "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1"
        or value.get("sector_map_id") != "POSITION_MANAGER_SECTOR_MAP_V1"
        or value.get("baseline_scheduler_id") != "STATIC_CORE_EQUAL"
        or value.get("mode") != "shadow_only"
        or value.get("execution_lane") != "simnow_shakedown"
        or value.get("countable_forward") is not False
        or value.get("authority_granted") is not False
        or value.get("dispatch_allowed") is not False
        or value.get("execution_day") != static_execution_day
    ):
        raise ExecutableTargetAdapterError(
            "position-manager snapshot identity is invalid"
        )
    targets = value.get("targets")
    if not isinstance(targets, list) or len(targets) != len(
        _STATIC_CORE_EQUAL_PRODUCTS
    ):
        raise ExecutableTargetAdapterError(
            "position-manager snapshot must contain the frozen ten targets"
        )
    final_rows: list[dict[str, Any]] = []
    by_product: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(targets):
        row = _mapping(raw, f"position-manager target[{index}]")
        product = row.get("product")
        if product != _STATIC_CORE_EQUAL_PRODUCTS[index] or product in by_product:
            raise ExecutableTargetAdapterError(
                "position-manager targets are incomplete or reordered"
            )
        static_row = static_rows[product]
        baseline_binding = {
            "product": product,
            "exact_contract": row.get("exact_contract"),
            "target_quantity": row.get("baseline_target_quantity"),
            "source_target_weight": row.get("baseline_source_target_weight"),
            "buffered_target_weight": row.get("baseline_buffered_target_weight"),
            "reference_open_price": row.get("reference_open_price"),
            "multiplier": row.get("multiplier"),
            "price_tick": row.get("price_tick"),
        }
        static_binding = {
            key: static_row.get(key)
            for key in (
                "product",
                "exact_contract",
                "target_quantity",
                "source_target_weight",
                "buffered_target_weight",
                "reference_open_price",
                "multiplier",
                "price_tick",
            )
        }
        if sha256_json(baseline_binding) != sha256_json(static_binding):
            raise ExecutableTargetAdapterError(
                f"position-manager baseline is not bound to STATIC_CORE_EQUAL: {product}"
            )
        shadow_quantity = row.get("shadow_target_quantity")
        if isinstance(shadow_quantity, bool) or not isinstance(shadow_quantity, int):
            raise ExecutableTargetAdapterError(
                "position-manager shadow target quantity is invalid"
            )
        _contract(row.get("exact_contract"))
        final_row = {
            "product": product,
            "sector": COMMODITY_FROZEN_SECTOR_MAP_V1[product],
            "exact_contract": row["exact_contract"],
            "target_quantity": shadow_quantity,
            "reference_open_price": row["reference_open_price"],
            "multiplier": row["multiplier"],
            "price_tick": row["price_tick"],
        }
        final_rows.append(final_row)
        by_product[product] = final_row
    projection = {
        "schema_version": "commodity_static_core_equal_final_target_projection_v1",
        "strategy_id": "STATIC_CORE_EQUAL",
        "baseline_scheduler_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "c_sleeve_id": COMMODITY_C_FAST_ALLOCATION_POLICY_IDENTITY_V1,
        "c_map_rule_id": COMMODITY_MAP_STRATEGY_IDENTITY_V1,
        "d_sleeve_id": "D_DONCHIAN20_EXIT10_NEUTRAL",
        "sector_map_id": COMMODITY_FROZEN_SECTOR_MAP_V1_ID,
        "position_manager_id": "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
        "source_month": value.get("source_month"),
        "execution_day": value.get("execution_day"),
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "targets": final_rows,
    }
    # Detach and prove the complete ten-product projection is canonical before
    # any product is selected as an execution mask.
    return _mapping(projection, "STATIC_CORE_EQUAL final target projection"), by_product


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
    quantity: int = 1,
) -> dict[str, Any]:
    if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 1:
        raise ExecutableTargetAdapterError("target position quantity is invalid")
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
        row["volume"] -= quantity
        if row["volume"] < 0:
            raise ExecutableTargetAdapterError("close target quantity exceeds position")
        result[key] = row
        return result
    candidates = sorted(
        (item for item in matching if item[1]["direction"].upper() == direction),
        key=lambda item: item[0],
    )
    if candidates:
        key, row = candidates[0]
        row["volume"] += quantity
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
        "volume": quantity,
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


def build_static_core_equal_keyless_target_decision(
    *,
    static_core_equal_projection: Mapping[str, Any],
    static_core_equal_freeze_contract: Mapping[str, Any],
    static_core_equal_target_evidence: Mapping[str, Any],
    position_manager_snapshot: Mapping[str, Any],
    position_manager_sha256: str,
    current_facts: GatewaySnapshot,
    reconciliation: Mapping[str, Any],
    product: str,
    run_id: str,
    expires_at: str,
    now: datetime | None = None,
) -> StaticCoreEqualKeylessDecision:
    """Replay and bind STATIC_CORE_EQUAL plus thermostat before masking.

    The full frozen ten-product final projection is built and hashed before
    ``product`` is inspected.  The execution mask may select only a product
    with the smallest nonzero final target quantity; ties are explicit operator
    choices.  A matching canonical target position returns a NOOP decision
    without custody or Execution mutation.  A real delta is admitted only from
    a flat account and produces one one-lot OPEN child order per target lot.
    """

    normalized_product = _require_text(product, "product").lower()
    if normalized_product not in _STATIC_CORE_EQUAL_PRODUCTS:
        raise ExecutableTargetAdapterError("product is outside the frozen universe")
    normalized_run_id = _require_text(run_id, "run id")
    if _RUN_ID.fullmatch(normalized_run_id) is None:
        raise ExecutableTargetAdapterError("run id is invalid")
    current_time = utc_now() if now is None else now
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ExecutableTargetAdapterError("adapter clock must be timezone-aware")
    try:
        normalized_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ExecutableTargetAdapterError("trusted keyless expiry is invalid") from exc
    if normalized_expiry.tzinfo is None or normalized_expiry <= current_time:
        raise ExecutableTargetAdapterError("trusted keyless expiry is invalid")

    static_sha256, static_rows, static_execution_day = _static_core_equal_outputs(
        producer_projection=static_core_equal_projection,
        freeze_contract=static_core_equal_freeze_contract,
        target_evidence=static_core_equal_target_evidence,
    )
    final_projection, final_rows = _position_manager_final_projection(
        snapshot=position_manager_snapshot,
        expected_sha256=position_manager_sha256,
        static_rows=static_rows,
        static_execution_day=static_execution_day,
    )
    final_target_sha256 = sha256_json(final_projection)
    eligible_products = tuple(
        product
        for product in _STATIC_CORE_EQUAL_PRODUCTS
        if final_rows[product]["target_quantity"] != 0
    )
    minimum_target_quantity = min(
        (abs(final_rows[product]["target_quantity"]) for product in eligible_products),
        default=None,
    )
    minimum_target_products = tuple(
        product
        for product in eligible_products
        if abs(final_rows[product]["target_quantity"]) == minimum_target_quantity
    )
    selected = final_rows[normalized_product]
    target_quantity = selected["target_quantity"]
    source_decision_fields = {
        "static_core_equal_sha256": static_sha256,
        "position_manager_sha256": _sha(
            position_manager_sha256, "position-manager snapshot hash"
        ),
        "final_target_sha256": final_target_sha256,
        "final_target_projection": final_projection,
        "selected_product": normalized_product,
        "selected_target_quantity": target_quantity,
    }
    if minimum_target_products and normalized_product not in minimum_target_products:
        raise ExecutableTargetAdapterError(
            "selected product is not a minimum nonzero target"
        )
    exchange, symbol = _contract(selected["exact_contract"])
    positions = _validate_snapshot(
        current_facts,
        account_scope="account:windows",
        environment="SIMNOW",
        reconciliation=reconciliation,
    )
    long_volume, short_volume, matching = _current_contract_positions(
        positions,
        exchange=exchange,
        symbol=symbol,
        gateway_name="CTP",
    )
    current_quantity = long_volume - short_volume
    if not minimum_target_products:
        return StaticCoreEqualKeylessDecision(
            handoff=None,
            current_quantity=current_quantity,
            stop_reason="no_nonzero_target",
            **source_decision_fields,
        )
    delta = target_quantity - current_quantity
    decision_fields = {
        **source_decision_fields,
        "current_quantity": current_quantity,
        "stop_reason": None,
    }
    gross_position_volume = sum(
        int(row.get("volume", 0))
        for row in positions.values()
        if isinstance(row, Mapping)
    )
    if delta == 0:
        if (
            len(positions) != 1
            or len(matching) != 1
            or gross_position_volume != abs(target_quantity)
            or long_volume + short_volume != abs(target_quantity)
            or (
                target_quantity > 0
                and (long_volume, short_volume) != (target_quantity, 0)
            )
            or (
                target_quantity < 0
                and (long_volume, short_volume) != (0, abs(target_quantity))
            )
        ):
            raise ExecutableTargetAdapterError(
                "NOOP requires the sole canonical target position"
            )
        return StaticCoreEqualKeylessDecision(handoff=None, **decision_fields)
    if gross_position_volume != 0:
        raise ExecutableTargetAdapterError(
            "STATIC_CORE_EQUAL Run A requires a flat account"
        )

    expected_before = before_position_projection_hash(
        positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    direction = "LONG" if delta > 0 else "SHORT"
    after_positions = _after_positions(
        positions,
        matching,
        exchange=exchange,
        symbol=symbol,
        gateway_name="CTP",
        direction=direction,
        offset="OPEN",
        quantity=abs(delta),
    )
    expected_after = target_position_projection_hash(
        after_positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    identity = sha256_json(
        {
            "static_core_equal_sha256": static_sha256,
            "position_manager_sha256": position_manager_sha256,
            "final_target_sha256": final_target_sha256,
            "expected_before_position_hash": expected_before,
            "product": normalized_product,
            "gateway_name": "CTP",
            "run_id": normalized_run_id,
        }
    )
    try:
        plan = build_trusted_keyless_target_plan_v2(
            plan_id=f"static-core-equal-target-plan-v2-{identity}",
            account_scope="account:windows",
            environment="SIMNOW",
            gateway_name="CTP",
            lineage={
                "static_core_equal_sha256": static_sha256,
                "position_manager_sha256": position_manager_sha256,
                "final_target_sha256": final_target_sha256,
            },
            scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
            generated_at=current_time.isoformat().replace("+00:00", "Z"),
            expires_at=expires_at,
            phase="OPEN",
            expected_before_position_hash=expected_before,
            expected_after_position_hash=expected_after,
            orders=[
                {
                    "symbol": symbol,
                    "exchange": exchange,
                    "direction": direction,
                    "type": "LIMIT",
                    "volume": 1,
                    "price": selected["reference_open_price"],
                    "offset": "OPEN",
                    "reference": sha256_json(
                        {"plan_identity": identity, "child_index": child_index}
                    ),
                    "gateway_name": "CTP",
                }
                for child_index in range(1, abs(delta) + 1)
            ],
        )
    except CommodityExecutionContractError as exc:
        raise ExecutableTargetAdapterError(
            f"STATIC_CORE_EQUAL TargetPlan v2 is invalid: {exc}"
        ) from exc
    handoff = ExecutableTargetPlanHandoff(
        target_plan=plan,
        lineage=(static_sha256, position_manager_sha256, final_target_sha256),
        scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
        expires_at=str(plan["expires_at"]),
    )
    return StaticCoreEqualKeylessDecision(handoff=handoff, **decision_fields)


__all__ = [
    "ExecutableTargetAdapterError",
    "ExecutableTargetPlanHandoff",
    "PeekCurrentFacts",
    "StaticCoreEqualKeylessDecision",
    "build_executable_target_plan",
    "build_static_core_equal_keyless_target_decision",
    "build_trusted_keyless_executable_target_plan",
    "peek_current_facts_to_snapshot",
]
