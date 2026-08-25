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
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
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
    FORMAL_QUOTE_PROOF_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    TARGET_PLAN_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
    CommodityExecutionContractError,
    TargetPlan,
    VerifiedCustodyReceipt,
    before_position_projection_hash,
    build_target_plan,
    build_trusted_keyless_target_plan,
    build_trusted_keyless_target_plan_v2,
    build_trusted_keyless_target_plan_v3,
    canonical_before_position_projection,
    canonical_target_position_projection,
    normalize_near_grid_price,
    sha256_json,
    simnow_experimental_adverse_cushion_ticks,
    target_position_projection_hash,
    trusted_keyless_target_plan_v3_plan_id,
)
from shared.commodity_execution.v1 import canonical_json, utc_now

from ..core.commodity_strategy_identity import (
    COMMODITY_C_FAST_ALLOCATION_POLICY_IDENTITY_V1,
    COMMODITY_FROZEN_SECTOR_MAP_V1,
    COMMODITY_FROZEN_SECTOR_MAP_V1_ID,
    COMMODITY_MAP_STRATEGY_IDENTITY_V1,
)
from .formal_tick_reader import FormalTickRequest
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
_STATIC_CORE_EQUAL_EXCHANGE_BY_PRODUCT = {
    product: "INE" if product == "sc" else "SHFE"
    for product in _STATIC_CORE_EQUAL_PRODUCTS
}
_FULL_PORTFOLIO_QUOTE_FUTURE_SKEW_SECONDS = 2
_FULL_PORTFOLIO_IDENTITY_SCHEMA_VERSION = (
    "commodity_static_core_equal_phase_identity_preimage_v1"
)
_FULL_PORTFOLIO_IDENTITY_FIELDS = frozenset(
    {
        "identity_schema_version",
        "strategy_id",
        "run_id",
        "phase",
        "account_scope",
        "environment",
        "gateway_name",
        "scope",
        "lineage",
        "expected_before_position_hash",
        "expected_after_position_hash",
        "orders",
        "formal_quote_bindings",
        "generated_at",
        "expires_at",
    }
)
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
class StaticCoreEqualPhaseBoundary:
    """One canonical post-close portfolio with both existing hash semantics.

    TargetPlan final reconciliation intentionally hashes the target projection,
    while a subsequent TargetPlan start hashes the before projection (including
    SHFE/INE ``yd_volume``).  Both hashes are derived here from the same detached
    position rows.  They are not claimed to be byte-equal; the runner must bind
    a future OPEN plan to fresh authoritative post-close facts.
    """

    positions: dict[str, Any]
    target_projection: dict[str, Any]
    before_projection: dict[str, Any]
    close_expected_after_position_hash: str
    open_expected_before_position_hash: str


@dataclass(frozen=True, slots=True)
class StaticCoreEqualFullPortfolioPhaseHandoff:
    """Custody-capable phase handoff with version-specific identity proof."""

    target_plan: dict[str, Any]
    lineage: tuple[str, ...]
    scope: dict[str, Any]
    expires_at: str
    identity_preimage: dict[str, Any] | None = None

    def recompute_plan_id(self) -> str:
        """Recompute the exact ID using the schema's frozen identity contract."""

        schema_version = self.target_plan.get("schema_version")
        if schema_version == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
            if self.identity_preimage is not None:
                raise ExecutableTargetAdapterError(
                    "full-portfolio v3 must not retain a hidden identity preimage"
                )
            return full_portfolio_phase_plan_id_from_payload(self.target_plan)
        if schema_version != KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION:
            raise ExecutableTargetAdapterError(
                "full-portfolio phase target plan schema is invalid"
            )
        if not isinstance(self.identity_preimage, Mapping):
            raise ExecutableTargetAdapterError(
                "full-portfolio v2 identity preimage is missing"
            )
        return full_portfolio_phase_plan_id_from_preimage(self.identity_preimage)

    def validate_identity_proof(self) -> str:
        """Fail closed unless the schema-specific proof is self-consistent."""

        schema_version = self.target_plan.get("schema_version")
        if schema_version == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION:
            preimage = self.identity_preimage
            if not isinstance(preimage, Mapping):
                raise ExecutableTargetAdapterError(
                    "full-portfolio v2 identity preimage is missing"
                )
            plan_id = self.recompute_plan_id()
            lineage = preimage.get("lineage")
            if not isinstance(lineage, Mapping):
                raise ExecutableTargetAdapterError(
                    "full-portfolio phase identity lineage is invalid"
                )
            target_bindings = {
                field: self.target_plan.get(field)
                for field in (
                    "account_scope",
                    "environment",
                    "gateway_name",
                    "scope",
                    "lineage",
                    "expected_before_position_hash",
                    "expected_after_position_hash",
                    "orders",
                    "generated_at",
                    "expires_at",
                    "phase",
                )
            }
            proof_bindings = {field: preimage.get(field) for field in target_bindings}
            expected_lineage = tuple(
                str(lineage[field])
                for field in (
                    "static_core_equal_sha256",
                    "position_manager_sha256",
                    "final_target_sha256",
                )
            )
            if (
                plan_id != self.target_plan.get("plan_id")
                or target_bindings != proof_bindings
                or self.scope != preimage.get("scope")
                or self.expires_at != preimage.get("expires_at")
                or self.lineage != expected_lineage
            ):
                raise ExecutableTargetAdapterError(
                    "full-portfolio phase identity proof does not match target plan"
                )
            return plan_id
        if schema_version != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
            raise ExecutableTargetAdapterError(
                "full-portfolio phase target plan schema is invalid"
            )
        try:
            plan = TargetPlan.from_mapping(self.target_plan)
        except CommodityExecutionContractError as exc:
            raise ExecutableTargetAdapterError(
                "full-portfolio phase identity proof is invalid"
            ) from exc
        plan_id = self.recompute_plan_id()
        lineage = plan.raw.get("lineage")
        if not isinstance(lineage, Mapping):  # pragma: no cover - strict v3 parser
            raise ExecutableTargetAdapterError(
                "full-portfolio phase identity lineage is invalid"
            )
        expected_lineage = tuple(
            str(lineage[field])
            for field in (
                "static_core_equal_sha256",
                "position_manager_sha256",
                "final_target_sha256",
            )
        )
        if (
            plan_id != plan.plan_id
            or self.scope != plan.raw.get("scope")
            or self.expires_at != plan.raw.get("expires_at")
            or self.lineage != expected_lineage
        ):
            raise ExecutableTargetAdapterError(
                "full-portfolio phase identity proof does not match target plan"
            )
        return plan_id

    def trusted_keyless_custody_artifact(self) -> dict[str, Any]:
        """Return the schema-matched create-only custody envelope."""

        schema_version = self.target_plan.get("schema_version")
        if schema_version not in {
            KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
            KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        }:
            raise ExecutableTargetAdapterError(
                "full-portfolio phase target plan schema is invalid"
            )
        self.validate_identity_proof()
        return new_artifact_envelope(
            artifact_type="simnow-target-plan",
            trust_domain="runtime_authorization",
            producer_id="static-core-equal-final-target-adapter",
            producer_version=(
                "v3"
                if schema_version == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
                else "v2"
            ),
            schema_ref=str(schema_version),
            payload=self.target_plan,
            generated_at=str(self.target_plan["generated_at"]),
            scope=self.scope,
            predecessor_refs=[],
            lineage=[],
        )


@dataclass(frozen=True, slots=True)
class StaticCoreEqualDeferredOpenIntent:
    """Non-custody OPEN template that must be replanned from fresh facts."""

    template: dict[str, Any]

    @property
    def custody_allowed(self) -> bool:
        return False

    @property
    def order_count(self) -> int:
        intents = self.template.get("intents", [])
        if not isinstance(intents, list):  # pragma: no cover - built internally
            return 0
        return sum(
            int(intent.get("volume", 0))
            for intent in intents
            if isinstance(intent, Mapping)
        )


@dataclass(frozen=True, slots=True)
class StaticCoreEqualFullPortfolioDecision:
    """Pure full-portfolio STATIC_CORE_EQUAL two-phase planning result.

    Ownership and completed-target admission are deliberately outside this
    pure adapter.  Its ``current_facts`` input must already be the complete,
    fail-closed strategy-owned account portfolio.  The adapter proves frozen
    replay, freshness/reconciliation, scope, ten-product deltas and immutable
    quote-aware TargetPlan v3 material; it has no ledger or mutation dependency.
    """

    close_handoff: StaticCoreEqualFullPortfolioPhaseHandoff | None
    open_handoff: StaticCoreEqualFullPortfolioPhaseHandoff | None
    deferred_open_intent: StaticCoreEqualDeferredOpenIntent | None
    phase_boundary: StaticCoreEqualPhaseBoundary
    static_core_equal_sha256: str
    position_manager_sha256: str
    final_target_sha256: str
    final_target_projection: dict[str, Any]
    current_before_position_hash: str
    current_target_position_hash: str
    final_position_hash: str
    close_formal_quote_bindings: dict[str, Any]
    open_formal_quote_bindings: dict[str, Any]
    close_order_count: int
    open_order_count: int
    deferred_open_order_count: int

    @property
    def noop(self) -> bool:
        return (
            self.close_handoff is None
            and self.open_handoff is None
            and self.deferred_open_intent is None
        )

    @property
    def handoffs(self) -> tuple[StaticCoreEqualFullPortfolioPhaseHandoff, ...]:
        return tuple(
            handoff
            for handoff in (self.close_handoff, self.open_handoff)
            if handoff is not None
        )


@dataclass(frozen=True, slots=True)
class StaticCoreEqualFullPortfolioQuoteRequirement:
    """One exact read-only quote request and the phase orders that consume it."""

    phase: str
    product: str
    exact_contract: str
    request: FormalTickRequest
    order_references: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.phase) is not str or self.phase not in {"CLOSE", "OPEN"}:
            raise ValueError("full-portfolio quote requirement phase is invalid")
        if type(self.product) is not str or self.product not in (
            _STATIC_CORE_EQUAL_PRODUCTS
        ):
            raise ValueError("full-portfolio quote requirement product is invalid")
        if type(self.exact_contract) is not str:
            raise ValueError("full-portfolio quote requirement contract is invalid")
        if type(self.request) is not FormalTickRequest:
            raise ValueError("full-portfolio quote requirement request is invalid")
        if type(self.order_references) is not tuple:
            raise ValueError("full-portfolio quote requirement orders are invalid")
        try:
            expected_request = _full_portfolio_quote_request(
                exact_contract=self.exact_contract,
                product=self.product,
                price_side=self.request.price_side,
                expected_price_tick=self.request.price_tick,
            )
        except ExecutableTargetAdapterError as exc:
            raise ValueError(
                "full-portfolio quote requirement request is invalid"
            ) from exc
        if self.request != expected_request:
            raise ValueError("full-portfolio quote requirement contract mismatches")
        if not self.order_references or len(set(self.order_references)) != len(
            self.order_references
        ):
            raise ValueError("full-portfolio quote requirement orders are invalid")
        for reference in self.order_references:
            _sha(reference, "full-portfolio quote requirement order reference")


@dataclass(frozen=True, slots=True)
class StaticCoreEqualFullPortfolioQuoteInputBinding:
    """Canonical immutable inputs that produced one quote-request batch."""

    static_core_equal_projection_sha256: str
    static_core_equal_freeze_contract_sha256: str
    static_core_equal_target_evidence_sha256: str
    position_manager_sha256: str
    current_before_position_hash: str
    desired_target_sha256: str
    reconciliation_sha256: str
    phase_boundary_sha256: str
    deferred_open_intent_sha256: str | None
    run_id: str
    event_generated_at: str
    target_plan_version: int
    input_binding_sha256: str = dataclass_field(init=False)

    def __post_init__(self) -> None:
        for value, label in (
            (
                self.static_core_equal_projection_sha256,
                "quote input STATIC_CORE_EQUAL projection hash",
            ),
            (
                self.static_core_equal_freeze_contract_sha256,
                "quote input STATIC_CORE_EQUAL freeze hash",
            ),
            (
                self.static_core_equal_target_evidence_sha256,
                "quote input STATIC_CORE_EQUAL target hash",
            ),
            (self.position_manager_sha256, "quote input position-manager hash"),
            (
                self.current_before_position_hash,
                "quote input current before-position hash",
            ),
            (self.desired_target_sha256, "quote input desired-target hash"),
            (self.reconciliation_sha256, "quote input reconciliation hash"),
            (self.phase_boundary_sha256, "quote input phase-boundary hash"),
        ):
            _sha(value, label)
        if self.deferred_open_intent_sha256 is not None:
            _sha(
                self.deferred_open_intent_sha256,
                "quote input deferred OPEN intent hash",
            )
        if type(self.run_id) is not str or _RUN_ID.fullmatch(self.run_id) is None:
            raise ValueError("quote input run id is invalid")
        if type(
            self.event_generated_at
        ) is not str or not self.event_generated_at.endswith("Z"):
            raise ValueError("quote input event generated_at is invalid")
        try:
            generated_at = datetime.fromisoformat(
                self.event_generated_at[:-1] + "+00:00"
            )
        except ValueError as exc:
            raise ValueError("quote input event generated_at is invalid") from exc
        if generated_at.utcoffset() != timezone.utc.utcoffset(generated_at):
            raise ValueError("quote input event generated_at is invalid")
        if type(
            self.target_plan_version
        ) is not int or self.target_plan_version not in {
            2,
            3,
        }:
            raise ValueError("quote input target-plan version is invalid")
        object.__setattr__(
            self,
            "input_binding_sha256",
            sha256_json(_full_portfolio_quote_input_binding_payload(self)),
        )


@dataclass(frozen=True, slots=True)
class StaticCoreEqualFullPortfolioQuoteRequirements:
    """The only formal-tick batch admitted for the next executable phase.

    A CLOSE phase suppresses all future OPEN requests.  OPEN requirements are
    produced only when fresh post-close facts make OPEN the immediate phase.
    An empty tuple is a true full-portfolio NOOP and consumes no quote.
    """

    phase: str | None
    requirements: tuple[StaticCoreEqualFullPortfolioQuoteRequirement, ...]
    deferred_open_order_count: int
    input_binding: StaticCoreEqualFullPortfolioQuoteInputBinding
    quote_requirements_sha256: str = dataclass_field(init=False)

    def __post_init__(self) -> None:
        if self.phase is not None and (
            type(self.phase) is not str or self.phase not in {"CLOSE", "OPEN"}
        ):
            raise ValueError("full-portfolio quote requirements phase is invalid")
        if type(self.requirements) is not tuple or any(
            type(row) is not StaticCoreEqualFullPortfolioQuoteRequirement
            for row in self.requirements
        ):
            raise ValueError("full-portfolio quote requirements are invalid")
        if (
            type(self.input_binding)
            is not StaticCoreEqualFullPortfolioQuoteInputBinding
        ):
            raise ValueError("full-portfolio quote input binding is invalid")
        if type(self.deferred_open_order_count) is not int:
            raise ValueError("full-portfolio deferred OPEN count is invalid")
        if self.deferred_open_order_count < 0:
            raise ValueError("full-portfolio deferred OPEN count is invalid")
        if self.phase != "CLOSE" and self.deferred_open_order_count != 0:
            raise ValueError(
                "full-portfolio deferred OPEN count requires a CLOSE phase"
            )
        if (self.deferred_open_order_count == 0) is not (
            self.input_binding.deferred_open_intent_sha256 is None
        ):
            raise ValueError(
                "full-portfolio deferred OPEN intent binding is inconsistent"
            )
        if (self.phase is None) is not (not self.requirements):
            raise ValueError("full-portfolio quote requirements phase is inconsistent")
        if any(row.phase != self.phase for row in self.requirements):
            raise ValueError("full-portfolio quote requirement phases are mixed")
        contracts = tuple(row.exact_contract for row in self.requirements)
        if contracts != tuple(sorted(contracts)) or len(set(contracts)) != len(
            contracts
        ):
            raise ValueError("full-portfolio quote requirements are not canonical")
        object.__setattr__(
            self,
            "quote_requirements_sha256",
            sha256_json(_full_portfolio_quote_requirements_payload(self)),
        )

    @property
    def requests(self) -> tuple[FormalTickRequest, ...]:
        return tuple(row.request for row in self.requirements)

    @property
    def noop(self) -> bool:
        return self.phase is None


def _full_portfolio_quote_input_binding_payload(
    binding: StaticCoreEqualFullPortfolioQuoteInputBinding,
) -> dict[str, Any]:
    return {
        "schema_version": "static_core_equal_quote_input_binding_v1",
        "static_core_equal_projection_sha256": (
            binding.static_core_equal_projection_sha256
        ),
        "static_core_equal_freeze_contract_sha256": (
            binding.static_core_equal_freeze_contract_sha256
        ),
        "static_core_equal_target_evidence_sha256": (
            binding.static_core_equal_target_evidence_sha256
        ),
        "position_manager_sha256": binding.position_manager_sha256,
        "current_before_position_hash": binding.current_before_position_hash,
        "desired_target_sha256": binding.desired_target_sha256,
        "reconciliation_sha256": binding.reconciliation_sha256,
        "phase_boundary_sha256": binding.phase_boundary_sha256,
        "deferred_open_intent_sha256": binding.deferred_open_intent_sha256,
        "run_id": binding.run_id,
        "event_generated_at": binding.event_generated_at,
        "target_plan_version": binding.target_plan_version,
    }


def _full_portfolio_quote_requirements_payload(
    value: StaticCoreEqualFullPortfolioQuoteRequirements,
) -> dict[str, Any]:
    return {
        "schema_version": "static_core_equal_quote_requirements_v1",
        "phase": value.phase,
        "requirements": [
            {
                "phase": row.phase,
                "product": row.product,
                "exact_contract": row.exact_contract,
                "request": {
                    "vt_symbol": row.request.vt_symbol,
                    "price_side": row.request.price_side,
                    "price_tick": row.request.price_tick,
                },
                "order_references": list(row.order_references),
            }
            for row in value.requirements
        ],
        "deferred_open_order_count": value.deferred_open_order_count,
        "input_binding_sha256": value.input_binding.input_binding_sha256,
    }


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


def _after_safety_flat_close(
    positions: Mapping[str, Any],
    matching: list[tuple[str, dict[str, Any]]],
    *,
    direction: str,
    offset: str,
) -> dict[str, Any]:
    """Consume precisely one selected-contract lot for SAFETY FLAT planning.

    Unlike the generic one-lot projection helper, this keeps SHFE/INE's
    ``yd_volume`` inventory coherent across more than one generated child.
    It is planning-only and never alters the broker facts it was derived from.
    """

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
    if len(candidates) != 1:
        raise ExecutableTargetAdapterError("SAFETY FLAT close position is invalid")
    key, row = candidates[0]
    result = _mapping(positions, "current positions")
    updated = _mapping(row, "current position row")
    if offset == "CLOSETODAY":
        yd_volume = updated.get("yd_volume")
        if (
            isinstance(yd_volume, bool)
            or not isinstance(yd_volume, int)
            or yd_volume < 0
            or yd_volume > updated["volume"]
            or updated["volume"] - yd_volume < 1
        ):
            raise ExecutableTargetAdapterError(
                "SHFE/INE current position yd_volume is missing or inconsistent"
            )
    elif offset == "CLOSEYESTERDAY":
        yd_volume = updated.get("yd_volume")
        if (
            isinstance(yd_volume, bool)
            or not isinstance(yd_volume, int)
            or yd_volume < 1
            or yd_volume > updated["volume"]
        ):
            raise ExecutableTargetAdapterError(
                "SHFE/INE current position yd_volume is missing or inconsistent"
            )
        updated["yd_volume"] = yd_volume - 1
    elif offset != "CLOSE":
        raise ExecutableTargetAdapterError("SAFETY FLAT would not close")
    updated["volume"] -= 1
    if updated["volume"] < 0:  # pragma: no cover - guarded above
        raise ExecutableTargetAdapterError("SAFETY FLAT close exceeds position")
    result[key] = updated
    return result


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
            expires_at = datetime.fromisoformat(
                trusted_keyless_expires_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ExecutableTargetAdapterError(
                "trusted keyless expiry is invalid"
            ) from exc
        if expires_at.tzinfo is None or expires_at <= current_time:
            raise ExecutableTargetAdapterError("trusted keyless expiry is invalid")
    else:
        if trusted_keyless_expires_at is not None:
            raise ExecutableTargetAdapterError(
                "signed target plan cannot set keyless expiry"
            )
        try:
            receipt = VerifiedCustodyReceipt.from_mapping(authority_receipt)
        except CommodityExecutionContractError as exc:
            raise ExecutableTargetAdapterError(
                "authority custody receipt is invalid"
            ) from exc
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
            raise ExecutableTargetAdapterError(
                "authority scope/gateway does not match target"
            )
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
        "expires_at": trusted_keyless_expires_at
        if keyless
        else str(receipt.raw["expires_at"]),
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


def _canonical_strategy_portfolio_positions(
    positions: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, tuple[str, dict[str, Any]]]]:
    """Normalize the already owner-verified account to one row per product."""

    original_symbol_by_product: dict[str, str] = {}
    for raw in positions.values():
        if not isinstance(raw, Mapping):
            raise ExecutableTargetAdapterError("strategy portfolio position is invalid")
        volume = raw.get("volume")
        if isinstance(volume, bool) or not isinstance(volume, int) or volume < 0:
            raise ExecutableTargetAdapterError(
                "strategy portfolio position volume is invalid"
            )
        if volume == 0:
            continue
        symbol = _require_text(raw.get("symbol"), "strategy position symbol")
        match = re.fullmatch(r"([A-Za-z]+)[0-9]{4}", symbol)
        if match is None:
            raise ExecutableTargetAdapterError(
                "strategy portfolio position symbol is invalid"
            )
        product = match.group(1).lower()
        if product not in _STATIC_CORE_EQUAL_PRODUCTS:
            raise ExecutableTargetAdapterError(
                "strategy portfolio contains a position outside the frozen universe"
            )
        if product in original_symbol_by_product:
            raise ExecutableTargetAdapterError(
                "strategy portfolio has split, hedged, or multi-contract product state"
            )
        original_symbol_by_product[product] = symbol

    try:
        projection = canonical_before_position_projection(
            positions,
            account_scope="account:windows",
            environment="SIMNOW",
        )
    except CommodityExecutionContractError as exc:
        raise ExecutableTargetAdapterError(
            f"strategy portfolio semantics are invalid: {exc}"
        ) from exc
    normalized: dict[str, Any] = {}
    by_product: dict[str, tuple[str, dict[str, Any]]] = {}
    for index, raw in enumerate(projection["positions"]):
        row = _mapping(raw, f"strategy portfolio position[{index}]")
        if row.get("gateway_name") != "CTP":
            raise ExecutableTargetAdapterError(
                "strategy portfolio position gateway is outside CTP"
            )
        canonical_symbol = _require_text(row.get("symbol"), "strategy position symbol")
        match = re.fullmatch(r"([A-Za-z]+)[0-9]{4}", canonical_symbol)
        if match is None:
            raise ExecutableTargetAdapterError(
                "strategy portfolio position symbol is invalid"
            )
        product = match.group(1).lower()
        if product not in _STATIC_CORE_EQUAL_PRODUCTS:
            raise ExecutableTargetAdapterError(
                "strategy portfolio contains a position outside the frozen universe"
            )
        symbol = original_symbol_by_product[product]
        row["symbol"] = symbol
        exchange = _require_text(
            row.get("exchange"), "strategy position exchange"
        ).upper()
        _contract(f"{exchange}.{symbol}")
        key = f"{symbol}.{exchange}.{row['direction']}.CTP.full-portfolio-v1"
        normalized[key] = row
        by_product[product] = (f"{exchange}.{symbol}", row)
    return normalized, by_product


def _full_portfolio_target_positions(
    final_rows: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for product in _STATIC_CORE_EQUAL_PRODUCTS:
        row = final_rows[product]
        quantity = row["target_quantity"]
        exchange, symbol = _contract(row["exact_contract"])
        match = re.fullmatch(r"([A-Za-z]+)[0-9]{4}", symbol)
        if (
            match is None
            or match.group(1).lower() != product
            or exchange != _STATIC_CORE_EQUAL_EXCHANGE_BY_PRODUCT[product]
        ):
            raise ExecutableTargetAdapterError(
                f"STATIC_CORE_EQUAL exact contract does not match product: {product}"
            )
        if quantity == 0:
            continue
        direction = "LONG" if quantity > 0 else "SHORT"
        result[f"{symbol}.{exchange}.{direction}.CTP.full-target-v1"] = {
            "gateway_name": "CTP",
            "symbol": symbol,
            "exchange": exchange,
            "direction": direction,
            "volume": abs(quantity),
        }
    return result


def _full_portfolio_quote_request(
    *,
    exact_contract: str,
    product: str,
    price_side: str,
    expected_price_tick: Any,
) -> FormalTickRequest:
    exchange, symbol = _contract(exact_contract)
    match = re.fullmatch(r"([A-Za-z]+)[0-9]{4}", symbol)
    if (
        product not in _STATIC_CORE_EQUAL_PRODUCTS
        or match is None
        or match.group(1).lower() != product
        or exchange != _STATIC_CORE_EQUAL_EXCHANGE_BY_PRODUCT[product]
        or price_side not in {"bid", "ask"}
    ):
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote request is invalid: {exact_contract}"
        )
    if isinstance(expected_price_tick, bool):
        raise ExecutableTargetAdapterError(
            f"full-portfolio frozen product price tick mismatch: {exact_contract}"
        )
    try:
        return FormalTickRequest(
            vt_symbol=f"{symbol}.{exchange}",
            price_side=price_side,
            price_tick=float(expected_price_tick),
        )
    except (TypeError, ValueError) as exc:
        raise ExecutableTargetAdapterError(
            f"full-portfolio frozen product price tick mismatch: {exact_contract}"
        ) from exc


def _full_portfolio_formal_quote(
    values: Mapping[str, Any] | None,
    *,
    exact_contract: str,
    product: str,
    price_side: str,
    expected_price_tick: Any,
    now: datetime,
    requirements_only: bool = False,
    adverse_cushion_ticks: int = 0,
) -> tuple[float, dict[str, Any], FormalTickRequest]:
    request = _full_portfolio_quote_request(
        exact_contract=exact_contract,
        product=product,
        price_side=price_side,
        expected_price_tick=expected_price_tick,
    )
    if requirements_only:
        return request.price_tick, {}, request
    if (
        isinstance(adverse_cushion_ticks, bool)
        or not isinstance(adverse_cushion_ticks, int)
        or adverse_cushion_ticks < 0
    ):
        raise ExecutableTargetAdapterError(
            f"full-portfolio adverse cushion is invalid: {exact_contract}"
        )
    if not isinstance(values, Mapping):
        raise ExecutableTargetAdapterError(
            "full-portfolio formal quote bindings must be an object"
        )
    if exact_contract not in values:
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote is missing: {exact_contract}"
        )
    quote = values[exact_contract]
    fields = {
        "source",
        "vt_symbol",
        "price_side",
        "stream_generation",
        "ingest_id",
        "ingest_seq",
        "event_hash",
        "received_at_utc",
        "reference_price",
        "price_tick",
    }
    if not isinstance(quote, Mapping) or set(quote) != fields:
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote binding is invalid: {exact_contract}"
        )
    exchange, symbol = _contract(exact_contract)
    if (
        quote.get("source") != "windows-tick-wire-v1"
        or quote.get("vt_symbol") != request.vt_symbol
        or quote.get("price_side") != request.price_side
    ):
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote identity is invalid: {exact_contract}"
        )
    for field in ("stream_generation", "ingest_id"):
        _require_text(quote.get(field), f"formal quote {field}")
    ingest_seq = quote.get("ingest_seq")
    if (
        isinstance(ingest_seq, bool)
        or not isinstance(ingest_seq, int)
        or ingest_seq < 1
    ):
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote sequence is invalid: {exact_contract}"
        )
    _sha(quote.get("event_hash"), "formal quote event hash")
    received_at = quote.get("received_at_utc")
    if not isinstance(received_at, str) or not received_at.endswith("Z"):
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote timestamp is invalid: {exact_contract}"
        )
    try:
        observed = datetime.fromisoformat(received_at[:-1] + "+00:00")
    except ValueError as exc:
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote timestamp is invalid: {exact_contract}"
        ) from exc
    if observed.utcoffset() != timezone.utc.utcoffset(observed):
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote timestamp is invalid: {exact_contract}"
        )
    age = (now - observed).total_seconds()
    if (
        age > V3_FORMAL_QUOTE_MAX_AGE_SECONDS
        or age < -_FULL_PORTFOLIO_QUOTE_FUTURE_SKEW_SECONDS
    ):
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote is stale or from the future: {exact_contract}"
        )
    if isinstance(quote["price_tick"], bool) or isinstance(expected_price_tick, bool):
        raise ExecutableTargetAdapterError(
            f"full-portfolio frozen product price tick mismatch: {exact_contract}"
        )
    try:
        quote_tick = Decimal(str(quote["price_tick"]))
        frozen_tick = Decimal(str(request.price_tick))
        reference = Decimal(str(quote["reference_price"]))
    except (InvalidOperation, ValueError) as exc:
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote price is invalid: {exact_contract}"
        ) from exc
    if (
        not quote_tick.is_finite()
        or quote_tick <= 0
        or not frozen_tick.is_finite()
        or frozen_tick <= 0
        or quote_tick != frozen_tick
    ):
        raise ExecutableTargetAdapterError(
            f"full-portfolio frozen product price tick mismatch: {exact_contract}"
        )
    try:
        reference = normalize_near_grid_price(reference, tick=frozen_tick)
    except ValueError as exc:
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote price is invalid: {exact_contract}"
        ) from exc
    if reference <= 0:
        raise ExecutableTargetAdapterError(
            f"full-portfolio formal quote price is invalid: {exact_contract}"
        )
    protected_steps = 1 + adverse_cushion_ticks
    protected = (
        reference + frozen_tick * protected_steps
        if price_side == "ask"
        else reference - frozen_tick * protected_steps
    )
    try:
        protected = normalize_near_grid_price(protected, tick=frozen_tick)
    except ValueError as exc:  # pragma: no cover - protected derives from grid values
        raise ExecutableTargetAdapterError(
            f"full-portfolio protected limit price is invalid: {exact_contract}"
        ) from exc
    if protected <= 0:
        raise ExecutableTargetAdapterError(
            f"full-portfolio protected limit price is invalid: {exact_contract}"
        )
    return (
        float(protected),
        _mapping(
            {**quote, "reference_price": float(reference)},
            "full-portfolio formal quote binding",
        ),
        request,
    )


def _simnow_experimental_adverse_cushion_ticks(
    *, run_id: str, product: str
) -> int:
    """Return the fixed experimental budget, never an operator-supplied value."""

    try:
        return simnow_experimental_adverse_cushion_ticks(
            execution_run_id=run_id,
            symbol=f"{product}0000",
        )
    except CommodityExecutionContractError as exc:  # pragma: no cover - frozen caller
        raise ExecutableTargetAdapterError(
            "SIMNOW_EXPERIMENTAL product is outside the frozen universe"
        ) from exc


def full_portfolio_phase_plan_id_from_preimage(
    value: Mapping[str, Any],
) -> str:
    """Reproduce one historical v2 plan ID from its canonical preimage."""

    preimage = _mapping(value, "full-portfolio phase identity preimage")
    phase = preimage.get("phase")
    if (
        set(preimage) != _FULL_PORTFOLIO_IDENTITY_FIELDS
        or preimage.get("identity_schema_version")
        != _FULL_PORTFOLIO_IDENTITY_SCHEMA_VERSION
        or preimage.get("strategy_id") != "STATIC_CORE_EQUAL"
        or phase not in {"CLOSE", "OPEN"}
        or preimage.get("account_scope") != "account:windows"
        or preimage.get("environment") != "SIMNOW"
        or preimage.get("gateway_name") != "CTP"
        or preimage.get("scope") != dict(TRUSTED_KEYLESS_SIMNOW_SCOPE)
    ):
        raise ExecutableTargetAdapterError(
            "full-portfolio phase identity preimage is invalid"
        )
    return f"static-core-full-{str(phase).lower()}-v2-{sha256_json(preimage)}"


def full_portfolio_phase_plan_id_from_payload(
    value: Mapping[str, Any],
) -> str:
    """Reproduce one v3 full-portfolio ID from its persisted payload."""

    try:
        return trusted_keyless_target_plan_v3_plan_id(value)
    except CommodityExecutionContractError as exc:
        raise ExecutableTargetAdapterError(
            "full-portfolio phase target-plan identity is invalid"
        ) from exc


def _full_portfolio_plan_handoff(
    *,
    phase: str,
    run_id: str,
    orders: list[dict[str, Any]],
    expected_before_position_hash: str,
    expected_after_position_hash: str,
    static_core_equal_sha256: str,
    position_manager_sha256: str,
    final_target_sha256: str,
    formal_quote_bindings: Mapping[str, Any],
    quote_validated_at: str,
    target_plan_version: int,
    generated_at: str,
    expires_at: str,
) -> StaticCoreEqualFullPortfolioPhaseHandoff:
    if type(target_plan_version) is not int or target_plan_version not in {2, 3}:
        raise ExecutableTargetAdapterError(
            "full-portfolio target plan version is invalid"
        )
    lineage = {
        "static_core_equal_sha256": static_core_equal_sha256,
        "position_manager_sha256": position_manager_sha256,
        "final_target_sha256": final_target_sha256,
    }
    if target_plan_version == 2:
        identity_preimage = _mapping(
            {
                "identity_schema_version": _FULL_PORTFOLIO_IDENTITY_SCHEMA_VERSION,
                "strategy_id": "STATIC_CORE_EQUAL",
                "run_id": run_id,
                "phase": phase,
                "account_scope": "account:windows",
                "environment": "SIMNOW",
                "gateway_name": "CTP",
                "scope": dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
                "lineage": lineage,
                "expected_before_position_hash": expected_before_position_hash,
                "expected_after_position_hash": expected_after_position_hash,
                "orders": orders,
                "formal_quote_bindings": dict(formal_quote_bindings),
                "generated_at": generated_at,
                "expires_at": expires_at,
            },
            "full-portfolio phase identity preimage",
        )
        plan_id = full_portfolio_phase_plan_id_from_preimage(identity_preimage)
        try:
            plan = build_trusted_keyless_target_plan_v2(
                plan_id=plan_id,
                account_scope="account:windows",
                environment="SIMNOW",
                gateway_name="CTP",
                lineage=_mapping(lineage, "phase lineage"),
                scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
                generated_at=generated_at,
                expires_at=expires_at,
                phase=phase,
                expected_before_position_hash=expected_before_position_hash,
                expected_after_position_hash=expected_after_position_hash,
                orders=orders,
            )
        except CommodityExecutionContractError as exc:
            raise ExecutableTargetAdapterError(
                f"STATIC_CORE_EQUAL full-portfolio {phase} TargetPlan v2 is invalid: {exc}"
            ) from exc
        return StaticCoreEqualFullPortfolioPhaseHandoff(
            target_plan=plan,
            lineage=(
                static_core_equal_sha256,
                position_manager_sha256,
                final_target_sha256,
            ),
            scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
            expires_at=str(plan["expires_at"]),
            identity_preimage=identity_preimage,
        )
    creation_quote_proof = {
        "schema_version": FORMAL_QUOTE_PROOF_SCHEMA_VERSION,
        "validated_at_utc": quote_validated_at,
        "max_age_seconds": V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
        "future_skew_seconds": _FULL_PORTFOLIO_QUOTE_FUTURE_SKEW_SECONDS,
        # This foundation retains deterministic creation evidence only.  A
        # later Execution admission must authenticate it against the journal
        # and obtain an independent fresh start proof.
        "journal_authenticated": False,
        "start_authorized": False,
        "bindings": dict(formal_quote_bindings),
    }
    try:
        plan = build_trusted_keyless_target_plan_v3(
            execution_run_id=run_id,
            account_scope="account:windows",
            environment="SIMNOW",
            gateway_name="CTP",
            lineage=_mapping(lineage, "phase lineage"),
            scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
            creation_quote_proof=creation_quote_proof,
            generated_at=generated_at,
            expires_at=expires_at,
            phase=phase,
            expected_before_position_hash=expected_before_position_hash,
            expected_after_position_hash=expected_after_position_hash,
            orders=orders,
        )
    except CommodityExecutionContractError as exc:
        raise ExecutableTargetAdapterError(
            f"STATIC_CORE_EQUAL full-portfolio {phase} TargetPlan v3 is invalid: {exc}"
        ) from exc
    return StaticCoreEqualFullPortfolioPhaseHandoff(
        target_plan=plan,
        lineage=(
            static_core_equal_sha256,
            position_manager_sha256,
            final_target_sha256,
        ),
        scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
        expires_at=str(plan["expires_at"]),
    )


def _full_portfolio_deferred_open_intent(
    *,
    run_id: str,
    static_core_equal_sha256: str,
    position_manager_sha256: str,
    final_target_sha256: str,
    expected_post_close_before_position_hash: str,
    expected_final_position_hash: str,
    event_generated_at: str,
    intents: list[dict[str, Any]],
) -> StaticCoreEqualDeferredOpenIntent:
    core = _mapping(
        {
            "schema_version": "commodity_static_core_equal_deferred_open_intent_v1",
            "strategy_id": "STATIC_CORE_EQUAL",
            "run_id": run_id,
            "static_core_equal_sha256": static_core_equal_sha256,
            "position_manager_sha256": position_manager_sha256,
            "final_target_sha256": final_target_sha256,
            "expected_post_close_before_position_hash": (
                expected_post_close_before_position_hash
            ),
            "expected_final_position_hash": expected_final_position_hash,
            "event_generated_at": event_generated_at,
            "custody_allowed": False,
            "executable": False,
            "intents": intents,
        },
        "STATIC_CORE_EQUAL deferred OPEN intent",
    )
    template = {
        **core,
        "intent_id": f"static-core-deferred-open-v1-{sha256_json(core)}",
    }
    return StaticCoreEqualDeferredOpenIntent(
        template=_mapping(template, "STATIC_CORE_EQUAL deferred OPEN intent")
    )


def _build_static_core_equal_full_portfolio(
    *,
    static_core_equal_projection: Mapping[str, Any],
    static_core_equal_freeze_contract: Mapping[str, Any],
    static_core_equal_target_evidence: Mapping[str, Any],
    position_manager_snapshot: Mapping[str, Any],
    position_manager_sha256: str,
    current_facts: GatewaySnapshot,
    reconciliation: Mapping[str, Any],
    formal_quotes_by_exact_contract: Mapping[str, Any] | None,
    run_id: str,
    event_generated_at: str,
    expires_at: str | None = None,
    now: datetime | None = None,
    target_plan_version: int = 2,
    requirements_only: bool = False,
    quote_requirements: StaticCoreEqualFullPortfolioQuoteRequirements | None = None,
) -> (
    StaticCoreEqualFullPortfolioDecision | StaticCoreEqualFullPortfolioQuoteRequirements
):
    """Build at most one immutable phase plan for the complete portfolio.

    The caller must prove that the complete account portfolio is owned by the
    last completed strategy target before invoking this pure planner.  This
    function does not accept a completion receipt and must not be used to infer
    ownership or authorize recovery.  Every mutating plan is bound to exact
    source-fenced formal bid/ask evidence.  If CLOSE is required, any following
    OPEN is emitted only as a non-custody template; a second invocation with
    fresh post-close facts and quotes is required to create the OPEN plan.  A
    true NOOP does not consume quote, expiry or any other mutation-only material.
    The production caller remains on historical v2 by default.  Quote-aware
    v3 is an explicit foundation-only opt-in until Execution gains independent
    journal authentication and fresh start admission.
    """

    if requirements_only:
        if quote_requirements is not None:
            raise ExecutableTargetAdapterError(
                "quote-only planning cannot consume quote requirements"
            )
    elif type(quote_requirements) is not StaticCoreEqualFullPortfolioQuoteRequirements:
        raise ExecutableTargetAdapterError(
            "full-portfolio quote requirements are required"
        )
    if type(target_plan_version) is not int or target_plan_version not in {2, 3}:
        raise ExecutableTargetAdapterError(
            "full-portfolio target-plan version is invalid"
        )

    normalized_run_id = _require_text(run_id, "run id")
    if _RUN_ID.fullmatch(normalized_run_id) is None:
        raise ExecutableTargetAdapterError("run id is invalid")
    current_time = utc_now() if now is None else now
    if (
        current_time.tzinfo is None
        or current_time.utcoffset() != timezone.utc.utcoffset(current_time)
    ):
        raise ExecutableTargetAdapterError("adapter clock must be explicit UTC")
    quote_validated_at = current_time.isoformat().replace("+00:00", "Z")
    if not isinstance(event_generated_at, str) or not event_generated_at.endswith("Z"):
        raise ExecutableTargetAdapterError("event generated_at is invalid")
    try:
        normalized_event_generated_at = datetime.fromisoformat(
            event_generated_at[:-1] + "+00:00"
        )
    except ValueError as exc:
        raise ExecutableTargetAdapterError("event generated_at is invalid") from exc
    if (
        normalized_event_generated_at.utcoffset()
        != timezone.utc.utcoffset(normalized_event_generated_at)
        or (normalized_event_generated_at - current_time).total_seconds()
        > _FULL_PORTFOLIO_QUOTE_FUTURE_SKEW_SECONDS
    ):
        raise ExecutableTargetAdapterError("event generated_at is invalid")

    static_sha256, static_rows, static_execution_day = _static_core_equal_outputs(
        producer_projection=static_core_equal_projection,
        freeze_contract=static_core_equal_freeze_contract,
        target_evidence=static_core_equal_target_evidence,
    )
    static_freeze_sha256 = sha256_json(
        _mapping(
            static_core_equal_freeze_contract,
            "STATIC_CORE_EQUAL freeze contract",
        )
    )
    static_target_sha256 = sha256_json(
        _mapping(
            static_core_equal_target_evidence,
            "STATIC_CORE_EQUAL target evidence",
        )
    )
    final_projection, final_rows = _position_manager_final_projection(
        snapshot=position_manager_snapshot,
        expected_sha256=position_manager_sha256,
        static_rows=static_rows,
        static_execution_day=static_execution_day,
    )
    normalized_position_manager_sha256 = _sha(
        position_manager_sha256, "position-manager snapshot hash"
    )
    final_target_sha256 = sha256_json(final_projection)
    positions = _validate_snapshot(
        current_facts,
        account_scope="account:windows",
        environment="SIMNOW",
        reconciliation=reconciliation,
    )
    reconciliation_sha256 = sha256_json(
        _mapping(reconciliation, "full-portfolio reconciliation")
    )
    current_positions, current_by_product = _canonical_strategy_portfolio_positions(
        positions
    )
    for product, (current_contract, _current_row) in current_by_product.items():
        current_exchange, _current_symbol = _contract(current_contract)
        target_exchange, _target_symbol = _contract(
            final_rows[product]["exact_contract"]
        )
        expected_exchange = _STATIC_CORE_EQUAL_EXCHANGE_BY_PRODUCT[product]
        if (
            current_exchange != expected_exchange
            or target_exchange != expected_exchange
        ):
            raise ExecutableTargetAdapterError(
                "strategy portfolio product is on an unexpected exchange"
            )
    expected_target_positions = _full_portfolio_target_positions(final_rows)
    current_before_position_hash = before_position_projection_hash(
        current_positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    current_target_position_hash = target_position_projection_hash(
        current_positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    final_position_hash = target_position_projection_hash(
        expected_target_positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )

    close_orders: list[dict[str, Any]] = []
    close_formal_quote_bindings: dict[str, Any] = {}
    close_quote_uses: list[tuple[str, str, FormalTickRequest, str]] = []
    after_close = current_positions
    for product in _STATIC_CORE_EQUAL_PRODUCTS:
        after_close, current_by_product = _canonical_strategy_portfolio_positions(
            after_close
        )
        current = current_by_product.get(product)
        if current is None:
            continue
        current_contract, current_row = current
        current_quantity = (
            current_row["volume"]
            if current_row["direction"] == "LONG"
            else -current_row["volume"]
        )
        target = final_rows[product]
        target_quantity = target["target_quantity"]
        same_contract = current_contract.upper() == target["exact_contract"].upper()
        if (
            not same_contract
            or target_quantity == 0
            or current_quantity * target_quantity < 0
        ):
            close_count = abs(current_quantity)
        elif abs(current_quantity) > abs(target_quantity):
            close_count = abs(current_quantity) - abs(target_quantity)
        else:
            close_count = 0
        for child_index in range(1, close_count + 1):
            exchange, symbol = _contract(current_contract)
            _long, _short, matching = _current_contract_positions(
                after_close,
                exchange=exchange,
                symbol=symbol,
                gateway_name="CTP",
            )
            direction = "SHORT" if current_quantity > 0 else "LONG"
            offset = _close_order_offset(
                matching,
                exchange=exchange,
                direction=direction,
            )
            price_side = "ask" if direction == "LONG" else "bid"
            price, formal_quote_binding, formal_tick_request = (
                _full_portfolio_formal_quote(
                    formal_quotes_by_exact_contract,
                    exact_contract=current_contract,
                    product=product,
                    price_side=price_side,
                    expected_price_tick=target["price_tick"],
                    now=current_time,
                    requirements_only=requirements_only,
                    adverse_cushion_ticks=(
                        _simnow_experimental_adverse_cushion_ticks(
                            run_id=normalized_run_id, product=product
                        )
                    ),
                )
            )
            close_formal_quote_bindings.setdefault(
                current_contract, formal_quote_binding
            )
            reference = sha256_json(
                {
                    "strategy_id": "STATIC_CORE_EQUAL",
                    "run_id": normalized_run_id,
                    "phase": "CLOSE",
                    "product": product,
                    "exact_contract": current_contract,
                    "child_index": child_index,
                }
            )
            close_quote_uses.append(
                (product, current_contract, formal_tick_request, reference)
            )
            close_orders.append(
                {
                    "symbol": symbol,
                    "exchange": exchange,
                    "direction": direction,
                    "type": "LIMIT",
                    "volume": 1,
                    "price": price,
                    "offset": offset,
                    "reference": reference,
                    "gateway_name": "CTP",
                }
            )
            after_close = _after_safety_flat_close(
                after_close,
                matching,
                direction=direction,
                offset=offset,
            )

    after_close, _boundary_by_product = _canonical_strategy_portfolio_positions(
        after_close
    )
    boundary_target_projection = canonical_target_position_projection(
        after_close,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    boundary_before_projection = canonical_before_position_projection(
        after_close,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    close_expected_after = sha256_json(boundary_target_projection)
    open_expected_before = sha256_json(boundary_before_projection)
    boundary = StaticCoreEqualPhaseBoundary(
        positions=_mapping(after_close, "STATIC_CORE_EQUAL phase boundary"),
        target_projection=_mapping(
            boundary_target_projection,
            "STATIC_CORE_EQUAL phase boundary target projection",
        ),
        before_projection=_mapping(
            boundary_before_projection,
            "STATIC_CORE_EQUAL phase boundary before projection",
        ),
        close_expected_after_position_hash=close_expected_after,
        open_expected_before_position_hash=open_expected_before,
    )

    open_intents: list[dict[str, Any]] = []
    after_open = after_close
    for product in _STATIC_CORE_EQUAL_PRODUCTS:
        after_open, current_by_product = _canonical_strategy_portfolio_positions(
            after_open
        )
        current = current_by_product.get(product)
        current_quantity = 0
        if current is not None:
            current_contract, current_row = current
            if (
                current_contract.upper()
                != final_rows[product]["exact_contract"].upper()
            ):
                raise ExecutableTargetAdapterError(
                    "post-close portfolio retains a stale exact contract"
                )
            current_quantity = (
                current_row["volume"]
                if current_row["direction"] == "LONG"
                else -current_row["volume"]
            )
        target = final_rows[product]
        target_quantity = target["target_quantity"]
        delta = target_quantity - current_quantity
        if delta == 0:
            continue
        if current_quantity and current_quantity * target_quantity <= 0:
            raise ExecutableTargetAdapterError(
                "post-close portfolio has an unresolved direction reversal"
            )
        exchange, symbol = _contract(target["exact_contract"])
        direction = "LONG" if delta > 0 else "SHORT"
        price_side = "ask" if direction == "LONG" else "bid"
        open_intents.append(
            {
                "product": product,
                "exact_contract": target["exact_contract"],
                "direction": direction,
                "volume": abs(delta),
                "price_side": price_side,
                "frozen_product_price_tick": target["price_tick"],
            }
        )
        _long, _short, matching = _current_contract_positions(
            after_open,
            exchange=exchange,
            symbol=symbol,
            gateway_name="CTP",
        )
        after_open = _after_positions(
            after_open,
            matching,
            exchange=exchange,
            symbol=symbol,
            gateway_name="CTP",
            direction=direction,
            offset="OPEN",
            quantity=abs(delta),
        )
        if exchange in _CLOSE_OFFSET_EXCHANGES:
            detached_after_open = _mapping(
                after_open, "STATIC_CORE_EQUAL post-open positions"
            )
            for key, raw in detached_after_open.items():
                if (
                    str(raw.get("symbol", "")).upper() == symbol.upper()
                    and str(raw.get("exchange", "")).upper() == exchange
                    and str(raw.get("direction", "")).upper() == direction
                    and raw.get("volume", 0) > 0
                ):
                    raw.setdefault("yd_volume", 0)
                    detached_after_open[key] = raw
            after_open = detached_after_open

    after_open, _final_by_product = _canonical_strategy_portfolio_positions(after_open)
    actual_final_position_hash = target_position_projection_hash(
        after_open,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    if actual_final_position_hash != final_position_hash:
        raise ExecutableTargetAdapterError(
            "full-portfolio planner did not converge to the complete final target"
        )

    open_orders: list[dict[str, Any]] = []
    open_formal_quote_bindings: dict[str, Any] = {}
    open_quote_uses: list[tuple[str, str, FormalTickRequest, str]] = []
    deferred_open_intent = None
    if close_orders and open_intents:
        deferred_open_intent = _full_portfolio_deferred_open_intent(
            run_id=normalized_run_id,
            static_core_equal_sha256=static_sha256,
            position_manager_sha256=normalized_position_manager_sha256,
            final_target_sha256=final_target_sha256,
            expected_post_close_before_position_hash=open_expected_before,
            expected_final_position_hash=final_position_hash,
            event_generated_at=event_generated_at,
            intents=open_intents,
        )
    elif open_intents:
        for intent in open_intents:
            product = str(intent["product"])
            exact_contract = str(intent["exact_contract"])
            direction = str(intent["direction"])
            price_side = str(intent["price_side"])
            exchange, symbol = _contract(exact_contract)
            price, formal_quote_binding, formal_tick_request = (
                _full_portfolio_formal_quote(
                    formal_quotes_by_exact_contract,
                    exact_contract=exact_contract,
                    product=product,
                    price_side=price_side,
                    expected_price_tick=intent["frozen_product_price_tick"],
                    now=current_time,
                    requirements_only=requirements_only,
                    adverse_cushion_ticks=(
                        _simnow_experimental_adverse_cushion_ticks(
                            run_id=normalized_run_id, product=product
                        )
                    ),
                )
            )
            open_formal_quote_bindings.setdefault(exact_contract, formal_quote_binding)
            for child_index in range(1, int(intent["volume"]) + 1):
                reference = sha256_json(
                    {
                        "strategy_id": "STATIC_CORE_EQUAL",
                        "run_id": normalized_run_id,
                        "phase": "OPEN",
                        "product": product,
                        "exact_contract": exact_contract,
                        "child_index": child_index,
                    }
                )
                open_quote_uses.append(
                    (product, exact_contract, formal_tick_request, reference)
                )
                open_orders.append(
                    {
                        "symbol": symbol,
                        "exchange": exchange,
                        "direction": direction,
                        "type": "LIMIT",
                        "volume": 1,
                        "price": price,
                        "offset": "OPEN",
                        "reference": reference,
                        "gateway_name": "CTP",
                    }
                )

    decision_fields = {
        "close_handoff": None,
        "open_handoff": None,
        "deferred_open_intent": deferred_open_intent,
        "phase_boundary": boundary,
        "static_core_equal_sha256": static_sha256,
        "position_manager_sha256": normalized_position_manager_sha256,
        "final_target_sha256": final_target_sha256,
        "final_target_projection": final_projection,
        "current_before_position_hash": current_before_position_hash,
        "current_target_position_hash": current_target_position_hash,
        "final_position_hash": final_position_hash,
        "close_formal_quote_bindings": close_formal_quote_bindings,
        "open_formal_quote_bindings": open_formal_quote_bindings,
        "close_order_count": len(close_orders),
        "open_order_count": len(open_orders),
        "deferred_open_order_count": (
            deferred_open_intent.order_count if deferred_open_intent is not None else 0
        ),
    }
    selected_phase = (
        "CLOSE" if close_quote_uses else ("OPEN" if open_quote_uses else None)
    )
    selected_uses = close_quote_uses if close_quote_uses else open_quote_uses
    by_contract: dict[str, tuple[str, FormalTickRequest, list[str]]] = {}
    for product, exact_contract, request, reference in selected_uses:
        prior = by_contract.get(exact_contract)
        if prior is None:
            by_contract[exact_contract] = (product, request, [reference])
            continue
        prior_product, prior_request, references = prior
        if prior_product != product or prior_request != request:
            raise ExecutableTargetAdapterError(
                "full-portfolio quote requirements conflict"
            )
        references.append(reference)
    computed_quote_requirements = StaticCoreEqualFullPortfolioQuoteRequirements(
        phase=selected_phase,
        requirements=tuple(
            StaticCoreEqualFullPortfolioQuoteRequirement(
                phase=str(selected_phase),
                product=product,
                exact_contract=exact_contract,
                request=request,
                order_references=tuple(references),
            )
            for exact_contract, (product, request, references) in sorted(
                by_contract.items()
            )
        ),
        deferred_open_order_count=(
            deferred_open_intent.order_count if deferred_open_intent is not None else 0
        ),
        input_binding=StaticCoreEqualFullPortfolioQuoteInputBinding(
            static_core_equal_projection_sha256=static_sha256,
            static_core_equal_freeze_contract_sha256=static_freeze_sha256,
            static_core_equal_target_evidence_sha256=static_target_sha256,
            position_manager_sha256=normalized_position_manager_sha256,
            current_before_position_hash=current_before_position_hash,
            desired_target_sha256=final_target_sha256,
            reconciliation_sha256=reconciliation_sha256,
            phase_boundary_sha256=sha256_json(
                {
                    "positions": boundary.positions,
                    "target_projection": boundary.target_projection,
                    "before_projection": boundary.before_projection,
                    "close_expected_after_position_hash": (
                        boundary.close_expected_after_position_hash
                    ),
                    "open_expected_before_position_hash": (
                        boundary.open_expected_before_position_hash
                    ),
                }
            ),
            deferred_open_intent_sha256=(
                sha256_json(deferred_open_intent.template)
                if deferred_open_intent is not None
                else None
            ),
            run_id=normalized_run_id,
            event_generated_at=event_generated_at,
            target_plan_version=target_plan_version,
        ),
    )
    if requirements_only:
        return computed_quote_requirements
    if quote_requirements != computed_quote_requirements:
        raise ExecutableTargetAdapterError(
            "full-portfolio quote requirements do not match planner inputs"
        )

    required_quote_contracts = {
        row.exact_contract for row in computed_quote_requirements.requirements
    }
    if (
        not isinstance(formal_quotes_by_exact_contract, Mapping)
        or set(formal_quotes_by_exact_contract) != required_quote_contracts
    ):
        raise ExecutableTargetAdapterError(
            "full-portfolio formal quote contract set is not exact"
        )
    if not close_orders and not open_orders and deferred_open_intent is None:
        return StaticCoreEqualFullPortfolioDecision(**decision_fields)
    if not isinstance(expires_at, str) or not expires_at.endswith("Z"):
        raise ExecutableTargetAdapterError("trusted keyless expiry is invalid")
    try:
        normalized_expiry = datetime.fromisoformat(expires_at[:-1] + "+00:00")
    except ValueError as exc:
        raise ExecutableTargetAdapterError("trusted keyless expiry is invalid") from exc
    if (
        normalized_expiry.utcoffset() != timezone.utc.utcoffset(normalized_expiry)
        or normalized_expiry <= current_time
        or normalized_expiry <= normalized_event_generated_at
    ):
        raise ExecutableTargetAdapterError("trusted keyless expiry is invalid")

    close_handoff = (
        _full_portfolio_plan_handoff(
            phase="CLOSE",
            run_id=normalized_run_id,
            orders=close_orders,
            expected_before_position_hash=current_before_position_hash,
            expected_after_position_hash=close_expected_after,
            static_core_equal_sha256=static_sha256,
            position_manager_sha256=normalized_position_manager_sha256,
            final_target_sha256=final_target_sha256,
            formal_quote_bindings=close_formal_quote_bindings,
            quote_validated_at=quote_validated_at,
            target_plan_version=target_plan_version,
            generated_at=event_generated_at,
            expires_at=expires_at,
        )
        if close_orders
        else None
    )
    open_handoff = (
        _full_portfolio_plan_handoff(
            phase="OPEN",
            run_id=normalized_run_id,
            orders=open_orders,
            expected_before_position_hash=open_expected_before,
            expected_after_position_hash=final_position_hash,
            static_core_equal_sha256=static_sha256,
            position_manager_sha256=normalized_position_manager_sha256,
            final_target_sha256=final_target_sha256,
            formal_quote_bindings=open_formal_quote_bindings,
            quote_validated_at=quote_validated_at,
            target_plan_version=target_plan_version,
            generated_at=event_generated_at,
            expires_at=expires_at,
        )
        if open_orders
        else None
    )
    decision_fields["close_handoff"] = close_handoff
    decision_fields["open_handoff"] = open_handoff
    return StaticCoreEqualFullPortfolioDecision(**decision_fields)


def build_full_portfolio_quote_requests(
    *,
    static_core_equal_projection: Mapping[str, Any],
    static_core_equal_freeze_contract: Mapping[str, Any],
    static_core_equal_target_evidence: Mapping[str, Any],
    position_manager_snapshot: Mapping[str, Any],
    position_manager_sha256: str,
    current_facts: GatewaySnapshot,
    reconciliation: Mapping[str, Any],
    run_id: str,
    event_generated_at: str,
    now: datetime | None = None,
    target_plan_version: int = 2,
) -> StaticCoreEqualFullPortfolioQuoteRequirements:
    """Return the exact formal-tick batch for the immediate executable phase.

    This is the same pure delta/phase path used by the final planner.  It reads
    no quote, performs no I/O or mutation, and never exposes deferred OPEN as a
    current request.  Callers may materialize ``result.requests`` with the one
    formal batch reader, key the returned bindings by ``exact_contract``, and
    pass that exact mapping to the final planner.
    """

    result = _build_static_core_equal_full_portfolio(
        static_core_equal_projection=static_core_equal_projection,
        static_core_equal_freeze_contract=static_core_equal_freeze_contract,
        static_core_equal_target_evidence=static_core_equal_target_evidence,
        position_manager_snapshot=position_manager_snapshot,
        position_manager_sha256=position_manager_sha256,
        current_facts=current_facts,
        reconciliation=reconciliation,
        formal_quotes_by_exact_contract=None,
        run_id=run_id,
        event_generated_at=event_generated_at,
        now=now,
        target_plan_version=target_plan_version,
        requirements_only=True,
    )
    if not isinstance(result, StaticCoreEqualFullPortfolioQuoteRequirements):
        raise ExecutableTargetAdapterError(
            "full-portfolio quote requirements were not produced"
        )
    return result


def build_static_core_equal_full_portfolio_keyless_decision(
    *,
    static_core_equal_projection: Mapping[str, Any],
    static_core_equal_freeze_contract: Mapping[str, Any],
    static_core_equal_target_evidence: Mapping[str, Any],
    position_manager_snapshot: Mapping[str, Any],
    position_manager_sha256: str,
    current_facts: GatewaySnapshot,
    reconciliation: Mapping[str, Any],
    quote_requirements: StaticCoreEqualFullPortfolioQuoteRequirements,
    formal_quotes_by_exact_contract: Mapping[str, Any] | None,
    run_id: str,
    event_generated_at: str,
    expires_at: str | None = None,
    now: datetime | None = None,
    target_plan_version: int = 2,
) -> StaticCoreEqualFullPortfolioDecision:
    """Build at most one immutable phase plan for the complete portfolio."""

    result = _build_static_core_equal_full_portfolio(
        static_core_equal_projection=static_core_equal_projection,
        static_core_equal_freeze_contract=static_core_equal_freeze_contract,
        static_core_equal_target_evidence=static_core_equal_target_evidence,
        position_manager_snapshot=position_manager_snapshot,
        position_manager_sha256=position_manager_sha256,
        current_facts=current_facts,
        reconciliation=reconciliation,
        formal_quotes_by_exact_contract=formal_quotes_by_exact_contract,
        run_id=run_id,
        event_generated_at=event_generated_at,
        expires_at=expires_at,
        now=now,
        target_plan_version=target_plan_version,
        requirements_only=False,
        quote_requirements=quote_requirements,
    )
    if not isinstance(result, StaticCoreEqualFullPortfolioDecision):
        raise ExecutableTargetAdapterError(
            "full-portfolio target-plan decision was not produced"
        )
    return result


def build_static_core_equal_keyless_safety_flat_decision(
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
    safety_flat_limit_price: float,
    now: datetime | None = None,
) -> StaticCoreEqualKeylessDecision:
    """Build the formal, selected-product-only SAFETY FLAT TargetPlan v2.

    The full STATIC_CORE_EQUAL/thermostat target remains verified and hashed
    before selecting the execution product.  This path never changes that
    strategy target: it can only derive a zero target from the fresh current
    position for the selected, minimum nonzero strategy product.  It therefore
    cannot open, reverse, resize, or close an unrelated position.
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
        item
        for item in _STATIC_CORE_EQUAL_PRODUCTS
        if final_rows[item]["target_quantity"] != 0
    )
    minimum_target_quantity = min(
        (abs(final_rows[item]["target_quantity"]) for item in eligible_products),
        default=None,
    )
    minimum_target_products = tuple(
        item
        for item in eligible_products
        if abs(final_rows[item]["target_quantity"]) == minimum_target_quantity
    )
    selected = final_rows[normalized_product]
    target_quantity = selected["target_quantity"]
    protected_limit_price = _reduce_only_limit_price(
        safety_flat_limit_price, price_tick=selected["price_tick"]
    )
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
    if not minimum_target_products:
        return StaticCoreEqualKeylessDecision(
            handoff=None,
            current_quantity=None,
            stop_reason="no_nonzero_target",
            **source_decision_fields,
        )
    if normalized_product not in minimum_target_products:
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
    decision_fields = {
        **source_decision_fields,
        "current_quantity": current_quantity,
        "stop_reason": None,
    }
    if current_quantity != target_quantity:
        raise ExecutableTargetAdapterError(
            "SAFETY FLAT requires the exact selected strategy target position"
        )
    gross_position_volume = sum(
        int(row.get("volume", 0))
        for row in positions.values()
        if isinstance(row, Mapping)
    )
    if gross_position_volume == 0:
        if positions:
            raise ExecutableTargetAdapterError("SAFETY FLAT positions are invalid")
        return StaticCoreEqualKeylessDecision(handoff=None, **decision_fields)
    if (
        len(positions) != 1
        or len(matching) != 1
        or long_volume + short_volume != gross_position_volume
        or (long_volume > 0 and short_volume > 0)
        or current_quantity == 0
    ):
        raise ExecutableTargetAdapterError(
            "SAFETY FLAT requires one directional selected-product position"
        )

    expected_before = before_position_projection_hash(
        positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    direction = "SHORT" if long_volume else "LONG"
    child_count = abs(current_quantity)
    working_positions = _mapping(positions, "current positions")
    offsets: list[str] = []
    for _child_index in range(1, child_count + 1):
        _working_long, _working_short, working_matching = _current_contract_positions(
            working_positions,
            exchange=exchange,
            symbol=symbol,
            gateway_name="CTP",
        )
        offset = _close_order_offset(
            working_matching, exchange=exchange, direction=direction
        )
        if offset not in _CLOSE_ORDER_OFFSETS:  # pragma: no cover - defensive
            raise ExecutableTargetAdapterError("SAFETY FLAT would not close")
        working_positions = _after_safety_flat_close(
            working_positions,
            working_matching,
            direction=direction,
            offset=offset,
        )
        offsets.append(offset)
    expected_after = target_position_projection_hash(
        working_positions,
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
            "mode": "SAFETY_FLAT",
            "protected_limit_price": protected_limit_price,
        }
    )
    try:
        plan = build_trusted_keyless_target_plan_v2(
            plan_id=f"static-core-equal-safety-flat-plan-v2-{identity}",
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
            phase="CLOSE",
            expected_before_position_hash=expected_before,
            expected_after_position_hash=expected_after,
            orders=[
                {
                    "symbol": symbol,
                    "exchange": exchange,
                    "direction": direction,
                    "type": "LIMIT",
                    "volume": 1,
                    "price": protected_limit_price,
                    "offset": offset,
                    "reference": sha256_json(
                        {"plan_identity": identity, "child_index": child_index}
                    ),
                    "gateway_name": "CTP",
                }
                for child_index, offset in enumerate(offsets, start=1)
            ],
        )
    except CommodityExecutionContractError as exc:
        raise ExecutableTargetAdapterError(
            f"STATIC_CORE_EQUAL SAFETY FLAT TargetPlan v2 is invalid: {exc}"
        ) from exc
    return StaticCoreEqualKeylessDecision(
        handoff=ExecutableTargetPlanHandoff(
            target_plan=plan,
            lineage=(static_sha256, position_manager_sha256, final_target_sha256),
            scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
            expires_at=str(plan["expires_at"]),
        ),
        **decision_fields,
    )


__all__ = [
    "ExecutableTargetAdapterError",
    "ExecutableTargetPlanHandoff",
    "PeekCurrentFacts",
    "StaticCoreEqualDeferredOpenIntent",
    "StaticCoreEqualFullPortfolioDecision",
    "StaticCoreEqualFullPortfolioPhaseHandoff",
    "StaticCoreEqualFullPortfolioQuoteInputBinding",
    "StaticCoreEqualFullPortfolioQuoteRequirement",
    "StaticCoreEqualFullPortfolioQuoteRequirements",
    "StaticCoreEqualKeylessDecision",
    "StaticCoreEqualPhaseBoundary",
    "build_executable_target_plan",
    "build_full_portfolio_quote_requests",
    "build_static_core_equal_full_portfolio_keyless_decision",
    "build_static_core_equal_keyless_safety_flat_decision",
    "build_static_core_equal_keyless_target_decision",
    "build_trusted_keyless_executable_target_plan",
    "full_portfolio_phase_plan_id_from_preimage",
    "full_portfolio_phase_plan_id_from_payload",
    "peek_current_facts_to_snapshot",
]
