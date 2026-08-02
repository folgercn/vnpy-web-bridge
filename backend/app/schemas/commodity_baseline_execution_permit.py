from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    model_validator,
)


MAX_BASELINE_PERMIT_LIFETIME = timedelta(minutes=10)


class StrictBaselinePermitModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
        revalidate_instances="always",
    )


def _strict_true(value: Any) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("authority value must be the boolean literal true")
    return True


def _strict_false(value: Any) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("authority value must be the boolean literal false")
    return False


StrictTrue = Annotated[Literal[True], BeforeValidator(_strict_true)]
StrictFalse = Annotated[Literal[False], BeforeValidator(_strict_false)]
StrictPositiveInt = Annotated[int, Field(strict=True, gt=0)]
StrictNonNegativeFloat = Annotated[float, Field(strict=True, ge=0)]
StrictPositiveFloat = Annotated[float, Field(strict=True, gt=0)]

BASELINE_EXECUTION_PLAN_CORE_KEYS = (
    "schema_version",
    "baseline_execution_session_id",
    "position_manager_shakedown_session_id",
    "strategy_id",
    "strategy_version",
    "plan_hash",
    "batch_hash",
    "batch_id",
    "source_snapshot_hash",
    "baseline_batch_hash",
    "execution_lane",
    "countable_forward",
    "account_hash",
    "execution_day",
    "previous_positions",
    "expected_after_close",
    "expected_final_positions",
    "close_orders",
    "open_orders",
    "targets",
    "risk_sector_map_id",
    "quote_snapshot_hash",
    "roll_products",
)


class CommodityBaselineOrderScopeDTO(StrictBaselinePermitModel):
    symbol: str = Field(min_length=1, max_length=64)
    exchange: str = Field(min_length=1, max_length=16)
    direction: Literal["long", "short"]
    offset: Literal["open", "close", "closetoday", "closeyesterday"]
    type: Literal["limit"] = "limit"
    volume: StrictPositiveInt
    reference: str = Field(min_length=1, max_length=128)
    minimum_price: StrictPositiveFloat
    maximum_price: StrictPositiveFloat

    @model_validator(mode="after")
    def validate_price_band(self) -> "CommodityBaselineOrderScopeDTO":
        if self.minimum_price > self.maximum_price:
            raise ValueError("baseline order price band is invalid")
        return self


class CommodityBaselineRiskEnvelopeDTO(StrictBaselinePermitModel):
    max_child_order_lots: StrictPositiveInt
    max_orders_per_phase: StrictPositiveInt
    max_total_phase_lots: StrictPositiveInt
    max_symbol_position_lots: StrictNonNegativeFloat
    max_product_weight: StrictPositiveFloat
    max_gross_weight: StrictPositiveFloat
    max_abs_net_weight: StrictPositiveFloat
    max_sector_weight: StrictPositiveFloat
    max_quote_age_seconds: StrictPositiveInt
    max_spread_ticks: StrictPositiveFloat


class CommodityBaselineExecutionPermitDTO(StrictBaselinePermitModel):
    schema_version: Literal["commodity_baseline_execution_permit_v1"]
    purpose: Literal["commodity_baseline_phase_one_shot_execution_permit"]
    permit_id: str = Field(
        pattern=r"^commodity-baseline-execution-permit-v1-[0-9a-f]{64}$"
    )
    nonce: str = Field(pattern=r"^[A-Za-z0-9._-]{16,128}$")
    issued_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    execution_environment: Literal["SIMNOW"]
    strategy_id: Literal[
        "STATIC_CORE_EQUAL",
        "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
    ]
    strategy_version: Literal[
        "commodity_static_core_equal_target_batch_v2",
        "commodity_relative_vol_position_manager_shakedown_v1",
    ]
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_plan_core_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_session_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    phase: Literal["close", "open"]
    account_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolved_gateway_name: str = Field(min_length=1, max_length=64)
    price_policy_id: Literal[
        "COMMODITY_SIMNOW_PROTECTED_TOUCH_PLUS_ONE_TICK_V1",
        "COMMODITY_SIMNOW_ACCEPTANCE_PASSIVE_TOUCH_V1",
    ]
    price_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    order_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    orders: list[CommodityBaselineOrderScopeDTO] = Field(
        min_length=1,
        max_length=500,
    )
    risk_envelope: CommodityBaselineRiskEnvelopeDTO
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    phase_dispatch_authorized: StrictTrue
    one_shot: StrictTrue
    replay_allowed: StrictFalse
    production_allowed: StrictFalse
    live_trading_authorized: StrictFalse
    automatic_promotion_authorized: StrictFalse
    c_fast_authority_reused: StrictFalse
    manual_authority_reused: StrictFalse
    signature: str = Field(
        min_length=88,
        max_length=88,
        pattern=r"^[A-Za-z0-9+/]{86}==$",
    )

    @model_validator(mode="after")
    def validate_scope(self) -> "CommodityBaselineExecutionPermitDTO":
        values = (
            self.issued_at_utc,
            self.not_before_utc,
            self.expires_at_utc,
        )
        if any(
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
            for value in values
        ):
            raise ValueError("baseline execution permit times require UTC")
        if not (self.issued_at_utc <= self.not_before_utc < self.expires_at_utc):
            raise ValueError("baseline execution permit time order is invalid")
        if self.expires_at_utc - self.issued_at_utc > MAX_BASELINE_PERMIT_LIFETIME:
            raise ValueError("baseline execution permit lifetime exceeds ten minutes")
        if self.strategy_id == "STATIC_CORE_EQUAL" and self.strategy_version != (
            "commodity_static_core_equal_target_batch_v2"
        ):
            raise ValueError("baseline strategy identity is invalid")
        if (
            self.strategy_id == "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1"
            and self.strategy_version
            != "commodity_relative_vol_position_manager_shakedown_v1"
        ):
            raise ValueError("position-manager strategy identity is invalid")
        references = [row.reference for row in self.orders]
        if len(set(references)) != len(references):
            raise ValueError("baseline permit order references must be unique")
        if self.order_set_sha256 != baseline_order_set_sha256(self.orders):
            raise ValueError("baseline permit order-set hash is invalid")
        return self


class CommodityBaselinePermitTrustedKeyDTO(StrictBaselinePermitModel):
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    public_key_base64: str = Field(min_length=44, max_length=44)
    purpose: Literal["commodity_baseline_execution_permit_signer"]


class CommodityBaselinePermitTrustedKeysDTO(StrictBaselinePermitModel):
    schema_version: Literal["commodity_baseline_execution_permit_trusted_keys_v1"]
    purpose: Literal["commodity_baseline_execution_permit_verification"]
    trusted_keys: list[CommodityBaselinePermitTrustedKeyDTO] = Field(
        min_length=1,
        max_length=16,
    )

    @model_validator(mode="after")
    def validate_unique_keys(
        self,
    ) -> "CommodityBaselinePermitTrustedKeysDTO":
        ids = [row.key_id for row in self.trusted_keys]
        materials = [row.public_key_base64 for row in self.trusted_keys]
        if len(set(ids)) != len(ids) or len(set(materials)) != len(materials):
            raise ValueError("baseline execution trusted keys must be unique")
        return self


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def unsigned_baseline_permit_payload(
    payload: CommodityBaselineExecutionPermitDTO | dict[str, Any],
) -> dict[str, Any]:
    values = (
        payload.model_dump(mode="json")
        if isinstance(payload, CommodityBaselineExecutionPermitDTO)
        else dict(payload)
    )
    return {key: value for key, value in values.items() if key != "signature"}


def baseline_permit_binding_payload(
    payload: CommodityBaselineExecutionPermitDTO | dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in unsigned_baseline_permit_payload(payload).items()
        if key != "permit_id"
    }


def derived_baseline_permit_id(
    payload: CommodityBaselineExecutionPermitDTO | dict[str, Any],
) -> str:
    digest = sha256_bytes(canonical_json(baseline_permit_binding_payload(payload)))
    return f"commodity-baseline-execution-permit-v1-{digest}"


def baseline_order_set_sha256(
    orders: list[CommodityBaselineOrderScopeDTO] | list[dict[str, Any]],
) -> str:
    rows = [
        row.model_dump(mode="json")
        if isinstance(row, CommodityBaselineOrderScopeDTO)
        else CommodityBaselineOrderScopeDTO.model_validate(row).model_dump(mode="json")
        for row in orders
    ]
    return sha256_bytes(canonical_json(rows))


def baseline_price_policy_payload(
    *,
    price_policy_id: str,
    max_quote_age_seconds: int,
    max_spread_ticks: float,
) -> dict[str, Any]:
    return {
        "price_policy_id": price_policy_id,
        "max_quote_age_seconds": max_quote_age_seconds,
        "max_spread_ticks": max_spread_ticks,
    }


def baseline_price_policy_sha256(**kwargs: Any) -> str:
    return sha256_bytes(canonical_json(baseline_price_policy_payload(**kwargs)))


def baseline_execution_plan_core_payload(
    plan: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: plan.get(key) for key in BASELINE_EXECUTION_PLAN_CORE_KEYS if key in plan
    }
