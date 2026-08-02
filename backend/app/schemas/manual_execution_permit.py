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

from app.schemas.trade import OrderRequestDTO


MAX_MANUAL_PERMIT_LIFETIME = timedelta(minutes=5)


class StrictManualExecutionModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
        revalidate_instances="always",
    )


BoundText = Annotated[str, Field(min_length=1, max_length=128)]
OptionalGateway = Annotated[str, Field(min_length=1, max_length=64)] | None


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
StrictPositiveFloat = Annotated[float, Field(strict=True, gt=0)]
StrictPositiveInt = Annotated[int, Field(strict=True, gt=0)]


class ManualExecutionOrderDTO(StrictManualExecutionModel):
    symbol: str = Field(min_length=1, max_length=64)
    exchange: str = Field(min_length=1, max_length=16)
    direction: Literal["long", "short"]
    offset: Literal["open", "close", "closetoday", "closeyesterday"]
    type: Literal["limit"] = "limit"
    price: StrictPositiveFloat
    volume: StrictPositiveInt
    gateway_name: OptionalGateway = None
    reference: str = Field(min_length=1, max_length=128)
    confirm: StrictTrue

    def to_order_request(self) -> OrderRequestDTO:
        return OrderRequestDTO.model_validate(
            self.model_dump(mode="python")
        )


class ManualExecutionPermitDTO(StrictManualExecutionModel):
    schema_version: Literal["manual_execution_permit_v1"]
    purpose: Literal["manual_order_one_shot_execution_permit"]
    permit_id: str = Field(
        pattern=r"^manual-execution-permit-v1-[0-9a-f]{64}$"
    )
    nonce: str = Field(pattern=r"^[A-Za-z0-9._-]{16,128}$")
    issued_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    execution_environment: Literal["SIMNOW"]
    account_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator: BoundText
    order: ManualExecutionOrderDTO
    resolved_gateway_name: str = Field(min_length=1, max_length=64)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    human_issued: StrictTrue
    manual_order_authorized: StrictTrue
    one_shot: StrictTrue
    replay_allowed: StrictFalse
    production_allowed: StrictFalse
    live_trading_authorized: StrictFalse
    automatic_dispatch_authorized: StrictFalse
    c_fast_authority_reused: StrictFalse
    signature: str = Field(
        min_length=88,
        max_length=88,
        pattern=r"^[A-Za-z0-9+/]{86}==$",
    )

    @model_validator(mode="after")
    def validate_time_window(self) -> "ManualExecutionPermitDTO":
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
            raise ValueError("manual execution permit times require UTC")
        if not (
            self.issued_at_utc
            <= self.not_before_utc
            < self.expires_at_utc
        ):
            raise ValueError("manual execution permit time order is invalid")
        if (
            self.expires_at_utc - self.issued_at_utc
            > MAX_MANUAL_PERMIT_LIFETIME
        ):
            raise ValueError("manual execution permit lifetime exceeds five minutes")
        return self


class ManualOrderSubmissionDTO(StrictManualExecutionModel):
    order: ManualExecutionOrderDTO
    execution_permit: ManualExecutionPermitDTO


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


def unsigned_manual_permit_payload(
    payload: ManualExecutionPermitDTO | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(payload, ManualExecutionPermitDTO):
        values = payload.model_dump(mode="json")
    else:
        values = dict(payload)
    return {
        key: value for key, value in values.items() if key != "signature"
    }


def manual_permit_binding_payload(
    payload: ManualExecutionPermitDTO | dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in unsigned_manual_permit_payload(payload).items()
        if key != "permit_id"
    }


def derived_manual_permit_id(
    payload: ManualExecutionPermitDTO | dict[str, Any],
) -> str:
    digest = sha256_bytes(
        canonical_json(manual_permit_binding_payload(payload))
    )
    return f"manual-execution-permit-v1-{digest}"


def manual_order_request_fingerprint(
    payload: ManualExecutionOrderDTO | OrderRequestDTO,
    *,
    resolved_gateway_name: str,
) -> str:
    if not isinstance(resolved_gateway_name, str) or not resolved_gateway_name:
        raise ValueError("resolved manual gateway_name is required")
    if isinstance(payload, ManualExecutionOrderDTO):
        order = payload
    else:
        order = ManualExecutionOrderDTO.model_validate(
            payload.model_dump(mode="python")
        )
    return sha256_bytes(
        canonical_json(
            {
                "order_request": order.model_dump(mode="json"),
                "resolved_gateway_name": resolved_gateway_name,
            }
        )
    )
