from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class OrderTradeSnapshot(BaseModel):
    orders: list[dict]
    trades: list[dict]


class OrderDto(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    vt_symbol: str | None = None
    orderid: str | None = None
    vt_orderid: str | None = None
    direction: str | None = None
    offset: str | None = None
    type: str | None = None
    price: float | int | None = None
    volume: float | int | None = None
    traded: float | int | None = None
    status: str | None = None
    datetime: str | None = None
    gateway_name: str | None = None


class TradeDto(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    vt_symbol: str | None = None
    tradeid: str | None = None
    vt_tradeid: str | None = None
    orderid: str | None = None
    vt_orderid: str | None = None
    direction: str | None = None
    offset: str | None = None
    price: float | int | None = None
    volume: float | int | None = None
    datetime: str | None = None
    gateway_name: str | None = None


class OrderRequestDTO(BaseModel):
    symbol: str = Field(min_length=1)
    exchange: str = Field(min_length=1)
    direction: Literal["long", "short"]
    offset: Literal["open", "close", "closetoday", "closeyesterday"]
    type: Literal["limit"] = "limit"
    price: float = Field(gt=0)
    volume: float = Field(gt=0)
    gateway_name: str | None = None
    reference: str | None = None
    confirm: bool = False


class OrderResponseDTO(BaseModel):
    vt_orderid: str
    accepted: bool


class CancelRequestDTO(BaseModel):
    gateway_name: str | None = None


class CancelResponseDTO(BaseModel):
    vt_orderid: str
    cancel_requested: bool
    status: str | None = None


class CancelAllRequestDTO(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    gateway_name: str | None = None


class CancelAllItemDTO(BaseModel):
    vt_orderid: str | None = None
    cancel_requested: bool
    error: str | None = None


class CancelAllResponseDTO(BaseModel):
    requested: int
    success: int
    failed: int
    items: list[CancelAllItemDTO]
