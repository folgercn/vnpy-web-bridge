from __future__ import annotations

from pydantic import BaseModel


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
