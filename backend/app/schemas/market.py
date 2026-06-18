from __future__ import annotations

from pydantic import BaseModel, Field


class SubscribeRequestDto(BaseModel):
    symbol: str = Field(min_length=1)
    exchange: str = Field(min_length=1)


class TickQuery(BaseModel):
    vt_symbol: str


class BarQueryDto(BaseModel):
    symbol: str = Field(min_length=1)
    exchange: str = Field(min_length=1)
    interval: str = "1m"
    limit: int = Field(default=300, ge=1, le=2000)


class MarketDataQueryDto(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    vt_symbol: str | None = None
    start: str | None = None
    end: str | None = None
    limit: int = Field(default=200, ge=1, le=5000)


class WatchlistCreateDto(BaseModel):
    vt_symbol: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    exchange: str = Field(min_length=1)
    display_name: str = Field(min_length=1)


class ContractDto(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    vt_symbol: str | None = None
    name: str | None = None
    product: str | None = None
    size: float | int | None = None
    pricetick: float | int | None = None
    gateway_name: str | None = None


class TickDto(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    vt_symbol: str | None = None
    datetime: str | None = None
    last_price: float | int | None = None
    volume: float | int | None = None
    turnover: float | int | None = None
    open_interest: float | int | None = None
    bid_price_1: float | int | None = None
    ask_price_1: float | int | None = None
    gateway_name: str | None = None


class BarDto(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    vt_symbol: str | None = None
    datetime: str | None = None
    interval: str | None = None
    volume: float | int | None = None
    open_price: float | int | None = None
    high_price: float | int | None = None
    low_price: float | int | None = None
    close_price: float | int | None = None
    gateway_name: str | None = None
