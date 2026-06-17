from __future__ import annotations

from pydantic import BaseModel


class AccountSnapshot(BaseModel):
    accounts: list[dict]
    positions: list[dict]


class AccountDto(BaseModel):
    accountid: str | None = None
    vt_accountid: str | None = None
    balance: float | int | None = None
    frozen: float | int | None = None
    available: float | int | None = None
    gateway_name: str | None = None


class PositionDto(BaseModel):
    symbol: str | None = None
    exchange: str | None = None
    vt_symbol: str | None = None
    direction: str | None = None
    volume: float | int | None = None
    frozen: float | int | None = None
    price: float | int | None = None
    pnl: float | int | None = None
    gateway_name: str | None = None
