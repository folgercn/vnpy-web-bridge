from __future__ import annotations

import json
from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "VnPy Web Bridge"
    app_env: str = "development"
    log_level: str = "INFO"

    vnpy_rpc_req_address: str = Field(default="tcp://127.0.0.1:2014")
    vnpy_rpc_pub_address: str = Field(default="tcp://127.0.0.1:4102")
    vnpy_gateway_name: str = Field(default="CTP")
    vnpy_rpc_timeout_ms: int = Field(default=10_000, ge=1_000)

    web_trade_enabled: bool = False
    default_gateway_name: str = "CTP"
    order_confirm_required: bool = True
    trade_reference_prefix: str = "web_bridge"

    jwt_secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = Field(default=480, ge=1)
    auth_users_json: str = "[]"

    risk_max_order_volume: float = Field(default=1, gt=0)
    risk_max_symbol_position: float = Field(default=5, ge=0)
    risk_max_daily_loss: float = Field(default=1000, ge=0)
    risk_price_protection_percent: float = Field(default=3, ge=0)
    risk_allowed_exchanges: str = "SHFE,DCE,CZCE,CFFEX,INE,GFEX"
    risk_allowed_symbols: str = ""
    risk_blocked_symbols: str = ""
    risk_trading_time_check_enabled: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.app_env.lower() != "production":
            return self
        if self.jwt_secret_key == "change-me-in-production":
            raise ValueError("JWT_SECRET_KEY must be set in production")
        if len(self.jwt_secret_key) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters in production")
        try:
            users = json.loads(self.auth_users_json)
        except json.JSONDecodeError as exc:
            raise ValueError("AUTH_USERS_JSON must be valid JSON in production") from exc
        if not any(user.get("role") == "admin" for user in users if isinstance(user, dict)):
            raise ValueError("At least one admin user is required in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
