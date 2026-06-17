from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "VnPy Web Bridge"
    app_env: str = "development"
    log_level: str = "INFO"

    vnpy_rpc_req_address: str = Field(default="tcp://127.0.0.1:2014")
    vnpy_rpc_pub_address: str = Field(default="tcp://127.0.0.1:4102")
    vnpy_gateway_name: str = Field(default="CTP")
    vnpy_rpc_timeout_ms: int = Field(default=10_000, ge=1_000)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
