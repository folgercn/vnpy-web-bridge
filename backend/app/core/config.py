from __future__ import annotations

import base64
import binascii
import json
import re
from functools import lru_cache
from pathlib import Path

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
    questdb_pg_dsn: str = ""
    questdb_ilp_conf: str = ""
    questdb_tick_persist_enabled: bool = True
    questdb_tick_queue_size: int = Field(default=100_000, ge=1)
    questdb_tick_batch_size: int = Field(default=1_000, ge=1)
    questdb_tick_flush_interval_ms: int = Field(default=500, ge=10)
    questdb_tick_retry_max_seconds: int = Field(default=60, ge=1)
    questdb_tick_spool_dir: str = "logs/tick-spool"
    questdb_tick_spool_max_bytes: int = Field(default=10 * 1024 * 1024 * 1024, ge=1)
    questdb_tick_spool_segment_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    questdb_tick_spool_fsync: bool = False
    questdb_tick_error_log_interval_seconds: int = Field(default=60, ge=1)
    database_url: str = ""

    monitor_enabled: bool = False
    monitor_interval_seconds: int = Field(default=15, ge=5)
    monitor_failure_threshold: int = Field(default=3, ge=1)
    monitor_recovery_threshold: int = Field(default=2, ge=1)
    monitor_startup_grace_seconds: int = Field(default=120, ge=0)
    monitor_flap_send_grace_seconds: int = Field(default=45, ge=0)
    monitor_flap_recovery_grace_seconds: int = Field(default=60, ge=0)
    monitor_critical_reminder_minutes: int = Field(default=0, ge=0)
    monitor_state_path: str = "/app/logs/monitor/state.json"
    monitor_events_path: str = "/app/logs/monitor/events.jsonl"
    monitor_maintenance_path: str = "/app/logs/watchdog/maintenance.json"
    monitor_max_silence_seconds: int = Field(default=86_400, ge=60)
    monitor_tick_stale_seconds: int = Field(default=120, ge=10)
    monitor_http_5xx_threshold: int = Field(default=5, ge=1)
    monitor_http_5xx_window_seconds: int = Field(default=300, ge=10)
    monitor_trade_failure_threshold: int = Field(default=3, ge=1)
    monitor_trade_failure_window_seconds: int = Field(default=300, ge=10)
    monitor_expected_strategies: str = ""

    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_send_levels: str = "critical,warning"
    telegram_http_timeout_seconds: int = Field(default=8, ge=1)
    telegram_trade_events_enabled: bool = False

    risk_max_order_volume: float = Field(default=1, gt=0)
    risk_max_symbol_position: float = Field(default=5, ge=0)
    risk_max_daily_loss: float = Field(default=1000, ge=0)
    risk_price_protection_percent: float = Field(default=3, ge=0)
    risk_allowed_exchanges: str = "SHFE,DCE,CZCE,CFFEX,INE,GFEX"
    risk_allowed_symbols: str = ""
    risk_blocked_symbols: str = ""
    risk_trading_time_check_enabled: bool = False

    commodity_simnow_enabled: bool = False
    commodity_simnow_gateway_name: str = "CTP"
    commodity_simnow_account_hashes: str = ""
    commodity_simnow_trusted_public_keys_json: str = "{}"
    commodity_simnow_state_path: str = "logs/commodity-simnow/state.json"
    commodity_simnow_min_source_month: str = "2026-08"
    commodity_simnow_max_child_order_lots: int = Field(default=10, ge=1, le=100)
    commodity_simnow_max_orders_per_phase: int = Field(default=128, ge=1, le=500)
    commodity_simnow_max_quote_age_seconds: int = Field(default=5, ge=1, le=60)
    commodity_simnow_max_spread_ticks: float = Field(default=4, gt=0, le=20)
    commodity_simnow_auto_dispatch_enabled: bool = True
    commodity_simnow_auto_dispatch_interval_seconds: float = Field(default=1.0, ge=0.25, le=60)
    commodity_simnow_auto_dispatch_reconcile_grace_seconds: int = Field(default=30, ge=5, le=300)
    commodity_simnow_submission_outcome_grace_seconds: int = Field(default=30, ge=5, le=300)
    commodity_simnow_submission_outcome_min_empty_snapshots: int = Field(default=3, ge=2, le=10)
    commodity_simnow_acceptance_passive_limit_enabled: bool = False
    commodity_simnow_acceptance_passive_limit_ttl_seconds: int = Field(default=15, ge=1, le=300)
    commodity_simnow_acceptance_max_total_orders: int = Field(default=2, ge=1, le=20)
    commodity_simnow_acceptance_max_total_lots: int = Field(default=2, ge=1, le=20)
    commodity_simnow_template_batch_path: str = ""
    commodity_position_manager_shadow_path: str = ""
    commodity_position_manager_shadow_state_path: str = (
        "logs/commodity-simnow/position-manager-shadow-state.json"
    )
    commodity_position_manager_simnow_shakedown_enabled: bool = False
    commodity_position_manager_simnow_state_path: str = (
        "logs/commodity-simnow/position-manager-shakedown.json"
    )
    commodity_position_manager_simnow_max_selected_products: int = Field(
        default=10, ge=1, le=10
    )
    commodity_position_manager_simnow_auto_dispatch_enabled: bool = False
    commodity_c_fast_shadow_enabled: bool = False
    commodity_c_fast_shadow_snapshot_path: str = ""
    commodity_c_fast_shadow_state_path: str = (
        "logs/commodity-c-fast-shadow/state.json"
    )
    commodity_c_fast_shadow_evidence_path: str = (
        "logs/commodity-c-fast-shadow/evidence.jsonl"
    )
    commodity_c_fast_shadow_trusted_public_keys_json: str = "{}"
    commodity_simnow_delivery_month_cutoff_day: int = Field(default=1, ge=1, le=15)
    commodity_simnow_sc_pre_delivery_cutoff_day: int = Field(default=15, ge=1, le=25)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.commodity_c_fast_shadow_enabled:
            if not self.commodity_c_fast_shadow_snapshot_path.strip():
                raise ValueError(
                    "COMMODITY_C_FAST_SHADOW_SNAPSHOT_PATH must be set when C_FAST Shadow is enabled"
                )
            c_paths = {
                Path(value).expanduser().resolve()
                for value in (
                    self.commodity_c_fast_shadow_snapshot_path,
                    self.commodity_c_fast_shadow_state_path,
                    self.commodity_c_fast_shadow_evidence_path,
                )
            }
            if len(c_paths) != 3:
                raise ValueError(
                    "COMMODITY_C_FAST_SHADOW snapshot/state/evidence paths must be distinct"
                )
            protected = {
                Path(value).expanduser().resolve()
                for value in (
                    self.commodity_simnow_state_path,
                    self.commodity_simnow_template_batch_path,
                    self.commodity_position_manager_shadow_path,
                    self.commodity_position_manager_shadow_state_path,
                    self.commodity_position_manager_simnow_state_path,
                )
                if value.strip()
            }
            if c_paths & protected:
                raise ValueError(
                    "COMMODITY_C_FAST_SHADOW paths must not overlap existing commodity paths"
                )
        if self.app_env.lower() != "production":
            return self
        if self.jwt_secret_key == "change-me-in-production":
            raise ValueError("JWT_SECRET_KEY must be set in production")
        if len(self.jwt_secret_key) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters in production")
        if self.telegram_enabled and (not self.telegram_bot_token or not self.telegram_chat_id):
            raise ValueError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set when Telegram is enabled")
        if self.commodity_simnow_enabled:
            account_hashes = {
                item.strip().lower()
                for item in self.commodity_simnow_account_hashes.split(",")
                if item.strip()
            }
            if not account_hashes or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in account_hashes):
                raise ValueError("COMMODITY_SIMNOW_ACCOUNT_HASHES must be set when commodity SimNow is enabled")
            try:
                trusted_keys = json.loads(self.commodity_simnow_trusted_public_keys_json)
            except json.JSONDecodeError as exc:
                raise ValueError("COMMODITY_SIMNOW_TRUSTED_PUBLIC_KEYS_JSON must be valid JSON") from exc
            if not isinstance(trusted_keys, dict) or not trusted_keys:
                raise ValueError(
                    "COMMODITY_SIMNOW_TRUSTED_PUBLIC_KEYS_JSON must contain at least one Ed25519 public key"
                )
            try:
                public_keys = [base64.b64decode(str(value), validate=True) for value in trusted_keys.values()]
            except (ValueError, binascii.Error) as exc:
                raise ValueError("COMMODITY_SIMNOW_TRUSTED_PUBLIC_KEYS_JSON contains invalid base64") from exc
            if any(len(value) != 32 for value in public_keys):
                raise ValueError("COMMODITY_SIMNOW_TRUSTED_PUBLIC_KEYS_JSON must contain 32-byte Ed25519 keys")
        if self.commodity_c_fast_shadow_enabled:
            try:
                trusted_keys = json.loads(
                    self.commodity_c_fast_shadow_trusted_public_keys_json
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON must be valid JSON"
                ) from exc
            if not isinstance(trusted_keys, dict) or not trusted_keys:
                raise ValueError(
                    "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON must contain at least one Ed25519 public key"
                )
            for entry in trusted_keys.values():
                if not isinstance(entry, dict) or set(entry) != {
                    "public_key_base64",
                    "purpose",
                }:
                    raise ValueError(
                        "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON entries must contain only public_key_base64 and purpose"
                    )
                if entry["purpose"] != "research_snapshot_signer":
                    raise ValueError(
                        "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON purpose must be research_snapshot_signer"
                    )
                try:
                    public_key = base64.b64decode(
                        str(entry["public_key_base64"]), validate=True
                    )
                except (ValueError, binascii.Error) as exc:
                    raise ValueError(
                        "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON contains invalid base64"
                    ) from exc
                if len(public_key) != 32:
                    raise ValueError(
                        "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON must contain 32-byte Ed25519 keys"
                    )
        allowed_levels = {"info", "warning", "critical"}
        levels = {item.strip().lower() for item in self.telegram_send_levels.split(",") if item.strip()}
        if not levels or levels - allowed_levels:
            raise ValueError("TELEGRAM_SEND_LEVELS must contain only info, warning, critical")
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
