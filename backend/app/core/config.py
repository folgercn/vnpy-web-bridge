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
    manual_execution_permit_enabled: bool = False
    manual_execution_permit_trusted_public_keys_json: str = "{}"
    manual_execution_permit_account_hashes: str = ""
    manual_execution_permit_consume_root: str = (
        "logs/manual-execution-permit/consumed"
    )
    manual_execution_permit_max_ttl_seconds: int = Field(
        default=300,
        ge=1,
        le=300,
    )

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
    questdb_tick_retention_days: int = Field(default=365, ge=0, le=3650)
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
    commodity_baseline_execution_permit_enabled: bool = False
    commodity_baseline_execution_permit_close_path: str = ""
    commodity_baseline_execution_permit_open_path: str = ""
    commodity_baseline_execution_permit_trusted_keyring_path: str = ""
    commodity_baseline_execution_permit_expected_keyring_raw_sha256: str = ""
    commodity_baseline_execution_permit_consume_root: str = (
        "logs/commodity-simnow/baseline-execution-permit-consumed"
    )
    commodity_baseline_execution_permit_max_ttl_seconds: int = Field(
        default=600,
        ge=1,
        le=600,
    )
    commodity_simnow_min_source_month: str = "2026-08"
    commodity_simnow_max_child_order_lots: int = Field(
        default=10, ge=1, le=100
    )
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
    commodity_c_fast_execution_quality_runtime_enabled: bool = False
    commodity_c_fast_execution_quality_runtime_admission_path: str = ""
    commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path: str = ""
    commodity_c_fast_execution_quality_runtime_admission_expected_keyring_raw_sha256: str = ""
    commodity_c_fast_execution_quality_runtime_admission_expected_owner_uid: int = Field(
        default=0,
        ge=0,
    )
    commodity_c_fast_execution_quality_artifact_custody_root: str = ""
    commodity_c_fast_execution_quality_artifact_paths_json: str = "{}"
    commodity_c_fast_execution_quality_artifact_expected_root_path_sha256: str = ""
    commodity_c_fast_execution_quality_artifact_expected_identity_sha256: str = ""
    commodity_c_fast_execution_quality_artifact_expected_owner_uid: int = Field(
        default=0,
        ge=0,
    )
    commodity_c_fast_execution_quality_role_keyring_paths_json: str = "{}"
    commodity_c_fast_execution_quality_role_keyring_raw_sha256_json: str = "{}"
    commodity_c_fast_execution_quality_policy_v1_path: str = ""
    commodity_c_fast_execution_quality_policy_v1_expected_raw_sha256: str = ""
    commodity_c_fast_execution_quality_journal_root: str = ""
    commodity_c_fast_execution_quality_evidence_export_root: str = ""
    commodity_c_fast_simnow_shakedown_enabled: bool = False
    commodity_c_fast_simnow_account_hashes: str = ""
    commodity_c_fast_simnow_state_path: str = (
        "logs/commodity-c-fast-shadow/shakedown-session.json"
    )
    commodity_c_fast_simnow_auto_dispatch_enabled: bool = False
    commodity_c_fast_simnow_max_selected_products: int = Field(
        default=2, ge=1, le=2
    )
    commodity_c_fast_simnow_execution_permit_enabled: bool = False
    commodity_c_fast_simnow_execution_permit_path: str = ""
    commodity_c_fast_simnow_execution_permit_trusted_keyring_path: str = ""
    commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256: str = ""
    commodity_c_fast_simnow_execution_one_shot_custody_root: str = ""
    commodity_c_fast_simnow_execution_one_shot_expected_root_path_sha256: str = ""
    commodity_c_fast_simnow_execution_one_shot_expected_identity_sha256: str = ""
    commodity_c_fast_simnow_execution_one_shot_expected_owner_uid: int = Field(
        default=0,
        ge=0,
    )
    commodity_c_fast_simnow_research_acceptance_path: str = ""
    commodity_c_fast_simnow_research_acceptance_consume_path: str = ""
    commodity_c_fast_simnow_research_acceptance_receipt_path: str = ""
    commodity_c_fast_simnow_research_acceptance_trusted_keyring_path: str = ""
    commodity_c_fast_simnow_research_acceptance_expected_keyring_raw_sha256: str = ""
    commodity_c_fast_simnow_research_acceptance_custody_root: str = ""
    commodity_c_fast_simnow_research_acceptance_expected_custody_root_path_sha256: str = ""
    commodity_c_fast_simnow_research_acceptance_expected_custody_identity_sha256: str = ""
    commodity_c_fast_simnow_research_keyring_path: str = ""
    commodity_c_fast_simnow_research_expected_keyring_raw_sha256: str = ""
    commodity_c_fast_simnow_research_expected_signer_sha256: str = ""
    commodity_c_fast_simnow_research_acceptance_expected_signer_sha256: str = ""
    commodity_c_fast_simnow_research_artifact_paths_json: str = "{}"
    commodity_c_fast_fee_statement_trusted_keyring_path: str = ""
    commodity_c_fast_fee_statement_expected_keyring_raw_sha256: str = ""
    commodity_c_fast_fee_statement_historical_trust_profiles_json: str = "[]"
    commodity_simnow_delivery_month_cutoff_day: int = Field(default=1, ge=1, le=15)
    commodity_simnow_sc_pre_delivery_cutoff_day: int = Field(default=15, ge=1, le=25)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @model_validator(mode="after")
    def validate_production_secrets(self) -> Settings:
        if self.manual_execution_permit_enabled:
            account_hashes = {
                item.strip().lower()
                for item in self.manual_execution_permit_account_hashes.split(",")
                if item.strip()
            }
            if not account_hashes or any(
                not re.fullmatch(r"[0-9a-f]{64}", item)
                for item in account_hashes
            ):
                raise ValueError(
                    "MANUAL_EXECUTION_PERMIT_ACCOUNT_HASHES must contain SHA256 account hashes"
                )
            try:
                trusted_keys = json.loads(
                    self.manual_execution_permit_trusted_public_keys_json
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "MANUAL_EXECUTION_PERMIT_TRUSTED_PUBLIC_KEYS_JSON must be valid JSON"
                ) from exc
            if not isinstance(trusted_keys, dict) or not trusted_keys:
                raise ValueError(
                    "MANUAL_EXECUTION_PERMIT_TRUSTED_PUBLIC_KEYS_JSON must contain at least one key"
                )
            for entry in trusted_keys.values():
                if not isinstance(entry, dict) or set(entry) != {
                    "public_key_base64",
                    "purpose",
                }:
                    raise ValueError(
                        "MANUAL_EXECUTION_PERMIT_TRUSTED_PUBLIC_KEYS_JSON entries are invalid"
                    )
                if entry["purpose"] != "manual_execution_permit_signer":
                    raise ValueError(
                        "MANUAL_EXECUTION_PERMIT trusted key purpose is invalid"
                    )
                try:
                    key_bytes = base64.b64decode(
                        str(entry["public_key_base64"]), validate=True
                    )
                except (ValueError, binascii.Error) as exc:
                    raise ValueError(
                        "MANUAL_EXECUTION_PERMIT trusted key is invalid base64"
                    ) from exc
                if len(key_bytes) != 32:
                    raise ValueError(
                        "MANUAL_EXECUTION_PERMIT trusted key must be 32-byte Ed25519"
                    )
            if not self.manual_execution_permit_consume_root.strip():
                raise ValueError(
                    "MANUAL_EXECUTION_PERMIT_CONSUME_ROOT must be set"
                )
        if self.commodity_baseline_execution_permit_enabled:
            required_paths = (
                self.commodity_baseline_execution_permit_close_path,
                self.commodity_baseline_execution_permit_open_path,
                self.commodity_baseline_execution_permit_trusted_keyring_path,
                self.commodity_baseline_execution_permit_consume_root,
            )
            authority_paths = [
                Path(value).expanduser().resolve() for value in required_paths
            ]
            protected_paths = {
                Path(value).expanduser().resolve()
                for value in (
                    self.commodity_simnow_state_path,
                    self.commodity_simnow_template_batch_path,
                    self.commodity_position_manager_shadow_path,
                    self.commodity_position_manager_shadow_state_path,
                    self.commodity_position_manager_simnow_state_path,
                    self.commodity_c_fast_shadow_snapshot_path,
                    self.commodity_c_fast_shadow_state_path,
                    self.commodity_c_fast_shadow_evidence_path,
                )
                if value.strip()
            }
            paths_overlap = any(
                left == right
                or left.is_relative_to(right)
                or right.is_relative_to(left)
                for index, left in enumerate(authority_paths)
                for right in authority_paths[index + 1 :]
            ) or any(
                authority == protected
                or authority.is_relative_to(protected)
                or protected.is_relative_to(authority)
                for authority in authority_paths
                for protected in protected_paths
            )
            if (
                any(not value.strip() for value in required_paths)
                or paths_overlap
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    self.commodity_baseline_execution_permit_expected_keyring_raw_sha256,
                )
            ):
                raise ValueError(
                    "Commodity baseline execution permit paths and keyring pin must be complete and distinct"
                )
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
        if self.commodity_c_fast_simnow_shakedown_enabled:
            if not self.commodity_c_fast_shadow_enabled:
                raise ValueError(
                    "COMMODITY_C_FAST_SHADOW_ENABLED must be true when C_FAST SimNow shakedown is enabled"
                )
            if not self.commodity_simnow_enabled:
                raise ValueError(
                    "COMMODITY_SIMNOW_ENABLED must be true when C_FAST SimNow shakedown is enabled"
                )
            account_hashes = {
                item.strip().lower()
                for item in self.commodity_c_fast_simnow_account_hashes.split(",")
                if item.strip()
            }
            if not account_hashes or any(
                not re.fullmatch(r"[0-9a-f]{64}", item)
                for item in account_hashes
            ):
                raise ValueError(
                    "COMMODITY_C_FAST_SIMNOW_ACCOUNT_HASHES must contain SHA256 account hashes"
                )
            c_fast_session_path = Path(
                self.commodity_c_fast_simnow_state_path
            ).expanduser().resolve()
            commodity_state_path = Path(
                self.commodity_simnow_state_path
            ).expanduser().resolve()
            commodity_active_path = commodity_state_path.with_name(
                f"{commodity_state_path.stem}.active"
                f"{commodity_state_path.suffix}"
            )
            protected_paths = {
                Path(value).expanduser().resolve()
                for value in (
                    self.commodity_simnow_state_path,
                    self.commodity_simnow_template_batch_path,
                    self.commodity_position_manager_shadow_path,
                    self.commodity_position_manager_shadow_state_path,
                    self.commodity_position_manager_simnow_state_path,
                    self.commodity_c_fast_shadow_snapshot_path,
                    self.commodity_c_fast_shadow_state_path,
                    self.commodity_c_fast_shadow_evidence_path,
                )
                if value.strip()
            }
            protected_paths.add(commodity_active_path)
            protected_paths.update(
                path.with_suffix(f"{path.suffix}.tmp")
                for path in list(protected_paths)
            )
            c_fast_derived_paths = {
                c_fast_session_path,
                c_fast_session_path.with_suffix(
                    f"{c_fast_session_path.suffix}.tmp"
                ),
                c_fast_session_path.with_name(
                    f"{c_fast_session_path.stem}.sessions"
                ),
            }
            c_fast_archive_dir = c_fast_session_path.with_name(
                f"{c_fast_session_path.stem}.sessions"
            )
            if c_fast_derived_paths & protected_paths or any(
                path.is_relative_to(c_fast_archive_dir)
                for path in protected_paths
            ):
                raise ValueError(
                    "COMMODITY_C_FAST_SIMNOW_STATE_PATH and derived paths must not overlap existing commodity paths"
                )
        if self.commodity_c_fast_simnow_execution_permit_enabled:
            authority_path_values = (
                self.commodity_c_fast_simnow_execution_permit_path,
                self.commodity_c_fast_simnow_execution_permit_trusted_keyring_path,
                self.commodity_c_fast_simnow_execution_one_shot_custody_root,
                self.commodity_c_fast_simnow_research_acceptance_path,
                self.commodity_c_fast_simnow_research_acceptance_consume_path,
                self.commodity_c_fast_simnow_research_acceptance_receipt_path,
                self.commodity_c_fast_simnow_research_acceptance_trusted_keyring_path,
                self.commodity_c_fast_simnow_research_acceptance_custody_root,
                self.commodity_c_fast_simnow_research_keyring_path,
            )
            required_text = authority_path_values
            required_pins = (
                self.commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256,
                self.commodity_c_fast_simnow_execution_one_shot_expected_root_path_sha256,
                self.commodity_c_fast_simnow_execution_one_shot_expected_identity_sha256,
                self.commodity_c_fast_simnow_research_acceptance_expected_keyring_raw_sha256,
                self.commodity_c_fast_simnow_research_acceptance_expected_custody_root_path_sha256,
                self.commodity_c_fast_simnow_research_acceptance_expected_custody_identity_sha256,
                self.commodity_c_fast_simnow_research_expected_keyring_raw_sha256,
                self.commodity_c_fast_simnow_research_expected_signer_sha256,
                self.commodity_c_fast_simnow_research_acceptance_expected_signer_sha256,
            )
            authority_paths = {
                Path(value).expanduser().resolve()
                for value in authority_path_values
                if value.strip()
            }
            one_shot_root = Path(
                self.commodity_c_fast_simnow_execution_one_shot_custody_root
            ).expanduser().resolve()
            non_one_shot_authority_paths = {
                Path(value).expanduser().resolve()
                for value in authority_path_values
                if (
                    value.strip()
                    and value
                    != self.commodity_c_fast_simnow_execution_one_shot_custody_root
                )
            }
            one_shot_overlaps_authority = any(
                path.is_relative_to(one_shot_root)
                or one_shot_root.is_relative_to(path)
                for path in non_one_shot_authority_paths
            )
            if (
                any(not value.strip() for value in required_text)
                or any(
                    not re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in required_pins
                )
                or len(authority_paths) != len(authority_path_values)
                or one_shot_overlaps_authority
                or (
                    self.app_env.lower() == "production"
                    and self.commodity_c_fast_simnow_execution_one_shot_expected_owner_uid
                    != 0
                )
            ):
                raise ValueError(
                    "C_FAST SimNow execution permit, one-shot custody and #165 acceptance paths/keyrings/custody pins must be complete and distinct"
                )
            try:
                artifact_paths = json.loads(
                    self.commodity_c_fast_simnow_research_artifact_paths_json
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "COMMODITY_C_FAST_SIMNOW_RESEARCH_ARTIFACT_PATHS_JSON must be valid JSON"
                ) from exc
            if (
                not isinstance(artifact_paths, dict)
                or set(artifact_paths)
                != {
                    "freeze_contract",
                    "research_manifest",
                    "signal_evidence",
                    "target_evidence",
                    "allocation_evidence",
                    "daily_roll_evidence",
                    "reference_price_evidence",
                    "calendar_authority",
                    "contract_spec_evidence",
                }
                or any(
                    not isinstance(value, str) or not value.strip()
                    for value in artifact_paths.values()
                )
            ):
                raise ValueError(
                    "COMMODITY_C_FAST_SIMNOW_RESEARCH_ARTIFACT_PATHS_JSON must bind all nine #165 Research artifacts"
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
            keys_by_purpose: dict[str, set[bytes]] = {
                "research_snapshot_signer": set(),
                "simnow_shakedown_control_signer": set(),
            }
            for entry in trusted_keys.values():
                if not isinstance(entry, dict) or set(entry) != {
                    "public_key_base64",
                    "purpose",
                }:
                    raise ValueError(
                        "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON entries must contain only public_key_base64 and purpose"
                    )
                if entry["purpose"] not in {
                    "research_snapshot_signer",
                    "simnow_shakedown_control_signer",
                }:
                    raise ValueError(
                        "COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON purpose must be research_snapshot_signer or simnow_shakedown_control_signer"
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
                keys_by_purpose[str(entry["purpose"])].add(public_key)
            if (
                keys_by_purpose["research_snapshot_signer"]
                & keys_by_purpose["simnow_shakedown_control_signer"]
            ):
                raise ValueError(
                    "C_FAST Research and Control public keys must be distinct"
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
