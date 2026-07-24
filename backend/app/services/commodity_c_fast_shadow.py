from __future__ import annotations

import base64
import binascii
import copy
import json
import math
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping
from zoneinfo import ZoneInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastShadowDTO,
    CommodityCFastShadowStateDTO,
)
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    formula_target_binding_sha256,
    sha256_json,
    unsigned_snapshot_payload,
)


CHINA_TZ = ZoneInfo("Asia/Shanghai")
GENESIS_SOURCE_MONTH = "2026-08"
PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
CFastContractLoader = Callable[
    [set[str]], Mapping[str, Mapping[str, Any]]
]
MAX_CLOCK_SKEW = timedelta(minutes=5)

# This candidate owns its frozen maps.  It deliberately does not import
# CommoditySimNowService or the position-manager shadow's mutable constants.
C_FAST_SECTOR_MAP_V1: dict[str, str] = {
    "ag": "precious",
    "al": "nonferrous",
    "au": "precious",
    "bu": "energy_chemical",
    "cu": "nonferrous",
    "rb": "ferrous",
    "ru": "energy_chemical",
    "sc": "energy",
    "sp": "light_industry",
    "zn": "nonferrous",
}
C_FAST_PRODUCT_SPECS_V1: dict[str, dict[str, Any]] = {
    "ag": {"exchange": "SHFE", "multiplier": 15, "price_tick": 1.0},
    "al": {"exchange": "SHFE", "multiplier": 5, "price_tick": 5.0},
    "au": {"exchange": "SHFE", "multiplier": 1000, "price_tick": 0.02},
    "bu": {"exchange": "SHFE", "multiplier": 10, "price_tick": 1.0},
    "cu": {"exchange": "SHFE", "multiplier": 5, "price_tick": 10.0},
    "rb": {"exchange": "SHFE", "multiplier": 10, "price_tick": 1.0},
    "ru": {"exchange": "SHFE", "multiplier": 10, "price_tick": 5.0},
    "sc": {"exchange": "INE", "multiplier": 1000, "price_tick": 0.1},
    "sp": {"exchange": "SHFE", "multiplier": 10, "price_tick": 2.0},
    "zn": {"exchange": "SHFE", "multiplier": 5, "price_tick": 5.0},
}


class CFastShadowInvalidError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _month(value: str) -> tuple[int, int]:
    try:
        year_text, month_text = value.split("-", 1)
        year, month = int(year_text), int(month_text)
        if value != f"{year:04d}-{month:02d}" or not 1 <= month <= 12:
            raise ValueError
        return year, month
    except (AttributeError, TypeError, ValueError) as exc:
        raise CFastShadowInvalidError("SOURCE_MONTH_INVALID") from exc


def _next_month(value: str) -> str:
    year, month = _month(value)
    return f"{year + 1:04d}-01" if month == 12 else f"{year:04d}-{month + 1:02d}"


def _close(left: float, right: float, *, tolerance: float = 1e-12) -> bool:
    return math.isclose(float(left), float(right), rel_tol=0, abs_tol=tolerance)


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))


class CommodityCFastShadowService:
    """Read-only signed C_FAST snapshot validator.

    The service intentionally has no order, cancellation, position, risk, or
    full RPC service dependency.  Its only external runtime capability is an
    optional read-only contract metadata loader.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        contract_loader: CFastContractLoader | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._contract_loader = contract_loader
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._state_load_error: str | None = None
        self._accepted_state = self._load_state()
        self._status = self._empty_status()

    def bind_contract_loader(self, loader: CFastContractLoader) -> None:
        with self._lock:
            self._contract_loader = loader

    def start(self) -> None:
        if self.settings.commodity_c_fast_shadow_enabled:
            self.reload(operator="system-startup", role="system", source_ip=None)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._status)

    def reload(
        self,
        *,
        operator: str,
        role: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        del source_ip  # Never persist client addresses in the research evidence.
        with self._lock:
            path_text = self.settings.commodity_c_fast_shadow_snapshot_path.strip()
            if not path_text:
                self._status = self._invalid_status(
                    "SNAPSHOT_PATH_NOT_CONFIGURED",
                    configured=False,
                    loaded=False,
                )
                return copy.deepcopy(self._status)
            paths_safe = not self.settings.commodity_c_fast_shadow_enabled
            try:
                if self.settings.commodity_c_fast_shadow_enabled:
                    self._verify_path_isolation()
                    paths_safe = True
                snapshot = self._load_snapshot(Path(path_text).expanduser())
                snapshot_hash = self._verify_snapshot(snapshot)
                continuity_state = self._verify_continuity(
                    snapshot, snapshot_hash
                )
                if (
                    self._accepted_state
                    and self._accepted_state.get("snapshot_hash")
                    == snapshot_hash
                ):
                    self._status = self._valid_status(
                        snapshot,
                        snapshot_hash,
                        continuity_state,
                        accepted=(
                            self.settings.commodity_c_fast_shadow_enabled
                        ),
                        idempotent=True,
                        reload_evidence_persisted=None,
                    )
                    return copy.deepcopy(self._status)
                if not self.settings.commodity_c_fast_shadow_enabled:
                    self._status = self._valid_status(
                        snapshot,
                        snapshot_hash,
                        continuity_state,
                        accepted=False,
                        idempotent=False,
                        reload_evidence_persisted=False,
                    )
                    return copy.deepcopy(self._status)
                self._verify_acceptance_freshness(snapshot)
                accepted = self._state_payload(
                    snapshot, snapshot_hash, continuity_state
                )
                self._write_state(accepted)
                self._accepted_state = accepted
                evidence_persisted = self._append_evidence_best_effort(
                    self._reload_evidence(
                        operator=operator,
                        role=role,
                        valid=True,
                        snapshot=snapshot,
                        snapshot_hash=snapshot_hash,
                        continuity_state=continuity_state,
                    )
                )
                self._status = self._valid_status(
                    snapshot,
                    snapshot_hash,
                    continuity_state,
                    accepted=True,
                    idempotent=False,
                    reload_evidence_persisted=evidence_persisted,
                )
            except Exception as exc:
                code = (
                    exc.code
                    if isinstance(exc, CFastShadowInvalidError)
                    else exc.__class__.__name__
                )
                loaded = code not in {
                    "SNAPSHOT_FILE_NOT_FOUND",
                    "SNAPSHOT_JSON_INVALID",
                    "SNAPSHOT_ROOT_INVALID",
                    "SNAPSHOT_TOO_LARGE",
                }
                self._status = self._invalid_status(
                    code, configured=True, loaded=loaded
                )
                if (
                    self.settings.commodity_c_fast_shadow_enabled
                    and paths_safe
                ):
                    self._append_evidence_best_effort(
                        {
                            "schema_version": "commodity_c_fast_shadow_reload_evidence_v1",
                            "reload_id": f"c-fast-reload-{uuid.uuid4().hex}",
                            "recorded_at_utc": self._clock()
                            .astimezone(timezone.utc)
                            .isoformat(),
                            "operator": operator,
                            "role": role,
                            "valid": False,
                            "validation_valid": False,
                            "error_code": code,
                            "state_load_error": self._state_load_error,
                            "authority_granted": False,
                            "dispatch_allowed": False,
                            "replacement_allowed": False,
                            "production_allowed": False,
                        }
                    )
            return copy.deepcopy(self._status)

    def _empty_status(self) -> dict[str, Any]:
        return {
            "configured": bool(
                self.settings.commodity_c_fast_shadow_snapshot_path.strip()
            ),
            "enabled": self.settings.commodity_c_fast_shadow_enabled,
            "loaded": False,
            "valid": False,
            "validation_valid": False,
            "accepted": False,
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "mode": "shadow_only",
            "read_only": True,
            "execution_quality_implemented": False,
            "contract_alignment": "NOT_CHECKED",
            "last_accepted": self._accepted_summary(),
            "state_load_error": self._state_load_error,
            **self._fixed_safety_status(),
        }

    def _valid_status(
        self,
        snapshot: CommodityCFastShadowDTO,
        snapshot_hash: str,
        continuity_state: str,
        *,
        accepted: bool,
        idempotent: bool,
        reload_evidence_persisted: bool | None,
    ) -> dict[str, Any]:
        return {
            "configured": True,
            "enabled": self.settings.commodity_c_fast_shadow_enabled,
            "loaded": True,
            "valid": accepted,
            "validation_valid": True,
            "candidate_id": snapshot.candidate_id,
            "frozen_rule_id": snapshot.frozen_rule_id,
            "frozen_rule_sha256": snapshot.frozen_rule_sha256,
            "mode": snapshot.mode,
            "execution_lane": snapshot.execution_lane,
            "read_only": True,
            "execution_quality_implemented": False,
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_hash": snapshot_hash,
            "formula_target_binding_sha256": (
                snapshot.formula_target_binding_sha256
            ),
            "source_month": snapshot.source_month,
            "source_official_day": snapshot.source_official_day.isoformat(),
            "execution_day": snapshot.execution_day.isoformat(),
            "continuity_state": continuity_state,
            "accepted": accepted,
            "idempotent": idempotent,
            "state_receipt_authoritative": accepted,
            "reload_evidence_persisted": reload_evidence_persisted,
            "contract_alignment": "RPC_SPEC_VERIFIED",
            "pit_main_alignment": snapshot.daily_roll_alignment,
            "calendar_alignment": snapshot.calendar_alignment,
            "allocator_output_validation": (
                snapshot.allocator_output_validation
            ),
            "source_target_derivation": (
                "SIGNED_RESEARCH_ASSERTION_NOT_RECOMPUTED"
            ),
            "target_count": len(snapshot.targets),
            "target_change_count": sum(
                target.previous_exact_contract != target.exact_contract
                or target.previous_target_quantity != target.target_quantity
                for target in snapshot.targets
            ),
            "last_accepted": self._accepted_summary(),
            "state_load_error": None,
            **self._fixed_safety_status(),
        }

    def _invalid_status(
        self, code: str, *, configured: bool, loaded: bool
    ) -> dict[str, Any]:
        contract_alignment = (
            "FAILED"
            if code.startswith(("RPC_", "CONTRACT_"))
            else "NOT_CHECKED"
        )
        return {
            "configured": configured,
            "enabled": self.settings.commodity_c_fast_shadow_enabled,
            "loaded": loaded,
            "valid": False,
            "validation_valid": False,
            "accepted": False,
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "mode": "shadow_only",
            "read_only": True,
            "execution_quality_implemented": False,
            "contract_alignment": contract_alignment,
            "pit_main_alignment": "NOT_CHECKED",
            "calendar_alignment": "NOT_CHECKED",
            "allocator_output_validation": "NOT_CHECKED",
            "error_code": code,
            "last_accepted": self._accepted_summary(),
            "state_load_error": self._state_load_error,
            **self._fixed_safety_status(),
        }

    def _reload_evidence(
        self,
        *,
        operator: str,
        role: str | None,
        valid: bool,
        snapshot: CommodityCFastShadowDTO,
        snapshot_hash: str,
        continuity_state: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": "commodity_c_fast_shadow_reload_evidence_v1",
            "reload_id": f"c-fast-reload-{uuid.uuid4().hex}",
            "recorded_at_utc": self._clock()
            .astimezone(timezone.utc)
            .isoformat(),
            "operator": operator,
            "role": role,
            "valid": valid,
            "validation_valid": valid,
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_hash": snapshot_hash,
            "source_month": snapshot.source_month,
            "continuity_state": continuity_state,
            "state_receipt_authoritative": True,
            "authority_granted": False,
            "dispatch_allowed": False,
            "replacement_allowed": False,
            "production_allowed": False,
        }

    @staticmethod
    def _fixed_safety_status() -> dict[str, Any]:
        return {
            "authority_granted": False,
            "dispatch_allowed": False,
            "replacement_allowed": False,
            "dynamic_selection_allowed": False,
            "production_allowed": False,
            "snapshot_producer_status": (
                "NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY"
            ),
            "orders_capability": False,
            "cancel_capability": False,
            "position_mutation_capability": False,
        }

    def _accepted_summary(self) -> dict[str, Any] | None:
        if not self._accepted_state:
            return None
        return {
            key: self._accepted_state.get(key)
            for key in (
                "snapshot_id",
                "snapshot_hash",
                "source_month",
                "source_official_day",
                "execution_day",
                "continuity_state",
                "accepted_at_utc",
            )
        }

    @staticmethod
    def _load_snapshot(path: Path) -> CommodityCFastShadowDTO:
        if not path.is_file():
            raise CFastShadowInvalidError("SNAPSHOT_FILE_NOT_FOUND")
        try:
            raw_bytes = path.read_bytes()
            if len(raw_bytes) > 2 * 1024 * 1024:
                raise CFastShadowInvalidError("SNAPSHOT_TOO_LARGE")
            raw = json.loads(raw_bytes.decode("utf-8"))
        except CFastShadowInvalidError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CFastShadowInvalidError("SNAPSHOT_JSON_INVALID") from exc
        if not isinstance(raw, dict):
            raise CFastShadowInvalidError("SNAPSHOT_ROOT_INVALID")
        try:
            return CommodityCFastShadowDTO.model_validate(raw)
        except ValidationError as exc:
            raise CFastShadowInvalidError("SNAPSHOT_SCHEMA_INVALID") from exc

    def _verify_snapshot(self, snapshot: CommodityCFastShadowDTO) -> str:
        self._verify_signature(snapshot)
        if (
            formula_target_binding_sha256(snapshot)
            != snapshot.formula_target_binding_sha256
        ):
            raise CFastShadowInvalidError("FORMULA_TARGET_BINDING_MISMATCH")
        self._verify_timing(snapshot)
        self._verify_targets(snapshot)
        self._verify_contract_alignment(snapshot)
        return sha256_json(unsigned_snapshot_payload(snapshot))

    def _verify_signature(self, snapshot: CommodityCFastShadowDTO) -> None:
        key = self._trusted_keys().get(snapshot.signer_key_id)
        if key is None:
            raise CFastShadowInvalidError("SIGNER_KEY_NOT_TRUSTED")
        try:
            signature = base64.b64decode(snapshot.signature, validate=True)
            key.verify(
                signature,
                canonical_json(unsigned_snapshot_payload(snapshot)),
            )
        except (InvalidSignature, ValueError, binascii.Error) as exc:
            raise CFastShadowInvalidError("SIGNATURE_INVALID") from exc

    def _trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        try:
            raw = json.loads(
                self.settings.commodity_c_fast_shadow_trusted_public_keys_json
            )
        except json.JSONDecodeError as exc:
            raise CFastShadowInvalidError("TRUSTED_KEYS_JSON_INVALID") from exc
        if not isinstance(raw, dict) or not raw:
            raise CFastShadowInvalidError("TRUSTED_KEYS_EMPTY")
        result: dict[str, Ed25519PublicKey] = {}
        for key_id, entry in raw.items():
            if not isinstance(entry, dict) or set(entry) != {
                "public_key_base64",
                "purpose",
            }:
                raise CFastShadowInvalidError("TRUSTED_KEY_ENTRY_INVALID")
            if entry["purpose"] != "research_snapshot_signer":
                raise CFastShadowInvalidError("TRUSTED_KEY_PURPOSE_INVALID")
            try:
                key_bytes = base64.b64decode(
                    str(entry["public_key_base64"]), validate=True
                )
                if len(key_bytes) != 32:
                    raise ValueError
                result[str(key_id)] = Ed25519PublicKey.from_public_bytes(
                    key_bytes
                )
            except (ValueError, binascii.Error) as exc:
                raise CFastShadowInvalidError("TRUSTED_KEY_INVALID") from exc
        return result

    def _verify_timing(self, snapshot: CommodityCFastShadowDTO) -> None:
        _month(snapshot.source_month)
        if snapshot.source_month < GENESIS_SOURCE_MONTH:
            raise CFastShadowInvalidError("SOURCE_MONTH_BEFORE_FORWARD_BOUNDARY")
        if snapshot.source_official_day.strftime("%Y-%m") != snapshot.source_month:
            raise CFastShadowInvalidError("SOURCE_DAY_MONTH_MISMATCH")
        if snapshot.execution_day.strftime("%Y-%m") != _next_month(
            snapshot.source_month
        ):
            raise CFastShadowInvalidError("EXECUTION_MONTH_NOT_NEXT_MONTH")
        if snapshot.execution_day <= snapshot.source_official_day:
            raise CFastShadowInvalidError("EXECUTION_NOT_AFTER_SOURCE")
        cutoff = snapshot.input_cutoff_at_utc
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise CFastShadowInvalidError("INPUT_CUTOFF_TIMEZONE_MISSING")
        if cutoff.astimezone(CHINA_TZ).date() != snapshot.source_official_day:
            raise CFastShadowInvalidError("INPUT_CUTOFF_DAY_MISMATCH")
        if cutoff.astimezone(CHINA_TZ).date() >= snapshot.execution_day:
            raise CFastShadowInvalidError("INPUT_CUTOFF_NOT_CAUSAL")
        created = snapshot.snapshot_created_at_utc
        if created.tzinfo is None or created.utcoffset() is None:
            raise CFastShadowInvalidError("SNAPSHOT_CREATED_TIMEZONE_MISSING")
        if created < cutoff:
            raise CFastShadowInvalidError("SNAPSHOT_CREATED_BEFORE_INPUT_CUTOFF")
        if created.astimezone(CHINA_TZ).date() != snapshot.execution_day:
            raise CFastShadowInvalidError("SNAPSHOT_CREATED_DAY_MISMATCH")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise CFastShadowInvalidError("SERVICE_CLOCK_TIMEZONE_MISSING")
        if created > now + MAX_CLOCK_SKEW:
            raise CFastShadowInvalidError("SNAPSHOT_CREATED_IN_FUTURE")
        if any(
            row.reference_price_observed_at_utc > now + MAX_CLOCK_SKEW
            for row in snapshot.targets
        ):
            raise CFastShadowInvalidError("REFERENCE_PRICE_OBSERVED_IN_FUTURE")

    def _verify_acceptance_freshness(
        self, snapshot: CommodityCFastShadowDTO
    ) -> None:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise CFastShadowInvalidError("SERVICE_CLOCK_TIMEZONE_MISSING")
        if now.astimezone(CHINA_TZ).date() != snapshot.execution_day:
            raise CFastShadowInvalidError(
                "SNAPSHOT_ACCEPTANCE_WINDOW_CLOSED"
            )

    def _verify_targets(self, snapshot: CommodityCFastShadowDTO) -> None:
        rows = sorted(snapshot.targets, key=lambda row: row.product)
        products = [row.product for row in rows]
        if tuple(products) != PRODUCTS or len(products) != len(set(products)):
            raise CFastShadowInvalidError("TARGET_UNIVERSE_INVALID")
        for row in rows:
            self._verify_target_row(row, snapshot)
            expected_score = (
                row.trend_21_sign
                + row.trend_63_sign
                + row.trend_126_sign
            ) / 3.0
            if not _close(row.source_score, expected_score):
                raise CFastShadowInvalidError("SOURCE_SCORE_FORMULA_MISMATCH")
            expected_raw = row.source_score / max(
                row.vol60_annualized, snapshot.volatility_floor
            )
            if not _close(row.raw_risk_score, expected_raw):
                raise CFastShadowInvalidError("RAW_RISK_SCORE_MISMATCH")
        observed_source = {
            row.product: row.source_target_weight for row in rows
        }
        self._verify_weight_caps(
            observed_source, product_cap=0.20, sector_cap=0.35, gross_cap=1.0
        )
        observed_buffered = {
            row.product: row.buffered_target_weight for row in rows
        }
        self._verify_weight_caps(
            observed_buffered,
            product_cap=0.12,
            sector_cap=0.27,
            gross_cap=0.80,
        )
        self._verify_integer_targets(snapshot)

    @staticmethod
    def _verify_weight_caps(
        weights: dict[str, float],
        *,
        product_cap: float,
        sector_cap: float,
        gross_cap: float,
    ) -> None:
        if any(not math.isfinite(value) for value in weights.values()):
            raise CFastShadowInvalidError("TARGET_WEIGHT_NONFINITE")
        if max(abs(value) for value in weights.values()) > product_cap + 1e-12:
            raise CFastShadowInvalidError("TARGET_PRODUCT_CAP_BREACH")
        if sum(abs(value) for value in weights.values()) > gross_cap + 1e-12:
            raise CFastShadowInvalidError("TARGET_GROSS_CAP_BREACH")
        if abs(sum(weights.values())) > 1e-10:
            raise CFastShadowInvalidError("TARGET_NET_NOT_ZERO")
        for sector in set(C_FAST_SECTOR_MAP_V1.values()):
            gross = sum(
                abs(weights[product])
                for product in PRODUCTS
                if C_FAST_SECTOR_MAP_V1[product] == sector
            )
            if gross > sector_cap + 1e-12:
                raise CFastShadowInvalidError("TARGET_SECTOR_CAP_BREACH")

    @staticmethod
    def _verify_target_row(
        row: Any, snapshot: CommodityCFastShadowDTO
    ) -> None:
        product = row.product
        if row.sector != C_FAST_SECTOR_MAP_V1[product]:
            raise CFastShadowInvalidError("TARGET_SECTOR_MISMATCH")
        spec = C_FAST_PRODUCT_SPECS_V1[product]
        pattern = rf"{spec['exchange']}\.{product}\d{{4}}"
        if not re.fullmatch(pattern, row.exact_contract):
            raise CFastShadowInvalidError("EXACT_CONTRACT_INVALID")
        if row.previous_exact_contract and not re.fullmatch(
            pattern, row.previous_exact_contract
        ):
            raise CFastShadowInvalidError("PREVIOUS_EXACT_CONTRACT_INVALID")
        if row.pit_main_exact_contract != row.exact_contract:
            raise CFastShadowInvalidError("PIT_MAIN_CONTRACT_MISMATCH")
        expected_roll = bool(
            row.previous_exact_contract
            and row.previous_exact_contract != row.exact_contract
        )
        if row.pit_main_roll != expected_roll:
            raise CFastShadowInvalidError("PIT_MAIN_ROLL_FLAG_MISMATCH")
        if row.previous_exact_contract is None and row.previous_target_quantity != 0:
            raise CFastShadowInvalidError("PREVIOUS_TARGET_WITHOUT_CONTRACT")
        if row.multiplier != spec["multiplier"] or not _close(
            row.price_tick, spec["price_tick"]
        ):
            raise CFastShadowInvalidError("FROZEN_CONTRACT_SPEC_MISMATCH")
        observed_at = row.reference_price_observed_at_utc
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise CFastShadowInvalidError(
                "REFERENCE_PRICE_TIMEZONE_MISSING"
            )
        if observed_at.astimezone(CHINA_TZ).date() != snapshot.execution_day:
            raise CFastShadowInvalidError("REFERENCE_PRICE_DAY_MISMATCH")
        if observed_at > snapshot.snapshot_created_at_utc:
            raise CFastShadowInvalidError(
                "REFERENCE_PRICE_AFTER_SNAPSHOT_CREATION"
            )
        expected_dte = (
            row.pit_main_official_last_trading_day - snapshot.execution_day
        ).days
        expected_following_dte = (
            row.pit_main_official_last_trading_day
            - row.pit_main_following_official_day
        ).days
        if row.pit_main_following_official_day <= snapshot.execution_day:
            raise CFastShadowInvalidError("PIT_FOLLOWING_DAY_INVALID")
        if (
            row.pit_main_dte != expected_dte
            or row.pit_main_following_dte != expected_following_dte
        ):
            raise CFastShadowInvalidError("PIT_DTE_ARITHMETIC_MISMATCH")
        if abs(row.previous_target_quantity) > 500 or abs(row.target_quantity) > 500:
            raise CFastShadowInvalidError("TARGET_QUANTITY_LIMIT")
        if row.target_quantity and (
            not row.buffered_target_weight
            or math.copysign(1, row.target_quantity)
            != math.copysign(1, row.buffered_target_weight)
        ):
            raise CFastShadowInvalidError("TARGET_QUANTITY_DIRECTION_MISMATCH")

    @staticmethod
    def _verify_integer_targets(snapshot: CommodityCFastShadowDTO) -> None:
        exposures: dict[str, float] = {}
        for row in snapshot.targets:
            unit_weight = (
                row.reference_open_price
                * row.multiplier
                / snapshot.virtual_nav_cny
            )
            exposures[row.product] = row.target_quantity * unit_weight
        if max(abs(value) for value in exposures.values()) >= 0.15 - 1e-12:
            raise CFastShadowInvalidError("INTEGER_PRODUCT_HARD_CAP_BREACH")
        if sum(abs(value) for value in exposures.values()) >= 1.0 - 1e-12:
            raise CFastShadowInvalidError("INTEGER_GROSS_HARD_CAP_BREACH")
        if abs(sum(exposures.values())) >= 0.10 - 1e-12:
            raise CFastShadowInvalidError("INTEGER_NET_HARD_CAP_BREACH")
        for sector in set(C_FAST_SECTOR_MAP_V1.values()):
            gross = sum(
                abs(exposures[product])
                for product in PRODUCTS
                if C_FAST_SECTOR_MAP_V1[product] == sector
            )
            if gross >= 0.35 - 1e-12:
                raise CFastShadowInvalidError("INTEGER_SECTOR_HARD_CAP_BREACH")

    def _verify_contract_alignment(
        self, snapshot: CommodityCFastShadowDTO
    ) -> None:
        if self._contract_loader is None:
            raise CFastShadowInvalidError("CONTRACT_LOADER_UNAVAILABLE")
        exacts = {row.exact_contract for row in snapshot.targets}
        exacts.update(
            row.previous_exact_contract
            for row in snapshot.targets
            if row.previous_exact_contract
        )
        try:
            contracts = self._contract_loader(exacts)
        except Exception as exc:
            raise CFastShadowInvalidError("CONTRACT_LOADER_FAILED") from exc
        if set(contracts) != exacts:
            raise CFastShadowInvalidError("RPC_CONTRACT_SET_MISMATCH")
        for row in snapshot.targets:
            for exact in {
                row.exact_contract,
                row.previous_exact_contract,
            } - {None}:
                contract = contracts[exact]
                multiplier = contract.get("multiplier", contract.get("size"))
                price_tick = contract.get(
                    "price_tick", contract.get("pricetick")
                )
                try:
                    multiplier_value = float(multiplier)
                    price_tick_value = float(price_tick)
                except (TypeError, ValueError) as exc:
                    raise CFastShadowInvalidError(
                        "RPC_CONTRACT_SPEC_MISMATCH"
                    ) from exc
                if not (
                    math.isfinite(multiplier_value)
                    and math.isfinite(price_tick_value)
                    and _close(multiplier_value, row.multiplier)
                    and _close(price_tick_value, row.price_tick)
                ):
                    raise CFastShadowInvalidError(
                        "RPC_CONTRACT_SPEC_MISMATCH"
                    )

    def _verify_continuity(
        self, snapshot: CommodityCFastShadowDTO, snapshot_hash: str
    ) -> str:
        if self._state_load_error:
            raise CFastShadowInvalidError("CONTINUITY_STATE_CORRUPT")
        previous = self._accepted_state
        if previous and previous.get("snapshot_hash") == snapshot_hash:
            return str(previous["continuity_state"])
        if previous is None:
            if (
                snapshot.source_month != GENESIS_SOURCE_MONTH
                or snapshot.previous_snapshot_hash is not None
                or any(
                    row.previous_exact_contract is not None
                    or row.previous_target_quantity != 0
                    for row in snapshot.targets
                )
            ):
                raise CFastShadowInvalidError("GENESIS_CONTINUITY_INVALID")
            return "genesis"
        if snapshot.source_month <= str(previous["source_month"]):
            raise CFastShadowInvalidError("SNAPSHOT_STALE_OR_REPLAYED")
        if snapshot.source_month != _next_month(str(previous["source_month"])):
            raise CFastShadowInvalidError("SOURCE_MONTH_CONTINUITY_GAP")
        if snapshot.previous_snapshot_hash != previous["snapshot_hash"]:
            raise CFastShadowInvalidError("PREVIOUS_SNAPSHOT_HASH_MISMATCH")
        return "verified"

    def _state_payload(
        self,
        snapshot: CommodityCFastShadowDTO,
        snapshot_hash: str,
        continuity_state: str,
    ) -> dict[str, Any]:
        core = {
            "schema_version": "commodity_c_fast_shadow_state_v1",
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_hash": snapshot_hash,
            "source_month": snapshot.source_month,
            "source_official_day": snapshot.source_official_day.isoformat(),
            "execution_day": snapshot.execution_day.isoformat(),
            "continuity_state": continuity_state,
            "accepted_at_utc": self._clock()
            .astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "targets": [
                {
                    "product": row.product,
                    "exact_contract": row.exact_contract,
                    "target_quantity": row.target_quantity,
                }
                for row in sorted(snapshot.targets, key=lambda item: item.product)
            ],
        }
        payload = {**core, "state_checksum": sha256_json(core)}
        return CommodityCFastShadowStateDTO.model_validate(payload).model_dump(
            mode="json"
        )

    def _load_state(self) -> dict[str, Any] | None:
        path = Path(
            self.settings.commodity_c_fast_shadow_state_path
        ).expanduser()
        if not path.exists():
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            self._state_load_error = "STATE_READ_FAILED"
            return None
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            self._state_load_error = "STATE_JSON_INVALID"
            return None
        try:
            state = CommodityCFastShadowStateDTO.model_validate(raw)
        except ValidationError:
            self._state_load_error = "STATE_SCHEMA_INVALID"
            return None
        products = tuple(sorted(row.product for row in state.targets))
        if products != PRODUCTS:
            self._state_load_error = "STATE_TARGET_UNIVERSE_INVALID"
            return None
        core = state.model_dump(mode="json", exclude={"state_checksum"})
        if state.state_checksum != sha256_json(core):
            self._state_load_error = "STATE_CHECKSUM_MISMATCH"
            return None
        if (
            state.accepted_at_utc.tzinfo is None
            or state.accepted_at_utc.utcoffset() is None
        ):
            self._state_load_error = "STATE_ACCEPTED_TIMEZONE_MISSING"
            return None
        return state.model_dump(mode="json")

    def _verify_path_isolation(self) -> None:
        c_paths = {
            Path(self.settings.commodity_c_fast_shadow_snapshot_path)
            .expanduser()
            .resolve(),
            Path(self.settings.commodity_c_fast_shadow_state_path)
            .expanduser()
            .resolve(),
            Path(self.settings.commodity_c_fast_shadow_evidence_path)
            .expanduser()
            .resolve(),
        }
        if len(c_paths) != 3:
            raise CFastShadowInvalidError("C_FAST_PATHS_NOT_DISTINCT")
        protected_texts = (
            self.settings.commodity_simnow_state_path,
            self.settings.commodity_simnow_template_batch_path,
            self.settings.commodity_position_manager_shadow_path,
            self.settings.commodity_position_manager_shadow_state_path,
            self.settings.commodity_position_manager_simnow_state_path,
        )
        protected = {
            Path(value).expanduser().resolve()
            for value in protected_texts
            if value.strip()
        }
        if c_paths & protected:
            raise CFastShadowInvalidError("C_FAST_PATH_COLLIDES_WITH_EXISTING")

    def _write_state(self, payload: dict[str, Any]) -> None:
        self._write_private_json(
            Path(self.settings.commodity_c_fast_shadow_state_path).expanduser(),
            payload,
        )

    @staticmethod
    def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(path)
            path.chmod(0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _append_evidence(self, payload: dict[str, Any]) -> None:
        path = Path(
            self.settings.commodity_c_fast_shadow_evidence_path
        ).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)

    def _append_evidence_best_effort(self, payload: dict[str, Any]) -> bool:
        try:
            self._append_evidence(payload)
            return True
        except OSError:
            return False


commodity_c_fast_shadow_service = CommodityCFastShadowService()


def normalize_rpc_contracts(
    contracts: list[dict[str, Any]], required: set[str]
) -> dict[str, dict[str, Any]]:
    """Normalize a read-only get_all_contracts result for the injected loader."""
    result: dict[str, dict[str, Any]] = {}
    for contract in contracts:
        symbol = str(contract.get("symbol") or "").strip().lower()
        exchange = _value(contract.get("exchange") or "").strip().upper()
        if not symbol or not exchange:
            vt_symbol = str(contract.get("vt_symbol") or "")
            if "." in vt_symbol:
                symbol, exchange = vt_symbol.rsplit(".", 1)
                symbol, exchange = symbol.lower(), exchange.upper()
        exact = f"{exchange}.{symbol}"
        if exact in required:
            if exact in result:
                raise CFastShadowInvalidError("RPC_CONTRACT_DUPLICATE")
            result[exact] = {
                "multiplier": contract.get("size", contract.get("multiplier")),
                "price_tick": contract.get(
                    "pricetick", contract.get("price_tick")
                ),
            }
    return result
