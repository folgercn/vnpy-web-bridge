from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, ROUND_HALF_UP
from typing import Annotated, Any, Literal, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BeforeValidator, ConfigDict, Field, model_validator

from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


Sha256 = str
DecimalString = Annotated[
    str,
    Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?$"),
]
FEE_STATEMENT_SIGNATURE_DOMAIN = (
    b"vnpy-web-bridge:commodity-c-fast-fee-statement:v1\x00"
)
MAX_FEE_CNY = Decimal("1000000000000")
CNY_CENT = Decimal("0.01")
_CONTRACT = re.compile(r"^[A-Za-z]{1,8}[0-9]{3,4}\.[A-Z]{2,12}$")
REQUIRED_EXCLUDED_AUTHORITY_DOMAINS = (
    "COMMODITY_BASELINE_EXECUTION_PERMIT",
    "C_FAST_EXECUTION_PERMIT",
    "C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION",
    "C_FAST_RESEARCH_ACCEPTANCE",
    "C_FAST_RESEARCH_BUNDLE",
    "MANUAL_EXECUTION_PERMIT",
)


def _strict_false(value: Any) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("value must be the boolean literal false")
    return False


StrictFalse = Annotated[Literal[False], BeforeValidator(_strict_false)]


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _parse_utc(value: str, field: str) -> datetime:
    try:
        normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        raise ValueError(f"{field} must use UTC")
    return parsed


def _valuation_belongs_to_trading_day(
    valuation_day: date,
    valuation_at_utc: datetime,
) -> bool:
    local = valuation_at_utc.astimezone(
        timezone(timedelta(hours=8))
    )
    day_gap = (valuation_day - local.date()).days
    return day_gap == 0 or (
        1 <= day_gap <= 3 and local.time() >= time(20, 0)
    )


def _decimal(value: str, field: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{field} is not decimal") from exc
    if not parsed.is_finite() or parsed < 0 or parsed > MAX_FEE_CNY:
        raise ValueError(f"{field} is outside the supported range")
    return parsed


def _decimal_text(value: Decimal) -> str:
    normalized = format(value, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"


def _require_cny_cent(value: str, field: str) -> Decimal:
    parsed = _decimal(value, field)
    if parsed.quantize(CNY_CENT) != parsed:
        raise ValueError(f"{field} must be quantized to CNY cent")
    return parsed


class StrictFeeModel(StrictFiniteModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, frozen=True)


class CommodityCFastFeeComponentRuleDTO(StrictFeeModel):
    by_volume_cny_per_lot: DecimalString
    by_turnover_rate: DecimalString
    minimum_cny_per_trade: DecimalString

    @model_validator(mode="after")
    def validate_amounts(self) -> "CommodityCFastFeeComponentRuleDTO":
        values = (
            _decimal(self.by_volume_cny_per_lot, "by_volume_cny_per_lot"),
            _decimal(self.by_turnover_rate, "by_turnover_rate"),
            _decimal(self.minimum_cny_per_trade, "minimum_cny_per_trade"),
        )
        if values[1] > Decimal("1"):
            raise ValueError("by_turnover_rate must not exceed one")
        return self


class CommodityCFastContractFeeRuleDTO(StrictFeeModel):
    rule_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    vt_symbol: str = Field(min_length=5, max_length=32)
    product: str = Field(
        min_length=1,
        max_length=8,
        pattern=r"^[a-z]{1,8}$",
    )
    exchange: str = Field(
        min_length=2,
        max_length=12,
        pattern=r"^[A-Z]{2,12}$",
    )
    offset: Literal["open", "close", "closetoday", "closeyesterday"]
    official_exchange: CommodityCFastFeeComponentRuleDTO
    broker_customer: CommodityCFastFeeComponentRuleDTO

    @model_validator(mode="after")
    def validate_contract(self) -> "CommodityCFastContractFeeRuleDTO":
        if not _CONTRACT.fullmatch(self.vt_symbol):
            raise ValueError("vt_symbol is not a concrete futures contract")
        if self.vt_symbol.rsplit(".", 1)[1] != self.exchange:
            raise ValueError("vt_symbol exchange suffix mismatch")
        symbol_product = re.match(r"^[A-Za-z]+", self.vt_symbol)
        if symbol_product is None or symbol_product.group(0).lower() != self.product:
            raise ValueError("vt_symbol product prefix mismatch")
        return self


class CommodityCFastFeeScheduleDTO(StrictFeeModel):
    schema_version: Literal["commodity_c_fast_fee_schedule_v1"]
    schedule_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    currency: Literal["CNY"]
    rounding_scope: Literal["PER_TRADE_COMPONENT"]
    rounding_mode: Literal["ROUND_HALF_EVEN", "ROUND_HALF_UP"]
    rounding_increment_cny: DecimalString
    rules: tuple[CommodityCFastContractFeeRuleDTO, ...] = Field(
        min_length=1,
        max_length=4096,
    )
    schedule_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_schedule(self) -> "CommodityCFastFeeScheduleDTO":
        increment = _decimal(self.rounding_increment_cny, "rounding_increment_cny")
        if increment != CNY_CENT:
            raise ValueError("rounding increment must be the CNY cent 0.01")
        identities = [(rule.vt_symbol, rule.offset) for rule in self.rules]
        if len(set(identities)) != len(identities):
            raise ValueError("fee rules duplicate contract/offset identity")
        if identities != sorted(identities):
            raise ValueError("fee rules must use canonical contract/offset order")
        core = self.model_dump(mode="json", exclude={"schedule_sha256"})
        if self.schedule_sha256 != sha256_bytes(canonical_json_bytes(core)):
            raise ValueError("schedule_sha256 mismatch")
        return self


class CommodityCFastFeeStatementDTO(StrictFeeModel):
    schema_version: Literal["commodity_c_fast_fee_statement_v1"]
    statement_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    signer_domain: Literal["C_FAST_SIMNOW_FEE_STATEMENT_V1"]
    issuer_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    signer_key_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    issued_at_utc: str = Field(min_length=20, max_length=40)
    not_before_at_utc: str = Field(min_length=20, max_length=40)
    expires_at_utc: str = Field(min_length=20, max_length=40)
    account_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    execution_environment: Literal["SIMNOW"]
    gateway_name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    execution_lane: Literal["simnow_shakedown"]
    session_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    trading_day: date
    effective_trading_day_start: date
    effective_trading_day_end: date
    session_archive_raw_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    orders_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    trades_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_document_raw_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_document_kind: Literal[
        "BROKER_CUSTOMER_FEE_STATEMENT",
        "BROKER_CUSTOMER_FEE_SCHEDULE",
    ]
    schedule: CommodityCFastFeeScheduleDTO
    signed_payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    signature_base64: str = Field(min_length=80, max_length=128)
    countable_forward: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_statement(self) -> "CommodityCFastFeeStatementDTO":
        issued = _parse_utc(self.issued_at_utc, "issued_at_utc")
        not_before = _parse_utc(self.not_before_at_utc, "not_before_at_utc")
        expires = _parse_utc(self.expires_at_utc, "expires_at_utc")
        if not not_before <= issued < expires:
            raise ValueError("fee statement lifetime is invalid")
        if not (
            self.effective_trading_day_start
            <= self.trading_day
            <= self.effective_trading_day_end
        ):
            raise ValueError("trading day is outside the effective fee window")
        core = self.model_dump(
            mode="json",
            exclude={"signed_payload_sha256", "signature_base64"},
        )
        if self.signed_payload_sha256 != sha256_bytes(canonical_json_bytes(core)):
            raise ValueError("signed_payload_sha256 mismatch")
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except ValueError as exc:
            raise ValueError("fee statement signature is not base64") from exc
        if len(signature) != 64:
            raise ValueError("fee statement signature length is invalid")
        return self


class CommodityCFastFeeStatementTrustedKeyDTO(StrictFeeModel):
    key_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    issuer_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    algorithm: Literal["Ed25519"]
    signer_domain: Literal["C_FAST_SIMNOW_FEE_STATEMENT_V1"]
    public_key_base64: str = Field(min_length=40, max_length=64)
    public_key_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    not_before_at_utc: str = Field(min_length=20, max_length=40)
    not_after_at_utc: str = Field(min_length=20, max_length=40)
    revoked: StrictFalse

    @model_validator(mode="after")
    def validate_key(self) -> "CommodityCFastFeeStatementTrustedKeyDTO":
        if _parse_utc(self.not_before_at_utc, "not_before_at_utc") >= _parse_utc(
            self.not_after_at_utc, "not_after_at_utc"
        ):
            raise ValueError("fee statement key lifetime is invalid")
        try:
            material = base64.b64decode(self.public_key_base64, validate=True)
        except ValueError as exc:
            raise ValueError("fee statement public key is not base64") from exc
        if len(material) != 32:
            raise ValueError("fee statement public key length is invalid")
        if self.public_key_sha256 != sha256_bytes(material):
            raise ValueError("fee statement public key hash mismatch")
        return self


class CommodityCFastFeeStatementTrustedKeyringDTO(StrictFeeModel):
    schema_version: Literal["commodity_c_fast_fee_statement_keyring_v1"]
    keyring_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    signer_domain: Literal["C_FAST_SIMNOW_FEE_STATEMENT_V1"]
    purpose: Literal["VERIFY_SIMNOW_FEE_STATEMENTS_ONLY"]
    trusted_keys: tuple[CommodityCFastFeeStatementTrustedKeyDTO, ...] = Field(
        min_length=1,
        max_length=32,
    )
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_keyring(
        self,
    ) -> "CommodityCFastFeeStatementTrustedKeyringDTO":
        key_ids = [key.key_id for key in self.trusted_keys]
        public_hashes = [key.public_key_sha256 for key in self.trusted_keys]
        if len(set(key_ids)) != len(key_ids) or len(set(public_hashes)) != len(
            public_hashes
        ):
            raise ValueError("fee statement keyring identities are not unique")
        if key_ids != sorted(key_ids):
            raise ValueError("fee statement keyring must use canonical key order")
        return self


class CommodityCFastTradeFeeChargeDTO(StrictFeeModel):
    vt_tradeid: str = Field(min_length=1, max_length=256)
    vt_orderid: str = Field(min_length=1, max_length=256)
    vt_symbol: str = Field(min_length=5, max_length=32)
    offset: Literal["open", "close", "closetoday", "closeyesterday"]
    rule_id: str = Field(min_length=8, max_length=128)
    volume: int = Field(ge=1, le=100_000)
    price: DecimalString
    multiplier: int = Field(ge=1, le=1_000_000)
    turnover_cny: DecimalString
    official_exchange_fee_cny: DecimalString
    broker_customer_fee_cny: DecimalString
    all_in_fee_cny: DecimalString

    @model_validator(mode="after")
    def validate_cent_amounts(self) -> "CommodityCFastTradeFeeChargeDTO":
        official = _require_cny_cent(
            self.official_exchange_fee_cny,
            "official_exchange_fee_cny",
        )
        broker = _require_cny_cent(
            self.broker_customer_fee_cny,
            "broker_customer_fee_cny",
        )
        all_in = _require_cny_cent(self.all_in_fee_cny, "all_in_fee_cny")
        if all_in != official + broker:
            raise ValueError("trade all-in fee does not match components")
        return self


class CommodityCFastFeeBindingEvidenceDTO(StrictFeeModel):
    schema_version: Literal["commodity_c_fast_fee_binding_evidence_v1"]
    fee_binding_state: Literal["BOUND"]
    statement: CommodityCFastFeeStatementDTO
    trusted_keyring: CommodityCFastFeeStatementTrustedKeyringDTO
    statement_raw_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_keyring_raw_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    excluded_authority_keyring_raw_sha256s: dict[str, Sha256] = Field(
        min_length=1,
        max_length=64,
    )
    excluded_authority_public_key_sha256s: dict[str, tuple[Sha256, ...]] = Field(
        min_length=1,
        max_length=64,
    )
    verified_at_utc: str = Field(min_length=20, max_length=40)
    trade_charges: tuple[CommodityCFastTradeFeeChargeDTO, ...] = Field(
        min_length=0,
        max_length=100_000,
    )
    official_exchange_fee_cny: DecimalString
    broker_customer_fee_cny: DecimalString
    all_in_cost_cny: DecimalString
    source_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    countable_forward: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_evidence(self) -> "CommodityCFastFeeBindingEvidenceDTO":
        statement_raw = canonical_json_bytes(self.statement.model_dump(mode="json"))
        keyring_raw = canonical_json_bytes(self.trusted_keyring.model_dump(mode="json"))
        if self.statement_raw_sha256 != sha256_bytes(statement_raw):
            raise ValueError("fee statement raw hash mismatch")
        if self.trusted_keyring_raw_sha256 != sha256_bytes(keyring_raw):
            raise ValueError("fee statement keyring raw hash mismatch")
        if tuple(sorted(self.excluded_authority_keyring_raw_sha256s)) != (
            REQUIRED_EXCLUDED_AUTHORITY_DOMAINS
        ):
            raise ValueError("required authority keyring domain map is incomplete")
        if tuple(sorted(self.excluded_authority_public_key_sha256s)) != (
            REQUIRED_EXCLUDED_AUTHORITY_DOMAINS
        ) or any(
            not values
            for role, values in self.excluded_authority_public_key_sha256s.items()
            if role != "MANUAL_EXECUTION_PERMIT"
        ):
            raise ValueError("required authority public key domain map is incomplete")
        if len(set(self.excluded_authority_keyring_raw_sha256s.values())) != len(
            self.excluded_authority_keyring_raw_sha256s
        ):
            raise ValueError("excluded authority keyring hashes are duplicated")
        if self.trusted_keyring_raw_sha256 in set(
            self.excluded_authority_keyring_raw_sha256s.values()
        ):
            raise ValueError("fee keyring overlaps another authority domain")
        public_rows = [
            item
            for values in self.excluded_authority_public_key_sha256s.values()
            for item in values
        ]
        excluded_public = set(public_rows)
        if len(excluded_public) != len(public_rows):
            raise ValueError("excluded authority public key hashes are duplicated")
        fee_public = {
            key.public_key_sha256 for key in self.trusted_keyring.trusted_keys
        }
        if fee_public & excluded_public:
            raise ValueError("fee signer key overlaps another authority domain")
        _verify_statement_signature(
            self.statement,
            self.trusted_keyring,
            self.verified_at_utc,
        )
        official = sum(
            (
                _decimal(row.official_exchange_fee_cny, "official fee")
                for row in self.trade_charges
            ),
            Decimal(0),
        )
        broker = sum(
            (
                _decimal(row.broker_customer_fee_cny, "broker fee")
                for row in self.trade_charges
            ),
            Decimal(0),
        )
        for value, field in (
            (self.official_exchange_fee_cny, "official_exchange_fee_cny"),
            (self.broker_customer_fee_cny, "broker_customer_fee_cny"),
            (self.all_in_cost_cny, "all_in_cost_cny"),
        ):
            _require_cny_cent(value, field)
        expected = (_decimal_text(official), _decimal_text(broker))
        if (
            self.official_exchange_fee_cny,
            self.broker_customer_fee_cny,
        ) != expected:
            raise ValueError("fee component totals do not match trade charges")
        if self.all_in_cost_cny != _decimal_text(official + broker):
            raise ValueError("all-in cost does not match fee components")
        source_core = {
            "statement_raw_sha256": self.statement_raw_sha256,
            "trusted_keyring_raw_sha256": self.trusted_keyring_raw_sha256,
            "excluded_authority_keyring_raw_sha256s": (
                self.excluded_authority_keyring_raw_sha256s
            ),
            "excluded_authority_public_key_sha256s": (
                self.excluded_authority_public_key_sha256s
            ),
            "trade_charges": [
                row.model_dump(mode="json") for row in self.trade_charges
            ],
        }
        if self.source_binding_sha256 != sha256_bytes(
            canonical_json_bytes(source_core)
        ):
            raise ValueError("fee source binding hash mismatch")
        return self


def verify_fee_statement_and_calculate(
    *,
    statement: CommodityCFastFeeStatementDTO,
    trusted_keyring: CommodityCFastFeeStatementTrustedKeyringDTO,
    statement_raw_sha256: str,
    trusted_keyring_raw_sha256: str,
    excluded_authority_keyring_raw_sha256s: Mapping[str, str],
    excluded_authority_public_key_sha256s: Mapping[str, Sequence[str]],
    verified_at_utc: str,
    archive_facts: Mapping[str, Any],
) -> CommodityCFastFeeBindingEvidenceDTO:
    statement_raw = canonical_json_bytes(statement.model_dump(mode="json"))
    keyring_raw = canonical_json_bytes(trusted_keyring.model_dump(mode="json"))
    if statement_raw_sha256 != sha256_bytes(statement_raw):
        raise ValueError("fee statement raw pin mismatch")
    if trusted_keyring_raw_sha256 != sha256_bytes(keyring_raw):
        raise ValueError("fee statement keyring raw pin mismatch")
    _verify_statement_signature(statement, trusted_keyring, verified_at_utc)
    trade_charges = _calculate_archive_trade_charges(
        statement,
        archive_facts,
        verified_at_utc=verified_at_utc,
    )
    official = sum(
        (
            _decimal(row.official_exchange_fee_cny, "official fee")
            for row in trade_charges
        ),
        Decimal(0),
    )
    broker = sum(
        (_decimal(row.broker_customer_fee_cny, "broker fee") for row in trade_charges),
        Decimal(0),
    )
    source_core = {
        "statement_raw_sha256": statement_raw_sha256,
        "trusted_keyring_raw_sha256": trusted_keyring_raw_sha256,
        "excluded_authority_keyring_raw_sha256s": dict(
            excluded_authority_keyring_raw_sha256s
        ),
        "excluded_authority_public_key_sha256s": {
            role: tuple(values)
            for role, values in excluded_authority_public_key_sha256s.items()
        },
        "trade_charges": [row.model_dump(mode="json") for row in trade_charges],
    }
    return CommodityCFastFeeBindingEvidenceDTO(
        schema_version="commodity_c_fast_fee_binding_evidence_v1",
        fee_binding_state="BOUND",
        statement=statement,
        trusted_keyring=trusted_keyring,
        statement_raw_sha256=statement_raw_sha256,
        trusted_keyring_raw_sha256=trusted_keyring_raw_sha256,
        excluded_authority_keyring_raw_sha256s=dict(
            excluded_authority_keyring_raw_sha256s
        ),
        excluded_authority_public_key_sha256s={
            role: tuple(values)
            for role, values in excluded_authority_public_key_sha256s.items()
        },
        verified_at_utc=verified_at_utc,
        trade_charges=trade_charges,
        official_exchange_fee_cny=_decimal_text(official),
        broker_customer_fee_cny=_decimal_text(broker),
        all_in_cost_cny=_decimal_text(official + broker),
        source_binding_sha256=sha256_bytes(canonical_json_bytes(source_core)),
        countable_forward=False,
        authority_granted=False,
        dispatch_allowed=False,
        production_allowed=False,
    )


def _verify_statement_signature(
    statement: CommodityCFastFeeStatementDTO,
    keyring: CommodityCFastFeeStatementTrustedKeyringDTO,
    verified_at_utc: str,
) -> None:
    verified_at = _parse_utc(verified_at_utc, "verified_at_utc")
    issued = _parse_utc(statement.issued_at_utc, "issued_at_utc")
    if not (
        _parse_utc(statement.not_before_at_utc, "not_before_at_utc")
        <= verified_at
        < _parse_utc(statement.expires_at_utc, "expires_at_utc")
    ):
        raise ValueError("fee statement is not active at verification time")
    selected = [
        key
        for key in keyring.trusted_keys
        if key.key_id == statement.signer_key_id
        and key.issuer_id == statement.issuer_id
    ]
    if len(selected) != 1:
        raise ValueError("fee statement signer identity is not uniquely trusted")
    key = selected[0]
    if not (
        _parse_utc(key.not_before_at_utc, "key.not_before_at_utc")
        <= issued
        < _parse_utc(key.not_after_at_utc, "key.not_after_at_utc")
    ):
        raise ValueError("fee statement signer was not active at issuance")
    material = base64.b64decode(key.public_key_base64, validate=True)
    signature = base64.b64decode(statement.signature_base64, validate=True)
    unsigned = statement.model_dump(
        mode="json",
        exclude={"signed_payload_sha256", "signature_base64"},
    )
    message = FEE_STATEMENT_SIGNATURE_DOMAIN + canonical_json_bytes(unsigned)
    try:
        Ed25519PublicKey.from_public_bytes(material).verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("fee statement signature verification failed") from exc


def _calculate_archive_trade_charges(
    statement: CommodityCFastFeeStatementDTO,
    archive_facts: Mapping[str, Any],
    *,
    verified_at_utc: str,
) -> tuple[CommodityCFastTradeFeeChargeDTO, ...]:
    archive = archive_facts.get("session_archive")
    if not isinstance(archive, Mapping):
        raise ValueError("session archive is missing from actual facts")
    execution = archive.get("execution")
    if not isinstance(execution, Mapping):
        raise ValueError("session archive execution is missing")
    raw = execution.get("terminal_raw_facts")
    if not isinstance(raw, Mapping):
        raise ValueError("session archive terminal facts are missing")
    expected_identity = (
        archive_facts.get("account_sha256"),
        archive_facts.get("session_id"),
        archive.get("signed_execution_day"),
        archive_facts.get("session_archive_raw_sha256"),
        archive_facts.get("orders_sha256"),
        archive_facts.get("trades_sha256"),
    )
    statement_identity = (
        statement.account_sha256,
        statement.session_id,
        statement.trading_day.isoformat(),
        statement.session_archive_raw_sha256,
        statement.orders_sha256,
        statement.trades_sha256,
    )
    if expected_identity != statement_identity:
        raise ValueError("fee statement session/archive identity mismatch")
    try:
        valuation_day = date.fromisoformat(
            str(archive_facts.get("valuation_day") or "")
        )
        archive_day = date.fromisoformat(str(archive.get("signed_execution_day") or ""))
    except ValueError as exc:
        raise ValueError("fee statement archive day is invalid") from exc
    valuation_at = _parse_utc(
        str(archive_facts.get("valuation_at_utc") or ""),
        "archive_facts.valuation_at_utc",
    )
    archive_completed = _parse_utc(
        str(archive.get("completed_at_utc") or ""),
        "archive.completed_at_utc",
    )
    issued_at = _parse_utc(statement.issued_at_utc, "statement.issued_at_utc")
    verified_at = _parse_utc(verified_at_utc, "verified_at_utc")
    archive_as_of = _parse_utc(
        str(archive_facts.get("as_of_at_utc") or ""),
        "archive_facts.as_of_at_utc",
    )
    if (
        statement.trading_day != valuation_day
        or archive_day != valuation_day
        or not _valuation_belongs_to_trading_day(
            valuation_day,
            valuation_at,
        )
    ):
        raise ValueError("fee statement trading/valuation day join mismatch")
    if not archive_completed <= issued_at <= verified_at <= archive_as_of:
        raise ValueError("fee statement temporal causality is invalid")
    guard = execution.get("terminal_guard")
    if not isinstance(guard, Mapping):
        raise ValueError("fee statement requires terminal gateway evidence")
    resolved_gateways = {
        str(guard.get("gateway_before") or ""),
        str(guard.get("gateway_after") or ""),
    }
    if (
        statement.execution_environment != "SIMNOW"
        or statement.execution_lane != archive.get("execution_lane")
        or resolved_gateways != {statement.gateway_name}
    ):
        raise ValueError("fee statement environment/gateway/lane mismatch")
    if not (
        statement.effective_trading_day_start
        <= statement.trading_day
        <= statement.effective_trading_day_end
    ):
        raise ValueError("fee statement is outside the effective trading window")
    trades = raw.get("trades")
    orders = raw.get("orders")
    contract_specs = raw.get("contract_specs")
    if (
        not isinstance(trades, list)
        or not isinstance(orders, list)
        or not all(isinstance(row, Mapping) for row in trades)
        or not all(isinstance(row, Mapping) for row in orders)
        or not isinstance(contract_specs, Mapping)
    ):
        raise ValueError("fee statement requires canonical order/trade facts")

    submitted = execution.get("submitted")
    snapshot = execution.get("execution_snapshot")
    if not isinstance(submitted, Mapping) or not isinstance(snapshot, Mapping):
        raise ValueError("fee statement requires submitted and execution facts")
    submitted_rows = [
        row
        for phase in ("close", "open")
        for row in submitted.get(phase, [])
        if isinstance(row, Mapping)
    ]
    snapshot_rows = snapshot.get("orders")
    if (
        not submitted_rows
        or not isinstance(snapshot_rows, list)
        or not all(isinstance(row, Mapping) for row in snapshot_rows)
    ):
        raise ValueError("fee statement plan-scope facts are incomplete")

    def row_hash(rows: list[Mapping[str, Any]]) -> str:
        row_hashes = [sha256_bytes(canonical_json_bytes(row)) for row in rows]
        return sha256_bytes(canonical_json_bytes(sorted(row_hashes)))

    if (
        row_hash(orders) != archive_facts.get("orders_sha256")
        or row_hash(trades) != archive_facts.get("trades_sha256")
        or raw.get("orders_sha256") != archive_facts.get("orders_sha256")
        or raw.get("trades_sha256") != archive_facts.get("trades_sha256")
    ):
        raise ValueError("fee statement raw order/trade hash join mismatch")
    def gateway_identity(row: Mapping[str, Any], kind: str) -> str:
        value = str(row.get(f"vt_{kind}id") or row.get(f"{kind}id") or "")
        gateway = str(row.get("gateway_name") or "")
        if value and gateway and not value.startswith(f"{gateway}."):
            return f"{gateway}.{value}"
        return value

    trade_ids = [gateway_identity(row, "trade") for row in trades]
    if any(not value for value in trade_ids) or len(set(trade_ids)) != len(trade_ids):
        raise ValueError("fee trade identities are missing or duplicated")

    def unique_by_order_id(
        rows: Sequence[Mapping[str, Any]],
        *,
        label: str,
    ) -> dict[str, Mapping[str, Any]]:
        result: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            order_id = gateway_identity(row, "order")
            if not order_id or order_id in result:
                raise ValueError(f"fee {label} order identity is missing or duplicated")
            result[order_id] = row
        return result

    orders_by_id = unique_by_order_id(orders, label="archive")
    submitted_by_id = unique_by_order_id(submitted_rows, label="submitted")
    snapshot_by_id = unique_by_order_id(snapshot_rows, label="snapshot")
    if not (set(orders_by_id) == set(submitted_by_id) == set(snapshot_by_id)):
        raise ValueError("fee archive orders do not exactly join submitted plan")

    order_trade_totals = {order_id: 0 for order_id in orders_by_id}
    order_trade_counts = {order_id: 0 for order_id in orders_by_id}
    for order_id, order in orders_by_id.items():
        submitted_row = submitted_by_id[order_id]
        gateway = str(order.get("gateway_name") or "")
        if (
            gateway != statement.gateway_name
            or str(order.get("reference") or "")
            != str(submitted_row.get("reference") or "")
            or not str(order.get("reference") or "")
            or str(order.get("vt_symbol") or "")
            != str(submitted_row.get("vt_symbol") or "")
            or _normalize_direction(order.get("direction"))
            != _normalize_direction(submitted_row.get("direction"))
            or _normalize_offset(order.get("offset"))
            != _normalize_offset(submitted_row.get("offset"))
            or _strict_positive_integer(order.get("volume"), "order volume")
            != _strict_positive_integer(submitted_row.get("volume"), "submitted volume")
        ):
            raise ValueError("fee archive order is spliced from another scope")

    rules = {(rule.vt_symbol, rule.offset): rule for rule in statement.schedule.rules}
    charges: list[CommodityCFastTradeFeeChargeDTO] = []
    for trade in sorted(trades, key=lambda row: gateway_identity(row, "trade")):
        trade_gateway = str(trade.get("gateway_name") or "")
        if trade_gateway != statement.gateway_name:
            raise ValueError("fee trade does not exactly join archived order")
        order_id = gateway_identity(trade, "order")
        order = orders_by_id.get(order_id)
        if order is None:
            raise ValueError("fee trade is orphaned from archived order")
        symbol = str(trade.get("vt_symbol") or "")
        offset = _normalize_offset(trade.get("offset"))
        direction = _normalize_direction(trade.get("direction"))
        if (
            symbol != str(order.get("vt_symbol") or "")
            or direction != _normalize_direction(order.get("direction"))
            or offset != _normalize_offset(order.get("offset"))
            or not str(trade.get("reference") or "")
            or str(trade.get("reference") or "") != str(order.get("reference") or "")
        ):
            raise ValueError("fee trade does not exactly join archived order")
        rule = rules.get((symbol, offset))
        if rule is None:
            raise ValueError("fee schedule does not cover an archived trade")
        spec = contract_specs.get(symbol)
        if not isinstance(spec, Mapping):
            raise ValueError("fee trade contract spec is missing")
        exchange = symbol.rsplit(".", 1)[1] if "." in symbol else ""
        if (
            spec.get("product") != rule.product
            or exchange != rule.exchange
            or rule.vt_symbol != symbol
        ):
            raise ValueError("fee rule contract identity mismatch")
        volume_raw = _strict_positive_integer(trade.get("volume"), "trade volume")
        multiplier_raw = spec.get("multiplier")
        if type(multiplier_raw) is not int or multiplier_raw <= 0:
            raise ValueError("fee trade volume or multiplier is invalid")
        order_trade_totals[order_id] += volume_raw
        order_trade_counts[order_id] += 1
        if order_trade_totals[order_id] > _strict_positive_integer(
            order.get("volume"), "order volume"
        ):
            raise ValueError("fee trade volume exceeds archived order")
        price_raw = trade.get("price")
        if type(price_raw) not in {int, float}:
            raise ValueError("fee trade price is invalid")
        price = Decimal(str(price_raw))
        if not price.is_finite() or price <= 0:
            raise ValueError("fee trade price is invalid")
        turnover = price * Decimal(multiplier_raw) * Decimal(volume_raw)
        official = _component_charge(
            rule.official_exchange,
            volume_raw,
            turnover,
            statement.schedule,
        )
        broker = _component_charge(
            rule.broker_customer,
            volume_raw,
            turnover,
            statement.schedule,
        )
        charges.append(
            CommodityCFastTradeFeeChargeDTO(
                vt_tradeid=gateway_identity(trade, "trade"),
                vt_orderid=order_id,
                vt_symbol=symbol,
                offset=offset,
                rule_id=rule.rule_id,
                volume=volume_raw,
                price=_decimal_text(price),
                multiplier=multiplier_raw,
                turnover_cny=_decimal_text(turnover),
                official_exchange_fee_cny=_decimal_text(official),
                broker_customer_fee_cny=_decimal_text(broker),
                all_in_fee_cny=_decimal_text(official + broker),
            )
        )
    if {row.vt_tradeid for row in charges} != set(trade_ids):
        raise ValueError("fee statement trade join is incomplete")
    for order_id, order in orders_by_id.items():
        snapshot_row = snapshot_by_id[order_id]
        filled = order_trade_totals[order_id]
        status = str(order.get("status") or "").strip().lower().replace("-", "_")
        if (
            _strict_nonnegative_integer(
                snapshot_row.get("filled_volume"), "snapshot filled volume"
            )
            != filled
            or _strict_nonnegative_integer(
                snapshot_row.get("trade_count"), "snapshot trade count"
            )
            != order_trade_counts[order_id]
            or (
                status in {"all_traded", "alltraded", "filled", "全部成交"}
                and filled
                != _strict_positive_integer(order.get("volume"), "order volume")
            )
            or (status == "rejected" and filled != 0)
        ):
            raise ValueError("fee trade accumulation does not explain order state")
    return tuple(charges)


def _normalize_offset(value: Any) -> str:
    raw = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    normalized = {
        "开": "open",
        "平": "close",
        "平今": "closetoday",
        "平昨": "closeyesterday",
    }.get(raw, raw)
    if normalized not in {"open", "close", "closetoday", "closeyesterday"}:
        raise ValueError("fee trade offset is invalid")
    return normalized


def _normalize_direction(value: Any) -> str:
    raw = str(value).strip().lower()
    normalized = {"多": "long", "空": "short"}.get(raw, raw)
    if normalized not in {"long", "short"}:
        raise ValueError("fee trade direction is invalid")
    return normalized


def _strict_positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} is invalid")
    return value


def _strict_nonnegative_integer(value: Any, field: str) -> int:
    if type(value) is int and value >= 0:
        return value
    if type(value) is float and value.is_integer() and value >= 0:
        return int(value)
    raise ValueError(f"{field} is invalid")


def _component_charge(
    rule: CommodityCFastFeeComponentRuleDTO,
    volume: int,
    turnover: Decimal,
    schedule: CommodityCFastFeeScheduleDTO,
) -> Decimal:
    raw = (
        _decimal(rule.by_volume_cny_per_lot, "by_volume_cny_per_lot") * Decimal(volume)
        + _decimal(rule.by_turnover_rate, "by_turnover_rate") * turnover
    )
    minimum = _decimal(rule.minimum_cny_per_trade, "minimum_cny_per_trade")
    charge = max(raw, minimum)
    increment = _decimal(schedule.rounding_increment_cny, "rounding_increment_cny")
    rounding = (
        ROUND_HALF_EVEN
        if schedule.rounding_mode == "ROUND_HALF_EVEN"
        else ROUND_HALF_UP
    )
    units = (charge / increment).quantize(Decimal("1"), rounding=rounding)
    return units * increment
