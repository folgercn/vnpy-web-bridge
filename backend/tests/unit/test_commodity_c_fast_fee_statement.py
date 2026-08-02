from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.core.errors import CommoditySimNowStateError
from app.core.config import Settings
from app.schemas.commodity_c_fast_fee_statement import (
    FEE_STATEMENT_SIGNATURE_DOMAIN,
    CommodityCFastFeeBindingEvidenceDTO,
    CommodityCFastFeeStatementDTO,
    CommodityCFastFeeStatementTrustedKeyringDTO,
    canonical_json_bytes,
    sha256_bytes,
    verify_fee_statement_and_calculate,
)
from app.schemas.commodity_c_fast_pnl_ledger import (
    ActualSimNowFeeBoundArchiveReplayFactsDTO,
    ActualSimNowSettledArchiveReplayFactsDTO,
    sha256_json,
)
from app.services.commodity_c_fast_fee_statement import (
    CFastFeeStatementError,
    load_and_verify_fee_binding,
    load_and_verify_fee_binding_with_trust_context_from_settings,
    load_and_verify_late_fee_correction_from_settings,
    load_fee_binding_trust_context_from_settings,
)
import app.services.commodity_c_fast_fee_statement as fee_statement_service
from app.services.commodity_c_fast_fee_binding_trust import (
    FeeBindingTrustContext,
    _mint_fee_binding_trust_context,
)
from app.services.commodity_c_fast_pnl_ledger import (
    CFastPnlLedgerError,
    build_actual_simnow_fee_bound_source_facts,
    build_actual_simnow_settled_archive_replay_source_facts,
    reattest_settled_archive_replay,
    reload_and_verify_four_layer_pnl_entry,
    settled_archive_replay_from_v4,
)
from app.services.commodity_c_fast_pnl_ledger_repository import (
    CFastPnlLedgerRepositoryError,
    CommodityCFastPnlLedgerRepository,
    reload_and_verify_repository_export,
)
from app.services.vnpy_rpc_service import RpcTimeoutError
from test_commodity_c_fast_simnow import (
    fills_for_submitted,
    prepare_c_fast_shakedown,
)
from test_commodity_c_fast_pnl_ledger import (
    _rehash_entry,
    build,
    rehash_verified_session_archive,
    source_inputs,
    source_inputs_with_verified_actual,
)
from test_commodity_simnow import FakeTrade, position


AUTHORITY_RAW_HASHES = {
    "COMMODITY_BASELINE_EXECUTION_PERMIT": "1" * 64,
    "C_FAST_EXECUTION_PERMIT": "2" * 64,
    "C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION": "3" * 64,
    "C_FAST_RESEARCH_ACCEPTANCE": "4" * 64,
    "C_FAST_RESEARCH_BUNDLE": "5" * 64,
    "MANUAL_EXECUTION_PERMIT": "6" * 64,
}
AUTHORITY_PUBLIC_HASHES = {
    "COMMODITY_BASELINE_EXECUTION_PERMIT": ("7" * 64,),
    "C_FAST_EXECUTION_PERMIT": ("8" * 64,),
    "C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION": ("9" * 64,),
    "C_FAST_RESEARCH_ACCEPTANCE": ("a" * 64,),
    "C_FAST_RESEARCH_BUNDLE": ("b" * 64,),
    "MANUAL_EXECUTION_PERMIT": ("c" * 64,),
}


class _AcceptedWithIdentityTimeoutTrade(FakeTrade):
    def send_order(self, request: Any, **kwargs: Any) -> dict[str, Any]:
        assert self.rpc is not None
        self.requests.append(request)
        self.rpc.orders.append(
            {
                "vt_orderid": "CTP.1",
                "orderid": "1",
                "reference": request.reference,
                "symbol": request.symbol,
                "vt_symbol": f"{request.symbol}.{request.exchange}",
                "gateway_name": "CTP",
                "direction": request.direction,
                "offset": request.offset,
                "volume": request.volume,
                "price": request.price,
                "status": "not_traded",
            }
        )
        raise RpcTimeoutError()


def _schedule() -> dict[str, Any]:
    rules = [
        {
            "rule_id": "fee-rule-ag-open-v1",
            "vt_symbol": "ag2609.SHFE",
            "product": "ag",
            "exchange": "SHFE",
            "offset": "open",
            "official_exchange": {
                "by_volume_cny_per_lot": "1",
                "by_turnover_rate": "0",
                "minimum_cny_per_trade": "5",
            },
            "broker_customer": {
                "by_volume_cny_per_lot": "0",
                "by_turnover_rate": "0.001",
                "minimum_cny_per_trade": "0",
            },
        },
        {
            "rule_id": "fee-rule-cu-open-v1",
            "vt_symbol": "cu2609.SHFE",
            "product": "cu",
            "exchange": "SHFE",
            "offset": "open",
            "official_exchange": {
                "by_volume_cny_per_lot": "1",
                "by_turnover_rate": "0",
                "minimum_cny_per_trade": "0",
            },
            "broker_customer": {
                "by_volume_cny_per_lot": "0",
                "by_turnover_rate": "0.001",
                "minimum_cny_per_trade": "0",
            },
        },
    ]
    core = {
        "schema_version": "commodity_c_fast_fee_schedule_v1",
        "schedule_id": "simnow-fee-schedule-20260902",
        "currency": "CNY",
        "rounding_scope": "PER_TRADE_COMPONENT",
        "rounding_mode": "ROUND_HALF_EVEN",
        "rounding_increment_cny": "0.01",
        "rules": rules,
    }
    return {
        **core,
        "schedule_sha256": sha256_bytes(canonical_json_bytes(core)),
    }


def _schedule_for_archive(archive_facts: dict[str, Any]) -> dict[str, Any]:
    raw = archive_facts["session_archive"]["execution"]["terminal_raw_facts"]
    identities = sorted(
        {(str(row["vt_symbol"]), str(row["offset"])) for row in raw["orders"]}
    )
    rules = []
    for index, (vt_symbol, offset) in enumerate(identities, start=1):
        product = str(raw["contract_specs"][vt_symbol]["product"])
        rules.append(
            {
                "rule_id": f"runtime-fee-rule-{product}-{offset}-{index}",
                "vt_symbol": vt_symbol,
                "product": product,
                "exchange": vt_symbol.rsplit(".", 1)[1],
                "offset": offset,
                "official_exchange": {
                    "by_volume_cny_per_lot": "1",
                    "by_turnover_rate": "0",
                    "minimum_cny_per_trade": "5",
                },
                "broker_customer": {
                    "by_volume_cny_per_lot": "0",
                    "by_turnover_rate": "0.001",
                    "minimum_cny_per_trade": "0",
                },
            }
        )
    core = {
        "schema_version": "commodity_c_fast_fee_schedule_v1",
        "schedule_id": "runtime-simnow-fee-schedule-v1",
        "currency": "CNY",
        "rounding_scope": "PER_TRADE_COMPONENT",
        "rounding_mode": "ROUND_HALF_EVEN",
        "rounding_increment_cny": "0.01",
        "rules": rules,
    }
    return {
        **core,
        "schedule_sha256": sha256_bytes(canonical_json_bytes(core)),
    }


def _signed_artifacts(
    archive_facts: dict[str, Any],
    *,
    private: Ed25519PrivateKey | None = None,
    gateway_name: str | None = None,
    expires_at_utc: str = "2026-09-02T09:00:00Z",
    source_document_raw_sha256: str = "f" * 64,
    schedule: dict[str, Any] | None = None,
    issued_at_utc: str = "2026-09-02T08:01:40Z",
    not_before_at_utc: str = "2026-09-02T08:01:30Z",
    trading_day: str = "2026-09-02",
) -> tuple[dict[str, Any], dict[str, Any], Ed25519PrivateKey]:
    private = private or Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    resolved_gateway = gateway_name or str(
        archive_facts["session_archive"]["execution"]["terminal_guard"]["gateway_after"]
    )
    core = {
        "schema_version": "commodity_c_fast_fee_statement_v1",
        "statement_id": "simnow-fee-statement-session-a-v1",
        "signer_domain": "C_FAST_SIMNOW_FEE_STATEMENT_V1",
        "issuer_id": "simnow-broker-fee-operations",
        "signer_key_id": "simnow-fee-key-2026-v1",
        "issued_at_utc": issued_at_utc,
        "not_before_at_utc": not_before_at_utc,
        "expires_at_utc": expires_at_utc,
        "account_sha256": archive_facts["account_sha256"],
        "execution_environment": "SIMNOW",
        "gateway_name": resolved_gateway,
        "execution_lane": "simnow_shakedown",
        "session_id": archive_facts["session_id"],
        "trading_day": trading_day,
        "effective_trading_day_start": "2026-09-01",
        "effective_trading_day_end": "2026-09-30",
        "session_archive_raw_sha256": archive_facts["session_archive_raw_sha256"],
        "orders_sha256": archive_facts["orders_sha256"],
        "trades_sha256": archive_facts["trades_sha256"],
        "source_document_raw_sha256": source_document_raw_sha256,
        "source_document_kind": "BROKER_CUSTOMER_FEE_STATEMENT",
        "schedule": schedule or _schedule(),
        "countable_forward": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
    }
    signed_payload_sha256 = sha256_bytes(canonical_json_bytes(core))
    signature = private.sign(
        FEE_STATEMENT_SIGNATURE_DOMAIN + canonical_json_bytes(core)
    )
    statement = {
        **core,
        "signed_payload_sha256": signed_payload_sha256,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }
    keyring = {
        "schema_version": "commodity_c_fast_fee_statement_keyring_v1",
        "keyring_id": "simnow-fee-keyring-2026-v1",
        "signer_domain": "C_FAST_SIMNOW_FEE_STATEMENT_V1",
        "purpose": "VERIFY_SIMNOW_FEE_STATEMENTS_ONLY",
        "trusted_keys": [
            {
                "key_id": "simnow-fee-key-2026-v1",
                "issuer_id": "simnow-broker-fee-operations",
                "algorithm": "Ed25519",
                "signer_domain": "C_FAST_SIMNOW_FEE_STATEMENT_V1",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "public_key_sha256": hashlib.sha256(public).hexdigest(),
                "not_before_at_utc": "2026-09-01T00:00:00Z",
                "not_after_at_utc": "2026-10-01T00:00:00Z",
                "revoked": False,
            }
        ],
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
    }
    return statement, keyring, private


def _evidence(
    archive_facts: dict[str, Any],
    *,
    statement: dict[str, Any] | None = None,
    keyring: dict[str, Any] | None = None,
    verified_at_utc: str = "2026-09-02T08:01:50Z",
) -> CommodityCFastFeeBindingEvidenceDTO:
    if statement is None or keyring is None:
        statement, keyring, _ = _signed_artifacts(archive_facts)
    statement_dto = CommodityCFastFeeStatementDTO.model_validate(statement)
    keyring_dto = CommodityCFastFeeStatementTrustedKeyringDTO.model_validate(keyring)
    return verify_fee_statement_and_calculate(
        statement=statement_dto,
        trusted_keyring=keyring_dto,
        statement_raw_sha256=sha256_bytes(canonical_json_bytes(statement)),
        trusted_keyring_raw_sha256=sha256_bytes(canonical_json_bytes(keyring)),
        excluded_authority_keyring_raw_sha256s=AUTHORITY_RAW_HASHES,
        excluded_authority_public_key_sha256s=AUTHORITY_PUBLIC_HASHES,
        verified_at_utc=verified_at_utc,
        archive_facts=archive_facts,
    )


def _trust_context(
    evidence: CommodityCFastFeeBindingEvidenceDTO,
) -> FeeBindingTrustContext:
    return _mint_fee_binding_trust_context(
        fee_keyring_raw_sha256=evidence.trusted_keyring_raw_sha256,
        excluded_authority_keyring_raw_sha256s=(
            evidence.excluded_authority_keyring_raw_sha256s
        ),
        excluded_authority_public_key_sha256s=(
            evidence.excluded_authority_public_key_sha256s
        ),
    )


def _historical_trust_profile(
    evidence: CommodityCFastFeeBindingEvidenceDTO,
) -> dict[str, Any]:
    return {
        "profile_id": "fee-trust-profile-20260902-v1",
        "fee_keyring_raw_sha256": evidence.trusted_keyring_raw_sha256,
        "excluded_authority_keyring_raw_sha256s": dict(
            evidence.excluded_authority_keyring_raw_sha256s
        ),
        "excluded_authority_public_key_sha256s": {
            role: list(pins)
            for role, pins in (
                evidence.excluded_authority_public_key_sha256s.items()
            )
        },
    }


def _write_private(path: Path, payload: dict[str, Any]) -> bytes:
    raw = canonical_json_bytes(payload)
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def _authority_keyrings(
    tmp_path: Path,
    *,
    reused_public_by_role: dict[str, bytes] | None = None,
) -> dict[str, tuple[Path, str]]:
    contracts = {
        "COMMODITY_BASELINE_EXECUTION_PERMIT": (
            "commodity_baseline_execution_permit_trusted_keys_v1",
            "commodity_baseline_execution_permit_verification",
            "trusted_keys",
        ),
        "C_FAST_EXECUTION_PERMIT": (
            "commodity_c_fast_simnow_execution_permit_trusted_keys_v1",
            "c_fast_simnow_control_execution_permit_verification",
            "trusted_keys",
        ),
        "C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION": (
            "commodity_c_fast_execution_quality_runtime_admission_trusted_keys_v1",
            "c_fast_execution_quality_runtime_admission_signature_verification",
            "trusted_keys",
        ),
        "C_FAST_RESEARCH_ACCEPTANCE": (
            "commodity_c_fast_simnow_research_acceptance_trusted_keys_v1",
            "c_fast_simnow_research_acceptance_signer",
            "keys",
        ),
        "C_FAST_RESEARCH_BUNDLE": (
            "commodity_c_fast_simnow_research_bundle_trusted_keys_v1",
            "c_fast_simnow_research_bundle_signer",
            "keys",
        ),
    }
    result: dict[str, tuple[Path, str]] = {}
    for index, (role, (version, purpose, rows_field)) in enumerate(contracts.items()):
        public = (reused_public_by_role or {}).get(role)
        if public is None:
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        row = {
            "key_id": f"authority-key-{index:02d}",
            "public_key_base64": base64.b64encode(public).decode("ascii"),
        }
        if rows_field == "trusted_keys":
            if role != "COMMODITY_BASELINE_EXECUTION_PERMIT":
                row.update(
                    {
                        "signer_type": "human",
                        "reviewer_role": f"authority-reviewer-{index:02d}",
                    }
                )
            else:
                row["purpose"] = "commodity_baseline_execution_permit_signer"
        else:
            row["purpose"] = purpose
        payload = {
            "schema_version": version,
            "purpose": purpose,
            rows_field: [row],
        }
        path = (tmp_path / f"authority-{index}.json").resolve()
        raw = _write_private(path, payload)
        result[role] = (path, sha256_bytes(raw))
    return result


def _fee_settings(
    *,
    fee_keyring_path: Path,
    fee_keyring_raw_sha256: str,
    authority: dict[str, tuple[Path, str]],
    historical_profiles: tuple[dict[str, Any], ...] = (),
) -> Settings:
    return Settings(
        commodity_c_fast_fee_statement_trusted_keyring_path=(str(fee_keyring_path)),
        commodity_c_fast_fee_statement_expected_keyring_raw_sha256=(
            fee_keyring_raw_sha256
        ),
        commodity_baseline_execution_permit_trusted_keyring_path=str(
            authority["COMMODITY_BASELINE_EXECUTION_PERMIT"][0]
        ),
        commodity_baseline_execution_permit_expected_keyring_raw_sha256=(
            authority["COMMODITY_BASELINE_EXECUTION_PERMIT"][1]
        ),
        commodity_c_fast_simnow_execution_permit_trusted_keyring_path=str(
            authority["C_FAST_EXECUTION_PERMIT"][0]
        ),
        commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256=(
            authority["C_FAST_EXECUTION_PERMIT"][1]
        ),
        commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path=str(
            authority["C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION"][0]
        ),
        commodity_c_fast_execution_quality_runtime_admission_expected_keyring_raw_sha256=(
            authority["C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION"][1]
        ),
        commodity_c_fast_simnow_research_acceptance_trusted_keyring_path=str(
            authority["C_FAST_RESEARCH_ACCEPTANCE"][0]
        ),
        commodity_c_fast_simnow_research_acceptance_expected_keyring_raw_sha256=(
            authority["C_FAST_RESEARCH_ACCEPTANCE"][1]
        ),
        commodity_c_fast_simnow_research_keyring_path=str(
            authority["C_FAST_RESEARCH_BUNDLE"][0]
        ),
        commodity_c_fast_simnow_research_expected_keyring_raw_sha256=(
            authority["C_FAST_RESEARCH_BUNDLE"][1]
        ),
        commodity_c_fast_fee_statement_historical_trust_profiles_json=(
            json.dumps(list(historical_profiles))
        ),
    )


def test_signed_fee_statement_exact_join_and_ledger_net_replay() -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    archive = sources["actual"]
    evidence = _evidence(archive)

    assert evidence.official_exchange_fee_cny == "11"
    assert evidence.broker_customer_fee_cny == "10"
    assert evidence.all_in_cost_cny == "21"
    assert [row.vt_tradeid for row in evidence.trade_charges] == [
        "CTP.T1",
        "CTP.T2",
    ]

    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    v4 = ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(archive)
    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=settled_archive_replay_from_v4(v4),
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=_trust_context(evidence),
    )
    ledger_sources = source_inputs(plan_hash=plan_hash)
    ledger_sources["actual"] = v5.model_dump(mode="json")
    entry = build(
        payloads=ledger_sources,
        plan_hash=plan_hash,
        fee_binding_trust_context=_trust_context(evidence),
    )
    actual = entry.actual_simnow_calibration_pnl

    assert actual.schema_version == (
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v4"
    )
    assert actual.fees_state == "BOUND"
    assert actual.official_exchange_fee_cny == 11.0
    assert actual.broker_customer_fee_cny == 10.0
    assert actual.all_in_cost_cny == actual.actual_fees_cny == 21.0
    assert actual.gross_execution_pnl_cny == 500.0
    assert actual.actual_net_pnl_cny == 479.0
    assert entry.authority_granted is False
    assert entry.dispatch_allowed is False


def test_self_signed_fee_binding_cannot_supply_its_own_trust_root(
    tmp_path: Path,
) -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    archive = sources["actual"]
    trusted_evidence = _evidence(archive)
    attacker_evidence = _evidence(archive)
    trusted_context = _trust_context(trusted_evidence)
    attacker_context = _trust_context(attacker_evidence)

    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    archive_replay = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(archive)
    )
    attacker_v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=archive_replay,
        fee_binding=attacker_evidence.model_dump(mode="json"),
        fee_binding_trust_context=attacker_context,
    )
    assert (
        ActualSimNowFeeBoundArchiveReplayFactsDTO.model_validate(
            attacker_v5.model_dump(mode="json")
        )
        == attacker_v5
    )
    ledger_sources = source_inputs(plan_hash=plan_hash)
    ledger_sources["actual"] = attacker_v5.model_dump(mode="json")

    with pytest.raises(CFastPnlLedgerError) as no_context:
        build(payloads=ledger_sources, plan_hash=plan_hash)
    assert no_context.value.code == "FEE_BOUND_EXTERNAL_TRUST_CONTEXT_REQUIRED"

    with pytest.raises(CFastPnlLedgerError) as wrong_context:
        build(
            payloads=ledger_sources,
            plan_hash=plan_hash,
            fee_binding_trust_context=trusted_context,
        )
    assert wrong_context.value.code == "FEE_BOUND_EXTERNAL_TRUST_CONTEXT_MISMATCH"

    attacker_entry = build(
        payloads=ledger_sources,
        plan_hash=plan_hash,
        fee_binding_trust_context=attacker_context,
    )
    attacker_payload = attacker_entry.model_dump(mode="json")
    for context, expected in (
        (None, "FEE_BOUND_EXTERNAL_TRUST_CONTEXT_REQUIRED"),
        (trusted_context, "FEE_BOUND_EXTERNAL_TRUST_CONTEXT_MISMATCH"),
    ):
        with pytest.raises(CFastPnlLedgerError) as reload_error:
            reload_and_verify_four_layer_pnl_entry(
                attacker_payload,
                fee_binding_trust_context=context,
            )
        assert reload_error.value.code == expected

    untrusted_repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path / "untrusted",
        attacker_entry.ledger_id,
    )
    with pytest.raises(CFastPnlLedgerRepositoryError) as append_error:
        untrusted_repository.append(attacker_payload)
    assert append_error.value.code == (
        "REPOSITORY_ENTRY_REJECTED:FEE_BOUND_EXTERNAL_TRUST_CONTEXT_REQUIRED"
    )

    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path / "trusted",
        attacker_entry.ledger_id,
        fee_binding_trust_context=attacker_context,
    )
    repository.append(attacker_payload)
    exported = repository.export().model_dump(mode="json")

    for context, expected in (
        (
            None,
            "REPOSITORY_EXPORT_CHAIN_INVALID:FEE_BOUND_EXTERNAL_TRUST_CONTEXT_REQUIRED",
        ),
        (
            trusted_context,
            "REPOSITORY_EXPORT_CHAIN_INVALID:FEE_BOUND_EXTERNAL_TRUST_CONTEXT_MISMATCH",
        ),
    ):
        with pytest.raises(CFastPnlLedgerRepositoryError) as export_error:
            reload_and_verify_repository_export(
                exported,
                fee_binding_trust_context=context,
            )
        assert export_error.value.code == expected

    with pytest.raises(CFastPnlLedgerRepositoryError) as open_error:
        CommodityCFastPnlLedgerRepository.open(
            tmp_path / "trusted",
            attacker_entry.ledger_id,
        )
    assert open_error.value.code == (
        "REPOSITORY_ENTRY_INVALID:FEE_BOUND_EXTERNAL_TRUST_CONTEXT_REQUIRED"
    )


def test_pinned_historical_profile_survives_fee_and_authority_rotation(
    tmp_path: Path,
) -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    evidence = _evidence(sources["actual"])
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(
            sources["actual"]
        )
    )
    old_context = _trust_context(evidence)
    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=settled,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=old_context,
    )
    payloads = source_inputs(plan_hash=plan_hash)
    payloads["actual"] = v5.model_dump(mode="json")
    entry = build(
        payloads=payloads,
        plan_hash=plan_hash,
        fee_binding_trust_context=old_context,
    )
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        entry.ledger_id,
        fee_binding_trust_context=old_context,
    )
    repository.append(entry.model_dump(mode="json"))

    _, rotated_keyring, _ = _signed_artifacts(sources["actual"])
    rotated_keyring_raw = _write_private(
        tmp_path / "rotated-fee-keyring.json",
        rotated_keyring,
    )
    rotated_authority = _authority_keyrings(tmp_path)
    unknown_settings = _fee_settings(
        fee_keyring_path=(tmp_path / "rotated-fee-keyring.json").resolve(),
        fee_keyring_raw_sha256=sha256_bytes(rotated_keyring_raw),
        authority=rotated_authority,
    )
    unknown_context = load_fee_binding_trust_context_from_settings(
        settings=unknown_settings,
    )
    with pytest.raises(CFastPnlLedgerRepositoryError):
        CommodityCFastPnlLedgerRepository.open(
            tmp_path,
            entry.ledger_id,
            fee_binding_trust_context=unknown_context,
        )

    restart_settings = _fee_settings(
        fee_keyring_path=(tmp_path / "rotated-fee-keyring.json").resolve(),
        fee_keyring_raw_sha256=sha256_bytes(rotated_keyring_raw),
        authority=rotated_authority,
        historical_profiles=(_historical_trust_profile(evidence),),
    )
    rotated_with_history = load_fee_binding_trust_context_from_settings(
        settings=restart_settings,
    )
    reopened = CommodityCFastPnlLedgerRepository.open(
        tmp_path,
        entry.ledger_id,
        fee_binding_trust_context=rotated_with_history,
    )

    assert reopened.entries() == (entry,)
    assert reopened.audit().actual_net_fee_bound_entry_count == 1
    assert reopened.export().entries == (entry,)


def test_malformed_historical_trust_profile_is_rejected_by_settings_loader(
    tmp_path: Path,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    evidence = _evidence(sources["actual"])
    malformed = _historical_trust_profile(evidence)
    malformed["profile_id"] = "bad"
    _, keyring, _ = _signed_artifacts(sources["actual"])
    keyring_raw = _write_private(tmp_path / "fee-keyring.json", keyring)
    settings = _fee_settings(
        fee_keyring_path=(tmp_path / "fee-keyring.json").resolve(),
        fee_keyring_raw_sha256=sha256_bytes(keyring_raw),
        authority=_authority_keyrings(tmp_path),
        historical_profiles=(malformed,),
    )

    with pytest.raises(CFastFeeStatementError) as error:
        load_fee_binding_trust_context_from_settings(
            settings=settings,
        )
    assert error.value.code == "FEE_TRUST_CONTEXT_VERIFICATION_FAILED"


def test_settings_only_trust_context_loader_rejects_mid_read_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    _, keyring, _ = _signed_artifacts(sources["actual"])
    _, replacement, _ = _signed_artifacts(sources["actual"])
    keyring_path = (tmp_path / "fee-keyring.json").resolve()
    keyring_raw = _write_private(keyring_path, keyring)
    settings = _fee_settings(
        fee_keyring_path=keyring_path,
        fee_keyring_raw_sha256=sha256_bytes(keyring_raw),
        authority=_authority_keyrings(tmp_path),
    )
    original = fee_statement_service._read_private_canonical_json
    calls = 0

    def rotating_read(
        path: Path,
        *,
        label: str,
    ) -> tuple[dict[str, Any], bytes]:
        nonlocal calls
        payload, raw = original(path, label=label)
        if label == "FEE_KEYRING" and calls == 0:
            calls += 1
            _write_private(path, replacement)
        return payload, raw

    monkeypatch.setattr(
        fee_statement_service,
        "_read_private_canonical_json",
        rotating_read,
    )

    with pytest.raises(CFastFeeStatementError) as error:
        load_fee_binding_trust_context_from_settings(settings=settings)
    assert error.value.code == "FEE_TRUST_ROOT_CHANGED_DURING_VERIFY"


def test_partial_fill_v5_charges_only_the_single_real_trade() -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(sources["actual"])
    ).model_dump(mode="json")
    archive = settled["session_archive"]
    execution = archive["execution"]
    raw = execution["terminal_raw_facts"]
    raw["trades"] = raw["trades"][:1]
    raw["orders"][1]["status"] = "cancelled"
    raw["positions"] = raw["positions"][:1]

    def row_hash(rows: list[dict[str, Any]]) -> str:
        return sha256_json(sorted(sha256_json(row) for row in rows))

    raw["orders_sha256"] = row_hash(raw["orders"])
    raw["trades_sha256"] = row_hash(raw["trades"])
    raw["positions_sha256"] = row_hash(raw["positions"])
    raw["all_orders_sha256"] = raw["orders_sha256"]
    raw["all_trades_sha256"] = raw["trades_sha256"]
    raw["all_positions_sha256"] = raw["positions_sha256"]
    final_positions = {"ag2609.SHFE": 4}
    execution["reconciliation"] = {
        "expected_positions": final_positions,
        "observed_positions": final_positions,
    }
    execution["final_positions"] = final_positions
    guard = execution["terminal_guard"]
    guard["final_positions"] = final_positions
    guard["second_snapshot"] = {
        "orders_hash": raw["orders_sha256"],
        "trades_hash": raw["trades_sha256"],
        "positions_hash": raw["positions_sha256"],
    }
    guard.update(
        {
            "facts_stable": True,
            "blockers": [],
            "active_plan_orders": [],
            "external_active_orders": [],
            "unknown_status_orders": [],
            "unresolved_intent_order_facts": [],
            "unresolved_intent_trade_facts": [],
            "inconsistent_trade_rows": [],
        }
    )
    snapshot = execution["execution_snapshot"]
    snapshot["filled_volume"] = 4
    snapshot["slippage_cny"] = 40.0
    snapshot["settlement_state"] = "SETTLED_COMPLETE"
    snapshot["orders"][1].update(
        {
            "filled_volume": 0.0,
            "trade_evidence_state": "SETTLED_COMPLETE",
            "average_fill_price": None,
            "slippage_cny": None,
            "trade_count": 0,
            "order_status": "cancelled",
        }
    )
    pnl = execution["pnl"]
    pnl["trade_evidence_state"] = "SETTLED_COMPLETE"
    pnl["mark_state"] = "AVAILABLE"
    pnl["mark_evidence"].pop("cu2609.SHFE")
    pnl["filled_volume"] = 4
    pnl["execution_mark_to_market_pnl_cny"] = 200.0
    pnl["adverse_slippage_cny"] = 40.0
    execution["settlement"] = {
        "schema_version": "commodity_c_fast_terminal_settlement_v1",
        "state": "SETTLED_COMPLETE",
        "basis": (
            "STABLE_TERMINAL_RAW_FACTS_POSITION_RECONCILIATION_"
            "NO_ACTIVE_ORDER_OR_UNRESOLVED_INTENT"
        ),
        "terminal_status": "HALTED_RECONCILED",
        "order_outcome": "PARTIAL_FILL",
        "unknown_outcome_settlement_state": "NOT_APPLICABLE",
        "expected_volume": 10,
        "filled_volume": 4,
        "actual_trade_count": 1,
        "pre_trade_positions": {},
    }
    execution["state_checksum"] = sha256_json(
        {key: value for key, value in execution.items() if key != "state_checksum"}
    )
    archive["status"] = "HALTED_RECONCILED"
    archive["terminal_checksum"] = sha256_json(
        {
            "session_id": archive["session_id"],
            "plan_hash": archive["plan_hash"],
            "status": archive["status"],
            "completed_at_utc": archive["completed_at_utc"],
            "execution_state_checksum": execution["state_checksum"],
        }
    )
    settled.update(
        {
            "orders_sha256": raw["orders_sha256"],
            "trades_sha256": raw["trades_sha256"],
            "positions_sha256": raw["positions_sha256"],
            "reconciliation_sha256": sha256_json(execution["reconciliation"]),
            "execution_state_checksum": execution["state_checksum"],
            "terminal_checksum": archive["terminal_checksum"],
            "terminal_status": "HALTED_RECONCILED",
            "valuation_at_utc": pnl["mark_evidence"]["ag2609.SHFE"]["received_at_utc"],
            "filled_lots": 4,
            "order_outcome": "PARTIAL_FILL",
            "session_archive_sha256": sha256_json(archive),
            "archive_chain_tip_terminal_checksum": archive["terminal_checksum"],
        }
    )
    partial = ActualSimNowSettledArchiveReplayFactsDTO.model_validate(settled)
    statement, keyring, _ = _signed_artifacts(partial.model_dump(mode="json"))
    evidence = _evidence(
        partial.model_dump(mode="json"),
        statement=statement,
        keyring=keyring,
    )
    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=partial,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=_trust_context(evidence),
    )
    ledger_sources = source_inputs(plan_hash=plan_hash)
    ledger_sources["actual"] = v5.model_dump(mode="json")
    actual = build(
        payloads=ledger_sources,
        plan_hash=plan_hash,
        fee_binding_trust_context=_trust_context(evidence),
    ).actual_simnow_calibration_pnl

    assert [row.vt_tradeid for row in evidence.trade_charges] == ["CTP.T1"]
    assert evidence.all_in_cost_cny == "9"
    assert actual.gross_execution_pnl_cny == 200.0
    assert actual.actual_fees_cny == 9.0
    assert actual.actual_net_pnl_cny == 191.0


@pytest.mark.parametrize(
    ("order_status", "expected_outcome", "expected_unknown_state"),
    [
        ("cancelled", "UNFILLED_CANCELLED", "NOT_APPLICABLE"),
        ("rejected", "REJECTED", "NOT_APPLICABLE"),
        (
            "cancelled",
            "TIMEOUT_OR_RESULT_UNKNOWN",
            "SETTLED_BY_TERMINAL_RAW_FACTS_AND_POSITION_RECONCILIATION",
        ),
    ],
)
def test_zero_fill_settled_outcomes_bind_zero_trade_fees_without_assumption(
    order_status: str,
    expected_outcome: str,
    expected_unknown_state: str,
) -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(sources["actual"])
    ).model_dump(mode="json")
    archive = settled["session_archive"]
    execution = archive["execution"]
    raw = execution["terminal_raw_facts"]
    raw["trades"] = []
    raw["positions"] = []
    for order in raw["orders"]:
        order["status"] = order_status

    def row_hash(rows: list[dict[str, Any]]) -> str:
        return sha256_json(sorted(sha256_json(row) for row in rows))

    raw["orders_sha256"] = row_hash(raw["orders"])
    raw["trades_sha256"] = row_hash(raw["trades"])
    raw["positions_sha256"] = row_hash(raw["positions"])
    raw["all_orders_sha256"] = raw["orders_sha256"]
    raw["all_trades_sha256"] = raw["trades_sha256"]
    raw["all_positions_sha256"] = raw["positions_sha256"]
    execution["reconciliation"] = {
        "expected_positions": {},
        "observed_positions": {},
    }
    execution["final_positions"] = {}
    guard = execution["terminal_guard"]
    guard["final_positions"] = {}
    guard["second_snapshot"] = {
        "orders_hash": raw["orders_sha256"],
        "trades_hash": raw["trades_sha256"],
        "positions_hash": raw["positions_sha256"],
    }
    guard.update(
        {
            "facts_stable": True,
            "blockers": [],
            "active_plan_orders": [],
            "external_active_orders": [],
            "unknown_status_orders": [],
            "unresolved_intent_order_facts": [],
            "unresolved_intent_trade_facts": [],
            "inconsistent_trade_rows": [],
        }
    )
    snapshot = execution["execution_snapshot"]
    snapshot["filled_volume"] = 0
    snapshot["slippage_cny"] = 0.0
    snapshot["settlement_state"] = "SETTLED_COMPLETE"
    for order in snapshot["orders"]:
        order.update(
            {
                "filled_volume": 0.0,
                "trade_evidence_state": "SETTLED_COMPLETE",
                "average_fill_price": None,
                "slippage_cny": None,
                "trade_count": 0,
                "order_status": order_status,
            }
        )
    pnl = execution["pnl"]
    pnl.update(
        {
            "trade_evidence_state": "SETTLED_COMPLETE",
            "mark_source": "NOT_REQUIRED_ZERO_FILL",
            "mark_state": "NOT_REQUIRED_ZERO_FILL",
            "mark_evidence": {},
            "filled_volume": 0,
            "execution_mark_to_market_pnl_cny": 0.0,
            "adverse_slippage_cny": 0.0,
        }
    )
    if expected_outcome == "TIMEOUT_OR_RESULT_UNKNOWN":
        execution["halt"] = execution.get("halt") or {}
        execution["halt"]["submission_outcome_unknown_observed"] = True
    execution["settlement"] = {
        "schema_version": "commodity_c_fast_terminal_settlement_v1",
        "state": "SETTLED_COMPLETE",
        "basis": (
            "STABLE_TERMINAL_RAW_FACTS_POSITION_RECONCILIATION_"
            "NO_ACTIVE_ORDER_OR_UNRESOLVED_INTENT"
        ),
        "terminal_status": "HALTED_RECONCILED",
        "order_outcome": expected_outcome,
        "unknown_outcome_settlement_state": expected_unknown_state,
        "expected_volume": 10,
        "filled_volume": 0,
        "actual_trade_count": 0,
        "pre_trade_positions": {},
    }
    execution["state_checksum"] = sha256_json(
        {key: value for key, value in execution.items() if key != "state_checksum"}
    )
    archive["status"] = "HALTED_RECONCILED"
    archive["terminal_checksum"] = sha256_json(
        {
            "session_id": archive["session_id"],
            "plan_hash": archive["plan_hash"],
            "status": archive["status"],
            "completed_at_utc": archive["completed_at_utc"],
            "execution_state_checksum": execution["state_checksum"],
        }
    )
    settled.update(
        {
            "orders_sha256": raw["orders_sha256"],
            "trades_sha256": raw["trades_sha256"],
            "positions_sha256": raw["positions_sha256"],
            "reconciliation_sha256": sha256_json(execution["reconciliation"]),
            "execution_state_checksum": execution["state_checksum"],
            "terminal_checksum": archive["terminal_checksum"],
            "terminal_status": "HALTED_RECONCILED",
            "valuation_at_utc": pnl["captured_at_utc"],
            "filled_lots": 0,
            "order_outcome": expected_outcome,
            "unknown_outcome_settlement_state": expected_unknown_state,
            "mark_source": "NOT_REQUIRED_ZERO_FILL",
            "session_archive_sha256": sha256_json(archive),
            "archive_chain_tip_terminal_checksum": archive["terminal_checksum"],
        }
    )
    zero_fill = ActualSimNowSettledArchiveReplayFactsDTO.model_validate(settled)
    statement, keyring, _ = _signed_artifacts(zero_fill.model_dump(mode="json"))
    evidence = _evidence(
        zero_fill.model_dump(mode="json"),
        statement=statement,
        keyring=keyring,
    )
    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=zero_fill,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=_trust_context(evidence),
    )
    ledger_sources = source_inputs(plan_hash=plan_hash)
    ledger_sources["actual"] = v5.model_dump(mode="json")
    actual = build(
        payloads=ledger_sources,
        plan_hash=plan_hash,
        fee_binding_trust_context=_trust_context(evidence),
    ).actual_simnow_calibration_pnl

    assert evidence.trade_charges == ()
    assert evidence.all_in_cost_cny == "0"
    assert actual.gross_execution_pnl_cny == 0.0
    assert actual.actual_fees_cny == 0.0
    assert actual.actual_net_pnl_cny == 0.0


@pytest.mark.parametrize(
    "expected_outcome",
    [
        "PARTIAL_FILL",
        "UNFILLED_CANCELLED",
        "REJECTED",
        "TIMEOUT_OR_RESULT_UNKNOWN",
    ],
)
def test_real_commodity_simnow_service_archives_bind_each_settled_outcome(
    tmp_path: Path,
    expected_outcome: str,
) -> None:
    trade: FakeTrade
    if expected_outcome == "REJECTED":
        trade = FakeTrade(complete_cancel=False)
    elif expected_outcome == "TIMEOUT_OR_RESULT_UNKNOWN":
        trade = _AcceptedWithIdentityTimeoutTrade()
    else:
        trade = FakeTrade()
    service, rpc, snapshot, snapshot_hash = prepare_c_fast_shakedown(
        tmp_path,
        trade=trade,
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip=None,
    )["preview"]
    if expected_outcome == "TIMEOUT_OR_RESULT_UNKNOWN":
        with pytest.raises(CommoditySimNowStateError):
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
    else:
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan is not None
    submitted = service.current_plan["submitted"]["open"][0]
    expected_lots = int(submitted["volume"])
    if expected_outcome == "PARTIAL_FILL":
        filled_lots = max(1, expected_lots // 2)
        rpc.orders = [{**submitted, "status": "part_traded"}]
        rpc.trades = fills_for_submitted(service.current_plan)
        rpc.trades[0]["volume"] = filled_lots
        rpc.positions = [position("ag", filled_lots, contract_month="2612")]
    elif expected_outcome == "REJECTED":
        filled_lots = 0
        rpc.orders = [{**submitted, "status": "rejected"}]
        rpc.trades = []
        rpc.positions = []
    else:
        filled_lots = 0
        if expected_outcome == "UNFILLED_CANCELLED":
            rpc.orders = [{**submitted, "status": "not_traded"}]
        rpc.trades = []
        rpc.positions = []

    service.stop_c_fast_shakedown(
        f"settle {expected_outcome}",
        operator="admin",
        role="admin",
        source_ip=None,
    )
    for _ in range(4):
        if service.current_plan is None:
            break
        service.auto_candidate_shakedown_advance()
    assert service.current_plan is None

    archive = service._load_c_fast_terminal_archive(preview["session_id"])
    assert archive is not None
    settlement = archive["execution"]["settlement"]
    pnl = archive["execution"]["pnl"]
    assert settlement["state"] == "SETTLED_COMPLETE"
    assert settlement["order_outcome"] == expected_outcome
    assert settlement["filled_volume"] == filled_lots
    assert pnl["trade_evidence_state"] == "SETTLED_COMPLETE"
    if filled_lots:
        assert set(pnl["mark_evidence"]) == {submitted["vt_symbol"]}
    else:
        assert pnl["mark_source"] == "NOT_REQUIRED_ZERO_FILL"
        assert pnl["mark_evidence"] == {}
        assert pnl["execution_mark_to_market_pnl_cny"] == 0.0
        assert pnl["adverse_slippage_cny"] == 0.0

    archive_path = service._c_fast_terminal_archive_path(preview["session_id"])
    verified_at = "2026-09-01T01:00:30Z"
    settled = build_actual_simnow_settled_archive_replay_source_facts(
        ledger_id=f"cfast-real-{expected_outcome.lower().replace('_', '-')}",
        snapshot_hash=snapshot_hash,
        formula_target_binding_sha256=(snapshot.formula_target_binding_sha256),
        valuation_day="2026-09-01",
        as_of_at_utc=verified_at,
        archive_dir=service._c_fast_terminal_archive_dir(),
        session_id=preview["session_id"],
        expected_archive_raw_sha256=hashlib.sha256(
            archive_path.read_bytes()
        ).hexdigest(),
        expected_terminal_checksum=archive["terminal_checksum"],
        expected_chain_tip_terminal_checksum=archive["terminal_checksum"],
    )
    ledger_sources = source_inputs(
        ledger_id=settled.ledger_id,
        snapshot_hash=settled.snapshot_hash,
        formula_hash=settled.formula_target_binding_sha256,
        plan_hash=settled.plan_hash,
        valuation_day="2026-09-01",
        as_of_at_utc=verified_at,
    )
    ledger_sources["actual"] = settled.model_dump(mode="json")
    unbound_entry = build(
        ledger_id=settled.ledger_id,
        snapshot_hash=settled.snapshot_hash,
        formula_hash=settled.formula_target_binding_sha256,
        plan_hash=settled.plan_hash,
        valuation_day="2026-09-01",
        created_at="2026-09-01T01:00:31Z",
        payloads=ledger_sources,
    )
    unbound = unbound_entry.actual_simnow_calibration_pnl
    assert unbound.schema_version == (
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v5"
    )
    assert unbound.actual_state == ("LOCAL_SETTLED_ARCHIVE_REPLAYED_FEES_UNBOUND")
    assert unbound.lineage.source_kind == (
        "SIMNOW_SETTLED_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"
    )
    assert unbound.gross_execution_pnl_cny == (pnl["execution_mark_to_market_pnl_cny"])
    assert unbound.adverse_slippage_cny == pnl["adverse_slippage_cny"]
    assert unbound.fees_state == "UNBOUND_NOT_ASSUMED_ZERO"
    assert unbound.actual_fees_cny is None
    assert unbound.net_pnl_state == ("UNAVAILABLE_UNTIL_AUTHORITATIVE_FEES_BOUND")
    assert unbound.actual_net_pnl_cny is None

    statement, keyring, _ = _signed_artifacts(
        settled.model_dump(mode="json"),
        schedule=_schedule_for_archive(settled.model_dump(mode="json")),
        issued_at_utc="2026-09-01T01:00:20Z",
        not_before_at_utc="2026-09-01T01:00:10Z",
        expires_at_utc="2026-09-01T02:00:00Z",
        trading_day="2026-09-01",
    )
    evidence = _evidence(
        settled.model_dump(mode="json"),
        statement=statement,
        keyring=keyring,
        verified_at_utc=verified_at,
    )
    actual_v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=settled,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=_trust_context(evidence),
    )

    assert actual_v5.archive_replay.order_outcome == expected_outcome
    assert len(evidence.trade_charges) == (1 if filled_lots else 0)
    if filled_lots:
        assert float(evidence.all_in_cost_cny) > 0
    else:
        assert evidence.all_in_cost_cny == "0"


def test_file_loader_requires_exact_canonical_private_stable_artifacts(
    tmp_path: Path,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = sources["actual"]
    source_raw = b"synthetic-test-fee-source-not-authority\n"
    source_path = (tmp_path / "source.bin").resolve()
    source_path.write_bytes(source_raw)
    source_path.chmod(0o600)
    statement, keyring, _ = _signed_artifacts(
        archive,
        source_document_raw_sha256=sha256_bytes(source_raw),
    )
    statement_raw = _write_private(tmp_path / "statement.json", statement)
    keyring_raw = _write_private(tmp_path / "keyring.json", keyring)

    evidence = load_and_verify_fee_binding(
        statement_path=(tmp_path / "statement.json").resolve(),
        trusted_keyring_path=(tmp_path / "keyring.json").resolve(),
        source_document_path=source_path,
        expected_statement_raw_sha256=sha256_bytes(statement_raw),
        expected_trusted_keyring_raw_sha256=sha256_bytes(keyring_raw),
        required_authority_keyrings=_authority_keyrings(tmp_path),
        manual_execution_permit_trusted_public_keys_json="{}",
        verified_at_utc="2026-09-02T08:01:50Z",
        archive_facts=archive,
    )

    assert evidence.fee_binding_state == "BOUND"
    assert evidence.statement.source_document_raw_sha256 == sha256_bytes(source_raw)

    (tmp_path / "statement.json").write_bytes(statement_raw + b"\n")
    with pytest.raises(CFastFeeStatementError) as exc_info:
        load_and_verify_fee_binding(
            statement_path=(tmp_path / "statement.json").resolve(),
            trusted_keyring_path=(tmp_path / "keyring.json").resolve(),
            source_document_path=source_path,
            expected_statement_raw_sha256=sha256_bytes(statement_raw + b"\n"),
            expected_trusted_keyring_raw_sha256=sha256_bytes(keyring_raw),
            required_authority_keyrings=_authority_keyrings(tmp_path),
            manual_execution_permit_trusted_public_keys_json="{}",
            verified_at_utc="2026-09-02T08:01:50Z",
            archive_facts=archive,
        )
    assert exc_info.value.code == "FEE_STATEMENT_NOT_CANONICAL"


@pytest.mark.parametrize("foreign_domain", ["baseline", "manual"])
def test_real_execution_key_domain_reuse_is_rejected(
    tmp_path: Path,
    foreign_domain: str,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = sources["actual"]
    source_raw = b"synthetic-test-fee-source-not-authority\n"
    source_path = (tmp_path / "source.bin").resolve()
    source_path.write_bytes(source_raw)
    source_path.chmod(0o600)
    statement, keyring, _ = _signed_artifacts(
        archive,
        source_document_raw_sha256=sha256_bytes(source_raw),
    )
    statement_raw = _write_private(tmp_path / "statement.json", statement)
    keyring_raw = _write_private(tmp_path / "keyring.json", keyring)
    fee_public = base64.b64decode(keyring["trusted_keys"][0]["public_key_base64"])
    authority = _authority_keyrings(
        tmp_path,
        reused_public_by_role=(
            {"COMMODITY_BASELINE_EXECUTION_PERMIT": fee_public}
            if foreign_domain == "baseline"
            else None
        ),
    )
    manual = "{}"
    if foreign_domain == "manual":
        manual = canonical_json_bytes(
            {
                "manual-key-reused-v1": {
                    "public_key_base64": base64.b64encode(fee_public).decode("ascii"),
                    "purpose": "manual_execution_permit_signer",
                }
            }
        ).decode("utf-8")

    with pytest.raises(CFastFeeStatementError) as exc_info:
        load_and_verify_fee_binding(
            statement_path=(tmp_path / "statement.json").resolve(),
            trusted_keyring_path=(tmp_path / "keyring.json").resolve(),
            source_document_path=source_path,
            expected_statement_raw_sha256=sha256_bytes(statement_raw),
            expected_trusted_keyring_raw_sha256=sha256_bytes(keyring_raw),
            required_authority_keyrings=authority,
            manual_execution_permit_trusted_public_keys_json=manual,
            verified_at_utc="2026-09-02T08:01:50Z",
            archive_facts=archive,
        )
    assert exc_info.value.code == "FEE_STATEMENT_VERIFICATION_FAILED"


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_account",
        "wrong_trading_day",
        "wrong_archive",
        "wrong_trades",
        "wrong_gateway",
        "missing_rule",
        "signature_tamper",
        "expired",
    ],
)
def test_fee_statement_identity_signature_schedule_and_expiry_fail_closed(
    mutation: str,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = sources["actual"]
    statement, keyring, private = _signed_artifacts(archive)
    if mutation == "wrong_account":
        statement["account_sha256"] = "9" * 64
    elif mutation == "wrong_trading_day":
        statement["trading_day"] = "2026-09-03"
    elif mutation == "wrong_archive":
        statement["session_archive_raw_sha256"] = "9" * 64
    elif mutation == "wrong_trades":
        statement["trades_sha256"] = "9" * 64
    elif mutation == "wrong_gateway":
        statement["gateway_name"] = "SIMNOW"
    elif mutation == "missing_rule":
        statement["schedule"]["rules"] = statement["schedule"]["rules"][:1]
        schedule_core = {
            key: value
            for key, value in statement["schedule"].items()
            if key != "schedule_sha256"
        }
        statement["schedule"]["schedule_sha256"] = sha256_bytes(
            canonical_json_bytes(schedule_core)
        )
    elif mutation == "signature_tamper":
        signature = bytearray(base64.b64decode(statement["signature_base64"]))
        signature[0] ^= 1
        statement["signature_base64"] = base64.b64encode(signature).decode()
    elif mutation == "expired":
        statement, keyring, private = _signed_artifacts(
            archive,
            private=private,
            expires_at_utc="2026-09-02T08:01:45Z",
        )
    if mutation not in {"expired", "signature_tamper"}:
        unsigned = {
            key: value
            for key, value in statement.items()
            if key not in {"signed_payload_sha256", "signature_base64"}
        }
        statement["signed_payload_sha256"] = sha256_bytes(
            canonical_json_bytes(unsigned)
        )
        statement["signature_base64"] = base64.b64encode(
            private.sign(
                FEE_STATEMENT_SIGNATURE_DOMAIN + canonical_json_bytes(unsigned)
            )
        ).decode()
    statement_dto = CommodityCFastFeeStatementDTO.model_validate(statement)
    keyring_dto = CommodityCFastFeeStatementTrustedKeyringDTO.model_validate(keyring)
    with pytest.raises(ValueError):
        verify_fee_statement_and_calculate(
            statement=statement_dto,
            trusted_keyring=keyring_dto,
            statement_raw_sha256=sha256_bytes(canonical_json_bytes(statement)),
            trusted_keyring_raw_sha256=sha256_bytes(canonical_json_bytes(keyring)),
            excluded_authority_keyring_raw_sha256s=AUTHORITY_RAW_HASHES,
            excluded_authority_public_key_sha256s=AUTHORITY_PUBLIC_HASHES,
            verified_at_utc="2026-09-02T08:01:50Z",
            archive_facts=archive,
        )


def test_key_domain_overlap_extra_fields_and_duplicate_trade_fail_closed() -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = sources["actual"]
    statement, keyring, _ = _signed_artifacts(archive)
    statement_dto = CommodityCFastFeeStatementDTO.model_validate(statement)
    keyring_dto = CommodityCFastFeeStatementTrustedKeyringDTO.model_validate(keyring)
    fee_public_hash = keyring["trusted_keys"][0]["public_key_sha256"]
    overlapping_public = dict(AUTHORITY_PUBLIC_HASHES)
    overlapping_public["C_FAST_EXECUTION_PERMIT"] = (fee_public_hash,)
    with pytest.raises(ValueError, match="overlaps another authority"):
        verify_fee_statement_and_calculate(
            statement=statement_dto,
            trusted_keyring=keyring_dto,
            statement_raw_sha256=sha256_bytes(canonical_json_bytes(statement)),
            trusted_keyring_raw_sha256=sha256_bytes(canonical_json_bytes(keyring)),
            excluded_authority_keyring_raw_sha256s=AUTHORITY_RAW_HASHES,
            excluded_authority_public_key_sha256s=overlapping_public,
            verified_at_utc="2026-09-02T08:01:50Z",
            archive_facts=archive,
        )

    with pytest.raises(ValidationError):
        CommodityCFastFeeStatementDTO.model_validate(
            {**statement, "password": "must-never-enter-evidence"}
        )

    duplicated = copy.deepcopy(archive)
    trades = duplicated["session_archive"]["execution"]["terminal_raw_facts"]["trades"]
    trades.append(copy.deepcopy(trades[0]))
    duplicated["trades_sha256"] = sha256_json(
        sorted(sha256_json(row) for row in trades)
    )
    raw = duplicated["session_archive"]["execution"]["terminal_raw_facts"]
    raw["trades_sha256"] = duplicated["trades_sha256"]
    duplicated_statement, duplicated_keyring, _ = _signed_artifacts(duplicated)
    with pytest.raises(ValueError, match="duplicated"):
        _evidence(
            duplicated,
            statement=duplicated_statement,
            keyring=duplicated_keyring,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("orphan_trade", "orphaned"),
        ("wrong_symbol", "does not exactly join"),
        ("wrong_direction", "does not exactly join"),
        ("wrong_offset", "does not exactly join"),
        ("wrong_gateway", "does not exactly join"),
        ("spliced_order", "spliced from another scope"),
        ("overfilled_order", "exceeds archived order"),
    ],
)
def test_fee_trade_requires_exact_archived_order_join(
    mutation: str,
    message: str,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = copy.deepcopy(sources["actual"])
    raw = archive["session_archive"]["execution"]["terminal_raw_facts"]
    orders = raw["orders"]
    trades = raw["trades"]

    if mutation == "orphan_trade":
        trades[0]["vt_orderid"] = "CTP.404"
    elif mutation == "wrong_symbol":
        trades[0]["vt_symbol"] = "cu2609.SHFE"
    elif mutation == "wrong_direction":
        trades[0]["direction"] = "short"
    elif mutation == "wrong_offset":
        trades[0]["offset"] = "close"
    elif mutation == "wrong_gateway":
        trades[0]["gateway_name"] = "OTHER"
    elif mutation == "spliced_order":
        orders[0]["reference"] = "CFAST:foreign-session:o:1"
        trades[0]["reference"] = "CFAST:foreign-session:o:1"
    else:
        trades[0]["volume"] = orders[0]["volume"] + 1

    archive["orders_sha256"] = sha256_json(sorted(sha256_json(row) for row in orders))
    archive["trades_sha256"] = sha256_json(sorted(sha256_json(row) for row in trades))
    raw["orders_sha256"] = archive["orders_sha256"]
    raw["trades_sha256"] = archive["trades_sha256"]
    statement, keyring, _ = _signed_artifacts(archive)

    with pytest.raises(ValueError, match=message):
        _evidence(
            archive,
            statement=statement,
            keyring=keyring,
        )


def test_cancel_reject_or_unknown_with_no_real_trades_charges_exact_zero() -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = copy.deepcopy(sources["actual"])
    raw = archive["session_archive"]["execution"]["terminal_raw_facts"]
    raw["trades"] = []
    for order in raw["orders"]:
        order["status"] = "cancelled"
    for snapshot_row in archive["session_archive"]["execution"]["execution_snapshot"][
        "orders"
    ]:
        snapshot_row.update(
            {
                "filled_volume": 0.0,
                "trade_count": 0,
                "average_fill_price": None,
                "slippage_cny": None,
                "order_status": "cancelled",
            }
        )
    empty_hash = sha256_json([])
    orders_hash = sha256_json(sorted(sha256_json(row) for row in raw["orders"]))
    archive["orders_sha256"] = orders_hash
    raw["orders_sha256"] = orders_hash
    archive["trades_sha256"] = empty_hash
    raw["trades_sha256"] = empty_hash
    statement, keyring, _ = _signed_artifacts(archive)

    evidence = _evidence(archive, statement=statement, keyring=keyring)

    assert evidence.trade_charges == ()
    assert evidence.official_exchange_fee_cny == "0"
    assert evidence.broker_customer_fee_cny == "0"
    assert evidence.all_in_cost_cny == "0"


@pytest.mark.parametrize(
    ("rounding_mode", "expected_official", "expected_net"),
    [
        ("ROUND_HALF_EVEN", "0", 500.0),
        ("ROUND_HALF_UP", "0.02", 499.98),
    ],
)
def test_authoritative_fees_and_net_use_cny_cent_tie_rounding(
    rounding_mode: str,
    expected_official: str,
    expected_net: float,
) -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    archive = sources["actual"]
    schedule = _schedule()
    schedule["rounding_mode"] = rounding_mode
    for rule in schedule["rules"]:
        rule["official_exchange"].update(
            {
                "by_volume_cny_per_lot": "0",
                "by_turnover_rate": "0",
                "minimum_cny_per_trade": "0.005",
            }
        )
        rule["broker_customer"].update(
            {
                "by_volume_cny_per_lot": "0",
                "by_turnover_rate": "0",
                "minimum_cny_per_trade": "0",
            }
        )
    schedule["schedule_sha256"] = sha256_bytes(
        canonical_json_bytes(
            {key: value for key, value in schedule.items() if key != "schedule_sha256"}
        )
    )
    statement, keyring, _ = _signed_artifacts(archive, schedule=schedule)
    evidence = _evidence(archive, statement=statement, keyring=keyring)

    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(archive)
    )
    context = _trust_context(evidence)
    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=settled,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=context,
    )
    payloads = source_inputs(plan_hash=plan_hash)
    payloads["actual"] = v5.model_dump(mode="json")
    actual = build(
        payloads=payloads,
        plan_hash=plan_hash,
        fee_binding_trust_context=context,
    ).actual_simnow_calibration_pnl

    assert evidence.official_exchange_fee_cny == expected_official
    assert evidence.broker_customer_fee_cny == "0"
    assert evidence.all_in_cost_cny == expected_official
    assert actual.actual_net_pnl_cny == expected_net


def test_fee_schedule_rejects_sub_cent_rounding_increment() -> None:
    sources, _ = source_inputs_with_verified_actual()
    schedule = _schedule()
    schedule["rounding_increment_cny"] = "0.000000000000000001"
    schedule["schedule_sha256"] = sha256_bytes(
        canonical_json_bytes(
            {key: value for key, value in schedule.items() if key != "schedule_sha256"}
        )
    )
    statement, _, _ = _signed_artifacts(sources["actual"], schedule=schedule)

    with pytest.raises(ValidationError, match="CNY cent"):
        CommodityCFastFeeStatementDTO.model_validate(statement)


def test_append_only_fee_correction_counts_terminal_gross_once(
    tmp_path: Path,
) -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(sources["actual"])
    )
    reattested = reattest_settled_archive_replay(
        settled,
        as_of_at_utc="2026-09-02T08:04:00Z",
    )
    statement, keyring, _ = _signed_artifacts(
        reattested.model_dump(mode="json"),
        issued_at_utc="2026-09-02T08:03:00Z",
        not_before_at_utc="2026-09-02T08:02:30Z",
        expires_at_utc="2026-09-02T09:00:00Z",
    )
    evidence = _evidence(
        reattested.model_dump(mode="json"),
        statement=statement,
        keyring=keyring,
        verified_at_utc="2026-09-02T08:04:00Z",
    )
    context = _trust_context(evidence)
    primary_sources = source_inputs(plan_hash=plan_hash)
    primary_sources["actual"] = settled.model_dump(mode="json")
    primary = build(payloads=primary_sources, plan_hash=plan_hash)
    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=reattested,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=context,
    )
    correction_sources = source_inputs(plan_hash=plan_hash)
    correction_sources["actual"] = v5.model_dump(mode="json")
    with pytest.raises(CFastPnlLedgerError) as premature_error:
        build(
            sequence=2,
            previous=primary.entry_hash,
            created_at="2026-09-02T08:03:59Z",
            payloads=correction_sources,
            plan_hash=plan_hash,
            fee_binding_trust_context=context,
            economic_counting_state=(
                "NON_COUNTING_FEE_BINDING_CORRECTION"
            ),
            supersedes_entry_hash=primary.entry_hash,
        )
    assert premature_error.value.code == (
        "LEDGER_CREATED_AT_PRECEDES_SOURCE_CUTOFF"
    )

    correction = build(
        sequence=2,
        previous=primary.entry_hash,
        created_at="2026-09-02T08:04:00Z",
        payloads=correction_sources,
        plan_hash=plan_hash,
        fee_binding_trust_context=context,
        economic_counting_state="NON_COUNTING_FEE_BINDING_CORRECTION",
        supersedes_entry_hash=primary.entry_hash,
    )
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        primary.ledger_id,
        fee_binding_trust_context=context,
    )

    repository.append(primary.model_dump(mode="json"))
    repository.append(correction.model_dump(mode="json"))
    audit = repository.audit()

    assert len(repository.entries()) == 2
    assert correction.economic_counting_state == ("NON_COUNTING_FEE_BINDING_CORRECTION")
    assert correction.supersedes_entry_hash == primary.entry_hash
    assert evidence.statement.issued_at_utc > (
        settled.as_of_at_utc.isoformat()
    )
    assert audit.actual_gross_replayed_entry_count == 1
    assert audit.actual_net_fee_bound_entry_count == 1
    reopened = CommodityCFastPnlLedgerRepository.open(
        tmp_path,
        primary.ledger_id,
        fee_binding_trust_context=context,
    )
    exported = reopened.export()
    assert exported.audit.actual_gross_replayed_entry_count == 1
    assert exported.audit.actual_net_fee_bound_entry_count == 1
    assert (
        reload_and_verify_repository_export(
            exported.model_dump(mode="json"),
            fee_binding_trust_context=context,
        )
        == exported
    )

    duplicate = build(
        sequence=3,
        previous=correction.entry_hash,
        created_at="2026-09-02T08:05:00Z",
        payloads=correction_sources,
        plan_hash=plan_hash,
        fee_binding_trust_context=context,
        economic_counting_state="NON_COUNTING_FEE_BINDING_CORRECTION",
        supersedes_entry_hash=primary.entry_hash,
    )
    with pytest.raises(CFastPnlLedgerRepositoryError) as duplicate_error:
        repository.append(duplicate.model_dump(mode="json"))
    assert duplicate_error.value.code == (
        "REPOSITORY_CHAIN_REJECTED:LEDGER_FEE_CORRECTION_LINK_INVALID"
    )


def test_fee_correction_rejects_changed_immutable_archive_identity(
    tmp_path: Path,
) -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(
            sources["actual"]
        )
    )
    tampered_payload = reattest_settled_archive_replay(
        settled,
        as_of_at_utc="2026-09-02T08:04:00Z",
    ).model_dump(mode="json")
    tampered_payload["session_archive_raw_sha256"] = "e" * 64
    tampered = ActualSimNowSettledArchiveReplayFactsDTO.model_validate(
        tampered_payload
    )
    statement, keyring, _ = _signed_artifacts(
        tampered.model_dump(mode="json"),
        issued_at_utc="2026-09-02T08:03:00Z",
        not_before_at_utc="2026-09-02T08:02:30Z",
    )
    evidence = _evidence(
        tampered.model_dump(mode="json"),
        statement=statement,
        keyring=keyring,
        verified_at_utc="2026-09-02T08:04:00Z",
    )
    context = _trust_context(evidence)
    primary_sources = source_inputs(plan_hash=plan_hash)
    primary_sources["actual"] = settled.model_dump(mode="json")
    primary = build(payloads=primary_sources, plan_hash=plan_hash)
    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=tampered,
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=context,
    )
    correction_sources = source_inputs(plan_hash=plan_hash)
    correction_sources["actual"] = v5.model_dump(mode="json")
    correction = build(
        sequence=2,
        previous=primary.entry_hash,
        created_at="2026-09-02T08:05:00Z",
        payloads=correction_sources,
        plan_hash=plan_hash,
        fee_binding_trust_context=context,
        economic_counting_state="NON_COUNTING_FEE_BINDING_CORRECTION",
        supersedes_entry_hash=primary.entry_hash,
    )
    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        primary.ledger_id,
        fee_binding_trust_context=context,
    )
    repository.append(primary.model_dump(mode="json"))

    with pytest.raises(CFastPnlLedgerRepositoryError) as caught:
        repository.append(correction.model_dump(mode="json"))
    assert caught.value.code == (
        "REPOSITORY_CHAIN_REJECTED:LEDGER_FEE_CORRECTION_LINK_INVALID"
    )


@pytest.mark.parametrize("valuation_day", ["2020-01-01", "2099-01-01"])
def test_settled_archive_rejects_past_or_future_valuation_day(
    valuation_day: str,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(sources["actual"])
    ).model_dump(mode="json")
    settled["valuation_day"] = valuation_day

    with pytest.raises(ValidationError, match="valuation day is misdated"):
        ActualSimNowSettledArchiveReplayFactsDTO.model_validate(settled)


def test_night_session_mark_joins_next_signed_trading_day() -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = copy.deepcopy(sources["actual"])
    marks = archive["session_archive"]["execution"]["pnl"][
        "mark_evidence"
    ]
    for index, mark in enumerate(marks.values(), start=1):
        received = f"2026-09-01T13:00:{index:02d}Z"
        mark["raw_quote"]["received_at"] = received
        mark["raw_quote_sha256"] = sha256_json(mark["raw_quote"])
        mark["received_at_utc"] = received
    trades = archive["session_archive"]["execution"][
        "terminal_raw_facts"
    ]["trades"]
    for index, trade in enumerate(trades, start=1):
        trade["trade_at_utc"] = f"2026-09-01T12:59:{index:02d}Z"
    archive["valuation_at_utc"] = "2026-09-01T13:00:02Z"
    rehash_verified_session_archive(archive)

    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(archive)
    )
    evidence = _evidence(settled.model_dump(mode="json"))

    assert settled.valuation_day.isoformat() == "2026-09-02"
    assert settled.valuation_at_utc.isoformat() == (
        "2026-09-01T13:00:02+00:00"
    )
    assert evidence.statement.trading_day.isoformat() == "2026-09-02"


def test_night_session_mark_cannot_splice_wrong_signed_trading_day() -> None:
    sources, _ = source_inputs_with_verified_actual()
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(sources["actual"])
    ).model_dump(mode="json")
    settled["valuation_day"] = "2026-09-03"

    with pytest.raises(ValidationError, match="valuation day is misdated"):
        ActualSimNowSettledArchiveReplayFactsDTO.model_validate(settled)


def test_misdated_fee_bound_entry_fails_reload_and_repository_export(
    tmp_path: Path,
) -> None:
    sources, plan_hash = source_inputs_with_verified_actual()
    archive = sources["actual"]
    evidence = _evidence(archive)
    context = _trust_context(evidence)
    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    v5 = build_actual_simnow_fee_bound_source_facts(
        archive_replay=settled_archive_replay_from_v4(
            ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(archive)
        ),
        fee_binding=evidence.model_dump(mode="json"),
        fee_binding_trust_context=context,
    )
    payloads = source_inputs(plan_hash=plan_hash)
    payloads["actual"] = v5.model_dump(mode="json")
    entry = build(
        payloads=payloads,
        plan_hash=plan_hash,
        fee_binding_trust_context=context,
    )
    tampered = entry.model_dump(mode="json")
    tampered["actual_simnow_calibration_pnl"]["source_facts"]["archive_replay"][
        "valuation_day"
    ] = "2099-01-01"
    _rehash_entry(tampered, "actual_simnow_calibration_pnl")

    with pytest.raises(CFastPnlLedgerError):
        reload_and_verify_four_layer_pnl_entry(
            tampered,
            fee_binding_trust_context=context,
        )

    repository = CommodityCFastPnlLedgerRepository.open_or_create(
        tmp_path,
        entry.ledger_id,
        fee_binding_trust_context=context,
    )
    repository.append(entry.model_dump(mode="json"))
    exported = repository.export().model_dump(mode="json")
    exported["entries"][0] = tampered
    exported["export_sha256"] = sha256_json(
        {key: value for key, value in exported.items() if key != "export_sha256"}
    )
    with pytest.raises(CFastPnlLedgerRepositoryError):
        reload_and_verify_repository_export(
            exported,
            fee_binding_trust_context=context,
        )


@pytest.mark.parametrize("mutation", ["backdated_issue", "future_archive"])
def test_fee_binding_rejects_temporal_causality_inversion(
    mutation: str,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = copy.deepcopy(sources["actual"])
    if mutation == "backdated_issue":
        statement, keyring, _ = _signed_artifacts(
            archive,
            issued_at_utc="2026-09-02T08:01:20Z",
            not_before_at_utc="2026-09-02T08:01:10Z",
        )
    else:
        archive["session_archive"]["completed_at_utc"] = "2026-09-02T08:01:45Z"
        statement, keyring, _ = _signed_artifacts(archive)

    with pytest.raises(ValueError, match="temporal causality"):
        _evidence(archive, statement=statement, keyring=keyring)


def test_settings_loader_rejects_self_signed_root_and_expired_backfill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources, _ = source_inputs_with_verified_actual()
    archive = sources["actual"]
    source_raw = b"synthetic-test-fee-source-not-authority\n"
    source_path = (tmp_path / "source.bin").resolve()
    source_path.write_bytes(source_raw)
    source_path.chmod(0o600)
    trusted_statement, trusted_keyring, trusted_private = _signed_artifacts(
        archive,
        source_document_raw_sha256=sha256_bytes(source_raw),
    )
    attacker_statement, attacker_keyring, _ = _signed_artifacts(
        archive,
        source_document_raw_sha256=sha256_bytes(source_raw),
    )
    trusted_keyring_raw = _write_private(
        tmp_path / "trusted-keyring.json",
        trusted_keyring,
    )
    trusted_statement_raw = _write_private(
        tmp_path / "trusted-statement.json",
        trusted_statement,
    )
    attacker_statement_raw = _write_private(
        tmp_path / "attacker-statement.json",
        attacker_statement,
    )
    _write_private(tmp_path / "attacker-keyring.json", attacker_keyring)
    settings = _fee_settings(
        fee_keyring_path=(tmp_path / "trusted-keyring.json").resolve(),
        fee_keyring_raw_sha256=sha256_bytes(trusted_keyring_raw),
        authority=_authority_keyrings(tmp_path),
    )
    monkeypatch.setattr(
        fee_statement_service,
        "_trusted_current_utc",
        lambda: "2026-09-02T08:01:50Z",
    )

    evidence, _ = load_and_verify_fee_binding_with_trust_context_from_settings(
        settings=settings,
        statement_path=(tmp_path / "trusted-statement.json").resolve(),
        source_document_path=source_path,
        expected_statement_raw_sha256=sha256_bytes(trusted_statement_raw),
        archive_facts=archive,
    )
    assert evidence.fee_binding_state == "BOUND"

    from app.schemas.commodity_c_fast_pnl_ledger import (
        ActualSimNowPinnedArchiveReplayFactsDTO,
    )

    settled = settled_archive_replay_from_v4(
        ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(archive)
    )
    late_statement, _, _ = _signed_artifacts(
        settled.model_dump(mode="json"),
        private=trusted_private,
        source_document_raw_sha256=sha256_bytes(source_raw),
        issued_at_utc="2026-09-02T08:03:00Z",
        not_before_at_utc="2026-09-02T08:02:30Z",
    )
    late_raw = _write_private(
        tmp_path / "late-statement.json",
        late_statement,
    )
    monkeypatch.setattr(
        fee_statement_service,
        "_trusted_current_utc",
        lambda: "2026-09-02T08:04:00Z",
    )
    reattested, late_evidence, _ = (
        load_and_verify_late_fee_correction_from_settings(
            settings=settings,
            statement_path=(tmp_path / "late-statement.json").resolve(),
            source_document_path=source_path,
            expected_statement_raw_sha256=sha256_bytes(late_raw),
            archive_replay=settled,
        )
    )
    assert reattested.as_of_at_utc.isoformat() == (
        "2026-09-02T08:04:00+00:00"
    )
    assert late_evidence.verified_at_utc == "2026-09-02T08:04:00Z"

    with pytest.raises(CFastFeeStatementError):
        load_and_verify_fee_binding_with_trust_context_from_settings(
            settings=settings,
            statement_path=(tmp_path / "attacker-statement.json").resolve(),
            source_document_path=source_path,
            expected_statement_raw_sha256=sha256_bytes(attacker_statement_raw),
            archive_facts=archive,
        )

    expired_statement, _, _ = _signed_artifacts(
        archive,
        private=trusted_private,
        source_document_raw_sha256=sha256_bytes(source_raw),
        expires_at_utc="2026-09-02T08:01:45Z",
    )
    expired_raw = _write_private(
        tmp_path / "expired-statement.json",
        expired_statement,
    )
    with pytest.raises(CFastFeeStatementError):
        load_and_verify_fee_binding_with_trust_context_from_settings(
            settings=settings,
            statement_path=(tmp_path / "expired-statement.json").resolve(),
            source_document_path=source_path,
            expected_statement_raw_sha256=sha256_bytes(expired_raw),
            archive_facts=archive,
        )
