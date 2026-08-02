from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from pydantic import ValidationError

from app.schemas.commodity_c_fast_fee_statement import (
    CommodityCFastFeeBindingEvidenceDTO,
    CommodityCFastFeeStatementDTO,
    CommodityCFastFeeStatementTrustedKeyringDTO,
    REQUIRED_EXCLUDED_AUTHORITY_DOMAINS,
    canonical_json_bytes,
    sha256_bytes,
    verify_fee_statement_and_calculate,
)
from app.schemas.commodity_c_fast_execution_permit import (
    CommodityCFastExecutionPermitTrustedKeysDTO,
)
from app.schemas.commodity_c_fast_execution_quality_runtime_admission import (
    CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO,
)
from app.schemas.commodity_c_fast_pnl_ledger import (
    ActualSimNowPinnedArchiveReplayFactsDTO,
    ActualSimNowSettledArchiveReplayFactsDTO,
)
from app.schemas.commodity_baseline_execution_permit import (
    CommodityBaselinePermitTrustedKeysDTO,
)
from app.services.commodity_c_fast_pnl_ledger import (
    reattest_settled_archive_replay,
    settled_archive_replay_from_v4,
)
from app.services.commodity_c_fast_fee_binding_trust import (
    FeeBindingTrustContext,
    _mint_fee_binding_trust_context,
)

if TYPE_CHECKING:
    from app.core.config import Settings


MAX_FEE_ARTIFACT_BYTES = 4 * 1024 * 1024
AUTHORITY_KEYRING_CONTRACTS = {
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


def _trusted_current_utc() -> str:
    """Return the process clock used by authoritative Settings-backed loads."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class CFastFeeStatementError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def load_settled_archive_replay_facts(
    *,
    path: str | Path,
    expected_raw_sha256: str,
) -> ActualSimNowSettledArchiveReplayFactsDTO:
    """Stable-read one canonical embedded archive source-facts artifact."""

    path = Path(path)
    try:
        payload, raw = _read_private_canonical_json(
            path,
            label="FEE_ARCHIVE_FACTS",
        )
        if sha256_bytes(raw) != expected_raw_sha256:
            raise CFastFeeStatementError("FEE_ARCHIVE_FACTS_RAW_PIN_MISMATCH")
        if payload.get("schema_version") == ("commodity_c_fast_actual_simnow_facts_v4"):
            settled = settled_archive_replay_from_v4(
                ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(payload)
            )
        else:
            settled = ActualSimNowSettledArchiveReplayFactsDTO.model_validate(payload)
        second_payload, second_raw = _read_private_canonical_json(
            path,
            label="FEE_ARCHIVE_FACTS",
        )
        if second_raw != raw or second_payload != payload:
            raise CFastFeeStatementError("FEE_ARCHIVE_FACTS_CHANGED_DURING_VERIFY")
        return settled
    except CFastFeeStatementError:
        raise
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastFeeStatementError("FEE_ARCHIVE_FACTS_INVALID") from exc


def load_and_verify_fee_binding(
    **kwargs: Any,
) -> CommodityCFastFeeBindingEvidenceDTO:
    evidence, _ = _load_and_verify_fee_binding(
        **kwargs,
        mint_trust_context=False,
    )
    return evidence


def _load_and_verify_fee_binding(
    *,
    statement_path: str | Path,
    trusted_keyring_path: str | Path,
    source_document_path: str | Path,
    expected_statement_raw_sha256: str,
    expected_trusted_keyring_raw_sha256: str,
    required_authority_keyrings: Mapping[str, tuple[str | Path, str]],
    manual_execution_permit_trusted_public_keys_json: str,
    verified_at_utc: str,
    archive_facts: Mapping[str, Any],
    mint_trust_context: bool,
    historical_trust_profiles: tuple[Mapping[str, Any], ...] = (),
) -> tuple[
    CommodityCFastFeeBindingEvidenceDTO,
    FeeBindingTrustContext | None,
]:
    """Stable-read, domain-check and replay one exact fee statement.

    The function is offline and read-only.  It grants no trading or database
    authority and never reads an account identifier in plaintext.
    """

    statement_path = Path(statement_path)
    keyring_path = Path(trusted_keyring_path)
    source_path = Path(source_document_path)
    authority_paths = [Path(value[0]) for value in required_authority_keyrings.values()]
    all_paths = [statement_path, keyring_path, source_path, *authority_paths]
    if any(not path.is_absolute() for path in all_paths) or len(set(all_paths)) != len(
        all_paths
    ):
        raise CFastFeeStatementError("FEE_ARTIFACT_PATH_INVALID_OR_OVERLAP")
    try:
        statement_payload, statement_raw = _read_private_canonical_json(
            statement_path,
            label="FEE_STATEMENT",
        )
        keyring_payload, keyring_raw = _read_private_canonical_json(
            keyring_path,
            label="FEE_KEYRING",
        )
        source_raw = _read_private_raw(
            source_path,
            label="FEE_SOURCE_DOCUMENT",
        )
        if sha256_bytes(statement_raw) != expected_statement_raw_sha256:
            raise CFastFeeStatementError("FEE_STATEMENT_RAW_PIN_MISMATCH")
        if sha256_bytes(keyring_raw) != expected_trusted_keyring_raw_sha256:
            raise CFastFeeStatementError("FEE_KEYRING_RAW_PIN_MISMATCH")
        authority_payloads, authority_raws, authority_public_hashes = (
            _load_required_authority_keyrings(required_authority_keyrings)
        )
        manual_raw, manual_public_hashes = _load_manual_authority_keys(
            manual_execution_permit_trusted_public_keys_json
        )
        authority_raws["MANUAL_EXECUTION_PERMIT"] = manual_raw
        authority_public_hashes["MANUAL_EXECUTION_PERMIT"] = manual_public_hashes
        statement = CommodityCFastFeeStatementDTO.model_validate(statement_payload)
        keyring = CommodityCFastFeeStatementTrustedKeyringDTO.model_validate(
            keyring_payload
        )
        if statement.source_document_raw_sha256 != sha256_bytes(source_raw):
            raise CFastFeeStatementError("FEE_SOURCE_DOCUMENT_RAW_PIN_MISMATCH")
        evidence = verify_fee_statement_and_calculate(
            statement=statement,
            trusted_keyring=keyring,
            statement_raw_sha256=expected_statement_raw_sha256,
            trusted_keyring_raw_sha256=(expected_trusted_keyring_raw_sha256),
            excluded_authority_keyring_raw_sha256s={
                role: sha256_bytes(raw) for role, raw in authority_raws.items()
            },
            excluded_authority_public_key_sha256s=authority_public_hashes,
            verified_at_utc=verified_at_utc,
            archive_facts=archive_facts,
        )
        second_statement_payload, second_statement_raw = _read_private_canonical_json(
            statement_path,
            label="FEE_STATEMENT",
        )
        second_keyring_payload, second_keyring_raw = _read_private_canonical_json(
            keyring_path,
            label="FEE_KEYRING",
        )
        second_source_raw = _read_private_raw(
            source_path,
            label="FEE_SOURCE_DOCUMENT",
        )
        second_authority_payloads, second_authority_raws, _ = (
            _load_required_authority_keyrings(required_authority_keyrings)
        )
        second_manual_raw, second_manual_public_hashes = _load_manual_authority_keys(
            manual_execution_permit_trusted_public_keys_json
        )
        second_authority_raws["MANUAL_EXECUTION_PERMIT"] = second_manual_raw
        if (
            second_statement_raw != statement_raw
            or second_keyring_raw != keyring_raw
            or second_statement_payload != statement_payload
            or second_keyring_payload != keyring_payload
            or second_source_raw != source_raw
            or second_authority_raws != authority_raws
            or second_authority_payloads != authority_payloads
            or second_manual_public_hashes != manual_public_hashes
        ):
            raise CFastFeeStatementError("FEE_ARTIFACT_CHANGED_DURING_VERIFY")
        context = None
        if mint_trust_context:
            context = _mint_fee_binding_trust_context(
                fee_keyring_raw_sha256=(expected_trusted_keyring_raw_sha256),
                excluded_authority_keyring_raw_sha256s={
                    role: sha256_bytes(raw) for role, raw in authority_raws.items()
                },
                excluded_authority_public_key_sha256s=(authority_public_hashes),
                historical_profiles=historical_trust_profiles,
            )
            context.assert_matches(evidence)
        return evidence, context
    except CFastFeeStatementError:
        raise
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastFeeStatementError("FEE_STATEMENT_VERIFICATION_FAILED") from exc


def load_and_verify_fee_binding_from_settings(
    *,
    settings: "Settings",
    statement_path: str | Path,
    source_document_path: str | Path,
    expected_statement_raw_sha256: str,
    archive_facts: Mapping[str, Any],
) -> CommodityCFastFeeBindingEvidenceDTO:
    """Use the repository's pinned formal C_FAST authority keyrings."""

    evidence, _ = load_and_verify_fee_binding_with_trust_context_from_settings(
        settings=settings,
        statement_path=statement_path,
        source_document_path=source_document_path,
        expected_statement_raw_sha256=expected_statement_raw_sha256,
        archive_facts=archive_facts,
    )
    return evidence


def load_and_verify_fee_binding_with_trust_context_from_settings(
    *,
    settings: "Settings",
    statement_path: str | Path,
    source_document_path: str | Path,
    expected_statement_raw_sha256: str,
    archive_facts: Mapping[str, Any],
) -> tuple[
    CommodityCFastFeeBindingEvidenceDTO,
    FeeBindingTrustContext,
]:
    """Stable-read fee and all excluded domains into one trust capability."""

    return _load_fee_binding_from_settings_at(
        settings=settings,
        statement_path=statement_path,
        source_document_path=source_document_path,
        expected_statement_raw_sha256=expected_statement_raw_sha256,
        verified_at_utc=_trusted_current_utc(),
        archive_facts=archive_facts,
    )


def load_fee_binding_trust_context_from_settings(
    *,
    settings: "Settings",
) -> FeeBindingTrustContext:
    """Stable-read deployment trust roots without requiring a fee statement.

    This restart/replay path grants only the process-local capability needed to
    authenticate already persisted fee-bound ledger evidence.  It neither
    verifies nor creates a fee statement and grants no execution authority.
    """

    (
        fee_keyring_path,
        fee_keyring_raw_sha256,
        required,
        manual_keys_json,
        historical_profiles,
    ) = _fee_binding_trust_roots_from_settings(settings)
    keyring_path = Path(fee_keyring_path)
    authority_paths = [Path(value[0]) for value in required.values()]
    all_paths = [keyring_path, *authority_paths]
    if any(not path.is_absolute() for path in all_paths) or len(
        set(all_paths)
    ) != len(all_paths):
        raise CFastFeeStatementError(
            "FEE_TRUST_ARTIFACT_PATH_INVALID_OR_OVERLAP"
        )
    try:
        keyring_payload, keyring_raw = _read_private_canonical_json(
            keyring_path,
            label="FEE_KEYRING",
        )
        if sha256_bytes(keyring_raw) != fee_keyring_raw_sha256:
            raise CFastFeeStatementError("FEE_KEYRING_RAW_PIN_MISMATCH")
        keyring = CommodityCFastFeeStatementTrustedKeyringDTO.model_validate(
            keyring_payload
        )
        authority_payloads, authority_raws, authority_public_hashes = (
            _load_required_authority_keyrings(required)
        )
        manual_raw, manual_public_hashes = _load_manual_authority_keys(
            manual_keys_json
        )
        authority_raws["MANUAL_EXECUTION_PERMIT"] = manual_raw
        authority_public_hashes["MANUAL_EXECUTION_PERMIT"] = (
            manual_public_hashes
        )
        _assert_fee_trust_roots_are_separate(
            keyring=keyring,
            fee_keyring_raw_sha256=fee_keyring_raw_sha256,
            authority_raws=authority_raws,
            authority_public_hashes=authority_public_hashes,
        )

        second_keyring_payload, second_keyring_raw = (
            _read_private_canonical_json(
                keyring_path,
                label="FEE_KEYRING",
            )
        )
        second_authority_payloads, second_authority_raws, (
            second_authority_public_hashes
        ) = _load_required_authority_keyrings(required)
        second_manual_raw, second_manual_public_hashes = (
            _load_manual_authority_keys(manual_keys_json)
        )
        second_authority_raws["MANUAL_EXECUTION_PERMIT"] = second_manual_raw
        second_authority_public_hashes["MANUAL_EXECUTION_PERMIT"] = (
            second_manual_public_hashes
        )
        if (
            second_keyring_payload != keyring_payload
            or second_keyring_raw != keyring_raw
            or second_authority_payloads != authority_payloads
            or second_authority_raws != authority_raws
            or second_authority_public_hashes != authority_public_hashes
        ):
            raise CFastFeeStatementError(
                "FEE_TRUST_ROOT_CHANGED_DURING_VERIFY"
            )
        return _mint_fee_binding_trust_context(
            fee_keyring_raw_sha256=fee_keyring_raw_sha256,
            excluded_authority_keyring_raw_sha256s={
                role: sha256_bytes(raw)
                for role, raw in authority_raws.items()
            },
            excluded_authority_public_key_sha256s=authority_public_hashes,
            historical_profiles=historical_profiles,
        )
    except CFastFeeStatementError:
        raise
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastFeeStatementError(
            "FEE_TRUST_CONTEXT_VERIFICATION_FAILED"
        ) from exc


def load_and_verify_late_fee_correction_from_settings(
    *,
    settings: "Settings",
    statement_path: str | Path,
    source_document_path: str | Path,
    expected_statement_raw_sha256: str,
    archive_replay: ActualSimNowSettledArchiveReplayFactsDTO,
) -> tuple[
    ActualSimNowSettledArchiveReplayFactsDTO,
    CommodityCFastFeeBindingEvidenceDTO,
    FeeBindingTrustContext,
]:
    """Re-attest a settled wrapper and verify a late fee at one clock instant."""

    verified_at_utc = _trusted_current_utc()
    reattested = reattest_settled_archive_replay(
        archive_replay,
        as_of_at_utc=verified_at_utc,
    )
    evidence, context = _load_fee_binding_from_settings_at(
        settings=settings,
        statement_path=statement_path,
        source_document_path=source_document_path,
        expected_statement_raw_sha256=expected_statement_raw_sha256,
        verified_at_utc=verified_at_utc,
        archive_facts=reattested.model_dump(mode="json"),
    )
    return reattested, evidence, context


def _load_fee_binding_from_settings_at(
    *,
    settings: "Settings",
    statement_path: str | Path,
    source_document_path: str | Path,
    expected_statement_raw_sha256: str,
    verified_at_utc: str,
    archive_facts: Mapping[str, Any],
) -> tuple[
    CommodityCFastFeeBindingEvidenceDTO,
    FeeBindingTrustContext,
]:
    """Internal single-clock Settings trust-root verification path."""

    (
        fee_keyring_path,
        fee_keyring_raw_sha256,
        required,
        manual_keys_json,
        historical_profiles,
    ) = _fee_binding_trust_roots_from_settings(settings)
    evidence, context = _load_and_verify_fee_binding(
        statement_path=statement_path,
        trusted_keyring_path=fee_keyring_path,
        source_document_path=source_document_path,
        expected_statement_raw_sha256=expected_statement_raw_sha256,
        expected_trusted_keyring_raw_sha256=fee_keyring_raw_sha256,
        required_authority_keyrings=required,
        manual_execution_permit_trusted_public_keys_json=manual_keys_json,
        verified_at_utc=verified_at_utc,
        archive_facts=archive_facts,
        mint_trust_context=True,
        historical_trust_profiles=historical_profiles,
    )
    if context is None:  # pragma: no cover - internal fail-closed invariant
        raise CFastFeeStatementError("FEE_TRUST_CONTEXT_NOT_MINTED")
    return evidence, context


def _fee_binding_trust_roots_from_settings(
    settings: "Settings",
) -> tuple[
    str,
    str,
    dict[str, tuple[str, str]],
    str,
    tuple[Mapping[str, Any], ...],
]:
    fee_keyring_path = settings.commodity_c_fast_fee_statement_trusted_keyring_path
    fee_keyring_raw_sha256 = (
        settings.commodity_c_fast_fee_statement_expected_keyring_raw_sha256
    )
    if (
        not fee_keyring_path.strip()
        or len(fee_keyring_raw_sha256) != 64
        or any(char not in "0123456789abcdef" for char in fee_keyring_raw_sha256)
    ):
        raise CFastFeeStatementError("FEE_SETTINGS_TRUST_ROOT_MISSING_OR_INVALID")
    try:
        historical_payload = json.loads(
            settings.commodity_c_fast_fee_statement_historical_trust_profiles_json
        )
    except (TypeError, ValueError) as exc:
        raise CFastFeeStatementError(
            "FEE_HISTORICAL_TRUST_PROFILES_INVALID"
        ) from exc
    if not isinstance(historical_payload, list) or not all(
        isinstance(profile, Mapping) for profile in historical_payload
    ):
        raise CFastFeeStatementError(
            "FEE_HISTORICAL_TRUST_PROFILES_INVALID"
        )

    required = {
        "COMMODITY_BASELINE_EXECUTION_PERMIT": (
            settings.commodity_baseline_execution_permit_trusted_keyring_path,
            settings.commodity_baseline_execution_permit_expected_keyring_raw_sha256,
        ),
        "C_FAST_EXECUTION_PERMIT": (
            settings.commodity_c_fast_simnow_execution_permit_trusted_keyring_path,
            settings.commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256,
        ),
        "C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION": (
            settings.commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path,
            settings.commodity_c_fast_execution_quality_runtime_admission_expected_keyring_raw_sha256,
        ),
        "C_FAST_RESEARCH_ACCEPTANCE": (
            settings.commodity_c_fast_simnow_research_acceptance_trusted_keyring_path,
            settings.commodity_c_fast_simnow_research_acceptance_expected_keyring_raw_sha256,
        ),
        "C_FAST_RESEARCH_BUNDLE": (
            settings.commodity_c_fast_simnow_research_keyring_path,
            settings.commodity_c_fast_simnow_research_expected_keyring_raw_sha256,
        ),
    }
    return (
        fee_keyring_path,
        fee_keyring_raw_sha256,
        required,
        settings.manual_execution_permit_trusted_public_keys_json,
        tuple(historical_payload),
    )


def _load_required_authority_keyrings(
    required: Mapping[str, tuple[str | Path, str]],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, bytes],
    dict[str, tuple[str, ...]],
]:
    expected_file_domains = tuple(
        role
        for role in REQUIRED_EXCLUDED_AUTHORITY_DOMAINS
        if role != "MANUAL_EXECUTION_PERMIT"
    )
    if tuple(sorted(required)) != expected_file_domains:
        raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_MAP_INCOMPLETE")
    payloads: dict[str, dict[str, Any]] = {}
    raws: dict[str, bytes] = {}
    public_hashes: dict[str, tuple[str, ...]] = {}
    for role in expected_file_domains:
        path_raw, expected_raw_sha256 = required[role]
        if (
            not str(path_raw).strip()
            or len(expected_raw_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_raw_sha256)
        ):
            raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_PIN_INVALID")
        payload, raw = _read_private_json(
            Path(path_raw),
            label=f"FEE_AUTHORITY_{role}",
            canonical_required=False,
        )
        if sha256_bytes(raw) != expected_raw_sha256:
            raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_RAW_PIN_MISMATCH")
        schema_version, purpose, rows_field = AUTHORITY_KEYRING_CONTRACTS[role]
        if (
            payload.get("schema_version") != schema_version
            or payload.get("purpose") != purpose
            or not isinstance(payload.get(rows_field), list)
            or not payload[rows_field]
        ):
            raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_SCHEMA_INVALID")
        if role == "COMMODITY_BASELINE_EXECUTION_PERMIT":
            CommodityBaselinePermitTrustedKeysDTO.model_validate(payload)
        elif role == "C_FAST_EXECUTION_PERMIT":
            CommodityCFastExecutionPermitTrustedKeysDTO.model_validate(payload)
        elif role == "C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION":
            CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO.model_validate(payload)
        else:
            if set(payload) != {"schema_version", "purpose", "keys"} or any(
                not isinstance(row, dict)
                or set(row) != {"key_id", "purpose", "public_key_base64"}
                or row.get("purpose") != purpose
                for row in payload[rows_field]
            ):
                raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_SCHEMA_INVALID")
        hashes: list[str] = []
        for row in payload[rows_field]:
            if not isinstance(row, dict):
                raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_SCHEMA_INVALID")
            try:
                material = base64.b64decode(
                    row.get("public_key_base64"),
                    validate=True,
                )
            except (TypeError, ValueError, binascii.Error) as exc:
                raise CFastFeeStatementError(
                    "FEE_AUTHORITY_DOMAIN_KEY_INVALID"
                ) from exc
            if len(material) != 32:
                raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_KEY_INVALID")
            hashes.append(sha256_bytes(material))
        if len(set(hashes)) != len(hashes):
            raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_KEY_INVALID")
        payloads[role] = payload
        raws[role] = raw
        public_hashes[role] = tuple(sorted(hashes))
    flattened = [item for values in public_hashes.values() for item in values]
    if len(set(flattened)) != len(flattened):
        raise CFastFeeStatementError("FEE_AUTHORITY_DOMAIN_KEY_OVERLAP")
    return payloads, raws, public_hashes


def _load_manual_authority_keys(
    configured: str,
) -> tuple[bytes, tuple[str, ...]]:
    raw = configured.encode("utf-8")
    try:
        payload = json.loads(configured)
    except json.JSONDecodeError as exc:
        raise CFastFeeStatementError("FEE_MANUAL_AUTHORITY_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise CFastFeeStatementError("FEE_MANUAL_AUTHORITY_JSON_INVALID")
    hashes: list[str] = []
    for key_id, row in sorted(payload.items()):
        if (
            not isinstance(key_id, str)
            or not 8 <= len(key_id) <= 128
            or not isinstance(row, dict)
            or set(row) != {"public_key_base64", "purpose"}
            or row.get("purpose") != "manual_execution_permit_signer"
        ):
            raise CFastFeeStatementError("FEE_MANUAL_AUTHORITY_JSON_INVALID")
        try:
            material = base64.b64decode(
                row["public_key_base64"],
                validate=True,
            )
        except (TypeError, ValueError, binascii.Error) as exc:
            raise CFastFeeStatementError("FEE_MANUAL_AUTHORITY_KEY_INVALID") from exc
        if (
            len(material) != 32
            or base64.b64encode(material).decode("ascii") != row["public_key_base64"]
        ):
            raise CFastFeeStatementError("FEE_MANUAL_AUTHORITY_KEY_INVALID")
        hashes.append(sha256_bytes(material))
    if len(set(hashes)) != len(hashes):
        raise CFastFeeStatementError("FEE_MANUAL_AUTHORITY_KEY_INVALID")
    return raw, tuple(hashes)


def _assert_fee_trust_roots_are_separate(
    *,
    keyring: CommodityCFastFeeStatementTrustedKeyringDTO,
    fee_keyring_raw_sha256: str,
    authority_raws: Mapping[str, bytes],
    authority_public_hashes: Mapping[str, tuple[str, ...]],
) -> None:
    authority_raw_pins = [
        sha256_bytes(raw) for raw in authority_raws.values()
    ]
    authority_public_pins = [
        pin
        for pins in authority_public_hashes.values()
        for pin in pins
    ]
    fee_public_pins = {
        row.public_key_sha256 for row in keyring.trusted_keys
    }
    if (
        len(set(authority_raw_pins)) != len(authority_raw_pins)
        or fee_keyring_raw_sha256 in authority_raw_pins
        or len(set(authority_public_pins)) != len(authority_public_pins)
        or fee_public_pins.intersection(authority_public_pins)
    ):
        raise CFastFeeStatementError("FEE_TRUST_AUTHORITY_OVERLAP")


def _read_private_canonical_json(
    path: Path,
    *,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    return _read_private_json(path, label=label, canonical_required=True)


def _read_private_json(
    path: Path,
    *,
    label: str,
    canonical_required: bool,
) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise CFastFeeStatementError(f"{label}_PATH_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CFastFeeStatementError(f"{label}_READ_FAILED") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size <= 0
            or before.st_size > MAX_FEE_ARTIFACT_BYTES
        ):
            raise CFastFeeStatementError(f"{label}_CUSTODY_INVALID")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_FEE_ARTIFACT_BYTES + 1)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except CFastFeeStatementError:
        raise
    except OSError as exc:
        raise CFastFeeStatementError(f"{label}_READ_FAILED") from exc
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(current)
    ):
        raise CFastFeeStatementError(f"{label}_CHANGED_DURING_READ")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CFastFeeStatementError(f"{label}_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise CFastFeeStatementError(f"{label}_JSON_INVALID")
    try:
        canonical = canonical_json_bytes(payload)
    except (TypeError, ValueError) as exc:
        raise CFastFeeStatementError(f"{label}_JSON_INVALID") from exc
    if canonical_required and raw != canonical:
        raise CFastFeeStatementError(f"{label}_NOT_CANONICAL")
    return payload, raw


def _read_private_raw(path: Path, *, label: str) -> bytes:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise CFastFeeStatementError(f"{label}_PATH_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CFastFeeStatementError(f"{label}_READ_FAILED") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size <= 0
            or before.st_size > MAX_FEE_ARTIFACT_BYTES
        ):
            raise CFastFeeStatementError(f"{label}_CUSTODY_INVALID")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_FEE_ARTIFACT_BYTES + 1)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except CFastFeeStatementError:
        raise
    except OSError as exc:
        raise CFastFeeStatementError(f"{label}_READ_FAILED") from exc
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(current)
    ):
        raise CFastFeeStatementError(f"{label}_CHANGED_DURING_READ")
    return raw


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
