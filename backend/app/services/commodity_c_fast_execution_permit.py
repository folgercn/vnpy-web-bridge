from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.schemas.commodity_c_fast_execution_permit import (
    CommodityCFastExecutionPermitTrustedKeyDTO,
    CommodityCFastExecutionPermitTrustedKeysDTO,
    CommodityCFastSimNowExecutionPermitDTO,
)
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastShakedownSnapshotDTO,
)
from app.services.commodity_c_fast_research_acceptance_evidence import (
    CommodityCFastResearchAcceptanceEvidenceService,
    VerifiedCommodityCFastResearchAcceptanceEvidence,
)

MAX_JSON_BYTES = 1024 * 1024
MAX_PERMIT_LIFETIME = timedelta(minutes=10)


class CommodityCFastExecutionPermitError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unsigned_permit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def permit_binding_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"permit_id", "signature"}
    }


def derived_permit_id(payload: dict[str, Any]) -> str:
    return (
        "cfast-simnow-execution-permit-v1-"
        f"{sha256_bytes(canonical_json(permit_binding_payload(payload)))}"
    )


def adapter_target_projection(
    *,
    product: str,
    exact_contract: str,
    previous_target_quantity: int,
    target_quantity: int,
) -> dict[str, Any]:
    return {
        "product": product,
        "exact_contract": exact_contract,
        "previous_target_quantity": previous_target_quantity,
        "target_quantity": target_quantity,
    }


def adapter_target_projection_sha256(**kwargs: Any) -> str:
    return sha256_bytes(canonical_json(adapter_target_projection(**kwargs)))


def _parse_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CommodityCFastExecutionPermitError(f"{label.upper()}_TIMEZONE_MISSING")
    return value.astimezone(timezone.utc)


def _read_exact_canonical_json(path: Path, label: str) -> tuple[Any, bytes]:
    try:
        stat = path.lstat()
        if not path.is_file() or path.is_symlink():
            raise CommodityCFastExecutionPermitError(f"{label}_FILE_INVALID")
        if stat.st_size <= 0 or stat.st_size > MAX_JSON_BYTES:
            raise CommodityCFastExecutionPermitError(f"{label}_SIZE_INVALID")
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise CommodityCFastExecutionPermitError(f"{label}_ROOT_INVALID")
        if raw != canonical_json(payload) + b"\n":
            raise CommodityCFastExecutionPermitError(f"{label}_NOT_EXACT_CANONICAL")
        if path.lstat() != stat:
            raise CommodityCFastExecutionPermitError(f"{label}_CHANGED_DURING_READ")
        return payload, raw
    except CommodityCFastExecutionPermitError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommodityCFastExecutionPermitError(f"{label}_READ_INVALID") from exc


def verified_execution_key_materials(
    keyring: CommodityCFastExecutionPermitTrustedKeysDTO,
    evidence: VerifiedCommodityCFastResearchAcceptanceEvidence,
) -> dict[str, tuple[CommodityCFastExecutionPermitTrustedKeyDTO, bytes]]:
    """Validate the complete Execution key domain before selecting a signer."""
    verified: dict[
        str,
        tuple[CommodityCFastExecutionPermitTrustedKeyDTO, bytes],
    ] = {}
    seen_materials: set[bytes] = set()
    for trusted in keyring.trusted_keys:
        try:
            material = base64.b64decode(
                trusted.public_key_base64,
                validate=True,
            )
            if len(material) != 32:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(material)
        except (ValueError, binascii.Error) as exc:
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_KEYRING_MATERIAL_INVALID"
            ) from exc
        if material in seen_materials:
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_KEYRING_MATERIAL_DUPLICATE"
            )
        if (
            material in evidence.research_key_materials
            or material in evidence.acceptance_key_materials
        ):
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_KEYRING_DOMAIN_COLLISION"
            )
        if (
            base64.b64encode(material).decode("ascii")
            != trusted.public_key_base64
        ):
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_KEYRING_MATERIAL_INVALID"
            )
        seen_materials.add(material)
        verified[trusted.key_id] = (trusted, material)
    return verified


class CommodityCFastExecutionPermitService:
    """Read-only verifier with no deployment, RPC, position or order dependency."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        clock: Callable[[], datetime] | None = None,
        acceptance_evidence: (
            CommodityCFastResearchAcceptanceEvidenceService | None
        ) = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.acceptance_evidence = (
            acceptance_evidence
            or CommodityCFastResearchAcceptanceEvidenceService(
                settings=self.settings,
                clock=self.clock,
            )
        )

    def verified_permit_for_snapshot(
        self,
        snapshot: CommodityCFastShakedownSnapshotDTO,
        snapshot_sha256: str,
    ) -> CommodityCFastSimNowExecutionPermitDTO:
        if not self.settings.commodity_c_fast_simnow_execution_permit_enabled:
            raise CommodityCFastExecutionPermitError("EXECUTION_PERMIT_BRIDGE_DISABLED")
        evidence = self.acceptance_evidence.verify_existing_receipt()
        permit_path = Path(
            self.settings.commodity_c_fast_simnow_execution_permit_path
        ).expanduser()
        keyring_path = Path(
            self.settings.commodity_c_fast_simnow_execution_permit_trusted_keyring_path
        ).expanduser()
        if permit_path.resolve() == keyring_path.resolve():
            raise CommodityCFastExecutionPermitError("EXECUTION_PERMIT_PATH_COLLISION")
        payload, permit_raw = _read_exact_canonical_json(
            permit_path, "EXECUTION_PERMIT"
        )
        keyring_payload, keyring_raw = _read_exact_canonical_json(
            keyring_path, "EXECUTION_PERMIT_KEYRING"
        )
        expected_keyring_sha256 = self.settings.commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256
        if not hmac.compare_digest(sha256_bytes(keyring_raw), expected_keyring_sha256):
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_KEYRING_PIN_MISMATCH"
            )
        try:
            permit = CommodityCFastSimNowExecutionPermitDTO.model_validate(payload)
            keyring = CommodityCFastExecutionPermitTrustedKeysDTO.model_validate(
                keyring_payload
            )
        except ValidationError as exc:
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_SCHEMA_INVALID"
            ) from exc
        if permit.permit_id != derived_permit_id(payload):
            raise CommodityCFastExecutionPermitError("EXECUTION_PERMIT_ID_MISMATCH")
        verified_keys = verified_execution_key_materials(
            keyring,
            evidence,
        )
        selected = verified_keys.get(permit.signer_key_id)
        if (
            selected is None
            or selected[0].reviewer_role != permit.reviewer_role
        ):
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_SIGNER_NOT_TRUSTED"
            )
        material = selected[1]
        try:
            signature = base64.b64decode(permit.signature, validate=True)
            if (
                len(signature) != 64
                or base64.b64encode(signature).decode("ascii")
                != permit.signature
            ):
                raise ValueError
            Ed25519PublicKey.from_public_bytes(material).verify(
                signature,
                canonical_json(unsigned_permit_payload(payload)),
            )
        except (ValueError, binascii.Error, InvalidSignature) as exc:
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_SIGNATURE_INVALID"
            ) from exc
        now = _parse_utc(self.clock(), "clock")
        issued_at = _parse_utc(permit.issued_at, "issued_at")
        not_before = _parse_utc(permit.not_before, "not_before")
        expires_at = _parse_utc(permit.expires_at, "expires_at")
        if (
            issued_at > not_before
            or not_before > now
            or now >= expires_at
            or expires_at - not_before > MAX_PERMIT_LIFETIME
        ):
            raise CommodityCFastExecutionPermitError("EXECUTION_PERMIT_TIMING_INVALID")
        self._verify_acceptance_binding(permit, evidence)
        self._verify_snapshot_binding(
            permit, snapshot=snapshot, snapshot_sha256=snapshot_sha256
        )
        if (
            _read_exact_canonical_json(permit_path, "EXECUTION_PERMIT")[1] != permit_raw
            or _read_exact_canonical_json(keyring_path, "EXECUTION_PERMIT_KEYRING")[1]
            != keyring_raw
        ):
            raise CommodityCFastExecutionPermitError("EXECUTION_PERMIT_INPUT_CHANGED")
        return permit.model_copy(deep=True)

    @staticmethod
    def _verify_acceptance_binding(
        permit: CommodityCFastSimNowExecutionPermitDTO,
        evidence: VerifiedCommodityCFastResearchAcceptanceEvidence,
    ) -> None:
        acceptance = evidence.acceptance
        receipt = evidence.receipt
        if (
            permit.acceptance_id != acceptance["acceptance_id"]
            or permit.acceptance_state != acceptance["acceptance_state"]
            or permit.acceptance_signer_key_id != acceptance["signer_key_id"]
            or permit.research_signer_key_id != evidence.research_signer_key_id
            or permit.acceptance_raw_sha256 != evidence.acceptance_raw_sha256
            or permit.acceptance_canonical_sha256
            != evidence.acceptance_canonical_sha256
            or permit.acceptance_receipt_raw_sha256 != evidence.receipt_raw_sha256
            or permit.acceptance_receipt_canonical_sha256
            != evidence.receipt_canonical_sha256
            or permit.acceptance_consume_raw_sha256 != evidence.consume_raw_sha256
            or permit.acceptance_consume_canonical_sha256
            != evidence.consume_canonical_sha256
            or permit.acceptance_consume_id != evidence.consume["consume_id"]
            or permit.research_bundle_id != acceptance["research_bundle_id"]
            or permit.research_artifact_index_sha256
            != acceptance["research_artifact_index_sha256"]
            or permit.selected_target_index_sha256
            != acceptance["selected_target_index_sha256"]
            or permit.custody_root_path_sha256 != acceptance["custody_root_path_sha256"]
            or permit.custody_identity_sha256 != acceptance["custody_identity_sha256"]
            or permit.formula_target_binding_sha256
            != acceptance["formula_target_binding_sha256"]
            or permit.expected_simnow_account_sha256
            != acceptance["expected_simnow_account_sha256"]
            or list(permit.selected_products) != acceptance["selected_products"]
            or permit.execution_day.isoformat() != acceptance["execution_day"]
        ):
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_ACCEPTANCE_BINDING_MISMATCH"
            )
        permit_targets = [
            {
                "product": row.product,
                "exact_contract": row.exact_contract,
                "previous_target_quantity": row.previous_target_quantity,
                "signed_target_quantity": row.signed_target_quantity,
                "signed_target_delta": row.signed_target_delta,
                "signed_target_row_sha256": row.signed_target_row_sha256,
            }
            for row in permit.selected_targets
        ]
        if permit_targets != acceptance["selected_targets"]:
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_ACCEPTANCE_TARGET_SPLICE"
            )
        if not (
            _parse_utc(
                datetime.fromisoformat(str(receipt["ready_at"]).replace("Z", "+00:00")),
                "acceptance_ready_at",
            )
            <= _parse_utc(permit.issued_at, "issued_at")
            and _parse_utc(permit.expires_at, "expires_at")
            <= _parse_utc(
                datetime.fromisoformat(
                    str(acceptance["expires_at"]).replace("Z", "+00:00")
                ),
                "acceptance_expires_at",
            )
        ):
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_OUTSIDE_ACCEPTANCE_WINDOW"
            )

    @staticmethod
    def _verify_snapshot_binding(
        permit: CommodityCFastSimNowExecutionPermitDTO,
        *,
        snapshot: CommodityCFastShakedownSnapshotDTO,
        snapshot_sha256: str,
    ) -> None:
        if (
            permit.source_snapshot_id != snapshot.snapshot_id
            or permit.source_snapshot_sha256 != snapshot_sha256
            or permit.legacy_control_acceptance_id != snapshot.control_acceptance_id
            or permit.legacy_execution_permit_id != snapshot.execution_permit_id
            or permit.formula_target_binding_sha256
            != snapshot.formula_target_binding_sha256
            or permit.execution_day != snapshot.execution_day
            or permit.expected_simnow_account_sha256 != snapshot.account_sha256
        ):
            raise CommodityCFastExecutionPermitError(
                "EXECUTION_PERMIT_SNAPSHOT_BINDING_MISMATCH"
            )
        snapshot_rows = {row.product: row for row in snapshot.targets}
        if list(permit.selected_products) != [
            row.product for row in permit.selected_targets
        ] or any(product not in snapshot_rows for product in permit.selected_products):
            raise CommodityCFastExecutionPermitError("EXECUTION_PERMIT_SCOPE_MISMATCH")
        for selected in permit.selected_targets:
            row = snapshot_rows[selected.product]
            projection_sha256 = adapter_target_projection_sha256(
                product=row.product,
                exact_contract=row.exact_contract,
                previous_target_quantity=row.previous_target_quantity,
                target_quantity=row.target_quantity,
            )
            if (
                selected.exact_contract != row.exact_contract
                or selected.previous_target_quantity != row.previous_target_quantity
                or selected.signed_target_quantity != row.target_quantity
                or selected.signed_target_delta
                != row.target_quantity - row.previous_target_quantity
                or selected.adapter_target_projection_sha256 != projection_sha256
            ):
                raise CommodityCFastExecutionPermitError(
                    "EXECUTION_PERMIT_TARGET_BINDING_MISMATCH"
                )


commodity_c_fast_execution_permit_service = CommodityCFastExecutionPermitService()
