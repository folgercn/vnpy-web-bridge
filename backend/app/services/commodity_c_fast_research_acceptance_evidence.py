from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.config import Settings, get_settings

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ACCEPTANCE_TTL = timedelta(minutes=15)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ACCEPTANCE_PREFIX = "cfast-simnow-research-accept-v1-"
CONSUME_PREFIX = "cfast-simnow-research-accept-consume-v1-"
ACCEPTANCE_STATE = "READY_FOR_HUMAN_SIMNOW_EXECUTION_PERMIT_ONLY"

ACCEPTANCE_FIELDS = frozenset(
    """
    schema_version purpose candidate_id parent_issue_number issue_number
    acceptance_id accepted_at not_before expires_at execution_day
    acceptance_state acceptance_scope execution_permit_required
    source_artifacts_exact_raw_reverified signer_type reviewer_role
    human_signature signer_key_id research_bundle_id
    research_bundle_raw_sha256 research_bundle_canonical_sha256
    research_keyring_raw_sha256 research_install_claim_id
    research_install_claim_raw_sha256
    research_install_claim_canonical_sha256
    research_install_receipt_raw_sha256
    research_install_receipt_canonical_sha256
    research_artifact_bindings research_artifact_index_sha256
    formula_target_binding_sha256 custody_root_path_sha256
    custody_identity_sha256 research_install_files_identity_sha256
    acceptance_keyring_raw_sha256 acceptance_verifier_sha256
    acceptance_signer_sha256 acceptance_schema_sha256
    acceptance_keyring_schema_sha256 consume_schema_sha256
    receipt_schema_sha256 expected_simnow_account_sha256
    selected_products selected_targets selected_target_index_sha256
    acceptance_is_deployment_authority acceptance_is_execution_authority
    countable_forward official_forward_claimed production_allowed
    deployment_authorized execution_permit_issued
    simnow_execution_authorized runtime_activation_authorized
    network_authorized web_bridge_rpc_authorized order_authorized
    order_submission_authorized position_read_authorized
    position_mutation_authorized dispatch_authorized trading_authorized
    replacement_authorized production_authorized
    automatic_promotion_authorized dynamic_selection_allowed
    replay_allowed account_data_read execution_data_read orders_sent
    positions_modified web_bridge_rpc_calls signature
    """.split()
)
CONSUME_FIELDS = frozenset(
    """
    schema_version purpose candidate_id acceptance_id consume_id consumed_at
    execution_day not_before expires_at research_bundle_id
    acceptance_raw_sha256 acceptance_canonical_sha256
    research_bundle_raw_sha256 research_bundle_canonical_sha256
    research_install_claim_raw_sha256
    research_install_receipt_raw_sha256 research_artifact_index_sha256
    formula_target_binding_sha256 research_keyring_raw_sha256
    acceptance_keyring_raw_sha256 expected_simnow_account_sha256
    selected_products selected_target_index_sha256 custody_root_path_sha256
    custody_identity_sha256 receipt_filename acceptance_state
    acceptance_is_deployment_authority acceptance_is_execution_authority
    countable_forward official_forward_claimed production_allowed
    deployment_authorized execution_permit_issued
    simnow_execution_authorized runtime_activation_authorized
    network_authorized web_bridge_rpc_authorized order_authorized
    order_submission_authorized position_read_authorized
    position_mutation_authorized dispatch_authorized trading_authorized
    replacement_authorized production_authorized
    automatic_promotion_authorized dynamic_selection_allowed
    replay_allowed account_data_read execution_data_read orders_sent
    positions_modified web_bridge_rpc_calls
    """.split()
)
RECEIPT_FIELDS = frozenset(
    """
    schema_version purpose candidate_id acceptance_id consume_id consumed_at
    final_revalidated_at ready_at execution_day research_bundle_id
    acceptance_raw_sha256 acceptance_canonical_sha256 consume_raw_sha256
    consume_canonical_sha256 consume_filename
    research_bundle_raw_sha256 research_install_claim_raw_sha256
    research_install_receipt_raw_sha256 research_artifact_index_sha256
    formula_target_binding_sha256 expected_simnow_account_sha256
    selected_products selected_target_index_sha256 custody_root_path_sha256
    custody_identity_sha256 acceptance_state
    acceptance_is_deployment_authority acceptance_is_execution_authority
    countable_forward official_forward_claimed production_allowed
    deployment_authorized execution_permit_issued
    simnow_execution_authorized runtime_activation_authorized
    network_authorized web_bridge_rpc_authorized order_authorized
    order_submission_authorized position_read_authorized
    position_mutation_authorized dispatch_authorized trading_authorized
    replacement_authorized production_authorized
    automatic_promotion_authorized dynamic_selection_allowed
    replay_allowed account_data_read execution_data_read orders_sent
    positions_modified web_bridge_rpc_calls
    """.split()
)
FALSE_AUTHORITY_FIELDS = frozenset(
    """
    acceptance_is_deployment_authority acceptance_is_execution_authority
    countable_forward official_forward_claimed production_allowed
    deployment_authorized execution_permit_issued
    simnow_execution_authorized runtime_activation_authorized
    network_authorized web_bridge_rpc_authorized order_authorized
    order_submission_authorized position_read_authorized
    position_mutation_authorized dispatch_authorized trading_authorized
    replacement_authorized production_authorized
    automatic_promotion_authorized dynamic_selection_allowed
    replay_allowed account_data_read execution_data_read
    """.split()
)
ZERO_COUNTER_FIELDS = (
    "orders_sent",
    "positions_modified",
    "web_bridge_rpc_calls",
)
SELECTED_TARGET_FIELDS = frozenset(
    {
        "product",
        "exact_contract",
        "previous_target_quantity",
        "signed_target_quantity",
        "signed_target_delta",
        "signed_target_row_sha256",
    }
)


class CommodityCFastResearchAcceptanceEvidenceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class VerifiedCommodityCFastResearchAcceptanceEvidence:
    acceptance: dict[str, Any]
    acceptance_raw_sha256: str
    acceptance_canonical_sha256: str
    consume: dict[str, Any]
    consume_raw_sha256: str
    consume_canonical_sha256: str
    receipt: dict[str, Any]
    receipt_raw_sha256: str
    receipt_canonical_sha256: str
    research_signer_key_id: str
    research_key_materials: frozenset[bytes]
    acceptance_key_materials: frozenset[bytes]


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _parse_time(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise CommodityCFastResearchAcceptanceEvidenceError(f"{label}_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CommodityCFastResearchAcceptanceEvidenceError(f"{label}_TIMEZONE_MISSING")
    return parsed.astimezone(timezone.utc)


def _read_exact(
    path: Path,
    *,
    label: str,
    custody: tuple[int, int, int] | None = None,
) -> tuple[dict[str, Any], bytes, os.stat_result]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or before.st_size <= 0
            or before.st_size > MAX_JSON_BYTES
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(f"{label}_FILE_INVALID")
        if custody is not None and (
            before.st_dev != custody[0]
            or before.st_uid != custody[1]
            or stat.S_IMODE(before.st_mode) != custody[2]
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                f"{label}_CUSTODY_INVALID"
            )
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        if (
            not isinstance(payload, dict)
            or raw != canonical_json(payload) + b"\n"
            or path.lstat() != before
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                f"{label}_EXACT_BYTES_INVALID"
            )
        return payload, raw, before
    except CommodityCFastResearchAcceptanceEvidenceError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommodityCFastResearchAcceptanceEvidenceError(
            f"{label}_READ_INVALID"
        ) from exc


def _require_exact_fields(
    payload: dict[str, Any],
    expected: frozenset[str],
    label: str,
) -> None:
    if set(payload) != expected:
        raise CommodityCFastResearchAcceptanceEvidenceError(
            f"{label}_SCHEMA_FIELDS_INVALID"
        )


def _require_false_authority(payload: dict[str, Any], label: str) -> None:
    if any(payload.get(field) is not False for field in FALSE_AUTHORITY_FIELDS) or any(
        payload.get(field) != 0 for field in ZERO_COUNTER_FIELDS
    ):
        raise CommodityCFastResearchAcceptanceEvidenceError(
            f"{label}_AUTHORITY_INVALID"
        )


def _custody_facts(path: Path) -> tuple[Path, str, str, int, int, int]:
    try:
        root = path.expanduser()
        if not root.is_absolute() or Path(os.path.normpath(str(root))) != root:
            raise ValueError
        resolved = root.resolve(strict=True)
        info = root.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if resolved != root or not stat.S_ISDIR(info.st_mode) or mode & 0o022:
            raise ValueError
    except (OSError, ValueError) as exc:
        raise CommodityCFastResearchAcceptanceEvidenceError(
            "ACCEPTANCE_CUSTODY_INVALID"
        ) from exc
    path_sha256 = _sha256(str(root).encode("utf-8"))
    identity = {
        "root_path_sha256": path_sha256,
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "mode": mode,
    }
    return (
        root,
        path_sha256,
        _sha256(canonical_json(identity)),
        info.st_dev,
        info.st_uid,
        0o600,
    )


class CommodityCFastResearchAcceptanceEvidenceService:
    """Verify #165 acceptance and its existing one-shot receipt.

    This service never creates or re-consumes the #165 marker/receipt.  It has
    no RPC, order, position, deployment or promotion dependency.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        clock: Callable[[], datetime] | None = None,
        full_acceptance_verifier: Callable[..., Any] | None = None,
        contract_schema_validator: Callable[..., Any] | None = None,
        consume_schema_path: Path | None = None,
        receipt_schema_path: Path | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._full_acceptance_verifier = full_acceptance_verifier
        self._contract_schema_validator = contract_schema_validator
        self._consume_schema_path = consume_schema_path
        self._receipt_schema_path = receipt_schema_path

    def bind_full_acceptance_verifier(
        self,
        verifier: Callable[..., Any],
        *,
        contract_schema_validator: Callable[..., Any],
        consume_schema_path: Path,
        receipt_schema_path: Path,
    ) -> None:
        self._full_acceptance_verifier = verifier
        self._contract_schema_validator = contract_schema_validator
        self._consume_schema_path = consume_schema_path
        self._receipt_schema_path = receipt_schema_path

    def verify_existing_receipt(
        self,
    ) -> VerifiedCommodityCFastResearchAcceptanceEvidence:
        if not self.settings.commodity_c_fast_simnow_execution_permit_enabled:
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_EVIDENCE_BRIDGE_DISABLED"
            )
        custody = _custody_facts(
            Path(self.settings.commodity_c_fast_simnow_research_acceptance_custody_root)
        )
        if not hmac.compare_digest(
            custody[1],
            self.settings.commodity_c_fast_simnow_research_acceptance_expected_custody_root_path_sha256,
        ) or not hmac.compare_digest(
            custody[2],
            self.settings.commodity_c_fast_simnow_research_acceptance_expected_custody_identity_sha256,
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_CUSTODY_PIN_MISMATCH"
            )
        acceptance_path = Path(
            self.settings.commodity_c_fast_simnow_research_acceptance_path
        ).expanduser()
        consume_path = Path(
            self.settings.commodity_c_fast_simnow_research_acceptance_consume_path
        ).expanduser()
        receipt_path = Path(
            self.settings.commodity_c_fast_simnow_research_acceptance_receipt_path
        ).expanduser()
        keyring_path = Path(
            self.settings.commodity_c_fast_simnow_research_acceptance_trusted_keyring_path
        ).expanduser()
        if (
            consume_path.parent != custody[0]
            or receipt_path.parent != custody[0]
            or len(
                {
                    acceptance_path.resolve(),
                    consume_path.resolve(),
                    receipt_path.resolve(),
                    keyring_path.resolve(),
                }
            )
            != 4
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_EVIDENCE_PATH_SPLICE"
            )
        acceptance, acceptance_raw, _ = _read_exact(acceptance_path, label="ACCEPTANCE")
        consume, consume_raw, _ = _read_exact(
            consume_path,
            label="ACCEPTANCE_CONSUME",
            custody=custody[3:],
        )
        receipt, receipt_raw, _ = _read_exact(
            receipt_path,
            label="ACCEPTANCE_RECEIPT",
            custody=custody[3:],
        )
        keyring, keyring_raw, _ = _read_exact(keyring_path, label="ACCEPTANCE_KEYRING")
        full_verified = self._verify_full_research_chain(
            acceptance,
            acceptance_raw,
            keyring_raw,
            acceptance_path=acceptance_path,
            keyring_path=keyring_path,
            custody=custody,
        )
        self._verify_acceptance(acceptance, acceptance_raw, keyring, keyring_raw)
        self._verify_consume_and_receipt(
            acceptance,
            acceptance_raw,
            consume,
            consume_raw,
            receipt,
            receipt_raw,
            consume_path=consume_path,
            receipt_path=receipt_path,
            custody=custody,
        )
        now = _parse_time(self.clock().isoformat(), "CLOCK")
        if not (
            _parse_time(acceptance["not_before"], "NOT_BEFORE")
            <= now
            < _parse_time(acceptance["expires_at"], "EXPIRES_AT")
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_EXPIRED_OR_NOT_YET_VALID"
            )
        final_raw = (
            _read_exact(acceptance_path, label="ACCEPTANCE")[1],
            _read_exact(
                consume_path,
                label="ACCEPTANCE_CONSUME",
                custody=custody[3:],
            )[1],
            _read_exact(
                receipt_path,
                label="ACCEPTANCE_RECEIPT",
                custody=custody[3:],
            )[1],
            _read_exact(keyring_path, label="ACCEPTANCE_KEYRING")[1],
        )
        if (
            final_raw
            != (
                acceptance_raw,
                consume_raw,
                receipt_raw,
                keyring_raw,
            )
            or _custody_facts(custody[0]) != custody
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_EVIDENCE_CHANGED_DURING_VERIFY"
            )
        return VerifiedCommodityCFastResearchAcceptanceEvidence(
            acceptance=acceptance,
            acceptance_raw_sha256=_sha256(acceptance_raw),
            acceptance_canonical_sha256=_sha256(canonical_json(acceptance)),
            consume=consume,
            consume_raw_sha256=_sha256(consume_raw),
            consume_canonical_sha256=_sha256(canonical_json(consume)),
            receipt=receipt,
            receipt_raw_sha256=_sha256(receipt_raw),
            receipt_canonical_sha256=_sha256(canonical_json(receipt)),
            research_signer_key_id=(
                full_verified.installed.verified.payload["signer_key_id"]
            ),
            research_key_materials=(full_verified.installed.research_key_materials),
            acceptance_key_materials=frozenset(
                base64.b64decode(row["public_key_base64"], validate=True)
                for row in keyring["keys"]
            ),
        )

    def _verify_full_research_chain(
        self,
        acceptance: dict[str, Any],
        acceptance_raw: bytes,
        acceptance_keyring_raw: bytes,
        *,
        acceptance_path: Path,
        keyring_path: Path,
        custody: tuple[Path, str, str, int, int, int],
    ) -> Any:
        verifier = self._full_acceptance_verifier
        if verifier is None:
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "FULL_PR165_ACCEPTANCE_VERIFIER_NOT_BOUND"
            )
        try:
            artifact_payload = json.loads(
                self.settings.commodity_c_fast_simnow_research_artifact_paths_json
            )
            artifact_paths = {
                role: Path(path).expanduser() for role, path in artifact_payload.items()
            }
            allowed_accounts = {
                value.strip().lower()
                for value in self.settings.commodity_c_fast_simnow_account_hashes.split(
                    ","
                )
                if value.strip()
            }
            expected_account = str(acceptance["expected_simnow_account_sha256"])
            if (
                expected_account not in allowed_accounts
                or SHA256_RE.fullmatch(expected_account) is None
            ):
                raise CommodityCFastResearchAcceptanceEvidenceError(
                    "ACCEPTANCE_ACCOUNT_NOT_PINNED"
                )
            verified = verifier(
                acceptance_path,
                custody_root=custody[0],
                research_keyring_path=Path(
                    self.settings.commodity_c_fast_simnow_research_keyring_path
                ).expanduser(),
                acceptance_keyring_path=keyring_path,
                artifact_paths=artifact_paths,
                expected_research_keyring_raw_sha256=(
                    self.settings.commodity_c_fast_simnow_research_expected_keyring_raw_sha256
                ),
                expected_research_signer_sha256=(
                    self.settings.commodity_c_fast_simnow_research_expected_signer_sha256
                ),
                expected_acceptance_keyring_raw_sha256=(
                    self.settings.commodity_c_fast_simnow_research_acceptance_expected_keyring_raw_sha256
                ),
                expected_acceptance_signer_sha256=(
                    self.settings.commodity_c_fast_simnow_research_acceptance_expected_signer_sha256
                ),
                expected_simnow_account_sha256=expected_account,
                now=_parse_time(self.clock().isoformat(), "CLOCK"),
            )
        except CommodityCFastResearchAcceptanceEvidenceError:
            raise
        except Exception as exc:
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "FULL_PR165_ACCEPTANCE_CHAIN_INVALID"
            ) from exc
        installed = getattr(verified, "installed", None)
        installed_custody = getattr(installed, "custody", None)
        if (
            getattr(verified, "payload", None) != acceptance
            or getattr(verified, "raw", None) != acceptance_raw
            or getattr(verified, "raw_sha256", None) != _sha256(acceptance_raw)
            or getattr(verified, "canonical_sha256", None)
            != _sha256(canonical_json(acceptance))
            or getattr(verified, "acceptance_keyring_raw", None)
            != acceptance_keyring_raw
            or getattr(installed_custody, "root_path_sha256", None) != custody[1]
            or getattr(installed_custody, "identity_sha256", None) != custody[2]
            or getattr(
                installed,
                "install_files_identity_sha256",
                None,
            )
            != acceptance["research_install_files_identity_sha256"]
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "FULL_PR165_ACCEPTANCE_CHAIN_RESULT_MISMATCH"
            )
        return verified

    def _verify_acceptance(
        self,
        payload: dict[str, Any],
        raw: bytes,
        keyring: dict[str, Any],
        keyring_raw: bytes,
    ) -> None:
        del raw
        _require_exact_fields(payload, ACCEPTANCE_FIELDS, "ACCEPTANCE")
        _require_false_authority(payload, "ACCEPTANCE")
        if (
            payload["schema_version"]
            != "commodity_c_fast_simnow_research_acceptance_v1"
            or payload["purpose"] != "c_fast_simnow_research_control_acceptance"
            or payload["candidate_id"] != "C_FAST_CROSS_SECTION_NEUTRAL"
            or payload["parent_issue_number"] != 114
            or payload["issue_number"] != 162
            or payload["acceptance_state"] != ACCEPTANCE_STATE
            or payload["acceptance_scope"] != "CONTROL_PLANE_RESEARCH_EVIDENCE_ONLY"
            or payload["execution_permit_required"] is not True
            or payload["source_artifacts_exact_raw_reverified"] is not True
            or payload["signer_type"] != "human"
            or str(payload["reviewer_role"]).startswith("PENDING_")
            or str(payload["human_signature"]).startswith("PENDING_")
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_SEMANTICS_INVALID"
            )
        binding = {
            key: value
            for key, value in payload.items()
            if key not in {"acceptance_id", "signature"}
        }
        if payload["acceptance_id"] != (
            ACCEPTANCE_PREFIX + _sha256(canonical_json(binding))
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_ID_MISMATCH"
            )
        accepted_at = _parse_time(payload["accepted_at"], "ACCEPTED_AT")
        not_before = _parse_time(payload["not_before"], "NOT_BEFORE")
        expires_at = _parse_time(payload["expires_at"], "EXPIRES_AT")
        if (
            not_before > accepted_at
            or accepted_at >= expires_at
            or expires_at - not_before > MAX_ACCEPTANCE_TTL
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_TIMING_INVALID"
            )
        products = payload["selected_products"]
        targets = payload["selected_targets"]
        if (
            not isinstance(products, list)
            or products != sorted(products)
            or not 1 <= len(products) <= 2
            or len(set(products)) != len(products)
            or not isinstance(targets, list)
            or len(targets) != len(products)
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_SCOPE_INVALID"
            )
        for product, target in zip(products, targets, strict=True):
            if (
                not isinstance(target, dict)
                or set(target) != SELECTED_TARGET_FIELDS
                or target["product"] != product
                or target["signed_target_quantity"] - target["previous_target_quantity"]
                != target["signed_target_delta"]
                or target["signed_target_delta"] == 0
                or SHA256_RE.fullmatch(str(target["signed_target_row_sha256"])) is None
            ):
                raise CommodityCFastResearchAcceptanceEvidenceError(
                    "ACCEPTANCE_TARGET_INVALID"
                )
        if (
            set(keyring) != {"schema_version", "purpose", "keys"}
            or keyring["schema_version"]
            != "commodity_c_fast_simnow_research_acceptance_trusted_keys_v1"
            or keyring["purpose"] != "c_fast_simnow_research_acceptance_signer"
            or not isinstance(keyring["keys"], list)
            or not keyring["keys"]
            or _sha256(keyring_raw)
            != self.settings.commodity_c_fast_simnow_research_acceptance_expected_keyring_raw_sha256
            or payload["acceptance_keyring_raw_sha256"] != _sha256(keyring_raw)
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_KEYRING_INVALID"
            )
        selected = None
        seen_ids: set[str] = set()
        seen_materials: set[bytes] = set()
        for row in keyring["keys"]:
            if (
                not isinstance(row, dict)
                or set(row) != {"key_id", "purpose", "public_key_base64"}
                or row["purpose"] != "c_fast_simnow_research_acceptance_signer"
                or row["key_id"] in seen_ids
            ):
                raise CommodityCFastResearchAcceptanceEvidenceError(
                    "ACCEPTANCE_KEYRING_INVALID"
                )
            try:
                material = base64.b64decode(row["public_key_base64"], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise CommodityCFastResearchAcceptanceEvidenceError(
                    "ACCEPTANCE_KEYRING_INVALID"
                ) from exc
            if len(material) != 32 or material in seen_materials:
                raise CommodityCFastResearchAcceptanceEvidenceError(
                    "ACCEPTANCE_KEYRING_INVALID"
                )
            seen_ids.add(row["key_id"])
            seen_materials.add(material)
            if row["key_id"] == payload["signer_key_id"]:
                selected = material
        if selected is None:
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_SIGNER_NOT_TRUSTED"
            )
        try:
            signature = base64.b64decode(payload["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(selected).verify(
                signature,
                canonical_json(
                    {key: value for key, value in payload.items() if key != "signature"}
                ),
            )
        except (ValueError, binascii.Error, InvalidSignature) as exc:
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_SIGNATURE_INVALID"
            ) from exc

    def _verify_consume_and_receipt(
        self,
        acceptance: dict[str, Any],
        acceptance_raw: bytes,
        consume: dict[str, Any],
        consume_raw: bytes,
        receipt: dict[str, Any],
        receipt_raw: bytes,
        *,
        consume_path: Path,
        receipt_path: Path,
        custody: tuple[Path, str, str, int, int, int],
    ) -> None:
        schema_validator = self._contract_schema_validator
        if (
            schema_validator is None
            or self._consume_schema_path is None
            or self._receipt_schema_path is None
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "FULL_PR165_RECEIPT_SCHEMA_VALIDATOR_NOT_BOUND"
            )
        try:
            schema_validator(
                consume,
                self._consume_schema_path,
                "runtime C_FAST Research Acceptance consume marker",
            )
            schema_validator(
                receipt,
                self._receipt_schema_path,
                "runtime C_FAST Research Acceptance receipt",
            )
        except Exception as exc:
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "FULL_PR165_RECEIPT_SCHEMA_INVALID"
            ) from exc
        _require_exact_fields(consume, CONSUME_FIELDS, "ACCEPTANCE_CONSUME")
        _require_exact_fields(receipt, RECEIPT_FIELDS, "ACCEPTANCE_RECEIPT")
        _require_false_authority(consume, "ACCEPTANCE_CONSUME")
        _require_false_authority(receipt, "ACCEPTANCE_RECEIPT")
        acceptance_raw_sha = _sha256(acceptance_raw)
        acceptance_canonical_sha = _sha256(canonical_json(acceptance))
        consume_binding = {
            key: value for key, value in consume.items() if key != "consume_id"
        }
        if consume["consume_id"] != (
            CONSUME_PREFIX + _sha256(canonical_json(consume_binding))
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_CONSUME_ID_MISMATCH"
            )
        shared = (
            "acceptance_id",
            "execution_day",
            "research_bundle_id",
            "research_artifact_index_sha256",
            "formula_target_binding_sha256",
            "expected_simnow_account_sha256",
            "selected_products",
            "selected_target_index_sha256",
            "custody_root_path_sha256",
            "custody_identity_sha256",
            "acceptance_state",
        )
        if (
            consume["schema_version"]
            != "commodity_c_fast_simnow_research_acceptance_consume_v1"
            or consume["purpose"]
            != "c_fast_simnow_research_acceptance_one_shot_consume"
            or receipt["schema_version"]
            != "commodity_c_fast_simnow_research_acceptance_receipt_v1"
            or receipt["purpose"]
            != "c_fast_simnow_research_acceptance_create_only_receipt"
            or any(consume[field] != acceptance[field] for field in shared)
            or any(receipt[field] != acceptance[field] for field in shared)
            or receipt["consume_id"] != consume["consume_id"]
            or consume["acceptance_raw_sha256"] != acceptance_raw_sha
            or receipt["acceptance_raw_sha256"] != acceptance_raw_sha
            or consume["acceptance_canonical_sha256"] != acceptance_canonical_sha
            or receipt["acceptance_canonical_sha256"] != acceptance_canonical_sha
            or receipt["consume_raw_sha256"] != _sha256(consume_raw)
            or receipt["consume_canonical_sha256"] != _sha256(canonical_json(consume))
            or consume["receipt_filename"] != receipt_path.name
            or receipt["consume_filename"] != consume_path.name
            or consume["custody_root_path_sha256"] != custody[1]
            or consume["custody_identity_sha256"] != custody[2]
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_RECEIPT_SPLICE_OR_HASH_MISMATCH"
            )
        acceptance_to_consume = (
            ("research_bundle_raw_sha256", "research_bundle_raw_sha256"),
            (
                "research_bundle_canonical_sha256",
                "research_bundle_canonical_sha256",
            ),
            (
                "research_install_claim_raw_sha256",
                "research_install_claim_raw_sha256",
            ),
            (
                "research_install_receipt_raw_sha256",
                "research_install_receipt_raw_sha256",
            ),
            ("research_keyring_raw_sha256", "research_keyring_raw_sha256"),
            (
                "acceptance_keyring_raw_sha256",
                "acceptance_keyring_raw_sha256",
            ),
        )
        if any(
            acceptance[left] != consume[right] for left, right in acceptance_to_consume
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_CONSUME_CHAIN_MISMATCH"
            )
        receipt_chain = (
            "research_bundle_raw_sha256",
            "research_install_claim_raw_sha256",
            "research_install_receipt_raw_sha256",
        )
        if any(acceptance[field] != receipt[field] for field in receipt_chain):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_RECEIPT_CHAIN_MISMATCH"
            )
        accepted_at = _parse_time(acceptance["accepted_at"], "ACCEPTED_AT")
        consumed_at = _parse_time(receipt["consumed_at"], "CONSUMED_AT")
        final_at = _parse_time(receipt["final_revalidated_at"], "FINAL_REVALIDATED_AT")
        ready_at = _parse_time(receipt["ready_at"], "READY_AT")
        expires_at = _parse_time(acceptance["expires_at"], "EXPIRES_AT")
        if receipt["consumed_at"] != consume["consumed_at"] or not (
            accepted_at <= consumed_at <= final_at <= ready_at < expires_at
        ):
            raise CommodityCFastResearchAcceptanceEvidenceError(
                "ACCEPTANCE_RECEIPT_CHRONOLOGY_INVALID"
            )


commodity_c_fast_research_acceptance_evidence_service = (
    CommodityCFastResearchAcceptanceEvidenceService()
)
