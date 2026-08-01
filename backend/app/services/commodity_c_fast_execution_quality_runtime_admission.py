from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.schemas.commodity_c_fast_execution_quality_runtime_admission import (
    CFastExecutionQualityRuntimeAdmissionDTO,
    CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO,
    derived_runtime_admission_id,
)


MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ADMISSION_LIFETIME = timedelta(minutes=10)
_SHA256_FIELDS = {
    "signed_p0_acceptance": "signed_p0_acceptance_sha256",
    "collection_admission": "collection_admission_sha256",
    "execution_policy": "execution_policy_sha256",
    "signed_snapshot": "signed_snapshot_sha256",
    "virtual_intent_plan": "virtual_intent_plan_sha256",
    "contract_spec_set": "contract_spec_set_sha256",
    "custody_binding": "custody_binding_sha256",
}


class CFastExecutionQualityRuntimeAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class VerifiedCFastExecutionQualityRuntimeAdmission:
    admission: CFastExecutionQualityRuntimeAdmissionDTO
    admission_raw_sha256: str
    admission_canonical_sha256: str
    trusted_keyring_raw_sha256: str


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def unsigned_admission_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "signature"}


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_fd_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_JSON_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _safe_parent_chain(path: Path, expected_owner_uid: int) -> bool:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            return False
        mode = stat.S_IMODE(metadata.st_mode)
        writable_by_others = bool(mode & 0o022)
        trusted_sticky_root = (
            metadata.st_uid == 0
            and bool(mode & stat.S_ISVTX)
        )
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, expected_owner_uid}
            or (writable_by_others and not trusted_sticky_root)
        ):
            return False
        if current.parent == current:
            return True
        current = current.parent


def _read_exact_private_canonical_json(
    path: Path,
    *,
    label: str,
    expected_owner_uid: int,
) -> tuple[dict[str, Any], bytes]:
    try:
        if (
            not path.is_absolute()
            or path.resolve(strict=True) != path
            or not _safe_parent_chain(path.parent, expected_owner_uid)
        ):
            raise OSError
        before_path = path.lstat()
        if (
            not stat.S_ISREG(before_path.st_mode)
            or before_path.st_uid != expected_owner_uid
            or before_path.st_nlink != 1
            or stat.S_IMODE(before_path.st_mode) & 0o077
            or before_path.st_size <= 0
            or before_path.st_size > MAX_JSON_BYTES
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                f"{label}_FILE_CUSTODY_INVALID"
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before_fd = os.fstat(descriptor)
            raw = _read_fd_bounded(descriptor)
            after_fd = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
        if (
            len(
                {
                    _stable_file_identity(before_path),
                    _stable_file_identity(before_fd),
                    _stable_file_identity(after_fd),
                    _stable_file_identity(after_path),
                }
            )
            != 1
            or len(raw) != before_fd.st_size
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                f"{label}_CHANGED_DURING_READ"
            )
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise CFastExecutionQualityRuntimeAdmissionError(f"{label}_ROOT_INVALID")
        if raw != canonical_json(payload) + b"\n":
            raise CFastExecutionQualityRuntimeAdmissionError(
                f"{label}_NOT_EXACT_CANONICAL"
            )
        return payload, raw
    except CFastExecutionQualityRuntimeAdmissionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CFastExecutionQualityRuntimeAdmissionError(
            f"{label}_READ_INVALID"
        ) from exc


class CommodityCFastExecutionQualityRuntimeAdmissionConsumer:
    """Verify one short-lived signed read-only sidecar admission.

    This service verifies exact private files, the pinned key domain, Ed25519
    signature, lifetime and every hash in the current full-revalidation
    receipt. Verification is reusable within the admission window; this
    default-off slice does not claim irreversible one-shot consumption. It
    owns no Tick, repository, network, account or trading handle.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def verify_for_receipt(
        self,
        revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> VerifiedCFastExecutionQualityRuntimeAdmission:
        if not self.settings.commodity_c_fast_execution_quality_runtime_enabled:
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_CONSUMER_DISABLED"
            )
        try:
            receipt = CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
                revalidation_receipt
            )
        except ValidationError as exc:
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_REVALIDATION_RECEIPT_INVALID"
            ) from exc

        admission_path = Path(
            self.settings.commodity_c_fast_execution_quality_runtime_admission_path
        ).expanduser()
        keyring_path = Path(
            self.settings.commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path
        ).expanduser()
        if admission_path == keyring_path:
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_PATH_COLLISION"
            )
        owner_uid = self.settings.commodity_c_fast_execution_quality_runtime_admission_expected_owner_uid
        admission_payload, admission_raw = _read_exact_private_canonical_json(
            admission_path,
            label="RUNTIME_ADMISSION",
            expected_owner_uid=owner_uid,
        )
        keyring_payload, keyring_raw = _read_exact_private_canonical_json(
            keyring_path,
            label="RUNTIME_ADMISSION_KEYRING",
            expected_owner_uid=owner_uid,
        )
        expected_keyring_hash = self.settings.commodity_c_fast_execution_quality_runtime_admission_expected_keyring_raw_sha256
        if not hmac.compare_digest(
            sha256_bytes(keyring_raw),
            expected_keyring_hash,
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_KEYRING_PIN_MISMATCH"
            )
        try:
            admission = CFastExecutionQualityRuntimeAdmissionDTO.model_validate(
                admission_payload
            )
            keyring = (
                CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO.model_validate(
                    keyring_payload
                )
            )
        except ValidationError as exc:
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_SCHEMA_INVALID"
            ) from exc

        self._verify_signature(admission_payload, admission, keyring)
        self._verify_timing(admission, receipt)
        self._verify_receipt_binding(admission, receipt)

        if (
            _read_exact_private_canonical_json(
                admission_path,
                label="RUNTIME_ADMISSION",
                expected_owner_uid=owner_uid,
            )[1]
            != admission_raw
            or _read_exact_private_canonical_json(
                keyring_path,
                label="RUNTIME_ADMISSION_KEYRING",
                expected_owner_uid=owner_uid,
            )[1]
            != keyring_raw
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_INPUT_CHANGED"
            )
        return VerifiedCFastExecutionQualityRuntimeAdmission(
            admission=admission.model_copy(deep=True),
            admission_raw_sha256=sha256_bytes(admission_raw),
            admission_canonical_sha256=sha256_bytes(canonical_json(admission_payload)),
            trusted_keyring_raw_sha256=sha256_bytes(keyring_raw),
        )

    @staticmethod
    def _verify_signature(
        payload: dict[str, Any],
        admission: CFastExecutionQualityRuntimeAdmissionDTO,
        keyring: CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO,
    ) -> None:
        if admission.admission_id != derived_runtime_admission_id(payload):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_ID_MISMATCH"
            )
        verified_keys: dict[str, tuple[Any, bytes]] = {}
        seen_materials: set[bytes] = set()
        for key in keyring.trusted_keys:
            try:
                material = base64.b64decode(
                    key.public_key_base64,
                    validate=True,
                )
                if (
                    len(material) != 32
                    or base64.b64encode(material).decode("ascii")
                    != key.public_key_base64
                    or material in seen_materials
                ):
                    raise ValueError
                Ed25519PublicKey.from_public_bytes(material)
            except (ValueError, binascii.Error) as exc:
                raise CFastExecutionQualityRuntimeAdmissionError(
                    "RUNTIME_ADMISSION_KEYRING_MATERIAL_INVALID"
                ) from exc
            seen_materials.add(material)
            verified_keys[key.key_id] = (key, material)
        selected = verified_keys.get(admission.signer_key_id)
        if (
            selected is None
            or selected[0].signer_type != admission.signer_type
            or selected[0].reviewer_role != admission.reviewer_role
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_SIGNER_NOT_TRUSTED"
        )
        try:
            material = selected[1]
            signature = base64.b64decode(admission.signature, validate=True)
            if (
                len(signature) != 64
                or base64.b64encode(signature).decode("ascii") != admission.signature
            ):
                raise ValueError
            Ed25519PublicKey.from_public_bytes(material).verify(
                signature,
                canonical_json(unsigned_admission_payload(payload)),
            )
        except (ValueError, binascii.Error, InvalidSignature) as exc:
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_SIGNATURE_INVALID"
            ) from exc

    def _verify_timing(
        self,
        admission: CFastExecutionQualityRuntimeAdmissionDTO,
        receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> None:
        now = self.clock()
        if (
            now.tzinfo is None
            or now.utcoffset() is None
            or now.utcoffset().total_seconds() != 0
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_CLOCK_MUST_USE_UTC"
            )
        if (
            admission.issued_at_utc > admission.not_before_utc
            or admission.not_before_utc > now
            or now >= admission.expires_at_utc
            or admission.expires_at_utc - admission.not_before_utc
            > MAX_ADMISSION_LIFETIME
            or admission.not_before_utc < receipt.revalidated_at_utc
            or admission.expires_at_utc > receipt.valid_until_utc
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_TIMING_INVALID"
            )

    @staticmethod
    def _verify_receipt_binding(
        admission: CFastExecutionQualityRuntimeAdmissionDTO,
        receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> None:
        if (
            admission.revalidation_receipt_sha256 != receipt.receipt_sha256
            or admission.exact_contracts != receipt.exact_contracts
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_RECEIPT_BINDING_MISMATCH"
            )
        digests = admission.artifact_raw_sha256.model_dump(mode="python")
        if any(
            not hmac.compare_digest(digests[role], getattr(receipt, field))
            for role, field in _SHA256_FIELDS.items()
        ):
            raise CFastExecutionQualityRuntimeAdmissionError(
                "RUNTIME_ADMISSION_ARTIFACT_BINDING_MISMATCH"
            )


commodity_c_fast_execution_quality_runtime_admission_consumer = (
    CommodityCFastExecutionQualityRuntimeAdmissionConsumer()
)


__all__ = [
    "CFastExecutionQualityRuntimeAdmissionError",
    "CommodityCFastExecutionQualityRuntimeAdmissionConsumer",
    "VerifiedCFastExecutionQualityRuntimeAdmission",
    "canonical_json",
    "commodity_c_fast_execution_quality_runtime_admission_consumer",
    "sha256_bytes",
    "unsigned_admission_payload",
]
