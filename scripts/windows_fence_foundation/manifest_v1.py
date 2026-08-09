"""Strict verifier for the signed WF-2 install manifest."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import AUTHORITY_FIELDS, canonical_json_bytes
from .target_contract_v1 import (
    WindowsFoundationTargetContractError,
    parse_windows_foundation_target_policy_v1,
)
from .trust_pins_v1 import (
    MANIFEST_KEY_DOMAIN,
    MANIFEST_SIGNER_ROLE,
    WindowsFoundationTrustPinsV1,
)
from .win32_fs import FilesystemFactsAdapter, PathSecurityFacts

MAX_MANIFEST_BYTES = 256 * 1024
MANIFEST_SCHEMA_VERSION = "windows_rpc_durable_fence_install_manifest_v1"
MANIFEST_ID_PREFIX = "windows-fence-install-manifest-"
SIGNATURE_DOMAIN = "vnpy.issue267.windows-foundation.install-manifest.v1"
INSTALL_ATTEMPT_DOMAIN = "vnpy.issue267.windows-foundation.install-attempt-id.v1"
INSTALL_ATTEMPT_FIELDS = frozenset(
    {
        "attempt_nonce_sha256",
        "bundle_sha256",
        "service_name",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "expected_account_sha256",
        "gateway_name",
        "gateway_scope_sha256",
    }
)

MANIFEST_FIELDS = frozenset(
    [
        "schema_version",
        "purpose",
        "manifest_id",
        "manifest_core_sha256",
        "install_attempt_id",
        "attempt_nonce_sha256",
        "expected_account_sha256",
        "gateway_name",
        "gateway_scope_sha256",
        "target_policy",
        "issued_at_utc",
        "expires_at_utc",
        "trusted_clock_id",
        "service_name",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "store_id",
        "store_owner_sid_sha256",
        "store_directory_acl_sddl_sha256",
        "store_state_acl_sddl_sha256",
        "bundle_sha256",
        "publish_mode",
        "final_version_directory_path_sha256",
        "expected_final_owner_sid_sha256",
        "expected_final_directory_acl_sddl_sha256",
        "expected_component_acl_sddl_sha256",
        "extension_version",
        "wrapper_sha256",
        "wrapper_destination_path_sha256",
        "extension_sha256",
        "extension_destination_path_sha256",
        "launcher_sha256",
        "launcher_destination_path_sha256",
        "assembly_sha256",
        "assembly_destination_path_sha256",
        "config_sha256",
        "config_destination_path_sha256",
        "service_image_path_canonical_sha256",
        "service_config_canonical_sha256",
        "expected_service_config_owner_sid_sha256",
        "expected_service_config_acl_sddl_sha256",
        "installer_write_access_after_publish",
        "preinstall_service_image_path_canonical_sha256",
        "preinstall_service_config_canonical_sha256",
        "safety_service_config_canonical_sha256",
        "service_config_transition_plan_sha256",
        "service_config_mutation_before_dispatch_reservation_authorized",
        "service_config_transition_after_dispatch_reservation_authorized",
        "unbound_service_config_mutation_after_observer_seal_authorized",
        "target_service_start_type",
        "target_recovery_actions_disabled",
        "target_failure_actions_disabled",
        "automatic_policy_restore_authorized",
        "expected_installer_principal_sid_sha256",
        "expected_installer_process_image_sha256",
        "python_class_sha256",
        "python_path_sha256",
        "target_state_schema_version",
        "preflight_receipt_id",
        "preflight_receipt_raw_sha256",
        "install_authorized",
        "restart_authorized",
        "automatic_restart_allowed",
        "authority",
        "canonicalization_profile",
        "signature_domain_separator",
        "signature_algorithm",
        "signer_role",
        "signer_key_domain",
        "signer_key_id",
        "signer_public_key_sha256",
        "signature",
    ]
)

EXPECTED_BINDING_FIELDS = frozenset(
    [
        "target_policy",
        "service_name",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "store_id",
        "store_owner_sid_sha256",
        "store_directory_acl_sddl_sha256",
        "store_state_acl_sddl_sha256",
        "bundle_sha256",
        "final_version_directory_path_sha256",
        "expected_final_owner_sid_sha256",
        "expected_final_directory_acl_sddl_sha256",
        "expected_component_acl_sddl_sha256",
        "wrapper_sha256",
        "wrapper_destination_path_sha256",
        "extension_sha256",
        "extension_destination_path_sha256",
        "launcher_sha256",
        "launcher_destination_path_sha256",
        "assembly_sha256",
        "assembly_destination_path_sha256",
        "config_sha256",
        "config_destination_path_sha256",
        "service_image_path_canonical_sha256",
        "service_config_canonical_sha256",
        "expected_service_config_owner_sid_sha256",
        "expected_service_config_acl_sddl_sha256",
        "preinstall_service_image_path_canonical_sha256",
        "preinstall_service_config_canonical_sha256",
        "safety_service_config_canonical_sha256",
        "service_config_transition_plan_sha256",
        "expected_installer_principal_sid_sha256",
        "expected_installer_process_image_sha256",
        "python_class_sha256",
        "python_path_sha256",
    ]
)

SHA_FIELDS = frozenset(field for field in MANIFEST_FIELDS if field.endswith("_sha256"))
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)


class ManifestVerificationError(ValueError):
    """A stable, fail-closed manifest rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FilesystemInstallAttemptNonceRegistryV1:
    """Atomic create-only nonce binding used by the offline manifest verifier."""

    root: Path
    filesystem: FilesystemFactsAdapter
    expected_root_facts: PathSecurityFacts

    def __post_init__(self) -> None:
        root = Path(self.root).absolute()
        object.__setattr__(self, "root", root)
        self._verify_root_facts()

    def _verify_root_facts(self) -> None:
        if hashlib.sha256(str(self.root).encode("utf-8")).hexdigest() != (
            self.expected_root_facts.path_sha256
        ):
            raise ManifestVerificationError("NONCE_REGISTRY_ROOT_PATH_MISMATCH")
        try:
            actual = self.filesystem.inspect(self.root)
        except OSError as exc:
            raise ManifestVerificationError("NONCE_REGISTRY_ROOT_INVALID") from exc
        if actual != self.expected_root_facts:
            raise ManifestVerificationError("NONCE_REGISTRY_ROOT_FACTS_MISMATCH")

    def _verify_open_directory_identity(self, descriptor: int) -> tuple[int, int]:
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise ManifestVerificationError("NONCE_REGISTRY_ROOT_INVALID") from exc
        identity = (info.st_dev, info.st_ino)
        if (
            not stat.S_ISDIR(info.st_mode)
            or self.expected_root_facts.file_identity != f"{info.st_dev}:{info.st_ino}"
            or self.expected_root_facts.volume_serial
            != f"{info.st_dev & 0xFFFFFFFF:08X}"
            or self.expected_root_facts.volume_identity_sha256
            != hashlib.sha256(
                f"portable-device:{info.st_dev}".encode("ascii")
            ).hexdigest()
        ):
            raise ManifestVerificationError("NONCE_REGISTRY_OPEN_HANDLE_MISMATCH")
        return identity

    @staticmethod
    def _read_from_directory(descriptor: int, name: str) -> bytes:
        file_descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        try:
            chunks: list[bytes] = []
            while True:
                chunk = os.read(file_descriptor, 65536)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        finally:
            os.close(file_descriptor)

    def compare_and_record(
        self, *, nonce_sha256: str, immutable_inputs_sha256: str
    ) -> str:
        if (
            not isinstance(nonce_sha256, str)
            or SHA_RE.fullmatch(nonce_sha256) is None
            or not isinstance(immutable_inputs_sha256, str)
            or SHA_RE.fullmatch(immutable_inputs_sha256) is None
        ):
            raise ManifestVerificationError("NONCE_REGISTRY_BINDING_INVALID")
        record = canonical_json_bytes(
            {
                "schema_version": "windows_rpc_durable_fence_nonce_binding_v1",
                "purpose": "reject_install_attempt_nonce_reuse_with_changed_inputs",
                "attempt_nonce_sha256": nonce_sha256,
                "immutable_inputs_sha256": immutable_inputs_sha256,
            }
        )
        name = f"{nonce_sha256}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        self._verify_root_facts()
        if os.open not in os.supports_dir_fd or not getattr(os, "O_NOFOLLOW", 0):
            raise ManifestVerificationError("NONCE_REGISTRY_HANDLE_ANCHOR_UNSUPPORTED")
        try:
            directory_descriptor = os.open(
                self.root,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0),
            )
        except OSError as exc:
            raise ManifestVerificationError("NONCE_REGISTRY_ROOT_INVALID") from exc
        opened_identity = self._verify_open_directory_identity(directory_descriptor)
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    name,
                    flags | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                try:
                    existing = self._read_from_directory(directory_descriptor, name)
                except OSError as exc:
                    raise ManifestVerificationError(
                        "NONCE_REGISTRY_READ_FAILED"
                    ) from exc
                if existing != record:
                    raise ManifestVerificationError(
                        "INSTALL_ATTEMPT_NONCE_REUSE_CONFLICT"
                    )
                result = "MATCHED_EXISTING"
            except OSError as exc:
                raise ManifestVerificationError("NONCE_REGISTRY_CREATE_FAILED") from exc
            else:
                try:
                    written = 0
                    while written < len(record):
                        count = os.write(descriptor, record[written:])
                        if count <= 0:
                            raise OSError("short nonce-registry write")
                        written += count
                    os.fsync(descriptor)
                except OSError as exc:
                    raise ManifestVerificationError(
                        "NONCE_REGISTRY_WRITE_FAILED"
                    ) from exc
                finally:
                    os.close(descriptor)
                    descriptor = None
                os.fsync(directory_descriptor)
                try:
                    if self._read_from_directory(directory_descriptor, name) != record:
                        raise ManifestVerificationError(
                            "NONCE_REGISTRY_READBACK_MISMATCH"
                        )
                except OSError as exc:
                    raise ManifestVerificationError(
                        "NONCE_REGISTRY_READ_FAILED"
                    ) from exc
                result = "CREATED"
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                final_identity = self._verify_open_directory_identity(
                    directory_descriptor
                )
            finally:
                os.close(directory_descriptor)
            if final_identity != opened_identity:
                raise ManifestVerificationError("NONCE_REGISTRY_OPEN_HANDLE_CHANGED")
        self._verify_root_facts()
        return result


@dataclass(frozen=True)
class VerifiedInstallManifestV1(Mapping[str, Any]):
    value: Mapping[str, Any]
    raw_sha256: str
    install_attempt_immutable_inputs_sha256: str
    verified_at_utc: datetime
    signature_valid: bool = True
    bindings_verified: bool = True
    install_ready: bool = False
    restart_authorized: bool = False

    def __getitem__(self, key: str) -> Any:
        return self.value[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.value)

    def __len__(self) -> int:
        return len(self.value)

    @property
    def manifest_id(self) -> str:
        return str(self.value["manifest_id"])

    @property
    def manifest_core_sha256(self) -> str:
        return str(self.value["manifest_core_sha256"])

    @property
    def signer_key_id(self) -> str:
        return str(self.value["signer_key_id"])


def _parse_canonical_object(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestVerificationError("MANIFEST_SIZE_INVALID")

    def reject_float(_: str) -> None:
        raise ManifestVerificationError("MANIFEST_JSON_FLOAT_FORBIDDEN")

    def reject_constant(_: str) -> None:
        raise ManifestVerificationError("MANIFEST_JSON_NONFINITE_FORBIDDEN")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ManifestVerificationError("MANIFEST_JSON_DUPLICATE_KEY")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
        canonical = canonical_json_bytes(value)
    except ManifestVerificationError:
        raise
    except Exception as exc:
        raise ManifestVerificationError("MANIFEST_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise ManifestVerificationError("MANIFEST_NOT_OBJECT")
    if canonical != raw:
        raise ManifestVerificationError("MANIFEST_RAW_NOT_CANONICAL")
    return value


def parse_install_manifest_candidate_v1(raw: bytes) -> Mapping[str, Any]:
    """Strictly parse a candidate before its signature is trusted.

    This deliberately performs no filesystem action and is only for deriving
    native facts which are then compared by ``verify_install_manifest_v1``.
    """
    value = _parse_canonical_object(raw)
    _require_schema(value)
    return MappingProxyType(value)


def _require_schema(value: dict[str, Any]) -> None:
    if set(value) != MANIFEST_FIELDS:
        raise ManifestVerificationError("MANIFEST_SCHEMA_FIELDS_MISMATCH")
    authority = value.get("authority")
    if not isinstance(authority, dict) or set(authority) != AUTHORITY_FIELDS:
        raise ManifestVerificationError("MANIFEST_AUTHORITY_FIELDS_MISMATCH")
    if any(
        type(authority[field]) is not bool or authority[field]
        for field in AUTHORITY_FIELDS
    ):
        raise ManifestVerificationError("MANIFEST_AUTHORITY_NOT_FROZEN_NONE")

    exact: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "purpose": "authorize_exact_windows_fence_files_and_one_post_reservation_service_config_transition_without_restart",
        "publish_mode": "atomic_content_addressed_final_directory",
        "extension_version": "windows-rpc-durable-fence-foundation-v1",
        "installer_write_access_after_publish": False,
        "service_config_mutation_before_dispatch_reservation_authorized": False,
        "service_config_transition_after_dispatch_reservation_authorized": True,
        "unbound_service_config_mutation_after_observer_seal_authorized": False,
        "target_service_start_type": "DEMAND_START",
        "target_recovery_actions_disabled": True,
        "target_failure_actions_disabled": True,
        "automatic_policy_restore_authorized": False,
        "target_state_schema_version": "windows_rpc_durable_fence_state_v1",
        "install_authorized": True,
        "restart_authorized": False,
        "automatic_restart_allowed": False,
        "canonicalization_profile": "windows-foundation-canonical-json-v1",
        "signature_domain_separator": SIGNATURE_DOMAIN,
        "signature_algorithm": "Ed25519",
        "signer_role": MANIFEST_SIGNER_ROLE,
        "signer_key_domain": MANIFEST_KEY_DOMAIN,
    }
    for field, expected in exact.items():
        if type(value.get(field)) is not type(expected) or value.get(field) != expected:
            raise ManifestVerificationError("MANIFEST_CONSTANT_MISMATCH")

    if any(
        not isinstance(value[field], str) or not SHA_RE.fullmatch(value[field])
        for field in SHA_FIELDS
    ):
        raise ManifestVerificationError("MANIFEST_SCHEMA_INVALID")
    try:
        policy = parse_windows_foundation_target_policy_v1(value["target_policy"])
    except WindowsFoundationTargetContractError as exc:
        raise ManifestVerificationError("MANIFEST_TARGET_POLICY_INVALID") from exc
    if dict(policy.manifest_value()) != value["target_policy"]:
        raise ManifestVerificationError("MANIFEST_TARGET_POLICY_INVALID")
    if (
        value["service_name"] != policy.service_name
        or value["store_path_sha256"]
        != hashlib.sha256(policy.store_root_path.encode("utf-8")).hexdigest()
        or value["store_volume_serial"] != policy.store_volume_serial
        or value["store_volume_identity_sha256"] != policy.store_volume_identity_sha256
        or value["store_owner_sid_sha256"] != policy.store_owner_sid_sha256
        or value["store_directory_acl_sddl_sha256"]
        != policy.store_directory_acl_sddl_sha256
        or value["store_state_acl_sddl_sha256"] != policy.store_state_acl_sddl_sha256
        or value["expected_final_owner_sid_sha256"] != policy.final_owner_sid_sha256
        or value["expected_final_directory_acl_sddl_sha256"]
        != policy.final_directory_acl_sddl_sha256
        or value["expected_component_acl_sddl_sha256"]
        != policy.component_acl_sddl_sha256
        or value["expected_service_config_owner_sid_sha256"]
        != policy.service_config_owner_sid_sha256
        or value["expected_service_config_acl_sddl_sha256"]
        != policy.service_config_acl_sddl_sha256
    ):
        raise ManifestVerificationError("MANIFEST_TARGET_POLICY_BINDING_MISMATCH")
    patterns = {
        "manifest_id": rf"^{MANIFEST_ID_PREFIX}[0-9a-f]{{64}}$",
        "install_attempt_id": r"^windows-fence-install-[0-9a-f]{64}$",
        "preflight_receipt_id": r"^windows-fence-preflight-[0-9a-f]{64}$",
        "trusted_clock_id": r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$",
        "service_name": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "gateway_name": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "store_volume_serial": r"^[A-F0-9]{8,32}$",
        "signer_key_id": rf"^{re.escape(MANIFEST_SIGNER_ROLE)}:[A-Za-z0-9][A-Za-z0-9._:-]{{7,127}}$",
    }
    if any(
        not isinstance(value[field], str) or re.fullmatch(pattern, value[field]) is None
        for field, pattern in patterns.items()
    ):
        raise ManifestVerificationError("MANIFEST_SCHEMA_INVALID")


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise ManifestVerificationError("MANIFEST_TIME_INVALID")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ManifestVerificationError("MANIFEST_TIME_INVALID") from exc


def derive_install_attempt_id_v1(inputs: Mapping[str, object]) -> tuple[str, str]:
    """Derive the deterministic ID and immutable-input hash for a WF install."""
    if not isinstance(inputs, Mapping) or set(inputs) != INSTALL_ATTEMPT_FIELDS:
        raise ManifestVerificationError("INSTALL_ATTEMPT_INPUT_FIELDS_MISMATCH")
    sha_fields = (
        "attempt_nonce_sha256",
        "bundle_sha256",
        "store_path_sha256",
        "store_volume_identity_sha256",
        "expected_account_sha256",
        "gateway_scope_sha256",
    )
    if any(
        not isinstance(inputs[field], str) or SHA_RE.fullmatch(inputs[field]) is None
        for field in sha_fields
    ):
        raise ManifestVerificationError("INSTALL_ATTEMPT_INPUT_INVALID")
    if (
        not isinstance(inputs["service_name"], str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", inputs["service_name"])
        is None
        or not isinstance(inputs["store_volume_serial"], str)
        or re.fullmatch(r"[A-F0-9]{8,32}", inputs["store_volume_serial"]) is None
        or not isinstance(inputs["gateway_name"], str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", inputs["gateway_name"])
        is None
    ):
        raise ManifestVerificationError("INSTALL_ATTEMPT_INPUT_INVALID")
    payload = {"issue": 267, **dict(inputs)}
    payload_raw = canonical_json_bytes(payload)
    immutable_inputs_sha256 = hashlib.sha256(payload_raw).hexdigest()
    identity = hashlib.sha256(
        INSTALL_ATTEMPT_DOMAIN.encode("utf-8") + b"\x00" + payload_raw
    ).hexdigest()
    return f"windows-fence-install-{identity}", immutable_inputs_sha256


def verify_install_manifest_v1(
    raw: bytes,
    *,
    trust_pins: WindowsFoundationTrustPinsV1,
    expected_bindings: Mapping[str, object],
    install_attempt_inputs: Mapping[str, object],
    now: datetime,
) -> VerifiedInstallManifestV1:
    """Verify identity, external pin, signature, time, and all caller bindings."""
    if not isinstance(trust_pins, WindowsFoundationTrustPinsV1):
        raise ManifestVerificationError("TRUST_PINS_INVALID")
    value = dict(parse_install_manifest_candidate_v1(raw))

    if (
        not isinstance(expected_bindings, Mapping)
        or set(expected_bindings) != EXPECTED_BINDING_FIELDS
    ):
        raise ManifestVerificationError("EXPECTED_BINDINGS_FIELDS_MISMATCH")
    if any(
        value[field] != expected_bindings[field]
        or type(value[field]) is not type(expected_bindings[field])
        for field in EXPECTED_BINDING_FIELDS
    ):
        raise ManifestVerificationError("MANIFEST_BINDING_MISMATCH")

    expected_attempt_id, immutable_inputs_sha256 = derive_install_attempt_id_v1(
        install_attempt_inputs
    )
    for field in (
        "attempt_nonce_sha256",
        "bundle_sha256",
        "service_name",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "expected_account_sha256",
        "gateway_name",
        "gateway_scope_sha256",
    ):
        if value[field] != install_attempt_inputs[field]:
            raise ManifestVerificationError("INSTALL_ATTEMPT_MANIFEST_BINDING_MISMATCH")
    if value["install_attempt_id"] != expected_attempt_id:
        raise ManifestVerificationError("INSTALL_ATTEMPT_ID_MISMATCH")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ManifestVerificationError("TRUSTED_CLOCK_INVALID")
    now_utc = now.astimezone(timezone.utc)
    issued = _parse_utc(value["issued_at_utc"])
    expires = _parse_utc(value["expires_at_utc"])
    if not issued <= now_utc < expires:
        raise ManifestVerificationError("MANIFEST_OUTSIDE_VALIDITY_WINDOW")

    core_payload = {
        key: item
        for key, item in value.items()
        if key not in {"manifest_id", "manifest_core_sha256", "signature"}
    }
    core_sha256 = hashlib.sha256(canonical_json_bytes(core_payload)).hexdigest()
    if value["manifest_core_sha256"] != core_sha256:
        raise ManifestVerificationError("MANIFEST_CORE_SHA256_MISMATCH")
    if value["manifest_id"] != f"{MANIFEST_ID_PREFIX}{core_sha256}":
        raise ManifestVerificationError("MANIFEST_ID_MISMATCH")

    pin = trust_pins.manifest
    if (
        value["signer_role"] != pin.role
        or value["signer_key_domain"] != pin.key_domain
        or value["signer_key_id"] != pin.key_id
        or value["signer_public_key_sha256"] != pin.public_key_sha256
    ):
        raise ManifestVerificationError("MANIFEST_EXTERNAL_PIN_MISMATCH")
    signature_text = value["signature"]
    if (
        not isinstance(signature_text, str)
        or re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature_text) is None
    ):
        raise ManifestVerificationError("MANIFEST_SIGNATURE_ENCODING_INVALID")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ManifestVerificationError("MANIFEST_SIGNATURE_ENCODING_INVALID") from exc
    if (
        len(signature) != 64
        or base64.b64encode(signature).decode("ascii") != signature_text
    ):
        raise ManifestVerificationError("MANIFEST_SIGNATURE_ENCODING_INVALID")
    envelope = {key: item for key, item in value.items() if key != "signature"}
    message = (
        SIGNATURE_DOMAIN.encode("utf-8") + b"\x00" + canonical_json_bytes(envelope)
    )
    try:
        Ed25519PublicKey.from_public_bytes(pin.public_key_raw).verify(
            signature, message
        )
    except (InvalidSignature, ValueError) as exc:
        raise ManifestVerificationError("MANIFEST_SIGNATURE_INVALID") from exc

    frozen_value = dict(value)
    frozen_value["authority"] = MappingProxyType(dict(value["authority"]))
    return VerifiedInstallManifestV1(
        value=MappingProxyType(frozen_value),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        install_attempt_immutable_inputs_sha256=immutable_inputs_sha256,
        verified_at_utc=now_utc,
    )


def verify_and_reserve_install_manifest_v1(
    raw: bytes,
    *,
    trust_pins: WindowsFoundationTrustPinsV1,
    expected_bindings: Mapping[str, object],
    install_attempt_inputs: Mapping[str, object],
    nonce_registry: FilesystemInstallAttemptNonceRegistryV1,
    now: datetime,
) -> VerifiedInstallManifestV1:
    """Reverify raw bytes and atomically reserve their nonce on the offline signer."""
    verified = verify_install_manifest_v1(
        raw,
        trust_pins=trust_pins,
        expected_bindings=expected_bindings,
        install_attempt_inputs=install_attempt_inputs,
        now=now,
    )
    if not isinstance(nonce_registry, FilesystemInstallAttemptNonceRegistryV1):
        raise ManifestVerificationError("INSTALL_ATTEMPT_NONCE_REGISTRY_INVALID")
    if nonce_registry.expected_root_facts != trust_pins.nonce_registry_root_facts:
        raise ManifestVerificationError("INSTALL_ATTEMPT_NONCE_REGISTRY_PIN_MISMATCH")
    nonce_registry.compare_and_record(
        nonce_sha256=verified["attempt_nonce_sha256"],
        immutable_inputs_sha256=verified.install_attempt_immutable_inputs_sha256,
    )
    return verified


__all__ = [
    "EXPECTED_BINDING_FIELDS",
    "INSTALL_ATTEMPT_DOMAIN",
    "INSTALL_ATTEMPT_FIELDS",
    "MANIFEST_ID_PREFIX",
    "SIGNATURE_DOMAIN",
    "FilesystemInstallAttemptNonceRegistryV1",
    "ManifestVerificationError",
    "VerifiedInstallManifestV1",
    "derive_install_attempt_id_v1",
    "parse_install_manifest_candidate_v1",
    "verify_and_reserve_install_manifest_v1",
    "verify_install_manifest_v1",
]
