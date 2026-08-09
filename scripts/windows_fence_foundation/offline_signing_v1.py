"""Offline-only, public-verifiable signing closure for the Windows fence.

Private key material is accepted only from a pre-opened read-only file
descriptor.  This module deliberately has no network, container, Windows SCM,
or runtime-control dependency.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

try:  # Windows has no portable way to prove an inherited CRT FD is read-only.
    import fcntl
except ImportError:  # pragma: no cover - fail-closed branch exercised on Windows CI.
    fcntl = None  # type: ignore[assignment]

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from .contracts import AUTHORITY_FIELDS, StoreContractError, canonical_json_bytes
from .trust_pins_v1 import (
    MANIFEST_KEY_DOMAIN,
    OBSERVER_KEY_DOMAIN,
    RESTART_KEY_DOMAIN,
    FoundationPublicKeyPin,
)

MAX_ARTIFACT_BYTES = 512 * 1024
MAX_PRIVATE_KEY_BYTES = 16 * 1024
_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "docs" / "schemas"
CANONICALIZATION_PROFILE = "windows-foundation-canonical-json-v1"
MANIFEST_DOMAIN = "vnpy.issue267.windows-foundation.install-manifest.v1"
RESTART_DOMAIN = "vnpy.issue267.windows-foundation.restart-authorization.v1"
OBSERVER_DOMAINS = frozenset(
    {
        "vnpy.issue267.windows-foundation.zero-order-preflight.v1",
        "vnpy.issue267.windows-foundation.publish-receipt.v1",
        "vnpy.issue267.windows-foundation.scm-dispatch-evidence.v1",
        "vnpy.issue267.windows-foundation.startup-receipt.v1",
        "vnpy.issue267.windows-foundation.attestation.v1",
    }
)


class OfflineSigningError(ValueError):
    """Stable fail-closed offline signing rejection."""


@dataclass(frozen=True)
class VerifiedPublicArtifactV1:
    value: Mapping[str, Any]
    raw_sha256: str


def _strict_object(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise OfflineSigningError("SIGNING_ARTIFACT_SIZE_INVALID")

    def duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OfflineSigningError("SIGNING_ARTIFACT_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=duplicate_reject,
            parse_float=lambda _value: (_ for _ in ()).throw(
                OfflineSigningError("SIGNING_ARTIFACT_FLOAT_FORBIDDEN")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                OfflineSigningError("SIGNING_ARTIFACT_NONFINITE_FORBIDDEN")
            ),
        )
        if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
            raise OfflineSigningError("SIGNING_ARTIFACT_NOT_CANONICAL")
    except OfflineSigningError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, StoreContractError) as exc:
        raise OfflineSigningError("SIGNING_ARTIFACT_JSON_INVALID") from exc
    return value


def _validate_schema(value: Mapping[str, Any], *, signed: bool) -> None:
    schema_version = value.get("schema_version")
    filenames = {
        "windows_rpc_durable_fence_install_manifest_v1": "windows-rpc-durable-fence-install-manifest-v1.schema.json",
        "windows_rpc_durable_fence_zero_order_preflight_v1": "windows-rpc-durable-fence-zero-order-preflight-v1.schema.json",
        "windows_rpc_durable_fence_restart_authorization_v1": "windows-rpc-durable-fence-restart-authorization-v1.schema.json",
        "windows_rpc_durable_fence_publish_receipt_v1": "windows-rpc-durable-fence-publish-receipt-v1.schema.json",
        "windows_rpc_durable_fence_scm_dispatch_evidence_v1": "windows-rpc-durable-fence-scm-dispatch-evidence-v1.schema.json",
        "windows_rpc_durable_fence_startup_receipt_v1": "windows-rpc-durable-fence-startup-receipt-v1.schema.json",
        "windows_rpc_durable_fence_foundation_attestation_v1": "windows-rpc-durable-fence-foundation-attestation-v1.schema.json",
    }
    filename = filenames.get(schema_version)
    if filename is None:
        raise OfflineSigningError("SIGNING_ARTIFACT_SCHEMA_UNSUPPORTED")
    candidate = dict(value)
    if not signed:
        candidate["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    try:
        schema = json.loads((_SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(candidate)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise OfflineSigningError("SIGNING_ARTIFACT_SCHEMA_INVALID") from exc


def read_canonical_artifact_v1(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise OfflineSigningError("SIGNING_ARTIFACT_UNREADABLE") from exc
    return raw, _strict_object(raw)


def read_ed25519_private_key_from_readonly_fd_v1(descriptor: int) -> Ed25519PrivateKey:
    """Read one offline key from an inherited read-only regular-file FD only."""
    if (
        isinstance(descriptor, bool)
        or not isinstance(descriptor, int)
        or descriptor < 3
    ):
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FD_INVALID")
    if fcntl is None:
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FD_ACCESS_UNVERIFIABLE")
    try:
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        before = os.fstat(descriptor)
    except OSError as exc:
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FD_UNAVAILABLE") from exc
    if (
        flags & os.O_ACCMODE != os.O_RDONLY
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_PRIVATE_KEY_BYTES
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FD_SECURITY_INVALID")
    try:
        duplicate = os.dup(descriptor)
        try:
            os.lseek(duplicate, 0, os.SEEK_SET)
            raw = os.read(duplicate, before.st_size + 1)
        finally:
            os.close(duplicate)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FD_READ_FAILED") from exc
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(raw) != before.st_size:
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FD_CHANGED")
    try:
        decoded = base64.b64decode(raw.strip(), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FORMAT_INVALID") from exc
    if len(decoded) != 32:
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_FORMAT_INVALID")
    return Ed25519PrivateKey.from_private_bytes(decoded)


def _signature_fields(value: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    schema = value.get("schema_version")
    if schema == "windows_rpc_durable_fence_foundation_attestation_v1":
        return (
            str(value.get("attester_role")),
            str(value.get("attester_key_domain")),
            str(value.get("attester_key_id")),
            str(value.get("attester_public_key_sha256")),
            "attestation",
        )
    if schema == "windows_rpc_durable_fence_restart_authorization_v1":
        return (
            str(value.get("restart_authorizer_role")),
            str(value.get("restart_authorizer_key_domain")),
            str(value.get("signer_key_id")),
            str(value.get("signer_public_key_sha256")),
            "authorization",
        )
    return (
        str(value.get("signer_role")),
        str(value.get("signer_key_domain")),
        str(value.get("signer_key_id")),
        str(value.get("signer_public_key_sha256")),
        "manifest"
        if schema == "windows_rpc_durable_fence_install_manifest_v1"
        else "receipt_or_evidence",
    )


def _expected_id(prefix: str, core: str) -> str:
    return prefix + core


def _core_fields(value: Mapping[str, Any]) -> tuple[str, str, str]:
    schema = str(value.get("schema_version"))
    if schema == "windows_rpc_durable_fence_install_manifest_v1":
        return "manifest_id", "manifest_core_sha256", "windows-fence-install-manifest-"
    if schema == "windows_rpc_durable_fence_restart_authorization_v1":
        return (
            "authorization_id",
            "authorization_core_sha256",
            "windows-fence-restart-authorization-",
        )
    if schema == "windows_rpc_durable_fence_foundation_attestation_v1":
        return (
            "attestation_id",
            "attestation_core_sha256",
            "windows-fence-foundation-attestation-",
        )
    prefixes = {
        "windows_rpc_durable_fence_zero_order_preflight_v1": "windows-fence-preflight-",
        "windows_rpc_durable_fence_publish_receipt_v1": "windows-fence-publish-receipt-",
        "windows_rpc_durable_fence_startup_receipt_v1": "windows-fence-startup-receipt-",
        "windows_rpc_durable_fence_scm_dispatch_evidence_v1": "windows-fence-scm-dispatch-evidence-",
    }
    if schema in prefixes:
        return (
            "evidence_id" if schema.endswith("evidence_v1") else "receipt_id",
            "evidence_core_sha256"
            if schema.endswith("evidence_v1")
            else "receipt_core_sha256",
            prefixes[schema],
        )
    raise OfflineSigningError("SIGNING_ARTIFACT_SCHEMA_UNSUPPORTED")


def _verify_identity_and_frozen_facts(value: Mapping[str, Any]) -> None:
    _validate_schema(value, signed="signature" in value)
    id_field, core_field, prefix = _core_fields(value)
    if not isinstance(value.get("signature_domain_separator"), str):
        raise OfflineSigningError("SIGNING_DOMAIN_MISSING")
    core = hashlib.sha256(
        canonical_json_bytes(
            {
                key: item
                for key, item in value.items()
                if key not in {id_field, core_field, "signature"}
            }
        )
    ).hexdigest()
    if value.get(core_field) != core or value.get(id_field) != _expected_id(
        prefix, core
    ):
        raise OfflineSigningError("SIGNING_ARTIFACT_CORE_OR_ID_MISMATCH")
    authority = value.get("authority")
    if (
        not isinstance(authority, dict)
        or set(authority) != AUTHORITY_FIELDS
        or any(type(item) is not bool or item for item in authority.values())
    ):
        raise OfflineSigningError("SIGNING_AUTHORITY_NOT_FROZEN")
    for key, expected in (
        ("pending_send_outcomes", 0),
        ("active_orders", []),
        ("web_trade_enabled", False),
        ("old_runtime_frozen", True),
        ("execution_authority_revoked", True),
        ("zero_order_preflight_verified", True),
    ):
        if key in value and value[key] != expected:
            raise OfflineSigningError("SIGNING_PREFLIGHT_NOT_ZERO_OR_FRESH")


def _assert_pin(value: Mapping[str, Any], pin: FoundationPublicKeyPin) -> None:
    role, domain, key_id, public_sha, _kind = _signature_fields(value)
    if (
        role != pin.role
        or domain != pin.key_domain
        or key_id != pin.key_id
        or public_sha != pin.public_key_sha256
    ):
        raise OfflineSigningError("SIGNING_PUBLIC_PIN_MISMATCH")
    separator = value.get("signature_domain_separator")
    allowed = {
        MANIFEST_KEY_DOMAIN: {MANIFEST_DOMAIN},
        OBSERVER_KEY_DOMAIN: OBSERVER_DOMAINS,
        RESTART_KEY_DOMAIN: {RESTART_DOMAIN},
    }.get(pin.key_domain)
    if (
        separator not in allowed
        or value.get("canonicalization_profile") != CANONICALIZATION_PROFILE
        or value.get("signature_algorithm") != "Ed25519"
    ):
        raise OfflineSigningError("SIGNING_DOMAIN_MISMATCH")


def _require_preflight_source_facts(
    value: Mapping[str, Any],
    *,
    execution_facts_raw: bytes | None,
    snapshot_raw: bytes | None,
) -> None:
    """Bind zero state to the original canonical facts, never summary fields alone."""
    if (
        value.get("schema_version")
        != "windows_rpc_durable_fence_zero_order_preflight_v1"
    ):
        return
    if execution_facts_raw is None or snapshot_raw is None:
        raise OfflineSigningError("SIGNING_PREFLIGHT_SOURCE_FACTS_REQUIRED")
    execution = _strict_object(execution_facts_raw)
    snapshot = _strict_object(snapshot_raw)
    if value.get("execution_facts_canonical_sha256") != _sha(
        execution_facts_raw
    ) or value.get("snapshot_raw_sha256") != _sha(snapshot_raw):
        raise OfflineSigningError("SIGNING_PREFLIGHT_SOURCE_FACTS_HASH_MISMATCH")
    for facts in (execution, snapshot):
        if (
            facts.get("pending_send_outcomes") != 0
            or facts.get("active_orders") != []
            or facts.get("positions") != []
        ):
            raise OfflineSigningError("SIGNING_PREFLIGHT_NOT_ZERO_OR_FRESH")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sign_artifact_with_fd_v1(
    draft: Mapping[str, Any],
    *,
    private_key_fd: int,
    pin: FoundationPublicKeyPin,
    observer_pin: FoundationPublicKeyPin | None = None,
    fresh_preflight_raw: bytes | None = None,
    now: datetime | None = None,
    execution_facts_raw: bytes | None = None,
    snapshot_raw: bytes | None = None,
) -> dict[str, Any]:
    if not isinstance(draft, Mapping) or "signature" in draft:
        raise OfflineSigningError("SIGNING_UNSIGNED_DRAFT_REQUIRED")
    value = dict(draft)
    _verify_identity_and_frozen_facts(value)
    _assert_pin(value, pin)
    _require_preflight_source_facts(
        value, execution_facts_raw=execution_facts_raw, snapshot_raw=snapshot_raw
    )
    if value.get("schema_version") in {
        "windows_rpc_durable_fence_install_manifest_v1",
        "windows_rpc_durable_fence_restart_authorization_v1",
    }:
        if observer_pin is None or fresh_preflight_raw is None or now is None:
            raise OfflineSigningError("SIGNING_FRESH_PREFLIGHT_REQUIRED")
        preflight = require_fresh_zero_preflight_v1(
            fresh_preflight_raw, pin=observer_pin, now=now
        )
        if value.get("preflight_receipt_raw_sha256") != preflight.raw_sha256:
            raise OfflineSigningError("SIGNING_PREFLIGHT_BINDING_MISMATCH")
    private = read_ed25519_private_key_from_readonly_fd_v1(private_key_fd)
    actual = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if not hmac.compare_digest(
        hashlib.sha256(actual).hexdigest(), pin.public_key_sha256
    ):
        raise OfflineSigningError("SIGNING_PRIVATE_KEY_PUBLIC_PIN_MISMATCH")
    signature = private.sign(
        str(value["signature_domain_separator"]).encode()
        + b"\x00"
        + canonical_json_bytes(value)
    )
    return {**value, "signature": base64.b64encode(signature).decode("ascii")}


def verify_public_artifact_v1(
    raw: bytes, *, pin: FoundationPublicKeyPin
) -> VerifiedPublicArtifactV1:
    value = _strict_object(raw)
    if "signature" not in value:
        raise OfflineSigningError("SIGNING_SIGNATURE_MISSING")
    _verify_identity_and_frozen_facts(value)
    _assert_pin(value, pin)
    signature_text = value["signature"]
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise OfflineSigningError("SIGNING_SIGNATURE_ENCODING_INVALID") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode() != signature_text:
        raise OfflineSigningError("SIGNING_SIGNATURE_ENCODING_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(pin.public_key_raw).verify(
            signature,
            str(value["signature_domain_separator"]).encode()
            + b"\x00"
            + canonical_json_bytes(
                {key: item for key, item in value.items() if key != "signature"}
            ),
        )
    except (InvalidSignature, ValueError) as exc:
        raise OfflineSigningError("SIGNING_SIGNATURE_INVALID") from exc
    return VerifiedPublicArtifactV1(
        value=value, raw_sha256=hashlib.sha256(raw).hexdigest()
    )


def require_fresh_zero_preflight_v1(
    raw: bytes, *, pin: FoundationPublicKeyPin, now: datetime
) -> VerifiedPublicArtifactV1:
    verified = verify_public_artifact_v1(raw, pin=pin)
    value = verified.value
    if (
        value.get("schema_version")
        != "windows_rpc_durable_fence_zero_order_preflight_v1"
    ):
        raise OfflineSigningError("SIGNING_PREFLIGHT_SCHEMA_REQUIRED")
    try:
        observed = datetime.fromisoformat(
            str(value["observed_at_utc"]).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            str(value["challenge_expires_at_utc"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise OfflineSigningError("SIGNING_PREFLIGHT_TIME_INVALID") from exc
    if (
        now.tzinfo is None
        or now.utcoffset() is None
        or observed > now
        or now >= expires
        or (now - observed).total_seconds() > 30
    ):
        raise OfflineSigningError("SIGNING_PREFLIGHT_NOT_ZERO_OR_FRESH")
    return verified


def write_canonical_create_only_v1(path: Path, payload: Mapping[str, Any]) -> bytes:
    output = Path(path)
    if not output.is_absolute():
        output = Path.cwd() / output
    parent = output.parent.resolve(strict=True)
    if (
        parent != output.parent
        or not parent.is_dir()
        or parent.is_symlink()
        or output.name in {"", ".", ".."}
    ):
        raise OfflineSigningError("SIGNING_OUTPUT_PARENT_UNSAFE")
    raw = canonical_json_bytes(dict(payload))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.fstat(directory)
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077
            ):
                raise OfflineSigningError("SIGNING_OUTPUT_PARENT_UNSAFE")
            descriptor = os.open(output.name, flags, 0o600, dir_fd=directory)
            try:
                os.write(descriptor, raw)
                os.fsync(descriptor)
                created = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            observed_info = os.stat(
                output.name, dir_fd=directory, follow_symlinks=False
            )
            after = os.fstat(directory)
            if (
                (created.st_dev, created.st_ino, created.st_size)
                != (observed_info.st_dev, observed_info.st_ino, observed_info.st_size)
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or observed_info.st_uid != os.geteuid()
                or stat.S_IMODE(observed_info.st_mode) & 0o077
                or not stat.S_ISREG(observed_info.st_mode)
            ):
                raise OfflineSigningError("SIGNING_OUTPUT_READBACK_MISMATCH")
            read_fd = os.open(
                output.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            try:
                observed = os.read(read_fd, len(raw) + 1)
            finally:
                os.close(read_fd)
            if observed != raw or _strict_object(observed) != dict(payload):
                raise OfflineSigningError("SIGNING_OUTPUT_READBACK_MISMATCH")
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as exc:
        raise OfflineSigningError("SIGNING_OUTPUT_EXISTS") from exc
    except OSError as exc:
        raise OfflineSigningError("SIGNING_OUTPUT_WRITE_FAILED") from exc
    return raw


def write_binary_create_only_v1(path: Path, raw: bytes) -> str:
    """Publish exact opaque bytes with the same retained-dirfd safety contract."""
    if type(raw) is not bytes or not raw:
        raise OfflineSigningError("SIGNING_BINARY_OUTPUT_INVALID")
    output = Path(path)
    if not output.is_absolute():
        output = Path.cwd() / output
    parent = output.parent.resolve(strict=True)
    if parent != output.parent or output.name in {"", ".", ".."}:
        raise OfflineSigningError("SIGNING_OUTPUT_PARENT_UNSAFE")
    directory = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(directory)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise OfflineSigningError("SIGNING_OUTPUT_PARENT_UNSAFE")
        descriptor = os.open(
            output.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
            identity = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        observed = os.stat(output.name, dir_fd=directory, follow_symlinks=False)
        read_fd = os.open(
            output.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory
        )
        try:
            readback = os.read(read_fd, len(raw) + 1)
        finally:
            os.close(read_fd)
        if (identity.st_dev, identity.st_ino, identity.st_size) != (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
        ) or readback != raw:
            raise OfflineSigningError("SIGNING_OUTPUT_READBACK_MISMATCH")
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(raw).hexdigest()


def write_audit_create_only_v1(
    path: Path, *, artifact_raw: bytes, action: str
) -> bytes:
    if not isinstance(action, str) or not action:
        raise OfflineSigningError("SIGNING_AUDIT_ACTION_INVALID")
    payload = {
        "schema_version": "windows_rpc_durable_fence_offline_signing_audit_v1",
        "purpose": "record_create_only_offline_signing_output_without_private_material",
        "action": action,
        "artifact_raw_sha256": hashlib.sha256(artifact_raw).hexdigest(),
        "artifact_size_bytes": len(artifact_raw),
    }
    return write_canonical_create_only_v1(path, payload)


_RESERVATION_KINDS = frozenset(
    {
        "preflight_challenge",
        "preflight_replay_guard",
        "manifest_attempt_nonce",
        "manifest_install_attempt",
        "restart_dispatch",
        "restart_authorization",
    }
)


def consume_replay_token_create_only_v1(
    directory: Path,
    *,
    token_sha256: str,
    reservation_kind: str,
    artifact: Mapping[str, Any],
) -> bytes:
    """Create the durable reservation receipt before signing or publication.

    The receipt is the reservation itself, not an audit copy.  It contains only
    public draft identity facts, so it never requires or exposes private key
    material.  Its immutable binding makes a ledger receipt unusable for a
    different signed artifact during final closure verification.
    """
    if (
        not isinstance(token_sha256, str)
        or len(token_sha256) != 64
        or any(c not in "0123456789abcdef" for c in token_sha256)
    ):
        raise OfflineSigningError("SIGNING_REPLAY_TOKEN_INVALID")
    if reservation_kind not in _RESERVATION_KINDS:
        raise OfflineSigningError("SIGNING_RESERVATION_KIND_INVALID")
    if not isinstance(artifact, Mapping):
        raise OfflineSigningError("SIGNING_RESERVATION_ARTIFACT_INVALID")
    schema = artifact.get("schema_version")
    try:
        id_field, core_field, _prefix = _core_fields(artifact)
        artifact_id = artifact[id_field]
        artifact_core = artifact[core_field]
        domain = artifact["signature_domain_separator"]
    except (KeyError, OfflineSigningError) as exc:
        raise OfflineSigningError("SIGNING_RESERVATION_ARTIFACT_INVALID") from exc
    if schema not in {
        "windows_rpc_durable_fence_zero_order_preflight_v1",
        "windows_rpc_durable_fence_install_manifest_v1",
        "windows_rpc_durable_fence_restart_authorization_v1",
    } or not all(
        isinstance(value, str) for value in (artifact_id, artifact_core, domain)
    ):
        raise OfflineSigningError("SIGNING_RESERVATION_ARTIFACT_INVALID")
    payload = {
        "schema_version": "windows_rpc_durable_fence_signing_reservation_receipt_v1",
        "purpose": "record_create_only_offline_signing_reservation_without_private_material",
        "reservation_kind": reservation_kind,
        "token_sha256": token_sha256,
        "reserved_artifact_schema_version": schema,
        "reserved_artifact_id": artifact_id,
        "reserved_artifact_core_sha256": artifact_core,
        "reserved_signature_domain_separator": domain,
    }
    # A public digest is safe as a filename; output bytes are the authoritative
    # receipt consumed by closure verification, rather than a secondary audit.
    return write_canonical_create_only_v1(
        Path(directory) / f"{reservation_kind}-{token_sha256}.reservation.json", payload
    )
