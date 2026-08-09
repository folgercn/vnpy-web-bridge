"""Local-only Windows credential descriptor and DPAPI blob boundary.

This module deliberately never accepts credentials from a bundle, command line,
environment, or ordinary service configuration.  The bundle can bind only this
descriptor's path, bytes hash, owner and protected DACL hash.  The descriptor
then names a distinct operator-created DPAPI blob which is checked again before
it is decrypted in the LocalSystem service process.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .contracts import (
    StoreContractError,
    canonical_json_bytes,
    canonical_local_windows_path,
)
from .win32_fs import FilesystemFactsAdapter, PathSecurityFacts

_SHA = re.compile(r"^[0-9a-f]{64}$")
_GATEWAY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DESCRIPTOR_SCHEMA_VERSION = "windows_rpc_credential_descriptor_v1"
DESCRIPTOR_PURPOSE = "bind_local_operator_dpapi_credential_blob_without_export"
_CRYPTPROTECT_LOCAL_MACHINE = 0x4


class CredentialConfigError(ValueError):
    """Stable fail-closed local credential boundary rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CredentialDescriptorBindingV1:
    """The only credential-related fields allowed in public bundle config."""

    path: str
    path_sha256: str
    raw_sha256: str
    owner_sid_sha256: str
    acl_sddl_sha256: str

    def __post_init__(self) -> None:
        try:
            path = canonical_local_windows_path(self.path)
        except StoreContractError:
            raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_PATH_INVALID") from None
        if path != self.path or self.path_sha256 != _digest(path.encode("utf-8")):
            raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_PATH_INVALID")
        for value in (
            self.path_sha256,
            self.raw_sha256,
            self.owner_sid_sha256,
            self.acl_sddl_sha256,
        ):
            if not isinstance(value, str) or _SHA.fullmatch(value) is None:
                raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_BINDING_INVALID")


@dataclass(frozen=True)
class LocalCredentialDescriptorV1:
    blob_path: str
    blob_path_sha256: str
    blob_raw_sha256: str
    blob_owner_sid_sha256: str
    blob_acl_sddl_sha256: str
    gateway_name: str


@dataclass(frozen=True)
class InstallerStoreBootstrapV1:
    store_root: str
    store_expectation: Mapping[str, Any]
    owner_sid: str
    directory_acl_sddl: str


class CredentialBlobReaderV1(Protocol):
    def decrypt(self, raw: bytes) -> bytes: ...


class CredentialBlobWriterV1(Protocol):
    def write_create_only(self, *, path: str, raw: bytes) -> None: ...


class WindowsSecureCredentialBlobWriterV1:
    """Create one machine-DPAPI blob with a pinned parent and protected DACL.

    This is intentionally an operator-side writer, not a general filesystem
    helper.  It verifies the parent through the Windows opened-handle facts
    adapter before *and* after the create-only write, then reads the new blob
    through an opened handle before returning.  No existing blob is replaced.
    """

    def __init__(
        self,
        *,
        parent_path: str,
        parent_owner_sid_sha256: str,
        parent_acl_sddl_sha256: str,
        blob_owner_sid: str,
        blob_acl_sddl: str,
    ) -> None:
        try:
            self._parent_path = canonical_local_windows_path(parent_path)
        except StoreContractError:
            raise CredentialConfigError("CREDENTIAL_BLOB_PARENT_INVALID") from None
        for value in (parent_owner_sid_sha256, parent_acl_sddl_sha256):
            if not isinstance(value, str) or _SHA.fullmatch(value) is None:
                raise CredentialConfigError("CREDENTIAL_BLOB_PARENT_INVALID")
        if not isinstance(blob_owner_sid, str) or not isinstance(blob_acl_sddl, str):
            raise CredentialConfigError("CREDENTIAL_BLOB_ACL_INVALID")
        self._parent_owner = parent_owner_sid_sha256
        self._parent_acl = parent_acl_sddl_sha256
        self._blob_owner = _digest(blob_owner_sid.encode("utf-8"))
        self._blob_owner_sid = blob_owner_sid
        self._blob_acl = _digest(blob_acl_sddl.encode("utf-8"))
        self._blob_sddl = blob_acl_sddl

    def _secure_parent(self, filesystem: FilesystemFactsAdapter) -> PathSecurityFacts:
        try:
            facts = filesystem.inspect(Path(self._parent_path))
        except OSError:
            raise CredentialConfigError("CREDENTIAL_BLOB_PARENT_READ_FAILED") from None
        if (
            not facts.directory
            or facts.reparse_point
            or not facts.parent_chain_reparse_free
            or facts.hardlink_count != 1
            or facts.alternate_data_streams
            or not facts.dacl_protected
            or facts.inherited_ace_count
            or facts.unsafe_write_principals
            or facts.owner_sid_sha256 != self._parent_owner
            or facts.acl_sddl_sha256 != self._parent_acl
        ):
            raise CredentialConfigError("CREDENTIAL_BLOB_PARENT_SECURITY_INVALID")
        return facts

    def _require_sddl_owner(self) -> None:
        try:
            import win32security  # type: ignore[import-not-found]

            descriptor = (
                win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    self._blob_sddl, 1
                )
            )
            owner = win32security.ConvertSidToStringSid(
                descriptor.GetSecurityDescriptorOwner()
            )
        except Exception:  # noqa: BLE001 - security provider errors are redacted
            raise CredentialConfigError("CREDENTIAL_BLOB_ACL_INVALID") from None
        if (
            owner != self._blob_owner_sid
            or _digest(owner.encode("utf-8")) != self._blob_owner
        ):
            raise CredentialConfigError("CREDENTIAL_BLOB_OWNER_MISMATCH")

    def write_create_only(self, *, path: str, raw: bytes) -> None:
        if os.name != "nt":
            raise CredentialConfigError("CREDENTIAL_DPAPI_WINDOWS_REQUIRED")
        try:
            canonical_path = canonical_local_windows_path(path)
        except StoreContractError:
            raise CredentialConfigError("CREDENTIAL_BLOB_PATH_INVALID") from None
        blob = Path(canonical_path)
        if str(blob.parent) != self._parent_path or not raw:
            raise CredentialConfigError("CREDENTIAL_BLOB_PATH_INVALID")
        try:
            from .win32_fs import WindowsFilesystemFactsAdapter

            filesystem = WindowsFilesystemFactsAdapter()
            self._require_sddl_owner()
            parent_before = self._secure_parent(filesystem)
            item = filesystem.write_file_create_only(
                blob, raw=raw, protected_sddl=self._blob_sddl
            )
            self._secure_parent(filesystem)
        except CredentialConfigError:
            raise
        except FileExistsError:
            raise CredentialConfigError(
                "CREDENTIAL_BLOB_CREATE_ONLY_CONFLICT"
            ) from None
        except OSError:
            raise CredentialConfigError("CREDENTIAL_BLOB_WRITE_FAILED") from None
        _secure_regular_file(
            item.facts,
            owner=self._blob_owner,
            acl=self._blob_acl,
            code="CREDENTIAL_BLOB_SECURITY_INVALID",
        )
        if (
            item.facts.path_sha256 != _digest(canonical_path.encode("utf-8"))
            or _digest(item.raw) != _digest(raw)
            or parent_before.file_identity
            != self._secure_parent(filesystem).file_identity
        ):
            raise CredentialConfigError("CREDENTIAL_BLOB_POST_WRITE_READBACK_MISMATCH")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _secure_regular_file(
    facts: PathSecurityFacts, *, owner: str, acl: str, code: str
) -> None:
    if (
        not facts.regular_file
        or facts.directory
        or facts.reparse_point
        or not facts.parent_chain_reparse_free
        or facts.hardlink_count != 1
        or facts.alternate_data_streams
        or not facts.dacl_protected
        or facts.inherited_ace_count
        or facts.unsafe_write_principals
        or facts.owner_sid_sha256 != owner
        or facts.acl_sddl_sha256 != acl
    ):
        raise CredentialConfigError(code)


def _parse_descriptor(raw: bytes) -> LocalCredentialDescriptorV1:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_JSON_INVALID") from None
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_NOT_CANONICAL")
    expected = {
        "schema_version",
        "purpose",
        "blob_path",
        "blob_path_sha256",
        "blob_raw_sha256",
        "blob_owner_sid_sha256",
        "blob_acl_sddl_sha256",
        "gateway_name",
    }
    if (
        set(value) != expected
        or value["schema_version"] != DESCRIPTOR_SCHEMA_VERSION
        or value["purpose"] != DESCRIPTOR_PURPOSE
    ):
        raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_FIELDS_INVALID")
    try:
        blob_path = canonical_local_windows_path(value["blob_path"])
    except StoreContractError:
        raise CredentialConfigError("CREDENTIAL_BLOB_PATH_INVALID") from None
    if blob_path != value["blob_path"] or value["blob_path_sha256"] != _digest(
        blob_path.encode("utf-8")
    ):
        raise CredentialConfigError("CREDENTIAL_BLOB_PATH_INVALID")
    if (
        not isinstance(value["gateway_name"], str)
        or _GATEWAY.fullmatch(value["gateway_name"]) is None
    ):
        raise CredentialConfigError("CREDENTIAL_GATEWAY_INVALID")
    for field in (
        "blob_path_sha256",
        "blob_raw_sha256",
        "blob_owner_sid_sha256",
        "blob_acl_sddl_sha256",
    ):
        if not isinstance(value[field], str) or _SHA.fullmatch(value[field]) is None:
            raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_FIELDS_INVALID")
    return LocalCredentialDescriptorV1(
        blob_path=blob_path,
        blob_path_sha256=value["blob_path_sha256"],
        blob_raw_sha256=value["blob_raw_sha256"],
        blob_owner_sid_sha256=value["blob_owner_sid_sha256"],
        blob_acl_sddl_sha256=value["blob_acl_sddl_sha256"],
        gateway_name=value["gateway_name"],
    )


def load_local_credential_descriptor_v1(
    binding: CredentialDescriptorBindingV1,
    *,
    filesystem: FilesystemFactsAdapter,
) -> LocalCredentialDescriptorV1:
    """Read exactly one externally-provisioned descriptor through secure facts."""
    path = Path(binding.path)
    try:
        item = filesystem.read_file(path)
    except OSError:
        raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_READ_FAILED") from None
    _secure_regular_file(
        item.facts,
        owner=binding.owner_sid_sha256,
        acl=binding.acl_sddl_sha256,
        code="CREDENTIAL_DESCRIPTOR_SECURITY_INVALID",
    )
    if (
        item.facts.path_sha256 != binding.path_sha256
        or _digest(item.raw) != binding.raw_sha256
    ):
        raise CredentialConfigError("CREDENTIAL_DESCRIPTOR_BINDING_MISMATCH")
    return _parse_descriptor(item.raw)


def parse_installer_store_bootstrap_v1(
    raw: bytes, *, expected_raw_sha256: str
) -> InstallerStoreBootstrapV1:
    """Parse only signed public config; never infer a store path from a hash."""
    if (
        not isinstance(expected_raw_sha256, str)
        or _SHA.fullmatch(expected_raw_sha256) is None
        or _digest(raw) != expected_raw_sha256
    ):
        raise CredentialConfigError("INSTALLER_PUBLIC_CONFIG_HASH_MISMATCH")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CredentialConfigError("INSTALLER_PUBLIC_CONFIG_JSON_INVALID") from None
    required = {
        "schema_version",
        "purpose",
        "store_root",
        "store_expectation",
        "installer_store_bootstrap",
        "runtime_config",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or canonical_json_bytes(value) != raw
    ):
        raise CredentialConfigError("INSTALLER_PUBLIC_CONFIG_NOT_CANONICAL")
    expectation = value["store_expectation"]
    bootstrap = value["installer_store_bootstrap"]
    if (
        not isinstance(expectation, dict)
        or not isinstance(bootstrap, dict)
        or set(bootstrap)
        != {"root_path", "root_path_sha256", "owner_sid", "directory_acl_sddl"}
    ):
        raise CredentialConfigError("INSTALLER_STORE_BOOTSTRAP_INVALID")
    try:
        root = canonical_local_windows_path(value["store_root"])
        bootstrap_root = canonical_local_windows_path(bootstrap["root_path"])
    except StoreContractError:
        raise CredentialConfigError("INSTALLER_STORE_BOOTSTRAP_INVALID") from None
    if (
        root != value["store_root"]
        or bootstrap_root != root
        or bootstrap["root_path_sha256"] != _digest(root.encode("utf-8"))
        or expectation.get("store_path_sha256") != bootstrap["root_path_sha256"]
        or expectation.get("owner_sid_sha256")
        != _digest(bootstrap["owner_sid"].encode("utf-8"))
        or expectation.get("directory_acl_sddl_sha256")
        != _digest(bootstrap["directory_acl_sddl"].encode("utf-8"))
    ):
        raise CredentialConfigError("INSTALLER_STORE_BOOTSTRAP_INVALID")
    return InstallerStoreBootstrapV1(
        store_root=root,
        store_expectation=expectation,
        owner_sid=bootstrap["owner_sid"],
        directory_acl_sddl=bootstrap["directory_acl_sddl"],
    )


def load_gateway_setting_from_local_blob_v1(
    descriptor: LocalCredentialDescriptorV1,
    *,
    filesystem: FilesystemFactsAdapter,
    reader: CredentialBlobReaderV1,
) -> Mapping[str, Any]:
    """Decrypt the independently secured blob without logging or returning it raw."""
    try:
        item = filesystem.read_file(Path(descriptor.blob_path))
    except OSError:
        raise CredentialConfigError("CREDENTIAL_BLOB_READ_FAILED") from None
    _secure_regular_file(
        item.facts,
        owner=descriptor.blob_owner_sid_sha256,
        acl=descriptor.blob_acl_sddl_sha256,
        code="CREDENTIAL_BLOB_SECURITY_INVALID",
    )
    if (
        item.facts.path_sha256 != descriptor.blob_path_sha256
        or _digest(item.raw) != descriptor.blob_raw_sha256
    ):
        raise CredentialConfigError("CREDENTIAL_BLOB_BINDING_MISMATCH")
    try:
        value = json.loads(reader.decrypt(item.raw).decode("utf-8", errors="strict"))
    except Exception:  # noqa: BLE001 - provider errors are deliberately redacted
        raise CredentialConfigError("CREDENTIAL_BLOB_DECRYPT_FAILED") from None
    if (
        not isinstance(value, dict)
        or not value
        or any(not isinstance(key, str) for key in value)
        or any(
            type(item) not in {str, bool, int, type(None)} for item in value.values()
        )
    ):
        raise CredentialConfigError("CREDENTIAL_BLOB_VALUE_INVALID")
    return value


class WindowsDpapiCredentialReaderV1:
    """Windows-only DPAPI reader; it intentionally has no environment fallback."""

    def decrypt(self, raw: bytes) -> bytes:
        if os.name != "nt":
            raise CredentialConfigError("CREDENTIAL_DPAPI_WINDOWS_REQUIRED")
        try:
            import win32crypt  # type: ignore[import-not-found]

            return bytes(win32crypt.CryptUnprotectData(raw, None, None, None, 0)[1])
        except Exception:  # noqa: BLE001 - DPAPI errors are deliberately redacted
            raise CredentialConfigError("CREDENTIAL_DPAPI_DECRYPT_FAILED") from None


def provision_local_dpapi_blob_v1(
    *,
    prompt: Callable[[], Mapping[str, Any]],
    blob_path: str,
    writer: WindowsSecureCredentialBlobWriterV1,
) -> str:
    """Operator-only local prompt path.  It returns only the blob digest."""
    if os.name != "nt":
        raise CredentialConfigError("CREDENTIAL_DPAPI_WINDOWS_REQUIRED")
    if not isinstance(writer, WindowsSecureCredentialBlobWriterV1):
        raise CredentialConfigError("CREDENTIAL_BLOB_SECURE_WRITER_REQUIRED")
    try:
        canonical_path = canonical_local_windows_path(blob_path)
        secret = dict(prompt())
        if not secret or any(not isinstance(key, str) for key in secret):
            raise CredentialConfigError("CREDENTIAL_PROMPT_VALUE_INVALID")
        raw = canonical_json_bytes(secret)
        import win32crypt  # type: ignore[import-not-found]

        # The service is LocalSystem while the prompt is an approved local
        # operator.  Machine scope is therefore required; the protected ACL on
        # both descriptor and blob remains the access boundary.
        protected = bytes(
            win32crypt.CryptProtectData(
                raw,
                "vnpy-windows-rpc-v1",
                None,
                None,
                None,
                _CRYPTPROTECT_LOCAL_MACHINE,
            )
        )
        writer.write_create_only(path=canonical_path, raw=protected)
        return _digest(protected)
    except CredentialConfigError:
        raise
    except Exception:  # noqa: BLE001 - prompt/provider errors are redacted
        raise CredentialConfigError("CREDENTIAL_PROVISION_FAILED") from None


__all__ = [
    "DESCRIPTOR_PURPOSE",
    "DESCRIPTOR_SCHEMA_VERSION",
    "CredentialBlobReaderV1",
    "CredentialBlobWriterV1",
    "CredentialConfigError",
    "CredentialDescriptorBindingV1",
    "InstallerStoreBootstrapV1",
    "LocalCredentialDescriptorV1",
    "WindowsDpapiCredentialReaderV1",
    "WindowsSecureCredentialBlobWriterV1",
    "load_gateway_setting_from_local_blob_v1",
    "load_local_credential_descriptor_v1",
    "parse_installer_store_bootstrap_v1",
    "provision_local_dpapi_blob_v1",
]
