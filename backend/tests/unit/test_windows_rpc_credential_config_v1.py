from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.windows_fence_foundation.contracts import canonical_json_bytes
from scripts.windows_fence_foundation.credential_config_v1 import (
    CredentialConfigError,
    CredentialDescriptorBindingV1,
    load_gateway_setting_from_local_blob_v1,
    load_local_credential_descriptor_v1,
)
from scripts.windows_fence_foundation.win32_fs import PathSecurityFacts, SecureFileRead


def _facts(
    path: str, *, owner: str, acl: str, unsafe: tuple[str, ...] = ()
) -> PathSecurityFacts:
    return PathSecurityFacts(
        path_sha256=hashlib.sha256(path.encode()).hexdigest(),
        volume_serial="A1B2C3D4",
        volume_identity_sha256="a" * 64,
        file_identity="A1B2C3D4:1",
        owner_sid_sha256=owner,
        acl_sddl_sha256=acl,
        unsafe_write_principals=unsafe,
        write_principal_sid_sha256s=("system-only",),
        regular_file=True,
        directory=False,
        reparse_point=False,
        parent_chain_reparse_free=True,
        hardlink_count=1,
        alternate_data_streams=False,
        dacl_protected=True,
        inherited_ace_count=0,
    )


class _Filesystem:
    def __init__(self, values: dict[str, SecureFileRead]) -> None:
        self.values = values

    def read_file(self, path: Path, **_kwargs: object) -> SecureFileRead:
        return self.values[str(path)]


class _Reader:
    def decrypt(self, raw: bytes) -> bytes:
        assert raw == b"machine-scoped-dpapi-blob"
        return canonical_json_bytes(
            {"user": "operator-input-never-bundled", "password": "local-only"}
        )


def test_public_binding_loads_only_secured_descriptor_then_independent_blob() -> None:
    descriptor_path = r"C:\ProgramData\vnpy-web-bridge\credentials\descriptor.json"
    blob_path = r"C:\ProgramData\vnpy-web-bridge\credentials\blob.dpapi"
    owner, acl = "b" * 64, "c" * 64
    blob_owner, blob_acl = "d" * 64, "e" * 64
    descriptor_raw = canonical_json_bytes(
        {
            "schema_version": "windows_rpc_credential_descriptor_v1",
            "purpose": "bind_local_operator_dpapi_credential_blob_without_export",
            "blob_path": blob_path,
            "blob_path_sha256": hashlib.sha256(blob_path.encode()).hexdigest(),
            "blob_raw_sha256": hashlib.sha256(b"machine-scoped-dpapi-blob").hexdigest(),
            "blob_owner_sid_sha256": blob_owner,
            "blob_acl_sddl_sha256": blob_acl,
            "gateway_name": "CTP",
        }
    )
    fs = _Filesystem(
        {
            descriptor_path: SecureFileRead(
                descriptor_raw, _facts(descriptor_path, owner=owner, acl=acl)
            ),
            blob_path: SecureFileRead(
                b"machine-scoped-dpapi-blob",
                _facts(blob_path, owner=blob_owner, acl=blob_acl),
            ),
        }
    )
    binding = CredentialDescriptorBindingV1(
        path=descriptor_path,
        path_sha256=hashlib.sha256(descriptor_path.encode()).hexdigest(),
        raw_sha256=hashlib.sha256(descriptor_raw).hexdigest(),
        owner_sid_sha256=owner,
        acl_sddl_sha256=acl,
    )

    descriptor = load_local_credential_descriptor_v1(binding, filesystem=fs)  # type: ignore[arg-type]
    gateway = load_gateway_setting_from_local_blob_v1(
        descriptor, filesystem=fs, reader=_Reader()
    )  # type: ignore[arg-type]

    assert gateway["user"] == "operator-input-never-bundled"
    assert b"operator-input-never-bundled" not in descriptor_raw


def test_non_authorized_writer_or_reparse_descriptor_is_rejected() -> None:
    path = r"C:\ProgramData\vnpy-web-bridge\credentials\descriptor.json"
    owner, acl = "b" * 64, "c" * 64
    raw = canonical_json_bytes(
        {
            "schema_version": "windows_rpc_credential_descriptor_v1",
            "purpose": "bind_local_operator_dpapi_credential_blob_without_export",
            "blob_path": r"C:\ProgramData\vnpy-web-bridge\credentials\blob.dpapi",
            "blob_path_sha256": "a" * 64,
            "blob_raw_sha256": "a" * 64,
            "blob_owner_sid_sha256": "a" * 64,
            "blob_acl_sddl_sha256": "a" * 64,
            "gateway_name": "CTP",
        }
    )
    binding = CredentialDescriptorBindingV1(
        path=path,
        path_sha256=hashlib.sha256(path.encode()).hexdigest(),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        owner_sid_sha256=owner,
        acl_sddl_sha256=acl,
    )
    fs = _Filesystem(
        {
            path: SecureFileRead(
                raw, _facts(path, owner=owner, acl=acl, unsafe=("untrusted-sid",))
            )
        }
    )
    with pytest.raises(CredentialConfigError, match="SECURITY"):
        load_local_credential_descriptor_v1(binding, filesystem=fs)  # type: ignore[arg-type]
