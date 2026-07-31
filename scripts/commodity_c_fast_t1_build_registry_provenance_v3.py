#!/usr/bin/env python3
"""Verify signed query-v4 build/registry provenance v3 offline."""

from __future__ import annotations

import hashlib
import hmac
import importlib.machinery
import os
from pathlib import Path
import stat
import sys
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
DELEGATE_VERIFIER_PATH = VERIFIER_PATH.with_name(
    "commodity_c_fast_t1_build_registry_provenance_v2.py"
)
DELEGATE_SIGNER_PATH = VERIFIER_PATH.with_name(
    "commodity_c_fast_t1_build_registry_provenance_sign_v2.py"
)
SUPPORT_PATH = VERIFIER_PATH.with_name(
    "commodity_c_fast_t1_one_shot.py"
)
EXPECTED_DELEGATE_VERIFIER_SHA256 = (
    "a78fc7c61412db40b59d3b24753675c313abf53c02d0ea156806ac3ca1209986"
)
EXPECTED_DELEGATE_SIGNER_SHA256 = (
    "945a0aa8dd1fd6e3828d3cb30ff405d1f01546feda56be43644ac4c1b5f5fee9"
)
EXPECTED_SUPPORT_SHA256 = (
    "6a4ea2da568d91825e8387897484e5da26bb0e0f96a19465480ed52eca8e2b20"
)
MAX_DELEGATE_SOURCE_BYTES = 8 * 1024 * 1024
SUPPORT_PUBLIC_MODULE = "commodity_c_fast_t1_one_shot"
PROVENANCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-build-registry-provenance-v3.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-build-registry-provenance-receipt-v3.schema.json"
)
CONTENT_ATTESTATION_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v4-image-attestation-v1.schema.json"
)
SOURCE_MANIFEST_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v4-source-manifest-v1.schema.json"
)
CONTENT_VERIFIER_PATH = (
    ROOT / "scripts/c_fast_t1/verify_query_v4_image_attestation.py"
)

SCHEMA_VERSION = "commodity_c_fast_t1_build_registry_provenance_v3"
RECEIPT_SCHEMA_VERSION = (
    "commodity_c_fast_t1_build_registry_provenance_receipt_v3"
)
CONTENT_ATTESTATION_SCHEMA_VERSION = (
    "commodity_c_fast_t1_query_v4_image_attestation_v1"
)
PURPOSE = "c_fast_t1_query_v4_external_build_registry_provenance"
SIGNING_TOOL_SOURCE_PATH = (
    "scripts/commodity_c_fast_t1_build_registry_provenance_sign_v3.py"
)
RECEIPT_STATUS = (
    "SIGNED_QUERY_V4_BUILD_REGISTRY_ASSERTIONS_VERIFIED_NO_RUNTIME_AUTHORITY"
)


class DelegateBootstrapError(RuntimeError):
    """Delegate source failed before any untrusted code was executed."""


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_fd_bytes(descriptor: int, label: str) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_DELEGATE_SOURCE_BYTES:
            raise DelegateBootstrapError(f"{label} is too large")
        chunks.append(chunk)


def _read_verified_source(
    path: Path,
    expected_sha256: str,
    label: str,
) -> tuple[bytes, str]:
    """Read one stable, unlinked source twice before it can be compiled."""

    descriptor = -1
    try:
        before_path = path.lstat()
        if (
            not stat.S_ISREG(before_path.st_mode)
            or stat.S_ISLNK(before_path.st_mode)
            or before_path.st_nlink != 1
        ):
            raise DelegateBootstrapError(
                f"{label} must be a single-link regular file"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(before_path) != _file_identity(opened):
            raise DelegateBootstrapError(
                f"{label} changed before stable read"
            )
        first = _read_fd_bytes(descriptor, label)
        after_first = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_fd_bytes(descriptor, label)
        after_second = os.fstat(descriptor)
        after_path = path.lstat()
        identity = _file_identity(opened)
        if (
            _file_identity(after_first) != identity
            or _file_identity(after_second) != identity
            or _file_identity(after_path) != identity
            or first != second
        ):
            raise DelegateBootstrapError(
                f"{label} changed during stable read"
            )
    except DelegateBootstrapError:
        raise
    except OSError as exc:
        raise DelegateBootstrapError(
            f"{label} cannot be read safely"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    digest = hashlib.sha256(first).hexdigest()
    if not hmac.compare_digest(digest, expected_sha256):
        raise DelegateBootstrapError(
            f"{label} failed the pre-execution SHA256 pin"
        )
    return first, digest


def _module_from_verified_source(
    name: str,
    path: Path,
    source: bytes,
) -> ModuleType:
    """Compile and execute only the exact in-memory bytes already verified."""

    module = ModuleType(name)
    module.__file__ = str(path)
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = importlib.machinery.ModuleSpec(
        name,
        loader=None,
        origin=str(path),
    )
    code = compile(source, str(path), "exec", dont_inherit=True)
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


(
    DELEGATE_VERIFIER_SOURCE,
    RETAINED_DELEGATE_VERIFIER_SHA256,
) = _read_verified_source(
    DELEGATE_VERIFIER_PATH,
    EXPECTED_DELEGATE_VERIFIER_SHA256,
    "query-v4 provenance verifier delegate",
)
(
    DELEGATE_SIGNER_SOURCE,
    RETAINED_DELEGATE_SIGNER_SHA256,
) = _read_verified_source(
    DELEGATE_SIGNER_PATH,
    EXPECTED_DELEGATE_SIGNER_SHA256,
    "query-v4 provenance signer delegate",
)
(
    SUPPORT_SOURCE,
    RETAINED_SUPPORT_SHA256,
) = _read_verified_source(
    SUPPORT_PATH,
    EXPECTED_SUPPORT_SHA256,
    "query-v4 provenance support module",
)
_support = _module_from_verified_source(
    "_c_fast_t1_verified_provenance_support",
    SUPPORT_PATH,
    SUPPORT_SOURCE,
)


def _load_delegate() -> ModuleType:
    name = "_c_fast_t1_query_v4_build_registry_provenance_delegate"
    previous = sys.modules.get(SUPPORT_PUBLIC_MODULE)
    sys.modules[SUPPORT_PUBLIC_MODULE] = _support
    try:
        return _module_from_verified_source(
            name,
            DELEGATE_VERIFIER_PATH,
            DELEGATE_VERIFIER_SOURCE,
        )
    finally:
        if previous is None:
            sys.modules.pop(SUPPORT_PUBLIC_MODULE, None)
        else:
            sys.modules[SUPPORT_PUBLIC_MODULE] = previous


_delegate = _load_delegate()
_delegate.VERIFIER_PATH = VERIFIER_PATH
_delegate.PROVENANCE_SCHEMA_PATH = PROVENANCE_SCHEMA_PATH
_delegate.RECEIPT_SCHEMA_PATH = RECEIPT_SCHEMA_PATH
_delegate.CONTENT_ATTESTATION_SCHEMA_PATH = (
    CONTENT_ATTESTATION_SCHEMA_PATH
)
_delegate.SOURCE_MANIFEST_SCHEMA_PATH = SOURCE_MANIFEST_SCHEMA_PATH
_delegate.CONTENT_VERIFIER_PATH = CONTENT_VERIFIER_PATH
_delegate.SCHEMA_VERSION = SCHEMA_VERSION
_delegate.RECEIPT_SCHEMA_VERSION = RECEIPT_SCHEMA_VERSION
_delegate.CONTENT_ATTESTATION_SCHEMA_VERSION = (
    CONTENT_ATTESTATION_SCHEMA_VERSION
)
_delegate.PURPOSE = PURPOSE
_delegate.SIGNING_TOOL_SOURCE_PATH = SIGNING_TOOL_SOURCE_PATH
_delegate.RECEIPT_STATUS = RECEIPT_STATUS

_delegate_runtime_file_hashes = _delegate._runtime_file_hashes
RETAINED_VERIFIER_SHA256 = hashlib.sha256(
    VERIFIER_PATH.read_bytes()
).hexdigest()


def _runtime_file_hashes() -> dict[str, str]:
    """Bind the exact delegate identities retained before execution."""

    hashes = _delegate_runtime_file_hashes()
    hashes.update(
        {
            "provenance_verifier_sha256": RETAINED_VERIFIER_SHA256,
            "provenance_delegate_verifier_sha256": (
                RETAINED_DELEGATE_VERIFIER_SHA256
            ),
            "provenance_delegate_signer_sha256": (
                RETAINED_DELEGATE_SIGNER_SHA256
            ),
            "provenance_support_sha256": RETAINED_SUPPORT_SHA256,
        }
    )
    return hashes


_delegate._runtime_file_hashes = _runtime_file_hashes

BuildRegistryProvenanceV3Error = (
    _delegate.BuildRegistryProvenanceV2Error
)
# Compatibility alias keeps the shared implementation and existing callers
# usable while the signed/schema namespace remains strictly v3/query-v4.
BuildRegistryProvenanceV2Error = BuildRegistryProvenanceV3Error

add_runtime_file_hashes = _delegate.add_runtime_file_hashes
load_excluded_authority_key_facts = (
    _delegate.load_excluded_authority_key_facts
)
unsigned_provenance_payload = _delegate.unsigned_provenance_payload
validate_provenance_semantics = _delegate.validate_provenance_semantics
verify_provenance = _delegate.verify_provenance
write_json_create_only = _delegate.write_json_create_only
parse_args = _delegate.parse_args
main = _delegate.main


def __getattr__(name: str) -> Any:
    return getattr(_delegate, name)


if __name__ == "__main__":
    raise SystemExit(main())
