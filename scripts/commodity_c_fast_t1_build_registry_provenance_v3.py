#!/usr/bin/env python3
"""Verify signed query-v4 build/registry provenance v3 offline."""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime
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
SIGNER_RUNTIME_VERIFICATION_SCOPE = (
    "INDEPENDENTLY_PINNED_DEPENDENCY_CLOSURE_IN_"
    "TRUSTED_READONLY_SIGNER_IMAGE"
)
EXPECTED_SIGNER_DEPENDENCY_MANIFEST_SHA256: str | None = None
EXPECTED_SIGNER_RUNTIME_IMAGE_DIGEST: str | None = None


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
write_json_create_only = _delegate.write_json_create_only
_delegate_validate_provenance_semantics = (
    _delegate.validate_provenance_semantics
)


def _validate_signer_runtime_identity(
    payload: dict[str, Any],
    *,
    expected_dependency_manifest_sha256: str,
    expected_runtime_image_digest: str,
) -> None:
    _delegate._validate_sha256(
        expected_dependency_manifest_sha256,
        "expected signer dependency manifest SHA256",
    )
    if (
        _delegate.OCI_DIGEST_PATTERN.fullmatch(
            expected_runtime_image_digest
        )
        is None
    ):
        raise BuildRegistryProvenanceV3Error(
            "expected signer runtime image digest is invalid"
        )
    identity = payload["signing_tool_source_identity"]
    _delegate._compare(
        str(identity["bootstrap_dependency_manifest_sha256"]),
        expected_dependency_manifest_sha256,
        "independently pinned signer dependency manifest",
    )
    _delegate._compare(
        str(identity["signer_runtime_image_digest"]),
        expected_runtime_image_digest,
        "trusted launcher signer runtime image",
    )
    if identity["runtime_verification_scope"] != (
        SIGNER_RUNTIME_VERIFICATION_SCOPE
    ):
        raise BuildRegistryProvenanceV3Error(
            "signer runtime verification scope is invalid"
        )


def validate_provenance_semantics(
    payload: dict[str, Any],
    content_raw: bytes,
    content: dict[str, Any],
    *,
    expected_runtime_source_commit_sha: str,
    expected_image_digest: str,
    expected_signing_tool_source_sha256: str,
    expected_signing_tool_source_commit_sha: str,
    expected_signer_dependency_manifest_sha256: str | None = None,
    expected_signer_runtime_image_digest: str | None = None,
    now: datetime | None = None,
) -> None:
    _delegate_validate_provenance_semantics(
        payload,
        content_raw,
        content,
        expected_runtime_source_commit_sha=(
            expected_runtime_source_commit_sha
        ),
        expected_image_digest=expected_image_digest,
        expected_signing_tool_source_sha256=(
            expected_signing_tool_source_sha256
        ),
        expected_signing_tool_source_commit_sha=(
            expected_signing_tool_source_commit_sha
        ),
        now=now,
    )
    manifest = (
        expected_signer_dependency_manifest_sha256
        if expected_signer_dependency_manifest_sha256 is not None
        else EXPECTED_SIGNER_DEPENDENCY_MANIFEST_SHA256
    )
    runtime_image = (
        expected_signer_runtime_image_digest
        if expected_signer_runtime_image_digest is not None
        else EXPECTED_SIGNER_RUNTIME_IMAGE_DIGEST
    )
    if manifest is None or runtime_image is None:
        raise BuildRegistryProvenanceV3Error(
            "independent signer runtime identity pins are required"
        )
    _validate_signer_runtime_identity(
        payload,
        expected_dependency_manifest_sha256=manifest,
        expected_runtime_image_digest=runtime_image,
    )


def verify_provenance(
    provenance_path: Path,
    trusted_keyring_path: Path,
    content_attestation_path: Path,
    *,
    expected_trusted_keyring_sha256: str,
    expected_runtime_source_commit_sha: str,
    expected_image_digest: str,
    expected_signing_tool_source_sha256: str,
    expected_signing_tool_source_commit_sha: str,
    expected_signer_dependency_manifest_sha256: str,
    expected_signer_runtime_image_digest: str,
    excluded_authority_key_hashes: list[str],
    excluded_authority_keyring_sha256s: dict[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    provenance_raw, provenance = _delegate._load_json(
        provenance_path,
        "signed query-v4 build and registry provenance v3",
    )
    _keyring_raw, keyring = _delegate._load_json(
        trusted_keyring_path,
        "build and registry provenance trusted keyring",
        private=True,
    )
    content_raw, content = _delegate._load_json(
        content_attestation_path,
        "query-v4 OCI content attestation",
    )
    _delegate._validate_schema(
        provenance,
        PROVENANCE_SCHEMA_PATH,
        "signed query-v4 build and registry provenance v3",
    )
    _delegate._validate_sha256(
        expected_trusted_keyring_sha256,
        "expected trusted keyring SHA256",
    )
    keyring_sha256 = _delegate._hash_bytes(
        _delegate.canonical_json(keyring)
    )
    _delegate._compare(
        keyring_sha256,
        expected_trusted_keyring_sha256,
        "independently pinned trusted keyring",
    )
    _delegate._compare(
        keyring_sha256,
        provenance["trusted_keyring_sha256"],
        "provenance trusted keyring",
    )
    public_key, provenance_key_hashes = _delegate._load_public_keyset(
        keyring,
        str(provenance["signer_key_id"]),
    )
    _delegate._validate_signer_independence(
        provenance,
        provenance_key_hashes,
        excluded_authority_key_hashes,
        excluded_authority_keyring_sha256s,
    )
    try:
        signature = base64.b64decode(
            provenance["signature"],
            validate=True,
        )
        if len(signature) != 64:
            raise ValueError
        public_key.verify(
            signature,
            _delegate.canonical_json(
                unsigned_provenance_payload(provenance)
            ),
        )
    except (
        _delegate.InvalidSignature,
        ValueError,
        TypeError,
        binascii.Error,
    ) as exc:
        raise BuildRegistryProvenanceV3Error(
            "build and registry provenance v3 signature is invalid"
        ) from exc
    validate_provenance_semantics(
        provenance,
        content_raw,
        content,
        expected_runtime_source_commit_sha=(
            expected_runtime_source_commit_sha
        ),
        expected_image_digest=expected_image_digest,
        expected_signing_tool_source_sha256=(
            expected_signing_tool_source_sha256
        ),
        expected_signing_tool_source_commit_sha=(
            expected_signing_tool_source_commit_sha
        ),
        expected_signer_dependency_manifest_sha256=(
            expected_signer_dependency_manifest_sha256
        ),
        expected_signer_runtime_image_digest=(
            expected_signer_runtime_image_digest
        ),
        now=now,
    )
    verified_at = _delegate._aware_utc_now(now)
    identity = provenance["signing_tool_source_identity"]
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "status": RECEIPT_STATUS,
        "provenance_id": provenance["provenance_id"],
        "verified_at": verified_at.isoformat(),
        "signed_provenance_raw_sha256": _delegate._hash_bytes(
            provenance_raw
        ),
        "signed_provenance_canonical_sha256": _delegate._hash_bytes(
            _delegate.canonical_json(provenance)
        ),
        "content_attestation_raw_sha256": _delegate._hash_bytes(
            content_raw
        ),
        "content_attestation_canonical_sha256": _delegate._hash_bytes(
            _delegate.canonical_json(content)
        ),
        "trusted_keyring_sha256": keyring_sha256,
        "excluded_authority_keyring_sha256s": (
            provenance["excluded_authority_keyring_sha256s"]
        ),
        "excluded_authority_public_key_sha256s": (
            provenance["excluded_authority_public_key_sha256s"]
        ),
        "signer_key_id": provenance["signer_key_id"],
        "signer_public_key_sha256": _delegate._hash_bytes(
            public_key.public_bytes_raw()
        ),
        "signing_tool_source_path": identity["path"],
        "signing_tool_source_commit_sha": identity["source_commit_sha"],
        "signing_tool_source_sha256": identity["sha256"],
        "signing_tool_source_pin_verified": True,
        "signing_tool_source_bytes_revalidated_at_runtime": False,
        "signing_tool_execution_independently_verified": False,
        "signer_dependency_manifest_sha256": identity[
            "bootstrap_dependency_manifest_sha256"
        ],
        "signer_dependency_manifest_pin_verified": True,
        "signer_runtime_image_digest": identity[
            "signer_runtime_image_digest"
        ],
        "signer_runtime_image_digest_pin_verified": True,
        "signer_runtime_execution_independently_verified": False,
        "runtime_source_commit_sha": provenance[
            "runtime_source_commit_sha"
        ],
        "source_bundle_archive_sha256": provenance[
            "source_bundle_archive_sha256"
        ],
        "source_manifest_canonical_sha256": provenance[
            "source_manifest_canonical_sha256"
        ],
        "image_reference": provenance["image_reference"],
        "image_digest": provenance["image_digest"],
        "signed_build_assertion_verified": True,
        "signed_registry_assertion_verified": True,
        "external_facts_independently_reverified": False,
        "receipt_is_authority": False,
        **{field: False for field in _delegate.FALSE_AUTHORITY_FIELDS},
        **{field: 0 for field in _delegate.ZERO_FACT_FIELDS},
    }
    _delegate._validate_schema(
        receipt,
        RECEIPT_SCHEMA_PATH,
        "build and registry provenance v3 receipt",
    )
    return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument("--expected-trusted-keyring-sha256", required=True)
    parser.add_argument("--content-attestation", type=Path, required=True)
    parser.add_argument(
        "--expected-runtime-source-commit-sha",
        required=True,
    )
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument(
        "--expected-signing-tool-source-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-signing-tool-source-commit-sha",
        required=True,
    )
    parser.add_argument(
        "--expected-signer-dependency-manifest-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-signer-runtime-image-digest",
        required=True,
    )
    parser.add_argument("--t1-authority-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-t1-authority-keyring-sha256",
        required=True,
    )
    parser.add_argument("--l3-authority-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-l3-authority-keyring-sha256",
        required=True,
    )
    parser.add_argument("--json-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        excluded_hashes, excluded_keyring_hashes = (
            load_excluded_authority_key_facts(
                t1_keyring_path=args.t1_authority_keyring,
                expected_t1_keyring_sha256=(
                    args.expected_t1_authority_keyring_sha256
                ),
                l3_keyring_path=args.l3_authority_keyring,
                expected_l3_keyring_sha256=(
                    args.expected_l3_authority_keyring_sha256
                ),
            )
        )
        receipt = verify_provenance(
            args.provenance,
            args.trusted_keyring,
            args.content_attestation,
            expected_trusted_keyring_sha256=(
                args.expected_trusted_keyring_sha256
            ),
            expected_runtime_source_commit_sha=(
                args.expected_runtime_source_commit_sha
            ),
            expected_image_digest=args.expected_image_digest,
            expected_signing_tool_source_sha256=(
                args.expected_signing_tool_source_sha256
            ),
            expected_signing_tool_source_commit_sha=(
                args.expected_signing_tool_source_commit_sha
            ),
            expected_signer_dependency_manifest_sha256=(
                args.expected_signer_dependency_manifest_sha256
            ),
            expected_signer_runtime_image_digest=(
                args.expected_signer_runtime_image_digest
            ),
            excluded_authority_key_hashes=excluded_hashes,
            excluded_authority_keyring_sha256s=excluded_keyring_hashes,
        )
        if args.json_output is not None:
            write_json_create_only(args.json_output, receipt)
    except (BuildRegistryProvenanceV3Error, OSError, ValueError) as exc:
        print(
            f"build/registry provenance v3 verification failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"status={receipt['status']}")
    print(f"provenance_id={receipt['provenance_id']}")
    print("readiness_authorized=false")
    print("production_query_authorized=false")
    return 0


def __getattr__(name: str) -> Any:
    return getattr(_delegate, name)


if __name__ == "__main__":
    raise SystemExit(main())
