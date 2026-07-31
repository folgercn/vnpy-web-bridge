#!/usr/bin/env python3
"""Verify signed query-v4 build/registry provenance v3 offline."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).resolve()
DELEGATE_VERIFIER_PATH = Path(__file__).with_name(
    "commodity_c_fast_t1_build_registry_provenance_v2.py"
)
DELEGATE_SIGNER_PATH = Path(__file__).with_name(
    "commodity_c_fast_t1_build_registry_provenance_sign_v2.py"
)
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


def _load_delegate() -> ModuleType:
    name = "_c_fast_t1_query_v4_build_registry_provenance_delegate"
    spec = importlib.util.spec_from_file_location(
        name,
        DELEGATE_VERIFIER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("query-v4 provenance delegate is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


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


def _runtime_file_hashes() -> dict[str, str]:
    """Bind this v3 wrapper and both executable delegate sources."""

    hashes = _delegate_runtime_file_hashes()
    hashes.update(
        {
            "provenance_delegate_verifier_sha256": _delegate._hash_bytes(
                _delegate._read_file(
                    DELEGATE_VERIFIER_PATH,
                    "provenance v3 verifier delegate",
                )
            ),
            "provenance_delegate_signer_sha256": _delegate._hash_bytes(
                _delegate._read_file(
                    DELEGATE_SIGNER_PATH,
                    "provenance v3 signer delegate",
                )
            ),
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
