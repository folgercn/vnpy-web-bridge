#!/usr/bin/env python3
"""Sign a reviewed query-v4 build/registry provenance-v3 record."""

from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import Any

import commodity_c_fast_t1_build_registry_provenance_v3 as provenance_v3


SIGNER_SOURCE_PATH = Path(__file__).resolve()
DELEGATE_SIGNER_PATH = SIGNER_SOURCE_PATH.with_name(
    "commodity_c_fast_t1_build_registry_provenance_sign_v2.py"
)


def _load_delegate() -> ModuleType:
    name = "_c_fast_t1_query_v4_build_registry_provenance_signer_delegate"
    source, digest = provenance_v3._read_verified_source(
        DELEGATE_SIGNER_PATH,
        provenance_v3.EXPECTED_DELEGATE_SIGNER_SHA256,
        "query-v4 provenance signer delegate",
    )
    if digest != provenance_v3.RETAINED_DELEGATE_SIGNER_SHA256:
        raise provenance_v3.DelegateBootstrapError(
            "query-v4 provenance signer delegate identity diverged"
        )
    module = provenance_v3._module_from_verified_source(
        name,
        DELEGATE_SIGNER_PATH,
        source,
    )
    module.provenance_v2 = provenance_v3
    module.SIGNER_SOURCE_PATH = SIGNER_SOURCE_PATH
    return module


_delegate = _load_delegate()

load_private_key = _delegate.load_private_key
prepare_provenance = _delegate.prepare_provenance
complete_signature = _delegate.complete_signature
sign_provenance = _delegate.sign_provenance
sign_provenance_from_private_key_path = (
    _delegate.sign_provenance_from_private_key_path
)
parse_args = _delegate.parse_args
main = _delegate.main


def __getattr__(name: str) -> Any:
    return getattr(_delegate, name)


if __name__ == "__main__":
    raise SystemExit(main())
